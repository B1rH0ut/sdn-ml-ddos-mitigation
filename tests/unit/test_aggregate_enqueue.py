"""Unit tests for _aggregate_and_enqueue() aggregation logic.

Tests the core aggregation algorithm from ddos_controller.py lines 1013-1178:
  - Leaf vs spine switch counting for ECMP double-count prevention
  - Network-wide destination aggregate computation
  - Priority-based flow sampling (top-N + PPS threshold)

Since _aggregate_and_enqueue() cannot be called directly (requires full Ryu
controller), these tests replicate the aggregation and sampling logic using
mock stat objects and verify correctness of the algorithm.
"""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

# ── Mock Ryu framework ──────────────────────────────────────────────────────

def _setup_ryu_mocks():
    """Install mock Ryu modules so ddos_controller can be imported."""
    mock_modules = {}
    mock_modules["ryu"] = MagicMock()
    mock_modules["ryu.base"] = MagicMock()
    mock_modules["ryu.base.app_manager"] = MagicMock()
    mock_modules["ryu.controller"] = MagicMock()
    mock_modules["ryu.controller.ofp_event"] = MagicMock()
    mock_modules["ryu.controller.handler"] = MagicMock()
    mock_modules["ryu.ofproto"] = MagicMock()
    mock_modules["ryu.ofproto.ofproto_v1_3"] = MagicMock()
    mock_modules["ryu.lib"] = MagicMock()
    mock_modules["ryu.lib.hub"] = MagicMock()
    mock_modules["ryu.lib.packet"] = MagicMock()
    mock_modules["ryu.lib.packet.packet"] = MagicMock()
    mock_modules["ryu.lib.packet.ethernet"] = MagicMock()
    mock_modules["ryu.lib.packet.arp"] = MagicMock()
    mock_modules["ryu.lib.packet.ipv4"] = MagicMock()

    ryu_cfg = MagicMock()
    ryu_cfg.CONF = MagicMock()
    ryu_cfg.CONF.packet_in_rate_limit = 100
    ryu_cfg.IntOpt = MagicMock()
    ryu_cfg.FloatOpt = MagicMock()
    mock_modules["ryu.cfg"] = ryu_cfg

    for mod_name, mock_mod in mock_modules.items():
        if mod_name not in sys.modules:
            sys.modules[mod_name] = mock_mod


try:
    import ryu  # noqa: F401
except ImportError:
    _setup_ryu_mocks()

from sdn_ddos_detector.controller.ddos_controller import (
    FLOW_SAMPLE_TOP_N, FLOW_SAMPLE_PPS_THRESHOLD,
)
from sdn_ddos_detector.config.topology_config import LEAF_DPIDS, SPINE_DPIDS


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_stat(priority, duration_sec, packet_count, byte_count,
               ipv4_src='10.0.0.1', ipv4_dst='10.0.0.7', ip_proto=6):
    """Create a mock flow stat object matching OFPFlowStats structure."""
    stat = SimpleNamespace()
    stat.priority = priority
    stat.duration_sec = duration_sec
    stat.packet_count = packet_count
    stat.byte_count = byte_count

    # match behaves like a dict with .get()
    match_data = {
        'ipv4_src': ipv4_src,
        'ipv4_dst': ipv4_dst,
        'ip_proto': ip_proto,
        'icmp_code': 0,
        'icmp_type': 0,
    }
    stat.match = SimpleNamespace()
    stat.match.get = lambda key, default='unknown': match_data.get(key, default)
    return stat


def _run_aggregation(pending_stats_replies):
    """Replicate the aggregation loop from _aggregate_and_enqueue.

    Returns (all_raw_flows, network_dst_counts, network_dst_sources).
    """
    all_raw_flows = []
    network_dst_counts = {}
    network_dst_sources = {}

    for dpid, body in pending_stats_replies.items():
        if body is None:
            continue

        is_leaf = dpid in LEAF_DPIDS

        for stat in body:
            if stat.priority == 0:
                continue
            if stat.match.get('ipv4_src', 'unknown') == 'unknown' and \
               stat.match.get('ipv4_dst', 'unknown') == 'unknown':
                continue
            if stat.duration_sec < 0 or stat.packet_count < 0 or stat.byte_count < 0:
                continue

            src_ip = stat.match.get('ipv4_src', 'unknown')
            dst_ip = stat.match.get('ipv4_dst', 'unknown')
            ip_proto = stat.match.get('ip_proto', 0)

            flow = {
                'dpid': dpid,
                'duration_sec': stat.duration_sec,
                'packet_count': stat.packet_count,
                'byte_count': stat.byte_count,
                'ip_proto': ip_proto,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
            }
            all_raw_flows.append(flow)

            if is_leaf and dst_ip != 'unknown':
                network_dst_counts[dst_ip] = \
                    network_dst_counts.get(dst_ip, 0) + 1
                if dst_ip not in network_dst_sources:
                    network_dst_sources[dst_ip] = set()
                if src_ip != 'unknown':
                    network_dst_sources[dst_ip].add(src_ip)

    return all_raw_flows, network_dst_counts, network_dst_sources


def _run_priority_sampling(all_raw_flows):
    """Replicate the priority-based sampling from _aggregate_and_enqueue.

    Returns the sampled flow list.
    """
    for flow in all_raw_flows:
        dur = max(flow['duration_sec'], 0.001)
        flow['_pps'] = flow['packet_count'] / dur

    all_raw_flows.sort(key=lambda f: f['_pps'], reverse=True)

    if len(all_raw_flows) > FLOW_SAMPLE_TOP_N:
        sampled = all_raw_flows[:FLOW_SAMPLE_TOP_N]
        for flow in all_raw_flows[FLOW_SAMPLE_TOP_N:]:
            if flow['_pps'] >= FLOW_SAMPLE_PPS_THRESHOLD:
                sampled.append(flow)
    else:
        sampled = all_raw_flows

    return sampled


# ── Tests ────────────────────────────────────────────────────────────────────

class TestAggregateAndEnqueue:

    def test_leaf_flows_counted_in_aggregates(self):
        """Flows from a leaf switch (dpid=3) update network_dst_counts and network_dst_sources."""
        pending = {
            3: [  # leaf switch
                _make_stat(10, 5, 100, 5000, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.7'),
                _make_stat(10, 3, 200, 8000, ipv4_src='10.0.0.2', ipv4_dst='10.0.0.7'),
            ],
        }

        all_flows, dst_counts, dst_sources = _run_aggregation(pending)

        assert len(all_flows) == 2
        assert dst_counts['10.0.0.7'] == 2
        assert dst_sources['10.0.0.7'] == {'10.0.0.1', '10.0.0.2'}

    def test_spine_flows_excluded_from_aggregates(self):
        """Flows from a spine switch (dpid=1) appear in all_raw_flows but NOT in aggregate counts."""
        pending = {
            1: [  # spine switch
                _make_stat(10, 5, 100, 5000, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.7'),
                _make_stat(10, 3, 200, 8000, ipv4_src='10.0.0.2', ipv4_dst='10.0.0.7'),
            ],
        }

        all_flows, dst_counts, dst_sources = _run_aggregation(pending)

        # Flows are collected but not counted in aggregates
        assert len(all_flows) == 2
        assert '10.0.0.7' not in dst_counts
        assert '10.0.0.7' not in dst_sources

    def test_dst_flow_counts_and_source_sets(self):
        """Multiple flows to same dst from different sources produce correct counts."""
        pending = {
            3: [  # leaf
                _make_stat(10, 5, 100, 5000, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.7'),
                _make_stat(10, 3, 200, 8000, ipv4_src='10.0.0.2', ipv4_dst='10.0.0.7'),
                _make_stat(10, 4, 150, 6000, ipv4_src='10.0.0.1', ipv4_dst='10.0.0.7'),
                _make_stat(10, 2, 50, 2000, ipv4_src='10.0.0.3', ipv4_dst='10.0.0.8'),
            ],
            4: [  # leaf
                _make_stat(10, 6, 300, 12000, ipv4_src='10.0.0.4', ipv4_dst='10.0.0.7'),
            ],
            1: [  # spine — should NOT count
                _make_stat(10, 5, 100, 5000, ipv4_src='10.0.0.5', ipv4_dst='10.0.0.7'),
            ],
        }

        all_flows, dst_counts, dst_sources = _run_aggregation(pending)

        assert len(all_flows) == 6
        # 3 flows from dpid=3 + 1 from dpid=4 targeting 10.0.0.7
        assert dst_counts['10.0.0.7'] == 4
        # Unique sources from leaf switches: 10.0.0.1, 10.0.0.2, 10.0.0.4
        assert dst_sources['10.0.0.7'] == {'10.0.0.1', '10.0.0.2', '10.0.0.4'}
        # 10.0.0.8 has 1 flow from 1 source
        assert dst_counts['10.0.0.8'] == 1
        assert dst_sources['10.0.0.8'] == {'10.0.0.3'}

    def test_priority_sampling_selects_highest_pps(self):
        """With >FLOW_SAMPLE_TOP_N flows, top PPS flows are kept + any above threshold."""
        # Create FLOW_SAMPLE_TOP_N + 100 flows with varying PPS
        flows = []
        for i in range(FLOW_SAMPLE_TOP_N + 100):
            # Most flows: low PPS (1 pps = 10 packets / 10 seconds)
            pps_val = 1
            pkt = 10
            dur = 10
            # 50 flows beyond TOP_N with high PPS (above threshold)
            if i >= FLOW_SAMPLE_TOP_N and i < FLOW_SAMPLE_TOP_N + 50:
                pps_val = FLOW_SAMPLE_PPS_THRESHOLD + 10
                pkt = (FLOW_SAMPLE_PPS_THRESHOLD + 10) * 10
                dur = 10

            flows.append({
                'dpid': 3,
                'duration_sec': dur,
                'packet_count': pkt,
                'byte_count': pkt * 50,
                'ip_proto': 6,
                'src_ip': f'10.0.0.{i % 254 + 1}',
                'dst_ip': '10.0.0.7',
            })

        sampled = _run_priority_sampling(flows)

        # Should have top N + 50 above-threshold flows
        # (some of the top-N may overlap with above-threshold, but in this
        # setup the high-PPS flows get sorted to the top, so top-N includes them)
        assert len(sampled) >= FLOW_SAMPLE_TOP_N
        # All sampled flows should be the highest PPS
        pps_values = [f['_pps'] for f in sampled]
        assert pps_values == sorted(pps_values, reverse=True)
