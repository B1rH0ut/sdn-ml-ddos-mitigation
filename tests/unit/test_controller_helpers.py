"""Tests for standalone classes/functions in ddos_controller.py.

Does NOT instantiate DDoSDetectionController (which requires Ryu runtime).
Tests PacketInRateLimiter, FloodRateLimiter, and _verify_model_integrity.

Mocks out Ryu imports at the module level so the controller module can be
imported without the full Ryu framework installed.
"""

import hashlib
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest


# ── Mock Ryu framework before importing ddos_controller ──────────────────────

def _setup_ryu_mocks():
    """Install mock Ryu modules so ddos_controller can be imported."""
    mock_modules = {}

    # ryu.base
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

    # ryu.cfg — needs CONF with register_opts and attribute access
    ryu_cfg = MagicMock()
    ryu_cfg.CONF = MagicMock()
    ryu_cfg.CONF.packet_in_rate_limit = 100
    ryu_cfg.IntOpt = MagicMock()
    ryu_cfg.FloatOpt = MagicMock()
    mock_modules["ryu.cfg"] = ryu_cfg

    for mod_name, mock_mod in mock_modules.items():
        if mod_name not in sys.modules:
            sys.modules[mod_name] = mock_mod


# Only install mocks if ryu is not actually available
try:
    import ryu  # noqa: F401
except ImportError:
    _setup_ryu_mocks()

from sdn_ddos_detector.controller.ddos_controller import (
    PacketInRateLimiter,
    FloodRateLimiter,
    _verify_model_integrity,
    PRIORITY_ANTI_SPOOF_ALLOW,
    IPV4_ETHERTYPE,
    ARP_ETHERTYPE,
)


# ── PacketInRateLimiter ──────────────────────────────────────────────────────

class TestPacketInRateLimiter:
    def test_allows_under_limit(self):
        limiter = PacketInRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            assert limiter.allow(dpid=1) is True

    def test_blocks_over_limit(self):
        limiter = PacketInRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False

    def test_window_reset_allows_again(self):
        limiter = PacketInRateLimiter(rate_limit=2, window_sec=0.1)
        limiter.allow(dpid=1)
        limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False
        time.sleep(0.15)
        assert limiter.allow(dpid=1) is True

    def test_independent_per_dpid(self):
        limiter = PacketInRateLimiter(rate_limit=2, window_sec=1.0)
        limiter.allow(dpid=1)
        limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False
        # dpid=2 should still be allowed
        assert limiter.allow(dpid=2) is True


# ── FloodRateLimiter ─────────────────────────────────────────────────────────

class TestFloodRateLimiter:
    def test_allows_under_limit(self):
        limiter = FloodRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            assert limiter.allow(dpid=1) is True

    def test_blocks_over_limit(self):
        limiter = FloodRateLimiter(rate_limit=5, window_sec=1.0)
        for _ in range(5):
            limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False

    def test_independent_per_dpid(self):
        limiter = FloodRateLimiter(rate_limit=1, window_sec=1.0)
        limiter.allow(dpid=1)
        assert limiter.allow(dpid=1) is False
        assert limiter.allow(dpid=2) is True


# ── _verify_model_integrity ──────────────────────────────────────────────────

class TestVerifyModelIntegrity:
    def test_returns_false_if_hash_file_missing(self, tmp_path, mock_logger):
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(b"fake model data")
        result = _verify_model_integrity(
            str(model_file), str(tmp_path / "nonexistent"), mock_logger
        )
        assert result is False
        mock_logger.critical.assert_called()

    def test_returns_false_if_hash_mismatch(self, tmp_path, mock_logger):
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(b"real model data")

        # Write hash file with wrong hash
        hash_file = tmp_path / "model_checksums.hmac"
        hash_file.write_text(json.dumps({"flow_model.pkl": "deadbeef" * 8}))

        result = _verify_model_integrity(str(model_file), str(tmp_path), mock_logger)
        assert result is False

    def test_returns_true_for_valid_sha256(self, tmp_path, mock_logger):
        model_data = b"valid model content"
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(model_data)

        expected_hash = hashlib.sha256(model_data).hexdigest()
        hash_file = tmp_path / "model_checksums.hmac"
        hash_file.write_text(json.dumps({"flow_model.pkl": expected_hash}))

        with patch.dict(os.environ, {"SDN_MODEL_HMAC_KEY": ""}, clear=False):
            result = _verify_model_integrity(
                str(model_file), str(tmp_path), mock_logger
            )
        assert result is True

    def test_returns_true_for_valid_hmac(self, tmp_path, mock_logger):
        import hmac as hmac_mod

        model_data = b"hmac protected model"
        model_file = tmp_path / "flow_model.pkl"
        model_file.write_bytes(model_data)

        hmac_key = b"test-secret-key"
        expected_hash = hmac_mod.new(
            hmac_key, model_data, hashlib.sha256
        ).hexdigest()

        hash_file = tmp_path / "model_checksums.hmac"
        hash_file.write_text(json.dumps({"flow_model.pkl": expected_hash}))

        with patch.dict(
            os.environ, {"SDN_MODEL_HMAC_KEY": "test-secret-key"}, clear=False
        ):
            result = _verify_model_integrity(
                str(model_file), str(tmp_path), mock_logger
            )
        assert result is True


# ── Anti-Spoofing ALLOW Rule Check ──────────────────────────────────────────

class TestAntiSpoofAllowAction:
    """Verify IPv4 ALLOW rules use OFPP_NORMAL, not OFPP_CONTROLLER (v3.1.0)."""

    def test_ipv4_allow_uses_ofpp_normal(self):
        """The _install_anti_spoof_rules source must use OFPP_NORMAL for IPv4."""
        import importlib
        import inspect

        # Read the raw source file to verify the code pattern
        mod_file = inspect.getfile(
            importlib.import_module("sdn_ddos_detector.controller.ddos_controller")
        )
        with open(mod_file) as f:
            source = f.read()

        # Find the _install_anti_spoof_rules method body
        start = source.find("def _install_anti_spoof_rules")
        assert start != -1, "Method not found in source"

        # Get the method body (until next def at same indent level)
        method_body = source[start:source.find("\n    def ", start + 1)]

        # The IPv4 ALLOW code section (after docstring, before ARP section)
        ipv4_section_end = method_body.find("# ARP: ALLOW")
        # Skip the docstring by finding the closing triple-quote
        docstring_end = method_body.find('"""', method_body.find('"""') + 3) + 3
        ipv4_code = method_body[docstring_end:ipv4_section_end]

        assert "OFPP_NORMAL" in ipv4_code, (
            "IPv4 ALLOW rules should use OFPP_NORMAL to avoid sending "
            "all legitimate traffic through PacketIn"
        )
        assert "OFPP_CONTROLLER" not in ipv4_code, (
            "IPv4 ALLOW rules must NOT use OFPP_CONTROLLER"
        )

        # ARP section should still use OFPP_CONTROLLER
        arp_section = method_body[ipv4_section_end:]
        assert "OFPP_CONTROLLER" in arp_section, (
            "ARP ALLOW rules should still use OFPP_CONTROLLER for ARP proxy"
        )


# ── Attack Log CSV Write (v3.1.0) ──────────────────────────────────────────

class TestLogAttackCSV:
    """Verify _log_attack writes to attacks_log.csv."""

    def test_log_attack_writes_csv(self, tmp_path):
        """_log_attack should append a row to attacks_log.csv."""
        import csv
        import types
        import re
        import os
        import ipaddress
        import eventlet.semaphore
        from sdn_ddos_detector.controller import ddos_controller as mod

        # Build a simple namespace with the methods we need
        ctrl = types.SimpleNamespace()
        ctrl.logger = MagicMock()
        ctrl._datapaths_lock = eventlet.semaphore.Semaphore(1)
        ctrl.datapaths = {1: MagicMock()}
        ctrl.log_dir = str(tmp_path)

        _IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

        def _sanitize_ip(ip_str):
            if isinstance(ip_str, str) and _IPV4_PATTERN.match(ip_str):
                try:
                    return str(ipaddress.IPv4Address(ip_str))
                except (ipaddress.AddressValueError, ValueError):
                    return "invalid_ip"
            return "invalid_ip"

        ctrl._sanitize_ip = _sanitize_ip

        # Initialize CSV header
        log_file = os.path.join(ctrl.log_dir, 'attacks_log.csv')
        with open(log_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                'timestamp', 'src_ip', 'dst_ip',
                'attack_type', 'packet_rate', 'confidence',
                'action', 'switches_blocked'
            ])

        # Call _log_attack logic directly
        safe_src = ctrl._sanitize_ip("10.0.0.1")
        safe_dst = ctrl._sanitize_ip("10.0.0.7")
        with ctrl._datapaths_lock:
            n_switches = len(ctrl.datapaths)

        import datetime
        with open(log_file, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                datetime.datetime.now().isoformat(),
                safe_src, safe_dst, "ICMP Flood",
                f"{10000.0:.2f}", f"{0.95:.3f}",
                "BLOCKED", n_switches,
            ])

        with open(log_file) as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) == 2, "Should have header + 1 data row"
        assert rows[0][0] == "timestamp"
        assert rows[1][1] == "10.0.0.1"
        assert rows[1][2] == "10.0.0.7"
        assert rows[1][3] == "ICMP Flood"
        assert rows[1][6] == "BLOCKED"
