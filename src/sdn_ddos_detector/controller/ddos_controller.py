#!/usr/bin/env python3
"""
SDN Controller with ML-based DDoS Detection and Mitigation

This Ryu application implements an OpenFlow 1.3 controller that:
1. Manages MAC learning and packet forwarding across the network
2. Collects flow statistics from all connected switches every 3 seconds
3. Aggregates stats network-wide before classification (audit 2.3)
4. Uses a trained Random Forest model to classify flows as normal or attack
5. Installs DROP rules on ALL switches to block detected attacks (audit 2.4)
6. Decouples ML inference from the event loop via green thread queue (audit 2.2)
7. Implements ECMP via group tables instead of STP (audit 5.1)
8. Priority-based flow sampling replaces random sampling (audit 7.2)
9. Monitors flow table capacity with emergency eviction (audit 7.4)

Architecture note (audit 5.3):
    Forwarding uses L2 (eth_src, eth_dst) for speed; blocking uses L3 (ipv4_src)
    for attacker targeting. Priority=100 blocks always override priority=10 forwarding.

Usage:
    ryu-manager ddos_controller.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4 as ipv4_pkt
from ryu.lib import hub
import joblib
import numpy as np
import hashlib
import json
import time
import os
import signal
import re
import ipaddress
import eventlet.semaphore
import eventlet.queue
import logging
import logging.handlers
from collections import namedtuple

# Error handling conventions for this module:
#   - Event handlers: catch specific exceptions, log, continue (never crash controller)
#   - Background threads: broad catch at loop level, specific inside
#   - File I/O: catch IOError specifically
#   - ML inference: catch Exception (sklearn can raise various types), track failures
#   - External commands: never called from controller

# IPv4 validation pattern for log sanitization
_IPV4_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# Import feature definitions from the single source of truth
from sdn_ddos_detector.ml.feature_engineering import (
    FEATURE_NAMES, EXPECTED_FEATURE_COUNT,
    extract_flow_features_from_stats, features_dict_to_array,
)
from sdn_ddos_detector.utils.bounded_cache import (
    BoundedMACTable, BoundedIPCounter, BoundedFloodHistory,
)
from sdn_ddos_detector.utils.logging_config import setup_logging
from sdn_ddos_detector.ml.drift_detector import DriftMonitor
from sdn_ddos_detector.ml.circuit_breaker import MLCircuitBreaker, ThresholdFallbackDetector
from sdn_ddos_detector.config.topology_config import (
    SPINE_DPIDS, LEAF_DPIDS, LEAF_TO_SPINE_PORTS, HOST_PORTS,
    GROUP_ECMP_BASE, GROUP_BCAST_BASE,
    PRIORITY_BLOCK, PRIORITY_ANTI_SPOOF, PRIORITY_FORWARDING,
    PRIORITY_ARP_PROXY, PRIORITY_TABLE_MISS,
    BLOCK_COOKIE, FLOW_TABLE_WARNING_PCT, FLOW_TABLE_CRITICAL_PCT,
    FLOW_TABLE_CHECK_INTERVAL, FLOW_TABLE_DEFAULT_MAX,
    HOST_PORT_ALLOWED_IPS, PRIORITY_ANTI_SPOOF_ALLOW,
    PRIORITY_ANTI_SPOOF_DROP, BLOCK_DST_COOKIE,
)


# =============================================================================
# Constants
# =============================================================================

# Flow statistics polling interval — reduced from 5s to 3s (audit 9.6)
STATS_POLL_INTERVAL = 3

# Allow ryu.conf to override via CONF object
from ryu import cfg as ryu_cfg
ryu_cfg.CONF.register_opts([
    ryu_cfg.IntOpt('stats_poll_interval', default=3,
                   help='Flow stats polling interval in seconds'),
    ryu_cfg.FloatOpt('confidence_threshold', default=0.7,
                     help='ML prediction confidence cutoff (0.0-1.0)'),
    ryu_cfg.IntOpt('block_rule_timeout', default=300,
                   help='DROP rule auto-expiry in seconds'),
    ryu_cfg.IntOpt('packet_in_rate_limit', default=100,
                   help='Max PacketIn events per switch per second'),
    ryu_cfg.IntOpt('max_macs_per_port', default=5,
                   help='Port security: max MACs per port per switch'),
    ryu_cfg.IntOpt('packetin_buffer_size', default=0xFFFF,
                   help='PacketIn max_len (0xFFFF=OFPCML_NO_BUFFER for full '
                        'packets needed for DDoS entropy calculation)'),
])

# Normal forwarding flow timeouts
FORWARDING_IDLE_TIMEOUT = 30
FORWARDING_HARD_TIMEOUT = 120

# PacketIn rate limiting
PACKET_IN_RATE_LIMIT = 100
PACKET_IN_WINDOW_SEC = 1.0

# Ethertypes
LLDP_ETHERTYPE = 0x88cc
IPV4_ETHERTYPE = 0x0800
IPV6_ETHERTYPE = 0x86DD
ARP_ETHERTYPE = 0x0806

# Model integrity hash file name
MODEL_HASH_FILE = 'model_hashes.json'

# MAC table aging
MAC_AGE_TIMEOUT = 300

# Max MACs per port
MAX_MACS_PER_PORT = 5

# Confidence threshold
CONFIDENCE_THRESHOLD = 0.7

# Flood rate limiting — per-switch, independent of MAC (audit 3.4)
FLOOD_RATE_LIMIT = 50
MAX_FLOODS_PER_SWITCH_PER_SECOND = 100
FLOOD_RATE_WINDOW_SEC = 1.0

# Priority-based flow sampling (audit 7.2)
# Always classify top N flows + all flows above PPS threshold
FLOW_SAMPLE_TOP_N = 500
FLOW_SAMPLE_PPS_THRESHOLD = 100

# ML inference queue and timeout
INFERENCE_QUEUE_MAXSIZE = 1000
ML_INFERENCE_TIMEOUT = 4  # seconds

# Stats reply collection deadline
STATS_REPLY_DEADLINE = 2  # seconds

# Syslog integration
SYSLOG_ADDRESS = '/dev/log'
SYSLOG_FACILITY = logging.handlers.SysLogHandler.LOG_LOCAL0

# Batch for ML inference
InferenceBatch = namedtuple('InferenceBatch', ['features', 'metadata', 'dpid'])


class PacketInRateLimiter:
    """Sliding-window rate limiter for PacketIn events per switch."""

    def __init__(self, rate_limit=None, window_sec=PACKET_IN_WINDOW_SEC):
        if rate_limit is None:
            rate_limit = ryu_cfg.CONF.packet_in_rate_limit
        self.rate_limit = rate_limit
        self.window_sec = window_sec
        self._counters = {}
        self._window_start = {}

    def allow(self, dpid):
        now = time.time()
        if dpid not in self._window_start:
            self._window_start[dpid] = now
            self._counters[dpid] = 0
        elapsed = now - self._window_start[dpid]
        if elapsed >= self.window_sec:
            self._window_start[dpid] = now
            self._counters[dpid] = 0
        if self._counters[dpid] >= self.rate_limit:
            return False
        self._counters[dpid] += 1
        return True


class FloodRateLimiter:
    """Rate limiter for flood (broadcast) packets per switch.

    Implements a per-switch rate limit INDEPENDENT of MAC addresses (audit 3.4).
    This prevents MAC rotation attacks from bypassing flood suppression.
    """

    def __init__(self, rate_limit=MAX_FLOODS_PER_SWITCH_PER_SECOND,
                 window_sec=FLOOD_RATE_WINDOW_SEC):
        self.rate_limit = rate_limit
        self.window_sec = window_sec
        self._counters = {}
        self._window_start = {}

    def allow(self, dpid):
        now = time.time()
        if dpid not in self._window_start:
            self._window_start[dpid] = now
            self._counters[dpid] = 0
        elapsed = now - self._window_start[dpid]
        if elapsed >= self.window_sec:
            self._window_start[dpid] = now
            self._counters[dpid] = 0
        if self._counters[dpid] >= self.rate_limit:
            return False
        self._counters[dpid] += 1
        return True


def _verify_model_integrity(model_path, config_dir, logger):
    """Verify model file integrity using HMAC-SHA256 or SHA-256 fallback.

    SECURITY: Returns False (refuses to load) in ALL failure cases:
    - Hash file missing
    - Hash mismatch
    - HMAC key not configured (falls back to SHA-256 with warning)
    """
    import hmac as hmac_mod

    hash_file = os.path.join(config_dir, "model_checksums.hmac")

    if not os.path.exists(hash_file):
        logger.critical(
            "Model hash file MISSING at %s — REFUSING to load model. "
            "Run: python -m sdn_ddos_detector.scripts.sign_model %s",
            hash_file, model_path
        )
        return False

    hmac_key = os.environ.get("SDN_MODEL_HMAC_KEY", "").encode()
    if not hmac_key:
        logger.warning(
            "SDN_MODEL_HMAC_KEY not set — using SHA-256 only (reduced security)."
        )

    try:
        with open(model_path, "rb") as f:
            file_bytes = f.read()
    except IOError as e:
        logger.error("Failed to read model file %s: %s", model_path, str(e))
        return False

    if hmac_key:
        actual_hash = hmac_mod.new(hmac_key, file_bytes, hashlib.sha256).hexdigest()
    else:
        actual_hash = hashlib.sha256(file_bytes).hexdigest()

    try:
        with open(hash_file, "r") as f:
            checksums = json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error("Failed to read hash file %s: %s", hash_file, str(e))
        return False

    model_name = os.path.basename(model_path)
    expected_hash = checksums.get(model_name)

    if expected_hash is None:
        logger.critical("No hash entry for %s in %s", model_name, hash_file)
        return False

    if not hmac_mod.compare_digest(actual_hash, expected_hash):
        logger.critical(
            "Model integrity FAILED for %s. Expected: %s..., Got: %s...",
            model_name, expected_hash[:16], actual_hash[:16]
        )
        return False

    logger.info("Model integrity verified for %s", model_name)
    return True


class DDoSDetectionController(app_manager.RyuApp):
    """Ryu SDN controller with ML-based DDoS detection and mitigation.

    Architecture (audit 2.2):
        Event loop handles PacketIn/switch events only (no ML).
        Stats monitor thread collects from ALL switches, aggregates network-wide.
        ML inference runs in a separate green thread via producer-consumer queue.
        Latency budget: 3s poll + 0.5s features + 0.5s inference + 0.5s rules = ~4.5s

    Mitigation (audit 2.4):
        Block rules installed on ALL switches, not just the reporting switch.
        Uses cookie=0xDEAD for bulk identification and deletion.

    Forwarding (audit 5.1, 5.3):
        ECMP via OpenFlow group tables (SELECT) replaces STP.
        L2 forwarding at priority=10, L3 blocking at priority=100.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSDetectionController, self).__init__(*args, **kwargs)

        # Async logging
        self._log_listener = setup_logging(log_dir="logs/")

        # eventlet-safe locks
        self._mac_lock = eventlet.semaphore.Semaphore(1)
        self._blocked_lock = eventlet.semaphore.Semaphore(1)
        self._datapaths_lock = eventlet.semaphore.Semaphore(1)
        self._flood_lock = eventlet.semaphore.Semaphore(1)

        # MAC address table with TTL-based eviction
        self.mac_to_port = BoundedMACTable(maxsize=4096, ttl=120)
        self._port_macs = BoundedMACTable(maxsize=2048, ttl=300)

        # Connected switches: {dpid: datapath} (audit 2.4)
        self.datapaths = {}

        # Active block rules: {(src_ip, dst_ip, ip_proto): expiry_timestamp}
        # Network-wide, not per-switch (audit 2.4)
        self.blocked_ips = BoundedIPCounter(maxsize=10000, ttl=300)

        # Rate limiters
        self._packet_in_limiter = PacketInRateLimiter()
        self._flood_limiter = FloodRateLimiter()

        # Broadcast loop prevention
        self._flood_history = BoundedFloodHistory(maxsize=512)
        self._flood_suppress_window = 1.0

        # ARP proxy cache: {ip: mac} for ARP response
        self._arp_cache = {}

        # Shutdown flag
        self._shutting_down = False

        # ADWIN drift detection (audit 4.7)
        self.drift_monitor = DriftMonitor(delta=0.002, window_size=1000)

        # Circuit breaker for ML inference (audit 8.3)
        self.circuit_breaker = MLCircuitBreaker(fail_max=5, reset_timeout=30)
        self.fallback_detector = ThresholdFallbackDetector()

        # ML inference queue (audit 2.2) — decouples inference from event loop
        self.inference_queue = eventlet.queue.LightQueue(
            maxsize=INFERENCE_QUEUE_MAXSIZE
        )

        # Previous flow stats for rate-of-change features (audit 9.7)
        # {(dpid, match_key): {packet_count, byte_count, timestamp}}
        self._prev_flow_stats = {}

        # Flow table capacity tracking (audit 7.4)
        self._flow_table_sizes = {}

        # Network-wide aggregates from last stats collection (audit 2.3)
        self._network_dst_flow_counts = {}
        self._network_dst_source_sets = {}
        self._pending_stats_replies = {}

        # ML model and scaler
        self.model = None
        self.scaler = None

        # Load ML model with integrity verification
        script_dir = os.path.dirname(os.path.abspath(__file__))
        ml_dir = os.path.join(script_dir, '..', 'ml')
        self.config_dir = os.path.join(script_dir, '..', 'config')
        model_path = os.path.join(ml_dir, 'flow_model.pkl')
        scaler_path = os.path.join(ml_dir, 'scaler.pkl')

        try:
            for artifact_path in [model_path, scaler_path]:
                if not _verify_model_integrity(
                    artifact_path, self.config_dir, self.logger
                ):
                    raise ValueError(
                        f"Model integrity verification failed for "
                        f"{os.path.basename(artifact_path)}."
                    )
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("ML model loaded successfully")
        except FileNotFoundError:
            self.logger.warning(
                "ML model files not found. Controller will operate without "
                "DDoS detection. Train the model first."
            )
        except ValueError as e:
            self.logger.critical("SECURITY: %s", str(e))
        except Exception as e:
            self.logger.error("Failed to load ML model: %s", str(e))

        # Log directory
        project_root = os.path.join(script_dir, '..', '..', '..', '..')
        self.log_dir = os.path.join(project_root, 'logs')
        os.makedirs(self.log_dir, exist_ok=True)
        self._init_attack_log()
        self._restore_state()

        # Health check counter
        self._stats_cycle_count = 0

        # Start background threads
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self._cleanup_thread = hub.spawn(self._periodic_cleanup)
        self._table_monitor_thread = hub.spawn(self._flow_table_monitor)

        # ML inference worker thread (audit 2.2)
        if self.model is not None:
            self._ml_worker = hub.spawn(self._ml_inference_loop)

        # Syslog
        self._setup_syslog()

        # Graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # TLS warning (audit 1.4)
        if not (hasattr(ryu_cfg.CONF, 'ctl_privkey') and ryu_cfg.CONF.ctl_privkey):
            self.logger.warning(
                "TLS is NOT configured for the OpenFlow channel. "
                "The control plane is vulnerable to MITM attacks. "
                "Run scripts/setup_tls.sh and uncomment TLS options in ryu.conf."
            )

        # REST API auth check (audit 3.1)
        api_token = os.environ.get('SDN_API_TOKEN', '')
        if not api_token:
            self.logger.warning(
                "SDN_API_TOKEN not set — REST API relies on 127.0.0.1 binding only. "
                "Set SDN_API_TOKEN env var for bearer token authentication."
            )

        self.logger.info("DDoS Detection Controller initialized")
        self.logger.info(
            "Config: stats_poll=%ds, confidence=%.2f, block_timeout=%ds, "
            "inference_timeout=%ds",
            ryu_cfg.CONF.stats_poll_interval,
            ryu_cfg.CONF.confidence_threshold,
            ryu_cfg.CONF.block_rule_timeout,
            ML_INFERENCE_TIMEOUT
        )

    # =========================================================================
    # Graceful shutdown
    # =========================================================================

    def _signal_handler(self, signum, frame):
        sig_name = signal.Signals(signum).name
        self.logger.info("Received %s — initiating graceful shutdown...", sig_name)
        self._shutting_down = True
        self._save_state()
        if hasattr(self, '_log_listener') and self._log_listener is not None:
            self._log_listener.stop()

    def close(self):
        self._shutting_down = True
        self._save_state()
        self.logger.info("Controller shutting down")
        if hasattr(self, '_log_listener') and self._log_listener is not None:
            self._log_listener.stop()
        super(DDoSDetectionController, self).close()

    # =========================================================================
    # State persistence
    # =========================================================================

    def _get_state_path(self):
        return os.path.join(self.log_dir, 'controller_state.json')

    def _save_state(self):
        state_path = self._get_state_path()
        try:
            with self._blocked_lock:
                now = time.time()
                active_blocks = {
                    f"{src}|{dst}|{proto}": expiry
                    for (src, dst, proto), expiry
                    in self.blocked_ips.items()
                    if expiry > now
                }
            state = {
                'version': 2,
                'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'blocked_ips': active_blocks,
            }
            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2)
            self.logger.info("Saved state (%d active blocks)", len(active_blocks))
        except (IOError, TypeError) as e:
            self.logger.error("Failed to save state: %s", str(e))

    def _restore_state(self):
        state_path = self._get_state_path()
        if not os.path.isfile(state_path):
            return
        try:
            with open(state_path, 'r') as f:
                state = json.load(f)
            version = state.get('version', 1)
            now = time.time()
            restored = 0
            for key_str, expiry in state.get('blocked_ips', {}).items():
                if expiry <= now:
                    continue
                parts = key_str.split('|')
                if version == 1 and len(parts) == 4:
                    # Legacy format: dpid|src|dst|proto
                    _, src, dst, proto = parts[0], parts[1], parts[2], int(parts[3])
                    self.blocked_ips[(src, dst, proto)] = expiry
                    restored += 1
                elif version >= 2 and len(parts) == 3:
                    src, dst, proto = parts[0], parts[1], int(parts[2])
                    self.blocked_ips[(src, dst, proto)] = expiry
                    restored += 1
            if restored:
                self.logger.info("Restored %d active block entries", restored)
            os.remove(state_path)
        except (IOError, json.JSONDecodeError, ValueError) as e:
            self.logger.error("Failed to restore state: %s", str(e))

    # =========================================================================
    # Init helpers
    # =========================================================================

    def _init_attack_log(self):
        log_file = os.path.join(self.log_dir, 'attacks_log.csv')
        if not os.path.isfile(log_file):
            try:
                import csv
                with open(log_file, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'timestamp', 'src_ip', 'dst_ip',
                        'attack_type', 'packet_rate', 'confidence',
                        'action', 'switches_blocked'
                    ])
            except IOError as e:
                self.logger.error("Failed to initialize attack log: %s", str(e))

    def _setup_syslog(self):
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=SYSLOG_ADDRESS, facility=SYSLOG_FACILITY
            )
            syslog_handler.setLevel(logging.WARNING)
            syslog_fmt = logging.Formatter(
                'SDN-DDoS[%(process)d]: %(levelname)s %(message)s'
            )
            syslog_handler.setFormatter(syslog_fmt)
            self.logger.addHandler(syslog_handler)
        except (OSError, ConnectionError):
            self.logger.info("Syslog not available — SIEM logging disabled")

    # =========================================================================
    # Flow entry helpers
    # =========================================================================

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, cookie=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]
        flow_mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=instructions, idle_timeout=idle_timeout,
            hard_timeout=hard_timeout, cookie=cookie,
        )
        datapath.send_msg(flow_mod)

    def _random_block_timeout(self):
        import random
        timeout = ryu_cfg.CONF.block_rule_timeout
        return random.randint(int(timeout * 0.8), int(timeout * 1.2))

    @staticmethod
    def _sanitize_ip(ip_str):
        if isinstance(ip_str, str) and _IPV4_PATTERN.match(ip_str):
            return ip_str
        return 'INVALID'

    # =========================================================================
    # MAC learning with aging and port security
    # =========================================================================

    def _learn_mac(self, dpid, mac, port):
        with self._mac_lock:
            self.mac_to_port.setdefault(dpid, {})
            self._port_macs.setdefault(dpid, {})
            self._port_macs[dpid].setdefault(port, set())
            port_mac_set = self._port_macs[dpid][port]
            if mac not in port_mac_set:
                if len(port_mac_set) >= ryu_cfg.CONF.max_macs_per_port:
                    self.logger.warning(
                        "Port security violation dpid=%s port=%s MAC=%s",
                        dpid, port, mac
                    )
                    return False
                port_mac_set.add(mac)
            self.mac_to_port[dpid][mac] = (port, time.time())
            return True

    def _lookup_mac(self, dpid, mac):
        with self._mac_lock:
            if dpid not in self.mac_to_port:
                return None
            entry = self.mac_to_port[dpid].get(mac)
            if entry is None:
                return None
            port, timestamp = entry
            if time.time() - timestamp > MAC_AGE_TIMEOUT:
                del self.mac_to_port[dpid][mac]
                if dpid in self._port_macs and port in self._port_macs[dpid]:
                    self._port_macs[dpid][port].discard(mac)
                return None
            return port

    def _age_mac_table(self):
        now = time.time()
        total_evicted = 0
        with self._mac_lock:
            for dpid in list(self.mac_to_port.keys()):
                expired_macs = [
                    mac for mac, (port, ts) in self.mac_to_port[dpid].items()
                    if now - ts > MAC_AGE_TIMEOUT
                ]
                for mac in expired_macs:
                    port, _ = self.mac_to_port[dpid][mac]
                    del self.mac_to_port[dpid][mac]
                    if dpid in self._port_macs and port in self._port_macs[dpid]:
                        self._port_macs[dpid][port].discard(mac)
                    total_evicted += 1
        if total_evicted:
            self.logger.info("Aged out %d MAC entries", total_evicted)

    # =========================================================================
    # Flood suppression (audit 3.4)
    # =========================================================================

    def _should_suppress_flood(self, dpid, src_mac, dst_mac, ethertype):
        """Check if flood should be suppressed.

        Two-level check (audit 3.4):
        1. Per-switch rate limit (independent of MACs — prevents MAC rotation bypass)
        2. Per-flow dedup (prevents duplicate floods within window)
        """
        # Level 1: Per-switch rate limit (MAC-independent)
        if not self._flood_limiter.allow(dpid):
            return True

        # Level 2: Per-flow dedup
        flood_key = (dpid, src_mac, dst_mac, ethertype)
        now = time.time()
        with self._flood_lock:
            if flood_key in self._flood_history:
                last_flood = self._flood_history[flood_key]
                if now - last_flood < self._flood_suppress_window:
                    return True
            self._flood_history[flood_key] = now
            return False

    # =========================================================================
    # Switch state tracking (audit 2.4)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Track switch connections and disconnections."""
        datapath = ev.datapath
        dpid = datapath.id

        if ev.state == MAIN_DISPATCHER:
            with self._datapaths_lock:
                self.datapaths[dpid] = datapath
            self.logger.info("Switch connected: dpid=%s", dpid)
        elif ev.state == DEAD_DISPATCHER:
            with self._datapaths_lock:
                self.datapaths.pop(dpid, None)
            self.logger.info("Switch disconnected: dpid=%s", dpid)

    # =========================================================================
    # Switch features handler with ECMP group tables (audit 5.1)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connections. Install table-miss and ECMP groups."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        with self._datapaths_lock:
            self.datapaths[dpid] = datapath

        # Table-miss: send to controller
        # PacketIn buffer size is configurable (audit 5.4)
        buffer_size = ryu_cfg.CONF.packetin_buffer_size
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, buffer_size)]
        self._add_flow(datapath, priority=PRIORITY_TABLE_MISS,
                       match=match, actions=actions)

        # Install ECMP group tables on leaf switches (audit 5.1)
        if dpid in LEAF_DPIDS:
            self._install_ecmp_groups(datapath)
            self._install_anti_spoof_rules(datapath)

        self.logger.info("Switch configured: dpid=%s (leaf=%s)",
                         dpid, dpid in LEAF_DPIDS)

    def _install_ecmp_groups(self, datapath):
        """Install ECMP SELECT group table for spine uplinks on a leaf switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        uplink_ports = LEAF_TO_SPINE_PORTS.get(dpid, [])
        if not uplink_ports:
            return

        # ECMP group: SELECT type for load balancing across spine uplinks
        group_id = GROUP_ECMP_BASE + dpid
        buckets = []
        for port in uplink_ports:
            bucket = parser.OFPBucket(
                weight=1,
                actions=[parser.OFPActionOutput(port)]
            )
            buckets.append(bucket)

        group_mod = parser.OFPGroupMod(
            datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_SELECT,
            group_id, buckets
        )
        datapath.send_msg(group_mod)

        # Broadcast group: ALL type for flooding to all ports
        bcast_group_id = GROUP_BCAST_BASE + dpid
        host_ports = HOST_PORTS.get(dpid, [])
        bcast_buckets = []
        for port in host_ports + uplink_ports:
            bcast_buckets.append(
                parser.OFPBucket(actions=[parser.OFPActionOutput(port)])
            )

        bcast_group_mod = parser.OFPGroupMod(
            datapath, ofproto.OFPGC_ADD, ofproto.OFPGT_ALL,
            bcast_group_id, bcast_buckets
        )
        datapath.send_msg(bcast_group_mod)

        self.logger.info(
            "ECMP groups installed on dpid=%s: ECMP(group=%d, ports=%s), "
            "BCAST(group=%d)",
            dpid, group_id, uplink_ports, bcast_group_id
        )

    # =========================================================================
    # Anti-spoofing rules (audit 1.3, 5.5)
    # =========================================================================

    def _install_anti_spoof_rules(self, datapath):
        """Install BCP38 anti-spoofing rules on leaf host-facing ports.

        For each host-facing port:
          Priority 50: ALLOW IP packets with matching source IP → forward normally
          Priority 40: DROP all other IP packets on that port → [] (catches spoofed)
          Priority 50: ALLOW ARP with matching arp_spa → forward normally
          Priority 40: DROP ARP with non-matching arp_spa → [] (catches ARP spoofing)
        """
        dpid = datapath.id
        parser = datapath.ofproto_parser
        port_ips = HOST_PORT_ALLOWED_IPS.get(dpid, {})

        if not port_ips:
            return

        for port_no, (allowed_ip, allowed_mask) in port_ips.items():
            # IPv4: ALLOW matching source IP on this port
            match_allow = parser.OFPMatch(
                in_port=port_no, eth_type=IPV4_ETHERTYPE,
                ipv4_src=(allowed_ip, allowed_mask),
            )
            # Action: send to table (normal processing) — empty instruction
            # means "continue to next table" but since we use single table,
            # we use GOTO or just don't install a DROP. The ALLOW rule at
            # priority 50 will match before the DROP at priority 40.
            # We use a no-op flow that just lets the packet continue matching.
            ofproto = datapath.ofproto
            actions_allow = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            # Actually, we want to let normal forwarding handle it.
            # Priority 50 ALLOW = just let it through (match and do nothing special,
            # so it falls to priority 10 forwarding). Use "goto table" or just
            # install with a controller action to trigger normal PacketIn handling.
            # Simplest: install a flow that outputs to CONTROLLER so normal
            # PacketIn processing occurs.
            self._add_flow(
                datapath, priority=PRIORITY_ANTI_SPOOF_ALLOW,
                match=match_allow,
                actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                ofproto.OFPCML_NO_BUFFER)],
            )

            # IPv4: DROP all other source IPs on this port (catches spoofed)
            match_drop = parser.OFPMatch(
                in_port=port_no, eth_type=IPV4_ETHERTYPE,
            )
            self._add_flow(
                datapath, priority=PRIORITY_ANTI_SPOOF_DROP,
                match=match_drop, actions=[],
            )

            # ARP: ALLOW matching arp_spa on this port
            match_arp_allow = parser.OFPMatch(
                in_port=port_no, eth_type=ARP_ETHERTYPE,
                arp_spa=(allowed_ip, allowed_mask),
            )
            self._add_flow(
                datapath, priority=PRIORITY_ANTI_SPOOF_ALLOW,
                match=match_arp_allow,
                actions=[parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                ofproto.OFPCML_NO_BUFFER)],
            )

            # ARP: DROP non-matching arp_spa on this port
            match_arp_drop = parser.OFPMatch(
                in_port=port_no, eth_type=ARP_ETHERTYPE,
            )
            self._add_flow(
                datapath, priority=PRIORITY_ANTI_SPOOF_DROP,
                match=match_arp_drop, actions=[],
            )

        self.logger.info(
            "Anti-spoofing rules installed on dpid=%s: %d ports",
            dpid, len(port_ips)
        )

    # =========================================================================
    # Packet-In handler
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        if not self._packet_in_limiter.allow(dpid):
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == LLDP_ETHERTYPE:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # ARP proxy: cache and respond directly for known hosts
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth, arp_pkt, msg)
            return

        # Learn MAC
        if not self._learn_mac(dpid, src_mac, in_port):
            return  # Port security violation

        # Lookup destination
        out_port_lookup = self._lookup_mac(dpid, dst_mac)

        if out_port_lookup is not None:
            out_port = out_port_lookup
        else:
            if self._should_suppress_flood(dpid, src_mac, dst_mac, eth.ethertype):
                return
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_dst=dst_mac, eth_src=src_mac
            )
            self._add_flow(
                datapath, priority=PRIORITY_FORWARDING, match=match,
                actions=actions, idle_timeout=FORWARDING_IDLE_TIMEOUT,
                hard_timeout=FORWARDING_HARD_TIMEOUT,
            )

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)

    def _handle_arp(self, datapath, in_port, eth, arp_pkt, msg):
        """ARP proxy: cache IP→MAC mappings, respond to requests for known hosts."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Learn sender
        self._learn_mac(dpid, eth.src, in_port)
        self._arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac

        if arp_pkt.opcode == arp.ARP_REQUEST:
            dst_mac = self._arp_cache.get(arp_pkt.dst_ip)
            if dst_mac:
                # Reply directly
                reply_pkt = packet.Packet()
                reply_pkt.add_protocol(ethernet.ethernet(
                    ethertype=ARP_ETHERTYPE, dst=eth.src, src=dst_mac,
                ))
                reply_pkt.add_protocol(arp.arp(
                    opcode=arp.ARP_REPLY, src_mac=dst_mac,
                    src_ip=arp_pkt.dst_ip, dst_mac=arp_pkt.src_mac,
                    dst_ip=arp_pkt.src_ip,
                ))
                reply_pkt.serialize()
                actions = [parser.OFPActionOutput(in_port)]
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=reply_pkt.data,
                )
                datapath.send_msg(out)
                return

        # Unknown target: flood the ARP
        if self._should_suppress_flood(dpid, eth.src, eth.dst, eth.ethertype):
            return
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)

    # =========================================================================
    # Network-wide stats monitor (audit 2.3, 9.6)
    # =========================================================================

    def _monitor_loop(self):
        """Periodically collect flow stats from ALL switches simultaneously.

        Phase 1: Send OFPFlowStatsRequest to all datapaths
        Phase 2: Wait for replies with deadline
        Phase 3: Aggregate network-wide, then enqueue for ML inference
        """
        while not self._shutting_down:
            self._stats_cycle_count += 1

            # Health status every 20 cycles (~60s at 3s interval)
            if self._stats_cycle_count % 20 == 0:
                ml_status = "ACTIVE" if self.model is not None else "DISABLED"
                with self._datapaths_lock:
                    n_switches = len(self.datapaths)
                with self._blocked_lock:
                    n_blocked = len(self.blocked_ips)
                self.logger.info(
                    "HEALTH: cycle=%d, switches=%d, blocked=%d, ml=%s",
                    self._stats_cycle_count, n_switches, n_blocked, ml_status
                )

            # Phase 1: Request stats from all switches simultaneously
            with self._datapaths_lock:
                dp_snapshot = dict(self.datapaths)

            if dp_snapshot:
                # Reset pending collection
                self._pending_stats_replies = {}

                for dpid, datapath in dp_snapshot.items():
                    try:
                        parser = datapath.ofproto_parser
                        ofproto = datapath.ofproto
                        request = parser.OFPFlowStatsRequest(
                            datapath, 0, ofproto.OFPTT_ALL,
                            ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                            0, 0, parser.OFPMatch()
                        )
                        datapath.send_msg(request)
                        self._pending_stats_replies[dpid] = None  # awaiting
                    except Exception as e:
                        self.logger.error(
                            "Failed to request stats from dpid=%s: %s", dpid, str(e)
                        )

                # Phase 2: Wait for replies with deadline
                deadline = time.time() + STATS_REPLY_DEADLINE
                while time.time() < deadline:
                    if all(v is not None
                           for v in self._pending_stats_replies.values()):
                        break
                    hub.sleep(0.1)

                # Phase 3: Aggregate and enqueue
                self._aggregate_and_enqueue()

            hub.sleep(ryu_cfg.CONF.stats_poll_interval)

        self.logger.info("Monitor thread exiting (shutdown)")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Collect stats replies into pending buffer for network-wide aggregation."""
        dpid = ev.msg.datapath.id
        if dpid in self._pending_stats_replies:
            self._pending_stats_replies[dpid] = ev.msg.body

    def _aggregate_and_enqueue(self):
        """Aggregate stats across all switches and enqueue for ML inference.

        Counts packets/bytes only at ingress leaf switch to avoid
        ECMP double-counting (audit 2.3).
        """
        if self.model is None or self.scaler is None:
            return

        # Collect all flows from all switches
        all_raw_flows = []
        network_dst_counts = {}
        network_dst_sources = {}

        for dpid, body in self._pending_stats_replies.items():
            if body is None:
                continue

            # Only count traffic at leaf switches (ingress) to avoid
            # double-counting flows that traverse multiple switches via ECMP
            is_leaf = dpid in LEAF_DPIDS

            for stat in body:
                if stat.priority == 0:
                    continue
                if stat.match.get('ipv4_src', 'unknown') == 'unknown' and \
                   stat.match.get('ipv4_dst', 'unknown') == 'unknown':
                    continue

                # Skip negative counters
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
                    'icmp_code': stat.match.get('icmp_code', 0),
                    'icmp_type': stat.match.get('icmp_type', 0),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                }

                # Rate-of-change features (audit 9.7)
                match_key = (dpid, src_ip, dst_ip, ip_proto)
                prev = self._prev_flow_stats.get(match_key)
                if prev:
                    dt = max(0.001, time.time() - prev.get('timestamp', 0))
                    pps_now = stat.packet_count / max(stat.duration_sec, 0.001)
                    pps_prev = prev.get('pps', 0)
                    bps_now = stat.byte_count / max(stat.duration_sec, 0.001)
                    bps_prev = prev.get('bps', 0)
                    flow['pps_delta'] = pps_now - pps_prev
                    flow['bps_delta'] = bps_now - bps_prev
                    flow['pps_acceleration'] = (pps_now - pps_prev) / dt
                else:
                    flow['pps_delta'] = 0
                    flow['bps_delta'] = 0
                    flow['pps_acceleration'] = 0

                # Update previous stats
                self._prev_flow_stats[match_key] = {
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'pps': stat.packet_count / max(stat.duration_sec, 0.001),
                    'bps': stat.byte_count / max(stat.duration_sec, 0.001),
                    'timestamp': time.time(),
                }

                all_raw_flows.append(flow)

                # Network-wide aggregates (audit 2.3)
                if is_leaf and dst_ip != 'unknown':
                    network_dst_counts[dst_ip] = \
                        network_dst_counts.get(dst_ip, 0) + 1
                    if dst_ip not in network_dst_sources:
                        network_dst_sources[dst_ip] = set()
                    if src_ip != 'unknown':
                        network_dst_sources[dst_ip].add(src_ip)

        if not all_raw_flows:
            return

        # Store network-wide aggregates for spoofed-source detection
        self._network_dst_flow_counts = network_dst_counts
        self._network_dst_source_sets = network_dst_sources

        # Priority-based sampling (audit 7.2)
        # Sort by packet rate descending, always classify top N + high-pps flows
        for flow in all_raw_flows:
            dur = max(flow['duration_sec'], 0.001)
            flow['_pps'] = flow['packet_count'] / dur

        all_raw_flows.sort(key=lambda f: f['_pps'], reverse=True)

        if len(all_raw_flows) > FLOW_SAMPLE_TOP_N:
            # Keep top N + all flows above PPS threshold
            sampled = all_raw_flows[:FLOW_SAMPLE_TOP_N]
            for flow in all_raw_flows[FLOW_SAMPLE_TOP_N:]:
                if flow['_pps'] >= FLOW_SAMPLE_PPS_THRESHOLD:
                    sampled.append(flow)
            self.logger.debug(
                "Priority sampled %d/%d flows (top-%d + >%d pps)",
                len(sampled), len(all_raw_flows),
                FLOW_SAMPLE_TOP_N, FLOW_SAMPLE_PPS_THRESHOLD
            )
        else:
            sampled = all_raw_flows

        # Build feature arrays
        batch_features = []
        batch_metadata = []

        for flow in sampled:
            dst_ip = flow['dst_ip']
            flows_to_dst = network_dst_counts.get(dst_ip, 0)
            unique_sources = len(network_dst_sources.get(dst_ip, set()))
            time_window = flow['duration_sec']
            if time_window > 0:
                flow_creation_rate = flows_to_dst / time_window
            else:
                flow_creation_rate = flows_to_dst

            flow_with_agg = dict(flow)
            flow_with_agg['flows_to_dst'] = flows_to_dst
            flow_with_agg['unique_sources_to_dst'] = unique_sources
            flow_with_agg['flow_creation_rate'] = flow_creation_rate

            features_dict = extract_flow_features_from_stats(flow_with_agg)
            feature_values = [features_dict[name] for name in FEATURE_NAMES]
            batch_features.append(feature_values)
            batch_metadata.append({
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'ip_proto': flow['ip_proto'],
                'icmp_type': flow.get('icmp_type', 0),
                'pps': flow['_pps'],
                'dpid': flow['dpid'],
                'pps_delta': flow.get('pps_delta', 0),
                'bps_delta': flow.get('bps_delta', 0),
                'pps_acceleration': flow.get('pps_acceleration', 0),
            })

        if not batch_features:
            return

        features_array = np.array(batch_features)
        batch = InferenceBatch(
            features=features_array, metadata=batch_metadata, dpid=0
        )

        # Non-blocking enqueue (audit 2.2)
        try:
            self.inference_queue.put_nowait(batch)
        except eventlet.queue.Full:
            self.logger.warning(
                "ML inference queue full — dropping batch of %d flows",
                len(batch_features)
            )

    # =========================================================================
    # ML inference worker (audit 2.2)
    # =========================================================================

    def _ml_inference_loop(self):
        """Separate green thread for ML inference. Never blocks the event loop."""
        while not self._shutting_down:
            try:
                batch = self.inference_queue.get(timeout=1)
            except eventlet.queue.Empty:
                continue

            try:
                with hub.Timeout(ML_INFERENCE_TIMEOUT):
                    normalized = self.scaler.transform(batch.features)

                    def _predict(X):
                        return self.model.predict_proba(X)

                    probabilities = self.circuit_breaker.call(
                        _predict, normalized,
                        fallback=lambda X: self.fallback_detector.detect_batch(X)
                    )

                    self._handle_detection_results(probabilities, batch.metadata)

                    # ADWIN drift detection (audit 4.7)
                    attack_probs = probabilities[:, 1]
                    mean_attack_prob = float(attack_probs.mean())
                    drift_result = self.drift_monitor.update(mean_attack_prob)
                    if drift_result.detected:
                        self.logger.warning(
                            "Concept drift detected: %s", drift_result.stats
                        )

            except hub.Timeout:
                self.logger.error(
                    "ML inference timeout (>%ds) for %d flows",
                    ML_INFERENCE_TIMEOUT, len(batch.features)
                )
            except Exception as e:
                self.logger.error("ML inference error: %s", str(e))

        self.logger.info("ML inference worker exiting (shutdown)")

    def _handle_detection_results(self, probabilities, metadata):
        """Process ML predictions and trigger mitigation for detected attacks."""
        for i in range(len(probabilities)):
            attack_prob = probabilities[i][1]

            if attack_prob < ryu_cfg.CONF.confidence_threshold:
                continue

            meta = metadata[i]
            src_ip = meta['src_ip']
            dst_ip = meta['dst_ip']
            ip_proto = meta['ip_proto']

            if src_ip == 'unknown':
                continue

            attack_type = self._get_attack_type(ip_proto, meta['icmp_type'])

            self.logger.warning(
                "DDoS DETECTED: src=%s dst=%s type=%s pps=%.1f conf=%.3f "
                "pps_delta=%.1f accel=%.2f",
                src_ip, dst_ip, attack_type, meta['pps'], attack_prob,
                meta.get('pps_delta', 0), meta.get('pps_acceleration', 0),
            )

            # Check for spoofed-source DDoS (audit 1.3):
            # If many unique sources target the same destination, sources are
            # likely spoofed → block by destination instead of source.
            unique_sources_to_dst = len(
                self._network_dst_source_sets.get(dst_ip, set())
            )
            flows_to_dst = self._network_dst_flow_counts.get(dst_ip, 0)

            # High source entropy: many unique sources to same destination
            is_spoofed_source = (unique_sources_to_dst >= 10
                                 and flows_to_dst >= 15)

            if is_spoofed_source:
                self.logger.warning(
                    "Spoofed-source DDoS: blocking by destination "
                    "dst=%s proto=%s (unique_sources=%d, flows=%d)",
                    dst_ip, ip_proto, unique_sources_to_dst, flows_to_dst
                )
                block_key = ('*', dst_ip, ip_proto)
                now = time.time()
                with self._blocked_lock:
                    existing_expiry = self.blocked_ips.get(block_key)
                    if existing_expiry is not None and now < existing_expiry:
                        continue
                    timeout = self._random_block_timeout()
                    self.blocked_ips[block_key] = now + timeout
                self._block_by_destination(dst_ip, ip_proto, timeout)
            else:
                # Normal case: block by (src, dst, proto)
                block_key = (src_ip, dst_ip, ip_proto)
                now = time.time()
                with self._blocked_lock:
                    existing_expiry = self.blocked_ips.get(block_key)
                    if existing_expiry is not None and now < existing_expiry:
                        continue
                    timeout = self._random_block_timeout()
                    self.blocked_ips[block_key] = now + timeout
                # Install block on ALL switches (audit 2.4)
                self._block_across_all_switches(src_ip, dst_ip, ip_proto, timeout)

            self._log_attack(
                src_ip=src_ip, dst_ip=dst_ip, attack_type=attack_type,
                packet_rate=meta['pps'], confidence=attack_prob,
            )

    # =========================================================================
    # Attack type detection
    # =========================================================================

    def _get_attack_type(self, ip_proto, icmp_type):
        if ip_proto == 1:
            return 'ICMP Flood'
        elif ip_proto == 6:
            return 'SYN Flood'
        elif ip_proto == 17:
            return 'UDP Flood'
        else:
            return f'Unknown (proto={ip_proto})'

    # =========================================================================
    # Network-wide mitigation (audit 2.4)
    # =========================================================================

    def _block_across_all_switches(self, src_ip, dst_ip=None, ip_proto=None,
                                    timeout=None):
        """Install DROP rule on ALL connected switches.

        Installs on leaf switches first (closest to the attack source),
        then spine switches.
        """
        if timeout is None:
            timeout = self._random_block_timeout()

        try:
            ipaddress.IPv4Address(src_ip)
            if dst_ip:
                ipaddress.IPv4Address(dst_ip)
        except (ipaddress.AddressValueError, ValueError):
            self.logger.warning("Invalid IP in block request: src=%s dst=%s",
                                src_ip, dst_ip)
            return

        with self._datapaths_lock:
            dp_snapshot = dict(self.datapaths)

        # Install on leaf switches first, then spines
        leaf_dps = [(dpid, dp) for dpid, dp in dp_snapshot.items()
                    if dpid in LEAF_DPIDS]
        spine_dps = [(dpid, dp) for dpid, dp in dp_snapshot.items()
                     if dpid in SPINE_DPIDS]
        blocked_count = 0

        for dpid, datapath in leaf_dps + spine_dps:
            try:
                parser = datapath.ofproto_parser
                match_fields = {'eth_type': IPV4_ETHERTYPE, 'ipv4_src': src_ip}
                if dst_ip:
                    match_fields['ipv4_dst'] = dst_ip
                if ip_proto and ip_proto > 0:
                    match_fields['ip_proto'] = ip_proto

                match = parser.OFPMatch(**match_fields)
                self._add_flow(
                    datapath, priority=PRIORITY_BLOCK, match=match,
                    actions=[], hard_timeout=timeout, idle_timeout=60,
                    cookie=BLOCK_COOKIE,
                )
                blocked_count += 1
            except Exception as e:
                self.logger.error(
                    "Failed to install block on dpid=%s: %s", dpid, str(e)
                )

        self.logger.info(
            "BLOCKED: src=%s dst=%s proto=%s on %d/%d switches (expires %ds)",
            src_ip, dst_ip, ip_proto, blocked_count, len(dp_snapshot), timeout
        )

    def _block_by_destination(self, dst_ip, ip_proto=None, timeout=None):
        """Block traffic TO a destination IP on ALL switches (audit 1.3).

        Used when source IPs are spoofed (high source entropy).
        Matches on (dst_ip, ip_proto) regardless of source.
        """
        if timeout is None:
            timeout = self._random_block_timeout()

        try:
            ipaddress.IPv4Address(dst_ip)
        except (ipaddress.AddressValueError, ValueError):
            self.logger.warning("Invalid dst IP in block request: %s", dst_ip)
            return

        with self._datapaths_lock:
            dp_snapshot = dict(self.datapaths)

        leaf_dps = [(dpid, dp) for dpid, dp in dp_snapshot.items()
                    if dpid in LEAF_DPIDS]
        spine_dps = [(dpid, dp) for dpid, dp in dp_snapshot.items()
                     if dpid in SPINE_DPIDS]
        blocked_count = 0

        for dpid, datapath in leaf_dps + spine_dps:
            try:
                parser = datapath.ofproto_parser
                match_fields = {'eth_type': IPV4_ETHERTYPE, 'ipv4_dst': dst_ip}
                if ip_proto and ip_proto > 0:
                    match_fields['ip_proto'] = ip_proto
                match = parser.OFPMatch(**match_fields)
                self._add_flow(
                    datapath, priority=PRIORITY_BLOCK, match=match,
                    actions=[], hard_timeout=timeout, idle_timeout=60,
                    cookie=BLOCK_DST_COOKIE,
                )
                blocked_count += 1
            except Exception as e:
                self.logger.error(
                    "Failed to install dst block on dpid=%s: %s", dpid, str(e)
                )

        self.logger.info(
            "BLOCKED BY DST: dst=%s proto=%s on %d/%d switches (expires %ds)",
            dst_ip, ip_proto, blocked_count, len(dp_snapshot), timeout
        )

    def _unblock_ip(self, src_ip):
        """Remove block rules for an IP from ALL switches."""
        with self._datapaths_lock:
            dp_snapshot = dict(self.datapaths)

        for dpid, datapath in dp_snapshot.items():
            try:
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(
                    eth_type=IPV4_ETHERTYPE, ipv4_src=src_ip
                )
                flow_mod = parser.OFPFlowMod(
                    datapath=datapath, command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                    match=match, cookie=BLOCK_COOKIE,
                    cookie_mask=0xFFFFFFFFFFFFFFFF,
                )
                datapath.send_msg(flow_mod)
            except Exception as e:
                self.logger.error(
                    "Failed to unblock %s on dpid=%s: %s", src_ip, dpid, str(e)
                )

    # =========================================================================
    # Flow table capacity monitoring (audit 7.4)
    # =========================================================================

    def _flow_table_monitor(self):
        """Monitor flow table sizes and evict low-priority flows at capacity."""
        while not self._shutting_down:
            hub.sleep(FLOW_TABLE_CHECK_INTERVAL)

            with self._datapaths_lock:
                dp_snapshot = dict(self.datapaths)

            for dpid, datapath in dp_snapshot.items():
                try:
                    parser = datapath.ofproto_parser
                    request = parser.OFPTableStatsRequest(datapath, 0)
                    datapath.send_msg(request)
                except Exception as e:
                    self.logger.error(
                        "Failed to request table stats from dpid=%s: %s",
                        dpid, str(e)
                    )

        self.logger.info("Table monitor thread exiting (shutdown)")

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def _table_stats_reply_handler(self, ev):
        """Handle table stats replies for capacity monitoring."""
        dpid = ev.msg.datapath.id
        datapath = ev.msg.datapath

        for stat in ev.msg.body:
            if stat.table_id != 0:
                continue

            active = stat.active_count
            max_entries = stat.max_entries if stat.max_entries > 0 \
                else FLOW_TABLE_DEFAULT_MAX

            usage = active / max_entries if max_entries > 0 else 0
            self._flow_table_sizes[dpid] = {
                'active': active, 'max': max_entries, 'usage': usage
            }

            if usage >= FLOW_TABLE_CRITICAL_PCT:
                self.logger.critical(
                    "FLOW TABLE CRITICAL: dpid=%s at %d/%d (%.0f%%) — "
                    "evicting low-priority flows",
                    dpid, active, max_entries, usage * 100
                )
                self._evict_low_priority_flows(datapath)
            elif usage >= FLOW_TABLE_WARNING_PCT:
                self.logger.warning(
                    "Flow table high: dpid=%s at %d/%d (%.0f%%)",
                    dpid, active, max_entries, usage * 100
                )

    def _evict_low_priority_flows(self, datapath):
        """Emergency eviction: delete idle forwarding flows to make room."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Delete low-priority forwarding flows (priority <= PRIORITY_FORWARDING)
        # Keep block rules and table-miss
        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=PRIORITY_FORWARDING,
            match=parser.OFPMatch(),
        )
        datapath.send_msg(flow_mod)
        self.logger.info("Evicted forwarding flows on dpid=%s", datapath.id)

    # =========================================================================
    # Periodic cleanup
    # =========================================================================

    def _periodic_cleanup(self):
        while not self._shutting_down:
            hub.sleep(60)
            now = time.time()

            with self._blocked_lock:
                expired_keys = [
                    key for key, expiry in list(self.blocked_ips.items())
                    if now >= expiry
                ]
                for key in expired_keys:
                    self.blocked_ips.pop(key, None)
            if expired_keys:
                self.logger.info("Cleaned %d expired block entries",
                                 len(expired_keys))

            with self._flood_lock:
                old_flood_keys = [
                    key for key, ts in list(self._flood_history.items())
                    if now - ts > self._flood_suppress_window * 10
                ]
                for key in old_flood_keys:
                    self._flood_history.pop(key, None)

            self._age_mac_table()

            # Trim stale prev_flow_stats entries (older than 5 minutes)
            stale_keys = [
                k for k, v in self._prev_flow_stats.items()
                if now - v.get('timestamp', 0) > 300
            ]
            for k in stale_keys:
                del self._prev_flow_stats[k]

        self.logger.info("Cleanup thread exiting (shutdown)")

    # =========================================================================
    # Attack logging
    # =========================================================================

    def _log_attack(self, src_ip, dst_ip, attack_type, packet_rate, confidence):
        safe_src = self._sanitize_ip(src_ip)
        safe_dst = self._sanitize_ip(dst_ip)
        with self._datapaths_lock:
            n_switches = len(self.datapaths)
        self.logger.info(
            "ATTACK_LOG src=%s dst=%s type=%s pps=%.2f confidence=%.3f "
            "action=BLOCKED switches=%d",
            safe_src, safe_dst, attack_type, packet_rate, confidence, n_switches
        )
