#!/usr/bin/env python3
"""
SDN Controller with ML-based DDoS Detection and Mitigation

This Ryu application implements an OpenFlow 1.3 controller that:
1. Manages MAC learning and packet forwarding across the network
2. Collects flow statistics from all connected switches every 5 seconds
3. Extracts 12 features from flow statistics for ML classification
4. Uses a trained Random Forest model to classify flows as normal or attack
5. Installs DROP rules to block detected DDoS attack flows
6. Implements loop prevention via per-switch flooding tracking
7. Rate-limits PacketIn events to prevent controller DoS
8. Verifies ML model integrity via SHA-256 before loading
9. Provides graceful shutdown with signal handling
10. Enforces MAC table aging and port security
11. Uses confidence threshold for ML predictions
12. Samples large flow tables for scalability

Features extracted (in order) — defined in utilities/feature_extractor.py:
    See FEATURE_NAMES in utilities/feature_extractor.py

Usage:
    ryu-manager mitigation_module.py

Requirements:
    - Ryu SDN framework
    - scikit-learn (for model loading)
    - joblib (for model deserialization)
    - numpy

"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4 as ipv4_pkt
from ryu.lib import hub
import joblib
import numpy as np
import hashlib
import json
import time
import csv
import os
import signal
import random
import re
import ipaddress
import eventlet.semaphore
import logging
import logging.handlers

# Error handling conventions for this module:
#   - Event handlers: catch specific exceptions, log, continue (never crash controller)
#   - Background threads: broad catch at loop level, specific inside
#   - File I/O: catch IOError specifically
#   - ML inference: catch Exception (sklearn can raise various types), track failures
#   - External commands: never called from controller (use subprocess in traffic scripts)

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


# =============================================================================
# Constants
# =============================================================================

# Flow statistics polling interval in seconds (default; overridden by ryu.conf)
STATS_POLL_INTERVAL = 5

# Allow ryu.conf to override via CONF object
from ryu import cfg as ryu_cfg
ryu_cfg.CONF.register_opts([
    ryu_cfg.IntOpt('stats_poll_interval', default=5,
                   help='Flow stats polling interval in seconds'),
    ryu_cfg.FloatOpt('confidence_threshold', default=0.7,
                     help='ML prediction confidence cutoff (0.0-1.0)'),
    ryu_cfg.IntOpt('block_rule_timeout', default=300,
                   help='DROP rule auto-expiry in seconds'),
    ryu_cfg.IntOpt('packet_in_rate_limit', default=100,
                   help='Max PacketIn events per switch per second'),
    ryu_cfg.IntOpt('max_macs_per_port', default=5,
                   help='Port security: max MACs per port per switch'),
])

# Block rule priority (highest to override normal forwarding)
BLOCK_RULE_PRIORITY = 32768

# Block rule hard timeout in seconds (default; overridden by ryu.conf)
BLOCK_RULE_TIMEOUT = 300

# Normal forwarding flow timeouts
# Increased from 10/30 to reduce PacketIn churn
FORWARDING_IDLE_TIMEOUT = 30
FORWARDING_HARD_TIMEOUT = 120

# PacketIn rate limiting: max events per switch per second
PACKET_IN_RATE_LIMIT = 100
PACKET_IN_WINDOW_SEC = 1.0

# LLDP ethertype (filtered from packet processing)
LLDP_ETHERTYPE = 0x88cc

# IPv4 ethertype
IPV4_ETHERTYPE = 0x0800

# IPv6 ethertype (detected but not yet classified)
IPV6_ETHERTYPE = 0x86DD

# Model integrity hash file name
MODEL_HASH_FILE = 'model_hashes.json'

# MAC table aging — entries older than this are evicted (seconds)
MAC_AGE_TIMEOUT = 300

# Port security — maximum MACs allowed per port per switch
MAX_MACS_PER_PORT = 5

# Confidence threshold — only block flows with attack probability
# above this threshold. Reduces false positives.
CONFIDENCE_THRESHOLD = 0.7

# Flood rate limiting — max floods per switch per second
FLOOD_RATE_LIMIT = 50
FLOOD_RATE_WINDOW_SEC = 1.0

# Flow sampling — when a stats reply exceeds this many flows,
# sample this fraction for ML classification (1.0 = no sampling)
FLOW_SAMPLE_THRESHOLD = 500
FLOW_SAMPLE_RATIO = 0.3

# Syslog integration for SIEM (set to None to disable)
# On macOS: '/var/run/syslog', on Linux: '/dev/log' or ('siem-host', 514)
SYSLOG_ADDRESS = '/dev/log'
SYSLOG_FACILITY = logging.handlers.SysLogHandler.LOG_LOCAL0


class PacketInRateLimiter:
    """
    Sliding-window rate limiter for PacketIn events per switch.

    Prevents controller DoS by dropping excess PacketIn events when
    a switch exceeds the configured rate limit.
    """

    def __init__(self, rate_limit=None,
                 window_sec=PACKET_IN_WINDOW_SEC):
        if rate_limit is None:
            rate_limit = ryu_cfg.CONF.packet_in_rate_limit
        self.rate_limit = rate_limit
        self.window_sec = window_sec
        self._counters = {}
        self._window_start = {}

    def allow(self, dpid):
        """Check if a PacketIn from the given switch should be processed."""
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
    """
    Rate limiter for flood (broadcast) packets per switch.

    Prevents broadcast storms from overwhelming the network by limiting
    how many OFPP_FLOOD actions are sent per switch per time window.
    """

    def __init__(self, rate_limit=FLOOD_RATE_LIMIT,
                 window_sec=FLOOD_RATE_WINDOW_SEC):
        self.rate_limit = rate_limit
        self.window_sec = window_sec
        self._counters = {}
        self._window_start = {}

    def allow(self, dpid):
        """Check if a flood action on the given switch should be allowed."""
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
    """
    Verify model file integrity using HMAC-SHA256 or SHA-256 fallback.

    SECURITY: Returns False (refuses to load) in ALL failure cases:
    - Hash file missing (audit 1.1: previously returned True → RCE risk)
    - Hash mismatch
    - HMAC key not configured (falls back to SHA-256 with warning)

    Args:
        model_path (str): Path to the model .pkl file.
        config_dir (str): Directory containing model_checksums.hmac.
        logger: Ryu logger instance.

    Returns:
        bool: True only if hash matches. False in all other cases.
    """
    import hmac as hmac_mod

    hash_file = os.path.join(config_dir, "model_checksums.hmac")

    if not os.path.exists(hash_file):
        logger.critical(
            "Model hash file MISSING at %s — REFUSING to load model. "
            "Run: python -m sdn_ddos_detector.scripts.sign_model %s",
            hash_file, model_path
        )
        return False  # NEVER return True when hash file is absent

    hmac_key = os.environ.get("SDN_MODEL_HMAC_KEY", "").encode()
    if not hmac_key:
        logger.warning(
            "SDN_MODEL_HMAC_KEY not set — using SHA-256 only (reduced security). "
            "Set the environment variable for HMAC-SHA256 verification."
        )

    # Compute actual hash
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

    # Load expected hash
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
    """
    Ryu SDN controller application for DDoS detection and mitigation.

    This controller performs three primary functions:
    1. L2 switching with MAC learning for normal packet forwarding
    2. Periodic flow statistics collection from all connected switches
    3. ML-based DDoS detection with automatic flow blocking

    Security features:
    - PacketIn rate limiting to prevent controller DoS
    - SHA-256 model integrity verification before loading
    - Specific flow-tuple DROP rules to prevent self-DoS
    - Broadcast loop prevention via per-switch flood tracking
    - MAC table aging with periodic eviction
    - Port security: max MACs per port
    - ML confidence threshold to reduce false positives
    - Flood rate limiting per switch
    - Flow sampling for large flow tables
    - Graceful shutdown with signal handling
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """Initialize the DDoS Detection Controller."""
        super(DDoSDetectionController, self).__init__(*args, **kwargs)

        # Async logging: QueueHandler + RotatingFileHandler (audit 6.2)
        self._log_listener = setup_logging(log_dir="logs/")

        # eventlet-safe: threading primitives block the C-level thread, freezing the entire
        # Ryu event loop. eventlet equivalents yield cooperatively within green threads.
        self._mac_lock = eventlet.semaphore.Semaphore(1)
        self._blocked_lock = eventlet.semaphore.Semaphore(1)
        self._datapaths_lock = eventlet.semaphore.Semaphore(1)
        self._flood_lock = eventlet.semaphore.Semaphore(1)

        # MAC address to port mapping with TTL-based eviction (bounded)
        # {dpid: {mac: (port, timestamp)}}
        self.mac_to_port = BoundedMACTable(maxsize=4096, ttl=120)

        # Port security — track MACs per port (bounded)
        # {dpid: {port: set(mac_addresses)}}
        self._port_macs = BoundedMACTable(maxsize=2048, ttl=300)

        # Connected switch datapaths: {dpid: datapath}
        self.datapaths = {}

        # Track IPs that already have active block rules (bounded)
        # {(dpid, src_ip, dst_ip, ip_proto): expiry_timestamp}
        self.blocked_ips = BoundedIPCounter(maxsize=10000, ttl=300)

        # PacketIn rate limiter
        self._packet_in_limiter = PacketInRateLimiter()

        # Flood rate limiter per switch
        self._flood_limiter = FloodRateLimiter()

        # Broadcast loop prevention (bounded LRU)
        self._flood_history = BoundedFloodHistory(maxsize=512)
        self._flood_suppress_window = 1.0

        # Graceful shutdown flag
        self._shutting_down = False

        # ADWIN-based concept drift detection (replaces EMA, audit 4.7)
        self.drift_monitor = DriftMonitor(delta=0.002, window_size=1000)

        # Circuit breaker for ML inference (audit 8.3)
        self.circuit_breaker = MLCircuitBreaker(fail_max=5, reset_timeout=30)
        self.fallback_detector = ThresholdFallbackDetector()

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
            # Verify each model file independently (audit 1.1, 1.2)
            for artifact_path in [model_path, scaler_path]:
                if not _verify_model_integrity(
                    artifact_path, self.config_dir, self.logger
                ):
                    raise ValueError(
                        f"Model integrity verification failed for "
                        f"{os.path.basename(artifact_path)}. "
                        f"Refusing to load potentially tampered model files."
                    )

            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("ML model loaded successfully from %s", model_path)
            self.logger.info("Feature scaler loaded successfully from %s",
                             scaler_path)
        except FileNotFoundError:
            self.logger.warning(
                "ML model files not found at %s. "
                "Controller will operate without DDoS detection. "
                "Train the model first: cd ml_model && python3 train_model.py",
                model_path
            )
        except ValueError as e:
            self.logger.critical(
                "SECURITY: %s. "
                "Controller will operate without DDoS detection.",
                str(e)
            )
        except Exception as e:
            self.logger.error(
                "Failed to load ML model: %s. "
                "Controller will operate without DDoS detection.",
                str(e)
            )

        # Ensure logs directory exists (project root /logs/)
        project_root = os.path.join(script_dir, '..', '..', '..', '..')
        self.log_dir = os.path.join(project_root, 'logs')
        os.makedirs(self.log_dir, exist_ok=True)

        # Initialize attack log header once
        self._init_attack_log()

        # Restore persisted state from previous run
        self._restore_state()

        # Health check counter — logs periodic status
        self._stats_cycle_count = 0

        # Start background threads
        self.stats_thread = hub.spawn(self._request_stats)
        self._cleanup_thread = hub.spawn(self._periodic_cleanup)

        # Attach syslog handler for SIEM integration
        self._setup_syslog()

        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        # VLAN awareness not implemented — flat L2 domain assumed
        # Future: add VLAN-aware MAC learning and per-VLAN detection policies

        # System validated in Mininet only — hardware switches may
        # have different flow table limits, timing, and OpenFlow behavior
        self.logger.info("DDoS Detection Controller initialized")
        self.logger.info(
            "Validated in Mininet environment only. "
            "Hardware switch behavior may differ."
        )
        self.logger.info(
            "Encrypted (TLS/HTTPS) traffic is classified by flow-level "
            "features only. Application-layer attacks may evade detection."
        )
        self.logger.info(
            "Config: stats_poll=%ds, confidence_threshold=%.2f, "
            "block_timeout=%ds, packet_in_rate_limit=%d, "
            "mac_age=%ds, max_macs_per_port=%d, flow_sample_threshold=%d",
            ryu_cfg.CONF.stats_poll_interval,
            ryu_cfg.CONF.confidence_threshold,
            ryu_cfg.CONF.block_rule_timeout,
            ryu_cfg.CONF.packet_in_rate_limit,
            MAC_AGE_TIMEOUT, ryu_cfg.CONF.max_macs_per_port,
            FLOW_SAMPLE_THRESHOLD
        )

    # =========================================================================
    # Graceful shutdown
    # =========================================================================

    def _signal_handler(self, signum, frame):
        """
        Handle SIGTERM/SIGINT for graceful shutdown.

        Sets the shutdown flag and logs the event. Background threads
        check this flag and exit their loops cleanly.

        Args:
            signum: Signal number received.
            frame: Current stack frame (unused).
        """
        sig_name = signal.Signals(signum).name
        self.logger.info(
            "Received %s — initiating graceful shutdown...", sig_name
        )
        self._shutting_down = True

        # Persist state before shutdown
        self._save_state()

        # Log final statistics
        self.logger.info(
            "Shutdown stats: %d switches connected, %d active block rules",
            len(self.datapaths), len(self.blocked_ips)
        )

        # Stop async log listener
        if hasattr(self, '_log_listener') and self._log_listener is not None:
            self._log_listener.stop()

    def close(self):
        """
        Clean up resources on application shutdown.

        Called by Ryu framework during app teardown.
        Persists state before exit and stops async log listener.
        """
        self._shutting_down = True
        self._save_state()
        self.logger.info("Controller shutting down, cleaning up resources")
        if hasattr(self, '_log_listener') and self._log_listener is not None:
            self._log_listener.stop()
        super(DDoSDetectionController, self).close()

    # =========================================================================
    # State persistence (save/restore across restarts)
    # =========================================================================

    def _get_state_path(self):
        """Return path to the controller state file."""
        return os.path.join(self.log_dir, 'controller_state.json')

    def _save_state(self):
        """
        Persist blocked_ips to disk for recovery after restart.

        Saves active block entries so they can be restored.
        """
        state_path = self._get_state_path()
        try:
            with self._blocked_lock:
                now = time.time()
                # Only save entries that haven't expired
                active_blocks = {
                    # Convert tuple key to string for JSON
                    f"{dpid}|{src}|{dst}|{proto}": expiry
                    for (dpid, src, dst, proto), expiry
                    in self.blocked_ips.items()
                    if expiry > now
                }

            state = {
                'version': 1,
                'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
                'blocked_ips': active_blocks,
            }

            with open(state_path, 'w') as f:
                json.dump(state, f, indent=2)

            self.logger.info(
                "Saved state (%d active blocks) to %s",
                len(active_blocks), state_path
            )
        except (IOError, TypeError) as e:
            self.logger.error("Failed to save state: %s", str(e))

    def _restore_state(self):
        """
        Restore blocked_ips from disk after restart.

        Re-populates in-memory state from last save.
        """
        state_path = self._get_state_path()
        if not os.path.isfile(state_path):
            return

        try:
            with open(state_path, 'r') as f:
                state = json.load(f)

            if state.get('version') != 1:
                self.logger.warning("Unknown state version, skipping restore")
                return

            now = time.time()
            restored = 0
            for key_str, expiry in state.get('blocked_ips', {}).items():
                if expiry <= now:
                    continue  # Already expired
                parts = key_str.split('|')
                if len(parts) != 4:
                    continue
                dpid, src, dst, proto = int(parts[0]), parts[1], parts[2], int(parts[3])
                self.blocked_ips[(dpid, src, dst, proto)] = expiry
                restored += 1

            if restored:
                self.logger.info(
                    "Restored %d active block entries from %s",
                    restored, state_path
                )

            # Clean up state file after successful restore
            os.remove(state_path)

        except (IOError, json.JSONDecodeError, ValueError) as e:
            self.logger.error("Failed to restore state: %s", str(e))

    # =========================================================================
    # INIT HELPER: Set up attack log file with headers
    # =========================================================================

    def _init_attack_log(self):
        """
        Initialize the attacks_log.csv file with headers if it doesn't exist.

        Called once during __init__.
        """
        log_file = os.path.join(self.log_dir, 'attacks_log.csv')
        if not os.path.isfile(log_file):
            try:
                with open(log_file, 'w', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow([
                        'timestamp', 'src_ip', 'dst_ip',
                        'attack_type', 'packet_rate', 'confidence',
                        'action', 'switch'
                    ])
            except IOError as e:
                self.logger.error("Failed to initialize attack log: %s",
                                  str(e))

    # =========================================================================
    # Syslog handler for SIEM integration
    # =========================================================================

    def _setup_syslog(self):
        """
        Attach a syslog handler to the controller logger for SIEM integration.

        Sends WARNING+ log messages to syslog/SIEM.
        Fails gracefully if syslog is unavailable.
        """
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=SYSLOG_ADDRESS,
                facility=SYSLOG_FACILITY
            )
            syslog_handler.setLevel(logging.WARNING)
            syslog_fmt = logging.Formatter(
                'SDN-DDoS[%(process)d]: %(levelname)s %(message)s'
            )
            syslog_handler.setFormatter(syslog_fmt)
            self.logger.addHandler(syslog_handler)
            self.logger.info("Syslog handler attached (WARNING+)")
        except (OSError, ConnectionError):
            self.logger.info(
                "Syslog not available at %s — SIEM logging disabled",
                SYSLOG_ADDRESS
            )

    # =========================================================================
    # HELPER: Add flow entry to a switch
    # =========================================================================

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """Install a flow entry on a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(flow_mod)

    # =========================================================================
    # MAC table aging
    # =========================================================================

    def _learn_mac(self, dpid, mac, port):
        """
        Learn a MAC address with timestamp for aging.

        Also enforces port security: if a port already has the configured
        max_macs_per_port different MACs, the new MAC is rejected.

        Protected by _mac_lock.

        Args:
            dpid: Switch datapath ID.
            mac (str): MAC address to learn.
            port (int): Port number where the MAC was seen.

        Returns:
            bool: True if the MAC was learned, False if rejected by
                  port security.
        """
        with self._mac_lock:
            self.mac_to_port.setdefault(dpid, {})
            self._port_macs.setdefault(dpid, {})
            self._port_macs[dpid].setdefault(port, set())

            # Check port security limit
            port_mac_set = self._port_macs[dpid][port]
            if mac not in port_mac_set:
                if len(port_mac_set) >= ryu_cfg.CONF.max_macs_per_port:
                    self.logger.warning(
                        "Port security violation on dpid=%s port=%s. "
                        "Rejecting MAC %s (limit=%d reached: %s)",
                        dpid, port, mac, ryu_cfg.CONF.max_macs_per_port, port_mac_set
                    )
                    return False
                port_mac_set.add(mac)

            # Store MAC with timestamp for aging
            self.mac_to_port[dpid][mac] = (port, time.time())
            return True

    def _lookup_mac(self, dpid, mac):
        """
        Look up a MAC address, returning the port if the entry is not aged out.

        Protected by _mac_lock.

        Args:
            dpid: Switch datapath ID.
            mac (str): MAC address to look up.

        Returns:
            int or None: Port number if found and not expired, else None.
        """
        with self._mac_lock:
            if dpid not in self.mac_to_port:
                return None
            entry = self.mac_to_port[dpid].get(mac)
            if entry is None:
                return None

            port, timestamp = entry
            if time.time() - timestamp > MAC_AGE_TIMEOUT:
                # Entry aged out — remove it
                del self.mac_to_port[dpid][mac]
                # Also remove from port security tracking
                if dpid in self._port_macs and port in self._port_macs[dpid]:
                    self._port_macs[dpid][port].discard(mac)
                return None

            return port

    def _age_mac_table(self):
        """
        Evict expired MAC entries from all switches.

        Called by the periodic cleanup thread. Protected by _mac_lock.
        """
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
                    # Clean port security tracking
                    if dpid in self._port_macs and port in self._port_macs[dpid]:
                        self._port_macs[dpid][port].discard(mac)
                    total_evicted += 1

        if total_evicted:
            self.logger.info("Aged out %d MAC entries", total_evicted)

    # =========================================================================
    # HELPER: Randomized block timeout
    # =========================================================================

    def _random_block_timeout(self):
        """
        Return a randomized block timeout to prevent predictable attack windows.

        Instead of a fixed 300s, randomize within +/- 20%.
        """
        timeout = ryu_cfg.CONF.block_rule_timeout
        return random.randint(
            int(timeout * 0.8),
            int(timeout * 1.2)
        )

    # =========================================================================
    # HELPER: Sanitize IP for logging
    # =========================================================================

    @staticmethod
    def _sanitize_ip(ip_str):
        """
        Validate and sanitize an IP address string for safe CSV logging.

        Prevents CSV injection via malformed IP strings.
        """
        if isinstance(ip_str, str) and _IPV4_PATTERN.match(ip_str):
            return ip_str
        return 'INVALID'

    # =========================================================================
    # EVENT HANDLER: Switch connection (CONFIG_DISPATCHER)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connections."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        with self._datapaths_lock:
            self.datapaths[dpid] = datapath

        # Install table-miss flow entry (priority 0, match all)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Switch connected: dpid=%s", dpid)

    # =========================================================================
    # LOOP PREVENTION: Check if flood should be suppressed
    # =========================================================================

    def _should_suppress_flood(self, dpid, src_mac, dst_mac, ethertype):
        """
        Check if a broadcast/flood packet should be suppressed.

        Protected by _flood_lock.

        Args:
            dpid: Switch datapath ID.
            src_mac (str): Source MAC address.
            dst_mac (str): Destination MAC address.
            ethertype (int): Ethernet frame type.

        Returns:
            bool: True if this flood should be suppressed (duplicate).
        """
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
    # EVENT HANDLER: Packet-In (MAIN_DISPATCHER)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle packets sent to the controller.

        Implements L2 MAC learning and forwarding with:
        - Rate limiting to prevent controller DoS
        - MAC table aging
        - Port security
        - Flood suppression to prevent broadcast loops
        - Flood rate limiting
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        # Rate limit PacketIn events per switch
        if not self._packet_in_limiter.allow(dpid):
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == LLDP_ETHERTYPE:
            return

        # Log IPv6 traffic (not yet supported for DDoS classification)
        if eth.ethertype == IPV6_ETHERTYPE:
            self.logger.debug(
                "IPv6 packet on dpid=%s port=%s — "
                "not classified (IPv6 DDoS detection not implemented)",
                dpid, in_port
            )

        src_mac = eth.src
        dst_mac = eth.dst

        # Learn MAC with aging and port security
        if not self._learn_mac(dpid, src_mac, in_port):
            # Port security violation — drop the packet
            return

        # Look up destination MAC with aging check
        out_port_lookup = self._lookup_mac(dpid, dst_mac)

        if out_port_lookup is not None:
            out_port = out_port_lookup
        else:
            # Suppress duplicate floods
            if self._should_suppress_flood(dpid, src_mac, dst_mac,
                                           eth.ethertype):
                return

            # Rate limit floods per switch
            if not self._flood_limiter.allow(dpid):
                return

            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac,
                eth_src=src_mac
            )
            self._add_flow(
                datapath,
                priority=1,
                match=match,
                actions=actions,
                idle_timeout=FORWARDING_IDLE_TIMEOUT,
                hard_timeout=FORWARDING_HARD_TIMEOUT
            )

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    # =========================================================================
    # FLOW STATISTICS: Periodic collection thread
    # =========================================================================

    def _request_stats(self):
        """
        Periodically request flow statistics from all connected switches.

        Checks the shutdown flag each iteration.
        Logs health status every 12 cycles (~60s at default 5s interval).
        """
        while not self._shutting_down:
            self._stats_cycle_count += 1

            # Periodic health status log
            if self._stats_cycle_count % 12 == 0:
                ml_status = "ACTIVE" if self.model is not None else "DISABLED"
                with self._datapaths_lock:
                    n_switches = len(self.datapaths)
                with self._blocked_lock:
                    n_blocked = len(self.blocked_ips)
                self.logger.info(
                    "HEALTH: cycle=%d, switches=%d, blocked=%d, "
                    "ml=%s, ml_failures=%d",
                    self._stats_cycle_count, n_switches,
                    n_blocked, ml_status,
                    self._consecutive_ml_failures
                )

            with self._datapaths_lock:
                dp_snapshot = list(self.datapaths.items())

            for dpid, datapath in dp_snapshot:
                try:
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser

                    request = parser.OFPFlowStatsRequest(
                        datapath,
                        0,
                        ofproto.OFPTT_ALL,
                        ofproto.OFPP_ANY,
                        ofproto.OFPG_ANY,
                        0,
                        0,
                        parser.OFPMatch()
                    )
                    datapath.send_msg(request)
                except Exception as e:
                    self.logger.error(
                        "Failed to request stats from switch dpid=%s: %s",
                        dpid, str(e)
                    )

            hub.sleep(ryu_cfg.CONF.stats_poll_interval)

        self.logger.info("Stats polling thread exiting (shutdown)")

    # =========================================================================
    # PERIODIC CLEANUP
    # =========================================================================

    def _periodic_cleanup(self):
        """
        Periodically clean up expired entries to prevent memory leaks.

        Handles: blocked_ips, flood_history, MAC table aging.
        Checks shutdown flag each iteration.
        """
        while not self._shutting_down:
            hub.sleep(60)

            now = time.time()

            # Clean expired blocked_ips entries (protected by lock)
            with self._blocked_lock:
                expired_keys = [
                    key for key, expiry in list(self.blocked_ips.items())
                    if now >= expiry
                ]
                for key in expired_keys:
                    self.blocked_ips.pop(key, None)
            if expired_keys:
                self.logger.info(
                    "Cleaned %d expired block entries", len(expired_keys)
                )

            # Clean old flood history entries (protected by lock)
            with self._flood_lock:
                old_flood_keys = [
                    key for key, ts in list(self._flood_history.items())
                    if now - ts > self._flood_suppress_window * 10
                ]
                for key in old_flood_keys:
                    self._flood_history.pop(key, None)

            # Age out MAC table entries
            self._age_mac_table()

        self.logger.info("Cleanup thread exiting (shutdown)")

    # =========================================================================
    # EVENT HANDLER: Flow Statistics Reply (MAIN_DISPATCHER)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Handle flow statistics replies from switches.

        Spawns processing in a green thread to avoid blocking
        the Ryu event loop while processing other switches' replies.
        """
        # Process stats in a separate green thread
        hub.spawn(self._process_flow_stats, ev)

    def _process_flow_stats(self, ev):
        """
        Process flow statistics from a single switch.

        Two-pass approach for aggregate features:
          Pass 1: Parse all flows, build per-destination aggregates
          Pass 2: Extract 12 features per flow (including aggregates),
                  batch predict with confidence threshold, and mitigate

        Samples flows when table exceeds FLOW_SAMPLE_THRESHOLD.
        Uses batched ML inference for performance.
        """
        datapath = ev.msg.datapath
        dpid = datapath.id
        body = ev.msg.body

        if self.model is None or self.scaler is None:
            return

        # =====================================================================
        # Filter non-classifiable flows
        # =====================================================================
        classifiable = []
        skipped_non_ipv4 = 0
        for stat in body:
            if stat.priority == 0:
                continue
            # Count flows without IPv4 match fields
            if stat.match.get('ipv4_src', 'unknown') == 'unknown' and \
               stat.match.get('ipv4_dst', 'unknown') == 'unknown':
                skipped_non_ipv4 += 1
                continue
            classifiable.append(stat)

        if skipped_non_ipv4 > 0:
            self.logger.debug(
                "Skipped %d non-IPv4 flows on dpid=%s "
                "(ARP, MAC-only, or non-IP traffic)",
                skipped_non_ipv4, dpid
            )

        if not classifiable:
            return

        # =====================================================================
        # Sample flows if table is very large
        # =====================================================================
        if len(classifiable) > FLOW_SAMPLE_THRESHOLD:
            sample_size = max(
                int(len(classifiable) * FLOW_SAMPLE_RATIO),
                FLOW_SAMPLE_THRESHOLD  # always classify at least threshold
            )
            sampled = random.sample(classifiable, sample_size)
            self.logger.debug(
                "Sampled %d/%d flows on dpid=%s",
                sample_size, len(classifiable), dpid
            )
        else:
            sampled = classifiable

        # =====================================================================
        # PASS 1: Parse flows and build per-destination aggregates
        # =====================================================================
        raw_flows = []
        dst_flow_counts = {}
        dst_source_sets = {}
        dst_earliest_time = {}

        for stat in sampled:
            flow_duration_sec = stat.duration_sec
            packet_count = stat.packet_count
            byte_count = stat.byte_count

            # Skip flows with negative counters (counter wrap or clock skew)
            if flow_duration_sec < 0 or packet_count < 0 or byte_count < 0:
                self.logger.debug(
                    "Skipping flow with negative values: duration=%s "
                    "packets=%s bytes=%s on dpid=%s",
                    flow_duration_sec, packet_count, byte_count, dpid
                )
                continue

            ip_proto = stat.match.get('ip_proto', 0)
            icmp_code = stat.match.get('icmp_code', 0)
            icmp_type = stat.match.get('icmp_type', 0)
            src_ip = stat.match.get('ipv4_src', 'unknown')
            dst_ip = stat.match.get('ipv4_dst', 'unknown')

            raw_flows.append({
                'duration_sec': flow_duration_sec,
                'packet_count': packet_count,
                'byte_count': byte_count,
                'ip_proto': ip_proto,
                'icmp_code': icmp_code,
                'icmp_type': icmp_type,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
            })

            if dst_ip != 'unknown':
                dst_flow_counts[dst_ip] = dst_flow_counts.get(dst_ip, 0) + 1
                if dst_ip not in dst_source_sets:
                    dst_source_sets[dst_ip] = set()
                if src_ip != 'unknown':
                    dst_source_sets[dst_ip].add(src_ip)
                if dst_ip not in dst_earliest_time:
                    dst_earliest_time[dst_ip] = flow_duration_sec
                else:
                    dst_earliest_time[dst_ip] = max(
                        dst_earliest_time[dst_ip], flow_duration_sec
                    )

        if not raw_flows:
            return

        # =====================================================================
        # PASS 2: Extract features via single source of truth (audit 4.2, 8.1)
        # =====================================================================
        batch_features = []
        batch_metadata = []

        for flow in raw_flows:
            dst_ip = flow['dst_ip']

            # Compute aggregate features for this destination
            flows_to_dst = dst_flow_counts.get(dst_ip, 0)
            unique_sources = len(dst_source_sets.get(dst_ip, set()))
            time_window = dst_earliest_time.get(dst_ip, 0)
            if time_window > 0:
                flow_creation_rate = flows_to_dst / time_window
            else:
                flow_creation_rate = flows_to_dst

            # Use the SINGLE SOURCE OF TRUTH for feature extraction
            flow_with_aggregates = dict(flow)
            flow_with_aggregates['flows_to_dst'] = flows_to_dst
            flow_with_aggregates['unique_sources_to_dst'] = unique_sources
            flow_with_aggregates['flow_creation_rate'] = flow_creation_rate

            features_dict = extract_flow_features_from_stats(flow_with_aggregates)
            feature_values = [features_dict[name] for name in FEATURE_NAMES]

            batch_features.append(feature_values)
            batch_metadata.append({
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'ip_proto': flow['ip_proto'],
                'icmp_type': flow.get('icmp_type', 0),
                'pps': features_dict['packet_count_per_second'],
            })

        # =====================================================================
        # BATCH ML CLASSIFICATION via circuit breaker (audit 8.3)
        # =====================================================================
        features_array = np.array(batch_features)
        normalized = self.scaler.transform(features_array)

        def _predict(X):
            return self.model.predict_proba(X)

        probabilities = self.circuit_breaker.call(
            _predict, normalized,
            fallback=lambda X: self.fallback_detector.detect_batch(X)
        )

        # ADWIN drift detection (audit 4.7 — replaces EMA adaptation)
        attack_probs = probabilities[:, 1]
        mean_attack_prob = float(attack_probs.mean())
        drift_result = self.drift_monitor.update(mean_attack_prob)
        if drift_result.detected:
            self.logger.warning(
                "Concept drift detected: %s", drift_result.stats
            )

        # =====================================================================
        # PROCESS PREDICTIONS with confidence threshold
        # =====================================================================
        for i in range(len(probabilities)):
            attack_prob = probabilities[i][1]  # P(attack)

            # Only act if confidence exceeds threshold
            if attack_prob < ryu_cfg.CONF.confidence_threshold:
                continue

            meta = batch_metadata[i]
            src_ip = meta['src_ip']
            dst_ip = meta['dst_ip']
            ip_proto = meta['ip_proto']

            if src_ip == 'unknown':
                continue

            attack_type = self._get_attack_type(ip_proto, meta['icmp_type'])

            self.logger.warning(
                "DDoS ATTACK DETECTED on switch dpid=%s: "
                "src=%s dst=%s type=%s pps=%.1f confidence=%.3f",
                dpid, src_ip, dst_ip, attack_type, meta['pps'], attack_prob
            )

            # Atomic check-and-set on blocked_ips with lock
            block_key = (dpid, src_ip, dst_ip, ip_proto)
            now = time.time()

            with self._blocked_lock:
                existing_expiry = self.blocked_ips.get(block_key)
                if existing_expiry is not None and now < existing_expiry:
                    continue  # Still active

                # Randomized timeout to prevent predictable attack windows
                timeout = self._random_block_timeout()
                self.blocked_ips[block_key] = now + timeout

            self._install_block_rule(datapath, src_ip, dst_ip, ip_proto,
                                     timeout=timeout)

            self._log_attack(
                src_ip=src_ip,
                dst_ip=dst_ip,
                attack_type=attack_type,
                packet_rate=meta['pps'],
                confidence=attack_prob,
                switch=dpid
            )

    # =========================================================================
    # HELPER: Determine attack type from protocol fields
    # =========================================================================

    def _get_attack_type(self, ip_proto, icmp_type):
        """Determine the DDoS attack type based on protocol fields."""
        if ip_proto == 1:
            return 'ICMP Flood'
        elif ip_proto == 6:
            return 'SYN Flood'
        elif ip_proto == 17:
            return 'UDP Flood'
        else:
            return 'Unknown (proto={})'.format(ip_proto)

    # =========================================================================
    # MITIGATION: Install DROP rule for specific attack flow
    # =========================================================================

    def _install_block_rule(self, datapath, src_ip, dst_ip, ip_proto,
                            timeout=None):
        """
        Install a high-priority DROP rule to block a specific attack flow.

        Matches on (src_ip, dst_ip, ip_proto) tuple.
        Uses randomized timeout if not specified.
        """
        if timeout is None:
            timeout = self._random_block_timeout()

        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Validate IP addresses before constructing OpenFlow match
        try:
            ipaddress.IPv4Address(src_ip)
            ipaddress.IPv4Address(dst_ip)
        except (ipaddress.AddressValueError, ValueError):
            self.logger.warning(
                "Invalid IP in block rule request: src=%s dst=%s on dpid=%s",
                src_ip, dst_ip, dpid
            )
            return

        try:
            match_fields = {
                'eth_type': IPV4_ETHERTYPE,
                'ipv4_src': src_ip,
                'ipv4_dst': dst_ip,
            }
            if ip_proto > 0:
                match_fields['ip_proto'] = ip_proto

            match = parser.OFPMatch(**match_fields)
            actions = []  # Empty = DROP

            self._add_flow(
                datapath,
                priority=BLOCK_RULE_PRIORITY,
                match=match,
                actions=actions,
                hard_timeout=timeout
            )

            self.logger.info(
                "ATTACK BLOCKED: DROP rule installed for "
                "src=%s dst=%s proto=%s on switch dpid=%s (expires in %ds)",
                src_ip, dst_ip, ip_proto, dpid, timeout
            )

        except Exception as e:
            self.logger.error(
                "Failed to install block rule for %s->%s on switch dpid=%s: %s",
                src_ip, dst_ip, dpid, str(e)
            )

    # =========================================================================
    # LOGGING: Record detected attacks to CSV file
    # =========================================================================

    def _log_attack(self, src_ip, dst_ip, attack_type, packet_rate,
                    confidence, switch):
        """
        Log a detected DDoS attack via async QueueHandler logging.

        Replaces synchronous CSV file writes (audit 6.2) with standard
        logging calls that go through the async QueueHandler and never
        block green threads.

        Args:
            src_ip (str): Source IP address of the attacker.
            dst_ip (str): Destination IP address of the target.
            attack_type (str): Type of attack.
            packet_rate (float): Packets per second observed.
            confidence (float): ML model confidence.
            switch: Datapath ID of the reporting switch.
        """
        # Sanitize IPs to prevent log injection
        safe_src = self._sanitize_ip(src_ip)
        safe_dst = self._sanitize_ip(dst_ip)

        self.logger.info(
            "ATTACK_LOG src=%s dst=%s type=%s pps=%.2f confidence=%.3f "
            "action=BLOCKED switch=%s",
            safe_src, safe_dst, attack_type, packet_rate, confidence, switch
        )
