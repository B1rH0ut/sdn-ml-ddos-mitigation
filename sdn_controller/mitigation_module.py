#!/usr/bin/env python3
"""
SDN Controller with ML-based DDoS Detection and Mitigation

This Ryu application implements an OpenFlow 1.3 controller that:
1. Manages MAC learning and packet forwarding across the network
2. Collects flow statistics from all connected switches every 5 seconds
3. Extracts 10 features from flow statistics for ML classification
4. Uses a trained Random Forest model to classify flows as normal or attack
5. Installs DROP rules to block detected DDoS attack flows

The controller integrates with the ML model trained by ml_model/train_model.py
and logs detected attacks to logs/attacks_log.csv.

Features extracted (in order):
    1. flow_duration_sec     6. packet_count_per_second
    2. idle_timeout          7. byte_count_per_second
    3. hard_timeout          8. ip_proto
    4. packet_count          9. icmp_code
    5. byte_count           10. icmp_type

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
from ryu.lib.packet import packet, ethernet
from ryu.lib import hub
import joblib
import numpy as np
import time
import csv
import os


class DDoSDetectionController(app_manager.RyuApp):
    """
    Ryu SDN controller application for DDoS detection and mitigation.

    This controller performs three primary functions:
    1. L2 switching with MAC learning for normal packet forwarding
    2. Periodic flow statistics collection from all connected switches
    3. ML-based DDoS detection with automatic flow blocking

    Attributes:
        mac_to_port (dict): MAC address to port mapping per datapath.
            Structure: {datapath_id: {mac_address: port_number}}
        datapaths (dict): Connected switch datapaths.
            Structure: {datapath_id: datapath_object}
        model: Trained Random Forest classifier loaded from flow_model.pkl,
            or None if model file is not found.
        scaler: StandardScaler loaded from scaler.pkl for feature normalization,
            or None if scaler file is not found.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        """
        Initialize the DDoS Detection Controller.

        Sets up MAC learning table, datapath tracking, and attempts to load
        the ML model and scaler from ../ml_model/. If model files are not
        found, the controller continues operating as a basic L2 switch
        without DDoS detection capability.
        """
        super(DDoSDetectionController, self).__init__(*args, **kwargs)

        # MAC address to port mapping: {dpid: {mac: port}}
        self.mac_to_port = {}

        # Connected switch datapaths: {dpid: datapath}
        self.datapaths = {}

        # Track IPs that already have active block rules to avoid duplicates
        # Entries are removed after the block timeout (300s) expires
        self.blocked_ips = {}  # {(dpid, src_ip): expiry_timestamp}

        # ML model and scaler initialization
        self.model = None
        self.scaler = None

        # Resolve model file paths relative to this script's directory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.join(script_dir, '..', 'ml_model', 'flow_model.pkl')
        scaler_path = os.path.join(script_dir, '..', 'ml_model', 'scaler.pkl')

        # Attempt to load the trained ML model and feature scaler
        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.logger.info("ML model loaded successfully from %s", model_path)
            self.logger.info("Feature scaler loaded successfully from %s", scaler_path)
        except FileNotFoundError:
            self.logger.warning(
                "ML model files not found at %s. "
                "Controller will operate without DDoS detection. "
                "Train the model first: cd ml_model && python3 train_model.py",
                model_path
            )
        except Exception as e:
            self.logger.error(
                "Failed to load ML model: %s. "
                "Controller will operate without DDoS detection.",
                str(e)
            )

        # Ensure logs directory exists for attack logging
        self.log_dir = os.path.join(script_dir, '..', 'logs')
        os.makedirs(self.log_dir, exist_ok=True)

        # Start periodic flow statistics collection thread
        # This thread requests stats from all switches every 5 seconds
        self.stats_thread = hub.spawn(self._request_stats)

        self.logger.info("DDoS Detection Controller initialized")

    # =========================================================================
    # HELPER: Add flow entry to a switch
    # =========================================================================

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """
        Install a flow entry on a switch.

        Constructs and sends an OFPFlowMod message to install a forwarding
        rule on the specified switch.

        Args:
            datapath: Switch datapath object to install the flow on.
            priority (int): Flow entry priority (higher = matched first).
            match: OFPMatch object specifying which packets to match.
            actions (list): List of OFPAction objects to apply to matched packets.
            idle_timeout (int): Seconds of inactivity before flow expires (0=never).
            hard_timeout (int): Seconds before flow expires regardless (0=never).
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Wrap actions in an Apply-Actions instruction
        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        # Build and send the FlowMod message
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
    # EVENT HANDLER: Switch connection (CONFIG_DISPATCHER)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handle new switch connections.

        Called when a switch completes the OpenFlow handshake. Installs a
        table-miss flow entry that sends unmatched packets to the controller,
        enabling reactive forwarding via packet_in_handler.

        Args:
            ev: EventOFPSwitchFeatures event containing the switch datapath.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Register this datapath for periodic stats collection
        self.datapaths[dpid] = datapath

        # Install table-miss flow entry (priority 0, match all)
        # Unmatched packets are sent to the controller for MAC learning
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Switch connected: dpid=%s", dpid)

    # =========================================================================
    # EVENT HANDLER: Packet-In (MAIN_DISPATCHER)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle packets sent to the controller.

        Implements L2 MAC learning and forwarding:
        1. Learns the source MAC address and its ingress port
        2. Looks up the destination MAC address in the learned table
        3. If destination is known, installs a flow entry and forwards
        4. If destination is unknown, floods the packet to all ports

        Flow entries are installed with idle_timeout=10 and hard_timeout=30
        to allow periodic re-evaluation by the ML detection system.

        Args:
            ev: EventOFPPacketIn event containing the received packet.
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        # Parse the incoming packet to extract Ethernet header
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets (used for topology discovery, not data)
        if eth.ethertype == 0x88cc:
            return

        src_mac = eth.src
        dst_mac = eth.dst

        # Initialize MAC table for this switch if not present
        self.mac_to_port.setdefault(dpid, {})

        # Learn source MAC address: map it to the ingress port
        self.mac_to_port[dpid][src_mac] = in_port

        # Determine output port based on destination MAC lookup
        if dst_mac in self.mac_to_port[dpid]:
            # Destination MAC is known - forward to the learned port
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            # Destination MAC unknown - flood to all ports
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # If destination is known, install a flow entry to avoid future
        # packet-in events for this MAC pair
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
                idle_timeout=10,
                hard_timeout=30
            )

        # Send the buffered packet out
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

        Runs as a background thread (spawned in __init__ via hub.spawn).
        Every 5 seconds, sends an OFPFlowStatsRequest to each registered
        datapath. The replies are handled by flow_stats_reply_handler().

        This continuous polling enables near-real-time DDoS detection by
        ensuring the ML model receives fresh flow data for classification.
        """
        while True:
            # Snapshot the datapaths to avoid RuntimeError if a switch
            # connects or disconnects during iteration
            for dpid, datapath in list(self.datapaths.items()):
                try:
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser

                    # Request all flow statistics (match-all, table 0)
                    request = parser.OFPFlowStatsRequest(
                        datapath,
                        0,                          # flags
                        ofproto.OFPTT_ALL,          # table_id: all tables
                        ofproto.OFPP_ANY,           # out_port: any
                        ofproto.OFPG_ANY,           # out_group: any
                        0,                          # cookie
                        0,                          # cookie_mask
                        parser.OFPMatch()           # match: all flows
                    )
                    datapath.send_msg(request)
                except Exception as e:
                    self.logger.error(
                        "Failed to request stats from switch dpid=%s: %s",
                        dpid, str(e)
                    )

            # Wait 5 seconds before next collection cycle
            hub.sleep(5)

    # =========================================================================
    # EVENT HANDLER: Flow Statistics Reply (MAIN_DISPATCHER)
    # =========================================================================

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """
        Handle flow statistics replies from switches.

        Processes each flow entry returned by the switch:
        1. Extracts 10 features from the flow statistics
        2. Normalizes features using the trained scaler
        3. Classifies the flow using the Random Forest model
        4. If classified as attack (label=1), blocks the source IP

        Feature extraction order must match the training dataset columns:
            flow_duration_sec, idle_timeout, hard_timeout, packet_count,
            byte_count, packet_count_per_second, byte_count_per_second,
            ip_proto, icmp_code, icmp_type

        Args:
            ev: EventOFPFlowStatsReply event containing flow statistics.
        """
        datapath = ev.msg.datapath
        dpid = datapath.id
        body = ev.msg.body

        for stat in body:
            # =================================================================
            # FEATURE EXTRACTION: Extract 10 features from flow statistics
            # =================================================================

            # Feature 1: Flow duration in seconds
            flow_duration_sec = stat.duration_sec

            # Feature 2: Idle timeout configured for this flow
            idle_timeout = stat.idle_timeout

            # Feature 3: Hard timeout configured for this flow
            hard_timeout = stat.hard_timeout

            # Feature 4: Total packet count for this flow
            packet_count = stat.packet_count

            # Feature 5: Total byte count for this flow
            byte_count = stat.byte_count

            # Feature 6: Packets per second (handle division by zero)
            # When duration is 0 (flow just installed), use packet_count as-is
            if flow_duration_sec > 0:
                packet_count_per_second = packet_count / flow_duration_sec
            else:
                packet_count_per_second = packet_count

            # Feature 7: Bytes per second (handle division by zero)
            if flow_duration_sec > 0:
                byte_count_per_second = byte_count / flow_duration_sec
            else:
                byte_count_per_second = byte_count

            # Features 8-10: Protocol fields from flow match
            # These may not be present in all flow entries (e.g., table-miss)
            # OFPMatch.get() returns the default when the field is absent
            ip_proto = stat.match.get('ip_proto', 0)
            icmp_code = stat.match.get('icmp_code', 0)
            icmp_type = stat.match.get('icmp_type', 0)

            # =================================================================
            # ML CLASSIFICATION: Predict if flow is normal or attack
            # =================================================================

            # Skip classification if ML model is not loaded
            if self.model is None or self.scaler is None:
                continue

            # Skip table-miss flow entry (priority 0, no useful features)
            if stat.priority == 0:
                continue

            # Assemble features in the exact order used during training
            features = [
                flow_duration_sec,          # 1. flow_duration_sec
                idle_timeout,               # 2. idle_timeout
                hard_timeout,               # 3. hard_timeout
                packet_count,               # 4. packet_count
                byte_count,                 # 5. byte_count
                packet_count_per_second,    # 6. packet_count_per_second
                byte_count_per_second,      # 7. byte_count_per_second
                ip_proto,                   # 8. ip_proto
                icmp_code,                  # 9. icmp_code
                icmp_type,                  # 10. icmp_type
            ]

            try:
                # Reshape to 2D array as expected by scaler and model
                features_array = np.array(features).reshape(1, -1)

                # Normalize features using the same scaler used during training
                # (loaded from ../ml_model/scaler.pkl)
                normalized = self.scaler.transform(features_array)

                # Classify: 0 = normal traffic, 1 = DDoS attack
                prediction = self.model.predict(normalized)

                if prediction[0] == 1:
                    # Attack detected - extract source IP for blocking
                    src_ip = stat.match.get('ipv4_src', 'unknown')
                    dst_ip = stat.match.get('ipv4_dst', 'unknown')

                    # Skip mitigation if source IP is unavailable
                    # (flows installed by MAC learning lack IPv4 match fields)
                    if src_ip == 'unknown':
                        continue

                    # Determine attack type based on protocol number
                    attack_type = self._get_attack_type(ip_proto, icmp_type)

                    self.logger.warning(
                        "DDoS ATTACK DETECTED on switch dpid=%s: "
                        "src=%s dst=%s type=%s pps=%.1f",
                        dpid, src_ip, dst_ip, attack_type,
                        packet_count_per_second
                    )

                    # Install DROP rule only if not already blocked
                    # Prevents flooding the switch with duplicate FlowMod messages
                    block_key = (dpid, src_ip)
                    now = time.time()

                    # Clean expired entries and check if already blocked
                    if block_key in self.blocked_ips:
                        if now < self.blocked_ips[block_key]:
                            # Block rule still active, skip reinstall
                            pass
                        else:
                            # Previous block expired, reinstall
                            del self.blocked_ips[block_key]

                    if block_key not in self.blocked_ips:
                        self._install_block_rule(datapath, src_ip)
                        # Track with 300s expiry matching the hard_timeout
                        self.blocked_ips[block_key] = now + 300

                    # Log the attack to CSV file
                    self._log_attack(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        attack_type=attack_type,
                        packet_rate=packet_count_per_second,
                        switch=dpid
                    )

            except Exception as e:
                self.logger.error(
                    "ML prediction error on switch dpid=%s: %s",
                    dpid, str(e)
                )

    # =========================================================================
    # HELPER: Determine attack type from protocol fields
    # =========================================================================

    def _get_attack_type(self, ip_proto, icmp_type):
        """
        Determine the DDoS attack type based on protocol fields.

        Maps IP protocol numbers and ICMP types to human-readable
        attack type labels.

        Args:
            ip_proto (int): IP protocol number (1=ICMP, 6=TCP, 17=UDP).
            icmp_type (int): ICMP type value (8=echo request).

        Returns:
            str: Attack type label (e.g., 'ICMP Flood', 'SYN Flood',
                 'UDP Flood', or 'Unknown').
        """
        if ip_proto == 1:
            return 'ICMP Flood'
        elif ip_proto == 6:
            return 'SYN Flood'
        elif ip_proto == 17:
            return 'UDP Flood'
        else:
            return 'Unknown (proto={})'.format(ip_proto)

    # =========================================================================
    # MITIGATION: Install DROP rule to block attacking source IP
    # =========================================================================

    def _install_block_rule(self, datapath, src_ip):
        """
        Install a high-priority DROP rule to block traffic from an attacking IP.

        Creates an OpenFlow flow entry that matches all IPv4 packets from the
        specified source IP and drops them (empty action list). The rule is
        installed with a hard timeout of 300 seconds (5 minutes), after which
        the switch automatically removes it, allowing traffic to resume if the
        attack has stopped.

        Args:
            datapath: Switch datapath object where the block rule is installed.
            src_ip (str): IPv4 address of the attacking host (e.g., '10.0.0.5').
        """
        parser = datapath.ofproto_parser
        dpid = datapath.id

        try:
            # Match all IPv4 packets from the attacking source IP
            # eth_type=0x0800 is required to enable IPv4 match fields
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip
            )

            # Empty action list = DROP (packets are discarded)
            actions = []

            # Install with high priority (32768) to override normal forwarding
            # hard_timeout=300s: rule auto-expires after 5 minutes
            self._add_flow(
                datapath,
                priority=32768,
                match=match,
                actions=actions,
                hard_timeout=300
            )

            self.logger.info(
                "ATTACK BLOCKED: DROP rule installed for src=%s "
                "on switch dpid=%s (expires in 300s)",
                src_ip, dpid
            )

        except Exception as e:
            self.logger.error(
                "Failed to install block rule for %s on switch dpid=%s: %s",
                src_ip, dpid, str(e)
            )

    # =========================================================================
    # LOGGING: Record detected attacks to CSV file
    # =========================================================================

    def _log_attack(self, src_ip, dst_ip, attack_type, packet_rate, switch):
        """
        Log a detected DDoS attack to the attacks_log.csv file.

        Appends a row to ../logs/attacks_log.csv with attack details. If the
        file does not exist, creates it with appropriate CSV headers first.

        CSV columns:
            timestamp, src_ip, dst_ip, attack_type, packet_rate, action, switch

        Args:
            src_ip (str): Source IP address of the attacker.
            dst_ip (str): Destination IP address of the target.
            attack_type (str): Type of attack ('ICMP Flood', 'SYN Flood',
                'UDP Flood', or 'Unknown').
            packet_rate (float): Packets per second observed in the flow.
            switch: Datapath ID of the switch that reported the flow.
        """
        log_file = os.path.join(self.log_dir, 'attacks_log.csv')
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

        try:
            # Check if file exists to determine whether to write headers
            file_exists = os.path.isfile(log_file)

            with open(log_file, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)

                # Write header row if this is a new file
                if not file_exists:
                    writer.writerow([
                        'timestamp', 'src_ip', 'dst_ip',
                        'attack_type', 'packet_rate', 'action', 'switch'
                    ])

                # Write the attack record
                writer.writerow([
                    timestamp,
                    src_ip,
                    dst_ip,
                    attack_type,
                    f'{packet_rate:.2f}',
                    'BLOCKED',
                    switch
                ])

            self.logger.info(
                "Attack logged: %s -> %s (%s) on switch %s",
                src_ip, dst_ip, attack_type, switch
            )

        except IOError as e:
            self.logger.error(
                "Failed to write to attack log %s: %s",
                log_file, str(e)
            )
