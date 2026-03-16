# Known Limitations

This document lists known limitations of the SDN DDoS detection system, organized by category. Each limitation includes suggested future work.

## Fundamental Limitations

### Aggregate Feature Train/Serve Distribution Mismatch

Features 10-12 (`flows_to_dst`, `unique_sources_to_dst`, `flow_creation_rate`) are computed differently during training and live serving. Training data computes them via dataset-wide `groupby` operations, which inflates counts for popular destinations. Live serving computes them over a sliding time window maintained by the controller. This distribution mismatch means the model may behave differently on live traffic than on test data, particularly for aggregate-dependent classification boundaries.

**Impact:** The model may under-detect attacks targeting rarely-seen destinations (where live aggregates are low but training aggregates were high) or over-detect traffic to popular destinations.

**Future work:** Generate training data using a sliding-window simulation that matches the controller's 5-second polling interval. Alternatively, normalize aggregate features to relative values (e.g., percentiles) that are distribution-invariant.

### Random Forest cannot detect novel zero-day attacks

The classifier is trained on known attack patterns (ICMP flood, SYN flood, UDP flood). Novel attack vectors that don't match learned feature distributions will be classified as normal traffic. This relates to audit findings ML-05 and ML-07.

**Future work:** Add unsupervised anomaly detection (Isolation Forest, autoencoders) as a complementary layer. Implement online learning with River to adapt to new patterns without full retraining.

### Encrypted traffic limits feature extraction

Encrypted traffic (QUIC, TLS 1.3, WireGuard) prevents inspection of application-layer features. Detection relies entirely on flow-level metadata: packet counts, byte counts, timing, and per-destination aggregates. Sophisticated attacks that mimic normal encrypted traffic patterns may evade detection. Relates to DEPLOY-02.

**Future work:** Integrate JA3/JA4 TLS fingerprinting for client identification. Add inter-packet timing analysis and flow size distribution features that are available even for encrypted traffic.

### Single-controller single point of failure

The system runs a single Ryu controller instance. If the controller crashes or becomes overloaded, the entire detection and mitigation pipeline stops. OVS switches fall back to standalone mode (basic L2 forwarding with no DDoS protection). Relates to ARCH-03.

**Future work:** Migrate to a clustered controller framework (ONOS or OpenDaylight) with leader election and state replication. Alternatively, run hot-standby Ryu instances with shared state via Redis.

## Implementation Limitations

### Ryu framework is unmaintained

Ryu's last release (4.34) was in 2021. The framework is no longer actively maintained. This limits compatibility with newer Python versions and OpenFlow extensions. Relates to SCALE-01.

**Future work:** Migrate to ONOS (Java, production-grade) or Faucet (Python, actively maintained OpenFlow controller). The modular `src/` layout was designed to make this migration feasible.

### Mininet emulation only

Testing is limited to Mininet-emulated networks. Mininet has practical limits around 64 switches and does not accurately model hardware switch behavior (TCAM sizes, flow table overflow, line-rate forwarding). Relates to DEPLOY-01.

**Future work:** Validate on hardware OpenFlow switches (e.g., NoviFlow, EdgeCore). Test with physical network testbeds or GENI/CloudLab infrastructure.

### No IPv6 support

All flow matching and feature extraction targets IPv4 only (`eth_type=0x0800`). Attacks using IPv6 (`eth_type=0x86DD`) bypass detection entirely. Relates to NET-05.

**Future work:** Add IPv6 flow matching with `eth_type=0x86DD`. Extend feature extraction to handle ICMPv6 and IPv6 extension headers.

### No VLAN awareness

MAC learning and forwarding do not account for VLAN tags. In VLAN-segmented networks, the controller may learn incorrect MAC-to-port mappings. Relates to NET-06.

**Future work:** Add VLAN-aware MAC learning with `(vlan_id, mac_address)` keys. Support 802.1Q tagged traffic in flow matching.

### No horizontal scaling

The single-controller architecture cannot distribute load across multiple instances. Flow stats processing is sequential per polling cycle. At scale (hundreds of switches, millions of flows), the 3-second polling interval may not be achievable. Relates to SCALE-04.

**Future work:** Implement distributed controller architecture with partitioned switch ownership. Use message queues (Kafka, ZeroMQ) for cross-controller coordination.

## Scope Boundaries

### Not a production DDoS mitigation system

This is a research prototype for academic evaluation. It lacks the reliability, scalability, and operational maturity required for production deployment. Do not use this system to protect production networks.

### No BGP Flowspec or RTBH integration

The system operates entirely within the SDN domain. It cannot signal upstream providers to filter attack traffic before it reaches the local network. For volumetric attacks that saturate the access link, local mitigation is insufficient. Relates to DEPLOY-03.

**Future work:** Integrate BGP Flowspec (RFC 5575) or Remote Triggered Black Hole (RTBH) routing to push mitigation upstream. Interface with cloud-based scrubbing services (e.g., Cloudflare, AWS Shield).

### Detection latency too slow for ISP-scale volumetric attacks

End-to-end detection latency is 3-5 seconds (polling interval + feature extraction + ML inference + rule installation). At ISP scale, a volumetric attack can saturate links in under 1 second. The threshold fast-path helps but still depends on the polling cycle.

**Future work:** Implement P4-based in-network detection for line-rate classification. Use hardware offload (FPGA/SmartNIC) for feature extraction. Reduce polling to sub-second intervals with incremental stats.
