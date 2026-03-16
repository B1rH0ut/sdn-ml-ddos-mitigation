# Feature Mapping: Canonical Features to Real Datasets

This document maps each of our 12 canonical features to their source columns
in each supported real-world dataset. Features marked as "Approximate" involve
a transformation or proxy that does not perfectly match what our SDN controller
extracts from OpenFlow statistics.

| # | Canonical Feature | CIC-IDS2017 Source | CIC-DDoS2019 Source | UNSW-NB15 Source | Transformation | Exact/Approximate |
|---|---|---|---|---|---|---|
| 1 | `flow_duration_sec` | `Flow Duration` | `Flow Duration` | `dur` | CIC: divide by 1,000,000 (microseconds → seconds) | CIC: Exact; UNSW: Exact |
| 2 | `packet_count` | `Total Fwd Packets` + `Total Backward Packets` | `Tot Fwd Pkts` + `Tot Bwd Pkts` | `spkts` + `dpkts` | Sum of forward and backward packets | Exact |
| 3 | `byte_count` | `Total Length of Fwd Packets` + `Total Length of Bwd Packets` | `TotLen Fwd Pkts` + `TotLen Bwd Pkts` | `sbytes` + `dbytes` | Sum of forward and backward bytes | Exact |
| 4 | `packet_count_per_second` | Derived: `packet_count / max(duration_sec, 0.001)` | Derived: same | Derived: same | Division with floor clamp | Approximate (CIC has `Flow Packets/s` but we recompute for consistency) |
| 5 | `byte_count_per_second` | Derived: `byte_count / max(duration_sec, 0.001)` | Derived: same | Derived: same | Division with floor clamp | Approximate (CIC has `Flow Bytes/s` but we recompute) |
| 6 | `avg_packet_size` | Derived: `byte_count / max(packet_count, 1)` | Derived: same | Derived: same | Division with floor clamp | Approximate (CIC has `Average Packet Size` but we recompute) |
| 7 | `ip_proto` | `Protocol` (numeric: 6, 17, 1) | `Protocol` (numeric) | `proto` (string → mapped) | UNSW: string-to-int mapping (tcp→6, udp→17, icmp→1) | CIC: Exact; UNSW: Exact (after mapping) |
| 8 | `icmp_code` | Not directly available | Not directly available | Not directly available | Set to 0 for non-ICMP; not extractable from CICFlowMeter/Argus | Approximate (always 0) |
| 9 | `icmp_type` | Not directly available | Not directly available | Not directly available | Set to 8 (Echo Request) when `ip_proto == 1`, else 0 | Approximate (heuristic) |
| 10 | `flows_to_dst` | `groupby("Destination IP").count()` | `groupby("Dst IP").count()` | `groupby("dstip").count()` | Count of flows sharing same destination IP | Approximate (dataset-wide vs. time-window in live) |
| 11 | `unique_sources_to_dst` | `groupby("Destination IP")["Source IP"].nunique()` | `groupby("Dst IP")["Src IP"].nunique()` | `groupby("dstip")["srcip"].nunique()` | Unique source IPs per destination | Approximate (dataset-wide vs. time-window) |
| 12 | `flow_creation_rate` | Derived from `Timestamp` ordering | Derived from `Timestamp` ordering | Derived from `stime` ordering | Rolling mean of inter-flow arrival rate per destination | Approximate (depends on timestamp resolution) |

## Train/Serve Alignment

| # | Feature | Train/Serve Aligned? | Notes |
|---|---------|---------------------|-------|
| 1-6 | Per-flow features | Yes | Computed identically from flow stats |
| 7 | `ip_proto` | Yes | Direct from OpenFlow match |
| 8-9 | `icmp_code`, `icmp_type` | Partial | Real datasets use heuristic (type=8 for ICMP); controller extracts exact values |
| 10 | `flows_to_dst` | **No** | Training: dataset-wide groupby; Serving: sliding time window |
| 11 | `unique_sources_to_dst` | **No** | Training: dataset-wide groupby; Serving: sliding time window |
| 12 | `flow_creation_rate` | **No** | Training: rolling mean over sorted timestamps; Serving: real-time rate |

See `docs/KNOWN_LIMITATIONS.md` for the full discussion of aggregate feature train/serve skew.

## Key Limitations

1. **ICMP code/type (features 8-9):** CICFlowMeter and Argus/Bro-IDS do not export
   per-flow ICMP code and type in their standard CSV output. We use a heuristic
   (type=8 for ICMP flows, 0 otherwise). This means these two features provide less
   discriminative power on real datasets compared to our SDN controller, which extracts
   them directly from OpenFlow matches.

2. **Aggregate features (10-12):** In live SDN operation, these are computed over a
   sliding time window maintained by the controller. In offline datasets, we approximate
   them using dataset-wide groupby operations, which inflates the count for popular
   destinations. This difference should be noted when comparing live vs. offline accuracy.

3. **Flow creation rate (feature 12):** Depends on timestamp granularity. CIC-IDS2017
   timestamps are to the second; UNSW-NB15 `stime` is Unix epoch with sub-second
   precision. Low-resolution timestamps may underestimate this feature.
