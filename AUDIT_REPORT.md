# Consolidated Audit Report

This document merges all unique findings from both independent audits into a single
actionable reference. Every issue has a unique ID for tracking.

---

## 1. Critical Vulnerabilities

### CRIT-01: DROP rule blocks entire source IP — self-DoS amplification
- **File**: `sdn_controller/mitigation_module.py:536-554`
- **Problem**: Block rule matches all IPv4 from `ipv4_src` only. If attacker spoofs a legitimate host's IP (e.g., 10.0.0.1 — the web server), the controller blocks all traffic from that host. Trivially exploitable DoS amplification.
- **Fix**: Match on full flow tuple `(src_ip, dst_ip, ip_proto)` at minimum. Add a whitelist for critical infrastructure IPs.

### CRIT-02: Pickle/joblib deserialization — Remote Code Execution
- **File**: `sdn_controller/mitigation_module.py:100-101`
- **Problem**: `joblib.load(model_path)` deserializes arbitrary Python objects. If an attacker replaces `flow_model.pkl` with a crafted payload, they get RCE as the controller process. No integrity verification (hash, HMAC, signature) before loading.
- **Fix**: Compute and verify SHA-256 hash of `.pkl` files before loading. Store expected hashes in a separate config. Long-term: use ONNX or a non-pickle serialization format.

### CRIT-03: No packet-in rate limiting — controller DoS
- **File**: `sdn_controller/mitigation_module.py:206-282`
- **Problem**: Every PacketIn is processed with no throttling. An attacker flooding unknown-destination packets overwhelms the controller's Python event loop, causing network-wide blackholing.
- **Fix**: Implement per-switch and global PacketIn rate limiting. Drop excess PacketIn events. Consider moving to a proactive forwarding model.

### CRIT-04: Model trained entirely on synthetic data with no real-world validation
- **File**: `datasets/generate_full_dataset.py`, `ml_model/train_model.py`
- **Problem**: 200x gap between normal and attack packet counts. Any classifier (even a single threshold) achieves near-perfect accuracy. Reported metrics are meaningless — they measure ability to separate two non-overlapping synthetic distributions, not real DDoS detection.
- **Fix**: Train/evaluate on real datasets (CIC-DDoS2019, UNSW-NB15). Report cross-dataset generalization. Test with adversarial examples in the boundary region. Add a baseline threshold classifier for comparison.

### CRIT-05: No OpenFlow channel authentication
- **File**: `sdn_controller/mitigation_module.py`, `network_topology/topology.py`, `sdn_controller/ryu.conf`
- **Problem**: OpenFlow uses plaintext TCP on port 6653 with no TLS, no mutual auth, no message integrity. Attacker can inject fake FlowStatsReply to poison ML input, fabricate PacketIn to corrupt MAC table, or install arbitrary flow rules by impersonating the controller.
- **Fix**: Configure TLS on the OpenFlow channel. Ryu supports `ssl_ctl` parameters. OVS supports `set-ssl` for certificate-based auth.

### CRIT-06: No loop prevention — broadcast storm
- **File**: `network_topology/topology.py`, `sdn_controller/mitigation_module.py:252-254`
- **Problem**: Spine-leaf topology has multiple paths between any two hosts. Controller floods unknown destinations (`OFPP_FLOOD`). No STP, no ECMP, no loop detection. ARP broadcasts loop infinitely: `h1 -> s3 -> s1 -> s4 -> s2 -> s3 -> s1 -> ...`. Network is non-functional on first `pingall`.
- **Fix**: Implement STP or proactive shortest-path forwarding. At minimum add TTL-based loop detection. Consider a proactive path computation approach.

### CRIT-07: OpenFlow/REST API listening on 0.0.0.0
- **File**: `sdn_controller/ryu.conf`
- **Problem**: Both `ofp_listen_host` and `wsapi_host` bind to `0.0.0.0`, exposing the control plane to all network interfaces including potentially untrusted networks.
- **Fix**: Bind to `127.0.0.1` or the specific management interface IP. Use firewall rules to restrict access.

---

## 2. Architectural Flaws

### ARCH-01: Single-threaded ML inference in the control path
- **File**: `sdn_controller/mitigation_module.py:421-431`
- **Problem**: ML inference runs synchronously inside `flow_stats_reply_handler` for every flow on every switch every 5 seconds. Blocks the Ryu event loop. If inference takes longer than 5 seconds, stats requests pile up, event queue grows, controller becomes unresponsive to PacketIn.
- **Fix**: Batch all features into one array and call `model.predict()` once per stats reply. Move ML inference to a separate worker thread/process with a queue.

### ARCH-02: Per-flow predict() calls instead of batching
- **File**: `sdn_controller/mitigation_module.py:421-431`
- **Problem**: `scaler.transform()` and `model.predict()` called once per flow entry with `(1, 10)` arrays. Sklearn is optimized for batch input. 500 individual calls is orders of magnitude slower than one call with `(500, 10)`.
- **Fix**: Accumulate all features from a stats reply into a single numpy array. Call `predict()` once. 10-100x speedup.

### ARCH-03: No controller redundancy or failover
- **File**: `sdn_controller/ryu.conf`, `network_topology/topology.py`, `network_topology/ovs_config.sh`
- **Problem**: Single Ryu instance. `ovs_config.sh` sets `fail-mode=secure`, meaning all traffic is dropped if controller dies. Combined with blocking ML inference, any crash causes total network failure.
- **Fix**: Set `fail-mode=standalone` so switches forward independently during failure. For production: use ONOS or OpenDaylight with clustering support.

### ARCH-04: Feature extraction duplicated across four files with no shared source
- **Files**: `mitigation_module.py`, `train_model.py`, `generate_full_dataset.py`, `feature_extractor.py`
- **Problem**: 10-feature definition copy-pasted across four files. `feature_extractor.py` exists as a "single source of truth" but is never imported by any other module. Changing feature order in one file silently produces garbage predictions.
- **Fix**: Make `feature_extractor.py` the canonical import. All other modules import `FEATURE_NAMES` and extraction logic from it.

### ARCH-05: No graceful shutdown
- **File**: `sdn_controller/mitigation_module.py`
- **Problem**: No cleanup of flow rules, no state persistence, no signal handling. Ctrl+C leaves orphaned flow entries on switches and loses all detection state.
- **Fix**: Implement signal handlers (SIGTERM, SIGINT) that clean up block rules and persist state before exit.

### ARCH-06: MAC learning table grows unbounded
- **File**: `sdn_controller/mitigation_module.py:79,245`
- **Problem**: `mac_to_port` dictionary — MACs are learned and never evicted. In environments with MAC rotation (VMs, containers, DHCP), memory grows without bound.
- **Fix**: Implement MAC table aging with timestamps and periodic cleanup, or cap size with LRU eviction.

---

## 3. Security Weaknesses

### SEC-01: Model evasion via slow-rate attacks
- **File**: `datasets/generate_full_dataset.py:223-258`
- **Problem**: Model's primary discriminators are `packet_count_per_second` and `byte_count_per_second`. Attacker sending at rates below the normal-attack boundary (100-500 pps instead of 10,000+) is classified as normal. Low-and-slow DDoS with thousands of bots at 50 pps each will evade detection entirely.
- **Fix**: Add aggregate features (total flows per source IP, flow creation rate, entropy of destination IPs). Consider anomaly detection alongside classification.

### SEC-02: SYN Flood and normal TCP indistinguishable without TCP flags
- **File**: `datasets/generate_full_dataset.py:261-296`, `sdn_controller/mitigation_module.py:391`
- **Problem**: Feature set lacks TCP flags (SYN, ACK, RST). Both normal TCP and SYN floods have `ip_proto=6, icmp_code=0, icmp_type=0`. Only difference is packet/byte counts. Cannot distinguish legitimate large file transfer from SYN flood at similar rates.
- **Fix**: Extract TCP flags from flow match fields. Add SYN/ACK/RST ratios as features. Consider connection completion rate.

### SEC-03: MAC table poisoning
- **File**: `sdn_controller/mitigation_module.py:245`
- **Problem**: `packet_in_handler` unconditionally learns any source MAC: `self.mac_to_port[dpid][src_mac] = in_port`. Attacker can send frames with spoofed MACs to redirect traffic. No MAC-port binding validation, no DHCP snooping, no dynamic ARP inspection.
- **Fix**: Implement port security (limit MACs per port). Validate MAC-IP bindings. Add static bindings for known hosts.

### SEC-04: Race conditions on shared dictionaries
- **File**: `sdn_controller/mitigation_module.py` (blocked_ips, mac_to_port, datapaths)
- **Problem**: `_request_stats` runs via `hub.spawn`. Multiple FlowStatsReply handlers access `blocked_ips` concurrently. Check-then-act pattern on `blocked_ips` is inherently unsafe. Ryu uses eventlet green threads which provides some safety but the pattern is still incorrect.
- **Fix**: Use explicit locking or thread-safe data structures. Consider `collections.OrderedDict` with a lock wrapper.

### SEC-05: CSV log injection
- **File**: `sdn_controller/mitigation_module.py:597-617`
- **Problem**: `src_ip` and `dst_ip` written to CSV without sanitization. Malformed flow entry producing string with commas or newlines corrupts the CSV and downstream pandas analysis.
- **Fix**: Validate IP format before logging. Use JSON or a database instead of CSV.

### SEC-06: Attack logs world-readable, no integrity protection
- **File**: `logs/init_logs.sh`
- **Problem**: Logs created with `chmod 644`. Attacker with local access can modify attack logs to cover tracks. No integrity protection (checksums, append-only, write-once).
- **Fix**: Set restrictive permissions (640/600). Use append-only filesystem flag. Consider log signing or centralized logging.

### SEC-07: No model integrity verification
- **File**: `sdn_controller/mitigation_module.py:99-101`
- **Problem**: Model files loaded without any hash verification. An attacker who gains write access to `ml_model/` can replace `.pkl` files to either cause RCE (CRIT-02) or install a backdoored model that classifies attacks as normal.
- **Fix**: Store SHA-256 hashes of model files. Verify before loading. Sign model artifacts during training.

### SEC-08: Fixed 300s block timeout creates predictable attack window
- **File**: `sdn_controller/mitigation_module.py:548`
- **Problem**: Block rules expire after exactly 300 seconds. Attacker knows precisely when to resume. Can automate attack-pause-attack cycles synchronized with the timeout.
- **Fix**: Randomize timeout (e.g., 240-360s). Implement escalating timeouts for repeat offenders. Consider permanent blocking with manual unblock.

---

## 4. ML Model Limitations

### ML-01: Feature leakage from idle_timeout and hard_timeout
- **File**: `datasets/generate_full_dataset.py`, `sdn_controller/mitigation_module.py:265-272`
- **Problem**: Synthetic attack flows have `idle_timeout ∈ {0, 5}`, normal flows have `idle_timeout ∈ {10, 15, 20, 30}`. But in production, the controller assigns `idle_timeout=10, hard_timeout=30` to ALL forwarding flows regardless of classification. The model learns a signal that doesn't exist at inference time. This is training/serving skew.
- **Fix**: Remove `idle_timeout` and `hard_timeout` from the feature set, or fix the synthetic generator to use the same timeout values the controller assigns.

### ML-02: No cross-validation, no hyperparameter tuning
- **File**: `ml_model/train_model.py:217-221`
- **Problem**: Single 75/25 split with hardcoded hyperparameters (100 trees, depth 20, random_state=42). No k-fold CV, no grid search, no learning curves. Evaluating on exactly one test fold.
- **Fix**: Use 5-fold or 10-fold stratified CV. Report mean ± std. Use `GridSearchCV` or `RandomizedSearchCV` for hyperparameter tuning.

### ML-03: Class imbalance not addressed
- **Problem**: 65/35 split. Accuracy as headline metric. A "predict always normal" dummy classifier gets 65%. Reported 84.5% is only ~20 points above baseline. No cost-sensitive learning, no SMOTE, no threshold tuning.
- **Fix**: Report precision-recall curves. Tune classification threshold. Use `class_weight='balanced'` in RandomForest. Report lift over baseline.

### ML-04: No confidence threshold — 51% triggers same as 99%
- **File**: `sdn_controller/mitigation_module.py:432`
- **Problem**: `prediction[0] == 1` uses the default 50% threshold. A flow predicted as attack with 51% probability triggers the same DROP rule as one at 99%. No tiered response.
- **Fix**: Use `model.predict_proba()` and set a configurable confidence threshold. Implement tiered responses: monitor at 60%, rate-limit at 80%, block at 95%.

### ML-05: Per-flow classification ignores aggregate behavior
- **Problem**: Each flow classified independently. Real DDoS detection requires understanding aggregate patterns: many flows from diverse sources to one target, flow table exhaustion rate, sudden flow creation spikes. Per-flow classifier cannot detect distributed attacks where each individual flow looks normal.
- **Fix**: Add aggregate features: flows-per-destination, unique-sources-per-destination, flow creation rate, entropy-based metrics.

### ML-06: No concept drift detection or retraining pipeline
- **Problem**: Model trained once and loaded statically. Network patterns change over time. No mechanism to detect when predictions become unreliable. No retraining pipeline.
- **Fix**: Log prediction probabilities. Monitor distribution shifts. Alert when confidence distribution changes. Build automated retraining pipeline.

### ML-07: No adversarial robustness testing
- **Problem**: No testing against adversarial examples. Attacker who knows the 10 features can craft traffic that sits just below decision boundaries. No evaluation of model robustness to feature manipulation.
- **Fix**: Generate adversarial examples using FGSM or PGD adapted for tabular data. Report model accuracy under adversarial perturbation. Consider adversarial training.

### ML-08: No temporal validation
- **Problem**: Single random split ignores temporal ordering. In real networks, training on past data and testing on future data is essential. Random splitting allows the model to "see the future" during training.
- **Fix**: Use time-based train/test split. Train on first N% of time-ordered data, test on remaining.

### ML-09: No baseline comparison
- **Problem**: No comparison to simple threshold-based detection (e.g., if `pps > X`, flag as attack). A threshold classifier may match RF accuracy on this data, proving the features — not the model — do the work.
- **Fix**: Implement and report results for: (1) threshold on pps, (2) logistic regression, (3) decision stump. Show RF adds value beyond these.

---

## 5. Networking Design Problems

### NET-01: Flooding on unknown destination — amplification risk
- **File**: `sdn_controller/mitigation_module.py:252-254`
- **Problem**: Unknown MACs cause flooding to all ports. In 16-link spine-leaf, one unknown-dest packet is replicated 15 times. Attacker sending random dest MACs creates packet multiplication without being detected by ML (flooding doesn't create classifiable flows).
- **Fix**: Rate-limit OFPP_FLOOD. Implement ARP-based learning. Consider proactive forwarding.

### NET-02: 5-second polling interval too slow for real-time detection
- **File**: `sdn_controller/mitigation_module.py:326`
- **Problem**: At 100,000 pps attack rate, 500,000 packets pass before first detection. After detection, FlowMod propagation adds more delay.
- **Fix**: Reduce to 1-2 seconds. Implement threshold-based fast-path detection (if pps > 10000 on any flow, block immediately without ML) alongside the ML slow path.

### NET-03: Short flow timeouts cause excessive PacketIn
- **File**: `sdn_controller/mitigation_module.py:265-272`
- **Problem**: `idle_timeout=10, hard_timeout=30`. Every expiry triggers new PacketIn on next matching packet. Under heavy traffic, continuous PacketIn stream overwhelms the controller.
- **Fix**: Increase timeouts for stable flows. Implement flow refresh on stats reply instead of re-learning.

### NET-04: Flows without IPv4 match fields silently skip mitigation
- **File**: `sdn_controller/mitigation_module.py:439-440`
- **Problem**: `if src_ip == 'unknown': continue`. ARP floods, non-IP attacks, and flows installed by MAC learning (which lack IPv4 fields) are never evaluated by the ML model.
- **Fix**: Log skipped flows. Add ARP flood detection separately. Consider extracting Ethernet-level features for non-IP traffic.

### NET-05: No IPv6 support
- **File**: `sdn_controller/mitigation_module.py:537-540`
- **Problem**: Entire system assumes IPv4 (`eth_type=0x0800`). IPv6 DDoS attacks pass through undetected.
- **Fix**: Add IPv6 feature extraction. Support `eth_type=0x86DD`. Extend feature set with IPv6-specific fields.

### NET-06: No VLAN awareness or multi-tenancy
- **Problem**: Controller treats entire network as flat L2 domain. No VLAN tagging, no tenant isolation, no per-tenant policies.
- **Fix**: Add VLAN-aware MAC learning. Support per-VLAN detection policies. Track flows per tenant.

---

## 6. Performance Bottlenecks

### PERF-01: Per-flow predict() calls (see ARCH-02)
- Covered under ARCH-02. 10-100x speedup available through batching.

### PERF-02: CSV file append with exclusive lock per flow
- **File**: `utilities/dataset_collector.py:192-202`
- **Problem**: `add_flow()` opens file, acquires exclusive lock, writes one row, releases lock, closes — per flow. Severe I/O contention under heavy collection.
- **Fix**: Buffer writes and flush periodically. Use `add_flows_batch()`. Consider in-memory buffer with periodic flush.

### PERF-03: Attack log existence checked on every write
- **File**: `sdn_controller/mitigation_module.py:595`
- **Problem**: `os.path.isfile()` called on every `_log_attack()` invocation. During active attack, called hundreds of times.
- **Fix**: Check and write headers in `__init__`. Only append in `_log_attack`.

### PERF-04: blocked_ips grows unbounded — memory leak
- **File**: `sdn_controller/mitigation_module.py:87,454-469`
- **Problem**: Expired entries only cleaned up reactively when same IP re-detected. Unique IPs attacked once stay in memory forever.
- **Fix**: Add periodic cleanup thread that removes expired entries every 60 seconds.

### PERF-05: 5-second polling interval hardcoded
- **File**: `sdn_controller/mitigation_module.py:326`
- **Problem**: `hub.sleep(5)` is a magic number. Cannot be tuned without editing source code.
- **Fix**: Make configurable via `ryu.conf` or command-line argument.

---

## 7. Scalability Issues

### SCALE-01: O(n) iteration over all flows on all switches
- **File**: `sdn_controller/mitigation_module.py:355`
- **Problem**: Every flow on every switch iterated and classified per cycle. With thousands of switches and millions of flows, controller falls over.
- **Fix**: Implement sampling-based detection. Use switch-side filtering. Only request stats for flows matching suspicious criteria.

### SCALE-02: Controller state in-memory with no persistence
- **Problem**: `mac_to_port`, `datapaths`, `blocked_ips` all in-memory dicts. Controller restart loses all state: MAC learning, block rules, detection history.
- **Fix**: Persist to Redis or SQLite. Implement state synchronization on restart.

### SCALE-03: Topology hardcoded for 2+3+10
- **File**: `network_topology/topology.py:68-70`
- **Problem**: `SPINE_COUNT=2, LEAF_COUNT=3, HOST_COUNT=10` and host distribution hardcoded. Cannot scale for testing with 100-1000 hosts without editing source.
- **Fix**: Accept as command-line arguments. Compute host distribution algorithmically.

### SCALE-04: Single-threaded stats processing for all switches
- **File**: `sdn_controller/mitigation_module.py:288-326`
- **Problem**: One thread polls all switches sequentially. Stats replies processed serially. With many switches, processing one reply delays all others.
- **Fix**: Process stats replies in parallel. Use per-switch worker threads or asyncio.

---

## 8. Code Quality Problems

### CODE-01: Bare except clauses swallow errors silently
- **Files**: `sdn_controller/mitigation_module.py:111-116`, `traffic_generation/generate_normal.py:145-146`
- **Problem**: `except Exception` catches everything. `TypeError` in command construction looks same as network timeout. Bugs are masked.
- **Fix**: Catch specific exceptions. Log full tracebacks for unexpected errors.

### CODE-02: Shell injection risk in traffic generation
- **File**: `traffic_generation/generate_normal.py:134-141`
- **Problem**: Commands built via f-string and passed to `shell=True`. While inputs are internally generated now, `shell=True` is unsafe if input sources change.
- **Fix**: Use `subprocess.run(['ping', '-c', str(count), dst_ip], shell=False)`.

### CODE-03: HTTP server process leak
- **File**: `traffic_generation/generate_normal.py:266-270`
- **Problem**: Every HTTP traffic call starts a new `python3 -m http.server` process. Over 300s, creates 20-60 orphaned servers. Port conflicts and zombie processes.
- **Fix**: Start HTTP server once at beginning of run. Check if already running before starting.

### CODE-04: Hardcoded magic numbers throughout
- **Files**: Multiple
- **Problem**: `5` (poll interval), `300` (block timeout), `32768` (block priority), `10` (idle timeout), `30` (hard timeout), `0x0800` (IPv4 ethertype), `0x88cc` (LLDP) — all bare literals. No named constants.
- **Fix**: Define as module-level constants with descriptive names. Make configurable where appropriate.

### CODE-05: Inconsistent error handling patterns
- **Problem**: Some functions return `bool` success/failure, some raise exceptions, some log and continue, some exit. No consistent contract.
- **Fix**: Establish error handling conventions. Critical path: raise exceptions. Background tasks: log and continue. User-facing scripts: print and exit with code.

### CODE-06: No tests, no CI/CD
- **Problem**: `feature_extractor.py` and `dataset_collector.py` have self-tests via `__main__`, but no test framework (pytest), no test directory, no CI pipeline. Cannot validate changes don't break existing functionality.
- **Fix**: Move self-tests to `tests/` directory using pytest. Add GitHub Actions CI. Run tests on every push.

### CODE-07: Silent exception swallowing in ML prediction path
- **File**: `sdn_controller/mitigation_module.py:480-484`
- **Problem**: ML prediction errors caught by bare `except Exception` and logged, but the flow is silently skipped. A systematic error (e.g., wrong feature count) would silently disable all detection with no alert.
- **Fix**: Count consecutive prediction failures. Alert if failure rate exceeds threshold. Distinguish recoverable vs. systematic errors.

---

## 9. Real-World Deployment Limitations

### DEPLOY-01: Mininet is not a production network
- **Problem**: Validated only in Mininet (kernel namespaces, virtual switches). Real switches have hardware flow table limits (2K-8K entries), TCAM constraints, different timing characteristics, firmware-specific OpenFlow bugs.
- **Fix**: Test on hardware switches (even commodity ones). Document known hardware compatibility.

### DEPLOY-02: No encrypted traffic awareness
- **Problem**: Feature set has no application-layer info. HTTPS/TLS traffic indistinguishable from encrypted attacks. HTTP floods, Slowloris have normal-looking flow features and evade detection.
- **Fix**: Add flow-level behavioral features (inter-packet timing, burst patterns). Consider JA3/JA4 TLS fingerprinting at the switch level.

### DEPLOY-03: No integration with existing security infrastructure
- **Problem**: No syslog, no SNMP traps, no REST API for SIEM, no BGP Flowspec for upstream mitigation, no threat intelligence feeds.
- **Fix**: Add syslog/CEF output. Implement REST API. Consider BGP Flowspec for upstream signaling.

### DEPLOY-04: No comparison to simple baseline methods
- **Problem**: No evidence that Random Forest outperforms a simple threshold on pps. With trivially separable data, any method works.
- **Fix**: Implement and report: (1) pps threshold, (2) logistic regression, (3) isolation forest. Demonstrate RF adds value.

### DEPLOY-05: Silent ML degradation when model files missing
- **File**: `sdn_controller/mitigation_module.py:99-116`
- **Problem**: If model files missing, controller silently degrades to basic L2 switch. No alert, no health check endpoint, no monitoring integration. Operator may not notice detection is disabled.
- **Fix**: Add health check endpoint. Log periodic status. Emit metric for monitoring systems. Consider startup flag to require model presence.

---

## Summary — All 50 Findings by Severity

| ID | Severity | Category | Summary |
|----|----------|----------|---------|
| CRIT-01 | Critical | Security | DROP by source IP — self-DoS amplification |
| CRIT-02 | Critical | Security | Pickle deserialization RCE |
| CRIT-03 | Critical | Security | No packet-in rate limiting |
| CRIT-04 | Critical | ML | Synthetic-only training data |
| CRIT-05 | Critical | Security | No OpenFlow authentication |
| CRIT-06 | Critical | Networking | No loop prevention — broadcast storm |
| CRIT-07 | Critical | Security | API listening on 0.0.0.0 |
| ARCH-01 | High | Architecture | Blocking ML inference in control path |
| ARCH-02 | High | Performance | Per-flow predict() instead of batching |
| ARCH-03 | High | Architecture | No controller redundancy |
| ARCH-04 | High | Architecture | Feature definition duplicated 4x |
| ARCH-05 | High | Architecture | No graceful shutdown |
| ARCH-06 | High | Architecture | MAC table grows unbounded |
| SEC-01 | High | Security | Model evasion via slow-rate attacks |
| SEC-02 | High | Security | No TCP flags in features |
| SEC-03 | High | Security | MAC table poisoning |
| SEC-04 | High | Security | Race conditions on shared dicts |
| SEC-05 | Medium | Security | CSV log injection |
| SEC-06 | Medium | Security | Logs world-readable, no integrity |
| SEC-07 | High | Security | No model integrity verification |
| SEC-08 | Medium | Security | Predictable 300s block timeout |
| ML-01 | High | ML | Feature leakage (idle/hard timeout) |
| ML-02 | High | ML | No cross-validation |
| ML-03 | Medium | ML | Class imbalance not addressed |
| ML-04 | High | ML | No confidence threshold |
| ML-05 | High | ML | Per-flow ignores aggregate behavior |
| ML-06 | Medium | ML | No concept drift detection |
| ML-07 | Medium | ML | No adversarial robustness testing |
| ML-08 | Medium | ML | No temporal validation |
| ML-09 | Medium | ML | No baseline comparison |
| NET-01 | High | Networking | Flood amplification risk |
| NET-02 | Medium | Networking | 5s polling too slow |
| NET-03 | Medium | Networking | Short timeouts → excessive PacketIn |
| NET-04 | Medium | Networking | Non-IPv4 flows skip mitigation |
| NET-05 | Medium | Networking | No IPv6 support |
| NET-06 | Medium | Networking | No VLAN / multi-tenancy |
| PERF-01 | High | Performance | Per-flow predict (see ARCH-02) |
| PERF-02 | Medium | Performance | CSV lock contention |
| PERF-03 | Low | Performance | Log existence check per write |
| PERF-04 | Medium | Performance | blocked_ips memory leak |
| PERF-05 | Low | Performance | Hardcoded poll interval |
| SCALE-01 | High | Scalability | O(n) all flows all switches |
| SCALE-02 | Medium | Scalability | No state persistence |
| SCALE-03 | Low | Scalability | Hardcoded topology size |
| SCALE-04 | Medium | Scalability | Single-threaded stats processing |
| CODE-01 | Medium | Code | Bare except swallows errors |
| CODE-02 | Medium | Code | Shell injection risk |
| CODE-03 | Low | Code | HTTP server process leak |
| CODE-04 | Low | Code | Hardcoded magic numbers |
| CODE-05 | Low | Code | Inconsistent error handling |
| CODE-06 | Medium | Code | No tests, no CI/CD |
| CODE-07 | Medium | Code | Silent ML prediction failures |
| DEPLOY-01 | Medium | Deployment | Mininet-only validation |
| DEPLOY-02 | Medium | Deployment | No encrypted traffic handling |
| DEPLOY-03 | Medium | Deployment | No SIEM/infra integration |
| DEPLOY-04 | Medium | Deployment | No baseline comparison |
| DEPLOY-05 | Medium | Deployment | Silent ML degradation |

**Total: 7 Critical, 16 High, 27 Medium, 6 Low**
