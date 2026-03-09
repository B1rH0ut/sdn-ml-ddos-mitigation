# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-03-10

### Breaking Changes
- **Feature set redesigned from 10 to 12 features** — removed `idle_timeout` and `hard_timeout` (OpenFlow artifacts, not traffic characteristics); added `avg_packet_size`, `flows_to_dst`, `unique_sources_to_dst`, `flow_creation_rate` (aggregate behavior features that capture DDoS patterns invisible at the individual flow level). Models trained on v1.0.0 datasets are incompatible.
- Dataset CSV format changed to match new 12-feature schema.
- Model artifacts (`flow_model.pkl`, `scaler.pkl`) must be regenerated.

### Added
- **SHA-256 model integrity verification** — controller validates `.pkl` file hashes before loading to prevent pickle RCE attacks.
- **PacketIn rate limiting** — per-switch throttling prevents controller DoS via packet flooding.
- **Flood rate limiting** — per-switch broadcast caps prevent amplification attacks.
- **MAC table aging** — entries auto-expire after 300s to prevent unbounded growth.
- **Port security** — maximum 5 MACs per port per switch.
- **Broadcast loop suppression** — duplicate flood tracking complements STP.
- **Randomized block timeouts** — DROP rule durations vary ±20% to prevent predictable attack windows.
- **Concept drift detection** — monitors prediction distribution shifts over time via exponential moving average.
- **State persistence** — controller saves/restores blocked IPs and MAC tables across restarts via JSON.
- **Graceful shutdown** — SIGTERM/SIGINT handlers persist state before exit.
- **Thread-safe shared state** — explicit locks on all shared data structures.
- **CSV log sanitization** — IP validation prevents injection in attack logs.
- **Localhost-only bindings** — OpenFlow and REST API bound to `127.0.0.1`.
- **Configurable topology** — `topology.py` accepts `--spines`, `--leaves`, `--hosts` CLI arguments.
- **pytest test suite** — 34 tests covering feature extraction (18) and dataset collection (16).
- **5-fold stratified cross-validation** in training pipeline.
- **Baseline comparison** — majority class, logistic regression, and PPS threshold baselines.
- **Adversarial robustness testing** — evaluates model under Gaussian noise at multiple levels.
- **ROC curve generation** — `create_roc.py` for model performance visualization.
- **Performance monitor** — `utilities/performance_monitor.py` tracks CPU, memory, and flow counts.
- **Log analysis tool** — `logs/analyze_logs.py` for post-run reporting.
- `AUDIT_REPORT.md` — 56-item security audit with categorized findings.

### Improved
- **Batched ML inference** — single `predict()` call per stats reply instead of per-flow classification.
- **Flow sampling** — large flow tables (>500 flows) are sampled at 30% for scalability.
- **ML confidence threshold** — uses `predict_proba()` with configurable threshold (default 0.7) instead of binary classification.
- **Specific DROP rules** — blocks `(src_ip, dst_ip, ip_proto)` tuples instead of entire source IPs.
- **Dataset generation** — rewritten for 12-feature output with realistic statistical distributions.
- **Single source of truth** — all feature definitions centralized in `utilities/feature_extractor.py`.

### Fixed
- Shell injection vulnerabilities in traffic generation scripts (replaced `shell=True` with list-based `subprocess.run()`).
- HTTP server process leak in `generate_normal.py` (single instance reused, cleanup on exit).
- OVS fail-mode changed from `secure` to `standalone` for proper fallback behavior.
- STP enabled on all switches to prevent broadcast storms in spine-leaf topology.

### Security
- Completed 56-item security audit (see `AUDIT_REPORT.md`).
- 7 critical findings resolved (model integrity, shell injection, controller DoS, binding exposure).

## [1.0.0] - 2025-01-01

### Added
- Initial SDN controller with basic L2 MAC learning and DDoS detection.
- Mininet spine-leaf topology (2 spine + 3 leaf switches, 10 hosts).
- Random Forest classifier with 10-feature flow analysis.
- Normal traffic generator (ICMP, TCP, HTTP mix).
- Attack generator using hping3 (ICMP, SYN, UDP floods).
- Synthetic dataset generator.
