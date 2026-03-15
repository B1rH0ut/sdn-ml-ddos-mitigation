# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-03-16

### Breaking Changes
- **`src/` package layout** — all modules moved under `src/sdn_ddos_detector/`. All import paths changed (see `docs/ARCHITECTURE.md` for migration table).
- **`pyproject.toml` replaces `requirements.txt`** — install via `pip install -e ".[dev,ml]"`.
- **Polling interval reduced from 5s to 3s** for faster detection response.
- **HMAC-SHA256 model signing** — models must be signed with `sign_model.py` before the controller will load them. Set `SDN_MODEL_HMAC_KEY` environment variable.
- **All import paths changed** — `utilities.feature_extractor` → `sdn_ddos_detector.ml.feature_engineering`, etc.

### Added
- **Real dataset integration** — CIC-IDS2017, CIC-DDoS2019, UNSW-NB15 adapters with automatic download and feature mapping.
- **ECMP load balancing** via OpenFlow group tables, replacing STP for spine-leaf inter-tier forwarding.
- **TLS support** for OpenFlow channel encryption (`SDN_TLS_CERT`, `SDN_TLS_KEY` env vars).
- **Circuit breaker** (Fowler pattern) — isolates ML inference failures, falls back to threshold-based detection.
- **ADWIN drift detection** (via River library) — monitors prediction distribution for concept drift with adaptive windowing.
- **91 automated tests** — unit tests for all components, adversarial robustness tests with ART.
- **Docker support** — `Dockerfile.controller`, `Dockerfile.mininet`, and `docker-compose.yml`.
- **Makefile** with targets for setup, training, testing, linting, and Docker operations.
- **Adversarial testing** with Gaussian noise at multiple levels via Adversarial Robustness Toolbox.
- **Spoofing-resistant features** — aggregate per-destination stats (`flows_to_dst`, `unique_sources_to_dst`, `flow_creation_rate`) are harder to manipulate with spoofed sources.
- **Rate-of-change detection** in threshold fast-path for immediate volumetric attack response.
- **BCP38 anti-spoofing** — ingress filtering rules at leaf switches based on known host-port mappings.
- **API token authentication** — REST API requires `SDN_API_TOKEN` bearer token.
- **Destination-based blocking** — DROP rules match `(src_ip, dst_ip, ip_proto)` tuples for precise mitigation.
- **Model signing utility** (`scripts/sign_model.py`) for HMAC-SHA256 hash generation.
- **Bounded caches** (`BoundedMACTable`, `BoundedIPCounter`, `BoundedFloodHistory`) prevent unbounded memory growth.
- **Structured logging** via structlog with async file handlers.
- **Topology configuration module** (`config/topology_config.py`) centralizing ECMP groups, port mappings, and priorities.
- **Architecture documentation** (`docs/ARCHITECTURE.md`), security guide (`docs/SECURITY.md`), known limitations (`docs/KNOWN_LIMITATIONS.md`).

### Changed
- **`src/` package layout** — standard Python packaging with `setuptools` and `pyproject.toml`.
- **eventlet locks** — all shared state protected by `eventlet.semaphore.Semaphore` instead of `threading.Lock`.
- **Bounded caches** replace unbounded dicts for MAC tables, IP counters, and flood history.
- **Async logging** — file handlers use `QueueHandler`/`QueueListener` to avoid blocking the event loop.
- **Network-wide mitigation** — DROP rules installed on ALL switches, not just the detecting switch (audit 2.4).
- **Temporal split** is now the default train/test strategy for real datasets (prevents data leakage from random splitting of time-series data).

### Fixed
- **Hash verification bypass** — HMAC-SHA256 replaces SHA-256 to prevent hash-only forgery.
- **Feature skew** — unified feature engineering module eliminates train/serve skew.
- **STP blocking** — replaced STP with ECMP group tables for spine-leaf forwarding.
- **Flow sampling evasion** — priority-based sampling replaces random sampling (audit 7.2).
- **Flood suppression bypass** — bounded flood rate limiter with per-switch caps.
- **Concept drift EMA masking** — ADWIN replaces fixed-alpha EMA that masked gradual drift.

### Security
- **HMAC-SHA256 model integrity** — env-var-based keyed hashing prevents both tampering and hash forgery.
- **BCP38 anti-spoofing** — ingress filtering at leaf switches blocks spoofed source IPs.
- **API token authentication** — REST API protected with bearer token from `SDN_API_TOKEN`.
- **Destination-based blocking** — precise `(src, dst, proto)` DROP rules instead of blanket source blocking.
- **TLS support** for OpenFlow controller-switch channel encryption.

### Removed
- `requirements.txt` — replaced by `pyproject.toml` with optional dependency groups.
- `sys.path` hacks — eliminated by proper `src/` package layout and `pip install -e .`.

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
