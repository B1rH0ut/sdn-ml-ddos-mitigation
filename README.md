# SDN-Based DDoS Detection and Mitigation with Machine Learning

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Tests: 91 passing](https://img.shields.io/badge/tests-91%20passing-brightgreen)

An intelligent network security system that combines **Software-Defined Networking (SDN)** with a **Random Forest classifier** to detect and automatically mitigate DDoS attacks in real time. Validated on three real-world datasets (CIC-IDS2017, CIC-DDoS2019, UNSW-NB15) and hardened against 44 of 56 audit findings. Built on a Ryu OpenFlow 1.3 controller with two-stage detection (threshold fast-path + ML), ECMP load balancing, and network-wide mitigation across a spine-leaf topology.

> Capstone project: Computer Engineering (Networking)

---

## Quick Start

**Python 3.10–3.13 required.** Python 3.14+ is not yet supported due to dependency compatibility (Ryu, river).

```bash
git clone https://github.com/B1rH0ut/sdn-ml-ddos-mitigation.git
cd sdn-ml-ddos-mitigation
make setup       # pip install -e ".[dev,ml]"
make train       # Train RF model on synthetic dataset
make run         # Start Ryu SDN controller
```

---

## How It Works

```
                    ┌─────────────────────────────────────┐
                    │         Application Layer           │
                    │   Two-Stage Detection Pipeline      │
                    │  Threshold fast-path (immediate)    │
                    │  RF predict_proba() (confidence≥0.7)│
                    │  Circuit breaker + ADWIN drift      │
                    │  HMAC-SHA256 model verification     │
                    └────────────────┬────────────────────┘
                                     │ predict / block
                    ┌────────────────▼────────────────────┐
                    │          Control Layer              │
                    │    Ryu SDN Controller (OF 1.3)      │
                    │  TLS channel · MAC learning · ECMP  │
                    │  Rate limiting · API auth · BCP38   │
                    │  3s stats polling · async logging   │
                    └────────────────┬────────────────────┘
                                     │ OpenFlow 1.3 (TLS)
                    ┌────────────────▼────────────────────┐
                    │           Data Layer               │
                    │    Mininet Spine-Leaf Topology      │
                    │  ECMP uplinks · Anti-spoofing rules │
                    │  Network-wide DROP · Bounded caches │
                    └─────────────────────────────────────┘
```

1. The **Ryu controller** manages a spine-leaf network with ECMP load-balanced uplinks
2. Every **3 seconds**, it collects flow statistics from all switches
3. **Threshold fast-path** catches obvious volumetric attacks immediately
4. **12 features** are extracted per flow, including per-destination aggregate behavior
5. Features are **batched** and classified by a **Random Forest model** using `predict_proba()`
6. Flows exceeding the **confidence threshold** (0.7) trigger **network-wide DROP rules** on all switches
7. **HMAC-SHA256** model integrity verification prevents pickle deserialization attacks
8. **Circuit breaker** falls back to threshold-only detection if ML inference fails

---

## Detection Pipeline

```
Flow Stats Reply (all switches, every 3s)
        │
        ▼
┌──────────────┐    ┌──────────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────────┐
│ Filter & Map │──▶ │ Threshold    │──▶ │ Batch Scale   │──▶ │ RF Predict   │──▶ │ Network-wide │
│  IPv4 flows  │    │ Fast-Path    │    │ StandardScaler│    │ predict_proba│    │ DROP + Log   │
│  + sampling  │    │ (immediate)  │    │  (σ, μ)       │    │ threshold≥0.7│    │ all switches │
└──────────────┘    └──────────────┘    └───────────────┘    └──────────────┘    └──────────────┘
                     │ ATTACK                                  │ confidence
                     ▼ (bypass ML)                             ▼ < 0.7
                   DROP                                      ALLOW
```

**Features extracted per flow (12):**

| # | Feature                   | Description                                  |
|---|---------------------------|----------------------------------------------|
| 1 | `flow_duration_sec`       | How long the flow has been active            |
| 2 | `packet_count`            | Total packets in flow                        |
| 3 | `byte_count`              | Total bytes in flow                          |
| 4 | `packet_count_per_second` | Packet rate                                  |
| 5 | `byte_count_per_second`   | Byte rate                                    |
| 6 | `avg_packet_size`         | Average bytes per packet                     |
| 7 | `ip_proto`                | IP protocol number (1=ICMP, 6=TCP, 17=UDP)  |
| 8 | `icmp_code`               | ICMP code field                              |
| 9 | `icmp_type`               | ICMP type field                              |
| 10 | `flows_to_dst`           | Number of flows targeting same destination   |
| 11 | `unique_sources_to_dst`  | Unique source IPs targeting same destination |
| 12 | `flow_creation_rate`     | New flows per second to same destination     |

Features 10-12 are **aggregate behavior features** that capture DDoS patterns invisible at the individual flow level. All feature definitions live in `sdn_ddos_detector.ml.feature_engineering` — the single source of truth.

---

## Validated Datasets

| Dataset | Records | Attack Types | Citation |
|---------|---------|-------------|----------|
| CIC-IDS2017 | 2,830,743 | Brute Force, DoS, DDoS, Web Attack, Infiltration, Botnet | Sharafaldin et al., 2018 |
| CIC-DDoS2019 | 50,063,112 | LDAP, MSSQL, NetBIOS, SYN, UDP, DNS amplification | Sharafaldin et al., 2019 |
| UNSW-NB15 | 2,540,044 | Fuzzers, Analysis, Backdoors, DoS, Exploits, Reconnaissance, Shellcode, Worms | Moustafa & Slay, 2015 |
| Synthetic | 505,433 | ICMP Flood, SYN Flood, UDP Flood | Generated via `make train` |

Dataset adapters automatically map each dataset's columns to the 12-feature schema. Download real datasets with `make download-data`.

---

## Network Topology

```
          s1 (spine)            s2 (spine)
         /    |    \           /    |    \
        /     |     \         /     |     \
      s3      s4      s5    s3     s4      s5
    (leaf)  (leaf)  (leaf)
     /|\     /||\     /|\
    / | \   / || \   / | \
  h1 h2 h3 h4 h5 h6 h8 h9 h10
              h7
```

- **5 OpenFlow 1.3 switches** in a 2-tier spine-leaf (Clos) architecture
- **ECMP load balancing** via group tables across all spine uplinks
- **BCP38 anti-spoofing** rules installed at leaf switch ingress
- **100 Mbps** links with **5 ms** delay
- **Configurable** via CLI: `sudo python -m sdn_ddos_detector.topology.topology --spines 4 --leaves 6 --hosts 50`

---

## Security Features

| Feature | Description |
|---------|-------------|
| HMAC-SHA256 model verification | Keyed hash verification before `joblib.load()` (prevents pickle RCE) |
| TLS OpenFlow channel | Encrypted controller-switch communication |
| API token authentication | Bearer token required for REST API access |
| BCP38 anti-spoofing | Ingress filtering at leaf switches blocks spoofed source IPs |
| Destination-based blocking | DROP rules match `(src_ip, dst_ip, ip_proto)` tuples |
| Network-wide mitigation | DROP rules installed on ALL switches, not just ingress |
| ECMP load balancing | Group tables distribute traffic across spine uplinks |
| Circuit breaker | Isolates ML failures; falls back to threshold detection |
| ADWIN drift detection | Monitors prediction distribution for concept drift |
| PacketIn rate limiting | Per-switch throttling prevents controller DoS |
| Flood rate limiting | Per-switch broadcast caps prevent amplification |
| Bounded caches | Fixed-size MAC tables, IP counters, flood history |
| MAC table aging | Entries auto-expire after 300s |
| Port security | Maximum 5 MACs per port per switch |
| ML confidence threshold | Only blocks flows with attack probability >= 0.7 |
| Localhost-only bindings | OpenFlow and REST API bound to `127.0.0.1` |
| Graceful shutdown | SIGTERM/SIGINT handlers persist state before exit |

---

## Project Structure

```
├── src/sdn_ddos_detector/
│   ├── controller/
│   │   ├── ddos_controller.py     # Ryu controller: L2 learning + ML detection + mitigation
│   │   └── api_auth.py            # REST API token authentication
│   ├── ml/
│   │   ├── feature_engineering.py # 12-feature definition (single source of truth)
│   │   ├── train.py               # RF training, cross-validation, baselines
│   │   ├── evaluation.py          # ROC curves, performance metrics
│   │   ├── circuit_breaker.py     # ML failure isolation with threshold fallback
│   │   ├── drift_detector.py      # ADWIN-based concept drift monitoring
│   │   ├── generate_synthetic_dataset.py  # Synthetic flow dataset generator
│   │   └── dataset_adapters/      # CIC-IDS2017, CIC-DDoS2019, UNSW-NB15
│   ├── config/
│   │   └── topology_config.py     # ECMP groups, port mappings, priorities
│   ├── topology/
│   │   └── topology.py            # Mininet spine-leaf network creation
│   ├── traffic/
│   │   └── generate_normal.py     # Normal traffic generator
│   ├── utils/
│   │   ├── bounded_cache.py       # Memory-safe MAC/IP/flood tables
│   │   ├── dataset_collector.py   # Buffered CSV collection
│   │   ├── logging_config.py      # Structured async logging setup
│   │   └── performance_monitor.py # CPU/memory/flow monitoring
│   ├── scripts/
│   │   ├── sign_model.py          # HMAC-SHA256 model signing
│   │   └── analyze_logs.py        # Post-run log analysis
│   └── datasets/
│       └── download_datasets.py   # Real dataset downloader
│
├── tests/
│   ├── unit/                      # 84 unit tests
│   └── adversarial/               # 7 adversarial robustness tests
│
├── docker/
│   ├── Dockerfile.controller      # Controller container
│   ├── Dockerfile.mininet         # Mininet container (Linux only)
│   └── README.md                  # Docker setup guide
│
├── docs/
│   ├── ARCHITECTURE.md            # System architecture and design decisions
│   ├── SECURITY.md                # Security model and hardening guide
│   ├── KNOWN_LIMITATIONS.md       # Known limitations and future work
│   └── AUDIT_REPORT.md            # 56-item security audit findings
│
├── docker-compose.yml             # Multi-container orchestration
├── Makefile                       # Build, test, run targets
├── pyproject.toml                 # Package config and dependencies
├── CHANGELOG.md                   # Version history
└── LICENSE                        # MIT License
```

---

## Tech Stack

| Component               | Technology                                                    |
|-------------------------|---------------------------------------------------------------|
| SDN Controller          | Ryu 4.34 (OpenFlow 1.3)                                      |
| Network Emulation       | Mininet 2.3+ with Open vSwitch                               |
| ML Classifier           | scikit-learn Random Forest (100 trees, depth 20, balanced)    |
| Feature Scaling         | StandardScaler (fit on training data only)                    |
| Model Integrity         | HMAC-SHA256 verification before loading                       |
| Drift Detection         | River (ADWIN)                                                 |
| Adversarial Testing     | Adversarial Robustness Toolbox (ART)                          |
| Concurrency             | eventlet green threads                                        |
| Logging                 | structlog with async handlers                                 |
| Attack Simulation       | hping3 (ICMP, SYN, UDP floods)                               |
| Traffic Generation      | iperf, wget, ping                                             |
| Testing                 | pytest (91 tests)                                             |
| Linting                 | ruff                                                          |
| Containerization        | Docker + Docker Compose                                       |
| Language                | Python 3.10–3.13                                              |

---

## Docker

Run the full system in containers:

```bash
# Build images
docker compose build

# Set environment variables
export SDN_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export SDN_MODEL_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Start controller and network
docker compose up -d

# View logs
docker compose logs -f controller

# Stop
docker compose down
```

See [`docker/README.md`](docker/README.md) for details. Note: the Mininet container requires Linux with `--privileged` mode.

---

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — system design, component diagrams, design decisions
- [Security](docs/SECURITY.md) — defense layers, hardening checklist, vulnerability reporting
- [Known Limitations](docs/KNOWN_LIMITATIONS.md) — fundamental limits and future work
- [Changelog](CHANGELOG.md) — version history
- [Audit Report](docs/AUDIT_REPORT.md) — 56-item security audit findings

---

## Citation

```bibtex
@misc{sdn-ml-ddos-2026,
  author       = {Abdullah Al-Hout},
  title        = {{SDN}-Based {DDoS} Detection and Mitigation with Machine Learning},
  year         = {2026},
  howpublished = {\url{https://github.com/B1rH0ut/sdn-ml-ddos-mitigation}},
  note         = {v3.0.0 — Research-grade SDN DDoS detection validated on CIC-IDS2017, CIC-DDoS2019, UNSW-NB15}
}
```

---

## Troubleshooting

| Problem                              | Solution                                                      |
|--------------------------------------|---------------------------------------------------------------|
| `ryu-manager: command not found`     | `make setup` or `pip install -e ".[dev,ml]"`                  |
| `ML model files not found` warning   | Run `make train` first                                        |
| Model integrity verification fails   | Re-run `make train` then `python -m sdn_ddos_detector.scripts.sign_model` |
| HMAC key not set                     | `export SDN_MODEL_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")` |
| API auth fails                       | `export SDN_API_TOKEN=your-token`                             |
| TLS not working                      | Set `SDN_TLS_CERT` and `SDN_TLS_KEY` env vars                |
| `This script must be run as root`    | Use `sudo` for topology and traffic scripts                   |
| Mininet cleanup errors               | Run `sudo mn -c` then restart topology                        |
| `pingall` shows packet loss          | Wait 15s for ECMP group table setup, then retry               |
| `hping3: command not found`          | `sudo apt-get install hping3`                                 |
| No switch connections                | Ensure controller is running *before* starting network        |
| Docker Mininet fails on macOS        | Mininet container requires Linux host (no macOS support)      |

---

## License

This project is licensed under the [MIT License](LICENSE).
