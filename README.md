# SDN-Based DDoS Detection and Mitigation with Machine Learning

An intelligent network security system that combines **Software-Defined Networking (SDN)** with a **Random Forest classifier** to detect and automatically mitigate DDoS attacks in real time. Built on a Ryu OpenFlow controller and tested on a Mininet-emulated spine-leaf data center topology.

> Capstone project: Computer Engineering (Networking)

---

## How It Works

```
                    ┌─────────────────────────────────┐
                    │       Application Layer         │
                    │    Random Forest Classifier     │
                    │  12 flow features · Scaler ·    │
                    │  Confidence threshold (0.7)     │
                    └───────────────┬─────────────────┘
                                    │ predict_proba()
                    ┌───────────────▼─────────────────┐
                    │        Control Layer            │
                    │   Ryu SDN Controller (OF 1.3)   │
                    │  MAC learning · Stats polling   │
                    │  Rate limiting · Loop prevention│
                    │  SHA-256 model verification     │
                    └───────────────┬─────────────────┘
                                    │ OpenFlow 1.3
                    ┌───────────────▼─────────────────┐
                    │         Data Layer              │
                    │   Mininet Spine-Leaf Topology   │
                    │  Configurable switches & hosts  │
                    │  STP enabled · 100Mbps links    │
                    └─────────────────────────────────┘
```

1. The **Ryu controller** manages a spine-leaf network with STP-enabled OpenFlow switches
2. Every **5 seconds** (configurable via `ryu.conf`), it collects flow statistics from all switches
3. **12 features** are extracted per flow, including per-destination aggregate behavior
4. Features are **batched** and classified by a **Random Forest model** using `predict_proba()`
5. Flows exceeding the **confidence threshold** (default 0.7) trigger a specific **DROP rule** on the switch
6. The controller verifies **SHA-256 model integrity** before loading to prevent tampering
7. All detections are **logged** to CSV with sanitized inputs

The controller gracefully degrades to a standard L2 switch if the ML model is not loaded.

---

## Detection Pipeline

```
Flow Stats Reply
        │
        ▼
┌──────────────┐    ┌──────────────┐    ┌───────────────┐    ┌──────────────┐    ┌──────────────┐
│ Filter & Map │──▶ │ Aggregate    │──▶ │ Batch Scale   │──▶ │ RF Predict   │──▶ │ DROP / Allow │
│  IPv4 flows  │    │ per-dst stats│    │ StandardScaler│    │ predict_proba│    │ + Log to CSV │
│  + sampling  │    │ 12 features  │    │  (σ, μ)       │    │ threshold≥0.7│    │ + syslog     │
└──────────────┘    └──────────────┘    └───────────────┘    └──────────────┘    └──────────────┘
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

Features 10–12 are **aggregate behavior features** that capture DDoS patterns invisible at the individual flow level (e.g., many sources flooding one target).

All feature definitions live in `utilities/feature_extractor.py` — the single source of truth imported by every module.

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

- **5 OpenFlow 1.3 switches** in a 2-tier spine-leaf (Clos) architecture (default; configurable)
- **Full mesh** between tiers — every leaf connects to every spine
- **10 hosts** (10.0.0.1–10, /24) distributed across leaf switches (default; configurable)
- **100 Mbps** links with **5 ms** delay
- **STP enabled** on all switches for loop prevention (15s convergence wait)
- **Configurable** via CLI: `sudo python3 topology.py --spines 4 --leaves 6 --hosts 50`

---

## Security Features

| Feature | Description |
|---------|-------------|
| SHA-256 model verification | Validates `.pkl` integrity before loading (prevents pickle RCE) |
| PacketIn rate limiting | Per-switch throttling prevents controller DoS |
| Flood rate limiting | Per-switch broadcast caps prevent amplification |
| Broadcast loop suppression | Duplicate flood tracking + STP on all switches |
| MAC table aging | Entries auto-expire after 300s to prevent unbounded growth |
| Port security | Maximum 5 MACs per port per switch |
| ML confidence threshold | Only blocks flows with attack probability above 0.7 |
| Specific DROP rules | Matches `(src_ip, dst_ip, ip_proto)` tuples, not entire source IPs |
| Randomized block timeouts | ±20% variation prevents predictable attack windows |
| CSV log sanitization | IP validation prevents injection in attack logs |
| Localhost-only bindings | OpenFlow and REST API bound to `127.0.0.1` |
| Graceful shutdown | SIGTERM/SIGINT handlers persist state before exit |
| Thread-safe shared state | Explicit locks on all shared data structures |
| Concept drift detection | Monitors prediction distribution shifts over time |

---

## Expected Output

### Model Training

Running `python3 train_model.py` produces:

```
======================================================================
  STEP 5: Evaluating Model Performance (holdout test set)
======================================================================

  Accuracy:      0.XXXX (XX.X%)
  Precision:     0.XXXX (XX.X%)
  Recall:        0.XXXX (XX.X%)
  F1-Score:      0.XXXX (XX.X%)
  ROC AUC:       0.XXXX

  Confusion Matrix:
                    Predicted
                  Normal  Attack
    Actual Normal   XXXXX   XXXXX
    Actual Attack   XXXXX   XXXXX

  Feature Importance (top contributors):
    packet_count_per_second        0.XXXX ##############
    byte_count_per_second          0.XXXX ###########
    flows_to_dst                   0.XXXX ########
    ...

======================================================================
  STEP 5b: Baseline Comparison
======================================================================
  Model                            Accuracy  Precision   Recall       F1
  PPS Threshold (best)              0.XXXX     0.XXXX   0.XXXX   0.XXXX
  Majority Class (always normal)    0.XXXX     0.XXXX   0.XXXX   0.XXXX
  Logistic Regression               0.XXXX     0.XXXX   0.XXXX   0.XXXX
  Random Forest (ours)              0.XXXX     0.XXXX   0.XXXX   0.XXXX
```

The training script also runs **5-fold cross-validation**, **baseline comparison** (majority class, logistic regression, PPS threshold), and **adversarial robustness testing** at multiple noise levels.

### Live Detection

When an attack is detected, the controller logs:

```
DDoS ATTACK DETECTED on switch dpid=5: src=10.0.0.3 dst=10.0.0.7 type=ICMP Flood pps=12847.3 confidence=0.983
ATTACK BLOCKED: DROP rule installed for src=10.0.0.3 dst=10.0.0.7 proto=1 on switch dpid=5 (expires in 287s)
```

| Detection Parameter     | Value                                     |
|-------------------------|--------------------------------------------|
| Flow polling interval   | 5 seconds (configurable via `ryu.conf`)    |
| Block rule priority     | 32768                                      |
| Block rule duration     | ~300 seconds (randomized ±20%)             |
| Confidence threshold    | 0.7 (configurable)                         |
| Supported attack types  | ICMP Flood, SYN Flood, UDP Flood           |

---

## Tech Stack

| Component               | Technology                                                  |
|-------------------------|-------------------------------------------------------------|
| SDN Controller          | Ryu 4.34 (OpenFlow 1.3)                                    |
| Network Emulation       | Mininet 2.3+ with Open vSwitch                             |
| ML Classifier           | scikit-learn Random Forest (100 trees, depth 20, balanced)  |
| Feature Scaling         | StandardScaler (fit on training data only)                  |
| Model Integrity         | SHA-256 hash verification before loading                    |
| Attack Simulation       | hping3 (ICMP, SYN, UDP floods)                             |
| Traffic Generation      | iperf, wget, ping                                          |
| Testing                 | pytest (34 tests)                                          |
| Performance Monitoring  | psutil                                                     |
| Language                | Python 3.8+ / Bash                                        |

---

## Project Structure

```
├── sdn_controller/
│   ├── mitigation_module.py    # Ryu controller with ML-based DDoS detection
│   └── ryu.conf                # Controller configuration (bindings, polling interval)
│
├── network_topology/
│   ├── topology.py             # Mininet spine-leaf topology (configurable size)
│   └── ovs_config.sh           # Open vSwitch configuration (standalone fail-mode)
│
├── ml_model/
│   ├── train_model.py          # RF training, cross-validation, baselines, adversarial tests
│   └── create_roc.py           # ROC curve visualization
│
├── traffic_generation/
│   ├── generate_normal.py      # Normal traffic generator (ICMP, TCP, HTTP)
│   └── attack_generator.sh     # DDoS attack simulator using hping3
│
├── datasets/
│   ├── generate_full_dataset.py  # Synthetic 12-feature flow dataset generator
│   └── dataset_info.txt          # Dataset specification
│
├── utilities/
│   ├── feature_extractor.py    # Feature definitions — single source of truth (12 features)
│   ├── dataset_collector.py    # Buffered CSV collection with file locking
│   └── performance_monitor.py  # Controller CPU/memory/flow monitoring
│
├── tests/
│   ├── test_feature_extractor.py  # 18 tests for feature extraction and validation
│   └── test_dataset_collector.py  # 16 tests for dataset collection
│
├── logs/
│   ├── init_logs.sh            # Log file initialization (640 permissions)
│   └── analyze_logs.py         # Post-run analysis and reporting
│
├── AUDIT_REPORT.md             # Security audit findings (56 items)
├── CHANGELOG.md                # Version history
└── requirements.txt            # Python dependencies
```

---

## Quick Start

### Prerequisites

Ubuntu 20.04+ with root access. Install system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch hping3 iperf python3 python3-pip
```

### Installation

```bash
git clone https://github.com/B1rH0ut/sdn-ml-ddos-mitigation.git
cd sdn-ml-ddos-mitigation
pip3 install -r requirements.txt
```

### Run

**1. Generate dataset and train model:**

```bash
cd datasets && python3 generate_full_dataset.py --total 505433 && cd ..
cd ml_model && python3 train_model.py && cd ..
```

This generates `flow_model.pkl`, `scaler.pkl`, and `model_hashes.json` (integrity hashes).

**2. Start the controller** (Terminal 1):

```bash
cd sdn_controller && ryu-manager mitigation_module.py
```

**3. Start the network** (Terminal 2):

```bash
cd network_topology && sudo python3 topology.py
```

**4. Generate traffic** (Terminal 3 — normal):

```bash
cd traffic_generation && sudo python3 generate_normal.py --duration 300
```

**5. Launch an attack** (Terminal 4):

```bash
cd traffic_generation && sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --duration 60
```

**6. Watch the controller terminal** for detection and mitigation logs.

### Supported Attack Types

```bash
# ICMP Flood
sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --duration 60

# SYN Flood
sudo bash attack_generator.sh --type syn --target 10.0.0.5 --duration 60

# UDP Flood
sudo bash attack_generator.sh --type udp --target 10.0.0.3 --duration 60

# All types sequentially
sudo bash attack_generator.sh --type all --target 10.0.0.7 --duration 30
```

### Run Tests

```bash
python3 -m pytest tests/ -v
```

---

## Troubleshooting

| Problem                            | Solution                                               |
|------------------------------------|--------------------------------------------------------|
| `ryu-manager: command not found`   | `pip3 install ryu==4.34`                               |
| `ML model files not found` warning | Run `cd ml_model && python3 train_model.py` first      |
| Model integrity verification fails | Re-run `train_model.py` to regenerate model and hashes |
| `This script must be run as root`  | Use `sudo` for topology.py and traffic scripts         |
| Mininet cleanup errors             | Run `sudo mn -c` then restart topology                 |
| `pingall` shows packet loss        | Wait 15s for STP convergence, then retry               |
| `hping3: command not found`        | `sudo apt-get install hping3`                          |
| No switch connections              | Ensure controller is running *before* starting network |
| Low model accuracy                 | Use larger dataset (50,000+ flows)                     |

---

## License

This project is licensed under the [MIT License](LICENSE).
