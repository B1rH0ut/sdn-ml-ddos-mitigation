# SDN-Based DDoS Detection and Mitigation with Machine Learning

An intelligent network security system that combines **Software-Defined Networking (SDN)** with a **Random Forest classifier** to detect and automatically mitigate DDoS attacks in real time. Built on a Ryu OpenFlow controller and tested on a Mininet-emulated spine-leaf data center topology.

> Capstone project: Computer Engineering (Networking)

---

## How It Works

```
                    ┌─────────────────────────────────┐
                    │       Application Layer         │
                    │    Random Forest Classifier     │
                    │   10 flow features · Scaler     │
                    └───────────────┬─────────────────┘
                                    │ predict()
                    ┌───────────────▼─────────────────┐
                    │        Control Layer            │
                    │   Ryu SDN Controller (OF 1.3)   │
                    │  MAC learning · Stats polling   │
                    │  Feature extraction · DROP rules│
                    └───────────────┬─────────────────┘
                                    │ OpenFlow 1.3
                    ┌───────────────▼─────────────────┐
                    │         Data Layer              │
                    │   Mininet Spine-Leaf Topology   │
                    │  5 switches · 10 hosts · 100Mbps│
                    └─────────────────────────────────┘
```

1. The **Ryu controller** manages a spine-leaf network of 5 OpenFlow switches and 10 hosts
2. Every **5 seconds**, it collects flow statistics from all switches
3. **10 features** are extracted from each flow (packet rates, byte counts, protocol fields)
4. A trained **Random Forest model** classifies each flow as normal or attack
5. Attacks trigger an automatic **DROP rule** (priority 32768, 300s timeout) on the switch
6. All detections are **logged** to CSV for post-incident analysis

The controller gracefully degrades to a standard L2 switch if the ML model is not loaded.

---

## Detection Pipeline

```
Flow Stats Request (every 5s)
        │
        ▼
┌──────────────────┐     ┌───────────────┐     ┌──────────────┐     ┌───────────────┐
│ Extract Features │ ──▶ │ Scale (σ, μ)  │ ──▶ │  RF Predict  │ ──▶ │ DROP / Allow  │
│   10 per flow    │     │ StandardScaler│     │  0=ok 1=ddos │     │ + Log to CSV  │
└──────────────────┘     └───────────────┘     └──────────────┘     └───────────────┘
```

**Features extracted per flow:**

| # | Feature                   | Description                       |
|---|---------------------------|-----------------------------------|
| 1 | `flow_duration_sec`       | How long the flow has been active |
| 2 | `idle_timeout`            | Configured idle expiry            |
| 3 | `hard_timeout`            | Configured hard expiry            |
| 4 | `packet_count`            | Total packets in flow             |
| 5 | `byte_count`              | Total bytes in flow               |
| 6 | `packet_count_per_second` | Packet rate                       |
| 7 | `byte_count_per_second`   | Byte rate                         |
| 8 | `ip_proto`                | IP protocol number (1/6/17)       |
| 9 | `icmp_code`               | ICMP code field                   |
| 10 | `icmp_type`              | ICMP type field                   |

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
- **Full mesh** between tiers — every leaf connects to every spine (6 inter-switch links)
- **10 hosts** (10.0.0.1–10, /24) distributed across 3 leaf switches
- **100 Mbps** links with **5 ms** delay on all connections

---

## Expected Output

### Model Training

Running `python3 train_model.py` produces output like:

```
======================================================================
  STEP 5: Evaluating Model Performance
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
    packet_count                   0.XXXX ########
    ...
```

Results vary based on dataset size and random seed. Larger datasets (100K+ flows) generally yield better separation between normal and attack classes.

### Live Detection

When an attack is detected, the controller prints:

```
DDoS ATTACK DETECTED on switch dpid=X: src=10.0.0.Y dst=10.0.0.Z type=ICMP Flood pps=XXXX.X
ATTACK BLOCKED: DROP rule installed for src=10.0.0.Y on switch dpid=X (expires in 300s)
```

| Detection Parameter    | Value                            |
|------------------------|----------------------------------|
| Flow polling interval  | 5 seconds                        |
| Block rule priority    | 32768 (highest)                  |
| Block rule duration    | 300 seconds (auto-expires)       |
| Supported attack types | ICMP Flood, SYN Flood, UDP Flood |

---

## Tech Stack

| Component               | Technology                                       |
|-------------------------|--------------------------------------------------|
| SDN Controller          | Ryu 4.34 (OpenFlow 1.3)                          |
| Network Emulation       | Mininet 2.3+ with Open vSwitch                   |
| ML Classifier           | scikit-learn Random Forest (100 trees, depth 20) |
| Feature Scaling         | StandardScaler (fit on training data only)       |
| Attack Simulation       | hping3 (ICMP, SYN, UDP floods)                   |
| Traffic Generation      | iperf, wget, ping                                |
| Performance Monitoring  | psutil                                           |
| Language                | Python 3.8+ / Bash                               |

---

## Project Structure

```
├── sdn_controller/
│   ├── mitigation_module.py    # Ryu controller with ML-based DDoS detection
│   └── ryu.conf                # Controller configuration
│
├── network_topology/
│   ├── topology.py             # Mininet spine-leaf topology (5 switches, 10 hosts)
│   └── ovs_config.sh           # Open vSwitch configuration
│
├── ml_model/
│   ├── train_model.py          # Random Forest training and evaluation
│   └── create_roc.py           # ROC curve visualization
│
├── traffic_generation/
│   ├── generate_normal.py      # Normal traffic generator (ICMP, TCP, HTTP)
│   └── attack_generator.sh     # DDoS attack simulator using hping3
│
├── datasets/
│   ├── generate_full_dataset.py  # Synthetic flow dataset generator
│   └── dataset_info.txt          # Dataset specification
│
├── utilities/
│   ├── feature_extractor.py    # Standalone feature extraction module
│   ├── dataset_collector.py    # CSV collection with file locking
│   └── performance_monitor.py  # Controller CPU/memory/flow monitoring
│
├── logs/
│   ├── init_logs.sh            # Log file initialization
│   └── analyze_logs.py         # Post-run analysis and reporting
│
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

**6. Watch the controller terminal for:**

```
DDoS ATTACK DETECTED on switch dpid=5: src=10.0.0.3 dst=10.0.0.7 type=ICMP Flood pps=12847.3
ATTACK BLOCKED: DROP rule installed for src=10.0.0.3 on switch dpid=5 (expires in 300s)
```

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

---

## Troubleshooting

| Problem                            | Solution                                               |
|------------------------------------|--------------------------------------------------------|
| `ryu-manager: command not found`   | `pip3 install ryu==4.34`                               |
| `ML model files not found` warning | Run `cd ml_model && python3 train_model.py` first      |
| `This script must be run as root`  | Use `sudo` for topology.py and traffic scripts         |
| Mininet cleanup errors             | Run `sudo mn -c` then restart topology                 |
| `pingall` shows packet loss        | Wait a few seconds for MAC learning, retry             |
| `hping3: command not found`        | `sudo apt-get install hping3`                          |
| No switch connections              | Ensure controller is running *before* starting network |
| Low model accuracy                 | Use larger dataset (50,000+ flows)                     |
---

## License

This project is licensed under the [MIT License](LICENSE).
