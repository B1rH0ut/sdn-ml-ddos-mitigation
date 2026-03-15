# Traffic Generation and Attack Scenarios

This directory contains scripts for generating normal and attack traffic
within the Mininet test environment.

## Scripts

### generate_normal.py
Generates realistic normal network traffic (ICMP pings, TCP transfers, HTTP).
```bash
sudo python3 generate_normal.py --duration 300
```

### attack_generator.sh
Generates controlled DDoS attack traffic using hping3.
```bash
sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --duration 60
```

## Attack Modes

| Mode | Flag | Command | Tests |
|------|------|---------|-------|
| **ICMP Flood** | `--type icmp` | `hping3 -1 --flood --rand-source` | Basic detection, spoofed-source handling |
| **SYN Flood** | `--type syn` | `hping3 -S --flood -p 80 --rand-source` | TCP attack detection, small packet detection |
| **UDP Flood** | `--type udp` | `hping3 --udp --flood -p 53 --rand-source` | UDP attack detection |
| **All** | `--type all` | Sequential ICMP → SYN → UDP | Multi-vector detection |
| **No Spoof** | `--no-spoof` | Omits `--rand-source` | Anti-spoofing rules (BCP38), source-based blocking |
| **Slow Ramp** | `--slow-ramp` | Gradual rate increase over 60s | Rate-of-change features (pps_delta, pps_acceleration) |
| **No Spoof + Slow Ramp** | Both flags | Combined | Tests both anti-spoofing and rate-of-change detection |

## What Each Mode Tests

### Standard mode (--rand-source)
- **Controller behavior:** Should detect high aggregate traffic to destination,
  switch to destination-based blocking when source IP entropy is high
- **Expected:** `_block_by_destination()` triggered, blocks (dst_ip, ip_proto)
- **Features tested:** flows_to_dst, unique_sources_to_dst, flow_creation_rate

### --no-spoof mode
- **Controller behavior:** Real source IPs allow source-based blocking
- **Expected:** `_block_across_all_switches()` triggered with actual src_ip
- **Features tested:** packet_count_per_second, byte_count_per_second
- **Also validates:** BCP38 anti-spoofing rules are working (spoofed packets
  from other ports should be dropped by priority-50 rules)

### --slow-ramp mode
- **Controller behavior:** Gradual rate increase should be caught by
  rate-of-change features (pps_delta, pps_acceleration)
- **Expected:** Detection within 30-60s even though instantaneous rates
  may initially be below threshold
- **Features tested:** pps_delta, bps_delta, pps_acceleration

## Testing Procedure

1. Start controller: `ryu-manager ddos_controller.py --config-file ryu.conf`
2. Start topology: `sudo python3 topology.py`
3. Generate normal traffic: `sudo python3 generate_normal.py --duration 300`
4. Launch attack (in another terminal within Mininet):
   ```bash
   sudo bash attack_generator.sh --type icmp --target 10.0.0.7 --duration 60
   ```
5. Check detection results:
   ```bash
   cat logs/attacks_log.csv
   cd logs && python3 analyze_logs.py
   ```
