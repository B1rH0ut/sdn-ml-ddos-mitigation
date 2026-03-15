# Security

> **WARNING: RESEARCH PROTOTYPE — NOT FOR PRODUCTION USE**
>
> This system is an academic research prototype. It has not undergone formal security review or penetration testing. Do not deploy it to protect production networks or critical infrastructure.

## Scope

This document describes the security model of the SDN DDoS detection research prototype. It covers defense layers, known security caveats, and hardening steps for lab/research deployments.

## Defense Layers

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Data Plane** | BCP38 anti-spoofing rules | Block packets with spoofed source IPs at leaf switch ingress |
| **Data Plane** | Destination-based blocking | DROP rules match `(src_ip, dst_ip, ip_proto)` tuples, not just source IPs |
| **Data Plane** | ECMP load balancing | Distribute traffic across spine uplinks to prevent single-path saturation |
| **Data Plane** | Network-wide DROP rules | Attack mitigation rules installed on ALL switches, not just the ingress switch |
| **Control Plane** | TLS on OpenFlow channel | Encrypt controller-switch communication (requires `setup_tls.sh`) |
| **Control Plane** | PacketIn rate limiting | Per-switch throttling prevents controller DoS via packet flooding |
| **Control Plane** | Flood rate limiting | Per-switch broadcast caps prevent amplification attacks |
| **Application** | HMAC-SHA256 model integrity | Verify `.pkl` files before `joblib.load()` to prevent pickle RCE |
| **Application** | API token authentication | Bearer token required for REST API access |
| **Application** | ML confidence threshold | Only blocks flows with attack probability >= 0.7, reducing false positives |
| **Application** | Circuit breaker | Isolates ML failures; falls back to threshold-based detection |
| **Host** | Localhost-only bindings | OpenFlow (6653) and REST API (8080) bound to `127.0.0.1` |
| **Host** | Bounded caches | MAC table, IP counters, flood history use fixed-size data structures |
| **Host** | MAC table aging | Entries auto-expire after 300s to prevent unbounded memory growth |
| **Host** | Port security | Maximum 5 MACs per port per switch to prevent CAM overflow attacks |

## Vulnerability Reporting

If you discover a security vulnerability in this project, please report it responsibly:

- **Email:** Report via private communication to the repository maintainer
- **Do NOT** open a public GitHub issue for security vulnerabilities
- Include steps to reproduce, impact assessment, and suggested fix if possible

## Known Security Caveats

| Caveat | Risk | Mitigation |
|--------|------|------------|
| Docker requires `--privileged` for Mininet | Container escape risk | Run only in isolated lab environments |
| Model `.pkl` files use Python pickle | Arbitrary code execution if files are tampered | HMAC-SHA256 verification before loading; set `SDN_MODEL_HMAC_KEY` |
| OpenFlow channel unencrypted by default | Controller-switch traffic visible on network | Enable TLS via `setup_tls.sh`; set `SDN_TLS_CERT` and `SDN_TLS_KEY` |
| Single controller instance | No failover if controller is compromised or crashes | Research limitation; see KNOWN_LIMITATIONS.md |
| REST API token is static | Token compromise gives full API access | Rotate `SDN_API_TOKEN` regularly; bind API to localhost |
| Model trained on known attacks only | Zero-day attacks bypass ML detection | Threshold fast-path catches volumetric attacks regardless of ML |
| Anti-spoofing assumes static host-port mapping | Dynamic environments may have incorrect allow lists | Update `topology_config.py` for your topology |
| eventlet has known CVEs | Potential for concurrency-related vulnerabilities | Pin to tested version; monitor advisories |

## Hardening Checklist

For research/lab deployments, apply these hardening steps:

1. **Set HMAC key for model integrity:**
   ```bash
   export SDN_MODEL_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   python3 -m sdn_ddos_detector.scripts.sign_model
   ```

2. **Set API authentication token:**
   ```bash
   export SDN_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   ```

3. **Enable TLS on the OpenFlow channel:**
   ```bash
   # Generate certificates (see setup_tls.sh if available)
   export SDN_TLS_CERT=/path/to/controller.crt
   export SDN_TLS_KEY=/path/to/controller.key
   ```

4. **Restrict model file permissions:**
   ```bash
   chmod 600 ml_model/flow_model.pkl ml_model/scaler.pkl ml_model/model_hashes.json
   ```

5. **Bind to management interface only:**
   Ensure `ryu.conf` binds OpenFlow and REST API to the management network, not the data plane network.

6. **Use environment variables for secrets:**
   Never commit `SDN_MODEL_HMAC_KEY` or `SDN_API_TOKEN` to version control.
