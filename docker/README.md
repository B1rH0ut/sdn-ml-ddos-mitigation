# Docker Setup

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2+
- Linux host (Mininet container requires `--privileged` and `--network host`)

## Quick Start

```bash
# From the project root:

# 1. Train the model first (generates ml_model/*.pkl files)
make train

# 2. Set security environment variables
export SDN_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export SDN_MODEL_HMAC_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# 3. Build and start
docker compose build
docker compose up -d

# 4. View controller logs
docker compose logs -f controller

# 5. Stop
docker compose down
```

## Volume Mounts

| Mount | Container Path | Purpose |
|-------|---------------|---------|
| `./ml_model` | `/app/ml_model` (read-only) | Trained model and scaler `.pkl` files |
| `./logs` | `/app/logs` | Detection and attack logs |

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `SDN_API_TOKEN` | Recommended | Bearer token for REST API authentication |
| `SDN_MODEL_HMAC_KEY` | Recommended | HMAC-SHA256 key for model integrity verification |

## Notes

- The **Mininet container** requires `--privileged` mode and `--network host` to create virtual network interfaces and interact with Open vSwitch. This is a security trade-off inherent to network emulation.
- The Mininet container **only works on Linux**. On macOS and Windows, Docker runs in a VM that lacks the necessary kernel modules for Open vSwitch and network namespaces.
- Model `.pkl` files must be generated on the host before starting containers. They are mounted read-only into the controller container.
- The controller binds to `0.0.0.0` inside the container (ports 6653 and 8080). Use Docker port mapping to control external access.
