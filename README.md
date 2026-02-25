# SNET – Simple Network Defense Tool

**SNET** is a lightweight, configurable, Go-based DNS proxy and L4 flood mitigator with real-time stats and basic gateway/firewall capabilities.

It was built as a learning/experimental project to explore DNS-level DDoS detection, packet-level filtering, configurability, observability, and self-contained runtime behavior.

**This is not production-grade software.**  
It is **not** intended to be used in professional, commercial, enterprise, or any security-critical environments.  
It lacks hardening, comprehensive testing, audit trails, proper privilege separation, rate-limit bypass resistance, and many other properties required for real-world deployment.

Use it for educational purposes, home lab experiments, or personal tinkering only.

## Features

- DNS proxy (UDP + TCP) forwarding to any upstream resolver
- Per-IP rate limiting & temporary blocking
- Four DNS-specific attack pattern detectors:
  - Excessive request rate
  - Repeated queries to the same domain
  - Random subdomain / water torture attacks
  - Sudden query bursts in short windows
- L3/L4 flood detection (SYN flood, UDP flood) via packet sniffing
- Automatic interface detection with interactive prompt
- All thresholds configurable via YAML + flag overrides
- HTTP `/stats` endpoint exposing:
  - Uptime
  - Blocked IPs (count + details)
  - Recent detections (last 10)
  - Current configuration snapshot
- Structured JSON logging (zap)

## Current limitations (explicitly not production-ready)

- No hardening against bypass techniques
- iptables rules are not namespaced or cleaned perfectly in all failure cases
- No authentication / access control on `/stats`
- No persistent block list across restarts
- No advanced anomaly detection (just rule-based + basic suppression)
- No TLS/DoH/DoT support
- No IPv6 support
- No formal security audit or fuzzing
- Logs can be verbose under load

## Quick Start

```bash
# Build
./setup.sh

# Basic DNS proxy (no sudo)
./snet -port 8053

# Full mode with filtering (requires sudo)
sudo ./snet -port 53 -iface wlp0s20f3

# Gateway mode (network-wide protection)
sudo ./snet --mode gateway --iface wlp0s20f3

# View stats
curl http://localhost:8080/stats
```

## Configuration (configs/config.yaml)

```yaml
port: 8053
upstream_dns: "8.8.8.8:53"
log_file: "logs/snet.log"
rate_limit: 100
block_time: 300
filter_interface: "auto"
stats_port: ":8080"

high_rate_threshold: 100
repeated_queries_min: 20
random_subdomains_min: 20
query_burst_threshold: 50
query_burst_window_sec: 10

syn_threshold: 50
udp_threshold: 200
filter_window_sec: 60
```

All values are optional — missing keys fall back to defaults.

## Installation (system-wide)

```bash
sudo ./setup.sh
```

This:
- Builds `snet`
- Installs to `/usr/local/bin/snet`
- Creates `/etc/snet/config.yaml` (if missing)
- Creates `/var/log/snet/` for logs
- Installs systemd service (`snet.service`)

Then use:

```bash
snet --help
sudo systemctl start snet
sudo systemctl enable snet
sudo systemctl status snet
journalctl -u snet -f
```

## Docker

```bash
# Build
docker build -t snet:latest .

# DNS-only mode
docker run -d --name snet-dns \
  --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v $(pwd)/configs:/configs \
  -v $(pwd)/logs:/logs \
  snet:latest --config /configs/config.yaml --port 8053

# Gateway mode
docker run -d --name snet-gateway \
  --net=host --privileged \
  -v $(pwd)/configs:/configs \
  -v $(pwd)/logs:/logs \
  snet:latest --config /configs/config.yaml --mode gateway --iface wlp0s20f3
```

## Building from source

```bash
# One-time setup & build
./setup.sh

# Manual
go mod tidy
go build -o snet ./cmd/server
```

## Disclaimer (read this)

**SNET is a student/hobby project.**  
It is **not** audited, **not** hardened, and **not** suitable for protecting real networks, production systems, or anything valuable.

It may:
- Miss attacks
- Cause false positives
- Leak information
- Open security holes if misconfigured
- Break networking if gateway mode is used incorrectly

Use only in isolated test environments.

## License & Usage Consent

SNET is released under the **MIT License** (see [LICENSE](./LICENSE)).

**Important consent notice:**

This project is provided **as-is** for educational, personal, and experimental use only.

By using SNET you explicitly agree and consent to the following:

- This software is **not audited, not hardened, and not suitable** for protecting real networks, production systems, sensitive data, or any environment where security or availability matters.
- It may miss attacks, create false positives/negatives, open unintended holes, or disrupt networking.
- The author(s) accept **no liability** whatsoever for any damage, data loss, downtime, legal consequences, or other harm resulting from use (or misuse) of this software.
- Do not use SNET in any professional, commercial, enterprise, government, or security-critical context.
- If you redistribute or modify SNET, you must retain this consent notice and the MIT license.
