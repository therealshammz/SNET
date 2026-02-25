# SNET – Simple Network Defense

**SNET** is a lightweight, single-binary Go tool that acts as a DNS proxy with built-in DDoS mitigation (DNS-layer + L3/L4 flood protection) and optional gateway mode for network-wide filtering.

It is **experimental / educational software** — **not audited, not hardened, and not suitable** for protecting real networks, production systems, sensitive data, or anything important.

Use it for learning, home labs, or personal tinkering only. No warranty, no liability.

## Features

- DNS proxy (UDP + TCP) forwarding to any upstream resolver
- Per-IP rate limiting & temporary blocking
- DNS attack detectors:
  - High request rate
  - Repeated same-domain queries
  - Random subdomain / water torture
  - Sudden query bursts
- L3/L4 flood detection (SYN + UDP) via packet sniffing
- HTTP `/stats` endpoint (uptime, blocked IPs, recent detections, config snapshot)
- Gateway mode: auto IP forwarding + NAT masquerade + iptables drops + cleanup
- Smart log suppression (no spam during sustained floods)
- Binary-relative config & logs (portable — move binary anywhere, auto-creates missing files)
- Graceful shutdown, structured JSON logging

## Requirements

- Linux (gateway mode uses iptables/sysctl)
- sudo (for port 53, packet capture, gateway mode)
- libpcap-dev (for packet filtering)

## Quick Setup (5 minutes)

### 1. Clone the repo
```bash
git clone https://github.com/therealshammz/SNET.git
cd SNET
```

### 2. Install system-wide (recommended)
```bash
sudo ./setup.sh
```

This does everything:
- Builds `snet` binary
- Installs to `/usr/local/bin/snet` (now runnable from **anywhere** as just `snet`)
- Creates `/etc/snet/config.yaml` (default config)
- Creates `/var/log/snet/` for logs
- Installs systemd service `snet.service` (auto-start on boot, manageable with `systemctl`)

### 3. Run SNET (after install)

#### Basic DNS proxy (no sudo needed)
```bash
snet --port 8053
```

Test:
```bash
dig @127.0.0.1 -p 8053 google.com
```

#### Full mode with filtering (sudo required)
```bash
sudo snet --port 53 --iface <interface>
```

#### Gateway mode (network-wide protection)
```bash
sudo snet --mode gateway --iface <interface>
```

This automatically:
- Enables IP forwarding
- Detects WAN interface
- Adds NAT masquerade
- Starts filtering + DNS proxy
- Cleans up NAT on Ctrl+C

On clients: set **default gateway** to your machine’s LAN IP.

### 4. Run as a system service (auto-start on boot)

```bash
sudo systemctl start snet
sudo systemctl enable snet
sudo systemctl status snet
```

Logs:
```bash
journalctl -u snet -f
```

## Configuration

Default config is created at `/etc/snet/config.yaml` (or next to binary if not installed system-wide).

```yaml
port: 8053
upstream_dns: "8.8.8.8:53"
log_file: "/var/log/snet/snet.log"  # or relative "logs/snet.log"
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

All values optional — defaults used if missing.

Override with flags:
```bash
sudo snet --mode gateway --iface eth0 --rate-limit 50 --udp-threshold 1000
```

## Monitoring

Live stats:
```bash
curl http://localhost:8080/stats
```

Live logs (service):
```bash
journalctl -u snet -f
```

Or direct file:
```bash
tail -f /var/log/snet/snet.log
```

## Common Issues & Fixes

**Port 53 already in use**
```bash
sudo lsof -i :53
# If systemd-resolved:
sudo systemctl stop systemd-resolved
```

**Permission denied**
Run with `sudo`, or set capabilities:
```bash
sudo setcap 'cap_net_bind_service,cap_net_raw,cap_net_admin+eip' /usr/local/bin/snet
```

**False positives from upstream**
Increase `udp_threshold` to 500–1000.

**No internet in gateway mode**
Check NAT:
```bash
sudo iptables -t nat -L -v
```

## Disclaimer

**SNET is experimental code.**  
It is **not** audited, **not** hardened, and **not** suitable for protecting real networks, production systems, sensitive data, or anything valuable.

It may:
- Miss attacks
- Cause false positives/negatives
- Disrupt networking
- Introduce security issues

Use only in isolated test environments. No warranty, no liability.

## License

MIT License (see [LICENSE](./LICENSE))

---
Built by Samuel Amartey – 2026
