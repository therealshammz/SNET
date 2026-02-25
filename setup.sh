#!/usr/bin/env bash

set -euo pipefail

echo "┌──────────────────────────────────────────────┐"
echo "│           SNET Installer v1.0                │"
echo "│   by 5H4MMZ - Installs to /usr/local/bin     │"
echo "└──────────────────────────────────────────────┘"
echo ""

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (sudo)."
   echo "Run: sudo ./setup.sh"
   exit 1
fi

BINARY_NAME="snet"
INSTALL_PATH="/usr/local/bin/$BINARY_NAME"
CONFIG_DIR="/etc/snet"
LOG_DIR="/var/log/snet"
SERVICE_NAME="snet.service"

echo "Checking Go installation..."
if ! command -v go &> /dev/null; then
    echo "❌ Go not found. Install Go ≥ 1.21 from https://go.dev/dl/"
    exit 1
fi
GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
echo "✓ Go $GO_VERSION found"

echo "Checking libpcap development headers..."
if ! pkg-config --exists libpcap 2>/dev/null; then
    echo "⚠️ libpcap-dev not found. Attempting install..."
    if command -v apt &> /dev/null; then
        apt update && apt install -y libpcap-dev
    else
        echo "Could not auto-install libpcap-dev. Install manually."
        exit 1
    fi
fi
echo "✓ libpcap development files found"

echo "Building SNET..."
go build -o "$BINARY_NAME" ./cmd/server
if [ $? -ne 0 ]; then
    echo "❌ Build failed. Check Go errors above."
    exit 1
fi
echo "✓ Binary built: $BINARY_NAME"

echo "Installing binary to $INSTALL_PATH..."
install -m 755 "$BINARY_NAME" "$INSTALL_PATH"
rm -f "$BINARY_NAME"
echo "✓ Installed: $INSTALL_PATH"

mkdir -p "$CONFIG_DIR" "$LOG_DIR"
chmod 755 "$CONFIG_DIR" "$LOG_DIR"

DEFAULT_CONFIG="$CONFIG_DIR/config.yaml"
if [ ! -f "$DEFAULT_CONFIG" ]; then
    echo "Creating default config at $DEFAULT_CONFIG..."
    cat > "$DEFAULT_CONFIG" << 'EOF'
port: 8053
upstream_dns: "8.8.8.8:53"
log_file: "/var/log/snet/snet.log"
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
EOF
    echo "✓ Default config created"
else
    echo "✓ Config already exists at $DEFAULT_CONFIG"
fi

SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"
echo "Creating systemd service: $SERVICE_PATH..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=SNET - DNS & Network DDoS Defense
After=network.target

[Service]
ExecStart=$INSTALL_PATH --config $DEFAULT_CONFIG
Restart=always
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
WorkingDirectory=$CONFIG_DIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo ""
echo "┌──────────────────── Installation Complete ──────┐"
echo " Binary:          $INSTALL_PATH                                 "
echo " Config:          $DEFAULT_CONFIG                               "
echo " Logs:            $LOG_DIR                                      "
echo " Run manually:    snet                                          "
echo " Run as service:  sudo systemctl start snet                     "
echo " Enable on boot:  sudo systemctl enable snet                    "
echo " View status:     sudo systemctl status snet                    "
echo " View logs:       journalctl -u snet -f                         "
echo "└─────────────────────────────────────────────────┘"
echo ""

echo "First run suggestions:"
echo "  sudo systemctl start snet       # start now"
echo "  sudo systemctl enable snet      # start on boot"
echo "  sudo systemctl status snet      # check status"
echo ""
echo "Done. SNET is now installed system-wide."
