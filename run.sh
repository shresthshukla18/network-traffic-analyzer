#!/usr/bin/env bash

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PYTHON_BIN="$PROJECT_DIR/venv/bin/python"
if [ ! -f "$PYTHON_BIN" ]; then
    PYTHON_BIN="$(which python3)"
fi

echo "[*] Authenticating sudo for packet capture..."
sudo -v

# 1. Ensure database schema exists
mkdir -p data
"$PYTHON_BIN" database.py
sudo chmod -R 777 data 2>/dev/null

# 2. Launch Scapy sniffer in background
echo "[+] Starting background packet capture..."
sudo "$PYTHON_BIN" packet_capture.py --continuous > /tmp/packet_capture.log 2>&1 &
SNIFFER_PID=$!

sleep 1
sudo chmod -R 777 data 2>/dev/null

# 3. Clean up only this specific sniffer PID on exit
cleanup() {
    echo -e "\n[!] Stopping packet capture (PID: $SNIFFER_PID)..."
    if [ -n "$SNIFFER_PID" ]; then
        sudo kill "$SNIFFER_PID" 2>/dev/null
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 4. Start Streamlit Dashboard
"$PROJECT_DIR/venv/bin/streamlit" run dashboard.py
