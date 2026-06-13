#!/bin/bash
cd "$(dirname "$0")"

sudo systemctl start suricata
systemctl is-active --quiet suricata && echo "[+] Suricata: running" || echo "[!] Suricata: NOT running"

(cd dvwa && docker compose up -d)

chmod +x ./setup_linux.sh
./setup_linux.sh >/dev/null
source .venv/bin/activate && python3 src/app.py
