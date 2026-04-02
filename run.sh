#!/bin/bash
sudo systemctl start suricata
sudo systemctl status suricata

cd ~/docker/dvwa
docker compose up -d

cd ~/p000774csitcp
./setup_linux.sh
source .venv/bin/activate && python3 src/app.py
