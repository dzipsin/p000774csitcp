#!/usr/bin/env bash
set -e

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip -q
python3 -m pip install -r requirements.txt
echo "Done. Run: source .venv/bin/activate && python src/app.py"
