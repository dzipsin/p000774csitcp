# AI-Assisted SOC Alert Triage System

**Project ID:** p000774csitcp (RMIT capstone)

**Contributors:** Dylan Zipsin, Sahil Thorat, Shaina Kaur, Tabasom Habibi, Ahrar Hossain.

Reads Suricata IDS alerts from `eve.json`, groups them into incidents by source IP, runs an agentic ReAct loop (local LLM via Ollama with three enrichment tools) to classify each alert as a real attack or noise, generates a structured incident report, and displays everything on a live web dashboard. State is persisted to SQLite.

## Demonstration

A full deployment walkthrough is recorded in [`P000774CSITCP-deployment-demonstration.mp4`](https://raw.githubusercontent.com/dzipsin/p000774csitcp/refs/heads/main/P000774CSITCP-deployment-demonstration.mp4).

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Linux | Kali 2025.x+ recommended | Python 3.11+, Suricata, and Ollama must be available |
| Python | 3.11+ | `tomllib` requires 3.11+ |
| Suricata | 7+ | IDS alert source |
| Ollama | Latest | Local LLM server |

**Python packages** (`requirements.txt`): `flask`, `flask-socketio`, `jsonschema`

**System requirements:** 8 GB+ RAM. A GPU (6+ GB VRAM) significantly improves Ollama inference latency; CPU-only works but is slower.

---

## Setup

### 1. Suricata

Install if not already present:

```bash
sudo apt update && sudo apt install -y suricata jq
```

Identify the network interface to monitor (e.g., the Docker bridge for a containerised web app):

```bash
ip link show type bridge
```

Edit `/etc/suricata/suricata.yaml`:
- Set `af-packet: - interface:` to your target interface
- Set address groups to match your environment:

```yaml
HOME_NET: "any"
EXTERNAL_NET: "any"
HTTP_SERVERS: "any"
```

Deploy the custom XSS + SQLi detection rules (71 rules total):

```bash
sudo cp lab/suricata/xss_alerts.rules lab/suricata/sqli_alerts.rules /var/lib/suricata/rules/
```

Edit `/etc/suricata/suricata.yaml` to load only the custom files (disable ET Open to keep the feed scoped to XSS + SQLi):

```yaml
rule-files:
  - xss_alerts.rules
  - sqli_alerts.rules
  # - suricata.rules    # ET Open - disable for scoped feed
```

Validate and restart:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml          # expect "successfully loaded"
sudo systemctl restart suricata
sudo grep "successfully loaded" /var/log/suricata/suricata.log | tail -1   # expect 71 rules
```

Full rule reference, priority tiers, and per-payload test cases: `lab/suricata/README.md`.

### 2. Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:3b
```

Ollama runs on `http://localhost:11434` by default. The model name is set in `app.config`.

### 3. Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Configuration

All configuration is in `app.config` (TOML format). Do not hardcode local paths here - use the `EVE_LOG_PATH` environment variable for the alert file path.

### `[model]` - LLM provider

```toml
[model]
provider    = "ollama"
max_tokens  = 1024
temperature = 0.0

[model.ollama]
model_name      = "qwen2.5:3b"           # any model you have pulled via ollama pull
base_url        = "http://localhost:11434"
request_timeout = 120
```

### `[agent]` - Triage strategy

```toml
[agent]
mode             = "react"    # "react" (agentic loop) | "single_shot" (single LLM call)
auto_enrichment  = true       # pre-run enrichment tools before LLM call
max_iterations   = 3
total_budget_seconds = 30.0
```

### `[monitor]` - Alert input

```toml
[monitor]
eve_log = "/var/log/suricata/eve.json"    # default Suricata output path on Kali
```

Override at runtime with `export EVE_LOG_PATH=/path/to/eve.json` if needed.

### `[[agent.environment.entries]]` - Network context

These entries teach the agent which IPs and URL paths are internal infrastructure vs external attackers. Edit to match your environment:

```toml
[[agent.environment.entries]]
pattern             = "172.18.0.0/16"
match_type          = "cidr"              # exact_ip | cidr | url_prefix | url_contains
role                = "docker_bridge"
description         = "Internal Docker bridge subnet"
classification_hint = "context_only"

[[agent.environment.entries]]
pattern             = "192.168.1.0/24"
match_type          = "cidr"
role                = "trusted_internal"
description         = "Internal network - traffic from here is likely benign"
classification_hint = "likely_false_positive_if_internal_only"
```

### `[storage]` - Report persistence

```toml
[storage]
db_path        = "data/reports.db"   # SQLite file; created if missing
retention_days = 90                  # 0 = keep forever
```

---

## Running

```bash
source .venv/bin/activate
python src/app.py
```

Dashboard: `http://127.0.0.1:5000`

The **Raw Alerts** tab shows alerts as they arrive from Suricata. Incident reports appear on the **Incidents** tab after the 3-second debounce window once Suricata starts generating alerts from your web traffic.

To reset the report database:

```bash
rm data/reports.db data/reports.db-wal data/reports.db-shm
# Schema is bootstrapped on next start
```

## Tests

```bash
source .venv/bin/activate
python -m unittest discover -s src/tests -p "test_*.py"
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Dashboard empty | `eve.json` path wrong or Suricata not running | Check `EVE_LOG_PATH`; verify `sudo systemctl status suricata` |
| No incidents appearing | Traffic not hitting monitored interface | Confirm Suricata is on the right interface; generate web traffic |
| Ollama slow | CPU-only inference | `ollama ps` - GPU with 6+ GB VRAM significantly improves latency |
| ReAct loop timeout | Model not pulled or wrong name | `ollama list`; verify name matches `app.config` `model_name` |
| `No module named flask` | venv not active or packages missing | `source .venv/bin/activate && pip install -r requirements.txt` |
| `data/reports.db` error | Corrupted WAL after crash | `rm data/reports.db*`; restart app |
| Incidents stuck open | Time window not yet expired | Wait `time_window_minutes` (default 2 min) or use Force Regenerate |

---

## Project Structure

```
app.config               # All configuration
requirements.txt
src/
  app.py                 # Entry point: wires all components
  log_monitor.py         # Tails eve.json, emits AlertRecord
  incident_manager.py    # Groups alerts into incidents by source IP
  react_agent.py         # ReAct loop with three enrichment tools
  report_generator.py    # Stage 1 + Stage 2 AI pipeline (orchestrator)
  prompts.py             # LLM prompt templates and builders
  rule_engine.py         # Deterministic derivations (CVSS, IOCs, MITRE override)
  suggestions.py         # Hybrid rule-based + LLM suggestion pipeline
  report_db.py           # SQLite persistence
  web_server.py          # Flask + Socket.IO dashboard
  models.py              # Data classes
  model_provider.py      # Ollama provider
  evaluation/            # EVAL-ONLY: capstone evaluation harness, never imported by app
                         #   Requires DVWA running at http://192.168.56.101:8080 (default creds)
                         #   Entry point: python -m src.evaluation.run_evaluation
  tests/                 # Test suites
lab/suricata/
  xss_alerts.rules       # 58 XSS detection rules (sids 1002001-1002058)
  sqli_alerts.rules      # 13 SQLi detection rules (sids 1001001-1001013)
  README.md              # Rule reference and deployment guide
docs/
  ARCHITECTURE.md        # System design, component walkthrough, storage reference
  AGENT.md               # ReAct agent design details
  EVALUATION.md          # Evaluation procedure
```
