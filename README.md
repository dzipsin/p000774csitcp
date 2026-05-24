# Prototype Development of an Agentic AI–Assisted SOC Alert Triage System
Project ID: p000774csitcp

Contributors:
- Dylan Zipsin
- Sahil Thorat
- Shaina Kaur
- Tabasom Habibi
- Ahrar Hossain


# Prototype AI-Assisted SOC Alert Triage System

An AI-powered Security Operations Centre (SOC) alert triage system that automates Tier-1 alert classification and summarisation. The system ingests Suricata IDS alerts, classifies them as true/false positives, assigns severity levels, and generates structured incident reports with response recommendations.

## Where to start reading

| You are... | Start here |
|---|---|
| **Picking up the project cold** (new chat / new teammate / future-you) | **`docs/HANDOFF.md`** — single source of truth for current state, branches, what's done, what's left |
| **Want a visual map of how the system works** | **`docs/ARCHITECTURE.md`** — hand-drawn system overview diagram + walkthrough of every component and arrow |
| Looking for the agent design rationale | `docs/AGENT_DESIGN.md` — full ReAct + tools + hybrid auto-enrichment spec |
| Running the evaluation campaign | `docs/PHASE_6_RUNBOOK.md` — 5-config staircase ablation procedure |
| Understanding the SQLite migration | `docs/PHASE_10_SQLITE.md` — schema, concurrency, retention, roll-back |
| Deploying custom XSS + SQLi Suricata rules | `lab/suricata/README.md` — install + validation hand-tests |
| Setting up the lab from scratch | the **Setup** section below |

**Branch state:** active development lives on `feature/sqlite-persistence` (latest, includes everything). `feature/agentic-react-loop` carries the same agent work without SQLite. `main` is pre-agentic — do not run from `main` for a demo. See `docs/HANDOFF.md` for the merge sequence.

## Architecture

```
┌─────────────────────────────────────┐     ┌────────────────────────────────────┐
│       KALI VM  (VirtualBox)         │     │       HOST  (Windows / Mac)        │
│                                     │     │                                    │
│  ┌──────────────┐   ┌────────────┐  │     │  ┌──────────┐   ┌──────────────┐   │
│  │  DVWA        │   │  Suricata  │  │     │  │  Ollama   │   │  AI Triage  │   │
│  │  (Docker)    │──▶│  (IDS)     │  │     │  │  (LLM)   │◀──│  Module     │   │
│  │  Port 8080   │   │  eve.json  │──┼─────┼─▶│  :11434   │  │  (Python)    │   │
│  └──────────────┘   └────────────┘  │share│  └──────────┘   └──────────────┘   │
│                                     │folder│                                   │
│  Component 1         Component 2    │     │         Component 3                │
└─────────────────────────────────────┘     └────────────────────────────────────┘
```

**Three logical components, two physical machines:**

- **Component 1 — Vulnerable Web App (DVWA):** Dockerised web application with XSS and SQLi vulnerabilities. Generates attack traffic when payloads are submitted.
- **Component 2 — IDS (Suricata):** Monitors the Docker bridge network for attack patterns. ET Open ruleset + our custom XSS ruleset (`lab/suricata/xss_alerts.rules`, SIDs 1000001-1000058, P1/P2/P3 tiers). Outputs structured JSON alerts to `eve.json`.
- **Component 3 — AI Triage Module (Python, host):** Reads `eve.json` via a VirtualBox shared folder and runs a multi-stage pipeline.

**Component 3 subsystems (host):**

```
log_monitor ──▶ ai_module ──▶ ReAct agent ──▶ Stage 2 narrative ──▶ report_generator
   (tail)        (Stage 1)    (3 tools +       (correlation +        (rule-based +
                              hybrid pre-      MITRE tactic           LLM-filtered
                              enrichment)      override)              suggestions)
                                                                          │
                                                                          ▼
                                                                  Incident report
                                                                  (template-v1 JSON,
                                                                   schema-validated)
                                                                          │
                                              SQLite (default) ◀──────────┘
                                              or JSON store
                                                    │
                                                    ▼
                                           Flask + Socket.IO dashboard
                                                  :5000
```

Data flows via a VirtualBox shared folder — Suricata writes `eve.json` inside the VM, the Python module reads it from the host filesystem. LLM stays local (Ollama, port `11434`). No network egress.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| VirtualBox | 7.1+ | VM hypervisor (Mac Apple-Silicon: UTM is the alternative — Phase 8) |
| Kali Linux VM | 2025.x+ (amd64) | Hosts DVWA + Suricata |
| Docker | 28+ (inside VM) | Runs DVWA container |
| Python | 3.11+ | AI module runtime (host). `tomllib` requires 3.11. |
| Ollama | Latest | Local LLM server (host) |
| Git | Any | Repository management |

**Python packages** (`requirements.txt`):
- `flask`, `flask-socketio` — dashboard + WebSocket
- `jsonschema` — template-v1 validation

**Host machine requirements:**
- 16 GB RAM minimum (4 GB allocated to VM, the rest for host + Ollama + the 3B model)
- GPU helps Ollama latency (NVIDIA 6 GB+ VRAM or Apple Silicon Metal). CPU-only works on Mac M-series at ~5-15 s per alert.
- ~40 GB free disk space (Kali VM + Docker images + 2 Ollama models + project)

**Ollama models** — pull both:
```bash
ollama pull qwen2.5:3b   # demo-best — better ReAct tool-call adherence
ollama pull llama3.2     # Phase 6 evaluation baseline
```

**Important (Windows only):** If Hyper-V is enabled, VirtualBox runs in a slower compatibility mode. For best performance, disable Hyper-V:

```powershell
# Run as Administrator
bcdedit /set hypervisorlaunchtype off
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
dism /online /disable-feature /featurename:VirtualMachinePlatform /norestart
# Restart your machine
```

To re-enable later (if you need WSL2/Docker Desktop):

```powershell
bcdedit /set hypervisorlaunchtype auto
dism /online /enable-feature /featurename:VirtualMachinePlatform /norestart
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart
# Restart your machine
```

---

## Setup

### 1. VirtualBox + Kali VM

1. Download and install [VirtualBox 7.1+](https://www.virtualbox.org/wiki/Downloads)
2. Download the [Kali Linux VirtualBox image](https://www.kali.org/get-kali/#kali-virtual-machines) (AMD64 `.7z` — extract with [7-Zip](https://www.7-zip.org/))
3. In VirtualBox: **Machine → Add** and select the `.vbox` file from the extracted folder
4. Configure the VM (right-click → Settings):

| Setting | Value |
|---------|-------|
| System → Memory | 4096 MB |
| System → Processors | 2 |
| Display → Video Memory | 128 MB |
| Network → Adapter 1 | NAT (internet access) |
| Network → Adapter 2 | Host-Only Adapter (host ↔ VM communication) |

> **Note:** If no Host-Only network exists, create one first: **File → Tools → Network Manager → Create**

5. Set up the shared folder (Settings → Shared Folders → Add):

| Field | Value |
|-------|-------|
| Folder Path | A folder on your host, e.g. `C:\Projects\soc-triage` or `~/Projects/soc-triage` |
| Folder Name | `soc-triage` |
| Auto-mount | Checked |
| Make Permanent | Checked |

6. Boot the VM. Default credentials: `kali` / `kali`

7. Verify both network adapters are working:

```bash
ip addr show
```

You should see two interfaces with IPs:
- `eth0`: `10.0.2.x` (NAT — internet)
- `eth1`: `192.168.56.x` (Host-Only — host communication)

If `eth1` has no IP, NetworkManager should assign one automatically. Wait 30 seconds and check again.

8. Verify connectivity from your host:

```bash
# From host terminal/PowerShell
ping 192.168.56.101    # or whatever IP eth1 received
```

### 2. DVWA (Inside the VM)

1. Install Docker:

```bash
sudo apt update && sudo apt install -y docker.io docker-compose
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

2. Verify Docker:

```bash
docker --version
docker run hello-world    # should work without sudo
```

3. Create and start DVWA:

```bash
mkdir -p ~/docker/dvwa

cat > ~/docker/dvwa/docker-compose.yml << 'EOF'
services:
  dvwa:
    image: ghcr.io/digininja/dvwa:latest
    ports:
      - "8080:80"
    environment:
      DB_SERVER: db
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: mariadb:10.11
    environment:
      MYSQL_ROOT_PASSWORD: dvwa
      MYSQL_DATABASE: dvwa
      MYSQL_USER: dvwa
      MYSQL_PASSWORD: p@ssw0rd
    restart: unless-stopped
EOF

cd ~/docker/dvwa && docker compose up -d
```

> **Important:** Do NOT use the `vulnerables/web-dvwa` Docker image — it is abandoned and unmaintained. Always use `ghcr.io/digininja/dvwa:latest`.

4. Wait ~15 seconds for MariaDB to initialise, then open in your host browser:

```
http://192.168.56.101:8080
```

5. Click **"Create / Reset Database"** at the bottom of the setup page
6. Log in: `admin` / `password`
7. Go to **DVWA Security** in the sidebar → set to **Low**

> **Why Low?** Higher security levels sanitise inputs at the application layer before they hit the network. Suricata would never see the attack payloads, making your IDS alerts and ground truth meaningless.

### 3. Suricata IDS (Inside the VM)

1. Install Suricata and jq:

```bash
sudo apt update && sudo apt install -y suricata jq
```

2. Update detection rules:

```bash
sudo suricata-update enable-source et/open
sudo suricata-update
```

3. Find the Docker bridge interface for DVWA:

```bash
ip link show type bridge
```

Look for the interface matching `dvwa_default` network (e.g. `br-9eba4eacee65`). Verify with:

```bash
docker network ls
# Compare the network ID to the bridge interface name
```

4. Configure Suricata:

```bash
sudo nano /etc/suricata/suricata.yaml
```

**Change 1 — Interface** (search for `af-packet:`):

```yaml
af-packet:
  - interface: br-XXXXXXXXXXXX    # your Docker bridge interface
```

**Change 2 — Address groups** (search for `HOME_NET`):

```yaml
    HOME_NET: "any"
    EXTERNAL_NET: "any"
    HTTP_SERVERS: "any"
    SQL_SERVERS: "any"
```

5. Start Suricata and verify:

```bash
sudo systemctl start suricata
sudo tail -5 /var/log/suricata/suricata.log
```

You should see: `creating 2 threads` and `Engine started` referencing your bridge interface.

6. Test detection — open a second terminal and watch for alerts:

```bash
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type == "alert")'
```

Then in your host browser, go to DVWA → SQL Injection and submit:

```
1' UNION SELECT user, password FROM users#
```

You should see alerts appear including `ET WEB_SERVER SELECT USER SQL Injection Attempt in URI`.

### 4. Shared Folder — eve.json to Host

Set up a live feed of alerts from the VM to the host:

```bash
# Ensure your user is in the vboxsf group
sudo adduser $USER vboxsf
# Log out and back in if newly added

# Start the live feed (run from any directory)
tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json &
```

Verify on your host:
- **Windows:** Check `C:\Projects\soc-triage\eve.json` exists and has content
- **Mac:** Check `~/Projects/soc-triage/eve.json`

> **Note:** `tail -F` does not persist across VM reboots. Add it to a startup script or re-run it after each boot. See the [Quick Start](#quick-start-after-initial-setup) section.

### 5. Ollama (On the Host)

1. Download and install from [ollama.com](https://ollama.com/download)
2. Pull both models (one for demo, one for evaluation baseline):

```bash
ollama pull qwen2.5:3b   # demo-best — better ReAct adherence
ollama pull llama3.2     # Phase 6 baseline — preserves earlier eval numbers
```

3. Verify both are listed:

```bash
ollama list
```

Ollama runs as a background service on port `11434` by default. The model
the app uses is chosen via `app.config` `[model.ollama].model_name`. See
**Configuration** below.

### 6. Python Environment (On the Host)

1. Clone the repository:

```bash
git clone https://github.com/dzipsin/p000774csitcp
cd p000774csitcp
```

2. Create and activate a virtual environment:

```bash
# Windows
python -m venv .venv --without-pip
.venv\Scripts\activate
python -m ensurepip --upgrade

# Mac / Linux
python3 -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

> **Tip:** Always use `python -m pip install` instead of `pip install` to avoid packages installing outside the venv (common issue with Microsoft Store Python on Windows).

### 7. (Optional) Deploy Custom XSS Rules

Project ships a custom Suricata ruleset (58 XSS-focused rules, SIDs `1000001`-`1000058`,
priority tiers P1/P2/P3) at `lab/suricata/xss_alerts.rules`. ET Open detects far less
XSS than SQLi, so this ruleset closes the gap.

Deployment is a one-time copy inside the Kali VM. Full walkthrough + hand-test
validation in **`lab/suricata/README.md`**. Short version:

```bash
# Inside Kali VM
sudo cp /media/sf_soc-triage/p000774csitcp/lab/suricata/xss_alerts.rules \
        /var/lib/suricata/rules/
# Edit /etc/suricata/suricata.yaml — append "xss_alerts.rules" under rule-files
sudo suricata -T -c /etc/suricata/suricata.yaml -i any   # validate config
sudo systemctl restart suricata
```

Verify by triggering a DVWA Reflected XSS — you should see SID `1000xxx` alerts.

---

## Running the System

### Quick Start (After Initial Setup)

**Step 1 — Start the VM services** (inside Kali terminal):

```bash
# Start DVWA
cd ~/docker/dvwa && docker compose up -d

# Start Suricata
sudo systemctl start suricata

# Start eve.json feed to shared folder
tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json &
```

**Step 2 — Start the AI module** (on your host):

```bash
cd p000774csitcp

# Activate venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

# Set the eve.json path (not needed if running inside the VM)
# Windows PowerShell:
$env:EVE_LOG_PATH = "C:/Projects/soc-triage/eve.json"
# Mac/Linux:
export EVE_LOG_PATH="$HOME/Projects/soc-triage/eve.json"

# Run
python src/app.py
```

**Step 3 — Open the dashboard:**

```
http://127.0.0.1:5000
```

**Step 4 — Generate alerts** by attacking DVWA at `http://192.168.56.101:8080`

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `EVE_LOG_PATH` | `/var/log/suricata/eve.json` | Path to Suricata eve.json. Set this when running the AI module on the host machine rather than inside the VM. |
| `API_KEY` | (empty) | API key for Anthropic provider (only needed if using remote LLM). |
| `LOCAL_MODEL_URL` | (empty) | Override base URL for Ollama or llama.cpp server. |

### Configuration

All configuration lives in `app.config` (TOML format). **Do not modify this file for local paths** — use environment variables instead so the config remains universal across machines.

#### `[model]` — LLM provider

```toml
[model]
provider = "ollama"               # "ollama" | "anthropic" | "llamacpp"
temperature = 0.2                 # low for consistent classifications

[model.ollama]
model_name = "qwen2.5:3b"         # demo-best — strong ReAct tool adherence
# model_name = "llama3.2"         # Phase 6 baseline alternative
base_url = "http://localhost:11434"
```

#### `[agent]` — Triage strategy

```toml
[agent]
mode = "react"                    # "react" | "single_shot"
auto_enrichment = true            # hybrid Option F — deterministic pre-enrich + LLM
max_react_steps = 6
log_reasoning_trace = true        # surfaces ReAct loop in dashboard
```

- `mode = "react"` + `auto_enrichment = true` → full demo behavior
- `mode = "single_shot"` → ablation baseline (no agentic loop). Suggestions stay safe — rule-based generator and LLM filter both consume enrichment via the same `lookup_environment_for_query` path, so `single_shot` runs do not regress to "Block 172.18.0.2"-class suggestions.

#### `[storage]` — Report persistence

```toml
[storage]
backend = "sqlite"                # "sqlite" | "json"
db_path = "data/reports.db"       # sqlite only
retention_days = 90               # 0 disables retention sweeper
cleanup_interval_seconds = 3600
```

SQLite is the default backend (WAL mode, thread-local connections, hybrid schema = indexed columns + JSON blob). JSON-file backend is still selectable as a fallback / for tests. Switching backends does not migrate data — see `docs/PHASE_10_SQLITE.md`.

#### `[environment]` — Lab inventory (drives enrichment)

Defines IPs/hostnames the agent's `lookup_environment_context` tool recognises. Edit when the lab changes (e.g. new DVWA host IP).

---

## Attack Scenarios for Testing

### SQL Injection

In DVWA → SQL Injection (security set to Low):

| Payload | Type | Expected Suricata Rule |
|---------|------|----------------------|
| `1' OR '1'='1` | Auth bypass | May not trigger HTTP-layer rule (simpler pattern) |
| `1' UNION SELECT user, password FROM users#` | UNION-based extraction | `ET WEB_SERVER SELECT USER SQL Injection Attempt in URI` |

### Cross-Site Scripting (XSS)

In DVWA → XSS (Reflected) (security set to Low):

| Payload | Type | Expected Suricata Rule |
|---------|------|----------------------|
| `<script>alert('xss')</script>` | Reflected XSS | `ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt` |

### False Positives (Expected)

Every attack generates additional `ET SCAN Suspicious inbound to mySQL port 3306` alerts. These are internal Docker traffic between DVWA and MariaDB — **not actual attacks**. The AI module should classify these as `likely_false_positive`.

---

## Project Structure

```
p000774csitcp/
├── app.config                       # TOML configuration (universal — no local paths)
├── requirements.txt
├── setup_linux.sh / setup_windows.bat
├── run.sh                           # Linux quick-start (VM only)
│
├── src/
│   ├── app.py                       # entrypoint — wires log_monitor / agent / storage / web
│   ├── log_monitor.py               # tails eve.json → AlertRecord
│   ├── alert.py                     # AlertRecord dataclass
│   ├── incident.py                  # Incident domain model
│   ├── incident_manager.py          # in-memory correlation, dedupe, lookup
│   ├── ai_module.py                 # Stage 1 classifier (per-alert)
│   ├── model_provider.py            # Ollama / Anthropic / llama.cpp facade
│   │
│   ├── react_agent.py               # ReAct loop — XML-tagged Reasoning/Acting,
│   │                                # hybrid pre-enrichment (Option F), 6-step budget
│   ├── tool_registry.py             # tool registration + dispatch
│   ├── agent_tools.py               # get_alert_history, lookup_environment_context,
│   │                                # get_attack_pattern_stats + lookup_environment_for_query
│   │
│   ├── report_generator.py          # Stage 2 narrative + rule-based suggestions +
│   │                                # 3-layer LLM filter + MITRE tactic override
│   ├── report_serializer.py         # template-v1 JSON shaper
│   ├── report_schema.py             # JSONSchema for template-v1
│   ├── report_storage.py            # JSON-file backend (legacy / fallback)
│   ├── report_db.py                 # SQLite backend (default) — WAL, thread-local,
│   │                                # retention sweeper, query methods by IP/attack/severity
│   │
│   ├── web_server.py                # Flask + Socket.IO dashboard server
│   ├── static/  templates/          # dashboard frontend
│   │
│   ├── evaluation/
│   │   ├── run_evaluation.py        # single-config eval runner (--config-dim)
│   │   ├── run_combined_report.py   # 5-config staircase report renderer
│   │   ├── scenarios/               # labelled attack fixtures
│   │   └── outputs/                 # per-run raw JSON + markdown
│   │
│   └── test_*.py                    # 9 test suites, 449+ assertions
│
├── lab/
│   └── suricata/
│       ├── xss_alerts.rules         # custom XSS ruleset, SIDs 1000001-1000058
│       └── README.md                # deploy + validate inside Kali VM
│
└── docs/
    ├── HANDOFF.md                   # START HERE — orientation for cold pickup
    ├── AGENT_DESIGN.md              # ReAct loop + tools + hybrid enrichment design
    ├── PHASE_6_RUNBOOK.md           # 5-config staircase ablation procedure
    └── PHASE_10_SQLITE.md           # SQLite migration design + roll-back path
```

---

## Troubleshooting

Canonical troubleshooting table (lab + agent + storage + eval issues) lives in **`docs/HANDOFF.md`**. Quick lab-only essentials below.

| Symptom | Likely cause | Fix |
|---|---|---|
| `eth1` has no IP in Kali | NetworkManager hasn't assigned yet | Wait 30 s, or `nmcli device status` |
| Cannot ping VM from host | Adapter 2 ≠ Host-Only | VirtualBox → Settings → Network → Adapter 2 |
| DVWA shows DB error on first load | MariaDB still booting (~15 s) | Wait, refresh. `docker logs dvwa-dvwa-1 --tail 10` |
| DVWA attacks don't trigger alerts | Security level not Low | DVWA Security → Low |
| No Suricata alerts at all | Wrong bridge interface | `ip link show type bridge`, update `suricata.yaml` |
| `eve.json` not updating on host | `tail -F` from `/var/log/suricata/eve.json` not running | Re-run feed command after VM boot |
| `No module named flask` | Packages outside venv | `python -m pip install -r requirements.txt` (note `python -m`) |
| Dashboard empty | `EVE_LOG_PATH` wrong | Check env var, verify file exists + growing |
| Ollama slow | CPU fallback | `ollama ps` → should show GPU layers |
| ReAct loop times out / loops | Model not pulled or wrong `model_name` | `ollama list`, verify `app.config` `model_name` |
| `Block 172.18.0.2` suggestion appears | Old report from before fix | Clear `data/reports.db` or JSON store, re-run |

---

## VM Snapshot Checklist

Take VirtualBox snapshots at these milestones:

1. **`clean-kali`** — Fresh Kali VM before any changes
2. **`working-dvwa-suricata`** — DVWA + Suricata installed and verified
3. **`pre-demo`** — Everything working, ready for demonstration

**Machine → Take Snapshot** in VirtualBox (works while VM is running).

---

## Team Notes

**Lab gotchas**

- **Python 3.11+ required** (`tomllib` is stdlib only from 3.11).
- **Do not hardcode local paths** in `app.config` — use `EVE_LOG_PATH` env var.
- **Do not use `vulnerables/web-dvwa`** Docker image — abandoned. Use `ghcr.io/digininja/dvwa:latest`.
- **Always `python -m pip install`** (not bare `pip`) to avoid Microsoft-Store-Python venv issues on Windows.
- **Docker bridge name changes** every time you `docker compose down && up -d`. Re-check `ip link show type bridge` and update `/etc/suricata/suricata.yaml` if it shifted.

**Branches** — work on `feature/sqlite-persistence` (latest, has everything). `main` is pre-agentic; do not demo from it. Merge sequence + state in `docs/HANDOFF.md`.

**Tests** — `python -m unittest discover -s src -p "test_*.py"` runs 9 suites covering log monitor, AI module, ReAct agent, tool registry, agent tools, report generator (incl. single_shot enrichment fallback), report DB, serializer, web server.

**Commit convention** — no AI-attribution trailers (no `Co-Authored-By: Claude ...`). Capstone academic integrity.

**Custom rules SID range** — `1000001`-`1000058` (user range). Do not collide with ET Open's `2000000-2999999`.