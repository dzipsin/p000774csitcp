# RUNBOOK — How to Run the SOC Triage System

This document is the practical, step-by-step guide for running the AI-assisted
SOC alert triage system on a fresh machine.

It covers:

1. Prerequisites and environment setup (Windows, macOS Intel, macOS Apple Silicon)
2. First-time setup of the Kali VM (DVWA + Suricata)
3. The day-to-day "I want to run a demo" workflow
4. Running the evaluation harness (Phase 4)
5. Troubleshooting common breakages

For architectural context, see `README.md` in the repo root.

---

## Table of contents

- [1. What you need before you start](#1-what-you-need-before-you-start)
- [2. First-time host setup](#2-first-time-host-setup)
  - [2a. Windows host setup](#2a-windows-host-setup)
  - [2b. macOS host setup (Intel and Apple Silicon)](#2b-macos-host-setup-intel-and-apple-silicon)
- [3. First-time VM setup](#3-first-time-vm-setup)
- [4. Day-to-day run sequence](#4-day-to-day-run-sequence)
  - [4a. Bring the VM up](#4a-bring-the-vm-up)
  - [4b. Verify the eve.json bridge](#4b-verify-the-evejson-bridge)
  - [4c. Verify Ollama is running](#4c-verify-ollama-is-running)
  - [4d. Start the app](#4d-start-the-app)
  - [4e. Open the dashboard and demo it](#4e-open-the-dashboard-and-demo-it)
- [5. Running the test suite](#5-running-the-test-suite)
- [6. Running the evaluation harness](#6-running-the-evaluation-harness)
- [7. Troubleshooting](#7-troubleshooting)
- [8. Quick reference](#8-quick-reference)

---

## 1. What you need before you start

| Tool | Version | Where it runs | Purpose |
|------|---------|---------------|---------|
| VirtualBox | 7.1+ | Host | VM hypervisor |
| Kali Linux | 2025.x amd64 (Intel/AMD hosts) **or** 2025.x arm64 (Apple Silicon) | Inside VM | Hosts DVWA + Suricata |
| Docker | 28+ | Inside VM | Runs DVWA |
| Python | 3.11+ | Host | App + evaluation runtime |
| Ollama | Latest | Host | Local LLM server |
| Git | Any | Host | Repo management |

**Hardware:** at least 16 GB RAM, 40 GB free disk, GPU recommended for Ollama
(any NVIDIA card with 6+ GB VRAM, or Apple Silicon M-series).

**Important — Apple Silicon Macs:** download the **arm64** Kali ISO, not amd64.
The amd64 ISO will install but boot painfully slow under emulation.

**Important — Windows:** if Hyper-V is enabled, VirtualBox runs in slow
compatibility mode. Disable it for best performance (see section 2a).

---

## 2. First-time host setup

Pick the section matching your OS. Skip the others.

### 2a. Windows host setup

**Step 1 — Disable Hyper-V (Run PowerShell as Administrator):**

```powershell
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
bcdedit /set hypervisorlaunchtype off
```

Reboot the machine. Without this, your VM will be slow.

**Step 2 — Install required software:**

- VirtualBox: <https://www.virtualbox.org/>
- Python 3.11+: <https://www.python.org/downloads/> (tick "Add Python to PATH")
- Ollama: <https://ollama.com/download/windows>
- Git: <https://git-scm.com/download/win>

**Step 3 — Pull the model:**

```powershell
ollama pull llama3.2
```

This downloads ~2 GB. Verify:

```powershell
curl.exe http://localhost:11434/api/tags
```

You should see a JSON list containing `"name":"llama3.2:latest"`.

**Step 4 — Clone the repo:**

```powershell
mkdir C:\Projects\soc-triage
cd C:\Projects\soc-triage
git clone https://github.com/dzipsin/p000774csitcp.git
cd p000774csitcp
```

**Step 5 — Set up a Python virtual environment:**

If using the regular Python installer:

```powershell
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If using the Microsoft Store version of Python and `venv` hangs, use this
two-step workaround instead:

```powershell
python -m venv .venv --without-pip
.venv\Scripts\activate
python -m ensurepip --upgrade
python -m pip install -r requirements.txt
```

### 2b. macOS host setup (Intel and Apple Silicon)

**Step 1 — Install Homebrew if you don't have it:**

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Step 2 — Install required software:**

```bash
brew install --cask virtualbox       # may require approving kernel extension in System Settings
brew install python@3.11
brew install --cask ollama
brew install git
```

On **Apple Silicon**, VirtualBox installs but only supports arm64 guests.
You **must** use the arm64 Kali ISO (not amd64).

**Step 3 — Start Ollama and pull the model:**

```bash
ollama serve &     # start Ollama in background (or just open the desktop app)
ollama pull llama3.2
```

Verify:

```bash
curl http://localhost:11434/api/tags
```

You should see `"name":"llama3.2:latest"` in the output.

**Step 4 — Clone the repo:**

```bash
mkdir -p ~/Projects/soc-triage
cd ~/Projects/soc-triage
git clone https://github.com/dzipsin/p000774csitcp.git
cd p000774csitcp
```

**Step 5 — Set up a Python virtual environment:**

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

---

## 3. First-time VM setup

This step is the same regardless of your host OS. Do it once per VM.

**Step 1 — Create the VM:**

In VirtualBox: New → Name `kali-soc`, type Linux, version Debian (64-bit) on
Intel/AMD or Debian (ARM 64-bit) on Apple Silicon. Memory: 4096 MB. Disk: 40 GB.

Mount the Kali ISO and run the installer. Default options are fine.

**Step 2 — Configure VM networking:**

VM Settings → Network:

- **Adapter 1:** NAT (default — Kali uses this for internet access)
- **Adapter 2:** Host-Only Adapter, name `vboxnet0` (Mac) or `VirtualBox Host-Only Ethernet Adapter` (Windows). Create one if it doesn't exist.

The host-only adapter is what lets your host reach DVWA at `192.168.56.101`.

**Step 3 — Configure shared folder:**

VM Settings → Shared Folders → Add:

- **Folder Path:** `C:\Projects\soc-triage` (Windows) or `~/Projects/soc-triage` (macOS)
- **Folder Name:** `soc-triage`
- **Auto-mount:** ✓
- **Make Permanent:** ✓

**Step 4 — Inside the VM, install Docker, Suricata, and Guest Additions:**

```bash
sudo apt update
sudo apt install -y docker.io docker-compose suricata jq virtualbox-guest-utils
sudo usermod -aG docker,vboxsf $USER
sudo reboot
```

After reboot, verify the shared folder is mounted:

```bash
ls /media/sf_soc-triage/
# Should list the contents of your host repo folder
```

**Step 5 — Set the host-only IP:**

```bash
sudo ip addr add 192.168.56.101/24 dev eth1
sudo ip link set eth1 up

# Persist across reboots — edit /etc/network/interfaces:
sudo nano /etc/network/interfaces
```

Add:

```
auto eth1
iface eth1 inet static
    address 192.168.56.101
    netmask 255.255.255.0
```

**Step 6 — Deploy DVWA:**

```bash
cd ~
mkdir dvwa-lab && cd dvwa-lab
cat > docker-compose.yml << 'EOF'
services:
  dvwa:
    image: ghcr.io/digininja/dvwa:latest
    ports:
      - "8080:80"
    depends_on:
      - db
  db:
    image: mariadb:10.11
    environment:
      MYSQL_ROOT_PASSWORD: dvwa
      MYSQL_DATABASE: dvwa
      MYSQL_USER: dvwa
      MYSQL_PASSWORD: p@ssw0rd
EOF
docker compose up -d
```

**Step 7 — Initialise DVWA's database (do this once):**

Open `http://192.168.56.101:8080/setup.php` in your **host** browser, scroll
down, click **Create / Reset Database**. Wait for the success message.

Then go to `http://192.168.56.101:8080/login.php`, log in as `admin` /
`password`, click **DVWA Security**, set to **Low**, Submit.

**Step 8 — Configure Suricata to listen on the Docker bridge:**

Find the bridge interface name:

```bash
ip link show type bridge
# Look for br-XXXXXXXXXXXX
```

Edit `/etc/suricata/suricata.yaml`:

```bash
sudo nano /etc/suricata/suricata.yaml
```

Find the `af-packet:` section and set:

```yaml
af-packet:
  - interface: br-9eba4eacee65   # ← your bridge name
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

Set `HOME_NET`, `EXTERNAL_NET`, `HTTP_SERVERS`, `SQL_SERVERS` all to `"any"`
(top of the file).

Update rules and start Suricata:

```bash
sudo suricata-update enable-source et/open
sudo suricata-update
sudo systemctl enable --now suricata
sudo systemctl status suricata --no-pager
```

**Step 9 — Take a VirtualBox snapshot.** Machine → Take Snapshot. Name it
`working-dvwa-suricata`. If anything ever breaks, you can roll back.

---

## 4. Day-to-day run sequence

Once first-time setup is done, this is the routine to bring the system up.

### 4a. Bring the VM up

Start the Kali VM (headless or windowed — doesn't matter).

Inside the VM, verify everything is running:

```bash
docker compose -f ~/dvwa-lab/docker-compose.yml ps
sudo systemctl is-active suricata
```

You should see DVWA + db containers `Up`, and `active`.

### 4b. Verify the eve.json bridge

This is the bridge that pipes Suricata's alerts from inside the VM out to the
shared folder where the host can read them.

```bash
pgrep -af "tail.*eve.json"
```

If empty, **the bridge is dead — start it:**

```bash
nohup tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json 2>/dev/null &
```

> Note: this `nohup tail` dies when the shell that started it exits its
> session group on logout. If you find the bridge dead every morning, set it
> up as a systemd service. For now, restart it as needed.

**Verify on the host that data is flowing.** Pick the right command for your OS:

**Windows:**
```powershell
Get-Item C:\Projects\soc-triage\eve.json | Select-Object LastWriteTime, Length
```

**macOS:**
```bash
ls -lh ~/Projects/soc-triage/eve.json
```

The timestamp should be within the last few seconds (Suricata writes stats
events every 8 seconds even with no traffic). If the timestamp is stale
(hours/days ago), see [Troubleshooting](#7-troubleshooting).

### 4c. Verify Ollama is running

**Windows:**
```powershell
curl.exe http://localhost:11434/api/tags
```

**macOS:**
```bash
curl http://localhost:11434/api/tags
```

You should see JSON containing `llama3.2:latest`. If Ollama isn't running:

- **Windows:** open the Ollama app from the Start menu, or run `ollama serve`
- **macOS:** open the Ollama app, or run `ollama serve` in a terminal

### 4d. Start the app

Activate the venv and start the app. Both pieces have to point at the
host-side eve.json file, which we override via an environment variable.

**Windows (PowerShell):**

```powershell
cd C:\Projects\soc-triage\p000774csitcp
.venv\Scripts\activate
$env:EVE_LOG_PATH = "C:/Projects/soc-triage/eve.json"
python src/app.py
```

**macOS (bash/zsh):**

```bash
cd ~/Projects/soc-triage/p000774csitcp
source .venv/bin/activate
export EVE_LOG_PATH="$HOME/Projects/soc-triage/eve.json"
python src/app.py
```

**Healthy startup output looks like this:**

```
INFO [app] Reports directory: .../reports
INFO [incident_manager] IncidentManager init: mode=per_actor, window=120.0s, debounce=3.0s
INFO [app] Incident pipeline: mode=per_actor, window=2.0min, debounce=3.0s
INFO [report_generator] ReportGenerator ready: lab_context=True, summary_mode=llm, retries=1
INFO [app] Model provider : ollama
INFO [app] Model          : llama3.2
INFO [app] Lab context    : True
INFO [app] Summary mode   : llm
INFO [incident_manager] IncidentManager started
INFO [web_server] Dashboard starting at http://0.0.0.0:5000
[LogMonitor] tailing C:/Projects/soc-triage/eve.json
 * Running on http://127.0.0.1:5000
```

If you see error or warning lines before the `Dashboard starting` line,
**stop and read them** — see [Troubleshooting](#7-troubleshooting).

### 4e. Open the dashboard and demo it

Open `http://127.0.0.1:5000` in any browser on the host machine.

You should see:

- Header: `SURICATA // ALERT MONITOR`
- Status dot: pulsing green, says `LIVE`
- Two tabs: **RAW ALERTS** (active by default, count 0) and **INCIDENTS** (count 0)

**Fire your first attack** in a separate browser window:

1. Open `http://192.168.56.101:8080`
2. Log in (`admin` / `password`), confirm Security is set to **Low**
3. Go to **Vulnerabilities → SQL Injection**
4. Paste this in the User ID field:
   ```
   1' UNION SELECT user, password FROM users#
   ```
5. Click **Submit**

**Within ~1 second:** a row appears in the Raw Alerts tab with red border and
the SQL injection signature.

**Within ~5-15 seconds** (debounce + LLM time): switch to the Incidents tab
and you'll see an incident card. Click **Show details** to see the AI
narrative, classification, severity, IoCs, and recommendations.

**That's the demo.**

To clear state between demos: click **Clear Incidents** on the Incidents tab.

---

## 5. Running the test suite

The project has four test suites (38 tests total). All are in-process — they
don't need the VM, Ollama, or DVWA.

```bash
cd <repo root>
# Activate your venv first

python src/test_incident_manager.py     # 10 tests
python src/test_report_generator.py     # 20 tests
python src/test_integration.py          # 5 integration tests
python src/test_evaluation.py           # 3 evaluation harness tests
```

Each ends with `All N tests PASSED`. Run these whenever you pull new code
to confirm nothing's broken.

---

## 6. Running the evaluation harness

The evaluation harness fires a labelled set of attack scenarios against DVWA,
collects the AI's classifications, and produces a markdown report with
precision/recall/F1 and a confusion matrix.

**This requires the full system running** — VM, Ollama, the app — because it
exercises the live pipeline end-to-end. It's the same setup as section 4.

### 6a. Verify the system is up

Walk through section 4a–4d. **Don't skip section 4b** — a stale eve.json
will produce a misleading evaluation report.

### 6b. Smoke test (1 scenario)

Before committing to a full ~15-minute run, fire one scenario manually to
confirm DVWA login works and the correlation pipeline is healthy.

**Windows:**

```powershell
@'
import sys
sys.path.insert(0, 'src')
from evaluation.attack_runner import DVWAClient
from evaluation.scenarios import SCENARIOS

c = DVWAClient()
c.login()
print("Login OK")
result = c.fire(SCENARIOS[0])
print("Fired:", result.url_fired)
print("Status:", result.http_status)
'@ | Out-File -FilePath smoke_test.py -Encoding utf8
python smoke_test.py
```

**macOS:**

```bash
cat > smoke_test.py << 'EOF'
import sys
sys.path.insert(0, 'src')
from evaluation.attack_runner import DVWAClient
from evaluation.scenarios import SCENARIOS

c = DVWAClient()
c.login()
print("Login OK")
result = c.fire(SCENARIOS[0])
print("Fired:", result.url_fired)
print("Status:", result.http_status)
EOF
python smoke_test.py
```

Expected output:

```
Login OK
Fired: http://192.168.56.101:8080/vulnerabilities/sqli/?id=...&eval_id=sqli_union_001
Status: 200
```

Then check the dashboard — the Raw Alerts tab should show a fresh alert
containing `eval_id=sqli_union_001`, and within 10-20 seconds an incident card
should appear.

If the smoke test fails, see the [DVWA login troubleshooting section](#dvwa-login-fails-from-the-script-but-works-in-browser).

### 6c. Full evaluation run

The harness fires 30 labelled scenarios (8 SQLi, 6 XSS, 3 command injection,
3 file inclusion, 2 reconnaissance, 8 benign), with 30 seconds between each
to let the pipeline catch up.

**Don't touch the dashboard or DVWA during a run.** Stray traffic will
contaminate the results.

**Single repetition (~15 minutes):**

```bash
python -m src.evaluation.run_evaluation --label lab_on
```

**Three repetitions for statistical confidence (~45 minutes):**

```bash
python -m src.evaluation.run_evaluation --label lab_on_x3 --repeats 3
```

**Outputs land in `eval_results/`:**

- `<label>_<timestamp>_raw.json` — full machine-readable results
- `<label>_<timestamp>_report.md` — human-readable markdown report

### 6d. The lab-context ablation

The `include_lab_context` flag in `app.config` controls whether the Stage 1
prompt tells the LLM about the Docker network layout. Comparing runs with
this flag on vs off is the project's headline ablation.

**Procedure:**

1. Run the baseline (lab_on) — keep `include_lab_context = true` in
   `app.config`, restart the app, run the eval with `--label lab_on`.

2. Stop the app (Ctrl+C in its terminal).

3. Edit `app.config` and change:
   ```toml
   [analysis]
   include_lab_context = false
   ```

4. Restart the app. **Confirm the startup log shows `Lab context : False`.**

5. Run again:
   ```bash
   python -m src.evaluation.run_evaluation --label lab_off
   ```

6. Compare the two markdown reports in `eval_results/`. The lab_off run
   typically shows lower recall and at least one false negative on attacks
   the LLM dismisses without environmental context.

**For the strongest comparison**, run both at `--repeats 3` overnight:

```bash
python -m src.evaluation.run_evaluation --label lab_on_x3  --repeats 3
# flip config, restart app
python -m src.evaluation.run_evaluation --label lab_off_x3 --repeats 3
```

### 6e. Useful evaluation flags

| Flag | Default | When to use |
|---|---|---|
| `--label NAME` | `default` | Tag for the output files; use to distinguish runs |
| `--repeats N` | `1` | Number of times to fire the full suite |
| `--settle-time SECONDS` | `30.0` | Wait between scenarios; lower if you have a fast LLM |
| `--final-wait SECONDS` | `45.0` | Pause after last scenario before fetching results |
| `--skip-clear` | off | Don't clear existing incidents at the start of the run |
| `--base-url URL` | `http://192.168.56.101:8080` | If your VM uses a different IP |
| `--dashboard URL` | `http://127.0.0.1:5000` | If your app runs on a different port |

---

## 7. Troubleshooting

### eve.json on the host shows an old timestamp

Almost always means the `tail -F` bridge in the VM died.

**On the VM:**
```bash
pgrep -af "tail.*eve.json"
# If empty:
nohup tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json 2>/dev/null &
```

If the timestamp on the host **still** doesn't update after restarting the
tail, VirtualBox's shared folder cache may be stale. Stop the app, delete the
host-side eve.json so the VM-side `tail` recreates it:

**Windows:**
```powershell
Remove-Item C:\Projects\soc-triage\eve.json -Force
```

**macOS:**
```bash
rm ~/Projects/soc-triage/eve.json
```

Then restart the tail in the VM (it will recreate the file).

### Dashboard says LIVE but no alerts ever appear

Confirm the chain:

1. Suricata in the VM is detecting traffic:
   ```bash
   grep '"event_type":"alert"' /var/log/suricata/eve.json | wc -l
   # should grow when you attack DVWA
   ```
2. The bridge is running (section 4b).
3. The host's eve.json is updating (section 4b).
4. The app's `EVE_LOG_PATH` matches that path (visible in startup log line
   `[LogMonitor] tailing ...`).

### Suricata is running but isn't seeing any traffic

Most likely the Docker bridge name changed. Every time `docker compose down &&
up` runs, Docker may regenerate the bridge ID.

```bash
ip link show type bridge
# Note the current br-XXXXXX name
sudo nano /etc/suricata/suricata.yaml
# Update the af-packet interface to match
sudo systemctl restart suricata
```

### DVWA login fails from the script but works in browser

If the Python attack runner can't log in, it's almost always one of:

- **DVWA database not initialised yet** — visit
  `http://192.168.56.101:8080/setup.php` in a browser, click Create/Reset Database.
- **Cookie domain rejection** — already fixed in current `attack_runner.py` via
  `DefaultCookiePolicy(strict_ns_domain=DomainLiberal)`. If you see this,
  ensure you have the latest version of the file.
- **user_token regex mismatch** — also fixed; the regex now handles both
  single-quoted and double-quoted token attributes.

### App startup log shows "AI analysis disabled"

Means the app couldn't reach Ollama. Confirm Ollama is running and the model
is pulled:

**Both OSes:**
```bash
curl http://localhost:11434/api/tags    # macOS
curl.exe http://localhost:11434/api/tags # Windows PowerShell
```

If you don't see `llama3.2`, run `ollama pull llama3.2`.

### "ModuleNotFoundError: No module named 'flask'"

Your venv isn't activated, or packages were installed system-wide instead of
in the venv. Reactivate and install:

**Windows:**
```powershell
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

**macOS:**
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

### Evaluation harness shows lots of "no_detection"

This is **expected** for two categories of scenarios:

1. **Benign scenarios** — they should produce no alert. Listed as ✓ in the
   report's `Status` column.
2. **Mild attacks Suricata's default rules don't catch** — e.g. lone single
   quote, javascript: URI, php:// wrapper. Listed as ○ (acknowledged
   limitation) in the Status column.

What would be a real problem is `?` (unknown miss) on a scenario marked
`expected_to_trigger_suricata=True`. Those are detection gaps worth
investigating.

### Evaluation harness can't reach the dashboard

Make sure the app is actually running on `http://127.0.0.1:5000` and the
status dot is green in the browser. Then re-run.

If your dashboard runs on a different port, pass:

```bash
python -m src.evaluation.run_evaluation --dashboard http://127.0.0.1:8000
```

---

## 8. Quick reference

### Daily startup checklist

| Step | Where | Command |
|------|-------|---------|
| 1. Start VM | VirtualBox | (start `kali-soc`) |
| 2. Verify DVWA + Suricata | VM terminal | `docker compose -f ~/dvwa-lab/docker-compose.yml ps && sudo systemctl is-active suricata` |
| 3. Restart eve.json bridge if needed | VM terminal | `pgrep -af tail; nohup tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json &` |
| 4. Verify Ollama | Host | `curl http://localhost:11434/api/tags` |
| 5. Start the app | Host (in repo) | (Windows) `.venv\Scripts\activate; $env:EVE_LOG_PATH=...; python src/app.py` |
| 6. Open dashboard | Host browser | `http://127.0.0.1:5000` |

### Demo URLs

- DVWA: <http://192.168.56.101:8080> (login admin / password, set Security to Low)
- Dashboard: <http://127.0.0.1:5000>
- Ollama API: <http://localhost:11434>

### Demo attacks

| Attack | DVWA page | Field | Payload |
|--------|-----------|-------|---------|
| SQLi UNION | SQL Injection | User ID | `1' UNION SELECT user, password FROM users#` |
| XSS reflected | XSS (Reflected) | Name | `<script>alert('xss')</script>` |
| XSS img | XSS (Reflected) | Name | `<img src=x onerror=alert(1)>` |
| Command injection | Command Execution | IP | `127.0.0.1; cat /etc/passwd` |
| Path traversal | File Inclusion | (URL) | `?page=../../../../etc/passwd` |

### File locations

| Path | What's there |
|------|--------------|
| `<repo>/src/app.py` | Main entrypoint |
| `<repo>/app.config` | Runtime config (provider, grouping, lab_context, etc.) |
| `<repo>/reports/` | Generated incident reports (gitignored) |
| `<repo>/eval_results/` | Phase 4 evaluation outputs (gitignored) |
| VM `/var/log/suricata/eve.json` | Suricata alert log (source of truth) |
| Host `<shared>/eve.json` | Mirrored copy the app reads from |

### Snapshot strategy

Take VirtualBox snapshots at:

1. `clean-kali` — fresh install, before any project setup
2. `working-dvwa-suricata` — DVWA running and Suricata detecting attacks
3. `pre-demo` — everything verified working, ready to present

Snapshots are free disk space rolled forward. Take them generously.
