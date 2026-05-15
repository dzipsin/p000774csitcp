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
- **Component 2 — IDS (Suricata):** Monitors the Docker bridge network for attack patterns. Outputs structured JSON alerts to `eve.json`.
- **Component 3 — AI Triage Module:** Python application on the host machine. Reads `eve.json` via a VirtualBox shared folder, displays alerts in a real-time dashboard, and sends them to a local LLM (Ollama) for classification and severity assignment.

Data flows via a VirtualBox shared folder — Suricata writes `eve.json` inside the VM, and the Python module reads it from the host filesystem.

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| VirtualBox | 7.1+ | VM hypervisor |
| Kali Linux VM | 2025.x+ (amd64) | Hosts DVWA + Suricata |
| Docker | 28+ (inside VM) | Runs DVWA container |
| Python | 3.11+ | AI module runtime (on host) |
| Ollama | Latest | Local LLM server (on host) |
| Git | Any | Repository management |

**Host machine requirements:**
- Minimum 16 GB RAM (4 GB allocated to VM, remainder for host + Ollama)
- GPU recommended for Ollama inference (any NVIDIA card with 6 GB+ VRAM, or Apple Silicon)
- ~40 GB free disk space

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
2. Pull the model:

```bash
ollama pull llama3.2
```

3. Verify:

```bash
ollama list
```

Ollama runs as a background service on port `11434` by default.

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

Key settings:

```toml
[model]
provider = "ollama"          # "ollama" | "anthropic" | "llamacpp"
temperature = 0.2            # Low for consistent classifications

[model.ollama]
model_name = "llama3.2"      # Must be pulled first: ollama pull llama3.2
base_url = "http://localhost:11434"
```

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
├── app.config              # TOML configuration (universal — do not add local paths)
├── requirements.txt        # Python dependencies
├── setup_linux.sh          # Linux/Mac venv setup script
├── setup_windows.bat       # Windows venv setup script
├── run.sh                  # Linux quick-start (VM only)
├── src/
│   ├── app.py              # Entrypoint — wires all modules together
│   ├── log_monitor.py      # Tails eve.json, emits AlertRecord objects
│   ├── model_provider.py   # Unified LLM interface (Ollama/Anthropic/llama.cpp)
│   ├── ai_module.py        # AI analyser — classifies alerts, generates reports
│   ├── web_server.py       # Flask + Socket.IO dashboard server
│   ├── static/
│   │   ├── app.js          # Dashboard frontend logic
│   │   ├── style.css       # Dashboard styling
│   │   └── favicon.ico
│   └── templates/
│       └── index.html      # Dashboard HTML template
```

---

## Troubleshooting

### VM networking

**eth1 has no IP:** NetworkManager usually assigns one automatically. If not:
```bash
sudo dhclient eth1    # may not be installed on Kali
# Alternative: check NetworkManager
nmcli device status
```

**Cannot ping VM from host:** Ensure VirtualBox Host-Only network exists (File → Tools → Network Manager) and Adapter 2 is set to Host-Only Adapter.

### DVWA

**Database connection error on first load:** MariaDB needs ~15 seconds to initialise. Wait and refresh. Verify with:
```bash
docker logs dvwa-dvwa-1 --tail 10
```

**Attacks don't work:** Check DVWA Security is set to **Low**.

### Suricata

**No alerts appearing:** Verify Suricata is monitoring the correct Docker bridge:
```bash
sudo tail -5 /var/log/suricata/suricata.log    # should show your br-XXXX interface
```

Verify `HOME_NET` is set to `"any"` in `/etc/suricata/suricata.yaml`.

**eve.json not updating:** Check Suricata is running:
```bash
sudo systemctl status suricata
```

### Dashboard

**"No module named flask":** Packages installed outside the venv. Fix:
```bash
python -m pip install -r requirements.txt    # use python -m pip, not pip directly
```

**Dashboard shows no alerts:** Check the `EVE_LOG_PATH` environment variable points to the correct file and that the file is being updated.

### Ollama

**Slow inference:** Ensure Ollama is using your GPU:
```bash
ollama ps    # should show GPU layers
```

If using CPU only, consider switching to a smaller model or reducing `max_tokens` in `app.config`.

---

## VM Snapshot Checklist

Take VirtualBox snapshots at these milestones:

1. **`clean-kali`** — Fresh Kali VM before any changes
2. **`working-dvwa-suricata`** — DVWA + Suricata installed and verified
3. **`pre-demo`** — Everything working, ready for demonstration

**Machine → Take Snapshot** in VirtualBox (works while VM is running).

---

## Team Notes

- **Python version:** 3.11+ required (`tomllib` is used for config parsing)
- **Do not hardcode local paths** in `app.config` — use `EVE_LOG_PATH` env var
- **Do not use `vulnerables/web-dvwa`** Docker image — it is abandoned. Use `ghcr.io/digininja/dvwa:latest`
- **Always use `python -m pip install`** instead of bare `pip install` to avoid venv issues on Windows
- **The Docker bridge interface name changes** every time Docker recreates the network. If you run `docker compose down && docker compose up -d`, check `ip link show type bridge` and update `/etc/suricata/suricata.yaml` if the interface name changed.