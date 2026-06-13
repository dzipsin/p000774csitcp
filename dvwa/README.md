# DVWA on Docker - Fresh Kali Setup

Damn Vulnerable Web Application (DVWA) is the deliberately-insecure target this project fires
XSS and SQLi payloads at. Suricata watches the traffic, and the SOC triage app classifies the
resulting alerts. This guide takes a fresh Kali Linux box from nothing to a running,
logged-in DVWA instance on Docker.

The `docker-compose.yml` in this directory runs two containers: `dvwa` (the web app, exposed on
host port `8080`) and `db` (a MariaDB backend). Default security level is set to `low`.

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Kali Linux | 2025.x+ | Fresh install is fine |
| Docker Engine | 20.10+ | Installed below |
| Docker Compose | v2 (plugin) | `docker compose`, not the legacy `docker-compose` |
| RAM | 2 GB+ free | DVWA + MariaDB are lightweight |

**Network:** the host needs outbound internet access to pull the container images on first run.

---

## Setup

### 1. Install Docker

Kali ships Docker in its repos, but the official Docker CE packages are recommended and more
current. Either approach works.

**Option A - Kali repo (simplest):**

```bash
sudo apt update && sudo apt install -y docker.io docker-compose-v2
```

**Option B - Official Docker CE:**

```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian bookworm stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

> Kali is Debian-based; the snippet above pins the `bookworm` Debian release. If a pull fails on
> a newer Kali, swap `bookworm` for your Debian base (`cat /etc/debian_version`).

### 2. Enable and start the Docker daemon

```bash
sudo systemctl enable --now docker
sudo systemctl status docker          # expect "active (running)"
```

### 3. Run Docker without sudo (optional but convenient)

```bash
sudo usermod -aG docker $USER
newgrp docker                          # apply the group in the current shell
docker run --rm hello-world            # verify; should print "Hello from Docker!"
```

Log out and back in for the group change to apply to all new shells.

### 4. Launch DVWA

From this directory (`dvwa/`):

```bash
cd dvwa
docker compose up -d
```

First run pulls `ghcr.io/digininja/dvwa:latest` and `mariadb:10.11` - give it a minute. Verify
both containers are up:

```bash
docker compose ps                      # both services should show "running"/"Up"
docker compose logs -f dvwa            # Ctrl-C to stop following
```

### 5. Initialise the DVWA database

DVWA needs its database created once on first launch.

1. Open `http://localhost:8080/setup.php` in a browser.
2. Scroll to the bottom and click **Create / Reset Database**.
3. You'll be redirected to the login page.

If the setup page reports it can't connect to the database, the `db` container may still be
initialising - wait ~20 seconds and reload.

### 6. Log in and set the security level

1. Go to `http://localhost:8080/login.php`.
2. Log in with the default credentials:

   | Field | Value |
   |-------|-------|
   | Username | `admin` |
   | Password | `password` |

3. Open **DVWA Security** (left menu), set the level to **Low**, and click **Submit**.

`DEFAULT_SECURITY_LEVEL=low` in the compose file pre-sets this, but the menu lets you change it
per session. The evaluation harness expects `low`.

---

## Configuration

The compose file (`docker-compose.yml`) is self-contained. Key settings:

| Setting | Value | Meaning |
|---|---|---|
| `ports: 8080:80` | host `8080` -> container `80` | Change the left number to use a different host port |
| `DEFAULT_SECURITY_LEVEL` | `low` | Initial DVWA security level |
| `MYSQL_PASSWORD` | `p@ssw0rd` | DB password DVWA uses to connect (matches DVWA's default `config.inc.php`) |
| `restart: unless-stopped` | - | Containers come back after a host reboot |

To change the host port (e.g. if `8080` is taken), edit the `dvwa` service:

```yaml
ports:
  - "8081:80"
```

...then `docker compose up -d` again, and use `8081` everywhere below.

---

## Integrating with the SOC triage project

The triage app reads Suricata alerts, so Suricata must watch the interface DVWA traffic crosses.

### Find the address to monitor / target

```bash
# DVWA is reachable on the host at:
http://localhost:8080            # from the host itself
http://<host-LAN-IP>:8080        # from another machine; get the IP with: ip -4 addr show
```

The evaluation harness (`src/evaluation/`) defaults its target to
`http://192.168.56.101:8080` (a typical host-only VM IP). If your DVWA is on a different
address, pass `--base-url` when running the evaluation:

```bash
python -m src.evaluation.run_evaluation --base-url http://localhost:8080
```

### Point Suricata at the right interface

For container traffic, monitor the Docker bridge. Find it with:

```bash
ip link show type bridge          # e.g. br-xxxxxxxx for the compose network, or docker0
```

Set that interface in `/etc/suricata/suricata.yaml` (`af-packet` section) per the main project
[README](../README.md#1-suricata), then deploy the XSS + SQLi rules and restart Suricata.

> Generate traffic by browsing DVWA's vulnerability pages (e.g. XSS, SQL Injection) or by running
> the evaluation harness. Suricata logs alerts to `/var/log/suricata/eve.json`, which the triage
> app tails.

---

## Lifecycle commands

```bash
docker compose up -d           # start (detached)
docker compose ps              # status
docker compose logs -f dvwa    # tail web app logs
docker compose stop            # stop, keep containers + data
docker compose start           # restart stopped containers
docker compose down            # stop and remove containers (DB data is in an anonymous volume)
docker compose down -v         # also remove volumes - wipes the DVWA database
```

To reset DVWA to a clean state: `docker compose down -v && docker compose up -d`, then redo the
**Create / Reset Database** step.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| setup.php: "Could not connect to the database" | `db` container still starting | Wait ~20s and reload; check `docker compose logs db` |
| Login fails with `admin`/`password` | DB not initialised | Visit `/setup.php` and click **Create / Reset Database** first |
| Pages 403 / blocked at higher difficulty | Security level not `low` | DVWA Security menu -> set **Low** -> Submit |
| Evaluation can't reach DVWA | Wrong `--base-url` | Pass the actual host address, e.g. `--base-url http://localhost:8080` |
| No Suricata alerts from DVWA traffic | Suricata on the wrong interface | Monitor the Docker bridge (`ip link show type bridge`); see main README |
