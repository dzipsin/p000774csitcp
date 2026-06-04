# Architecture and Workflow

End-to-end description of how the system processes alerts and produces incident reports.

---

## System Overview

Suricata monitors a network interface and writes alerts to `eve.json`. The Python triage app tails that file, groups alerts into incidents by source IP, runs an agentic ReAct loop (local LLM + three enrichment tools) to classify each alert, then generates a structured incident report shown on a live dashboard.

The pipeline has two AI stages and several deterministic post-processing steps:

**Stage 1 - per-alert classification.** For each alert in an incident, `ReActAgent` runs a ReAct loop: three deterministic enrichment tool calls fire first (alert history, environment context, attack pattern stats), results are seeded into the prompt, then the LLM classifies the alert as true positive or likely false positive with severity and rationale.

**Stage 2 - incident narrative.** Once all alerts in an incident are classified, `ReportGenerator` makes a single LLM call to write the cross-alert narrative: MITRE tactic, attack vectors, exposed data, and suggested response actions. Deterministic post-processing runs on top: a MITRE tactic override (corrects common misclassifications by scanning the signature and URL for credential keywords), a rule-based suggestion generator, and a three-layer filter that drops generic LLM suggestions and those that contradict enrichment data.

The finished report is saved to SQLite and broadcast over WebSocket to the dashboard. Raw alerts stream to the dashboard immediately on arrival, before the AI finishes.

---

## Component Roles

| Component | File | Responsibility |
|---|---|---|
| Log monitor | `log_monitor.py` | Tails `eve.json`, parses each line into an `AlertRecord` |
| Incident manager | `incident_manager.py` | Groups alerts by source IP, 2-minute window, 3-second debounce |
| ReAct agent | `react_agent.py` | XML-tagged reasoning loop, three tools, max 3 iterations, 30-second budget |
| Report generator | `report_generator.py` | Stage 1 + Stage 2 pipeline, MITRE override, suggestion filter |
| Report database | `report_db.py` | SQLite persistence (WAL mode, thread-local connections, retention sweeper) |
| Web server | `web_server.py` | Flask + Socket.IO: REST endpoints + WebSocket broadcast |
| Tool registry | `tool_registry.py` | Tool registration and dispatch |
| Agent tools | `agent_tools.py` | `get_alert_history`, `lookup_environment_context`, `get_attack_pattern_stats` |

---

## Data Flow

1. Suricata writes an alert line to `eve.json`.
2. `LogMonitor` parses the line into an `AlertRecord` and passes it to two subscribers: the raw-alert WebSocket broadcast and `IncidentManager`.
3. `IncidentManager` groups the alert into an incident (by source IP, 2-minute sliding window). After 3 seconds of silence, it fires the regenerate callback.
4. `ReportGenerator.generate(incident)` runs Stage 1 (per-alert `ReActAgent.classify()`) then Stage 2 (incident narrative LLM call) then deterministic post-processing.
5. The finished `IncidentReport` is saved to `data/reports.db` and pushed to all connected dashboard clients over WebSocket.

---

## What the LLM Does

The model (`qwen2.5:3b` by default) has exactly two jobs:

**Job 1 - classify one alert.** Given an alert and pre-fetched enrichment context, decide: real attack or false positive, severity, one-line rationale, recommended action (block / escalate / monitor).

**Job 2 - write the incident narrative.** Given all classified alerts in one incident, write the multi-paragraph summary: MITRE tactic, attack vectors, exposed data, suggested response actions.

The LLM does not receive raw alerts directly, call external APIs, write files, or remember anything between alerts. State lives in SQLite and the in-memory incident manager.

### Model limits and mitigations

| Observed behaviour | Mitigation |
|---|---|
| Sometimes mislabels `attack_type` to "Other" | `models.extract_attack_type()` resolves from SID range first (deterministic), falls back to LLM string |
| Sometimes picks wrong MITRE tactic | Rule-based override in `report_generator.py`; preserves LLM verdict when already correct |
| Sometimes suggests blocking internal IPs | Three-layer suggestion filter drops suggestions contradicting enrichment data |
| Occasional broken JSON or malformed XML output | Strict parser, retry once, single-shot fallback path |
| Slight variation across reruns at `temperature=0.0` | Structured fields (classification, severity) are stable; free-text fields may vary slightly |

Confidence scores are LLM-generated and advisory only. The model has not been fine-tuned for SOC work. Latency per alert is a few seconds on GPU, 10-15 seconds on CPU.

---

## LLM Choice

`qwen2.5:3b` runs locally via Ollama. Nothing leaves the machine: no API keys, no costs, no external data transfer. 3B parameters is approximately the floor where ReAct-style tool use is reliable; smaller models tend to skip tool calls or emit malformed output.

To use a different model, change `model_name` in `app.config`. A larger model (7B, 13B, or a remote API via `provider`) will generally classify more accurately with no other changes required.

---

## Storage

Reports are persisted to `data/reports.db` (SQLite, WAL mode). The schema uses indexed columns for commonly filtered fields plus a `full_report_json` blob containing the complete report payload.

### Schema

```sql
CREATE TABLE incidents (
    incident_id           TEXT PRIMARY KEY,
    source_ip             TEXT NOT NULL,
    status                TEXT NOT NULL,
    overall_severity      TEXT NOT NULL,
    overall_cvss          REAL NOT NULL,
    repeat_offender       INTEGER NOT NULL,
    total_alerts          INTEGER NOT NULL,
    detected_attacks      TEXT NOT NULL,          -- JSON array
    generated_at          TEXT NOT NULL,          -- ISO-8601 UTC
    last_updated_at       TEXT NOT NULL,
    first_seen            TEXT,
    last_seen             TEXT,
    report_version        TEXT,
    classification_counts TEXT NOT NULL,          -- JSON object
    model_used            TEXT,
    provider_type         TEXT,
    generation_status     TEXT,
    full_report_json      TEXT NOT NULL
);

CREATE TABLE alerts (
    alert_id        TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    src_ip          TEXT,
    signature       TEXT,
    signature_id    INTEGER,
    timestamp       TEXT,
    attack_type     TEXT,
    classification  TEXT,
    severity        TEXT,
    PRIMARY KEY (alert_id, incident_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);
```

The `alerts` table is denormalised from the report so per-IP history queries don't need to parse the JSON blob for every row.

### Configuration

```toml
[storage]
db_path                  = "data/reports.db"
retention_days           = 90                # 0 = never expire
cleanup_interval_seconds = 3600              # 0 = no automatic cleanup
```

`data/` is created if missing and is gitignored.

### API Endpoints

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/incidents` | All incidents, newest first |
| `GET` | `/api/incidents/<id>` | One incident, full payload |
| `GET` | `/api/incidents/by-ip/<ip>?hours=N` | Incidents from a source IP |
| `GET` | `/api/incidents/by-attack/<type>?hours=N` | Incidents by attack type |
| `GET` | `/api/incidents/by-severity/<sev>` | Incidents by severity |
| `GET` | `/api/incidents/stats?hours=N` | Counts by status / severity / attack type |
| `POST` | `/api/incidents/regenerate` | Force regen of all open + recently-closed |
| `POST` | `/api/incidents/clear` | Clear cache + delete from storage |
| `POST` | `/api/incidents/cleanup` | Trigger retention sweep, returns `{dropped: N}` |

### Concurrency and Retention

Each thread gets its own `sqlite3.Connection` via `threading.local`. WAL mode allows concurrent readers while a writer is committing. All writes use explicit transactions so the per-incident alerts rewrite is atomic.

When `retention_days > 0` and `cleanup_interval_seconds > 0`, a daemon thread runs `cleanup_expired()` on a tick. Set either to `0` to disable automatic cleanup.

### Operational Notes

```bash
# Inspect
sqlite3 data/reports.db "SELECT incident_id, source_ip, overall_severity, generated_at FROM incidents ORDER BY generated_at DESC LIMIT 10;"

# Reset (stop the app first)
rm data/reports.db data/reports.db-wal data/reports.db-shm

# Backup (safe while running under WAL)
cp data/reports.db data/reports.db.bak
```

---

## Further Reading

| Topic | Document |
|---|---|
| ReAct agent design details | `docs/AGENT.md` |
| Suricata rule reference and deployment | `lab/suricata/README.md` |
| Evaluation procedure | `docs/EVALUATION.md` |
