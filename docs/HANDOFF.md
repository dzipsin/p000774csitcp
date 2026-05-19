# Project Handoff — AI-Assisted SOC Alert Triage

This is the single source of truth for picking up the project from cold. A
fresh chat session, a new teammate, or future-you can read this top-to-
bottom and get oriented in 15 minutes.

If you have time for only one section: **Quick orientation** (next) and
**What's left** (near the bottom).

---

## Quick orientation

**What it is.** A working prototype Tier-1 SOC alert triage system. Pulls
Suricata IDS alerts from a controlled lab, groups them into incidents,
runs an agentic ReAct loop with three deterministic enrichment tools,
classifies each alert (true / likely-false positive + severity), produces
a structured incident report, and pushes everything to a live dashboard.
Backed by SQLite for cross-run history. Custom XSS rules from the team
land in the same pipeline.

**What's done.** Phases 1-5, 5.5 (hybrid auto-enrichment), 3.5 (template
serializer), 10 (SQLite migration), plus custom XSS rules integration
(task #19). All test suites green: **449 assertions across 9 suites**.

**What's left.** Phase 6 evaluation campaign (operator runs, ~3 hours
sequential), Phase 7 docs polish (this file is part of that), Phase 8
Mac portability, Phase 9 Mac demo dry-run, Phase 17 post-impl design-doc
cleanup. Detailed list at the bottom.

**Two active branches.**
- `feature/agentic-react-loop` — agentic upgrade, custom XSS rules, Phase
  6 scaffolding. Demo-ready as-is.
- `feature/sqlite-persistence` — built on top of agentic. Adds SQLite +
  query API + retention sweeper. Also demo-ready. This is the most-up-to-
  date branch.

**Operator preferences captured in memory.**
- Never add `Co-Authored-By` trailers to commits. Project is a capstone;
  attribution to AI affects academic integrity framing.

---

## System architecture

```
┌──────────────────────────────────────┐     ┌──────────────────────────────────────┐
│         KALI VM (VirtualBox)         │     │           HOST (Windows / Mac)       │
│                                      │     │                                      │
│  ┌──────────────┐ ┌────────────────┐ │     │ ┌──────────┐ ┌────────────────────┐  │
│  │  DVWA        │ │  Suricata IDS  │ │     │ │  Ollama  │ │ AI Triage App      │  │
│  │  (Docker)    │─▶│ + ET Open      │ │     │ │  :11434  │◀│ src/app.py         │  │
│  │  Port 8080   │ │ + custom XSS   │ │     │ │ qwen2.5:3b│ │ :5000              │  │
│  │              │ │ rules (lab/    │ │     │ └──────────┘ │  - LogMonitor       │  │
│  │              │ │ suricata/      │ │     │              │  - IncidentManager  │  │
│  │              │ │ xss_alerts.    │ │     │              │  - ReActAgent       │  │
│  │              │ │ rules)         │ │     │              │  - ReportGenerator  │  │
│  └──────────────┘ └────────────────┘ │     │              │  - ReportDatabase   │  │
│                          │           │     │              │    (SQLite)         │  │
│                          ▼           │     │              │  - Flask + SocketIO │  │
│                  /var/log/suricata/  │     │              └─────────┬───────────┘  │
│                  eve.json            │     │                        │              │
│                          │           │     │                        ▼              │
│                          ▼           │     │              data/reports.db          │
│              tail -F bridge ─────────┼─────┼─▶ host-side eve.json                  │
│             (VirtualBox shared       │     │       │                                │
│              folder)                 │     │       └──▶ LogMonitor                  │
│                                      │     │                                       │
│   Component 1 (web app) +            │     │       Component 3 (AI agent +         │
│   Component 2 (IDS) on this VM       │     │       storage + dashboard) here       │
└──────────────────────────────────────┘     └──────────────────────────────────────┘
```

**Data flow:**

1. Attacker (host browser or curl) fires HTTP attack at DVWA running in the VM
2. Suricata sees the packet on the Docker bridge, fires matching rules
   (ET Open + custom XSS rules), writes alert lines to `eve.json`
3. `tail -F` running in the VM mirrors `eve.json` to a VirtualBox shared
   folder; host reads it
4. `LogMonitor` (on host) tails the host-side `eve.json`, parses each
   alert line into an `AlertRecord`, broadcasts to two subscribers:
   - `Server.push_alert` — Raw Alerts tab in dashboard
   - `IncidentManager.process_alert` — groups into incidents
5. `IncidentManager` groups by source IP within a 2-minute sliding window,
   debounces 3 s, fires the regenerate callback
6. `ReportGenerator.generate(incident)` runs Stage 1 (per-alert ReAct
   classify) + Stage 2 (incident narrative) + rule-based suggestions +
   filters
7. Final `IncidentReport` saved to SQLite (`data/reports.db`) AND pushed
   to dashboard cache, broadcast over WebSocket to connected browsers

---

## Branch state

Both branches are pushed to `origin`. Tests pass on both.

### `feature/agentic-react-loop`

Built on top of `feature/ai-triage-module` (older starting state).
Contains:
- ReAct agent core + 3 tools + 14 commits of agentic work
- Custom XSS Suricata rules cherry-picked from teammate's `suricata-rules`
  branch into `lab/suricata/xss_alerts.rules`
- Phase 6 evaluation scaffolding (`run_combined_report.py`, `--config-dim`
  flag, runbook)
- Single-shot fallback fix (rule-based + filter work in any mode)

Latest commit on this branch: `4fa7e68 fix: rule-based suggestions + LLM
filter work in single_shot mode`.

### `feature/sqlite-persistence`

Branched from `feature/agentic-react-loop`. Adds:
- `src/report_db.py` (`ReportDatabase` SQLite class, drop-in replacement
  for `ReportStorage`)
- `data/reports.db` (gitignored — local-machine state)
- `[storage]` section in `app.config` (backend toggle, retention)
- New HTTP endpoints under `/api/incidents/` for history queries
- Retention sweeper thread
- Single-shot fix merged in via merge commit `f89f497`

Latest commit: `f89f497 Merge branch 'feature/agentic-react-loop' into
feature/sqlite-persistence`.

**This is the canonical work-in-progress branch.** Use this when
demoing or developing further. Merge to `main` when ready for the
capstone submission.

---

## Code structure

```
p000774csitcp/
├── app.config                       # TOML — provider, mode, agent, storage, env entries
├── requirements.txt                 # flask, flask-socketio, jsonschema
├── README.md                        # original install + run instructions
├── Incident Report Template v1.pdf  # capstone template the serializer matches
├── docs/
│   ├── AGENT_DESIGN.md              # Phase 1 design spec for the ReAct agent (824 lines)
│   ├── PHASE_6_RUNBOOK.md           # operator procedure for the 5-config ablation
│   ├── PHASE_10_SQLITE.md           # SQLite migration design + operations
│   └── HANDOFF.md                   # THIS FILE
├── lab/
│   └── suricata/
│       ├── README.md                # deployment + validation for custom XSS rules
│       └── xss_alerts.rules         # 58 rules across P1/P2/P3 priorities
└── src/
    ├── app.py                       # entrypoint — wires everything
    ├── log_monitor.py               # tails eve.json, emits AlertRecord
    ├── incident_manager.py          # alert grouping, debounce, sweeper
    ├── report_generator.py          # Stage 1 + Stage 2 pipeline, rule-based
    │                                # suggestions, LLM filters, MITRE override
    ├── report_serializer.py         # template-v1 JSON serializer + schema
    ├── report_db.py                 # ReportDatabase (SQLite backend) — Phase 10
    ├── storage.py                   # ReportStorage (JSON file backend, legacy)
    ├── models.py                    # AlertClassification, Incident, IncidentReport,
    │                                # ReasoningStep + all nested dataclasses
    ├── model_provider.py            # ModelProvider ABC + Ollama / Anthropic /
    │                                # llama.cpp implementations
    ├── ai_module.py                 # legacy AIAnalyzer for /api/analyse
    ├── react_agent.py               # ReActAgent — XML-tagged ReAct loop +
    │                                # auto-enrichment + reasoning trace
    ├── tool_registry.py             # ToolDefinition + ToolRegistry + ToolResult
    ├── agent_tools.py               # 3 tool implementations + the public
    │                                # lookup_environment_for_query
    ├── web_server.py                # Flask + Socket.IO — REST endpoints,
    │                                # WebSocket broadcasts, /api/incidents/* routes
    ├── static/                      # dashboard HTML/JS/CSS
    │   ├── app.js                   # incident card render + reasoning trace UI
    │   └── style.css
    ├── templates/index.html
    ├── test_incident_manager.py
    ├── test_report_generator.py
    ├── test_report_serializer.py
    ├── test_report_db.py            # Phase 10
    ├── test_react_agent.py
    ├── test_tool_registry.py
    ├── test_agent_tools.py
    ├── test_integration.py
    ├── test_evaluation.py
    └── evaluation/
        ├── attack_runner.py         # DVWA HTTP client that fires scenarios
        ├── result_collector.py      # polls /api/incidents, computes metrics
        ├── report_writer.py         # per-run markdown report
        ├── run_evaluation.py        # CLI — fires scenarios, --config-dim flag
        ├── run_combined_report.py   # CLI — aggregates per-config runs into
        │                            # the staircase ablation report
        └── scenarios.py             # 30 labelled attack scenarios + ground truth
```

`reports/`, `eval_results/`, `data/`, `.claude/` are all gitignored.

---

## Configuration — `app.config` cheat sheet

```toml
[server]
host = "0.0.0.0"
port = 5000

[monitor]
eve_log = "/var/log/suricata/eve.json"   # used inside the VM
# On host, override with env var EVE_LOG_PATH=C:/Projects/soc-triage/eve.json

[incident]
grouping_mode        = "per_actor"     # or per_attack_type
time_window_minutes  = 2.0             # how long an incident stays open
debounce_seconds     = 3.0
reports_dir          = "reports"       # used only when storage.backend="json"
sweep_interval_seconds = 10.0

[analysis]
include_lab_context = true             # injects Docker/MariaDB context into Stage 1
summary_mode        = "llm"            # "llm" or "template"
max_retries         = 1                # per LLM call on parse/validation fails

[agent]
mode                     = "react"     # "single_shot" | "react"
max_iterations           = 3
tool_timeout_seconds     = 5.0
total_budget_seconds     = 30.0
reasoning_trace_enabled  = true
auto_enrichment          = true        # Option F hybrid — deterministic pre-LLM tools

[agent.tools]
get_alert_history             = true
lookup_environment_context    = true
get_attack_pattern_stats      = true

# [[agent.environment.entries]]
# pattern              = "172.18.0.2"
# match_type           = "exact_ip"     # exact_ip | cidr | url_prefix | url_contains
# role                 = "internal_database"
# description          = "EXPECTED INTERNAL — MariaDB inside Docker bridge..."
# classification_hint  = "likely_false_positive_if_internal_only"
# (5 entries shipped: MariaDB, Docker bridge CIDR, host-only CIDR,
#  DVWA SQLi endpoint, DVWA XSS endpoint)

[storage]                              # Phase 10 — SQLite backend
backend                  = "sqlite"    # "sqlite" | "json"
db_path                  = "data/reports.db"
retention_days           = 90          # 0 = never expire
cleanup_interval_seconds = 3600        # 0 = no automatic cleanup

[model]
provider    = "ollama"
max_tokens  = 1024
temperature = 0.0

[model.ollama]
model_name      = "qwen2.5:3b"         # demo-best; flip to "llama3.2" for Phase 6 baseline
base_url        = "http://localhost:11434"
request_timeout = 120
```

**Two canonical configs**:

| Setting | Demo-best | Phase 6 baseline |
|---|---|---|
| `[model.ollama].model_name` | `"qwen2.5:3b"` | `"llama3.2"` |
| `[agent].mode` | `"react"` | `"single_shot"` |
| `[agent].auto_enrichment` | `true` | `false` |

Toggling those three is enough to swap between demo and baseline modes.
Comments in `app.config` show the alternates.

---

## How to run

### Daily run (host + VM)

**1. Inside Kali VM** (every boot):

```bash
# DVWA
cd ~/docker/dvwa && docker compose up -d

# Suricata
sudo systemctl start suricata

# eve.json bridge to shared folder
pkill -f "tail.*eve.json"
nohup tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json 2>/dev/null &
```

**2. On host** (Windows / Mac):

```powershell
# Activate venv
.venv\Scripts\Activate.ps1          # PowerShell
# OR
source .venv/bin/activate           # bash

# Point at the shared-folder eve.json
$env:EVE_LOG_PATH = "C:/Projects/soc-triage/eve.json"
# Mac/Linux: export EVE_LOG_PATH="$HOME/Projects/soc-triage/eve.json"

# Run
python src/app.py
```

Dashboard: <http://127.0.0.1:5000>. Attack DVWA at
<http://192.168.56.101:8080> (or whatever your VM's host-only IP is).

### Running tests

```powershell
# All 9 suites:
python src/test_incident_manager.py
python src/test_report_generator.py
python src/test_report_serializer.py
python src/test_report_db.py
python src/test_react_agent.py
python src/test_tool_registry.py
python src/test_agent_tools.py
python src/test_integration.py
python src/test_evaluation.py
```

Or one-line sequential check:

```powershell
foreach ($t in "test_incident_manager","test_report_generator","test_report_serializer","test_report_db","test_react_agent","test_tool_registry","test_agent_tools","test_integration","test_evaluation") { python "src\$t.py" 2>&1 | Select-Object -Last 3 }
```

Expect: all pass (counts in the **Test totals** section below).

### Evaluation harness (Phase 6)

See `docs/PHASE_6_RUNBOOK.md` for the full operator procedure. TL;DR:

```powershell
# Per-run:
python -m src.evaluation.run_evaluation `
    --label "p6_<step>_rep<N>" `
    --repeats 1 `
    --config-dim '{\"step\":\"<step>\",\"model\":\"<model>\",\"agent_mode\":\"<mode>\",\"auto_enrichment\":<bool>,\"custom_xss_rules\":<bool>}'

# After all 15 runs:
python -m src.evaluation.run_combined_report `
    --indir eval_results `
    --label-prefix "p6_" `
    --order "baseline,model_swap,react,enrich,custom_rules" `
    --out eval_results/p6_combined_report.md
```

5 configs × 3 reps = 15 runs, ~3 hours. Can be split across multiple
sessions — each run produces its own raw JSON, combined report
reaggregates them.

### Switching storage backends

```toml
[storage]
backend = "sqlite"   # default
# backend = "json"  # legacy file-per-incident
```

`data/reports.db` is created automatically. To wipe and restart from
clean:

```bash
rm data/reports.db data/reports.db-wal data/reports.db-shm
```

---

## Architecture deep dive

For full design rationale, read `docs/AGENT_DESIGN.md`. Highlights here:

### The two-stage pipeline + ReAct

Stage 1 = per-alert classification. Stage 2 = incident-level narrative.
Stage 1 in `agent.mode = "react"` mode is replaced by `ReActAgent` —
XML-tagged Reasoning + Acting loop with three tools:

- `get_alert_history(src_ip, hours)` — prior alerts from this IP across
  in-memory + storage
- `lookup_environment_context(query)` — env config lookup
  (exact_ip / cidr / url_prefix / url_contains)
- `get_attack_pattern_stats(attack_type, hours)` — aggregate stats

In `mode = "single_shot"`, Stage 1 is the legacy one-LLM-call-per-alert
path — kept for evaluation baseline.

### Option F — hybrid auto-enrichment

`auto_enrichment = true` means before the LLM ever sees an alert, the
agent runtime deterministically calls all three tools. Results are
seeded into `reasoning_trace` with `source="system"` and rendered in the
LLM prompt as `<system_enrichment>` blocks. The LLM can still issue
additional tool calls afterwards. Compensates for qwen2.5:3b's tool-call
adherence drift while keeping the LLM autonomous on the verdict.

Toggle off (`auto_enrichment = false`) for the Phase 6 evaluation
ablation that measures the contribution of this design choice.

### Rule-based suggestions + filter ladder

Stage 2's `ai_suggestions` field goes through three layers:

1. **Rule-based generator** — produces deterministic playbook-style
   suggestions for known patterns (Block IP, Rotate credentials, Audit
   XSS endpoint, Tier-2 ticket, Pentest hint, Tune Suricata for FP
   cluster). Works in ALL modes (single_shot, react, react+enrich) —
   derives facts from `incident.source_ip` + `env_entries` config when
   no reasoning trace exists.

2. **LLM filter** — drops LLM suggestions that:
   - Start with banned generic phrases ("Implement additional",
     "Review and update", "Enhance monitoring", etc.)
   - Contradict enrichment facts ("Block 172.18.0.x" when source is
     internal infrastructure; "Tune Suricata to suppress" when source
     is untrusted external)
   - Duplicate rule-based output by (first verb, first IP)

3. **Merge** — rule-based first, surviving LLM second, dedup'd by exact
   match, capped at 6 total.

### MITRE override

After Stage 2 returns an `overall_attack_stage`, a rule-based override
kicks in. qwen2.5:3b sometimes labels SQLi/XSS as "Reconnaissance" or
"Execution"; the override maps attack types to canonical tactics
(SQLi targeting credentials → Credential Access, XSS → Initial Access,
CommandInjection → Execution, etc.). Honest engineering: rule-based for
what we KNOW, LLM judgment for everything else.

### Template-v1 serializer

`report_serializer.py` produces a JSON envelope matching
`Incident Report Template v1.pdf`. Field renames (`src_ip` → `source_ip`,
`signature` → `alert_msg`, etc.), section duplication where the template
puts the same data in two places, severity normalisation to 3 levels.
Schema validation via `jsonschema`. ReportStorage / ReportDatabase /
WebSocket push all emit this shape.

### SQLite migration

`ReportDatabase` is a drop-in replacement for `ReportStorage`
(`save / list_reports / load_raw / clear_all`). Adds query methods
(`list_by_source_ip`, `list_by_attack_type`, `list_by_severity`,
`aggregate_stats`, `cleanup_expired`) and a retention sweeper thread.
Hybrid schema: indexed columns + JSON blob. WAL mode + thread-local
connections. See `docs/PHASE_10_SQLITE.md` for the full design.

### Custom XSS rules

58 rules from teammate (KAUR97) in `lab/suricata/xss_alerts.rules`.
P1 catches confirmed exploit chains (`document.cookie` + exfiltration
vector), P2 catches encoded tag injection, P3 catches generic JS sinks.
SIDs in user range 1000001-1000058 (renumbered from teammate's original
2000001-2000058 which clashed with ET Open). Deployment + validation
procedure in `lab/suricata/README.md`.

---

## All locked design decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | Two-VM lab collapsed to one Kali VM (DVWA + Suricata co-located) | Spec drift documented as deliberate simplification; spans-port limitation in VirtualBox makes proper split impractical |
| 2 | XML-tagged ReAct format (not native function calling) | Provider-portable, parses on 3B models, no Ollama-specific tool-use API dependency |
| 3 | Three tools fixed (history / env / stats) | Each maps to a real Tier-1 SOC question; all read existing app state |
| 4 | Default LLM `qwen2.5:3b`; baseline `llama3.2:3b` | Better tool-use adherence; baseline preserves comparability with original eval numbers |
| 5 | Single-shot mode kept under config flag | Enables ablation; demo fallback if ReAct misbehaves |
| 6 | Mac demo: UTM + Kali mirror | Path of least resistance; not yet executed (Phase 8) |
| 7 | Reasoning trace UI: static render only | Live streaming was stretch goal; static suffices for spec + demo |
| 8 | Hybrid Option F: deterministic pre-LLM enrichment + LLM exploration | Compensates for small-model adherence; honest framing in report |
| 9 | Rule-based MITRE override | qwen2.5:3b mislabels common cases; override is honest engineering |
| 10 | Rule-based suggestion generator + 3-layer LLM filter | qwen2.5:3b produces platitudes + occasional dangerous advice; layered defence |
| 11 | Template-v1 serializer | Marker reads the JSON, expects template fields; serializer keeps internal model rich while emitting template-compliant shape |
| 12 | SQLite hybrid schema | Indexed cols for cheap queries + JSON blob for full payload; standard pragmatic choice |
| 13 | No migration from JSON to SQLite | Fresh database on first run; minimises operational risk |
| 14 | SIDs renumbered to 1000001-1000058 | User-rule range; original 2000xxx range clashes with ET Open |
| 15 | `HOME_NET = any` kept (broken-by-design) | Fixing properly would change which alerts fire and break eval comparability |
| 16 | Phase 6 staircase: 5 configs × 3 reps | Each row isolates one design-decision contribution to F1; complete story for capstone report |
| 17 | No AI commit trailers | Academic integrity framing — operator preference saved to memory |

---

## Memory entries (persistence across sessions)

These live in `C:/Users/Ahruxu/.claude/projects/C--Projects-soc-triage-p000774csitcp/memory/`.

| Memory | What it captures |
|---|---|
| `feedback_commit_trailers.md` | Never add `Co-Authored-By` trailers to commits on this repo |
| `project_custom_xss_rules.md` | Teammates' XSS rules — was pending, now delivered + integrated |

A fresh session should automatically pick these up.

---

## Test totals (snapshot)

| Suite | Count |
|---|---|
| `test_report_db` (Phase 10) | 14 |
| `test_report_generator` | 54 |
| `test_integration` | 6 |
| `test_evaluation` | 4 |
| `test_incident_manager` | 11 |
| `test_tool_registry` | 54 |
| `test_agent_tools` | 119 |
| `test_react_agent` | 121 |
| `test_report_serializer` | 66 |
| **Total** | **449 — all pass on `feature/sqlite-persistence`** |

Some are "assertion counts" (uses a `_assert` helper that tracks
pass/fail per condition) and some are "test function counts" (each
function runs one or more asserts but counts as a single test). Both
are reported here to match the suites' own output.

---

## What's done — phase-by-phase

| Phase | Deliverable | Status |
|---|---|---|
| **1** | `docs/AGENT_DESIGN.md` design spec + branch cut + qwen2.5:3b verified | ✅ |
| **2** | Tool registry + 3 tool implementations + tests | ✅ |
| **3** | ReActAgent core + XML parser + 80 unit tests | ✅ |
| **3.5** | Template-v1 serializer + JSONSchema + 66 tests | ✅ |
| **4** | ReActAgent wired into ReportGenerator + `[agent]` config | ✅ |
| **5** | Dashboard reasoning trace UI (static) | ✅ |
| **5.5** | Hybrid auto-enrichment (Option F) + cache + filter tightening | ✅ |
| **Custom XSS rules** (task #19) | Cherry-picked + renumbered to 1000xxx + deployed + validated | ✅ |
| **10** | SQLite migration + history-query API + retention sweeper | ✅ |
| **6 (code)** | Eval-harness `--config-dim` flag + combined-report generator + runbook | ✅ |
| **6 (runs)** | 5-config × 3-rep evaluation campaign | **Pending operator runs (~3 hr)** |
| **7** | README / RUNBOOK / HANDOFF / ARCHITECTURE refresh | **In progress (this file)** |
| **8** | Mac portability — UTM + Kali setup runbook | **Pending** |
| **9** | End-to-end Mac demo dry-run | **Pending** |
| **17** | `docs/AGENT_DESIGN.md` cleanup to design-only (post-impl) | **Pending** |

---

## What's left

In priority order:

### High priority (capstone deliverables)

1. **Phase 6 evaluation campaign** — operator runs 5 configs × 3 reps. See
   `docs/PHASE_6_RUNBOOK.md` for the step-by-step. Total ~3 hours, can be
   split across days. Output: `eval_results/p6_combined_report.md` with
   ΔF1 column per design decision.

2. **README refresh** — the existing `README.md` was written before the
   agentic upgrade. Needs to mention:
   - ReAct mode + `[agent]` config
   - SQLite backend + `[storage]` config
   - Custom XSS rules in `lab/suricata/`
   - The 9-suite test layout
   - This handoff doc as the orientation point

3. **`docs/ARCHITECTURE.md`** — was mentioned in earlier HANDOFF but never
   created. Could be a slimmer companion to `AGENT_DESIGN.md` focused on
   the operational/runtime view rather than the design rationale.

### Medium priority (demo robustness)

4. **Phase 8: Mac portability** — current pipeline runs on Windows with
   VBox + Kali. Capstone demo target is Mac Air M4 16GB. Need to either
   verify VBox 7 on Apple Silicon works OR document UTM-based path. The
   Python triage app is platform-independent — only the lab side is
   Mac-specific.

5. **Phase 9: Mac demo dry-run** — once Phase 8 is documented, run the
   full attack → alert → triage → incident report flow on Mac. Identify
   any failure modes, update demo runbook.

### Low priority (post-impl polish)

6. **Phase 17: Trim `docs/AGENT_DESIGN.md` to design-only** — currently
   contains process content (locked decisions table, phase timeline, next
   steps). Strip those once implementation is done. Operator (Ahrar)
   asked for this explicitly during Phase 1.

7. **Merge to main** — both feature branches need to land on `main`. Order:
   `feature/agentic-react-loop` first, then `feature/sqlite-persistence`
   (which is already based on top of the first). Or single merge of
   `feature/sqlite-persistence` directly to `main` (it carries everything).

### Branch reconciliation note

`feature/sqlite-persistence` already contains everything in
`feature/agentic-react-loop` (via the `f89f497` merge commit). A single
merge of `feature/sqlite-persistence → main` brings the whole thing in.

---

## Known limitations (honest list for the eval report)

1. **`HOME_NET = any`** in `suricata.yaml` — flagged from day 1 but kept
   to avoid breaking baseline alert detection. Three ET Open rules
   (sids 2011802, 2000328, 2002087) fail to load due to this — they're
   email-detection rules irrelevant to the demo, log a parse error at
   startup, then Suricata continues. Cosmetic noise, not blocking.

2. **qwen2.5:3b non-determinism at `temperature = 0.0`** — same alert
   classified differently across regens. Documented in
   `docs/AGENT_DESIGN.md §13`.

3. **qwen2.5:3b XML format adherence drift** — model occasionally emits
   both `<action>` and `<final_answer>` in one response, or malformed
   `action_input` JSON. Mitigated by robust XML parser + retry logic +
   single-shot fallback. Parse failure rate tracked as an eval metric.

4. **`observed_true_positive_rate` is self-referential** —
   `get_attack_pattern_stats` reports the historical TPR from past LLM
   verdicts. Useful as relative signal, not absolute accuracy. Flagged
   in design doc.

5. **Reasoning trace storage cost** — each trace adds ~500-2000 bytes per
   report. Negligible for current lab volumes (50-200 KB/day at 100
   incidents/day) but worth noting if scaling to production.

6. **No multi-agent orchestration** — capstone spec called for "Single
   Agent" so this is by-design, but a marker who reads "agentic" loosely
   might want richer multi-agent narrative. Defensible: ReAct loop +
   pre-enrichment + tool autonomy is the standard agentic pattern.

7. **Phase 6 eval ablation has not yet been run.** No measured ΔF1 in
   the final report yet — pending operator time.

8. **MITRE override is rule-based, not model-derived.** Honest framing
   in the eval report: rule-based for known cases, LLM for everything
   else. Defensible.

---

## Troubleshooting

| Symptom | Most likely cause | Fix |
|---|---|---|
| No alerts in dashboard Raw Alerts tab | `eve.json` bridge died inside VM | re-run `nohup tail -F /var/log/suricata/eve.json > /media/sf_soc-triage/eve.json &` |
| Alerts visible but incidents stuck "open" forever | `IncidentManager` window hasn't expired | Wait `time_window_minutes` (default 2 min) OR click Force Regenerate |
| Suricata startup says `Loading signatures failed` | Pre-existing ET Open rules with `!$HOME_NET` (HOME_NET is `any`). Cosmetic. | Confirm with `sudo grep "rules loaded" /var/log/suricata/suricata.log` — should show ~49600 rules loaded despite the error line |
| Custom XSS rule SIDs not firing | File in wrong path | Must be `/var/lib/suricata/rules/xss_alerts.rules`, not `/etc/suricata/rules/` |
| Dashboard always shows FP=0 | Older JS cached | Hard-refresh (Ctrl+Shift+R). Fix was committed `7f42d3c` |
| Stage 2 picks wrong MITRE tactic | LLM adherence drift | MITRE override handles common cases; check console log for `Stage 2 MITRE tactic overridden:` line |
| LLM emits "let me check ..." after enrichment data is already in the prompt | Stylistic prompt adherence | Tightened in `2ff1a1d`. If still happens occasionally, accept — it's qwen2.5:3b's ceiling |
| `python src/app.py` shows `Storage backend: SQLite at ...` but you wanted JSON | `[storage].backend = "sqlite"` (default) | Set `backend = "json"` in `app.config` and restart |
| `data/reports.db` corrupted or stuck | Crash mid-write | `rm data/reports.db*` (all WAL/SHM sidecars) — fresh schema on next start |
| Evaluation harness `Dashboard not reachable` | App on host isn't running, or port differs | Verify `python src/app.py` is alive on :5000 |
| Combined report says "no runs matched" | Eval runs missing `--config-dim` | Re-run with the flag; or manually edit the raw JSON to add `config_dimensions.step` |

---

## Quick-start for a brand-new chat session

If you're starting from a fresh session, here's the minimum context needed:

1. **Read this file top-to-bottom.** Should take ~10 minutes.
2. **Run the tests** (block above titled *Running tests*). Confirms
   nothing broke since last session.
3. **Check git status** — current branch + uncommitted changes:
   ```powershell
   git branch --show-current
   git log --oneline -5
   git status
   ```
4. **Look at the task list** — open this conversation's task tracker or
   skim the **What's left** section above.
5. **Check `app.config`** — confirm whether it's set to demo-best or
   Phase 6 baseline (see *Configuration cheat sheet* above).

After that, ask the operator (or your own judgment):
- "What did we last work on?"
- "What's the next thing to do?"
- "Is the demo soon?"

---

## Useful references

| Doc | When to consult |
|---|---|
| `docs/AGENT_DESIGN.md` | Full design rationale for the agentic ReAct loop. Read on Phase 17 cleanup or when explaining the agent to a marker. |
| `docs/PHASE_6_RUNBOOK.md` | Operator procedure for the evaluation campaign — exact commands per config, troubleshooting, interpretation. |
| `docs/PHASE_10_SQLITE.md` | SQLite migration design + operations — schema, concurrency, retention, roll-back to JSON. |
| `lab/suricata/README.md` | Deployment + hand-test plan for custom XSS rules. |
| `Incident Report Template v1.pdf` | The template the marker expects the JSON to conform to. |
| `README.md` | Original setup (predates this work — needs the Phase 7 refresh). |

---

*This handoff doc is the canonical orientation for the project as of
2026-05-20. Update it whenever a major milestone lands or a key
decision changes.*
