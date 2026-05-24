# Architecture and Workflow

Visual reference for the prototype. Five Mermaid diagrams, each zooming further
in than the previous. GitHub renders Mermaid inline in markdown — if a diagram
appears as raw text in your editor, the source is still readable; push to GitHub
or open in any Mermaid-aware viewer.

> **New to the project?** Read in this order: this doc → `docs/HANDOFF.md`
> (written context: what's done, what's left, why) → `README.md` (setup). Each
> diagram below has a short explanation under it; the explanations are part of
> the document, not optional.

## How to read

| Symbol / Style | Meaning |
|---|---|
| **Subgraph box** | Components that share a physical machine, a phase, or a file boundary |
| **Solid arrow** `-->` | Synchronous data or call flow |
| **Dashed arrow** `-.->` / `-->>` | Asynchronous notification, broadcast, or return value |
| **Diamond** `{...}` | Decision point |
| **Cylinder** `[(...)]` | Persistent storage |
| **Stadium** `([...])` | External boundary (caller enters / value leaves) |
| **`<br/>` second line in a node** | File path or implementation detail |
| **Edge label** | Protocol, data shape, or invocation name |

---

## 1. System overview — containers and boundaries

Big-picture: what runs where and how data crosses the VM ↔ host boundary.

```mermaid
flowchart TB
    subgraph VM["Kali VM (VirtualBox)"]
        AtkBrowser["Attacker browser<br/>or curl"]
        DVWA["DVWA<br/>Docker container, port 8080"]
        Suricata["Suricata IDS<br/>monitors Docker bridge<br/>custom rules ONLY"]
        Rules["/var/lib/suricata/rules/<br/>xss_alerts.rules sid 1000001-1000058<br/>sqli_alerts.rules sid 1000101-1000113"]
        Eve["/var/log/suricata/eve.json<br/>JSON alert events"]
        Tail["tail -F (background process)"]

        AtkBrowser -->|HTTP attack payload| DVWA
        DVWA -.->|Docker bridge mirror| Suricata
        Rules --> Suricata
        Suricata -->|append alert event| Eve
        Eve --> Tail
    end

    subgraph SF["VirtualBox shared folder<br/>(host path: C:/Projects/soc-triage)"]
        SE["eve.json mirror"]
    end

    Tail -->|stdout redirect| SE

    subgraph H["Host machine (Python + Ollama)"]
        direction TB
        APP["app.py<br/>entry point, wires everything"]
        LM["log_monitor.py<br/>tails eve.json"]
        IM["incident_manager.py<br/>grouping + lifecycle"]
        AG["react_agent.py<br/>Stage 1 classifier"]
        RG["report_generator.py<br/>Stage 2 narrative + filters"]
        DB[("SQLite<br/>data/reports.db<br/>WAL mode, 90d retention")]
        WS["web_server.py<br/>Flask + Socket.IO :5000"]
        OL["Ollama :11434<br/>qwen2.5:3b (local LLM)"]

        APP --> LM
        APP --> IM
        APP --> RG
        APP --> WSV_INIT[" "]
        APP --> WS
        SE --> LM
        LM -->|AlertRecord| IM
        LM -->|raw alert event| WS
        IM -->|incident snapshot| RG
        RG --> AG
        AG -->|complete prompt| OL
        OL -.->|response| AG
        RG -->|complete prompt| OL
        OL -.->|response| RG
        RG -->|save report| DB
        RG -->|report_ready broadcast| WS
        WS -->|history queries| DB
    end

    Analyst["Analyst browser<br/>dashboard at http://localhost:5000"]
    WS <-->|WebSocket events + REST| Analyst

    style WSV_INIT fill:transparent,stroke:transparent
```

**Two machines, one shared folder.** The VM runs the vulnerable app + IDS so
attack traffic flows over a real network bridge. The host runs Python + Ollama
because they need more RAM and a model file you do not want on a throw-away VM.

**Custom rules only.** ET Open and Suricata's built-in protocol-event rules are
disabled in `suricata.yaml`. Every alert is one of the 71 team-authored rules.
This keeps the feed scoped to the two attack classes the project demonstrates
(XSS + SQLi) and makes every alert traceable to a rule the team wrote.

**The shared folder is the only data path out of the VM.** Suricata streams
`eve.json` into the folder via `tail -F`; the host's `log_monitor` tails it.
No network port is exposed from the VM.

---

## 2. Alert lifecycle — sequence

One alert's complete path from packet to dashboard incident report.

```mermaid
sequenceDiagram
    autonumber
    participant Atk as Attacker
    participant DVWA
    participant Sur as Suricata
    participant Eve as eve.json
    participant Mon as log_monitor
    participant Inc as incident_manager
    participant Agt as react_agent
    participant RG as report_generator
    participant Ol as Ollama
    participant DB as SQLite
    participant UI as Browser dashboard

    Atk->>DVWA: HTTP GET with UNION SELECT payload
    DVWA-->>Sur: bridge mirror (HTTP request seen)
    Sur->>Sur: pcre match on URI buffer
    Sur->>Eve: append alert (sid 1000101, priority 1)
    Eve->>Mon: new JSON line
    Mon->>UI: WebSocket emit raw_alert
    Mon->>Inc: AlertRecord (parsed dataclass)
    Inc->>Inc: open or extend incident (per src_ip, 2-min window)
    Inc->>Inc: debounce 3s, then trigger regeneration

    loop per alert in incident (Stage 1)
        Inc->>Agt: classify(alert)
        Agt->>Agt: auto-enrichment phase (3 tools, deterministic)
        Agt->>Ol: ReAct round 1 (prompt + enrichment trace)
        Ol-->>Agt: thought + final_answer JSON
        opt model emitted action instead
            Agt->>Agt: execute extra tool, append observation
            Agt->>Ol: ReAct round 2 (with observation)
            Ol-->>Agt: final_answer JSON
        end
        Agt-->>Inc: AlertClassification
    end

    Inc->>RG: generate(incident, classifications)
    RG->>Ol: Stage 2 narrative call
    Ol-->>RG: narrative + tactic + vectors + raw suggestions
    RG->>RG: MITRE override (scan signature + URL)
    RG->>RG: suggestion filter (rule + 3-layer LLM filter)
    RG->>RG: serialize to template-v1 + JSONSchema validate

    par save and broadcast
        RG->>DB: save report (hybrid schema)
    and notify dashboard
        RG->>UI: WebSocket emit report_ready
    end

    UI->>DB: GET /api/incidents/<id>
    DB-->>UI: full template-v1 JSON
    UI->>UI: render incident card with reasoning trace
```

**Two LLM stages.** Stage 1 classifies each alert individually inside the ReAct
agent. Stage 2 builds the cross-alert incident narrative in `report_generator`.
Each uses one or more Ollama calls; both run on the same `qwen2.5:3b` model by
default.

**Debounce prevents thrashing.** Bursts of alerts (e.g. one HTTP request firing
three custom rules at once) collapse into a single regeneration 3 s after the
last alert arrives. The dashboard sees the alerts immediately via raw_alert
events; the incident report follows once classification + Stage 2 finish.

**Two paths to the browser.** Raw alerts go through WebSocket as they arrive
(real-time feed). Incident reports go through WebSocket (live update) *and*
SQLite (so a page reload reconstructs the report from persisted state via REST).

---

## 3. ReAct agent internals

Inside `react_agent.classify(alert)`. Implements the hybrid Option F design —
deterministic enrichment first, then the LLM drives the rest.

```mermaid
flowchart TB
    start([AlertRecord arrives])

    subgraph PRE["Phase 1 — deterministic auto-enrichment (iteration 0, no LLM)"]
        T1["get_alert_history<br/>{src_ip, hours: 24}"]
        T2["lookup_environment_context<br/>{query: src_ip}"]
        T3["get_attack_pattern_stats<br/>{attack_type, hours: 24}"]
        Seed["seed reasoning_trace<br/>source = 'system'"]
        T1 --> Seed
        T2 --> Seed
        T3 --> Seed
    end

    start --> PRE
    Seed --> RN

    subgraph LLM["Phase 2 — LLM ReAct loop (max 3 iter, 30 s budget)"]
        RN["Round N<br/>build prompt = system + alert + trace<br/>call qwen2.5:3b"]
        Parse{"parse XML tags<br/>thought / action / final_answer"}
        Validate["validate JSON against<br/>classification schema"]
        Exec["execute tool<br/>(get_alert_history /<br/>lookup_environment_context /<br/>get_attack_pattern_stats)"]
        Obs["append observation<br/>source = 'llm'"]
        Retry{"retry budget left?"}
        Fallback["fallback<br/>single-shot LLM call<br/>no tools, no loop"]

        RN --> Parse
        Parse -->|final_answer present| Validate
        Parse -->|action + action_input| Exec
        Parse -->|parse error| Retry
        Exec --> Obs
        Obs --> RN
        Retry -->|yes| RN
        Retry -->|no| Fallback
    end

    Validate --> Out["AlertClassification<br/>classification: true_positive / likely_false_positive / error<br/>attack_type: SQLi / XSS / Other<br/>severity: High / Medium / Low<br/>summary, recommendation,<br/>confidence_score, reasoning_trace[]"]
    Fallback --> Out

    Out --> done([return to incident_manager])
```

**Phase 1 fires the tools the LLM should almost always want anyway.** Without
this scaffold, small models often skip enrichment and classify from the alert
msg alone, losing the contextual signal (prior-alert counts, untrusted-source
flag, attack-type history). The deterministic phase guarantees the LLM sees the
enrichment results before it speaks.

**Phase 2 lets the LLM still explore.** The model can emit further tool calls
if needed (e.g. checking a different attack type's pattern stats), or jump
straight to `<final_answer>`. Most classifications resolve in iteration 1
because Phase 1 already answered the question.

**Fallback is single-shot.** If parsing fails repeatedly or the time budget
expires, the loop bails to a direct LLM call with no tools, classifying from the
msg alone. Better than no classification — the result is still consistent with
the rest of the pipeline.

---

## 4. Stage 2 pipeline — incident to report

Inside `report_generator.generate(incident, classifications)`. Runs once per
incident regeneration (not once per alert).

```mermaid
flowchart TB
    in([Incident with N classified alerts])

    in --> S2["Stage 2 LLM call<br/>synthesise narrative across N alerts<br/>qwen2.5:3b"]
    S2 --> Raw["raw Stage 2 output<br/>narrative, tactic, vectors,<br/>data exposure, raw_suggestions[]"]

    Raw --> MO["MITRE tactic override<br/>scan signature + URL for credentials<br/>SQLi + creds -> Credential Access<br/>preserve LLM tactic if already valid"]

    subgraph SF["Suggestion filter pipeline (3-layer LLM filter + rule-based merge)"]
        RB["rule-based generator<br/>SOC playbook patterns<br/>(block IP, open ticket,<br/>rotate creds, audit endpoint)"]
        F1["Layer 1 — generic-platitude filter<br/>drop 'Open ticket' /<br/>'Investigate' starters"]
        F2["Layer 2 — enrichment-aware filter<br/>drop 'Block internal IP'<br/>contradictions"]
        F3["Layer 3 — verb+IP dedup<br/>strip near-duplicates of<br/>rule-based output"]
        Merge["merge rule-based + filtered LLM"]

        F1 --> F2 --> F3 --> Merge
        RB --> Merge
    end

    Raw -->|raw LLM suggestions| F1
    MO --> Out
    Merge --> Out["IncidentReport (in-memory)"]

    Out --> SER["template-v1 serializer<br/>(report_serializer.py)"]
    SER --> SCH["JSONSchema validate<br/>(report_schema.py)"]

    SCH --> DB[("SQLite reports.db<br/>incidents + alerts tables")]
    SCH --> WS["WebSocket emit<br/>report_ready event"]

    DB --> done([dashboard fetches via REST])
    WS --> done
```

**One LLM call per incident**, not per alert. Stage 2 synthesises across all
classifications — cross-alert narrative ("UNION SELECT followed by INTO OUTFILE
from the same IP") only emerges here.

**Deterministic post-processing fixes known LLM weaknesses.** The MITRE override
corrects tactic when the LLM picked something wrong (forces Initial Access for
generic SQLi, bumps to Credential Access when the URL names credentials), while
preserving the LLM's choice when it's already valid. The 3-layer suggestion
filter strips generic platitudes, drops suggestions that contradict enrichment
("block internal IP" when the IP belongs to a documented internal system), and
removes near-duplicates of rule-based output.

**Template-v1 is the wire format.** The serializer reshapes the in-memory report
into the JSON shape the dashboard and persistent store expect; the JSONSchema
validation is a hard guard against accidental field drift over time.

---

## 5. Module map — who imports whom

File-level dependency map. Use this when reading the code top-down or when
locating the owner of a specific behaviour.

```mermaid
flowchart LR
    subgraph entry["Entry"]
        APP[app.py]
    end

    subgraph io["I/O boundary"]
        LM[log_monitor.py]
        WSV[web_server.py]
        RDB[report_db.py]
        RS[report_storage.py<br/>legacy JSON backend]
    end

    subgraph domain["Domain models"]
        MOD[models.py<br/>AlertClassification<br/>Incident<br/>IncidentReport]
        IM[incident_manager.py]
    end

    subgraph aipipe["AI pipeline"]
        AGT[agent_tools.py]
        TR[tool_registry.py]
        RA[react_agent.py]
        AM[ai_module.py<br/>legacy single-shot]
        RG[report_generator.py]
        SER[report_serializer.py]
        SCH[report_schema.py]
        MP[model_provider.py]
    end

    subgraph cfg["Config + scenarios"]
        CFG[app.config<br/>TOML]
        SC[evaluation/scenarios.py]
    end

    APP --> LM
    APP --> IM
    APP --> RG
    APP --> WSV
    APP --> RDB
    APP --> CFG

    LM --> MOD
    IM --> MOD
    IM --> RG

    RG --> RA
    RG --> SER
    RG --> MP
    SER --> SCH

    RA --> AGT
    RA --> TR
    RA --> MP
    AGT --> MOD

    RDB --> MOD
    WSV --> RDB
```

**Recommended reading order to learn the codebase:**

1. **`app.py`** — wires everything together; start here.
2. **`models.py`** — data shapes (AlertClassification, Incident, IncidentReport);
   understand these before reading consumers.
3. **`log_monitor.py`** — input boundary.
4. **`incident_manager.py`** — grouping + lifecycle + debounce.
5. **`react_agent.py`** + **`agent_tools.py`** — Stage 1 (AI pipeline).
6. **`report_generator.py`** — Stage 2 + MITRE override + suggestion filters.
7. **`report_serializer.py`** + **`report_schema.py`** — wire format.
8. **`report_db.py`** — persistence layer.
9. **`web_server.py`** — dashboard + REST + WebSocket.

**Legacy / fallback paths you can skip on first read:**

- `ai_module.py` — legacy per-alert single-shot classifier; superseded by
  `react_agent.py`. Still imported because the single-shot fallback path in the
  ReAct loop reuses some helpers.
- `report_storage.py` — legacy JSON-file backend; superseded by `report_db.py`
  (SQLite). Selectable via `[storage].backend = "json"` in `app.config` for
  comparison runs.

---

## Where to go next

| You want to... | Read |
|---|---|
| See what's done + what's left + branch state | `docs/HANDOFF.md` |
| Understand the agent design decisions | `docs/AGENT_DESIGN.md` |
| Run the evaluation campaign | `docs/PHASE_6_RUNBOOK.md` |
| Understand the SQLite layer | `docs/PHASE_10_SQLITE.md` |
| Deploy or modify the Suricata rules | `lab/suricata/README.md` |
| Set up the lab from a clean machine | top-level `README.md` |
