# Design Document: Incident-Based Triage Architecture

**Status:** Proposed  
**Date:** April 2026  
**Authors:** Technical Implementation team

This document explains the design of the incident-based AI triage architecture that replaces the earlier batch-mode analysis. It covers what changed, why it changed, and how the pieces fit together.

---

## Motivation

The first version of the AI module worked in **batch mode**: a user clicked "Analyse", the system dumped every buffered alert into one report, and the LLM generated a single summary. This worked for a handful of alerts but broke down for realistic SOC scenarios where:

1. Multiple attackers generate alerts simultaneously — a single report conflated them.
2. Alerts from the same attacker arriving over time had no narrative continuity.
3. The user had to manually trigger analysis rather than the system responding to ongoing events.
4. The output schema was a generic batch summary, not an incident report matching industry conventions.

The new architecture groups related alerts into **incidents** and generates a structured **IncidentReport** per incident, updating iteratively as new alerts arrive.

---

## Architecture Overview

```
┌──────────────┐
│  LogMonitor  │  reads eve.json, emits AlertRecord
└──────┬───────┘
       │
       ▼
┌──────────────────┐
│ IncidentManager  │  groups alerts by (source_ip + sliding time window)
│                  │
│  - open/close    │  incidents transition open → closed after time_window_minutes
│  - debounce      │  3-second timer; regenerate when quiet
│  - repeat flag   │  tracks IPs seen earlier in session
└────────┬─────────┘
         │ (when debounce fires)
         ▼
┌──────────────────┐
│ ReportGenerator  │  two-stage LLM pipeline
│                  │
│  Stage 1: per-alert classification (N LLM calls)
│  Stage 2: incident narrative (1 LLM call)
│  + rule-based fields (CVSS, confidence, IOCs)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐     ┌──────────────────┐
│   JSON Storage   │────▶│   WebSocket      │
│  reports/*.json  │     │  push to frontend│
└──────────────────┘     └──────────────────┘
```

Three new components replace what was previously one monolithic `AIAnalyzer.analyse()`:

- **IncidentManager** — pure Python, no LLM. Groups alerts, tracks state, triggers regeneration.
- **ReportGenerator** — orchestrates the two-stage LLM pipeline and rule-based field computation.
- **Storage** — thin wrapper over the `reports/` directory.

---

## Incident Grouping

### Rule

An incident is a collection of Suricata alerts from the **same source IP** that occur within a **sliding time window** of each other.

```
incident = {alerts from src_ip X where each alert is within 
            time_window_minutes of the previous alert}
```

### Grouping Modes

Two grouping modes are supported, selectable via configuration. Both use the same sliding time window; they differ in how strictly they group.

| Mode | One incident = | Notes |
|---|---|---|
| **`per_actor`** (default) | All activity from one source IP within the time window, regardless of attack type | Recommended. Matches template design (multi-attack arrays). |
| `per_attack_type` | One source IP + one attack type within the time window | SQLi and XSS from same IP become two separate incidents. Useful for granular evaluation. |

**Why `per_actor` is the default:**

A real attacker probing a target with multiple techniques (SQLi, then XSS, then directory traversal) constitutes one campaign, not three. A SOC analyst reviewing the incident wants the full picture. The provided report template supports this directly — `detected_attacks` is an array, not a single value. The `attack_vectors` field expects a list too.

**Rejected alternative:** "Per source IP + session" (all activity from one IP across the entire app lifetime, no time window). Rejected because it never closes — an attacker returning hours later would keep extending the same incident indefinitely, defeating the point of incident boundaries.

### How Attack Type Is Extracted

Attack type is needed for:
1. Grouping decisions when running in `per_attack_type` mode
2. The `detected_attacks` field in the final report (both modes)
3. Per-alert `attack_type_classified` in `alert_analyses[]`

Attack type extraction is **rule-based, not LLM-based**, for two reasons: speed (needed during grouping before any LLM call happens), and determinism (the same alert always produces the same attack type).

The classifier reads the Suricata `alert.signature` string:

```python
def extract_attack_type(signature: str) -> str:
    s = signature.upper()
    if "SQL INJECTION" in s or "SQLI" in s:
        return "SQLi"
    if "XSS" in s or "CROSS SITE SCRIPTING" in s:
        return "XSS"
    if "SCAN" in s or "PORT" in s or "RECONNAISSANCE" in s:
        return "Reconnaissance"
    if "DIRECTORY TRAVERSAL" in s or "PATH TRAVERSAL" in s:
        return "PathTraversal"
    if "COMMAND INJECTION" in s or "RCE" in s:
        return "CommandInjection"
    return "Other"
```

The LLM in Stage 2 does not re-classify attack types; it *narrates* the attack based on these labels and the raw alert data. This separation keeps the classification consistent across runs.

### Worked Example

Scenario: attacker `192.168.56.1` generates four alerts over 90 seconds.

```
14:00:00  SQLi alert    - ET WEB_SERVER SELECT USER SQL Injection Attempt in URI
14:00:15  MySQL noise   - ET SCAN Suspicious inbound to mySQL port 3306  (FP)
14:00:30  XSS alert     - ET WEB_SERVER Script tag in URI Possible XSS
14:01:45  SQLi alert    - ET WEB_SERVER SELECT USER SQL Injection Attempt in URI
```

**Under `per_actor` (default):**
- All 4 alerts → 1 incident
- `detected_attacks: ["SQLi", "XSS", "Reconnaissance"]`
- `alert_analyses[]` shows per-alert classification
- Stage 2 narrative connects them: "Attacker combined SQLi with XSS attempts, targeting the DVWA web application. Reconnaissance-style MySQL port traffic was also observed within the same window."

**Under `per_attack_type`:**
- Incident A: 2 SQLi alerts
- Incident B: 1 XSS alert
- Incident C: 1 Reconnaissance alert
- Three parallel incidents, each with its own narrative

The raw data is identical; only the grouping changes.

### Why "sliding window"

A **fixed** window (e.g. incident opens at first alert, closes 10 minutes later) artificially splits ongoing attack campaigns. An attacker who probes for 30 minutes would generate three separate incidents with no semantic reason to split them.

A **sliding** window stays open as long as new alerts arrive within `time_window_minutes` of the most recent alert. Incident closes only after silence.

```
time_window_minutes = 2  (configurable)

Alert at 14:00:00 → opens incident
Alert at 14:01:30 → still open (1m30s since last)
Alert at 14:03:00 → still open (1m30s since last)
No alerts for 2 minutes →
At 14:05:00 → incident closes
Alert at 14:07:00 → opens NEW incident
```

### Configuration

```toml
[incident]
grouping_mode = "per_actor"          # "per_actor" | "per_attack_type"
time_window_minutes = 2.0            # float; supports sub-minute values like 0.5
```

The default `per_actor` treats all attack types from one IP as one incident (recommended, matches template design). The alternative `per_attack_type` splits by type, useful for evaluation discussion.

---

## Report Lifecycle

### States

An incident and its report progress through two states:

- **`open`** — new alerts may still be added. Time window has not yet expired since the most recent alert.
- **`closed`** — time window has expired. Report is final.

### Versioning

A report gets regenerated every time:
1. A new alert is added to an open incident, OR
2. An incident transitions from open to closed (final version).

Each regeneration increments `report_version` (v1, v2, v3...) and updates `last_updated_at` in the single `reports/inc_<id>.json` file. **Historical versions are not retained** — only the latest state is stored. This keeps storage lean; version history was judged unnecessary for the demo.

### Debouncing

Regenerating a report on every single alert is expensive (each regeneration = N+1 LLM calls). To avoid thrashing:

- Every new alert resets a 3-second timer attached to the incident.
- When the timer fires without further alerts, regeneration happens.
- If more alerts arrive during the 3 seconds, the timer resets.

This means reports update near-real-time (within 3-5 seconds of the last alert) but never run more than necessary.

### Automatic vs Manual Regeneration

The entire flow is automated — users do not need to click anything. However, for demo and development purposes, a **Force Regenerate** button (previously labelled "Analyse") is retained. It regenerates the report for all open incidents immediately without waiting for the debounce timer.

---

## Two-Stage LLM Pipeline

### Why Two Stages

A single LLM call processing 10 alerts and generating a structured incident report is unreliable — the model loses track of individual alerts while trying to summarise globally.

Splitting responsibilities is more robust:

**Stage 1 — Per-alert classification**  
One LLM call per alert. Output: true_positive/false_positive, severity, recommendation, reasoning. Uses Ollama's JSON mode for structured output.

**Stage 2 — Incident narrative**  
One LLM call per incident, given the Stage 1 results and aggregated statistics. Output: overview, attack vectors, attack stage, AI suggestions, exposure assessment, impact narrative.

Stage 1 handles the "what is this alert?" question. Stage 2 handles the "what does this campaign mean?" question. Different scopes, different prompts.

### LLM Call Count

For an incident with N alerts:
- Stage 1: N calls
- Stage 2: 1 call
- Total: N + 1 calls

For Llama 3.2 on a typical consumer GPU, each call takes 3-10 seconds. A 10-alert incident takes ~30-60 seconds to fully regenerate. This is documented as a known limitation.

---

## Rule-Based Fields

Certain fields in the report template are unreliable when LLM-generated:

| Field | Why LLM fails | Computed instead by |
|---|---|---|
| `overall_cvss_estimate` | LLMs hallucinate numbers; real CVSS requires deep vulnerability context | Map from severity: High→7.5, Medium→5.0, Low→3.0 |
| `alert_exposures[].cvss_estimate` | Same | Same per-alert severity mapping |
| `confidence_score` | LLMs cannot produce calibrated confidence | Rule-based: high if HTTP payload + MITRE tags present, medium if signature known, low otherwise |
| `data_sensitive_rating` | LLM doesn't know our actual data classifications | Endpoint pattern match: `/vulnerabilities/sqli/`→"confidential", etc |
| `indicators_of_compromise` | Too vague; LLM invents entries | Extract from raw alerts: source IPs, destination URLs, triggered signatures |

**Design principle:** if a field requires numerical calibration or domain knowledge the LLM lacks, compute it deterministically. Everything narrative-driven stays with the LLM.

This is documented as a deliberate design choice, not a limitation of the system. In the evaluation report, the team should explain why rule-based derivation is more honest than LLM-generated guesses for these fields.

---

## Template Compliance

The final IncidentReport schema aligns with the provided Incident Report Template, with intentional additions and removals:

### Added fields (not in template)

- `incident_id` — distinct from `report_id` because one incident can have its report regenerated many times
- `incident_status` — `open` or `closed`, reflects incident lifecycle
- `source_ip` at the incident summary level — since grouping is by attacker IP
- `first_seen`, `last_seen` — explicit time bounds
- `classification_counts` — quick `{true_positive: N, likely_false_positive: N}` summary

### Removed/merged fields

- `attack_types_identified` merged into `detected_attacks` (were duplicates in the template)

### Kept but rule-based

See Rule-Based Fields section above.

---

## Configuration

All tunable parameters live in `app.config`:

```toml
[incident]
grouping_mode = "per_actor"          # "per_actor" | "per_attack_type"
time_window_minutes = 2.0            # incident closes after this many minutes of silence
debounce_seconds = 3                 # wait this long after last alert before regenerating
reports_dir = "reports"              # where incident reports are written

[analysis]
include_lab_context = true           # (existing) include Docker lab details in prompt
summary_mode = "llm"                 # (existing) "llm" | "template"
```

Changing the time window for a demo is as simple as editing `time_window_minutes` and restarting the app.

---

## Storage Layout

```
reports/
├── inc_a3f81.json
├── inc_c2e04.json
├── inc_f7b29.json
└── ...
```

One file per incident. Filename is `inc_<first 5 chars of incident_id>.json`. Overwritten on regeneration. Easy to inspect in a text editor.

The `reports/` directory is gitignored — individual runs produce different data.

---

## Concurrency Model

Three threads coexist:

1. **LogMonitor thread** — tails eve.json, pushes AlertRecords to IncidentManager
2. **Flask main thread** — serves HTTP requests
3. **Debounce timers** — one per open incident, fires the ReportGenerator

IncidentManager's internal dictionary of open incidents is protected by a lock. ReportGenerator itself is stateless; each call operates on an Incident snapshot passed in.

If a new alert arrives for an incident that's currently being regenerated, the incident keeps its data (the alert is appended to the list) but the regeneration currently running will not include it. A fresh debounce timer is set, and the next regeneration picks up the newer alert.

---

## What Stays the Same

- LogMonitor, AlertRecord, Suricata/DVWA/VM setup — unchanged
- ModelProvider abstraction — unchanged
- System prompt for Stage 1 classification — minor tweaks, same structure
- WebSocket dashboard — unchanged for raw alerts, new endpoints added for incidents
- Classification values (`true_positive`, `likely_false_positive`, `Low`/`Medium`/`High`, three recommendations) — unchanged

## What Changes

- `AIAnalyzer` becomes a thin orchestrator wrapping IncidentManager + ReportGenerator
- The old batch `AlertReport` is replaced by per-incident `IncidentReport`
- The "Analyse" button becomes "Force Regenerate" (optional; main flow is automatic)
- Dashboard gains an "Incidents" tab alongside the existing "Alerts" tab
- New `reports/` directory for persisted incident JSON

---

## Implementation Plan

Work is staged so each piece is independently testable:

**Stage A — Data structures and grouping logic**  
Files: `src/models.py`, `src/incident_manager.py`  
No LLM. Writes unit-testable Python. Verify grouping behaviour manually.

**Stage B — Report generation and storage**  
Files: `src/report_generator.py`, `src/storage.py`, updated `src/ai_module.py`  
Two-stage LLM pipeline, rule-based fields, JSON persistence.

**Stage C — Frontend and wiring**  
Files: `src/web_server.py`, `src/templates/index.html`, `src/static/app.js`, `src/static/style.css`, `src/app.py`, `app.config`  
WebSocket events, Incidents tab, config additions.

Each stage is its own git commit.

---

## Open Questions for Later

- **Persistence across restarts.** Currently repeat-offender tracking is in-memory. Could load incidents from `reports/` on startup to restore state.
- **Evaluation framework.** Ground truth logging, precision/recall calculations — separate work, Phase 4.
- **Frontend incident drill-down.** Clicking an incident card could show the full report in a modal. Nice-to-have.

---

## Summary

The incident-based architecture turns a simple batch analyser into a stateful system that mirrors real SOC workflows. Alerts are grouped by attacker, reports update iteratively as campaigns unfold, and the output schema follows industry conventions. The two-stage LLM pipeline keeps each call focused on one task, and rule-based fields handle what LLMs can't do reliably.

The net result is a demonstrable system: an attacker hits the DVWA, alerts flow through Suricata, the AI groups them into a coherent incident, and a structured report appears on the dashboard within seconds — matching what a real SOC product would do.
