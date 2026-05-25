# Agentic ReAct Triage Loop — Design Specification

**Status:** Implemented. Phases 1-5 plus 5.5 (hybrid auto-enrichment), 3.5 (template serializer), 10 (SQLite persistence) all landed. Active branch: `feature/sqlite-persistence`.
**Author context:** Capstone project p000774csitcp (RMIT).
**Scope:** Design rationale for the agentic Stage 1 (ReAct loop + 3 tools). Stage 2 still makes one LLM call per incident but gained deterministic post-processing (MITRE override + 3-layer suggestion filter).

> **This doc is the design rationale, not a status tracker.** For current implementation status, branches, what's done, what's left, read `docs/HANDOFF.md`. For a hand-drawn workflow diagram with explanations, read `docs/ARCHITECTURE.md`. Several decisions made during implementation supplement or override what is described below — they are summarised in section 16 ("Design changes during implementation") at the bottom of this doc.

---

## 1. Purpose

The capstone specification mandates a *"Python-based **agentic** AI module"* for the AI Triage Module (Single Agent). The current implementation uses a two-stage stateless LLM pipeline:

- **Stage 1**: per-alert classification — one `complete_json` call per alert.
- **Stage 2**: incident-level narrative — one `complete_json` call per incident.

This pipeline is structured but not genuinely agentic — the LLM does not autonomously decide what information to gather, nor does it use tools. A sharp grader applying a strict definition of "agentic" can challenge this.

This design replaces Stage 1 with a **ReAct (Reasoning + Acting) loop** in which the LLM:

1. Observes an alert,
2. Decides whether it needs additional context,
3. Optionally calls one or more tools to gather context,
4. Repeats until it has enough information,
5. Emits a final classification.

The two-stage architecture is preserved — Stage 2 stays unchanged. Only Stage 1 becomes a tool-using agent.

This satisfies the capstone spec's agentic requirement while keeping the system within "Single Agent" scope (one agent with internal reasoning + tool use, not a multi-agent orchestration).

---

## 2. Capstone specification compliance

| Spec requirement | How this design satisfies it |
|---|---|
| *"agentic AI module"* | ReAct loop with tool use; LLM autonomously chooses when to call tools |
| *"Single Agent"* | One agent (`ReActAgent`) with internal reasoning. Not multiple coordinating agents |
| *"classifies them (true positive vs likely false positive)"* | Final answer field `classification` retains binary label |
| *"assigns severity levels (Low/Medium/High)"* | Final answer field `severity` |
| *"generates structured incident summaries"* | Stage 2 unchanged — still produces `IncidentSummaryDescription` |
| *"provides basic SOC response recommendations such as block source IP, escalate to Tier-2, or continue monitoring"* | Final answer field `recommendation` retains the same enum |
| *"Evaluate the AI module by comparing its classifications against manual ground truth and analysing accuracy and consistency"* | Evaluation harness extended with 2×2×2 ablation matrix (model × agent_mode × lab_context) |

---

## 3. Architecture

### 3.1 Where the agent lives in the existing pipeline

```
┌──────────────────────────────────────────────────────────────────────┐
│                        ReportGenerator.generate()                    │
│                                                                      │
│   ┌────────────────────────────┐    ┌───────────────────────────┐    │
│   │  Stage 1: classify alerts  │    │  Stage 2: narrative       │    │
│   │  ┌──────────────────────┐  │    │  ┌──────────────────────┐ │    │
│   │  │  for each alert:     │  │    │  │  one LLM call,       │ │    │
│   │  │    [NEW] ReActAgent  │  │───▶│  │  unchanged           │ │    │
│   │  │       .classify()    │  │    │  │                      │ │    │
│   │  └──────────────────────┘  │    │  └──────────────────────┘ │    │
│   └────────────────────────────┘    └───────────────────────────┘    │
│                                                                      │
│   ┌────────────────────────────────────────────────────────────┐     │
│   │  Rule-based enrichment (CVSS, IoCs, confidence) unchanged  │     │
│   └────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────┘
```

`ReActAgent` is plugged in at `ReportGenerator._classify_single` (the per-alert classification function). Public interfaces — `ReportGenerator.generate(incident)`, `AlertClassification`, the regenerate callback — remain unchanged.

### 3.2 The ReAct loop

```
                          ┌──────────────────────────┐
                          │   ReActAgent.classify    │
                          │   (alert: AlertRecord)   │
                          └────────────┬─────────────┘
                                       │
                                       ▼
              ┌──────────────────────────────────────────────┐
              │ Build initial prompt: system + alert payload │
              └──────────────────────────────────────────────┘
                                       │
                                       ▼
                          ┌──────────────────────────┐
                ┌────────▶│   LLM call (round N)     │
                │         └────────────┬─────────────┘
                │                      │
                │                      ▼
                │         ┌──────────────────────────┐
                │         │  Parse model output      │
                │         │  (XML tags)              │
                │         └────────────┬─────────────┘
                │                      │
                │       ┌──────────────┼──────────────┐
                │       │              │              │
                │       ▼              ▼              ▼
                │  ┌────────┐   ┌──────────┐   ┌──────────┐
                │  │ final  │   │  action  │   │  parse   │
                │  │ answer │   │  +input  │   │  fail    │
                │  └───┬────┘   └────┬─────┘   └────┬─────┘
                │      │             │              │
                │      ▼             ▼              ▼
                │  return       ┌──────────┐   retry once,
                │  result       │ execute  │   else fallback
                │               │  tool    │   to single-shot
                │               └────┬─────┘
                │                    │
                │                    ▼
                │           ┌──────────────────┐
                │           │ append           │
                │           │ <observation>    │
                │           │ to prompt        │
                │           └────────┬─────────┘
                │                    │
                │       ┌────────────┴────────────┐
                │       │  iteration cap reached? │
                │       └────────────┬────────────┘
                │                    │
                │              ┌─────┴──────┐
                │              │ no    yes  │
                └──────────────┘            └────────────────┐
                                                             ▼
                                              ┌─────────────────────────┐
                                              │ Force final answer via  │
                                              │ single-shot prompt with │
                                              │ accumulated context     │
                                              └─────────────────────────┘
```

### 3.3 Module structure

```
src/
├── react_agent.py        # ReActAgent class, ReasoningStep, XML parser
├── tool_registry.py      # ToolDefinition, ToolRegistry, ToolResult
└── agent_tools.py        # 3 tool factory functions + their implementations
```

Three new files. No existing files moved or renamed. Existing files modified:

- `src/models.py` — add `ReasoningStep` dataclass; add `reasoning_trace: Optional[List[ReasoningStep]]` to `AlertClassification`.
- `src/report_generator.py` — `_classify_single` delegates to `ReActAgent.classify()` when `agent_mode == "react"`.
- `src/app.py` — wire `ToolRegistry` + `ReActAgent` into `ReportGenerator` at startup.
- `app.config` — new `[agent]` section.

---

## 4. Data model changes

### 4.1 New: `ReasoningStep`

```python
@dataclass
class ReasoningStep:
    """One iteration of the ReAct loop.

    Captured for dashboard display and post-hoc evaluation.
    """
    iteration: int                       # 0-indexed
    thought: str                         # model's stated reasoning
    action: Optional[str]                # tool name, or None on final answer
    action_input: Optional[Dict]         # tool arguments, parsed JSON
    observation: Optional[str]           # tool output, serialized JSON; None on final
    duration_ms: int                     # wall-clock for LLM call + tool execution
    parse_error: Optional[str] = None    # set if this step's raw output failed to parse
```

### 4.2 Added: `AlertClassification.reasoning_trace`

```python
@dataclass
class AlertClassification:
    # ... existing fields ...
    reasoning_trace: Optional[List[ReasoningStep]] = None
    agent_mode: str = "single_shot"      # "react" | "single_shot"
    parse_failure_count: int = 0         # how many model outputs failed to parse
    tool_calls: int = 0                  # how many tools were invoked
```

All four fields are **optional** with safe defaults — existing single-shot path produces `reasoning_trace=None`, `agent_mode="single_shot"`, `parse_failure_count=0`, `tool_calls=0`. All 38 existing tests continue to pass without modification.

### 4.3 Schemas: `ToolDefinition`, `ToolResult`

```python
@dataclass
class ToolDefinition:
    name: str                            # e.g. "get_alert_history"
    description: str                     # for model prompt
    parameters_schema: Dict              # JSONSchema for argument validation
    function: Callable[[Dict], Any]      # actual implementation, takes args dict

@dataclass
class ToolResult:
    tool_name: str
    arguments: Dict
    output: Any                          # JSON-serializable; serialized for observation
    error: Optional[str] = None
    duration_ms: int = 0
```

---

## 5. Tool catalog

Three tools. All read-only, in-process, synchronous. No external API
calls. Total per-call latency target: <100 ms.

> **Source-of-truth note.** Tool descriptions, JSON Schemas, and return
> shapes below capture the design intent. The exact strings used at
> runtime live in `src/agent_tools.py` (`_ALERT_HISTORY_DESCRIPTION`,
> `_ENV_LOOKUP_SCHEMA`, etc.) and may have been slightly reworded as
> the prompts were tuned. When in doubt, the code is canonical.

### 5.1 `get_alert_history`

**Purpose:** Detect repeat offenders. Maps directly to the spec's `block_source_ip` recommendation logic.

**Signature:**
```json
{
  "name": "get_alert_history",
  "description": "Look up prior alerts from a specific source IP within a time window. Use this when you need to determine if the source IP is a repeat offender. Returns counts and attack types seen.",
  "parameters": {
    "type": "object",
    "properties": {
      "src_ip": {
        "type": "string",
        "description": "The source IP address to look up (e.g. '192.168.56.1')"
      },
      "hours": {
        "type": "integer",
        "description": "How many hours back to search. Default 24, maximum 168 (1 week).",
        "default": 24,
        "minimum": 1,
        "maximum": 168
      }
    },
    "required": ["src_ip"]
  }
}
```

**Data sources:**
- `IncidentManager._open_incidents` — current open incidents this session.
- `IncidentManager._recently_closed` — closed in this session, still in memory.
- The active storage backend's `list_reports()` — `ReportDatabase` (SQLite,
  default since Phase 10) or `ReportStorage` (legacy JSON files) — for
  persisted reports from prior sessions.

**Return shape:**
```json
{
  "src_ip": "192.168.56.1",
  "lookback_hours": 24,
  "total_prior_alerts": 12,
  "attack_types_seen": ["SQLi", "XSS"],
  "first_seen_iso": "2026-05-14T10:00:00+00:00",
  "last_seen_iso": "2026-05-14T10:04:30+00:00",
  "prior_incident_count": 2,
  "is_repeat_offender_this_session": true
}
```

If no prior alerts found: returns `{"src_ip": "...", "total_prior_alerts": 0, ...}` with empty/zero fields. Never raises.

### 5.2 `lookup_environment_context`

**Purpose:** Replace the hardcoded `include_lab_context` prompt-injection block with a queryable lookup. Agent asks for context only when uncertain about an IP or URL.

**Signature:**
```json
{
  "name": "lookup_environment_context",
  "description": "Look up known facts about an IP address or URL in the lab environment. Use this when the alert involves an IP or URL you are uncertain about, to determine if it is expected internal infrastructure.",
  "parameters": {
    "type": "object",
    "properties": {
      "query": {
        "type": "string",
        "description": "The IP, CIDR, hostname, or URL path to look up"
      }
    },
    "required": ["query"]
  }
}
```

**Data source:** New `[agent.environment]` section in `app.config`:

```toml
[agent.environment]
# Each entry: pattern (string or CIDR) -> classification + description
[[agent.environment.entries]]
pattern = "172.18.0.2"
match_type = "exact_ip"
role = "internal_database"
description = "MariaDB server inside Docker bridge network. Traffic to/from this IP on port 3306 is expected internal database communication."
classification_hint = "likely_false_positive_if_internal_only"

[[agent.environment.entries]]
pattern = "172.18.0.0/16"
match_type = "cidr"
role = "docker_bridge"
description = "Docker bridge subnet. Internal lab infrastructure."
classification_hint = "context_only"

[[agent.environment.entries]]
pattern = "192.168.56.0/24"
match_type = "cidr"
role = "host_only_network"
description = "VirtualBox host-only network. Attacker traffic originates here."
classification_hint = "untrusted_source_likely_attacker"
```

**Return shape (hit):**
```json
{
  "query": "172.18.0.2",
  "match_found": true,
  "matched_pattern": "172.18.0.2",
  "role": "internal_database",
  "description": "MariaDB server inside Docker bridge network...",
  "classification_hint": "likely_false_positive_if_internal_only"
}
```

**Return shape (miss):**
```json
{
  "query": "8.8.8.8",
  "match_found": false
}
```

Migration note (kept for history): the original Stage 1 single-shot path
injected a hardcoded `include_lab_context` block into the prompt. The
structured environment map ran in parallel during ReAct mode while both
paths coexisted. ReAct + auto-enrichment is now the default, so the
hardcoded block is no longer a primary code path.

### 5.3 `get_attack_pattern_stats`

**Purpose:** Calibrate severity. "47 SQLi attempts in last hour" indicates active campaign — bump severity to High even if individual alert is ambiguous.

**Signature:**
```json
{
  "name": "get_attack_pattern_stats",
  "description": "Get aggregate statistics for a specific attack type over a time window. Use this when you want to know if an attack type is currently active in the environment, to help calibrate severity.",
  "parameters": {
    "type": "object",
    "properties": {
      "attack_type": {
        "type": "string",
        "description": "Attack type to look up. Valid values: SQLi, XSS, CommandInjection, PathTraversal, CSRF, FileInclusion, BruteForce, Reconnaissance, WebAttack",
        "enum": ["SQLi", "XSS", "CommandInjection", "PathTraversal", "CSRF", "FileInclusion", "BruteForce", "Reconnaissance", "WebAttack"]
      },
      "hours": {
        "type": "integer",
        "description": "Lookback window in hours. Default 24.",
        "default": 24,
        "minimum": 1,
        "maximum": 168
      }
    },
    "required": ["attack_type"]
  }
}
```

**Data source:** Aggregate over `IncidentManager._open_incidents`,
`_recently_closed`, and the active storage backend's `list_reports()`
(`ReportDatabase` by default, `ReportStorage` when running the legacy
JSON backend).

**Return shape:**
```json
{
  "attack_type": "SQLi",
  "lookback_hours": 24,
  "total_alerts": 47,
  "unique_source_ips": 3,
  "incident_count": 5,
  "observed_true_positive_rate": 0.85,
  "most_recent_alert_iso": "2026-05-14T10:04:30+00:00"
}
```

`observed_true_positive_rate` is derived from past report classifications — useful signal but is itself a product of past LLM outputs (documented circularity, noted in limitations).

---

## 6. ReAct loop specification

### 6.1 XML format

Model output is parsed using XML-style tags. Chosen over Markdown headers or native function calling for:

- Format reliability on 3B models (XML tags parse with strict regex; Markdown header levels drift; native function calling is patchy on Ollama with small models)
- Provider portability — no dependency on Ollama, Anthropic, or OpenAI tool-use APIs
- Debuggability — failed parses leave readable text in logs

**Per-iteration model output (tool call):**
```
<thought>SQLi pattern in URL. Need to check if this source IP has hit us before.</thought>
<action>get_alert_history</action>
<action_input>{"src_ip": "192.168.56.1", "hours": 24}</action_input>
```

**Per-iteration agent response (injected by agent, not generated by model):**
```
<observation>{"src_ip": "192.168.56.1", "total_prior_alerts": 12, "attack_types_seen": ["SQLi"], "is_repeat_offender_this_session": true}</observation>
```

**Final answer:**
```
<thought>12 prior SQLi alerts from same IP — active attack campaign. High severity warranted, block the IP.</thought>
<final_answer>
{
  "classification": "true_positive",
  "severity": "High",
  "summary": "Active SQLi campaign from repeat offender 192.168.56.1",
  "recommendation": "block_source_ip",
  "reasoning": "12 prior SQLi alerts from same source IP in past 24h indicates sustained attack. Block the source IP to interrupt the campaign."
}
</final_answer>
```

### 6.2 Parser rules

1. Strip whitespace.
2. Find `<final_answer>...</final_answer>` first. If present:
   - Parse contents as JSON.
   - Validate against existing Stage 1 schema (`_validate_stage1_response`).
   - Return result.
3. Otherwise find `<action>...</action>` and `<action_input>...</action_input>`:
   - Action must match a registered tool name.
   - Action input must parse as JSON and validate against tool's parameter schema.
   - Execute tool. Inject observation. Loop.
4. If neither `<final_answer>` nor `<action>` found, OR tags malformed: parse failure.

Regex pattern (Python, `re.DOTALL`):
```python
_TAG_PATTERN = re.compile(
    r"<(?P<tag>thought|action|action_input|final_answer)>"
    r"(?P<content>.*?)"
    r"</(?P=tag)>",
    re.DOTALL,
)
```

### 6.3 Iteration rules

- **Max iterations:** 3 (configurable via `app.config`).
- **Per-tool timeout:** 5 seconds (tools should complete in <100ms; timeout catches deadlocks).
- **Total budget:** 30 seconds wall-clock per alert classification.
- **On iteration cap:** force a final answer via a single-shot prompt that includes all accumulated `<observation>` contents. The model is told it must finalize now.
- **On total budget exceeded:** return a degraded `AlertClassification` with `status="partial"`, `parse_failure_count` recording any parse issues, and a fallback severity of `Medium` + recommendation of `escalate_tier2`. This is a defensive default — escalate to a human rather than guess.

### 6.4 Fallback ladder

```
1. Try ReAct loop with retries on parse failure       (primary path)
2. If parse fails after 1 retry → try single-shot     (no tools, same model)
3. If single-shot also fails → return error AlertClassification
                                with status="error"   (matches current behavior)
```

Each fallback step records its triggering condition in `reasoning_trace[].parse_error` for evaluation transparency.

### 6.5 System prompt

System prompt has four parts, concatenated:

1. **Role + task** — same as current Stage 1 base prompt.
2. **Available tools** — auto-generated from `ToolRegistry`, includes name, description, parameter schema for each.
3. **Output format spec** — describes the XML tags and final answer JSON shape.
4. **Few-shot examples** — three worked examples (see 6.6).

Stage 1 system prompt prompt-injection defense block is retained in part 1.

### 6.6 Few-shot examples

The system prompt ships a small number of worked examples covering the
three common paths through the loop:

1. Obvious attack, no tools needed: clear SQLi URL pattern, straight to
   `<final_answer>`.
2. Ambiguous alert, one tool needed: alert from an unknown IP, look up
   environment context, then `<final_answer>`.
3. Sustained activity, more than one tool needed: check history and
   pattern stats, raise severity, then `<final_answer>`.

The exact wording of each example has been tuned during prompt iteration
(qwen 3B is sensitive to format drift). See `_SYSTEM_PROMPT` in
`src/react_agent.py` for the verbatim text used at runtime — that file is
the source of truth and embedding the prompt here would rot the moment
the next prompt tweak lands.

### 6.7 Tool over-use prevention

The system prompt explicitly instructs:

> Only call a tool when the alert is genuinely ambiguous. For obviously malicious payloads (clear SQL injection, script tags, command injection), output `<final_answer>` immediately without calling tools. Tool calls cost time and should be reserved for cases where additional context changes your verdict.

Average tool calls per alert will be tracked as an evaluation metric. Target: <1.5 average. If higher in testing, the system prompt is retuned.

---

## 7. Provider integration

`ReActAgent` consumes a `ModelProvider`. It uses `complete()` (not `complete_json()`) because output is XML-tagged text, not JSON.

```python
class ReActAgent:
    def __init__(
        self,
        provider: ModelProvider,
        tools: ToolRegistry,
        max_iterations: int = 3,
        tool_timeout_seconds: float = 5.0,
        total_budget_seconds: float = 30.0,
    ): ...

    def classify(self, alert: AlertRecord) -> AlertClassification:
        """Run the ReAct loop. Always returns an AlertClassification —
        never raises on expected failures. Falls back to single-shot
        if the loop misbehaves."""
```

The agent is provider-agnostic. Ollama (qwen2.5:3b, llama3.2:3b) and Anthropic (if added later) both work via the same `complete()` interface.

---

## 8. Configuration schema

Additions to `app.config` (current state, as committed):

```toml
[agent]
# "react" enables the tool-using ReAct loop. "single_shot" uses the
# original Stage 1 path (preserved for evaluation ablation).
mode                    = "react"

# Max ReAct iterations before forcing a final answer.
max_iterations          = 3

# Per-tool execution timeout (seconds). Tools should finish in <100ms;
# this catches deadlocks.
tool_timeout_seconds    = 5.0

# Wall-clock budget for a single alert classification (all LLM calls
# + all tool calls combined).
total_budget_seconds    = 30.0

# Capture reasoning trace on each classification. Surfaced in the
# dashboard and persisted in the report for evaluation transparency.
reasoning_trace_enabled = true

# Hybrid auto-enrichment (Phase 5.5, "Option F"). When true, the agent
# deterministically runs all three tools BEFORE the LLM ever sees the
# alert, seeding the reasoning_trace with the results. The LLM can then
# still emit additional tool calls if it wants. Set to false for the
# pure-LLM-driven tool-use ablation in evaluation runs.
auto_enrichment         = true

# Tool registration. Disabling a tool removes it from the prompt and
# from the registry — useful for ablation studies.
[agent.tools]
get_alert_history             = true
lookup_environment_context    = true
get_attack_pattern_stats      = true

# Environment-context entries used by lookup_environment_context.
# Each entry: pattern + match_type (exact_ip | cidr | url_prefix |
# url_contains) + optional role / description / classification_hint.

[[agent.environment.entries]]
pattern              = "172.18.0.2"
match_type           = "exact_ip"
role                 = "internal_database"
description          = "EXPECTED INTERNAL — MariaDB inside Docker bridge. Traffic between DVWA and this IP on port 3306 is benign internal database communication."
classification_hint  = "likely_false_positive_if_internal_only"

[[agent.environment.entries]]
pattern              = "172.18.0.0/16"
match_type           = "cidr"
role                 = "docker_bridge"
description          = "EXPECTED INTERNAL — Docker bridge subnet hosting DVWA + MariaDB. Lab infrastructure, not an attacker."
classification_hint  = "context_only"

[[agent.environment.entries]]
pattern              = "192.168.56.0/24"
match_type           = "cidr"
role                 = "host_only_network"
description          = "UNTRUSTED EXTERNAL — VirtualBox host-only network where the attacker simulator runs. Treat all traffic from this range as adversarial unless explicitly proven benign."
classification_hint  = "untrusted_source_likely_attacker"

[[agent.environment.entries]]
pattern              = "/vulnerabilities/sqli"
match_type           = "url_prefix"
role                 = "vulnerable_endpoint"
description          = "EXPECTED ATTACK TARGET — DVWA SQLi training endpoint."
classification_hint  = "expected_attack_target"

[[agent.environment.entries]]
pattern              = "/vulnerabilities/xss"
match_type           = "url_prefix"
role                 = "vulnerable_endpoint"
description          = "EXPECTED ATTACK TARGET — DVWA XSS training endpoint."
classification_hint  = "expected_attack_target"

# Storage backend (Phase 10). "sqlite" is the default; "json" is the
# legacy file-per-incident backend, preserved for backwards-compat and
# evaluation comparison runs.
[storage]
backend                  = "sqlite"
db_path                  = "data/reports.db"
retention_days           = 90                  # 0 = never expire
cleanup_interval_seconds = 3600                # 0 = no auto cleanup
```

Match types supported: `exact_ip`, `cidr`, `url_prefix`, `url_contains`. Each implemented in `agent_tools.py`.

---

## 9. ReportGenerator integration

The agent is plugged into `ReportGenerator` via two optional constructor
kwargs (`react_agent`, `agent_mode`). When `agent_mode == "react"` the
per-alert classifier delegates to `react_agent.classify(alert)`; otherwise
it falls through to the original single-shot path. Existing callers that
do not pass the new kwargs keep getting single-shot behaviour, so all
prior tests stayed green during the migration.

The `app.py` startup is where the wiring happens: read the `[agent]`
section of `app.config`, build a `ToolRegistry`, register each enabled
tool via its factory in `agent_tools.py` (passing the live
`incident_manager` and `storage` so the tools can query real state),
construct a `ReActAgent` with the provider + registry + timeouts, and
hand it into `ReportGenerator`.

The exact constructor signatures and the wire-up flow have been refined
through normal refactoring. See:

- `src/report_generator.py` — `ReportGenerator.__init__` and
  `_classify_single` for the delegation logic.
- `src/app.py` — startup wiring: tool registration, ReActAgent
  construction, ReportGenerator instantiation, storage backend selection
  (`ReportDatabase` for SQLite, `ReportStorage` for JSON).
- `src/tool_registry.py` — `ToolRegistry.register()` semantics.

Trying to keep a verbatim copy of the constructor signature in this doc
would rot every refactor; the source files above are canonical.

---

## 10. Backwards compatibility

| Surface | Behavior |
|---|---|
| `ReportGenerator.generate(incident)` signature | Unchanged |
| `ReportGenerator.__init__` signature | New optional kwargs only; existing callers continue to work |
| `AlertClassification` shape | New optional fields with safe defaults |
| `IncidentReport` shape | Unchanged (Stage 2 untouched) |
| `/api/incidents` HTTP endpoint | Unchanged |
| `app.config` schema | New `[agent]` section is additive |
| Existing 38 unit tests | All pass without modification (verified before merge) |
| Evaluation harness `/api/incidents` consumer | Unchanged |

When `agent_mode = "single_shot"`, the system behaves identically to the current implementation. This is verified by re-running the existing evaluation suite as part of the new 2×2×2 matrix.

---

## 11. Dashboard reasoning trace

The original Phase 5 plan had a small ASCII mockup of the incident card with
just the reasoning trace shown inline. Reality is a lot richer because Stage 2,
the serializer, the suggestion filters, and the reasoning trace all landed
together. What the dashboard actually renders for each incident card:

- **Header line**: incident ID, status (`open` / `closed`), source IP,
  repeat-offender badge (when applicable), alert count, overall severity,
  overall CVSS, time-ago, report version (`v1`, `v2`, ...), detected attack
  types (e.g. `SQLi`, `XSS`).
- **Overview**: the Stage 2 narrative in plain English.
- **Summary block**: MITRE attack stage, vectors, true-positive / false-positive
  counts, first-seen and last-seen timestamps, data sensitivity.
- **AI Suggestions**: the merged rule-based + LLM-filtered suggestion list.
- **Information Exposure**: exposure, impact, exposed data types, affected
  systems.
- **Alert Analyses (N)**: one block per alert in the incident. Shows the
  `attack_type` (e.g. `SQLi`), the LLM-picked subtype (e.g. `UNION-based SQL
  injection`), the per-alert summary, and the confidence score.
- **Agent Reasoning** (per analysis): expandable trace of every step the ReAct
  loop took. Each step renders the iteration number, the tool name + JSON input
  + JSON output (for action steps), the model's `<thought>` when present, and
  a `final answer ✓` marker. Auto-enrichment steps (Phase 1 of Option F) are
  tagged with an `A` badge and an `Auto-enrichment:` label so a reader can tell
  what the runtime did automatically versus what the LLM itself chose to do.
- **Indicators of Compromise**: source IPs, signatures (e.g.
  `P1 - SQLi UNION SELECT in URI`), URLs.
- **Footer**: model name, provider type, report ID.

The whole card is collapsible via a "Hide details" / "Show details" toggle.

**Implementation**: `src/static/app.js` renders the card from the template-v1
JSON the dashboard receives via WebSocket (`report_ready` event) or via REST
(`GET /api/incidents/<id>`). The reasoning trace renders when
`AlertClassification.reasoning_trace` is non-empty; it stays hidden if
`reasoning_trace_enabled = false` in `app.config` or if the trace is null.
Styles in `src/static/style.css`.

**Live streaming** of partial reasoning (showing tool calls as they happen
rather than only after the report finishes) was a stretch goal in the original
plan and was never implemented. The trace renders statically once the report
is saved.

---

## 12. Evaluation strategy

### 12.1 2×2×2 ablation matrix

| Dimension | Values |
|---|---|
| `model` | `llama3.2:3b`, `qwen2.5:3b` |
| `agent_mode` | `react`, `single_shot` |
| `lab_context` (or `lookup_environment_context` tool in ReAct mode) | enabled, disabled |

8 configs × 3 repetitions = 24 evaluation runs. Estimated 1.5–2 hours total on Windows dev machine.

### 12.2 Metrics

Existing metrics retained: precision, recall, F1, accuracy, confusion matrix.

New metrics (ReAct-specific):

| Metric | Definition |
|---|---|
| Tool call rate | Average tools invoked per alert |
| Tool usage distribution | Histogram per tool name |
| Parse failure rate | Fraction of model outputs that failed XML parsing |
| Fallback rate | Fraction of classifications that fell back to single-shot |
| Latency p50, p95 | Wall-clock per classification |
| Severity consistency | Stddev of severity rank across the 3 repetitions for the same scenario |

### 12.3 Per-configuration outputs

Each run produces:
- `eval_results/<label>_<config>_<timestamp>_results.json` (raw classifications)
- `eval_results/<label>_<config>_<timestamp>_report.md` (markdown summary)

A new combined report at `eval_results/<label>_combined_<timestamp>_report.md` cross-tabulates metrics across configs for the final capstone report.

---

## 13. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Small models (3B) generate malformed XML | Medium | High | Strict regex parser, retry-once with corrective prompt, fallback to single-shot, track parse failure rate as eval metric |
| Agent over-uses tools (calls tools on every alert) | Medium | Medium | Explicit "only when needed" instruction + few-shot example showing direct classification path, measure tool call rate, retune prompt if >1.5 |
| Latency creep hurts demo feel | Medium | Medium | 30s hard budget; dashboard shows "processing..." state; static reasoning trace UI hides single-call delays |
| Existing tests break | Low | High | All new fields nullable with safe defaults; new code in new files; CI runs full test suite on each commit |
| Evaluation numbers regress vs baseline | Low | Medium | Single-shot mode preserved; ReAct framed as additive option, not replacement |
| Mac demo Mac VM setup fails | Medium | High | Phase 8 scheduled before Phase 9 dry-run; teammate Macs as fallback hardware |
| 3B model can't handle ReAct format on Ollama | Medium | High | Test qwen2.5:3b first (Apache 2.0, trained for tool use); fallback config can pin llama3.2:3b in single_shot mode for the demo |
| Scope creep into SQLite migration mid-implementation | High | Medium | Hard scope list in §2; SQLite is explicitly Phase 10 on a separate branch |

---

## 14. Implementation phases

Original plan was 1-10 with day estimates. Current status below. Two
extra phases (3.5 and 5.5) were inserted during implementation when new
needs surfaced.

| Phase | Deliverable | Status |
|---|---|---|
| **1. Foundation** | This design doc + branch + qwen2.5:3b verified | Done |
| **2. Tools** | Tool registry + 3 tool implementations + unit tests | Done |
| **3. ReAct loop** | ReActAgent class + XML parser + iteration logic + tests | Done |
| **3.5. Serializer** *(inserted)* | Template-v1 JSON serializer + JSONSchema validation | Done |
| **4. Integration** | ReportGenerator delegation + end-to-end smoke test | Done |
| **5. Dashboard** | Reasoning trace UI in incident card | Done |
| **5.5. Hybrid enrichment** *(inserted)* | Option F deterministic pre-LLM tool calls | Done |
| **6. Evaluation** | 5-config staircase ablation (revised from 2×2×2) | In progress (operator runs) |
| **7. Docs** | README, HANDOFF, ARCHITECTURE, runbooks | Done |
| **8. Mac port** | UTM + Kali setup runbook for Apple Silicon | Pending |
| **9. Demo dry-run** | End-to-end on Mac, demo runbook | Pending |
| **10. SQLite (separate branch)** | Persistence migration; later merged into the main feature branch | Done (`feature/sqlite-persistence`) |

For the live status (which branch has what, which tests pass, what's
queued next), see `docs/HANDOFF.md`. Phase 6's "2×2×2 matrix" was
replaced with a 5-config staircase ablation; the rationale and runbook
live in `docs/PHASE_6_RUNBOOK.md`.

---

## 15. Locked decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | XML-tagged ReAct format (not native function calling) | Provider-portable, parses reliably on 3B models |
| 2 | 3 tools (alert_history, env_context, pattern_stats) | Each maps to a real Tier-1 SOC question, all read existing state |
| 3 | Max 3 iterations | Bounds latency; one tool call per iteration suffices |
| 4 | Default model: qwen2.5:3b | Better tool use than llama3.2:3b at same size class |
| 5 | Baseline preserved: llama3.2:3b | Existing eval numbers stay comparable |
| 6 | Single-shot mode kept under config flag | Enables ablation; demo fallback if ReAct misbehaves |
| 7 | 1 Kali VM colocated (not 2 VMs) | Spec drift documented as deliberate simplification |
| 8 | Mac demo: UTM + Kali mirror | Path of least resistance; matches Windows architecture |
| 9 | Evaluation host: Windows dev PC | Faster; accuracy metrics are hardware-portable |
| 10 | Reasoning trace UI: static render only | Live streaming is stretch; static suffices for spec + demo |
| 11 | SQLite migration: separate branch after this is merged | No scope creep mid-implementation |

The decisions below were not in the original draft. They were made during
implementation when new evidence or requirements surfaced.

| # | Decision | Rationale |
|---|---|---|
| 12 | Suricata runs custom-only (ET Open + built-in protocol-event rules disabled in the lab) | Keeps the alert feed scoped to the two attack classes the project demonstrates; every alert traceable to a team-written rule; removes ET double-alerting + ET SCAN noise. See `lab/suricata/README.md` |
| 13 | `attack_type` resolved deterministically from custom SID range when available (SQLi: 1000101-1000113, XSS: 1000001-1000058) | qwen 3B sometimes hedged `attack_type` to "Other / unclassified" on broad-tier alerts while its own rationale clearly named SQLi. SID-range path is correctness-first; string fallback covers ET Open or unknown SIDs |
| 14 | MITRE tactic override scans signature **and** URL for credential keywords, and preserves the LLM's tactic when already valid | Original override forced SQLi -> Initial Access whenever the signature msg lacked USER/PASS. Custom rule msgs are generic, so credential intent lives in the URL. Override now bumps to Credential Access on URL evidence; if the LLM already picked a valid tactic, no override fires |
| 15 | Alert severity scale = critical / high / low. No "medium" tier | Aligns with custom rules' P1/P2/P3 priority tiers. Suricata severity 3+ maps to "low"; the dashboard Medium card and filter button were removed |
| 16 | SQLite is the default storage backend; JSON file backend stays selectable | Phase 10. WAL mode, thread-local connections, hybrid schema (indexed columns + full template JSON blob). Enables cross-run history queries and retention sweep. Switchable via `[storage].backend = "json"` for ablation runs |
| 17 | Hybrid auto-enrichment (Option F) is the default agent behaviour | qwen 3B's tool-call adherence drifts when classifying from msg alone. Phase 1 of Option F runs the 3 tools deterministically before the LLM ever sees the alert; Phase 2 (the LLM loop) can still emit further tool calls. Pure LLM-driven tool use stays available via `auto_enrichment = false` for the ablation row |
| 18 | Suricata SQLi rule pcres use `[\s+]` (not `\s`) for inter-keyword spacing | DVWA's GET form encodes spaces as `+`; Suricata's `http.uri` buffer decodes `%XX` but leaves `+` as `+`. With bare `\s`, the P1 UNION SELECT rule never fired on the canonical payload, capping severity at high. `[\s+]` matches space, decoded `%20`, and `+` |

---

## 16. Design changes during implementation

The body of this doc still describes the original design. Where the
implementation diverged, the divergence is captured in section 15 above
(decisions 12 onwards) and explained in detail in:

- `docs/HANDOFF.md` — written context for everything that has happened
- `docs/ARCHITECTURE.md` — hand-drawn diagram + walkthrough of the
  current data flow
- `docs/PHASE_6_RUNBOOK.md` — current evaluation strategy (5-config
  staircase, supersedes the 2×2×2 matrix described in section 12)
- `docs/PHASE_10_SQLITE.md` — SQLite layer design
- `lab/suricata/README.md` — custom-only ruleset deploy + validation

When reading the rest of this doc, treat sections 1-13 as the original
design intent. They are accurate at the level of "why we built it this
way" but a few specific numbers (test counts, exact eval matrix shape,
default `lookup_environment_context` entries) have moved on. Always
cross-check current-state details against `HANDOFF.md` or the live code.
