# Agentic ReAct Triage Loop

This is the deep-dive on the agent. It covers what the agent is, how it
processes a single alert end to end, what each tool does, how the ReAct
loop is parsed and bounded, what runs deterministically vs what the LLM
drives, and how the result lands in the dashboard.

For a hand-drawn workflow diagram, read `docs/ARCHITECTURE.md` first.
For current branch state and pickup notes, read `docs/HANDOFF.md`.

---

## 1. What the agent is

The triage system processes alerts in two stages:

- **Stage 1** is per-alert: classify each alert as a true positive or a
  likely false positive, with severity, confidence, and a one-line
  rationale. Stage 1 is the **agentic** part — it runs a ReAct loop
  with three lookup tools, backed by a small local LLM.
- **Stage 2** is per-incident: take all the classified alerts in one
  incident and weave them into a plain-English narrative, plus a MITRE
  tactic, vectors, exposed-data list, and suggested response actions.
  Stage 2 is a single LLM call followed by deterministic
  post-processing.

This doc is mostly about Stage 1. Stage 2 only shows up in the
integration section (§10) and in §13 (the suggestion filter pipeline
that cleans up Stage 2's output).

The agent satisfies the capstone spec's "agentic AI module / Single
Agent" requirement: one agent (`ReActAgent`) with internal reasoning
and tool use, not a multi-agent orchestration. The classification,
severity, summary, and recommendation fields keep the shape the spec
asks for.

### Spec compliance summary

| Spec requirement | Where it lives |
|---|---|
| *"agentic AI module"* | `ReActAgent` runs the ReAct loop and decides when to call tools |
| *"Single Agent"* | One agent with internal reasoning, no agent-to-agent calls |
| *"classifies as true positive vs likely false positive"* | `AlertClassification.classification` |
| *"assigns severity"* | `AlertClassification.severity` (critical / high / low) |
| *"generates structured incident summaries"* | Stage 2 in `report_generator.py` |
| *"basic SOC response recommendations"* | `AlertClassification.recommendation` + Stage 2 AI Suggestions list |
| *"evaluation against ground truth"* | `src/evaluation/` — 5-config staircase ablation |

---

## 2. How the agent processes one alert (end to end)

Concrete walk-through. An alert arrives at
`ReActAgent.classify(alert: AlertRecord)`. Here is everything that
happens before the function returns:

### Step 0 — extract a quick attack type

`models.extract_attack_type(alert.signature, alert.signature_id)` runs
first. If the SID is in a custom rule range it returns `"SQLi"` or
`"XSS"` deterministically. Otherwise it substring-matches the
signature msg. This value is used to pick which pattern-stats tool
call to fire in step 1, and to seed the prompt with a hint of what
attack class we are looking at.

### Step 1 — auto-enrichment (Phase 1, no LLM)

Before the model sees anything, three tool calls fire deterministically:

1. `get_alert_history(src_ip=alert.src_ip, hours=24)` — prior alerts
   from this IP across the in-memory incident manager plus the
   persistent store.
2. `lookup_environment_context(query=alert.src_ip)` — is this IP one
   of ours, the attacker simulator, or unknown?
3. `get_attack_pattern_stats(attack_type=<extracted>, hours=24)` —
   how many alerts of this type have we seen recently, from how many
   distinct IPs? (Skipped if `attack_type == "Other"`.)

Each tool result becomes a `ReasoningStep` with `source="system"`,
`iteration=0`, and the JSON output captured verbatim. The dashboard
tags these steps with an `A` badge so a reader can tell them apart
from steps the LLM chose to run.

The model has not been called yet. Latency so far is a few
milliseconds (all reads are in-memory or one SQL query).

### Step 2 — build the round-1 prompt

The agent assembles a single string with four parts:

1. **System prompt** — role, task, output format spec, tool catalog
   (auto-generated from the registered tools), and a small number
   of few-shot examples.
2. **The alert** — JSON of the relevant `AlertRecord` fields.
3. **The reasoning trace so far** — the three auto-enrichment results
   wrapped in `<observation>` blocks so the model sees them as if it
   had asked for them itself.
4. **The "your turn" instruction** — emit either `<thought>` +
   `<action>` + `<action_input>` for another tool call, or
   `<thought>` + `<final_answer>` to finalise.

### Step 3 — LLM round

`provider.complete(prompt)` sends the request to Ollama (qwen2.5:3b
by default). The response is XML-tagged text. The parser handles
three outcomes:

- **`<final_answer>` present.** Parse the body as JSON, validate
  against the Stage 1 schema (classification enum, severity enum,
  required fields). On success, return an `AlertClassification` with
  the verdict + the full reasoning trace. Done.
- **`<action>` + `<action_input>` present.** Look up the tool by
  name, validate the input JSON against the tool's parameter schema,
  execute the tool, append an `<observation>` step to the reasoning
  trace, and loop to the next round.
- **Neither parses cleanly.** Increment a parse-failure counter. If
  the retry budget is left, loop again so the model can see its own
  failed output and self-correct. If retries are exhausted, fall
  back to the single-shot path.

### Step 4 — bounds

The loop is bounded two ways:

- **`max_iterations`** (default 3) caps the number of LLM rounds.
- **`total_budget_seconds`** (default 30) caps wall-clock time across
  all LLM calls + tool calls combined.

If either fires before a `<final_answer>` lands, the agent forces a
final-answer prompt that includes everything accumulated so far and
tells the model it must finalise now.

### Step 5 — fallback

If even the forced final-answer fails, or if the LLM is unreachable,
the agent falls back to single-shot mode: one LLM call with no tools,
classifying from the alert message alone. This is the same path used
when `agent.mode = "single_shot"` in the config.

The single-shot fallback writes a `parse_failure_count` into the
`AlertClassification` so the evaluation harness can count how often
this happens (a useful quality metric for the small model).

### Step 6 — return

`classify()` returns an `AlertClassification` with everything
captured: classification, severity, summary, recommendation, the
full reasoning trace (auto-enrichment steps + LLM steps), how many
tools the model invoked, how many parse failures occurred, and which
agent mode produced this verdict.

---

## 3. Where the agent fits in the bigger pipeline

The agent runs inside `ReportGenerator.generate(incident)`. There are
two LLM stages and several deterministic post-processing steps:

```
┌──────────────────────────────────────────────────────────────────────┐
│                  ReportGenerator.generate(incident)                  │
│                                                                      │
│   ┌────────────────────────────┐    ┌───────────────────────────┐    │
│   │  Stage 1: classify alerts  │    │  Stage 2: narrative       │    │
│   │  for each alert:           │───▶│  one LLM call across the  │    │
│   │     ReActAgent.classify()  │    │  full incident            │    │
│   └────────────────────────────┘    └───────────────────────────┘    │
│                                                  │                   │
│                                                  ▼                   │
│   ┌────────────────────────────────────────────────────────────┐     │
│   │  Deterministic post-processing:                            │     │
│   │   - MITRE tactic override (signature + URL scan)           │     │
│   │   - Rule-based suggestion generator                        │     │
│   │   - 3-layer LLM-suggestion filter                          │     │
│   │   - Template-v1 serializer + JSONSchema validation         │     │
│   └────────────────────────────────────────────────────────────┘     │
│                                                                      │
│   Save report to SQLite + WebSocket broadcast to dashboard.          │
└──────────────────────────────────────────────────────────────────────┘
```

The agent lives in three files under `src/`:

| File | Owns |
|---|---|
| `react_agent.py` | `ReActAgent`, `_SYSTEM_PROMPT`, XML parser, iteration loop, fallback ladder |
| `tool_registry.py` | `ToolDefinition`, `ToolRegistry`, `ToolResult` |
| `agent_tools.py` | The three tool factories + the public `lookup_environment_for_query` helper used by the suggestion filter |

It touches three more for integration:

| File | What it does for the agent |
|---|---|
| `models.py` | Holds `ReasoningStep`, `AlertClassification`, `extract_attack_type` (the SID-range classifier) |
| `report_generator.py` | Calls `ReActAgent.classify()` per alert |
| `app.py` | Reads `[agent]` config, builds the `ToolRegistry`, instantiates `ReActAgent`, hands it to `ReportGenerator` |

---

## 4. The ReAct loop (visual)

```
                          ┌──────────────────────────┐
                          │   ReActAgent.classify    │
                          │   (alert: AlertRecord)   │
                          └────────────┬─────────────┘
                                       │
                                       ▼
              ┌──────────────────────────────────────────────┐
              │ Auto-enrichment (Phase 1, no LLM):           │
              │  - get_alert_history                         │
              │  - lookup_environment_context                │
              │  - get_attack_pattern_stats (if known type)  │
              │ Seed reasoning_trace with results.           │
              └──────────────────────────────────────────────┘
                                       │
                                       ▼
              ┌──────────────────────────────────────────────┐
              │ Build initial prompt: system + alert + trace │
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

---

## 5. The three tools

All three tools are read-only, in-process, synchronous. No external
API calls. Per-call latency is well under 100 ms. The strings below
mirror what is registered with the `ToolRegistry`; the canonical
source for prompt-facing text is `src/agent_tools.py` (the
`_ALERT_HISTORY_DESCRIPTION`, `_ENV_LOOKUP_DESCRIPTION`, and
`_PATTERN_STATS_DESCRIPTION` constants).

### 5.1 `get_alert_history`

**What it does.** Looks up prior alerts from a specific source IP
within a time window. Use this to determine if the source IP is a
repeat offender or part of a sustained attack campaign.

**Signature:**
```json
{
  "name": "get_alert_history",
  "parameters": {
    "type": "object",
    "properties": {
      "src_ip": {
        "type": "string",
        "description": "The source IP address to look up (e.g. '192.168.56.1')"
      },
      "hours": {
        "type": "integer",
        "default": 24,
        "minimum": 1,
        "maximum": 168
      }
    },
    "required": ["src_ip"]
  }
}
```

**Data sources** (combined and deduplicated by incident ID):
- `IncidentManager._open_incidents` — open incidents this session.
- `IncidentManager._recently_closed` — closed this session, still
  cached in memory.
- `ReportDatabase.list_reports()` — every report persisted across all
  sessions of the dashboard.

**Return shape (with prior activity):**
```json
{
  "src_ip": "192.168.56.1",
  "lookback_hours": 24,
  "total_prior_alerts": 12,
  "attack_types_seen": ["SQLi", "XSS"],
  "first_seen_iso": "2026-05-14T10:00:00+00:00",
  "last_seen_iso":  "2026-05-14T10:04:30+00:00",
  "prior_incident_count": 2,
  "is_repeat_offender_this_session": true
}
```

When there are no prior alerts the same shape returns with zero
counts and empty lists. The tool never raises.

### 5.2 `lookup_environment_context`

**What it does.** Looks up known facts about an IP, CIDR range, or
URL path in the lab environment. Use this when the alert involves
an IP or URL whose role is unclear (internal infrastructure?
attacker simulator? known vulnerable endpoint?).

**Signature:**
```json
{
  "name": "lookup_environment_context",
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

**Data source.** The `[[agent.environment.entries]]` blocks in
`app.config`. Each entry has a pattern, a match type, a role, a
description, and a classification hint. Match types supported:
`exact_ip`, `cidr`, `url_prefix`, `url_contains`.

The lab currently ships five entries: MariaDB (internal database),
the Docker bridge CIDR, the host-only network CIDR (the attacker
simulator), the DVWA SQLi endpoint, and the DVWA XSS endpoint.

**Return shape (hit):**
```json
{
  "query": "172.18.0.2",
  "match_found": true,
  "matched_pattern": "172.18.0.2",
  "match_type": "exact_ip",
  "role": "internal_database",
  "description": "EXPECTED INTERNAL — MariaDB inside Docker bridge...",
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

### 5.3 `get_attack_pattern_stats`

**What it does.** Aggregates statistics for a specific attack type
over a time window. Use this to calibrate severity: a sustained
campaign of 47 SQLi attempts over an hour deserves a higher
recommendation than a single isolated attempt, even when the
individual alerts look identical.

**Signature:**
```json
{
  "name": "get_attack_pattern_stats",
  "parameters": {
    "type": "object",
    "properties": {
      "attack_type": {
        "type": "string",
        "enum": ["SQLi", "XSS", "CommandInjection", "PathTraversal",
                 "CSRF", "FileInclusion", "BruteForce",
                 "Reconnaissance", "WebAttack"]
      },
      "hours": {
        "type": "integer",
        "default": 24,
        "minimum": 1,
        "maximum": 168
      }
    },
    "required": ["attack_type"]
  }
}
```

**Data source.** Aggregates over `IncidentManager._open_incidents`,
`_recently_closed`, and the active storage backend's
`list_reports()`.

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

`observed_true_positive_rate` is self-referential: it is computed
from past LLM verdicts. Useful as a relative signal; not absolute
accuracy. The agent's prompt is aware of this caveat.

---

## 6. ReAct loop format and rules

### 6.1 XML format

Model output uses XML-style tags. The choice over native function
calling is deliberate: native tool-use APIs are inconsistent across
providers and patchy on Ollama with small models; XML parses
reliably with strict regex; failed parses leave readable text in
logs.

**Per-iteration model output, tool call branch:**
```
<thought>SQLi pattern in URL. Need to check if this source IP has hit us before.</thought>
<action>get_alert_history</action>
<action_input>{"src_ip": "192.168.56.1", "hours": 24}</action_input>
```

**Per-iteration agent response (the agent writes this, not the model):**
```
<observation>{"src_ip": "192.168.56.1", "total_prior_alerts": 12, "attack_types_seen": ["SQLi"], "is_repeat_offender_this_session": true}</observation>
```

**Final answer branch:**
```
<thought>12 prior SQLi alerts from same IP. Active campaign. High severity, block the IP.</thought>
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
   - Validate against the Stage 1 schema.
   - Return result.
3. Otherwise find `<action>...</action>` and
   `<action_input>...</action_input>`:
   - Action must match a registered tool name.
   - Action input must parse as JSON and validate against the
     tool's parameter schema.
   - Execute tool. Inject observation. Loop.
4. If neither `<final_answer>` nor `<action>` are found, OR if any
   tag is malformed: count as a parse failure.

Regex (Python, `re.DOTALL`):
```python
_TAG_PATTERN = re.compile(
    r"<(?P<tag>thought|action|action_input|final_answer)>"
    r"(?P<content>.*?)"
    r"</(?P=tag)>",
    re.DOTALL,
)
```

### 6.3 Iteration rules

- **Max iterations:** 3 (configurable).
- **Per-tool timeout:** 5 seconds (tools should finish in well under
  100 ms; the timeout catches deadlocks).
- **Total budget:** 30 seconds wall-clock per alert classification,
  across all LLM calls + tool calls combined.
- **On iteration cap:** force a final answer by re-prompting with
  everything accumulated and telling the model it must finalise now.
- **On total budget exceeded:** return a degraded
  `AlertClassification` with `status="partial"`, `parse_failure_count`
  set, fallback severity of `Medium`, and recommendation
  `escalate_tier2`. Escalating to a human is the right default when
  the agent ran out of time.

### 6.4 Fallback ladder

```
1. Try ReAct loop, with one retry on parse failure  (primary path)
2. If parse still fails -> single-shot LLM call, no tools
3. If single-shot also fails -> AlertClassification with status="error"
                                  (matches the legacy single-shot
                                  error contract)
```

Each fallback step writes its triggering condition into
`reasoning_trace[].parse_error` so the evaluation harness can see
why the loop bailed.

### 6.5 System prompt structure

The system prompt is built once per `ReActAgent` instance and has
four parts:

1. **Role + task.** What the agent is and what it is being asked to
   produce. Includes a prompt-injection defence block: the LLM is
   told that any text inside an alert payload is data, not
   instructions.
2. **Available tools.** Auto-generated from the registered tools.
   Each tool contributes its name, description, and JSON Schema.
3. **Output format spec.** Describes the XML tags, the final-answer
   JSON shape, and which fields are required.
4. **Few-shot examples.** A small number of worked examples covering
   the three common paths through the loop (see §6.6).

The verbatim text lives in `_SYSTEM_PROMPT` in `src/react_agent.py`.
Treat that file as canonical; the prompt is sensitive to format and
has been tuned for qwen 3B.

### 6.6 Few-shot examples

The system prompt includes worked examples covering:

1. **Obvious attack, no tools needed.** Clear SQLi URL pattern,
   straight to `<final_answer>`. Teaches the model that it is fine
   to skip tool calls when the alert is unambiguous.
2. **Ambiguous alert, one tool needed.** Alert from an unfamiliar IP,
   look up environment context, then `<final_answer>`. Teaches the
   model how to use `lookup_environment_context`.
3. **Sustained activity, multiple tools needed.** Check history and
   pattern stats, raise severity to reflect the campaign context.
   Teaches the model how to combine signals across tools.

### 6.7 Tool over-use prevention

The system prompt explicitly tells the model:

> Only call a tool when the alert is genuinely ambiguous. For
> obviously malicious payloads (clear SQL injection, script tags,
> command injection), output `<final_answer>` immediately without
> calling tools. Tool calls cost time and should be reserved for
> cases where additional context changes your verdict.

Average tool calls per alert is tracked as an evaluation metric.
Target: under 1.5 calls per alert across the test set.

---

## 7. Auto-enrichment (the deterministic phase)

`auto_enrichment = true` in `app.config` turns on a deterministic
pre-LLM phase. When enabled (and it is on by default):

1. As soon as `classify()` is called and before any LLM call, the
   agent runs all three tools using the alert's own fields:
   `get_alert_history(src_ip=alert.src_ip)`,
   `lookup_environment_context(query=alert.src_ip)`, and (only when
   the attack type was recognised by `extract_attack_type`)
   `get_attack_pattern_stats(attack_type=<extracted>)`.
2. Each result is captured as a `ReasoningStep` with `source="system"`
   and `iteration=0`. The dashboard renders these with an `A` badge
   so a reader can tell auto-enrichment steps apart from steps the
   LLM chose to run.
3. The results are seeded into the round-1 prompt as `<observation>`
   blocks. From the LLM's perspective, three tool calls have
   already happened.
4. The LLM still has the option to call additional tools afterwards
   (for example, asking for the pattern stats on a different attack
   type). Auto-enrichment is the floor, not the ceiling.

The reason this exists: 3B models drift on tool-call adherence. Left
to its own devices, qwen 3B sometimes skips tool calls entirely and
classifies the alert from the message alone, losing the historical
and environmental signal. Pre-running the three obvious lookups
guarantees that the LLM always sees the enrichment before it speaks.

For evaluation purposes, `auto_enrichment = false` disables the
deterministic phase. The LLM then has to choose to call tools on its
own. This is the ablation row that measures how much the hybrid
design contributes vs pure LLM-driven tool use.

---

## 8. Data model

### 8.1 `ReasoningStep`

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
    observation: Optional[str]           # tool output JSON; None on final
    duration_ms: int                     # wall-clock for LLM + tool call
    parse_error: Optional[str] = None    # set if this step's output failed to parse
    source: str = "llm"                  # "llm" or "system" (auto-enrichment)
```

### 8.2 `AlertClassification` additions

```python
@dataclass
class AlertClassification:
    # ... base fields: classification, severity, summary,
    #     recommendation, reasoning, confidence, etc.
    reasoning_trace: Optional[List[ReasoningStep]] = None
    agent_mode: str = "single_shot"      # "react" | "single_shot"
    parse_failure_count: int = 0         # how many model outputs failed to parse
    tool_calls: int = 0                  # how many tools the LLM itself invoked
```

The four agent-specific fields are all optional with safe defaults,
so any code path that does not run the agent (e.g. the single-shot
fallback) produces a valid `AlertClassification` with the legacy
shape.

### 8.3 `ToolDefinition` and `ToolResult`

```python
@dataclass
class ToolDefinition:
    name: str                            # e.g. "get_alert_history"
    description: str                     # for model prompt
    parameters_schema: Dict              # JSONSchema for argument validation
    function: Callable[[Dict], Any]      # takes args dict, returns JSON-serialisable

@dataclass
class ToolResult:
    tool_name: str
    arguments: Dict
    output: Any                          # serialised for <observation>
    error: Optional[str] = None
    duration_ms: int = 0
```

---

## 9. Configuration

The current `[agent]` and `[storage]` blocks in `app.config`:

```toml
[agent]
mode                     = "react"          # "react" | "single_shot"
max_iterations           = 3
tool_timeout_seconds     = 5.0
total_budget_seconds     = 30.0
reasoning_trace_enabled  = true             # dashboard + persisted in report
auto_enrichment          = true             # see §7

[agent.tools]
get_alert_history             = true
lookup_environment_context    = true
get_attack_pattern_stats      = true

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

[storage]
db_path                  = "data/reports.db"
retention_days           = 90               # 0 = never expire
cleanup_interval_seconds = 3600             # 0 = no auto cleanup
```

`ReActAgent` consumes a `ModelProvider` (currently Ollama) through the
`complete()` / `complete_json()` interface, so the agent itself is
backend-agnostic if a second local provider is wired later.

---

## 10. Integration with `ReportGenerator`

`ReActAgent` plugs in via two optional constructor kwargs on
`ReportGenerator`: `react_agent` (the agent instance) and `agent_mode`
(string). When `agent_mode == "react"`, the per-alert classifier
delegates to `react_agent.classify(alert)`. Otherwise it falls through
to the original single-shot classifier (the same code path used as
the loop's fallback).

`app.py` does the wiring at startup:

1. Read the `[agent]` section of `app.config`.
2. Build a `ToolRegistry`.
3. For each enabled tool, call its factory in `agent_tools.py`
   (`make_alert_history_tool`, `make_environment_lookup_tool`,
   `make_pattern_stats_tool`). The factories capture the live
   `IncidentManager` and storage backend in closures so the tools
   can query real state.
4. Construct a `ReActAgent(provider, registry, max_iterations,
   tool_timeout_seconds, total_budget_seconds, auto_enrichment)`.
5. Hand the agent + `agent_mode="react"` to `ReportGenerator`.

For the canonical signatures and the actual wiring flow, see
`src/app.py` and `src/report_generator.py`. Duplicating them here
would rot every refactor.

---

## 11. The reasoning trace in the dashboard

Each incident card on the dashboard shows the full Stage 1 + Stage 2
output:

- **Header line**: incident ID, status, source IP, repeat-offender
  badge, alert count, overall severity, overall CVSS, time-ago,
  report version, detected attack types.
- **Overview**: the Stage 2 narrative in plain English.
- **Summary block**: MITRE attack stage, vectors, true-positive
  and false-positive counts, first-seen and last-seen, data
  sensitivity.
- **AI Suggestions**: the merged rule-based + LLM-filtered list.
- **Information Exposure**: exposure, impact, exposed data types,
  affected systems.
- **Alert Analyses (N)**: one block per alert. Shows attack type,
  LLM-picked subtype, per-alert summary, confidence score.
- **Agent Reasoning** (per analysis): expandable trace of every step
  the ReAct loop took. Each step shows the iteration number, the
  tool name + JSON input + JSON output (for action steps), the
  model's `<thought>` when present, and a `final answer ✓` marker.
  Auto-enrichment steps get an `A` badge and an `Auto-enrichment:`
  label.
- **Indicators of Compromise**: source IPs, signatures (e.g.
  `P1 - SQLi UNION SELECT in URI`), URLs.
- **Footer**: model name, provider type, report ID.

`src/static/app.js` renders the card from the template-v1 JSON
delivered via WebSocket (`report_ready` event) or REST
(`GET /api/incidents/<id>`). The reasoning trace renders only when
`AlertClassification.reasoning_trace` is non-empty and
`reasoning_trace_enabled = true` in `app.config`.

Live streaming of the trace (showing tool calls as they happen
rather than only after the report finishes) is not implemented. The
trace renders statically once the report is saved.

---

## 12. MITRE tactic override

The Stage 2 LLM picks an `overall_attack_stage` MITRE tactic. qwen 3B
sometimes picks something noisy (e.g. labelling a UNION SELECT as
"Reconnaissance"), so a deterministic post-processor runs after the
Stage 2 LLM call.

Logic:

1. For each known attack type detected in the incident, map it to its
   canonical tactic (SQLi → Initial Access, XSS → Initial Access,
   CommandInjection → Execution, etc.).
2. If SQLi is present and any alert in the incident names credential
   keywords (`USER`, `PASS`, `PASSWD`, `CRED`, `TOKEN`, `LOGIN`,
   `AUTH`, `SECRET`) in the signature msg OR in the URL payload,
   bump the candidate set to `Credential Access` (and remove
   `Initial Access`).
3. If the LLM's tactic is already in the candidate set, preserve it.
   The LLM picked something valid; no override needed.
4. Otherwise pick the highest-priority candidate (by a fixed priority
   table) and override.

The URL scan is the important nuance: our custom SQLi rule messages
are generic ("P1 - SQLi UNION SELECT in URI"), so the credential
intent lives in the URL (`?id=1' UNION SELECT user, password FROM
users#`), not in the signature msg. Scanning both catches the
common case.

Implementation: `_override_mitre_tactic` and
`_alert_mentions_credentials` in `src/report_generator.py`. Test
coverage: 9 cases in `test_report_generator.py`.

---

## 13. Suggestion filter pipeline

Stage 2 emits an `ai_suggestions` array as part of its narrative.
qwen 3B on a 3B-parameter budget produces a mix: some grounded,
specific suggestions, some generic platitudes, the occasional
suggestion that contradicts the enrichment data. A three-layer
filter cleans this up before the suggestions land in the report:

1. **Layer 1 — generic-platitude filter.** Drop suggestions whose
   first word matches a banned starter list (`Implement`, `Enhance`,
   `Review`, `Investigate generally`, etc.). These are the
   no-content openers the model defaults to.
2. **Layer 2 — enrichment-aware filter.** Drop suggestions that
   contradict the enrichment data. The classic example: a "Block
   172.18.0.2" suggestion when 172.18.0.2 is documented as the
   internal MariaDB server. The filter resolves the suggestion's
   target IP and checks it against the environment entries; if the
   target is internal infrastructure or otherwise contradicts a
   `classification_hint`, the suggestion is dropped.
3. **Layer 3 — verb + IP dedup.** Drop LLM suggestions that overlap
   the rule-based suggestion generator's output (by leading verb +
   IP). This avoids "Block 192.168.56.1 at firewall" showing up
   twice with slightly different wording.

Surviving LLM suggestions are merged with the rule-based generator's
output (which produces deterministic SOC-playbook patterns: open
Tier-2 ticket, block IP, rotate creds, audit endpoint, tune Suricata
for FP cluster, etc.). The merged list is capped at six entries to
keep the dashboard card readable.

Implementation: `_filter_llm_suggestions` and
`_generate_rule_based_suggestions` in `src/report_generator.py`.

---

## 14. Evaluation strategy

The evaluation harness runs a **5-config staircase ablation**.
Each row adds one capability to the previous row, so the F1 / recall
delta between rows attributes triage quality to specific design
choices.

| # | Step           | Model        | `agent.mode`  | `auto_enrichment` | Custom Suricata rules |
|---|----------------|--------------|---------------|-------------------|-----------------------|
| 1 | `baseline`     | llama3.2:3b  | single_shot   | false             | off                   |
| 2 | `model_swap`   | qwen2.5:3b   | single_shot   | false             | off                   |
| 3 | `react`        | qwen2.5:3b   | react         | false             | off                   |
| 4 | `enrich`       | qwen2.5:3b   | react         | true              | off                   |
| 5 | `custom_rules` | qwen2.5:3b   | react         | true              | on                    |

3 reps per config × 5 configs = 15 evaluation runs. Each run takes
roughly 10-15 minutes depending on model speed and LLM latency.

Per-run metrics retained from the legacy harness: precision, recall,
F1, accuracy, confusion matrix.

Agent-specific metrics added:

| Metric | What it captures |
|---|---|
| Tool call rate | Average tools the model itself invoked per alert (excludes auto-enrichment) |
| Tool usage distribution | Histogram by tool name |
| Parse failure rate | Fraction of model outputs that failed XML parsing |
| Fallback rate | Fraction of classifications that fell back to single-shot |
| Latency p50 / p95 | Wall-clock per classification |
| Severity consistency | Stddev of severity rank across the 3 repetitions of the same scenario |

Per-config raw outputs land in `eval_results/<label>_<config>_<ts>_results.json`
plus a markdown summary. The combined report
(`run_combined_report.py`) cross-tabulates metrics across configs
into the staircase, with the ΔF1 column attributing quality to each
added capability. See `docs/PHASE_6_RUNBOOK.md` for the operator
procedure.

---

## 15. Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | XML-tagged ReAct format (not native function calling) | Provider-portable, parses reliably on 3B models |
| 2 | Three tools: `get_alert_history`, `lookup_environment_context`, `get_attack_pattern_stats` | Each maps to a real Tier-1 SOC question, all read existing state |
| 3 | Max 3 iterations, 30 s total budget | Bounds latency; one tool call per iteration is enough for most cases |
| 4 | Default LLM `qwen2.5:3b`; baseline `llama3.2:3b` | Better tool use at the same size class; baseline keeps eval numbers comparable |
| 5 | Single-shot mode kept under a config flag | Enables ablation; demo fallback if ReAct misbehaves |
| 6 | Hybrid Option F: deterministic auto-enrichment + LLM-driven exploration | Compensates for 3B-model adherence drift while keeping the LLM autonomous on the verdict |
| 7 | Rule-based MITRE override (scans signature + URL, preserves LLM when valid) | qwen 3B mislabels common cases; override is honest engineering: rule-based for what we know, LLM judgment for everything else |
| 8 | Rule-based suggestion generator + 3-layer LLM filter | qwen 3B produces a mix of grounded and platitude suggestions; layered defence keeps the report clean |
| 9 | Template-v1 serializer with JSONSchema validation | The marker reads the JSON and expects the template fields; serializer keeps the internal model rich while emitting a template-compliant shape |
| 10 | One Kali VM (DVWA + Suricata co-located) | Spec drift documented as deliberate simplification; spans-port limitation in VirtualBox makes a proper split impractical |
| 11 | Reasoning trace UI: static render only | Live streaming was a stretch goal; static suffices for the spec + demo |
| 12 | Suricata lab runs custom-only (ET Open + built-in event rules disabled) | Scopes the feed to the two attack classes the project demonstrates; every alert is traceable to a team-written rule; removes ET double-alerting + ET SCAN / SURICATA noise |
| 13 | `attack_type` resolved by custom SID range before string fallback (1000001-58 → XSS, 1000101-13 → SQLi) | qwen 3B sometimes hedges `attack_type` to "Other / unclassified" on broad-tier alerts; SID-range path is correctness-first; string fallback still handles ET Open if re-enabled |
| 14 | Alert severity scale = critical / high / low (no medium) | Aligns with the custom rules' P1 / P2 / P3 priority tiers; Suricata severity 3+ maps to "low" |
| 15 | SQLi rule pcres use `[\s+]` not `\s` for inter-keyword spacing | DVWA's GET form encodes spaces as `+` which Suricata's URI buffer does not decode; bare `\s` made the P1 UNION SELECT rule silently fail to fire |
| 16 | SQLite hybrid schema (indexed columns + JSON blob, WAL mode) | Cheap queries on the columns you filter on, full payload available; standard pragmatic choice |
| 17 | No JSON → SQLite migration tool | Fresh database on first run; the legacy JSON backend was retired after the migration. |
| 18 | Teammate contributions integrated via cherry-pick (preserves authorship); cleanup in a separate follow-up commit | Capstone academic integrity; same motivation as no-AI-commit-trailers |
| 19 | No AI commit trailers | Capstone academic integrity |

---

## 16. Known limitations

1. **qwen 3B non-determinism at `temperature = 0.0`.** The same alert
   can produce slightly different rationales across regenerations.
   The structured fields (classification, severity, attack_type) are
   stable; the free-text fields drift. Documented; not a blocker.
2. **qwen 3B XML adherence drift.** Occasional output where both
   `<action>` and `<final_answer>` appear in one round, or where
   `action_input` JSON is malformed. The parser handles these as
   parse failures; the retry + single-shot fallback covers the case.
   Parse-failure rate is tracked as an evaluation metric.
3. **`observed_true_positive_rate` is self-referential.** It is
   computed from past LLM verdicts, not from ground truth. Useful as
   a relative signal; the prompt flags this so the model treats it
   as such.
4. **Reasoning trace storage cost.** Each trace adds roughly 500-2000
   bytes per report. Negligible at lab volumes (50-200 KB/day for
   100 incidents/day); worth flagging if scaled to production.
5. **No multi-agent orchestration.** The capstone spec called for a
   "Single Agent" so this is by design. A marker reading "agentic"
   loosely might want a richer multi-agent narrative; the
   counter-argument is that ReAct loop + pre-enrichment + tool
   autonomy is the standard agentic pattern.
6. **MITRE override is rule-based, not model-derived.** The override
   table is small and hand-crafted; it does not cover every MITRE
   tactic. The preserve-LLM-when-valid logic limits the blast radius.
