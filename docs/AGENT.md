# Agentic ReAct Triage Loop

Deep-dive on the ReAct agent: how it processes a single alert, what each tool does, how the loop is bounded, and how the result lands in the report.

---

## 1. Two-Stage Pipeline

Alert triage runs in two stages:

- **Stage 1 - per-alert classification.** Classifies each alert as true positive or likely false positive, with severity, confidence, and a one-line rationale. Runs a ReAct loop with three lookup tools backed by a local LLM.
- **Stage 2 - incident narrative.** After all alerts in an incident are classified, a single LLM call produces the cross-alert narrative: MITRE tactic, attack vectors, exposed data list, and suggested response actions. Deterministic post-processing follows.

---

## 2. Per-Alert Processing: End to End

When `ReActAgent.classify(alert)` is called:

**Step 0 - extract attack type.** `models.extract_attack_type(alert.signature, alert.signature_id)` runs first. Custom SID ranges map deterministically to `"SQLi"` or `"XSS"`; otherwise substring-matches the signature message. Used to pick the pattern-stats tool call and seed the prompt.

**Step 1 - auto-enrichment (no LLM).** Three tool calls fire deterministically before the model sees anything:
1. `get_alert_history(src_ip)` - prior alerts from this IP in the last 24 hours
2. `lookup_environment_context(query=alert.src_ip)` - is this IP internal infrastructure, known attacker range, or unknown?
3. `get_attack_pattern_stats(attack_type)` - how many alerts of this type have been seen recently across all IPs?

Each result becomes a `ReasoningStep` with `source="system"` and `iteration=0`. The dashboard renders these with an `A` badge. No LLM call yet.

**Step 2 - build prompt.** The agent assembles: system prompt (role, tool catalog, output format, few-shot examples) + alert JSON + auto-enrichment results as `<observation>` blocks + "your turn" instruction.

**Step 3 - LLM round.** The model responds with XML-tagged output. Three outcomes:
- `<final_answer>` present: parse as JSON, validate, return `AlertClassification`. Done.
- `<action>` + `<action_input>` present: look up the tool, execute it, append `<observation>`, loop.
- Neither parses cleanly: count as parse failure, retry once, then fall back to single-shot.

**Step 4 - bounds.** The loop is capped by `max_iterations` (default 3) and `total_budget_seconds` (default 30). If either fires before a `<final_answer>`, the agent issues a forced-final-answer prompt with all accumulated context.

**Step 5 - fallback.** If even the forced answer fails, a single-shot LLM call classifies from the alert message alone. If that also fails, an `AlertClassification` with `status="error"` is returned. Each fallback step records why it fired in `reasoning_trace[].parse_error`.

**Step 6 - return.** `AlertClassification` contains: classification, severity, summary, recommendation, the full reasoning trace (auto-enrichment + LLM steps), tool call count, parse failure count, agent mode.

---

## 3. Pipeline Context

`ReActAgent` runs inside `ReportGenerator.generate(incident)`. After Stage 1 classifies all alerts, Stage 2 runs a single LLM call for the incident narrative, followed by:
- MITRE tactic override (signature + URL scan for credential keywords)
- Rule-based suggestion generator
- Three-layer LLM suggestion filter
- Template-v1 serializer + JSONSchema validation

Save to SQLite + WebSocket broadcast to dashboard.

---

## 4. The Three Tools

All tools are read-only, in-process, synchronous. Per-call latency is under 100 ms.

### `get_alert_history`

Looks up prior alerts from a specific source IP within a time window. Used to determine if the source is a repeat offender or part of a sustained campaign.

Parameters: `src_ip` (required), `hours` (default 24, max 168).

Data sources: open incidents, recently-closed incidents, and all persisted reports in SQLite.

Returns: total prior alerts, attack types seen, first/last seen timestamps, incident count, repeat-offender flag.

### `lookup_environment_context`

Looks up known facts about an IP, CIDR range, or URL path. Used to determine whether an IP is internal infrastructure, an attacker simulator, or unknown.

Parameters: `query` (IP, CIDR, hostname, or URL path).

Data source: the `[[agent.environment.entries]]` blocks in `app.config`. Supported match types: `exact_ip`, `cidr`, `url_prefix`, `url_contains`.

Returns on hit: matched pattern, match type, role, description, classification hint. Returns `{"match_found": false}` on miss.

### `get_attack_pattern_stats`

Aggregates statistics for a specific attack type over a time window. Used to calibrate severity: a sustained campaign of many attempts deserves a higher recommendation than an isolated one.

Parameters: `attack_type` (enum: SQLi, XSS, CommandInjection, PathTraversal, CSRF, FileInclusion, BruteForce, Reconnaissance, WebAttack), `hours` (default 24).

Returns: total alerts, unique source IPs, incident count, observed true-positive rate (self-referential: computed from past LLM verdicts, useful as relative signal only).

---

## 5. ReAct Loop Format

### XML tags

Model output uses XML-style tags rather than native function calling. Native tool-use APIs are inconsistent across Ollama model versions and unreliable on 3B models; XML parses reliably with strict regex.

**Tool call:**
```
<thought>SQLi pattern in URL. Need history for this IP.</thought>
<action>get_alert_history</action>
<action_input>{"src_ip": "192.168.56.1", "hours": 24}</action_input>
```

**Agent response (appended to prompt):**
```
<observation>{"src_ip": "192.168.56.1", "total_prior_alerts": 12, ...}</observation>
```

**Final answer:**
```
<thought>12 prior alerts. Active campaign. Block the IP.</thought>
<final_answer>
{
  "classification": "true_positive",
  "severity": "critical",
  "summary": "Active SQLi campaign from 192.168.56.1",
  "recommendation": "block_source_ip",
  "reasoning": "12 prior SQLi alerts from same IP in last 24h; sustained attack."
}
</final_answer>
```

### Parser rules

1. Find `<final_answer>` first. If present: parse as JSON, validate, return.
2. Otherwise find `<action>` + `<action_input>`: validate tool name and parameters, execute, inject `<observation>`, loop.
3. If neither present or any tag malformed: parse failure.

Regex used (Python, `re.DOTALL`):
```python
_TAG_PATTERN = re.compile(
    r"<(?P<tag>thought|action|action_input|final_answer)>"
    r"(?P<content>.*?)"
    r"</(?P=tag)>",
    re.DOTALL,
)
```

### Bounds and fallback ladder

```
1. ReAct loop, max 3 iterations, 30s total budget (primary path)
2. If iteration cap or budget exceeded -> force final-answer prompt with accumulated context
3. If forced final-answer fails -> single-shot LLM call, no tools
4. If single-shot fails -> AlertClassification(status="error")
```

On budget exhaustion before any answer, returns `AlertClassification` with `status="partial"`, fallback severity `medium`, recommendation `escalate_tier2`.

### Tool over-use prevention

The system prompt tells the model to call tools only when the alert is genuinely ambiguous. For obviously malicious payloads, it should output `<final_answer>` immediately. Average tool calls per alert (excluding auto-enrichment) is tracked as an evaluation metric; target is under 1.5 per alert.

---

## 6. Auto-Enrichment

When `auto_enrichment = true` (default), all three tools fire deterministically before the first LLM call. Results appear in the dashboard reasoning trace with an `A` badge (`source="system"`, `iteration=0`).

The LLM still has the option to call additional tools afterwards. Auto-enrichment is the floor, not the ceiling.

Reason this exists: 3B models drift on tool-call adherence. Without pre-enrichment, the model sometimes skips tool calls entirely and classifies from the alert message alone, losing the historical and environmental context.

Set `auto_enrichment = false` to disable and let the LLM decide whether to call tools (useful as an ablation comparison).

---

## 7. Data Model

### `ReasoningStep`

```python
@dataclass
class ReasoningStep:
    iteration: int
    thought: str
    action: Optional[str]          # tool name, or None on final answer
    action_input: Optional[Dict]
    observation: Optional[str]     # tool output JSON; None on final
    duration_ms: int
    parse_error: Optional[str] = None
    source: str = "llm"            # "llm" or "system" (auto-enrichment)
```

### `AlertClassification` agent fields

```python
reasoning_trace: Optional[List[ReasoningStep]] = None
agent_mode: str = "single_shot"    # "react" | "single_shot"
parse_failure_count: int = 0
tool_calls: int = 0
```

---

## 8. System Prompt Structure

The system prompt is built once per `ReActAgent` instance:

1. **Role + task.** What the agent is and what it must produce. Includes a prompt-injection defence: alert payload text is explicitly framed as data, not instructions.
2. **Available tools.** Auto-generated from registered tools: name, description, JSON Schema.
3. **Output format spec.** XML tags, final-answer JSON shape, required fields.
4. **Few-shot examples.** Three worked examples covering: obvious attack (skip tools), ambiguous IP (use `lookup_environment_context`), sustained campaign (use history + pattern stats).

The verbatim text lives in `_SYSTEM_PROMPT` in `src/react_agent.py`. The prompt is tuned for `qwen2.5:3b`; treat it as sensitive to format changes.

---

## 9. Configuration

Relevant `app.config` sections:

```toml
[agent]
mode                     = "react"          # "react" | "single_shot"
max_iterations           = 3
tool_timeout_seconds     = 5.0
total_budget_seconds     = 30.0
reasoning_trace_enabled  = true
auto_enrichment          = true

[agent.tools]
get_alert_history             = true
lookup_environment_context    = true
get_attack_pattern_stats      = true
```

---

## 10. MITRE Tactic Override

After Stage 2 returns an `overall_attack_stage`, a rule-based override runs:

1. Map each detected attack type to its canonical MITRE tactic (SQLi -> Initial Access, XSS -> Initial Access, CommandInjection -> Execution, etc.).
2. If SQLi is present and any alert in the incident contains credential keywords (`USER`, `PASS`, `CRED`, `TOKEN`, `LOGIN`, `AUTH`, `SECRET`) in the signature message or URL, promote to `Credential Access`.
3. If the LLM's tactic is already in the candidate set, preserve it (no override needed).
4. Otherwise override with the highest-priority candidate.

The URL scan is necessary because custom rule messages are generic (e.g., "P1 - SQLi UNION SELECT in URI"), while the credential intent lives in the URL payload.

Implementation: `_override_mitre_tactic` and `_alert_mentions_credentials` in `src/report_generator.py`.

---

## 11. Suggestion Filter Pipeline

Stage 2 produces `ai_suggestions`. A three-layer filter runs before they land in the report:

1. **Generic-platitude filter.** Drops suggestions whose first word matches a banned list (`Implement`, `Enhance`, `Review`, `Investigate generally`, etc.).
2. **Enrichment-aware filter.** Drops suggestions that contradict the enrichment data (e.g., "Block 172.18.0.2" when that IP is documented as internal database infrastructure).
3. **Verb + IP dedup.** Drops LLM suggestions that overlap the rule-based generator's output by leading verb + IP.

Surviving LLM suggestions merge with the rule-based generator's output (deterministic SOC-playbook patterns: block IP, rotate credentials, audit endpoint, Tier-2 ticket, tune Suricata for FP cluster). Merged list is capped at six entries.

Implementation: `_filter_llm_suggestions` and `_generate_rule_based_suggestions` in `src/report_generator.py`.

---

## 12. Dashboard Reasoning Trace

Each incident card shows the full Stage 1 + Stage 2 output including an expandable **Agent Reasoning** section per alert: each step's iteration, tool name + JSON input + output, the model's `<thought>`, and a final-answer marker. Auto-enrichment steps show an `A` badge.

The reasoning trace renders statically once the report is saved (live streaming during classification is not implemented).

`src/static/app.js` renders the card from the template-v1 JSON delivered via WebSocket (`report_ready` event) or REST (`GET /api/incidents/<id>`).

---

## 13. Known Limitations

1. **`HOME_NET = any` in `suricata.yaml`.** Broadens address matching. ET Open rules using `!$HOME_NET` will fail to load if ET Open is re-enabled; they log a parse error at startup and Suricata continues. Cosmetic noise with custom-only rules.
2. **Non-determinism at `temperature=0.0`.** The same alert can produce slightly different rationales across reruns. Structured fields (classification, severity, attack type) are stable; free-text fields may vary in wording.
3. **XML adherence drift.** Occasional output where both `<action>` and `<final_answer>` appear in one round, or `action_input` JSON is malformed. Handled by robust parser + retry + single-shot fallback.
4. **`observed_true_positive_rate` is self-referential.** Computed from past LLM verdicts, not ground truth. Useful as a relative signal; the prompt flags this.
5. **Reasoning trace storage cost.** Each trace adds ~500-2000 bytes per report. Negligible at lab volumes; worth noting if scaling.
6. **MITRE override is rule-based, not model-derived.** The override table is small and hand-crafted; it does not cover every MITRE tactic. The preserve-LLM-when-valid logic limits the blast radius.

---

## 14. Design Decisions

| Decision | Rationale |
|---|---|
| XML-tagged ReAct format (not native function calling) | Provider-portable; parses reliably on 3B models without Ollama-specific tool-use API dependency |
| Three fixed tools: history / env / stats | Each maps to a real Tier-1 SOC question; all read existing in-memory and SQLite state |
| Max 3 iterations, 30s total budget | Bounds latency; one tool call per iteration is sufficient for most cases |
| Hybrid auto-enrichment: deterministic pre-LLM tools + LLM-driven exploration | Compensates for small-model tool-call adherence drift while keeping the LLM autonomous on the verdict |
| Rule-based MITRE override | Model sometimes mislabels common attack stages; override scans signature + URL, preserves LLM verdict when valid |
| Rule-based suggestion generator + 3-layer LLM filter | Small model produces a mix of grounded and generic suggestions; layered defence keeps the report clean |
| SQLite hybrid schema (indexed columns + JSON blob, WAL mode) | Cheap queries on filtered columns; full payload available via blob |
| Alert severity scale: critical / high / low (no medium) | Aligns with custom rules P1/P2/P3 priority tiers |
| `attack_type` resolved from custom SID ranges before string fallback | SID-range path is correctness-first; model sometimes hedges to "Other" on broad-tier alerts |
| Single-shot mode kept under config flag | Enables ablation comparison; also serves as fallback if ReAct loop fails persistently |
