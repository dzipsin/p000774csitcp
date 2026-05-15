"""
test_react_agent.py - Manual test harness for react_agent.

Plain Python script with manual assertions (no pytest). Run with:

    python src/test_react_agent.py

Uses a deterministic MockProvider that replays canned response strings,
so tests do not require Ollama / a real LLM. Real-LLM testing happens
via the integration test in Phase 4.

Covers:
  - XML tag extractor (_extract_tags, _find_first)
  - Round-prompt accumulator (_build_round_prompt)
  - Direct final_answer (no tool)
  - One tool call then final
  - Two tool calls then final
  - Parse failure -> retry succeeds
  - Parse failure -> retry budget exhausted -> single-shot fallback
  - action_input not JSON -> parse_error
  - Unknown tool name -> tool registry returns error result, loop continues
  - LLM provider raises -> caught, fallback
  - Iteration cap reached -> fallback
  - final_answer JSON validation failure -> parse_error
  - Single-shot fallback success path (clean status="complete")
  - Single-shot fallback failure path (status="error")
  - reasoning_trace ordering and content captured correctly
  - Empty tool registry still works
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make src/ imports work from anywhere
sys.path.insert(0, str(Path(__file__).parent))

from log_monitor import AlertRecord
from model_provider import ModelProvider, ProviderType
from models import AlertClassification, ReasoningStep
from tool_registry import ToolDefinition, ToolRegistry
from react_agent import (
    ReActAgent,
    _build_react_system_prompt,
    _extract_tags,
    _find_first,
)


# ---------------------------------------------------------------------------
# Test infrastructure
# ---------------------------------------------------------------------------

_passed = 0
_failed = 0


def _assert(condition: bool, label: str, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  PASS  {label}")
    else:
        _failed += 1
        msg = f"  FAIL  {label}"
        if detail:
            msg += f"  ({detail})"
        print(msg)


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

class MockProvider(ModelProvider):
    """ModelProvider that replays a canned list of responses in order.

    Each entry can be a string (returned as-is) or an Exception instance
    (raised when .complete() is called). Useful for simulating LLM
    misbehaviour without actually running a model.
    """

    def __init__(
        self,
        responses: List[Any],
        json_responses: Optional[List[Any]] = None,
        model_name: str = "mock-3b",
    ):
        self._responses = list(responses)
        # complete_json may be called by single-shot fallback; if not provided,
        # falls back to the same response list.
        self._json_responses = list(json_responses) if json_responses is not None else None
        self._idx = 0
        self._json_idx = 0
        self.calls: List[str] = []
        self.json_calls: List[str] = []
        self._mn = model_name

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        if self._idx >= len(self._responses):
            raise RuntimeError(
                f"MockProvider.complete out of responses (idx={self._idx})"
            )
        item = self._responses[self._idx]
        self._idx += 1
        if isinstance(item, Exception):
            raise item
        return str(item)

    def complete_json(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        self.json_calls.append(prompt)
        pool = self._json_responses if self._json_responses is not None else self._responses
        if pool is self._responses:
            idx_attr = "_idx"
        else:
            idx_attr = "_json_idx"

        idx = getattr(self, idx_attr)
        if idx >= len(pool):
            raise RuntimeError(
                f"MockProvider.complete_json out of responses (idx={idx})"
            )
        item = pool[idx]
        setattr(self, idx_attr, idx + 1)
        if isinstance(item, Exception):
            raise item
        return str(item)

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.OLLAMA

    @property
    def model_name(self) -> str:
        return self._mn


def _make_alert(
    src_ip: str = "192.168.56.1",
    signature: str = "ET WEB_SERVER SQL Injection Attempt",
) -> AlertRecord:
    return AlertRecord(
        timestamp_raw="2026-05-15T10:00:00Z",
        timestamp_display="10:00:00.000",
        timestamp_epoch=time.time(),
        severity_level=1,
        severity_label="critical",
        src_ip=src_ip,
        src_port="12345",
        dst_ip="172.18.0.3",
        dst_port="80",
        proto="TCP",
        signature=signature,
        signature_id=2010963,
        category="Web Application Attack",
        action="allowed",
        flow_id=42,
        app_proto="http",
        in_iface="br-test",
        raw_event={"http": {"url": "/sqli/?id=1' UNION SELECT user,password FROM users#"}},
    )


def _stub_tool(name: str = "stub_tool", returns: Any = None) -> ToolDefinition:
    """Build a tool that always returns a fixed value."""
    return ToolDefinition(
        name=name,
        description=f"Stub tool {name}",
        parameters_schema={
            "type": "object",
            "properties": {
                "x": {"type": "string", "description": "anything"},
            },
            "required": [],
        },
        function=lambda args: returns if returns is not None else {"echoed": args},
    )


def _empty_registry() -> ToolRegistry:
    return ToolRegistry()


def _registry_with_stub() -> ToolRegistry:
    r = ToolRegistry()
    r.register(_stub_tool("get_alert_history", returns={"prior_alerts": 7}))
    return r


def _final_answer_xml(
    classification: str = "true_positive",
    severity: str = "High",
    summary: str = "test summary",
    recommendation: str = "block_source_ip",
    reasoning: str = "test reasoning explaining classification",
    thought: str = "this is obvious",
) -> str:
    return f"""<thought>{thought}</thought>
<final_answer>
{{"classification": "{classification}", "severity": "{severity}", "summary": "{summary}", "recommendation": "{recommendation}", "reasoning": "{reasoning}"}}
</final_answer>"""


def _action_xml(
    action: str = "get_alert_history",
    action_input: str = '{"src_ip": "192.168.56.1"}',
    thought: str = "let me check history",
) -> str:
    return f"""<thought>{thought}</thought>
<action>{action}</action>
<action_input>{action_input}</action_input>"""


# ---------------------------------------------------------------------------
# XML parser tests
# ---------------------------------------------------------------------------

def test_extract_tags_basic() -> None:
    _section("XML parser: extract_tags basic")

    text = "<thought>hi</thought><action>foo</action><action_input>{}</action_input>"
    tags = _extract_tags(text)
    _assert(len(tags) == 3, "three tags extracted", str(tags))
    _assert(tags[0] == ("thought", "hi"), "thought first")
    _assert(tags[1] == ("action", "foo"), "action second")
    _assert(tags[2] == ("action_input", "{}"), "action_input third")


def test_extract_tags_multiline() -> None:
    _section("XML parser: multi-line tag content")

    text = """<thought>line1
line2</thought>
<final_answer>
{"a": 1}
</final_answer>"""
    tags = _extract_tags(text)
    _assert(len(tags) == 2, "two tags from multi-line")
    _assert("line1" in tags[0][1] and "line2" in tags[0][1], "thought includes both lines")


def test_extract_tags_strips_whitespace() -> None:
    _section("XML parser: strips whitespace inside tags")

    text = "<thought>   hi   </thought>"
    tags = _extract_tags(text)
    _assert(tags[0] == ("thought", "hi"), "whitespace stripped")


def test_extract_tags_ignores_unknown() -> None:
    _section("XML parser: unknown tags ignored")

    text = "<thought>hi</thought><banana>x</banana><final_answer>{}</final_answer>"
    tags = _extract_tags(text)
    names = [t[0] for t in tags]
    _assert("banana" not in names, "unknown <banana> not extracted")
    _assert("thought" in names and "final_answer" in names, "known tags extracted")


def test_find_first() -> None:
    _section("XML parser: _find_first")

    tags = [("thought", "a"), ("action", "x"), ("thought", "b")]
    _assert(_find_first(tags, "thought") == "a", "first thought")
    _assert(_find_first(tags, "action") == "x", "action found")
    _assert(_find_first(tags, "missing") is None, "missing returns None")


def test_extract_tags_empty_input() -> None:
    _section("XML parser: empty input")

    _assert(_extract_tags("") == [], "empty string -> empty list")
    _assert(_extract_tags(None) == [], "None -> empty list")


# ---------------------------------------------------------------------------
# System prompt assembly
# ---------------------------------------------------------------------------

def test_build_react_system_prompt_includes_sections() -> None:
    _section("System prompt: includes all major sections")

    registry = _registry_with_stub()
    prompt = _build_react_system_prompt(registry.to_prompt_block())
    _assert("CLASSIFICATION RULES" in prompt, "classification rules section")
    _assert("SEVERITY SCALE" in prompt, "severity scale section")
    _assert("RECOMMENDATIONS" in prompt, "recommendations section")
    _assert("AVAILABLE TOOLS" in prompt, "tools header section")
    _assert("OUTPUT FORMAT" in prompt, "output format section")
    _assert("WHEN TO USE TOOLS" in prompt, "tool-use guidance section")
    _assert("EXAMPLES" in prompt, "few-shot examples section")
    _assert("get_alert_history" in prompt, "tool name appears (from registry)")


# ---------------------------------------------------------------------------
# ReActAgent tests
# ---------------------------------------------------------------------------

def test_direct_final_answer_no_tool() -> None:
    _section("ReActAgent: direct final_answer (no tool)")

    provider = MockProvider([_final_answer_xml()])
    agent = ReActAgent(provider, _registry_with_stub(), max_iterations=3)
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "status complete", cls.status)
    _assert(cls.classification == "true_positive", "classification set")
    _assert(cls.severity == "High", "severity set")
    _assert(cls.recommendation == "block_source_ip", "recommendation set")
    _assert(cls.agent_mode == "react", "agent_mode marked react")
    _assert(cls.tool_calls == 0, "no tools used")
    _assert(cls.parse_failure_count == 0, "no parse failures")
    _assert(cls.reasoning_trace is not None and len(cls.reasoning_trace) == 1,
            "one reasoning step", str(cls.reasoning_trace))
    _assert(cls.reasoning_trace[0].action is None, "final step has no action")


def test_one_tool_call_then_final() -> None:
    _section("ReActAgent: one tool call then final")

    provider = MockProvider([
        _action_xml("get_alert_history", '{"src_ip": "192.168.56.1"}', "checking history"),
        _final_answer_xml(reasoning="based on history"),
    ])
    agent = ReActAgent(provider, _registry_with_stub(), max_iterations=3)
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "status complete", cls.status)
    _assert(cls.tool_calls == 1, "one tool call recorded")
    _assert(cls.parse_failure_count == 0, "no parse failures")
    _assert(len(cls.reasoning_trace) == 2, "two reasoning steps")
    _assert(cls.reasoning_trace[0].action == "get_alert_history", "first step action")
    _assert(cls.reasoning_trace[0].observation is not None, "tool observation captured")
    _assert(cls.reasoning_trace[1].action is None, "second step is final")


def test_two_tool_calls_then_final() -> None:
    _section("ReActAgent: two tool calls then final (within iteration cap)")

    registry = ToolRegistry()
    registry.register(_stub_tool("get_alert_history", returns={"prior": 5}))
    registry.register(_stub_tool("get_attack_pattern_stats", returns={"total": 22}))

    provider = MockProvider([
        _action_xml("get_alert_history", '{"src_ip": "10.0.0.1"}'),
        _action_xml("get_attack_pattern_stats", '{"attack_type": "SQLi"}', "now check stats"),
        _final_answer_xml(),
    ])
    agent = ReActAgent(provider, registry, max_iterations=3)
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "complete after 2 tools + final")
    _assert(cls.tool_calls == 2, "two tools recorded")
    _assert(len(cls.reasoning_trace) == 3, "three reasoning steps")


def test_parse_failure_then_retry_succeeds() -> None:
    _section("ReActAgent: parse failure then retry succeeds")

    provider = MockProvider([
        "garbage output, no tags",
        _final_answer_xml(),
    ])
    agent = ReActAgent(
        provider, _registry_with_stub(),
        max_iterations=3, max_retries_on_parse_fail=1,
    )
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "recovered after retry", cls.status)
    _assert(cls.parse_failure_count == 1, "one parse failure recorded")
    _assert(len(cls.reasoning_trace) == 2, "two reasoning steps incl. failed one")
    _assert(cls.reasoning_trace[0].parse_error is not None, "first step has parse_error")


def test_parse_failure_exhausts_retries_falls_back() -> None:
    _section("ReActAgent: parse failures exhaust retries -> single-shot fallback")

    provider = MockProvider(
        # ReAct rounds: 2 garbage outputs (initial + 1 retry)
        responses=["garbage 1", "garbage 2"],
        # Single-shot fallback then provides a clean JSON
        json_responses=[
            '{"classification": "likely_false_positive", "severity": "Low", '
            '"summary": "fallback verdict", "recommendation": "continue_monitoring", '
            '"reasoning": "fell back to single-shot after parse failures"}'
        ],
    )
    agent = ReActAgent(
        provider, _registry_with_stub(),
        max_iterations=3, max_retries_on_parse_fail=1,
    )
    cls = agent.classify(_make_alert())

    _assert(cls.status == "partial", "partial — fallback after react failures",
            cls.status)
    _assert(cls.parse_failure_count == 2, "both parse failures recorded",
            str(cls.parse_failure_count))
    _assert(cls.classification == "likely_false_positive", "fallback classification used")
    _assert(cls.agent_mode == "react", "still labeled react path")
    _assert(len(cls.reasoning_trace) == 2, "two failed steps in trace")


def test_action_input_not_json_is_parse_error() -> None:
    _section("ReActAgent: action_input not JSON -> parse_error")

    provider = MockProvider([
        # action with malformed JSON args
        "<thought>checking</thought><action>get_alert_history</action>"
        "<action_input>not valid json</action_input>",
        _final_answer_xml(),
    ])
    agent = ReActAgent(
        provider, _registry_with_stub(),
        max_iterations=3, max_retries_on_parse_fail=1,
    )
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "recovered after retry")
    _assert(cls.parse_failure_count == 1, "one parse failure")
    _assert(cls.tool_calls == 0, "no tool actually executed")


def test_unknown_tool_name_loop_continues() -> None:
    _section("ReActAgent: unknown tool name -> error observation, loop continues")

    provider = MockProvider([
        _action_xml("nonexistent_tool", '{"x": 1}', "calling unknown"),
        _final_answer_xml(),
    ])
    agent = ReActAgent(
        provider, _registry_with_stub(),
        max_iterations=3,
    )
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "loop continued to success")
    _assert(cls.tool_calls == 1, "tool call counted (even though tool was unknown)")
    _assert(cls.reasoning_trace[0].observation is not None, "error observation captured")
    _assert(
        "Unknown tool" in cls.reasoning_trace[0].observation,
        "observation reports unknown tool",
        cls.reasoning_trace[0].observation,
    )


def test_llm_call_raises_falls_back() -> None:
    _section("ReActAgent: LLM provider raises -> single-shot fallback")

    provider = MockProvider(
        responses=[RuntimeError("network down")],
        json_responses=[
            '{"classification": "true_positive", "severity": "Medium", '
            '"summary": "fallback verdict", "recommendation": "escalate_tier2", '
            '"reasoning": "fallback after LLM error"}'
        ],
    )
    agent = ReActAgent(provider, _registry_with_stub(), max_iterations=3)
    cls = agent.classify(_make_alert())

    _assert(cls.status == "partial", "partial after LLM error + fallback",
            cls.status)
    _assert(cls.severity == "Medium", "fallback verdict used")
    _assert(len(cls.reasoning_trace) == 1, "one step recording the LLM error")
    _assert(cls.reasoning_trace[0].parse_error is not None, "parse_error set on the failed step")


def test_iteration_cap_falls_back() -> None:
    _section("ReActAgent: iteration cap reached -> single-shot fallback")

    # Provider keeps returning action-only outputs forever
    actions = [_action_xml() for _ in range(10)]
    provider = MockProvider(
        responses=actions,
        json_responses=[
            '{"classification": "likely_false_positive", "severity": "Low", '
            '"summary": "fallback after iter cap", "recommendation": "continue_monitoring", '
            '"reasoning": "iteration cap hit"}'
        ],
    )
    agent = ReActAgent(provider, _registry_with_stub(), max_iterations=2)
    cls = agent.classify(_make_alert())

    _assert(cls.status == "partial", "partial after iter cap fallback")
    _assert(cls.tool_calls == 2, "tool called exactly max_iterations times",
            str(cls.tool_calls))
    _assert(len(cls.reasoning_trace) == 2, "trace length matches max_iterations")


def test_final_answer_validation_failure() -> None:
    _section("ReActAgent: final_answer with invalid classification -> parse_error")

    bad_final = """<thought>done</thought>
<final_answer>
{"classification": "totally_wrong_label", "severity": "High",
 "summary": "x", "recommendation": "block_source_ip", "reasoning": "y"}
</final_answer>"""

    provider = MockProvider(
        responses=[bad_final, _final_answer_xml()],
    )
    agent = ReActAgent(
        provider, _registry_with_stub(),
        max_iterations=3, max_retries_on_parse_fail=1,
    )
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "recovered after retry", cls.status)
    _assert(cls.parse_failure_count == 1, "validation failure counted")
    _assert(
        cls.reasoning_trace[0].parse_error is not None
        and "classification" in cls.reasoning_trace[0].parse_error.lower(),
        "parse_error mentions classification",
        cls.reasoning_trace[0].parse_error or "",
    )


def test_fallback_failure_returns_error_classification() -> None:
    _section("ReActAgent: fallback also fails -> error classification")

    provider = MockProvider(
        responses=["garbage 1", "garbage 2"],   # exhaust react retries
        json_responses=["not even valid json"],  # fallback also broken
    )
    agent = ReActAgent(
        provider, _registry_with_stub(),
        max_iterations=3, max_retries_on_parse_fail=1,
    )
    cls = agent.classify(_make_alert())

    _assert(cls.status == "error", "error status when fallback fails", cls.status)
    _assert(cls.classification == "", "no classification populated on error")
    _assert(cls.error is not None and "Fallback" in cls.error,
            "error message mentions fallback", cls.error or "")
    _assert(cls.agent_mode == "react", "still react path")


def test_empty_tool_registry_works() -> None:
    _section("ReActAgent: empty tool registry — direct final_answer still works")

    provider = MockProvider([_final_answer_xml()])
    agent = ReActAgent(provider, _empty_registry(), max_iterations=3)
    cls = agent.classify(_make_alert())

    _assert(cls.status == "complete", "completes without tools available")
    _assert(cls.tool_calls == 0, "no tools called")


def test_reasoning_trace_field_ordering() -> None:
    _section("ReActAgent: reasoning_trace iteration field is 1-indexed and ordered")

    provider = MockProvider([
        _action_xml(),
        _final_answer_xml(),
    ])
    agent = ReActAgent(provider, _registry_with_stub(), max_iterations=3)
    cls = agent.classify(_make_alert())

    _assert(cls.reasoning_trace[0].iteration == 1, "first step iteration=1")
    _assert(cls.reasoning_trace[1].iteration == 2, "second step iteration=2")


def test_alert_classification_passthrough_fields() -> None:
    _section("ReActAgent: AlertClassification pass-through fields populated")

    alert = _make_alert(src_ip="10.99.99.1")
    provider = MockProvider([_final_answer_xml()])
    agent = ReActAgent(provider, _registry_with_stub(), max_iterations=3)
    cls = agent.classify(alert)

    _assert(cls.src_ip == "10.99.99.1", "src_ip passed through")
    _assert(cls.signature == alert.signature, "signature passed through")
    _assert(cls.signature_id == alert.signature_id, "signature_id passed through")
    _assert(cls.dst_ip == alert.dst_ip, "dst_ip passed through")
    _assert(cls.alert_id == "42", "alert_id derived from flow_id")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    tests = [
        # XML parser
        test_extract_tags_basic,
        test_extract_tags_multiline,
        test_extract_tags_strips_whitespace,
        test_extract_tags_ignores_unknown,
        test_find_first,
        test_extract_tags_empty_input,
        # System prompt
        test_build_react_system_prompt_includes_sections,
        # ReAct loop
        test_direct_final_answer_no_tool,
        test_one_tool_call_then_final,
        test_two_tool_calls_then_final,
        test_parse_failure_then_retry_succeeds,
        test_parse_failure_exhausts_retries_falls_back,
        test_action_input_not_json_is_parse_error,
        test_unknown_tool_name_loop_continues,
        test_llm_call_raises_falls_back,
        test_iteration_cap_falls_back,
        test_final_answer_validation_failure,
        test_fallback_failure_returns_error_classification,
        test_empty_tool_registry_works,
        test_reasoning_trace_field_ordering,
        test_alert_classification_passthrough_fields,
    ]

    for t in tests:
        t()

    print(f"\n{'=' * 60}")
    total = _passed + _failed
    print(f"Results: {_passed}/{total} assertions passed")
    if _failed > 0:
        print(f"  {_failed} FAILED")
        return 1
    print("  All assertions PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
