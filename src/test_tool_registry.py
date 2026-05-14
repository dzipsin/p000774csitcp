"""
test_tool_registry.py - Manual test harness for tool_registry.

Follows the existing project test style: plain Python script with manual
assertions, no pytest. Run with:

    python src/test_tool_registry.py

Covers ToolResult, ToolDefinition (validation, prompt rendering, call),
and ToolRegistry (register, lookup, call, prompt block).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make src/ imports work from anywhere
sys.path.insert(0, str(Path(__file__).parent))

from tool_registry import ToolDefinition, ToolRegistry, ToolResult


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
# Reusable fixtures
# ---------------------------------------------------------------------------

def _echo_tool() -> ToolDefinition:
    """Tool that echoes its validated arguments."""
    return ToolDefinition(
        name="echo",
        description="Returns its arguments verbatim.",
        parameters_schema={
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "Text to echo back.",
                },
                "count": {
                    "type": "integer",
                    "description": "How many times.",
                    "default": 1,
                    "minimum": 1,
                    "maximum": 10,
                },
            },
            "required": ["message"],
        },
        function=lambda args: dict(args),
    )


def _enum_tool() -> ToolDefinition:
    """Tool with an enum-constrained parameter."""
    return ToolDefinition(
        name="pick_colour",
        description="Pick a colour from an allowed list.",
        parameters_schema={
            "type": "object",
            "properties": {
                "colour": {
                    "type": "string",
                    "description": "Allowed colour.",
                    "enum": ["red", "green", "blue"],
                },
            },
            "required": ["colour"],
        },
        function=lambda args: {"chose": args["colour"]},
    )


def _raising_tool() -> ToolDefinition:
    """Tool whose function always raises — exercises error path."""
    def _explode(args):  # noqa: ARG001
        raise RuntimeError("intentional test failure")

    return ToolDefinition(
        name="boom",
        description="Always raises.",
        parameters_schema={"type": "object", "properties": {}, "required": []},
        function=_explode,
    )


def _noparams_tool() -> ToolDefinition:
    """Tool with no parameters at all."""
    return ToolDefinition(
        name="now",
        description="Returns a fixed value.",
        parameters_schema={"type": "object", "properties": {}, "required": []},
        function=lambda args: {"timestamp": "fixed-for-test"},  # noqa: ARG005
    )


# ---------------------------------------------------------------------------
# ToolResult
# ---------------------------------------------------------------------------

def test_tool_result_succeeded() -> None:
    _section("ToolResult.succeeded")

    ok = ToolResult(tool_name="t", arguments={}, output={"a": 1})
    _assert(ok.succeeded is True, "success path")

    err = ToolResult(tool_name="t", arguments={}, output=None, error="boom")
    _assert(err.succeeded is False, "error path")


def test_tool_result_observation_json() -> None:
    _section("ToolResult.to_observation_json")

    ok = ToolResult(
        tool_name="t",
        arguments={"x": 1},
        output={"prior_alerts": 5, "ips": ["a", "b"]},
    )
    parsed = json.loads(ok.to_observation_json())
    _assert(parsed == {"prior_alerts": 5, "ips": ["a", "b"]}, "serialises success output")

    err = ToolResult(tool_name="t", arguments={}, output=None, error="parse failed")
    parsed_err = json.loads(err.to_observation_json())
    _assert(parsed_err.get("error") == "parse failed", "serialises error as JSON")
    _assert(parsed_err.get("tool") == "t", "error JSON includes tool name")

    class Unserialisable:
        pass

    weird = ToolResult(tool_name="t", arguments={}, output=Unserialisable())
    # default=str fallback in to_observation_json should let it succeed
    raw = weird.to_observation_json()
    _assert(isinstance(raw, str) and len(raw) > 0, "non-serialisable output handled")


# ---------------------------------------------------------------------------
# ToolDefinition.validate_args
# ---------------------------------------------------------------------------

def test_validate_required_missing() -> None:
    _section("validate_args: required field missing")

    tool = _echo_tool()
    validated, err = tool.validate_args({})
    _assert(err is not None and "message" in err, "missing 'message' rejected", err)


def test_validate_default_applied() -> None:
    _section("validate_args: default applied")

    tool = _echo_tool()
    validated, err = tool.validate_args({"message": "hi"})
    _assert(err is None, "validates", err or "")
    _assert(validated.get("count") == 1, "default count=1 applied", str(validated))


def test_validate_explicit_overrides_default() -> None:
    _section("validate_args: explicit overrides default")

    tool = _echo_tool()
    validated, err = tool.validate_args({"message": "hi", "count": 5})
    _assert(err is None, "validates", err or "")
    _assert(validated.get("count") == 5, "count=5 preserved", str(validated))


def test_validate_wrong_type_string_int() -> None:
    _section("validate_args: wrong type (int where string expected)")

    tool = _echo_tool()
    _, err = tool.validate_args({"message": 42})
    _assert(err is not None and "string" in err, "rejects int for string field", err)


def test_validate_bool_for_int_field() -> None:
    _section("validate_args: bool rejected for integer field")

    tool = _echo_tool()
    _, err = tool.validate_args({"message": "hi", "count": True})
    _assert(err is not None and "integer" in err, "rejects bool for integer field", err)


def test_validate_int_below_minimum() -> None:
    _section("validate_args: integer below minimum")

    tool = _echo_tool()
    _, err = tool.validate_args({"message": "hi", "count": 0})
    _assert(err is not None and "1" in err, "rejects below minimum", err)


def test_validate_int_above_maximum() -> None:
    _section("validate_args: integer above maximum")

    tool = _echo_tool()
    _, err = tool.validate_args({"message": "hi", "count": 999})
    _assert(err is not None and "10" in err, "rejects above maximum", err)


def test_validate_enum_violation() -> None:
    _section("validate_args: enum violation")

    tool = _enum_tool()
    _, err = tool.validate_args({"colour": "purple"})
    _assert(
        err is not None and "purple" in err.lower(),
        "rejects out-of-enum value",
        err,
    )


def test_validate_enum_ok() -> None:
    _section("validate_args: enum allowed value")

    tool = _enum_tool()
    validated, err = tool.validate_args({"colour": "green"})
    _assert(err is None and validated["colour"] == "green", "accepts valid enum", err or "")


def test_validate_unknown_arg_rejected() -> None:
    _section("validate_args: unknown argument rejected")

    tool = _echo_tool()
    _, err = tool.validate_args({"message": "hi", "wat": "no"})
    _assert(err is not None and "wat" in err, "rejects unknown argument", err)


def test_validate_non_dict_args() -> None:
    _section("validate_args: non-dict input rejected")

    tool = _echo_tool()
    _, err = tool.validate_args("not a dict")  # type: ignore[arg-type]
    _assert(err is not None and "object" in err, "rejects non-dict input", err)


# ---------------------------------------------------------------------------
# ToolDefinition.call
# ---------------------------------------------------------------------------

def test_call_success() -> None:
    _section("call: success path")

    tool = _echo_tool()
    result = tool.call({"message": "hello", "count": 3})

    _assert(result.succeeded, "result.succeeded", result.error or "")
    _assert(
        result.output == {"message": "hello", "count": 3},
        "output matches input args",
        str(result.output),
    )
    _assert(result.duration_ms >= 0, "duration recorded")


def test_call_validation_failure() -> None:
    _section("call: validation failure returns ToolResult, does not raise")

    tool = _echo_tool()
    result = tool.call({})  # missing required 'message'

    _assert(not result.succeeded, "marked failed")
    _assert(
        result.error is not None and "message" in result.error,
        "error mentions missing field",
        result.error or "",
    )
    _assert(result.output is None, "no output on failure")


def test_call_tool_exception_caught() -> None:
    _section("call: tool function exception caught")

    tool = _raising_tool()
    result = tool.call({})

    _assert(not result.succeeded, "exception turns into failure")
    _assert(
        result.error is not None and "RuntimeError" in result.error,
        "error names exception type",
        result.error or "",
    )
    _assert(
        result.error is not None and "intentional" in result.error,
        "error includes original message",
        result.error or "",
    )


def test_call_no_params() -> None:
    _section("call: no-param tool")

    tool = _noparams_tool()
    result = tool.call({})

    _assert(result.succeeded, "succeeds", result.error or "")
    _assert(result.output is not None, "output produced", str(result.output))


# ---------------------------------------------------------------------------
# ToolDefinition.to_prompt_description
# ---------------------------------------------------------------------------

def test_prompt_description_required_optional() -> None:
    _section("to_prompt_description: marks required vs optional")

    tool = _echo_tool()
    rendered = tool.to_prompt_description()

    _assert("message:" in rendered, "shows required param without ? marker")
    _assert("count?:" in rendered, "shows optional param with ? marker")
    _assert("default 1" in rendered, "shows default value")
    _assert("min 1" in rendered, "shows minimum")
    _assert("max 10" in rendered, "shows maximum")


def test_prompt_description_enum() -> None:
    _section("to_prompt_description: enum")

    tool = _enum_tool()
    rendered = tool.to_prompt_description()
    _assert("red" in rendered and "green" in rendered and "blue" in rendered,
            "lists enum values")


def test_prompt_description_no_params() -> None:
    _section("to_prompt_description: no parameters")

    tool = _noparams_tool()
    rendered = tool.to_prompt_description()
    _assert("no parameters" in rendered, "states no parameters")


# ---------------------------------------------------------------------------
# ToolRegistry
# ---------------------------------------------------------------------------

def test_registry_register_and_lookup() -> None:
    _section("ToolRegistry: register / get / has / list / count")

    registry = ToolRegistry()
    _assert(registry.count() == 0, "starts empty")

    echo = _echo_tool()
    registry.register(echo)
    _assert(registry.count() == 1, "count after register")
    _assert(registry.has("echo"), "has() finds it")
    _assert(registry.get("echo") is echo, "get() returns the registered instance")
    _assert(registry.list_names() == ["echo"], "list_names sorted")

    enum_tool = _enum_tool()
    registry.register(enum_tool)
    _assert(
        registry.list_names() == ["echo", "pick_colour"],
        "names sorted across multiple tools",
        str(registry.list_names()),
    )


def test_registry_register_duplicate_rejected() -> None:
    _section("ToolRegistry: duplicate registration rejected")

    registry = ToolRegistry()
    registry.register(_echo_tool())
    try:
        registry.register(_echo_tool())
        _assert(False, "should have raised ValueError")
    except ValueError as e:
        _assert("already registered" in str(e).lower(), "raises ValueError with hint",
                str(e))


def test_registry_register_empty_name_rejected() -> None:
    _section("ToolRegistry: empty name rejected")

    registry = ToolRegistry()
    bad = ToolDefinition(
        name="",
        description="x",
        parameters_schema={"type": "object", "properties": {}, "required": []},
        function=lambda a: a,
    )
    try:
        registry.register(bad)
        _assert(False, "should have raised ValueError")
    except ValueError as e:
        _assert("non-empty" in str(e).lower(), "rejects empty name", str(e))


def test_registry_call_unknown_tool() -> None:
    _section("ToolRegistry: calling unknown tool returns error result")

    registry = ToolRegistry()
    registry.register(_echo_tool())

    result = registry.call("does_not_exist", {})
    _assert(not result.succeeded, "marked failed")
    _assert(
        result.error is not None and "Unknown tool" in result.error,
        "error mentions unknown tool",
        result.error or "",
    )
    _assert(
        result.error is not None and "echo" in result.error,
        "error lists available tools",
        result.error or "",
    )


def test_registry_call_dispatches() -> None:
    _section("ToolRegistry: dispatches to registered tool")

    registry = ToolRegistry()
    registry.register(_echo_tool())

    result = registry.call("echo", {"message": "ok"})
    _assert(result.succeeded, "tool ran", result.error or "")
    _assert(
        result.output == {"message": "ok", "count": 1},
        "default applied through registry path",
        str(result.output),
    )


def test_registry_prompt_block_empty() -> None:
    _section("ToolRegistry.to_prompt_block: empty registry")

    registry = ToolRegistry()
    block = registry.to_prompt_block()
    _assert("no tools" in block, "placeholder text for empty registry")


def test_registry_prompt_block_multiple() -> None:
    _section("ToolRegistry.to_prompt_block: multiple tools")

    registry = ToolRegistry()
    registry.register(_echo_tool())
    registry.register(_enum_tool())
    block = registry.to_prompt_block()

    _assert("Tool: echo" in block, "includes echo tool")
    _assert("Tool: pick_colour" in block, "includes pick_colour tool")
    _assert(
        block.index("Tool: echo") < block.index("Tool: pick_colour"),
        "tools rendered in sorted order",
    )


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    tests = [
        test_tool_result_succeeded,
        test_tool_result_observation_json,
        test_validate_required_missing,
        test_validate_default_applied,
        test_validate_explicit_overrides_default,
        test_validate_wrong_type_string_int,
        test_validate_bool_for_int_field,
        test_validate_int_below_minimum,
        test_validate_int_above_maximum,
        test_validate_enum_violation,
        test_validate_enum_ok,
        test_validate_unknown_arg_rejected,
        test_validate_non_dict_args,
        test_call_success,
        test_call_validation_failure,
        test_call_tool_exception_caught,
        test_call_no_params,
        test_prompt_description_required_optional,
        test_prompt_description_enum,
        test_prompt_description_no_params,
        test_registry_register_and_lookup,
        test_registry_register_duplicate_rejected,
        test_registry_register_empty_name_rejected,
        test_registry_call_unknown_tool,
        test_registry_call_dispatches,
        test_registry_prompt_block_empty,
        test_registry_prompt_block_multiple,
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
