"""
tool_registry.py - Tool registry for the agentic ReAct triage loop.

Provides ToolDefinition (metadata + validated callable wrapper) and
ToolRegistry (collection used by ReActAgent to discover and execute tools).

Tools are pure read functions over existing application state — they never
mutate state and have no external side effects. Each tool declares a
JSONSchema-lite parameter schema; the registry validates arguments before
invoking the underlying function and packages the result in a ToolResult.

Validation is hand-rolled (no jsonschema dependency) and supports the small
subset of JSONSchema we actually need: required fields, primitive type
checks, enum constraints, integer min/max, and default values.

Threading model:
    - register()  must be called only at app startup, before any classify()
                  call. Not thread-safe.
    - call()      is safe to invoke from any thread. Tool implementations
                  are themselves responsible for thread-safe data access.

Depends on: stdlib only.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ToolResult — uniform return shape for any tool invocation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolResult:
    """Result of a tool execution. Always returned (never raises).

    Fields:
        tool_name:    name of the tool that was invoked
        arguments:    the arguments dict as passed to the tool (post-validation
                      on success; raw args on validation failure)
        output:       the tool's return value on success; None on failure
        error:        human-readable error message on failure; None on success
        duration_ms:  wall-clock execution time including validation
    """
    tool_name: str
    arguments: Dict[str, Any]
    output: Any
    error: Optional[str] = None
    duration_ms: int = 0

    @property
    def succeeded(self) -> bool:
        return self.error is None

    def to_observation_json(self) -> str:
        """Serialize result for injection into the ReAct prompt as <observation>.

        On error: returns a small JSON object with "error" and "tool" fields so
        the model can see what went wrong and try a different action.

        On success: serializes output. Falls back to str() for any non-JSON-
        serializable values rather than raising.
        """
        if self.error is not None:
            return json.dumps({"error": self.error, "tool": self.tool_name})
        try:
            return json.dumps(self.output, default=str)
        except (TypeError, ValueError) as e:
            return json.dumps(
                {"error": f"Output not serialisable: {e}", "tool": self.tool_name}
            )


# ---------------------------------------------------------------------------
# ToolDefinition — metadata + validated callable
# ---------------------------------------------------------------------------

# Supported JSONSchema-lite types
_SUPPORTED_TYPES = {
    "string": str,
    "integer": int,
    "boolean": bool,
    "number": (int, float),
}


@dataclass(frozen=True)
class ToolDefinition:
    """Static metadata + executable function for one tool.

    parameters_schema follows a JSONSchema-lite shape::

        {
          "type": "object",
          "properties": {
            "src_ip":  {"type": "string",  "description": "..."},
            "hours":   {"type": "integer", "description": "...",
                        "default": 24, "minimum": 1, "maximum": 168},
            "attack":  {"type": "string",  "enum": ["SQLi", "XSS"], ...}
          },
          "required": ["src_ip"]
        }

    function takes a validated args dict and returns any JSON-serialisable
    value. It MUST be a pure read function — the registry contract assumes
    tools have no side effects.
    """
    name: str
    description: str
    parameters_schema: Dict[str, Any]
    function: Callable[[Dict[str, Any]], Any]

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_args(
        self, raw_args: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        """Apply defaults, check required fields, type/enum/range constraints.

        Returns:
            (validated_args, error_or_None). If error_or_None is non-None,
            validated_args is empty and the tool MUST NOT be invoked.
        """
        if not isinstance(raw_args, dict):
            return {}, (
                f"Arguments must be a JSON object, "
                f"got {type(raw_args).__name__}"
            )

        props: Dict[str, Dict[str, Any]] = self.parameters_schema.get("properties", {})
        required = set(self.parameters_schema.get("required", []))

        validated: Dict[str, Any] = {}

        for name, spec in props.items():
            if name in raw_args:
                value = raw_args[name]
                error = _check_value(name, value, spec)
                if error is not None:
                    return {}, error
                validated[name] = value
            elif name in required:
                return {}, f"Missing required argument '{name}'"
            elif "default" in spec:
                validated[name] = spec["default"]
            # else: optional field with no default — omit from validated args

        # Reject unknown args defensively. The model occasionally invents
        # parameters; surfacing the error in the observation lets it correct.
        unknown = sorted(set(raw_args) - set(props))
        if unknown:
            return {}, f"Unknown argument(s): {unknown}"

        return validated, None

    # ------------------------------------------------------------------
    # Prompt rendering
    # ------------------------------------------------------------------

    def to_prompt_description(self) -> str:
        """Format this tool for inclusion in the LLM system prompt.

        Output is compact, readable plain text — works on any LLM regardless
        of native function-calling support.
        """
        props: Dict[str, Dict[str, Any]] = self.parameters_schema.get("properties", {})
        required = set(self.parameters_schema.get("required", []))

        if not props:
            params_text = "  (no parameters)"
        else:
            lines = []
            for name, spec in props.items():
                req_marker = "" if name in required else "?"
                type_str = spec.get("type", "any")
                desc = spec.get("description", "")

                extras = []
                if "enum" in spec:
                    extras.append(f"one of {spec['enum']}")
                if "default" in spec:
                    extras.append(f"default {spec['default']}")
                if "minimum" in spec:
                    extras.append(f"min {spec['minimum']}")
                if "maximum" in spec:
                    extras.append(f"max {spec['maximum']}")
                extras_str = f" [{'; '.join(extras)}]" if extras else ""

                lines.append(f"  - {name}{req_marker}: {type_str}{extras_str} — {desc}")
            params_text = "\n".join(lines)

        return (
            f"Tool: {self.name}\n"
            f"  Description: {self.description}\n"
            f"  Parameters:\n{params_text}"
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def call(
        self,
        raw_args: Dict[str, Any],
        timeout_seconds: float = 5.0,  # advisory only; tools should be fast
    ) -> ToolResult:
        """Validate args and execute the underlying function.

        Always returns a ToolResult — exceptions are caught and packaged as
        error results so the agent loop never crashes mid-iteration.

        timeout_seconds is reserved for future use (subprocess-based tool
        isolation). Current in-process tools are expected to return in <100ms;
        the agent's higher-level total_budget_seconds is the real timeout.
        """
        start = time.monotonic()

        validated, error = self.validate_args(raw_args)
        if error is not None:
            return ToolResult(
                tool_name=self.name,
                arguments=raw_args,
                output=None,
                error=error,
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        try:
            output = self.function(validated)
        except Exception as e:  # noqa: BLE001 — defensive boundary
            log.exception("Tool %s raised: %s", self.name, e)
            return ToolResult(
                tool_name=self.name,
                arguments=validated,
                output=None,
                error=f"Tool execution error: {type(e).__name__}: {e}",
                duration_ms=int((time.monotonic() - start) * 1000),
            )

        return ToolResult(
            tool_name=self.name,
            arguments=validated,
            output=output,
            error=None,
            duration_ms=int((time.monotonic() - start) * 1000),
        )


# ---------------------------------------------------------------------------
# Internal: value-level validation
# ---------------------------------------------------------------------------

def _check_value(
    name: str, value: Any, spec: Dict[str, Any],
) -> Optional[str]:
    """Validate one value against its schema spec. Returns error message or None."""
    expected_type = spec.get("type")
    if expected_type and expected_type in _SUPPORTED_TYPES:
        py_type = _SUPPORTED_TYPES[expected_type]
        # bool is an int in Python — guard against bools sneaking through int check
        if expected_type == "integer" and isinstance(value, bool):
            return f"Argument '{name}' must be an integer, got bool"
        if not isinstance(value, py_type):
            return (
                f"Argument '{name}' must be {expected_type}, "
                f"got {type(value).__name__}"
            )

    enum = spec.get("enum")
    if enum is not None and value not in enum:
        return f"Argument '{name}' must be one of {enum}, got {value!r}"

    if isinstance(value, int) and not isinstance(value, bool):
        minimum = spec.get("minimum")
        if minimum is not None and value < minimum:
            return f"Argument '{name}' must be >= {minimum}, got {value}"
        maximum = spec.get("maximum")
        if maximum is not None and value > maximum:
            return f"Argument '{name}' must be <= {maximum}, got {value}"

    return None


# ---------------------------------------------------------------------------
# ToolRegistry — collection of available tools
# ---------------------------------------------------------------------------

class ToolRegistry:
    """Collection of available tools used by the ReAct agent.

    Lifecycle:
        1. Construct registry at app startup.
        2. Register each enabled tool via register().
        3. Pass the registry to ReActAgent.
        4. Agent calls get(), list_names(), to_prompt_block(), call() at
           runtime.

    Once startup registration is complete, the registry is read-only.
    """

    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}

    # ------------------------------------------------------------------
    # Mutation (startup-only)
    # ------------------------------------------------------------------

    def register(self, tool: ToolDefinition) -> None:
        """Register a tool. Raises ValueError if the name is already used."""
        if not tool.name:
            raise ValueError("Tool name must be non-empty")
        if tool.name in self._tools:
            raise ValueError(f"Tool '{tool.name}' is already registered")
        self._tools[tool.name] = tool
        log.info("Registered tool: %s", tool.name)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(name)

    def has(self, name: str) -> bool:
        return name in self._tools

    def list_names(self) -> List[str]:
        return sorted(self._tools)

    def count(self) -> int:
        return len(self._tools)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def call(
        self,
        name: str,
        raw_args: Dict[str, Any],
        timeout_seconds: float = 5.0,
    ) -> ToolResult:
        """Execute the named tool. Returns an error result if not found."""
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(
                tool_name=name,
                arguments=raw_args,
                output=None,
                error=(
                    f"Unknown tool '{name}'. "
                    f"Available: {self.list_names()}"
                ),
                duration_ms=0,
            )
        return tool.call(raw_args, timeout_seconds=timeout_seconds)

    # ------------------------------------------------------------------
    # Prompt rendering
    # ------------------------------------------------------------------

    def to_prompt_block(self) -> str:
        """Render all registered tools as a system-prompt block.

        Output is plain text — model-agnostic. Empty registry returns a
        placeholder string the agent prompt can include without breaking.
        """
        if not self._tools:
            return "(no tools available)"
        descriptions = [
            self._tools[name].to_prompt_description()
            for name in self.list_names()
        ]
        return "\n\n".join(descriptions)
