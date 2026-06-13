"""
models.py - Shared data contracts for the incident-based triage architecture.

All dataclasses used across multiple modules live here to keep the codebase flat
and avoid circular imports. Each class is either:
  - A pure value object (AlertClassification, ThreatActor, etc.)
  - A mutable domain object with documented lifecycle (Incident)
  - A serialisation target (IncidentReport)

Depends on:
  log_monitor.AlertRecord  - input data contract (not redefined here)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from log_monitor import AlertRecord


# ---------------------------------------------------------------------------
# ReasoningStep - one iteration of the ReAct loop (agentic mode)
# ---------------------------------------------------------------------------

@dataclass
class ReasoningStep:
    """One iteration of the ReAct loop captured for transparency.

    Used by the agentic ReAct path (ReActAgent). Single-shot path leaves
    AlertClassification.reasoning_trace as None.

    Captured for two purposes:
      1. Dashboard display - shows the marker / user how the agent reasoned.
      2. Evaluation - lets us audit when the agent uses tools and why.

    `source` distinguishes who issued the step:
      - "model"  -> emitted by the LLM during the ReAct loop
      - "system" -> automatic pre-enrichment done deterministically by the
                   agent before the LLM call (Option F hybrid policy).

    `iteration = 0` is the convention for system-driven enrichment steps;
    LLM-driven iterations start at 1.
    """
    iteration: int                          # 0 = system enrichment, 1+ = LLM round
    thought: str                            # model's stated reasoning
    action: Optional[str]                   # tool name, or None on final answer
    action_input: Optional[Dict]            # tool arguments (parsed JSON)
    observation: Optional[str]              # tool output JSON; None on final
    duration_ms: int                        # wall-clock for LLM + tool exec
    parse_error: Optional[str] = None       # set if this round's output failed to parse
    source: str = "model"                   # "model" | "system"


# ---------------------------------------------------------------------------
# Per-alert AI classification (Stage 1 output)
# ---------------------------------------------------------------------------

@dataclass
class AlertClassification:
    """AI-generated verdict for a single Suricata alert.

    Produced by ReportGenerator Stage 1 (single-shot path) OR by ReActAgent
    (react path). One per alert in the incident.
    """

    alert_id: str                    # derived from flow_id or UUID
    timestamp: str                   # original alert timestamp_raw
    classification: str              # "true_positive" | "likely_false_positive"
    severity: str                    # "critical" | "high" | "low" (matches Suricata P1/P2/P3 tiers)
    summary: str                     # one-line description
    recommendation: str              # "block_source_ip" | "escalate_tier2" | "continue_monitoring"
    reasoning: str                   # LLM's explanation

    # Pass-through fields for traceability
    signature: str
    signature_id: int
    category: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str

    # Rule-based fields (computed, not LLM-generated)
    attack_type: str = "Other"       # SQLi | XSS | Reconnaissance | ...
    confidence_score: float = 0.5    # 0.0 - 1.0, rule-based

    # Metadata
    status: str = "complete"         # "complete" | "error" | "partial"
    error: Optional[str] = None

    # ReAct agent metadata (None / defaults when produced by single-shot path)
    reasoning_trace: Optional[List[ReasoningStep]] = None
    agent_mode: str = "single_shot"  # "single_shot" | "react"
    parse_failure_count: int = 0     # ReAct-only: how many model outputs failed to parse
    tool_calls: int = 0              # ReAct-only: number of tools invoked


# ---------------------------------------------------------------------------
# Aggregated intelligence (for the report summary section)
# ---------------------------------------------------------------------------

@dataclass
class ThreatActor:
    """Aggregated view of a single source IP across one incident."""
    ip: str
    alert_count: int
    signatures: List[str]
    severity_labels: List[str]
    targeted_ports: List[str]


@dataclass
class SignatureHit:
    """Aggregated view of a single Suricata signature across one incident."""
    signature: str
    signature_id: int
    category: str
    hit_count: int
    severity_label: str
    source_ips: List[str]


# ---------------------------------------------------------------------------
# Incident - the domain object tracked by IncidentManager
# ---------------------------------------------------------------------------

@dataclass
class Incident:
    """A group of related alerts forming a single security incident.

    Lifecycle:
        1. Created with first alert via IncidentManager.process_alert()
        2. Additional alerts appended as long as time window holds
        3. Marked "closed" when time window expires (no new alerts)

    Incidents are mutated over their lifetime. All mutation happens inside
    IncidentManager under a lock, so individual fields are safe to read
    via snapshots.

    Note on `report_version`: starts at 0, incremented to 1 on first generation.
    A value of 0 means "no report generated yet".
    """

    incident_id: str                         # UUID4 string
    source_ip: str                           # attacker IP (grouping key)
    attack_type: Optional[str]               # only set in per_attack_type mode; else None
    alerts: List[AlertRecord] = field(default_factory=list)
    first_seen_epoch: float = 0.0            # earliest alert epoch
    last_seen_epoch: float = 0.0             # most recent alert epoch
    created_at: float = 0.0                  # when incident object was created (arrival time)
    last_activity_at: float = 0.0            # last time we received an alert (arrival time)
    status: str = "open"                     # "open" | "closed"
    report_version: int = 0                  # 0 = not yet generated; increments on each regenerate

    def add_alert(self, alert: AlertRecord, arrival_time: float) -> None:
        """Append an alert and update timestamps.

        arrival_time is the wall-clock time we received the alert.
        This is separate from alert.timestamp_epoch because clock skew
        or buffered delivery can produce out-of-order alert timestamps.
        We use arrival_time for window/debounce calculations so we're
        resilient to timestamp issues.
        """
        self.alerts.append(alert)
        self.last_activity_at = arrival_time

        # Track alert-reported times if usable, else fall back to arrival
        alert_epoch = alert.timestamp_epoch if alert.timestamp_epoch > 0 else arrival_time

        if self.first_seen_epoch == 0.0 or alert_epoch < self.first_seen_epoch:
            self.first_seen_epoch = alert_epoch
        if alert_epoch > self.last_seen_epoch:
            self.last_seen_epoch = alert_epoch

    @property
    def alert_count(self) -> int:
        return len(self.alerts)

    @property
    def first_seen_display(self) -> str:
        if self.first_seen_epoch <= 0:
            return "N/A"
        return datetime.fromtimestamp(
            self.first_seen_epoch, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")

    @property
    def last_seen_display(self) -> str:
        if self.last_seen_epoch <= 0:
            return "N/A"
        return datetime.fromtimestamp(
            self.last_seen_epoch, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------------------
# IncidentReport - serialised output matching the report template
# ---------------------------------------------------------------------------

@dataclass
class IncidentSummary:
    """Top-level summary section of an IncidentReport."""
    incident_id: str
    report_id: str                          # distinct UUID per generation
    report_version: str                     # "v1", "v2", ...
    incident_status: str                    # "open" | "closed"
    generated_at: str                       # ISO-8601 UTC
    last_updated_at: str                    # ISO-8601 UTC
    first_seen: str                         # human-readable
    last_seen: str                          # human-readable
    source_ip: str                          # the attacker
    total_alerts: int
    classification_counts: Dict[str, int]   # {"true_positive": N, "likely_false_positive": N, "error": N}
    detected_attacks: List[str]             # ["SQLi", "XSS", ...]
    overall_severity: str                   # "critical" | "high" | "low" (matches Suricata P1/P2/P3 tiers)
    overall_cvss_estimate: float            # 0.0 - 10.0, rule-based
    repeat_offender: bool                   # IP seen in prior incidents this session


@dataclass
class AlertAnalysis:
    """Per-alert analysis entry in the incident report."""
    alert_id: str
    attack_type_classified: str             # SQLi | XSS | Reconnaissance | Other
    payload_observed: str                   # the URL or signature
    payload_classification: str             # e.g. "reflected XSS", "UNION-based SQLi"
    likely_intent: str                      # LLM-inferred goal
    confidence_score: float                 # 0.0 - 1.0, rule-based

    # Stage 1 verdict mirrored here so downstream consumers (UI, evaluation)
    # can read per-alert TP/FP labels without having to re-derive them.
    # Default values kept for backward compatibility with existing test fixtures.
    classification: str = ""                # "true_positive" | "likely_false_positive" | "" (error)
    severity: str = ""                      # "critical" | "high" | "low" | "" (matches Suricata P1/P2/P3 tiers)
    recommendation: str = ""                # block_source_ip | escalate_tier2 | continue_monitoring
    classification_status: str = "complete" # complete | error

    # ReAct agent metadata (None / defaults when produced by single-shot path).
    # The reasoning_trace is what the dashboard renders in the timeline view -
    # without it, the agentic story is invisible to the user / marker.
    reasoning_trace: Optional[List[ReasoningStep]] = None
    agent_mode: str = "single_shot"         # "single_shot" | "react"
    parse_failure_count: int = 0            # ReAct-only
    tool_calls: int = 0                     # ReAct-only


@dataclass
class AlertExposure:
    """Per-alert exposure detail in the incident report."""
    alert_id: str
    affected_data_fields: List[str]
    cvss_estimate: float                    # rule-based from per-alert severity


@dataclass
class IncidentSummaryDescription:
    """AI narrative section of the incident report."""
    overview: str                           # LLM
    attack_vectors: List[str]               # LLM ["URL parameter", "form field"]
    overall_attack_stage: str               # LLM (MITRE tactic)
    ai_suggestions: List[str]               # LLM recommendations


@dataclass
class InformationExposure:
    """Exposure assessment section."""
    exposure_detected: bool                 # LLM
    exposure_types: List[str]               # LLM
    affected_systems: List[str]             # LLM
    data_sensitive_rating: str              # rule-based
    indicators_of_compromise: List[Dict[str, str]]  # rule-based, {"type": ..., "value": ...}


@dataclass
class InformationExposureDescription:
    """Narrative for the exposure section."""
    exposure_summary: str                   # LLM
    impact_assessment: str                  # LLM


@dataclass
class IncidentReport:
    """Complete incident report, serialisable to JSON.

    Mirrors the provided Incident Report Template with documented additions
    and removals. See docs/ARCHITECTURE.md for the rationale.
    """
    incident_summary: IncidentSummary
    alerts: List[Dict]                          # raw alert dicts (pass-through)
    incident_summary_description: IncidentSummaryDescription
    alert_analyses: List[AlertAnalysis]
    information_exposure: InformationExposure
    alert_exposures: List[AlertExposure]
    information_exposure_description: InformationExposureDescription

    # Generation metadata (not in template, useful for debugging)
    model_used: Optional[str] = None
    provider_type: Optional[str] = None
    generation_status: str = "complete"         # "complete" | "partial" | "error"
    generation_error: Optional[str] = None


# ---------------------------------------------------------------------------
# Attack type classification (rule-based, shared utility)
# ---------------------------------------------------------------------------

# SID ranges of our custom rule files (see lab/suricata/).
# These map deterministically to attack types regardless of msg wording,
# which avoids substring-match misses on signatures like
# "P2 - SQL Comment Sequence in URI" (no "SQLI" / "SQL INJECTION" token).
_CUSTOM_XSS_SID_RANGE = range(1002001, 1002059)    # xss_alerts.rules: 1002001-1002058
_CUSTOM_SQLI_SID_RANGE = range(1001001, 1001014)   # sqli_alerts.rules: 1001001-1001013


def extract_attack_type(signature: str, signature_id: Optional[int] = None) -> str:
    """Classify a Suricata alert signature into a broad attack type.

    Deterministic and fast; used for grouping decisions and report
    population. Runs before any LLM call.

    Resolution order:
      1. signature_id in a custom SID range (SQLi / XSS) -> definitive
      2. case-insensitive substring match on the signature msg
      3. "Other"

    Pass signature_id when available -- it is robust against msg-wording
    changes in the rule files. Falls back to substring matching for ET
    Open or unknown SIDs.

    Handles empty/None signatures gracefully (returns "Other").
    """
    if signature_id is not None:
        if signature_id in _CUSTOM_SQLI_SID_RANGE:
            return "SQLi"
        if signature_id in _CUSTOM_XSS_SID_RANGE:
            return "XSS"

    if not signature:
        return "Other"

    s = signature.upper()

    # Order matters - check specific before generic
    if "SQL INJECTION" in s or "SQLI" in s or "UNION SELECT" in s:
        return "SQLi"
    if "XSS" in s or "CROSS SITE SCRIPTING" in s or "CROSS-SITE SCRIPTING" in s:
        return "XSS"
    if "COMMAND INJECTION" in s or "RCE" in s or "REMOTE CODE" in s:
        return "CommandInjection"
    if "DIRECTORY TRAVERSAL" in s or "PATH TRAVERSAL" in s or "../" in s:
        return "PathTraversal"
    if "CSRF" in s or "CROSS SITE REQUEST" in s:
        return "CSRF"
    if "FILE INCLUSION" in s or "LFI" in s or "RFI" in s:
        return "FileInclusion"
    if "BRUTE FORCE" in s or "BRUTEFORCE" in s:
        return "BruteForce"
    if "SCAN" in s or "RECONNAISSANCE" in s or "RECON" in s:
        return "Reconnaissance"
    if "WEB_SERVER" in s or "WEB APPLICATION" in s:
        # Catch-all for web attacks we didn't specifically identify
        return "WebAttack"

    return "Other"