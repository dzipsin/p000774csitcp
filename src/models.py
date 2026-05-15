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
# Per-alert AI classification (Stage 1 output)
# ---------------------------------------------------------------------------

@dataclass
class AlertClassification:
    """AI-generated verdict for a single Suricata alert.

    Produced by ReportGenerator Stage 1. One per alert in the incident.
    """

    alert_id: str                    # derived from flow_id or UUID
    timestamp: str                   # original alert timestamp_raw
    classification: str              # "true_positive" | "likely_false_positive"
    severity: str                    # "Low" | "Medium" | "High"
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
    status: str = "complete"         # "complete" | "error"
    error: Optional[str] = None


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
# Incident — the domain object tracked by IncidentManager
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
# IncidentReport — serialised output matching the report template
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
    overall_severity: str                   # "Low" | "Medium" | "High"
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
    severity: str = ""                      # "Low" | "Medium" | "High" | ""
    recommendation: str = ""                # block_source_ip | escalate_tier2 | continue_monitoring
    classification_status: str = "complete" # complete | error


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

def extract_attack_type(signature: str) -> str:
    """Classify a Suricata alert signature into a broad attack type.

    This is deterministic and fast, used for grouping decisions and report
    population. Runs before any LLM call.

    Handles empty/None signatures gracefully (returns "Other").
    Case-insensitive matching.
    """
    if not signature:
        return "Other"

    s = signature.upper()

    # Order matters — check specific before generic
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