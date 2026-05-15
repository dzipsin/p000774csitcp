"""
report_serializer.py - Template-compliant serialization for IncidentReport.

Emits JSON matching the "Incident Report Template v1" specification (see
Incident Report Template v1.pdf at the project root). Used by:
    - ReportStorage.save() to write template-shape JSON to disk
    - Server.push_incident_report() to publish template-shape JSON to
      dashboard / WebSocket clients / /api/incidents endpoint

The internal IncidentReport dataclass remains unchanged. This module is a
pure serialization adapter — it reads the rich internal model and emits a
flatter, template-compliant dict. Field naming, section placement, type
coercion, and severity-level normalisation are all handled here.

Extras (fields present in the internal model but not required by the
template) are preserved in the output for the dashboard and evaluation
harness. The JSONSchema uses `additionalProperties: True` to permit them.

Public surface:
    TEMPLATE_V1_SCHEMA           the JSONSchema for the template
    to_template_v1(report)       -> dict (template-shape JSON)
    validate_template_v1(data)   -> None (raises jsonschema.ValidationError)

Depends on:
    jsonschema                   (added to requirements.txt in Phase 3.5)
    models.IncidentReport        + nested dataclasses
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    from jsonschema import validate as _jsonschema_validate
    from jsonschema import ValidationError as _ValidationError
    _JSONSCHEMA_AVAILABLE = True
except ImportError:  # pragma: no cover — covered by requirements.txt
    _JSONSCHEMA_AVAILABLE = False
    _ValidationError = Exception  # type: ignore[misc, assignment]

from models import IncidentReport

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Template v1 JSONSchema
#
# Mirrors the structure described in Incident Report Template v1.pdf.
# `additionalProperties: True` everywhere so our internal extras
# (incident_id, classification per alert, etc.) survive the schema check.
# ---------------------------------------------------------------------------

_VALID_SEVERITIES = ["Low", "Medium", "High"]

TEMPLATE_V1_SCHEMA: Dict[str, Any] = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "Incident Report Template v1",
    "type": "object",
    "required": [
        "incident_summary",
        "alerts",
        "incident_summary_description",
        "alert_analyses",
        "information_exposure",
        "alert_exposures",
        "information_exposure_description",
    ],
    "additionalProperties": True,
    "properties": {
        "incident_summary": {
            "type": "object",
            "required": [
                "report_id",
                "report_version",
                "generated_at",
                "last_updated_at",
                "detected_attacks",
                "overall_severity",
                "total_alerts",
                "repeat_offender",
            ],
            "additionalProperties": True,
            "properties": {
                "report_id": {"type": "string"},
                "report_version": {"type": "string"},
                "generated_at": {"type": "string"},
                "last_updated_at": {"type": "string"},
                "detected_attacks": {
                    "type": "array", "items": {"type": "string"},
                },
                "overall_severity": {"type": "string", "enum": _VALID_SEVERITIES},
                "total_alerts": {"type": "integer", "minimum": 0},
                "repeat_offender": {"type": "boolean"},
            },
        },
        "alerts": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "alert_id",
                    "event_timestamp",
                    "alert_msg",
                    "severity",
                    "source_ip",
                    "source_port",
                    "destination_ip",
                    "destination_port",
                    "targeted_endpoint",
                    "http_method",
                    "protocol",
                    "suricata_rule_id",
                ],
                "additionalProperties": True,
                "properties": {
                    "alert_id": {"type": "string"},
                    "event_timestamp": {"type": "string"},
                    "alert_msg": {"type": "string"},
                    "severity": {"type": "string", "enum": _VALID_SEVERITIES},
                    "source_ip": {"type": "string"},
                    "source_port": {"type": ["integer", "null"]},
                    "destination_ip": {"type": "string"},
                    "destination_port": {"type": ["integer", "null"]},
                    "targeted_endpoint": {"type": "string"},
                    "http_method": {"type": "string"},
                    "protocol": {"type": "string"},
                    "suricata_rule_id": {"type": "string"},
                },
            },
        },
        "incident_summary_description": {
            "type": "object",
            "required": [
                "overview",
                "attack_types_identified",
                "attack_vectors",
                "overall_attack_stage",
            ],
            "additionalProperties": True,
            "properties": {
                "overview": {"type": "string"},
                "attack_types_identified": {
                    "type": "array", "items": {"type": "string"},
                },
                "attack_vectors": {
                    "type": "array", "items": {"type": "string"},
                },
                "overall_attack_stage": {"type": "string"},
            },
        },
        "alert_analyses": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "alert_id",
                    "attack_type_classified",
                    "payload_observed",
                    "payload_classification",
                    "likely_intent",
                    "confidence_score",
                ],
                "additionalProperties": True,
                "properties": {
                    "alert_id": {"type": "string"},
                    "attack_type_classified": {"type": "string"},
                    "payload_observed": {"type": "string"},
                    "payload_classification": {"type": "string"},
                    "likely_intent": {"type": "string"},
                    "confidence_score": {
                        "type": "number", "minimum": 0.0, "maximum": 1.0,
                    },
                },
            },
        },
        "information_exposure": {
            "type": "object",
            "required": [
                "exposure_detected",
                "exposure_types",
                "affected_systems",
                "overall_cvss_estimate",
            ],
            "additionalProperties": True,
            "properties": {
                "exposure_detected": {"type": "boolean"},
                "exposure_types": {
                    "type": "array", "items": {"type": "string"},
                },
                "affected_systems": {
                    "type": "array", "items": {"type": "string"},
                },
                "overall_cvss_estimate": {
                    "type": "number", "minimum": 0.0, "maximum": 10.0,
                },
            },
        },
        "alert_exposures": {
            "type": "array",
            "items": {
                "type": "object",
                "required": [
                    "alert_id",
                    "affected_data_fields",
                    "cvss_estimate",
                ],
                "additionalProperties": True,
                "properties": {
                    "alert_id": {"type": "string"},
                    "affected_data_fields": {
                        "type": "array", "items": {"type": "string"},
                    },
                    "cvss_estimate": {
                        "type": "number", "minimum": 0.0, "maximum": 10.0,
                    },
                },
            },
        },
        "information_exposure_description": {
            "type": "object",
            "required": [
                "exposure_summary",
                "impact_assessment",
                "data_sensitive_rating",
                "indicators_of_compromise",
            ],
            "additionalProperties": True,
            "properties": {
                "exposure_summary": {"type": "string"},
                "impact_assessment": {"type": "string"},
                "data_sensitive_rating": {"type": "string"},
                "indicators_of_compromise": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["type", "value"],
                        "additionalProperties": True,
                        "properties": {
                            "type": {"type": "string"},
                            "value": {"type": "string"},
                        },
                    },
                },
                "ai_suggestions": {
                    "type": "array", "items": {"type": "string"},
                },
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_template_v1(data: Dict[str, Any]) -> None:
    """Validate that data matches TEMPLATE_V1_SCHEMA.

    Raises jsonschema.ValidationError on schema violation.

    No-op if jsonschema is not installed (shouldn't happen — added to
    requirements.txt — but defensive).
    """
    if not _JSONSCHEMA_AVAILABLE:
        log.warning("jsonschema not installed; skipping template v1 validation")
        return
    _jsonschema_validate(data, TEMPLATE_V1_SCHEMA)


# ---------------------------------------------------------------------------
# Helpers — type coercion and field mapping
# ---------------------------------------------------------------------------

# Map AlertRecord.severity_label (lowercase) -> template severity (capitalized).
# "critical" is collapsed to "High" because the project spec uses a 3-level
# scale (Low/Medium/High) per docs/AGENT_DESIGN.md §15 decision 11.
_SEVERITY_NORMALISE = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _normalise_severity(value: Any) -> str:
    """Coerce a severity label to the template enum.

    Empty or unknown values default to "Low" so the schema always validates.
    """
    if not value:
        return "Low"
    text = str(value).strip()
    # If already capitalized (Low/Medium/High), accept as-is.
    if text in _VALID_SEVERITIES:
        return text
    return _SEVERITY_NORMALISE.get(text.lower(), "Low")


def _coerce_port(value: Any) -> Optional[int]:
    """Coerce an AlertRecord port string ('12345' or '?') to integer or None."""
    if value is None:
        return None
    try:
        if isinstance(value, bool):  # bool is subclass of int — guard
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _endpoint_from_url(url: str) -> str:
    """Extract just the path portion of a URL for `targeted_endpoint`."""
    if not url:
        return ""
    try:
        # URLs from Suricata are relative ("/foo?bar=1"). urlparse handles both.
        parsed = urlparse(url if "://" in url else f"http://x{url}")
        return parsed.path or ""
    except Exception:
        return ""


def _build_alert_id(
    flow_id: Any, report_id: str, index: int,
) -> str:
    """Derive a stable alert_id.

    Prefers Suricata flow_id (stable, traceable). Falls back to
    "<report_id>_<index>" when flow_id is missing or zero.
    """
    try:
        fid = int(flow_id) if flow_id is not None else 0
    except (TypeError, ValueError):
        fid = 0
    if fid > 0:
        return str(fid)
    return f"{report_id}_{index:03d}"


# ---------------------------------------------------------------------------
# Section serialisers
# ---------------------------------------------------------------------------

def _serialise_alerts(
    raw_alerts: List[Dict[str, Any]],
    report_id: str,
) -> List[Dict[str, Any]]:
    """Convert internal alert dicts (AlertRecord.to_dict) -> template alert objects.

    Internal field names (src_ip, dst_ip, signature, signature_id, proto,
    severity_label, raw_event.http.*, etc.) are mapped to template names
    (source_ip, destination_ip, alert_msg, suricata_rule_id, protocol,
    severity, targeted_endpoint, http_method).
    """
    out: List[Dict[str, Any]] = []
    for i, raw in enumerate(raw_alerts):
        if not isinstance(raw, dict):
            continue

        # http_url / http_method are flattened by AlertRecord.to_dict() into
        # top-level keys; fall back to a nested "http" / "raw_event.http"
        # block only when callers pass an unflatten'd dict.
        http_url = raw.get("http_url", "")
        http_method = raw.get("http_method", "")
        if not http_url and not http_method:
            nested = raw.get("http")
            if not isinstance(nested, dict):
                nested = (raw.get("raw_event") or {}).get("http") if isinstance(
                    raw.get("raw_event"), dict,
                ) else {}
            if isinstance(nested, dict):
                http_url = nested.get("url", "") or http_url
                http_method = nested.get("http_method", "") or http_method

        # App-layer protocol takes precedence over transport (template
        # examples are "HTTP, HTTPS").
        app_proto = str(raw.get("app_proto", "") or "").upper()
        transport_proto = str(raw.get("proto", "") or "").upper()
        protocol = app_proto or transport_proto

        out.append({
            "alert_id": _build_alert_id(raw.get("flow_id"), report_id, i),
            "event_timestamp": str(raw.get("timestamp_raw", "") or ""),
            "alert_msg": str(raw.get("signature", "") or ""),
            "severity": _normalise_severity(raw.get("severity_label")),
            "source_ip": str(raw.get("src_ip", "") or ""),
            "source_port": _coerce_port(raw.get("src_port")),
            "destination_ip": str(raw.get("dst_ip", "") or ""),
            "destination_port": _coerce_port(raw.get("dst_port")),
            "targeted_endpoint": _endpoint_from_url(str(http_url or "")),
            "http_method": str(http_method or ""),
            "protocol": protocol,
            "suricata_rule_id": str(raw.get("signature_id", "") or ""),
            # Preserve a few internal fields the dashboard already reads.
            # These are template "extras" — additionalProperties allows them.
            "_internal": {
                "src_port_raw": raw.get("src_port"),
                "dst_port_raw": raw.get("dst_port"),
                "category": raw.get("category"),
                "action": raw.get("action"),
                "flow_id": raw.get("flow_id"),
            },
        })
    return out


def _serialise_incident_summary(report: IncidentReport) -> Dict[str, Any]:
    s = report.incident_summary
    return {
        "report_id": s.report_id,
        "report_version": s.report_version,
        "generated_at": s.generated_at,
        "last_updated_at": s.last_updated_at,
        "detected_attacks": list(s.detected_attacks or []),
        "overall_severity": _normalise_severity(s.overall_severity),
        "total_alerts": int(s.total_alerts or 0),
        "repeat_offender": bool(s.repeat_offender),
        # Extras (allowed via additionalProperties)
        "incident_id": s.incident_id,
        "incident_status": s.incident_status,
        "first_seen": s.first_seen,
        "last_seen": s.last_seen,
        "source_ip": s.source_ip,
        "classification_counts": dict(s.classification_counts or {}),
        "overall_cvss_estimate": float(s.overall_cvss_estimate or 0.0),
    }


def _serialise_summary_description(report: IncidentReport) -> Dict[str, Any]:
    d = report.incident_summary_description
    # attack_types_identified duplicates detected_attacks (template wants
    # both — top-level for headline, here for narrative parity).
    return {
        "overview": d.overview or "",
        "attack_types_identified": list(report.incident_summary.detected_attacks or []),
        "attack_vectors": list(d.attack_vectors or []),
        "overall_attack_stage": d.overall_attack_stage or "",
        # Note: template puts ai_suggestions under information_exposure_description,
        # not here. We retain the internal copy as an extra for the dashboard.
        "ai_suggestions": list(d.ai_suggestions or []),
    }


def _serialise_alert_analyses(
    report: IncidentReport,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for a in report.alert_analyses:
        analysis: Dict[str, Any] = {
            "alert_id": a.alert_id,
            "attack_type_classified": a.attack_type_classified or "unknown",
            "payload_observed": a.payload_observed or "",
            "payload_classification": a.payload_classification or "",
            "likely_intent": a.likely_intent or "",
            "confidence_score": float(a.confidence_score or 0.0),
            # Extras — Stage 1 verdict mirror
            "classification": a.classification,
            "severity": a.severity,
            "recommendation": a.recommendation,
            "classification_status": a.classification_status,
            # ReAct agent metadata (extras — allowed via additionalProperties)
            "agent_mode": getattr(a, "agent_mode", "single_shot"),
            "parse_failure_count": int(getattr(a, "parse_failure_count", 0) or 0),
            "tool_calls": int(getattr(a, "tool_calls", 0) or 0),
        }
        # Reasoning trace: serialise to a list of plain dicts if present.
        trace = getattr(a, "reasoning_trace", None)
        if trace:
            analysis["reasoning_trace"] = [
                {
                    "iteration": step.iteration,
                    "thought": step.thought,
                    "action": step.action,
                    "action_input": step.action_input,
                    "observation": step.observation,
                    "duration_ms": step.duration_ms,
                    "parse_error": step.parse_error,
                }
                for step in trace
            ]
        else:
            analysis["reasoning_trace"] = None
        out.append(analysis)
    return out


def _serialise_information_exposure(report: IncidentReport) -> Dict[str, Any]:
    e = report.information_exposure
    return {
        "exposure_detected": bool(e.exposure_detected),
        "exposure_types": list(e.exposure_types or []),
        "affected_systems": list(e.affected_systems or []),
        # Template places overall_cvss_estimate here; we duplicate from summary.
        "overall_cvss_estimate": float(
            report.incident_summary.overall_cvss_estimate or 0.0,
        ),
        # Internal copies retained as extras
        "data_sensitive_rating": e.data_sensitive_rating,
        "indicators_of_compromise": list(e.indicators_of_compromise or []),
    }


def _serialise_alert_exposures(
    report: IncidentReport,
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for ae in report.alert_exposures:
        out.append({
            "alert_id": ae.alert_id,
            "affected_data_fields": list(ae.affected_data_fields or []),
            "cvss_estimate": float(ae.cvss_estimate or 0.0),
        })
    return out


def _serialise_exposure_description(report: IncidentReport) -> Dict[str, Any]:
    ed = report.information_exposure_description
    ie = report.information_exposure
    isd = report.incident_summary_description
    return {
        "exposure_summary": ed.exposure_summary or "",
        "impact_assessment": ed.impact_assessment or "",
        # Template duplicates these from information_exposure.
        "data_sensitive_rating": ie.data_sensitive_rating or "unknown",
        "indicators_of_compromise": list(ie.indicators_of_compromise or []),
        # Template duplicates ai_suggestions from incident_summary_description.
        "ai_suggestions": list(isd.ai_suggestions or []),
    }


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------

def to_template_v1(report: IncidentReport) -> Dict[str, Any]:
    """Serialise an IncidentReport to a template-v1-compliant dict.

    Always returns a dict — never raises on missing/malformed internal
    data. Use validate_template_v1() to schema-check the output.

    Internal extras (incident_id, classification per alert, reasoning
    trace from ReActAgent, etc.) are preserved as additional fields. The
    template schema permits additionalProperties everywhere.
    """
    if report is None:
        raise ValueError("Cannot serialise None report")

    payload: Dict[str, Any] = {
        "incident_summary": _serialise_incident_summary(report),
        "alerts": _serialise_alerts(
            report.alerts or [],
            report.incident_summary.report_id,
        ),
        "incident_summary_description": _serialise_summary_description(report),
        "alert_analyses": _serialise_alert_analyses(report),
        "information_exposure": _serialise_information_exposure(report),
        "alert_exposures": _serialise_alert_exposures(report),
        "information_exposure_description": _serialise_exposure_description(report),
        # Generation metadata as a top-level extra (not in template).
        "_generation_metadata": {
            "model_used": report.model_used,
            "provider_type": report.provider_type,
            "generation_status": report.generation_status,
            "generation_error": report.generation_error,
        },
    }
    return payload
