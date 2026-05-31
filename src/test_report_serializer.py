"""
test_report_serializer.py - Manual test harness for report_serializer.

Plain Python script with manual assertions (no pytest). Run with:

    python src/test_report_serializer.py

Covers:
  - Helper coercion (severity normalisation, port coercion, endpoint
    extraction, alert_id derivation)
  - Per-section serialisers
  - Full round-trip: IncidentReport -> template dict -> schema validate
  - Schema rejects: missing required field, bad type, bad enum
  - Additional properties (our extras) survive validation
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Make src/ imports work from anywhere
sys.path.insert(0, str(Path(__file__).parent))

from log_monitor import AlertRecord
from models import (
    AlertAnalysis,
    AlertExposure,
    IncidentReport,
    IncidentSummary,
    IncidentSummaryDescription,
    InformationExposure,
    InformationExposureDescription,
)
from report_serializer import (
    TEMPLATE_V1_SCHEMA,
    _build_alert_id,
    _coerce_port,
    _endpoint_from_url,
    _normalise_severity,
    to_template_v1,
    validate_template_v1,
)

try:
    from jsonschema import ValidationError
except ImportError:
    ValidationError = Exception  # type: ignore[misc, assignment]


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

def _make_alert_record(
    src_ip: str = "192.168.56.1",
    signature: str = "ET WEB_SERVER SQL Injection Attempt",
    http_url: str = "/vulnerabilities/sqli/?id=1",
    http_method: str = "GET",
    severity_label: str = "high",
) -> AlertRecord:
    return AlertRecord(
        timestamp_raw="2026-05-15T10:00:00Z",
        timestamp_display="10:00:00.000",
        timestamp_epoch=time.time(),
        severity_level=2,
        severity_label=severity_label,
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
        raw_event={"http": {"url": http_url, "http_method": http_method}},
    )


def _make_minimal_report(
    alert_records: List[AlertRecord],
    detected_attacks: List[str] = None,
    overall_severity: str = "critical",
    repeat_offender: bool = False,
) -> IncidentReport:
    detected_attacks = detected_attacks if detected_attacks is not None else ["SQLi"]
    return IncidentReport(
        incident_summary=IncidentSummary(
            incident_id="abc12345-test",
            report_id="rep-xyz-001",
            report_version="v1",
            incident_status="closed",
            generated_at="2026-05-15T10:05:00+00:00",
            last_updated_at="2026-05-15T10:05:00+00:00",
            first_seen="2026-05-15 10:00:00 UTC",
            last_seen="2026-05-15 10:04:30 UTC",
            source_ip="192.168.56.1",
            total_alerts=len(alert_records),
            classification_counts={"true_positive": 1, "likely_false_positive": 0, "error": 0},
            detected_attacks=detected_attacks,
            overall_severity=overall_severity,
            overall_cvss_estimate=7.5,
            repeat_offender=repeat_offender,
        ),
        alerts=[a.to_dict() for a in alert_records],
        incident_summary_description=IncidentSummaryDescription(
            overview="A clear SQLi attack from a single source IP.",
            attack_vectors=["URL parameter"],
            overall_attack_stage="Initial Access",
            ai_suggestions=["Block source IP", "Review WAF rules"],
        ),
        alert_analyses=[
            AlertAnalysis(
                alert_id=str(a.flow_id) if a.flow_id else "rep-xyz-001_000",
                attack_type_classified="SQLi",
                payload_observed=a.raw_event.get("http", {}).get("url", ""),
                payload_classification="reflected SQLi",
                likely_intent="database extraction",
                confidence_score=0.85,
                classification="true_positive",
                severity="critical",
                recommendation="block_source_ip",
                classification_status="complete",
            )
            for a in alert_records
        ],
        information_exposure=InformationExposure(
            exposure_detected=True,
            exposure_types=["database contents"],
            affected_systems=["web application", "database server"],
            data_sensitive_rating="confidential",
            indicators_of_compromise=[
                {"type": "ip", "value": "192.168.56.1"},
                {"type": "signature", "value": "ET WEB_SERVER SQL Injection Attempt"},
            ],
        ),
        alert_exposures=[
            AlertExposure(
                alert_id=str(a.flow_id) if a.flow_id else "rep-xyz-001_000",
                affected_data_fields=["id"],
                cvss_estimate=7.5,
            )
            for a in alert_records
        ],
        information_exposure_description=InformationExposureDescription(
            exposure_summary="Possible exfiltration of user credentials.",
            impact_assessment="High impact if attack succeeded.",
        ),
        model_used="qwen2.5:3b",
        provider_type="ollama",
        generation_status="complete",
    )


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------

def test_normalise_severity_critical_passthrough() -> None:
    _section("_normalise_severity: critical stays critical (3-tier P1/P2/P3 scale)")
    _assert(_normalise_severity("critical") == "critical", "lowercase critical -> critical")
    _assert(_normalise_severity("Critical") == "critical", "capitalised Critical -> critical (lowercased)")


def test_normalise_severity_3_levels() -> None:
    _section("_normalise_severity: canonical lowercase variants")
    _assert(_normalise_severity("critical") == "critical", "critical -> critical")
    _assert(_normalise_severity("high") == "high", "high -> high")
    _assert(_normalise_severity("low") == "low", "low -> low")


def test_normalise_severity_legacy_dialects() -> None:
    _section("_normalise_severity: legacy dialects fold into the 3-tier scale")
    # Legacy 4-tier "Medium" maps onto the Suricata P2 band (high).
    _assert(_normalise_severity("medium") == "high", "medium -> high (P2 bucket)")
    _assert(_normalise_severity("Medium") == "high", "capitalised Medium -> high")
    # "info"/"informational" still seen from some upstream feeds — collapse to low.
    _assert(_normalise_severity("info") == "low", "info -> low")
    _assert(_normalise_severity("informational") == "low", "informational -> low")
    # Legacy TitleCase forms still parsable for back-compat with stored reports.
    _assert(_normalise_severity("High") == "high", "High -> high")
    _assert(_normalise_severity("Low") == "low", "Low -> low")


def test_normalise_severity_empty_defaults_low() -> None:
    _section("_normalise_severity: empty/unknown -> low")
    _assert(_normalise_severity("") == "low", "empty -> low")
    _assert(_normalise_severity(None) == "low", "None -> low")
    _assert(_normalise_severity("nonsense") == "low", "unknown -> low")


def test_coerce_port() -> None:
    _section("_coerce_port: string / int / '?' / None")
    _assert(_coerce_port("12345") == 12345, "numeric string")
    _assert(_coerce_port(80) == 80, "int passthrough")
    _assert(_coerce_port("?") is None, "'?' -> None")
    _assert(_coerce_port(None) is None, "None -> None")
    _assert(_coerce_port("not a port") is None, "garbage -> None")
    _assert(_coerce_port(True) is None, "bool guarded out")


def test_endpoint_from_url() -> None:
    _section("_endpoint_from_url")
    _assert(
        _endpoint_from_url("/sqli/?id=1") == "/sqli/",
        "relative URL path extracted",
    )
    _assert(
        _endpoint_from_url("http://x.com/foo/bar?z=1") == "/foo/bar",
        "absolute URL path extracted",
    )
    _assert(_endpoint_from_url("") == "", "empty -> empty")
    _assert(_endpoint_from_url(None) == "", "None -> empty")


def test_build_alert_id() -> None:
    _section("_build_alert_id: flow_id preferred, fallback to report_id_NNN")
    _assert(_build_alert_id(42, "rep", 0) == "42", "non-zero flow_id used")
    _assert(_build_alert_id(0, "rep", 0) == "rep_000", "zero flow_id -> report_NNN")
    _assert(_build_alert_id(None, "rep", 5) == "rep_005", "None flow_id -> report_NNN")
    _assert(_build_alert_id("abc", "rep", 1) == "rep_001", "garbage flow_id -> report_NNN")


# ---------------------------------------------------------------------------
# Alert serialisation tests
# ---------------------------------------------------------------------------

def test_serialise_alerts_renames_fields() -> None:
    _section("Alert serialisation: field renames + type coercion")

    rec = _make_alert_record()
    report = _make_minimal_report([rec])

    payload = to_template_v1(report)
    alert = payload["alerts"][0]

    # Field rename checks
    _assert(alert["source_ip"] == "192.168.56.1", "src_ip -> source_ip")
    _assert(alert["destination_ip"] == "172.18.0.3", "dst_ip -> destination_ip")
    _assert(alert["alert_msg"] == rec.signature, "signature -> alert_msg")
    _assert(alert["suricata_rule_id"] == "2010963", "signature_id -> suricata_rule_id (str)")
    _assert(alert["event_timestamp"] == rec.timestamp_raw, "timestamp_raw -> event_timestamp")

    # Severity normalisation
    _assert(alert["severity"] == "high", "severity_label high -> high passthrough")

    # Port coercion
    _assert(alert["source_port"] == 12345, "source_port int")
    _assert(alert["destination_port"] == 80, "destination_port int")

    # HTTP extraction via flat fields
    _assert(alert["targeted_endpoint"] == "/vulnerabilities/sqli/", "endpoint path extracted")
    _assert(alert["http_method"] == "GET", "http_method extracted")

    # Protocol — app_proto preferred (HTTP, not TCP)
    _assert(alert["protocol"] == "HTTP", "app_proto upper preferred over transport")

    # Alert_id derived from non-zero flow_id
    _assert(alert["alert_id"] == "42", "alert_id from flow_id")


def test_serialise_alerts_missing_http_block() -> None:
    _section("Alert serialisation: no http info in raw_event")

    rec = AlertRecord(
        timestamp_raw="2026-05-15T10:00:00Z",
        timestamp_display="10:00:00",
        timestamp_epoch=time.time(),
        severity_level=3, severity_label="medium",
        src_ip="10.0.0.1", src_port="22", dst_ip="10.0.0.2", dst_port="22",
        proto="TCP",
        signature="generic alert", signature_id=1, category="x", action="",
        flow_id=0, app_proto="", in_iface="",
        raw_event={},
    )
    report = _make_minimal_report([rec])
    payload = to_template_v1(report)
    alert = payload["alerts"][0]

    _assert(alert["targeted_endpoint"] == "", "no URL -> empty endpoint")
    _assert(alert["http_method"] == "", "no http_method -> empty")
    _assert(alert["protocol"] == "TCP", "fallback to transport proto")


def test_serialise_alerts_port_unknown() -> None:
    _section("Alert serialisation: '?' port becomes null")

    rec = AlertRecord(
        timestamp_raw="2026-05-15T10:00:00Z",
        timestamp_display="10:00:00",
        timestamp_epoch=time.time(),
        severity_level=3, severity_label="low",
        src_ip="10.0.0.1", src_port="?", dst_ip="10.0.0.2", dst_port="?",
        proto="ICMP",
        signature="x", signature_id=1, category="x", action="",
        flow_id=99, app_proto="", in_iface="",
        raw_event={},
    )
    report = _make_minimal_report([rec])
    payload = to_template_v1(report)
    alert = payload["alerts"][0]

    _assert(alert["source_port"] is None, "'?' src_port -> null")
    _assert(alert["destination_port"] is None, "'?' dst_port -> null")


# ---------------------------------------------------------------------------
# Section duplication tests (template requires fields in multiple sections)
# ---------------------------------------------------------------------------

def test_attack_types_identified_duplicates_detected_attacks() -> None:
    _section("attack_types_identified duplicates detected_attacks")

    rec = _make_alert_record()
    report = _make_minimal_report([rec], detected_attacks=["SQLi", "XSS"])
    payload = to_template_v1(report)

    _assert(
        payload["incident_summary"]["detected_attacks"] == ["SQLi", "XSS"],
        "summary detected_attacks preserved",
    )
    _assert(
        payload["incident_summary_description"]["attack_types_identified"] == ["SQLi", "XSS"],
        "description attack_types_identified mirrors detected_attacks",
    )


def test_overall_cvss_estimate_duplicated_in_information_exposure() -> None:
    _section("overall_cvss_estimate present in both summary and exposure")

    rec = _make_alert_record()
    report = _make_minimal_report([rec])
    payload = to_template_v1(report)

    _assert(
        payload["incident_summary"]["overall_cvss_estimate"] == 7.5,
        "summary cvss",
    )
    _assert(
        payload["information_exposure"]["overall_cvss_estimate"] == 7.5,
        "information_exposure cvss (template location)",
    )


def test_data_sensitive_rating_and_iocs_in_exposure_description() -> None:
    _section("data_sensitive_rating + indicators_of_compromise in exposure description")

    rec = _make_alert_record()
    report = _make_minimal_report([rec])
    payload = to_template_v1(report)

    desc = payload["information_exposure_description"]
    _assert(desc["data_sensitive_rating"] == "confidential", "data_sensitive_rating duplicated")
    _assert(len(desc["indicators_of_compromise"]) == 2, "iocs duplicated")
    _assert(
        desc["indicators_of_compromise"][0]["type"] == "ip",
        "ioc shape preserved",
    )


def test_ai_suggestions_in_exposure_description() -> None:
    _section("ai_suggestions duplicated into exposure description")

    rec = _make_alert_record()
    report = _make_minimal_report([rec])
    payload = to_template_v1(report)

    suggestions = payload["information_exposure_description"]["ai_suggestions"]
    _assert(len(suggestions) == 2, "ai_suggestions copied")
    _assert("Block source IP" in suggestions, "suggestion content preserved")


# ---------------------------------------------------------------------------
# Schema validation tests
# ---------------------------------------------------------------------------

def test_valid_payload_validates() -> None:
    _section("Schema validation: full valid payload passes")

    rec = _make_alert_record()
    report = _make_minimal_report([rec])
    payload = to_template_v1(report)

    try:
        validate_template_v1(payload)
        _assert(True, "valid payload validates without error")
    except ValidationError as e:
        _assert(False, "validation failed unexpectedly", str(e))


def test_missing_top_level_required_section_rejected() -> None:
    _section("Schema validation: missing top-level section rejected")

    rec = _make_alert_record()
    payload = to_template_v1(_make_minimal_report([rec]))
    del payload["alerts"]

    raised = False
    try:
        validate_template_v1(payload)
    except ValidationError:
        raised = True
    _assert(raised, "deleting 'alerts' triggers ValidationError")


def test_missing_alert_required_field_rejected() -> None:
    _section("Schema validation: missing alert required field rejected")

    rec = _make_alert_record()
    payload = to_template_v1(_make_minimal_report([rec]))
    del payload["alerts"][0]["source_ip"]

    raised = False
    try:
        validate_template_v1(payload)
    except ValidationError:
        raised = True
    _assert(raised, "deleting alerts[0].source_ip triggers ValidationError")


def test_bad_severity_enum_rejected() -> None:
    _section("Schema validation: out-of-scale severity rejected")

    rec = _make_alert_record()
    payload = to_template_v1(_make_minimal_report([rec]))
    # "Critical" (TitleCase) is no longer in the schema enum — the canonical
    # form is lowercase "critical". This guards the schema against bypassing
    # normalisation.
    payload["incident_summary"]["overall_severity"] = "Critical"

    raised = False
    try:
        validate_template_v1(payload)
    except ValidationError:
        raised = True
    _assert(raised, "TitleCase 'Critical' rejected by lowercase 3-tier enum")


def test_bad_type_rejected() -> None:
    _section("Schema validation: wrong type rejected")

    rec = _make_alert_record()
    payload = to_template_v1(_make_minimal_report([rec]))
    payload["incident_summary"]["total_alerts"] = "five"  # should be integer

    raised = False
    try:
        validate_template_v1(payload)
    except ValidationError:
        raised = True
    _assert(raised, "total_alerts as string rejected")


def test_additional_properties_allowed() -> None:
    _section("Schema validation: additional properties allowed (our extras)")

    rec = _make_alert_record()
    payload = to_template_v1(_make_minimal_report([rec]))

    # Extras already in payload (e.g. incident_id, classification_counts)
    _assert("incident_id" in payload["incident_summary"], "extra field present")
    _assert(
        "classification" in payload["alert_analyses"][0],
        "extra field on analysis present",
    )

    try:
        validate_template_v1(payload)
        _assert(True, "payload with extras still validates")
    except ValidationError as e:
        _assert(False, "extras unexpectedly rejected", str(e))


# ---------------------------------------------------------------------------
# Top-level entry point tests
# ---------------------------------------------------------------------------

def test_to_template_v1_none_raises() -> None:
    _section("to_template_v1: None input raises")

    raised = False
    try:
        to_template_v1(None)
    except ValueError:
        raised = True
    _assert(raised, "None report raises ValueError")


def test_to_template_v1_empty_alerts_validates() -> None:
    _section("to_template_v1: report with zero alerts still validates")

    report = _make_minimal_report([])
    payload = to_template_v1(report)
    _assert(payload["incident_summary"]["total_alerts"] == 0, "total_alerts = 0")
    _assert(payload["alerts"] == [], "empty alerts array")

    try:
        validate_template_v1(payload)
        _assert(True, "empty-alerts report validates")
    except ValidationError as e:
        _assert(False, "empty-alerts unexpectedly rejected", str(e))


def test_to_template_v1_metadata_block_present() -> None:
    _section("to_template_v1: _generation_metadata extra block present")

    report = _make_minimal_report([_make_alert_record()])
    payload = to_template_v1(report)
    meta = payload.get("_generation_metadata")
    _assert(meta is not None, "metadata block present")
    _assert(meta.get("model_used") == "qwen2.5:3b", "model_used captured")
    _assert(meta.get("generation_status") == "complete", "generation_status captured")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    tests = [
        # Helpers
        test_normalise_severity_critical_passthrough,
        test_normalise_severity_3_levels,
        test_normalise_severity_legacy_dialects,
        test_normalise_severity_empty_defaults_low,
        test_coerce_port,
        test_endpoint_from_url,
        test_build_alert_id,
        # Alert serialisation
        test_serialise_alerts_renames_fields,
        test_serialise_alerts_missing_http_block,
        test_serialise_alerts_port_unknown,
        # Section duplications
        test_attack_types_identified_duplicates_detected_attacks,
        test_overall_cvss_estimate_duplicated_in_information_exposure,
        test_data_sensitive_rating_and_iocs_in_exposure_description,
        test_ai_suggestions_in_exposure_description,
        # Schema validation
        test_valid_payload_validates,
        test_missing_top_level_required_section_rejected,
        test_missing_alert_required_field_rejected,
        test_bad_severity_enum_rejected,
        test_bad_type_rejected,
        test_additional_properties_allowed,
        # Top-level
        test_to_template_v1_none_raises,
        test_to_template_v1_empty_alerts_validates,
        test_to_template_v1_metadata_block_present,
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
