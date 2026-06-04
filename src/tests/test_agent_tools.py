"""
test_agent_tools.py - Manual test harness for agent_tools.

Plain Python script with manual assertions (no pytest). Run with:

    python src/test_agent_tools.py

Exercises:
  - get_alert_history tool via make_alert_history_tool factory
  - The two new IncidentManager methods backing it
    (get_alerts_for_ip, get_incident_count_for_ip)

Uses a real IncidentManager (no sweeper started) and a fake storage
backend. Network/disk are not touched.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict, List

# Make src/ imports work from anywhere - tests/ sits one level below src/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_tools import (
    make_alert_history_tool,
    make_environment_lookup_tool,
    make_pattern_stats_tool,
)
from incident_manager import IncidentManager
from log_monitor import AlertRecord


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

def _make_alert(
    src_ip: str,
    signature: str = "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI",
    timestamp_epoch: float = 0.0,
) -> AlertRecord:
    """Build a synthetic AlertRecord. If timestamp_epoch == 0, use 'now'."""
    if timestamp_epoch == 0.0:
        timestamp_epoch = time.time()
    return AlertRecord(
        timestamp_raw="2026-05-15T10:00:00Z",
        timestamp_display="10:00:00.000",
        timestamp_epoch=timestamp_epoch,
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
        flow_id=0,
        app_proto="http",
        in_iface="br-test",
        raw_event={},
    )


class _FakeStorage:
    """Minimal stand-in that satisfies the same list_reports() shape as
    ReportDatabase - lets the agent-tool tests run without spinning up a
    real SQLite file."""

    def __init__(self, reports: List[Dict[str, Any]] = None):
        self._reports = list(reports or [])

    def list_reports(self) -> List[Dict[str, Any]]:
        return list(self._reports)


def _make_report_dict(
    incident_id: str,
    source_ip: str,
    alerts: List[Dict[str, Any]],
    generated_at: str = "2026-05-15T10:00:00+00:00",
) -> Dict[str, Any]:
    """Build a minimal report dict in the shape ReportDatabase.list_reports() returns."""
    return {
        "incident_summary": {
            "incident_id": incident_id,
            "source_ip": source_ip,
            "total_alerts": len(alerts),
            "generated_at": generated_at,
        },
        "alerts": alerts,
    }


def _new_manager() -> IncidentManager:
    """IncidentManager with safe-for-test settings - no sweeper started."""
    return IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=10.0,
        debounce_seconds=999.0,   # don't trigger debounce in tests
        sweep_interval_seconds=999.0,
        on_regenerate=lambda _: None,
    )


# ---------------------------------------------------------------------------
# Direct tests for IncidentManager additions
# ---------------------------------------------------------------------------

def test_get_alerts_for_ip_filters_by_ip() -> None:
    _section("IncidentManager.get_alerts_for_ip: filters by IP")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.2"))

    found = mgr.get_alerts_for_ip("10.0.0.1")
    _assert(len(found) == 2, "two alerts for 10.0.0.1", str(len(found)))

    found_other = mgr.get_alerts_for_ip("10.0.0.2")
    _assert(len(found_other) == 1, "one alert for 10.0.0.2", str(len(found_other)))

    none = mgr.get_alerts_for_ip("10.0.0.99")
    _assert(len(none) == 0, "no alerts for unknown IP")


def test_get_alerts_for_ip_filters_by_time() -> None:
    _section("IncidentManager.get_alerts_for_ip: filters by since_epoch")

    mgr = _new_manager()
    now = time.time()
    old = _make_alert("10.0.0.1", timestamp_epoch=now - 7200)   # 2h ago
    recent = _make_alert("10.0.0.1", timestamp_epoch=now - 60)  # 1m ago

    mgr.process_alert(old)
    mgr.process_alert(recent)

    # Window = last 30 min only
    since_30min = now - 1800
    found = mgr.get_alerts_for_ip("10.0.0.1", since_epoch=since_30min)
    _assert(len(found) == 1, "only recent alert in 30-min window", str(len(found)))

    # No filter
    all_found = mgr.get_alerts_for_ip("10.0.0.1")
    _assert(len(all_found) == 2, "no filter returns all", str(len(all_found)))


def test_get_incident_count_for_ip() -> None:
    _section("IncidentManager.get_incident_count_for_ip")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.1"))   # same incident
    mgr.process_alert(_make_alert("10.0.0.2"))   # different incident

    _assert(mgr.get_incident_count_for_ip("10.0.0.1") == 1, "10.0.0.1 has 1 open incident")
    _assert(mgr.get_incident_count_for_ip("10.0.0.2") == 1, "10.0.0.2 has 1 open incident")
    _assert(mgr.get_incident_count_for_ip("10.0.0.99") == 0, "unknown IP returns 0")


def test_get_all_incidents() -> None:
    _section("IncidentManager.get_all_incidents: open + recently_closed snapshot")

    mgr = _new_manager()
    _assert(len(mgr.get_all_incidents()) == 0, "empty before any alerts")

    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.2"))

    all_incs = mgr.get_all_incidents()
    _assert(len(all_incs) == 2, "two open incidents visible", str(len(all_incs)))
    ips = {inc.source_ip for inc in all_incs}
    _assert(ips == {"10.0.0.1", "10.0.0.2"}, "both source IPs present")


# ---------------------------------------------------------------------------
# Tool tests: get_alert_history
# ---------------------------------------------------------------------------

def test_history_empty_returns_zero_defaults() -> None:
    _section("get_alert_history: no history -> zero defaults")

    mgr = _new_manager()
    storage = _FakeStorage([])
    tool = make_alert_history_tool(mgr, storage)

    result = tool.call({"src_ip": "10.0.0.1"})
    _assert(result.succeeded, "tool ran", result.error or "")

    out = result.output
    _assert(out["src_ip"] == "10.0.0.1", "src_ip echoed")
    _assert(out["total_prior_alerts"] == 0, "no alerts")
    _assert(out["attack_types_seen"] == [], "no attack types")
    _assert(out["first_seen_iso"] is None, "no first_seen")
    _assert(out["last_seen_iso"] is None, "no last_seen")
    _assert(out["prior_incident_count"] == 0, "no incidents")
    _assert(out["is_repeat_offender_this_session"] is False, "not repeat offender")
    _assert(out["lookback_hours"] == 24, "default lookback applied")


def test_history_in_memory_only() -> None:
    _section("get_alert_history: in-memory alerts only")

    mgr = _new_manager()
    storage = _FakeStorage([])
    mgr.process_alert(_make_alert("10.0.0.1", signature="SQL Injection Attempt"))
    mgr.process_alert(_make_alert("10.0.0.1", signature="XSS Cross Site Scripting"))

    tool = make_alert_history_tool(mgr, storage)
    result = tool.call({"src_ip": "10.0.0.1"})

    _assert(result.succeeded, "tool ran", result.error or "")
    out = result.output
    _assert(out["total_prior_alerts"] == 2, "two alerts found", str(out))
    _assert(
        set(out["attack_types_seen"]) == {"SQLi", "XSS"},
        "both attack types detected",
        str(out["attack_types_seen"]),
    )
    _assert(out["prior_incident_count"] == 1, "one incident", str(out["prior_incident_count"]))
    _assert(out["first_seen_iso"] is not None, "first_seen recorded")
    _assert(out["last_seen_iso"] is not None, "last_seen recorded")
    _assert(out["is_repeat_offender_this_session"] is True, "marked repeat offender")


def test_history_disk_only() -> None:
    _section("get_alert_history: disk reports only")

    mgr = _new_manager()
    now_epoch = time.time()
    reports = [
        _make_report_dict(
            incident_id="inc-disk-1",
            source_ip="10.0.0.5",
            alerts=[
                {
                    "timestamp_epoch": now_epoch - 600,  # 10 min ago
                    "signature": "ET WEB_SERVER SQL Injection",
                    "src_ip": "10.0.0.5",
                },
                {
                    "timestamp_epoch": now_epoch - 300,  # 5 min ago
                    "signature": "ET WEB_SERVER SQL Injection",
                    "src_ip": "10.0.0.5",
                },
            ],
        )
    ]
    storage = _FakeStorage(reports)
    tool = make_alert_history_tool(mgr, storage)

    result = tool.call({"src_ip": "10.0.0.5"})
    _assert(result.succeeded, "tool ran", result.error or "")

    out = result.output
    _assert(out["total_prior_alerts"] == 2, "two disk alerts", str(out))
    _assert(out["attack_types_seen"] == ["SQLi"], "SQLi detected from disk")
    _assert(out["prior_incident_count"] == 1, "one disk incident")
    _assert(out["is_repeat_offender_this_session"] is False, "not in-session repeat")


def test_history_combined_dedupe_by_incident_id() -> None:
    _section("get_alert_history: in-memory + disk dedupe by incident_id")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.7", signature="SQL Injection"))
    open_incs = mgr.get_open_incidents()
    in_mem_inc_id = open_incs[0].incident_id  # use real ID from manager

    # Disk has a report for the SAME incident_id - should not double-count
    now_epoch = time.time()
    reports = [
        _make_report_dict(
            incident_id=in_mem_inc_id,  # dedup target
            source_ip="10.0.0.7",
            alerts=[
                {
                    "timestamp_epoch": now_epoch - 60,
                    "signature": "SQL Injection",
                    "src_ip": "10.0.0.7",
                },
            ],
        ),
        _make_report_dict(
            incident_id="inc-disk-only",
            source_ip="10.0.0.7",
            alerts=[
                {
                    "timestamp_epoch": now_epoch - 120,
                    "signature": "SQL Injection",
                    "src_ip": "10.0.0.7",
                },
            ],
        ),
    ]
    storage = _FakeStorage(reports)
    tool = make_alert_history_tool(mgr, storage)

    result = tool.call({"src_ip": "10.0.0.7"})
    _assert(result.succeeded, "tool ran", result.error or "")
    out = result.output
    # 1 in-memory + 1 disk (the dedup-target's disk alerts skipped)
    _assert(
        out["total_prior_alerts"] == 2,
        "in-memory alert + 1 disk alert from non-dedup incident",
        str(out["total_prior_alerts"]),
    )
    # 1 in-memory incident + 1 disk-only incident = 2; dedup target NOT counted
    _assert(
        out["prior_incident_count"] == 2,
        "incident count = in-memory + disk-only (dedup skipped)",
        str(out["prior_incident_count"]),
    )


def test_history_time_filter_excludes_old_alerts() -> None:
    _section("get_alert_history: time filter excludes old alerts")

    mgr = _new_manager()
    now = time.time()
    # Old alert (2 hours ago)
    mgr.process_alert(_make_alert("10.0.0.8", timestamp_epoch=now - 7200))
    # Recent alert (5 min ago)
    mgr.process_alert(_make_alert("10.0.0.8", timestamp_epoch=now - 300))

    storage = _FakeStorage([])
    tool = make_alert_history_tool(mgr, storage)

    # 1-hour window - only the recent one
    result = tool.call({"src_ip": "10.0.0.8", "hours": 1})
    _assert(result.succeeded, "tool ran", result.error or "")
    out = result.output
    _assert(
        out["total_prior_alerts"] == 1,
        "only recent alert in 1-hour window",
        str(out["total_prior_alerts"]),
    )
    _assert(out["lookback_hours"] == 1, "hours passed through")


def test_history_no_match_for_different_ip() -> None:
    _section("get_alert_history: queries for unrelated IP return empty")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.1"))

    storage = _FakeStorage([])
    tool = make_alert_history_tool(mgr, storage)

    result = tool.call({"src_ip": "10.0.0.99"})  # different IP
    _assert(result.succeeded, "tool ran")
    out = result.output
    _assert(out["total_prior_alerts"] == 0, "no alerts for unrelated IP")
    _assert(out["is_repeat_offender_this_session"] is False, "not repeat for unrelated IP")


def test_history_null_storage() -> None:
    _section("get_alert_history: None storage uses null adapter")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1"))

    tool = make_alert_history_tool(mgr, storage=None)
    result = tool.call({"src_ip": "10.0.0.1"})

    _assert(result.succeeded, "tool ran with None storage", result.error or "")
    _assert(result.output["total_prior_alerts"] == 1, "in-memory still found")


def test_history_validation_rejects_missing_src_ip() -> None:
    _section("get_alert_history: missing src_ip rejected by validation")

    mgr = _new_manager()
    tool = make_alert_history_tool(mgr, storage=None)

    result = tool.call({})  # missing required src_ip
    _assert(not result.succeeded, "validation rejected")
    _assert(
        result.error is not None and "src_ip" in result.error,
        "error mentions src_ip",
        result.error or "",
    )


def test_history_validation_clamps_hours() -> None:
    _section("get_alert_history: hours range enforced")

    mgr = _new_manager()
    tool = make_alert_history_tool(mgr, storage=None)

    # Too small
    r1 = tool.call({"src_ip": "10.0.0.1", "hours": 0})
    _assert(not r1.succeeded, "hours=0 rejected")

    # Too big
    r2 = tool.call({"src_ip": "10.0.0.1", "hours": 999})
    _assert(not r2.succeeded, "hours=999 rejected")

    # Valid
    r3 = tool.call({"src_ip": "10.0.0.1", "hours": 48})
    _assert(r3.succeeded, "hours=48 accepted", r3.error or "")


def test_history_disk_read_exception_handled() -> None:
    _section("get_alert_history: disk read exception is non-fatal")

    class _BrokenStorage:
        def list_reports(self):
            raise RuntimeError("disk on fire")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1"))

    tool = make_alert_history_tool(mgr, storage=_BrokenStorage())
    result = tool.call({"src_ip": "10.0.0.1"})

    _assert(result.succeeded, "tool succeeded despite broken storage", result.error or "")
    _assert(
        result.output["total_prior_alerts"] == 1,
        "in-memory alerts still returned",
        str(result.output),
    )


def test_history_attack_types_excludes_other() -> None:
    _section("get_alert_history: attack_types_seen excludes 'Other'")

    mgr = _new_manager()
    # Mix of recognised and unrecognised signatures
    mgr.process_alert(_make_alert("10.0.0.1", signature="SQL Injection"))
    mgr.process_alert(_make_alert("10.0.0.1", signature="something completely unrelated"))

    storage = _FakeStorage([])
    tool = make_alert_history_tool(mgr, storage)
    result = tool.call({"src_ip": "10.0.0.1"})

    _assert(result.succeeded, "tool ran")
    types = result.output["attack_types_seen"]
    _assert("SQLi" in types, "SQLi included")
    _assert("Other" not in types, "Other excluded")


# ---------------------------------------------------------------------------
# Tool tests: lookup_environment_context
# ---------------------------------------------------------------------------

def _docker_entries() -> List[Dict[str, Any]]:
    """Reusable env_entries fixture mirroring the lab config."""
    return [
        {
            "pattern": "172.18.0.2",
            "match_type": "exact_ip",
            "role": "internal_database",
            "description": "MariaDB inside Docker bridge.",
            "classification_hint": "likely_false_positive_if_internal_only",
        },
        {
            "pattern": "172.18.0.0/16",
            "match_type": "cidr",
            "role": "docker_bridge",
            "description": "Docker bridge subnet.",
            "classification_hint": "context_only",
        },
        {
            "pattern": "192.168.56.0/24",
            "match_type": "cidr",
            "role": "host_only_network",
            "description": "VirtualBox host-only network.",
            "classification_hint": "untrusted_source_likely_attacker",
        },
        {
            "pattern": "/vulnerabilities/sqli",
            "match_type": "url_prefix",
            "role": "vulnerable_endpoint",
            "description": "DVWA SQLi training endpoint.",
            "classification_hint": "expected_attack_target",
        },
    ]


def test_env_empty_entries_no_match() -> None:
    _section("env_lookup: empty entries -> no match")

    tool = make_environment_lookup_tool([])
    result = tool.call({"query": "172.18.0.2"})
    _assert(result.succeeded, "tool ran")
    _assert(result.output["match_found"] is False, "no match for empty entries")


def test_env_exact_ip_match() -> None:
    _section("env_lookup: exact IP match")

    tool = make_environment_lookup_tool(_docker_entries())
    result = tool.call({"query": "172.18.0.2"})
    out = result.output

    _assert(result.succeeded, "tool ran")
    _assert(out["match_found"] is True, "exact IP matched")
    _assert(out["matched_pattern"] == "172.18.0.2", "correct pattern returned")
    _assert(out["role"] == "internal_database", "role returned")
    _assert(
        out["classification_hint"] == "likely_false_positive_if_internal_only",
        "classification hint returned",
    )


def test_env_exact_ip_miss() -> None:
    _section("env_lookup: exact IP miss falls through to CIDR")

    tool = make_environment_lookup_tool(_docker_entries())
    # 172.18.0.3 is in the bridge CIDR but not an exact entry
    result = tool.call({"query": "172.18.0.3"})
    out = result.output
    _assert(result.succeeded, "tool ran")
    _assert(out["match_found"] is True, "matched CIDR after exact miss")
    _assert(out["match_type"] == "cidr", "matched via CIDR")
    _assert(out["matched_pattern"] == "172.18.0.0/16", "correct CIDR pattern")


def test_env_cidr_outside_subnet() -> None:
    _section("env_lookup: CIDR miss for IP outside all subnets")

    tool = make_environment_lookup_tool(_docker_entries())
    result = tool.call({"query": "10.0.0.99"})
    _assert(result.succeeded, "tool ran")
    _assert(result.output["match_found"] is False, "no match outside all subnets")


def test_env_cidr_with_non_ip_query() -> None:
    _section("env_lookup: CIDR with non-IP query (e.g. URL) does not crash")

    tool = make_environment_lookup_tool(_docker_entries())
    # URL string - should still try URL matchers, fail to match CIDR cleanly
    result = tool.call({"query": "not.an.ip.string"})
    _assert(result.succeeded, "tool ran")
    _assert(result.output["match_found"] is False, "non-IP query produced clean miss")


def test_env_url_prefix_match() -> None:
    _section("env_lookup: url_prefix match")

    tool = make_environment_lookup_tool(_docker_entries())
    result = tool.call({"query": "/vulnerabilities/sqli/?id=1"})
    out = result.output
    _assert(result.succeeded, "tool ran")
    _assert(out["match_found"] is True, "URL prefix matched")
    _assert(out["match_type"] == "url_prefix", "match_type reported")
    _assert(out["role"] == "vulnerable_endpoint", "role returned")


def test_env_url_prefix_miss() -> None:
    _section("env_lookup: url_prefix miss")

    tool = make_environment_lookup_tool(_docker_entries())
    result = tool.call({"query": "/login.php"})
    _assert(result.succeeded, "tool ran")
    _assert(result.output["match_found"] is False, "URL prefix did not match")


def test_env_url_contains_match() -> None:
    _section("env_lookup: url_contains match")

    entries = [
        {
            "pattern": "/admin/",
            "match_type": "url_contains",
            "role": "admin_path",
            "description": "Anywhere in URL.",
            "classification_hint": "high_severity_target",
        }
    ]
    tool = make_environment_lookup_tool(entries)

    # Anywhere in the string
    result = tool.call({"query": "/portal/admin/users?id=1"})
    _assert(result.output["match_found"] is True, "substring matched mid-URL")


def test_env_unknown_match_type_skipped() -> None:
    _section("env_lookup: unknown match_type at config rejected silently")

    entries = [
        {"pattern": "x", "match_type": "regex"},   # unsupported
        {"pattern": "1.2.3.4", "match_type": "exact_ip", "role": "ok"},
    ]
    tool = make_environment_lookup_tool(entries)
    # Bad entry should be skipped; good entry still works
    result = tool.call({"query": "1.2.3.4"})
    _assert(result.output["match_found"] is True, "valid entry still matches")
    _assert(result.output["role"] == "ok", "correct role from valid entry")


def test_env_invalid_cidr_skipped() -> None:
    _section("env_lookup: invalid CIDR rejected, other entries still work")

    entries = [
        {"pattern": "999.999.999.999/8", "match_type": "cidr"},  # invalid
        {"pattern": "10.0.0.0/8", "match_type": "cidr", "role": "private"},
    ]
    tool = make_environment_lookup_tool(entries)
    # Invalid CIDR skipped at compile time; valid one still matches
    result = tool.call({"query": "10.5.5.5"})
    _assert(result.output["match_found"] is True, "valid CIDR matched")
    _assert(result.output["role"] == "private", "valid CIDR role returned")


def test_env_first_match_wins() -> None:
    _section("env_lookup: first matching entry wins (order matters)")

    entries = [
        {"pattern": "10.0.0.5", "match_type": "exact_ip", "role": "first"},
        {"pattern": "10.0.0.0/8", "match_type": "cidr", "role": "second"},
    ]
    tool = make_environment_lookup_tool(entries)

    result = tool.call({"query": "10.0.0.5"})
    _assert(result.output["match_found"] is True, "matched")
    _assert(result.output["role"] == "first", "exact entry won over CIDR")


def test_env_ipv6_cidr() -> None:
    _section("env_lookup: IPv6 CIDR")

    entries = [
        {"pattern": "2001:db8::/32", "match_type": "cidr", "role": "ipv6_doc"},
    ]
    tool = make_environment_lookup_tool(entries)

    result = tool.call({"query": "2001:db8::1"})
    _assert(result.output["match_found"] is True, "IPv6 CIDR matched")
    _assert(result.output["role"] == "ipv6_doc", "IPv6 role returned")


def test_env_empty_query() -> None:
    _section("env_lookup: empty query is graceful no-match")

    tool = make_environment_lookup_tool(_docker_entries())
    result = tool.call({"query": "   "})  # whitespace only -> empty after strip
    _assert(result.succeeded, "tool ran")
    _assert(result.output["match_found"] is False, "empty query did not match")
    _assert("reason" in result.output, "reason field present for empty")


def test_env_missing_query_rejected() -> None:
    _section("env_lookup: missing query rejected by validation")

    tool = make_environment_lookup_tool([])
    result = tool.call({})
    _assert(not result.succeeded, "validation rejected")
    _assert(
        result.error is not None and "query" in result.error,
        "error mentions query field",
        result.error or "",
    )


# ---------------------------------------------------------------------------
# Tool tests: get_attack_pattern_stats
# ---------------------------------------------------------------------------

def test_stats_empty_returns_zeros() -> None:
    _section("pattern_stats: empty everywhere -> zeros, null TPR")

    mgr = _new_manager()
    storage = _FakeStorage([])
    tool = make_pattern_stats_tool(mgr, storage)

    result = tool.call({"attack_type": "SQLi"})
    _assert(result.succeeded, "tool ran", result.error or "")

    out = result.output
    _assert(out["attack_type"] == "SQLi", "echoes attack_type")
    _assert(out["total_alerts"] == 0, "no alerts")
    _assert(out["unique_source_ips"] == 0, "no IPs")
    _assert(out["incident_count"] == 0, "no incidents")
    _assert("observed_true_positive_rate" not in out,
            "TPR field omitted when no data")
    _assert(out["most_recent_alert_iso"] is None, "no recent timestamp")
    _assert(out["lookback_hours"] == 24, "default lookback")


def test_stats_in_memory_matching_type() -> None:
    _section("pattern_stats: in-memory alerts of matching attack type")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1", signature="SQL Injection"))
    mgr.process_alert(_make_alert("10.0.0.1", signature="SQL Injection"))
    mgr.process_alert(_make_alert("10.0.0.2", signature="UNION SELECT SQL Injection"))

    storage = _FakeStorage([])
    tool = make_pattern_stats_tool(mgr, storage)
    result = tool.call({"attack_type": "SQLi"})
    out = result.output

    _assert(out["total_alerts"] == 3, "3 SQLi alerts counted", str(out))
    _assert(out["unique_source_ips"] == 2, "2 unique IPs")
    _assert(out["incident_count"] == 2, "2 incidents")
    _assert("observed_true_positive_rate" not in out,
            "TPR field omitted from in-memory-only output")
    _assert(out["most_recent_alert_iso"] is not None, "recent timestamp recorded")


def test_stats_non_matching_type_excluded() -> None:
    _section("pattern_stats: non-matching attack types excluded")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1", signature="SQL Injection"))
    mgr.process_alert(_make_alert("10.0.0.2", signature="XSS Cross Site Scripting"))

    tool = make_pattern_stats_tool(mgr, _FakeStorage([]))

    # Querying SQLi should not pick up XSS
    sqli = tool.call({"attack_type": "SQLi"}).output
    _assert(sqli["total_alerts"] == 1, "only SQLi counted", str(sqli))
    _assert(sqli["unique_source_ips"] == 1, "only one IP for SQLi")

    # Querying XSS should not pick up SQLi
    xss = tool.call({"attack_type": "XSS"}).output
    _assert(xss["total_alerts"] == 1, "only XSS counted")


def test_stats_disk_classifications_compute_tpr() -> None:
    _section("pattern_stats: disk classifications compute true-positive rate")

    mgr = _new_manager()

    # Disk-only report with 3 SQLi alerts: 2 TP, 1 FP
    now_epoch = time.time()
    report = {
        "incident_summary": {
            "incident_id": "inc-disk-1",
            "source_ip": "10.0.0.5",
            "total_alerts": 3,
            "generated_at": "2026-05-15T10:00:00+00:00",
        },
        "alerts": [
            {
                "timestamp_epoch": now_epoch - 600,
                "signature": "SQL Injection",
                "src_ip": "10.0.0.5",
            },
            {
                "timestamp_epoch": now_epoch - 500,
                "signature": "UNION SELECT SQL Injection",
                "src_ip": "10.0.0.5",
            },
            {
                "timestamp_epoch": now_epoch - 400,
                "signature": "SQL Injection",
                "src_ip": "10.0.0.5",
            },
        ],
        "alert_analyses": [
            {"alert_id": "a1", "classification": "true_positive"},
            {"alert_id": "a2", "classification": "true_positive"},
            {"alert_id": "a3", "classification": "likely_false_positive"},
        ],
    }
    storage = _FakeStorage([report])

    tool = make_pattern_stats_tool(mgr, storage)
    out = tool.call({"attack_type": "SQLi"}).output

    _assert(out["total_alerts"] == 3, "3 disk SQLi alerts counted", str(out))
    _assert(
        out["observed_true_positive_rate"] == round(2 / 3, 3),
        "TPR = 2/3 from 2 TP + 1 FP",
        str(out["observed_true_positive_rate"]),
    )


def test_stats_dedup_by_incident_id() -> None:
    _section("pattern_stats: in-memory + disk same incident_id is counted once")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.7", signature="SQL Injection"))
    inc_id = mgr.get_open_incidents()[0].incident_id

    now_epoch = time.time()
    # Disk report for SAME incident_id - should not double-count volume
    report = {
        "incident_summary": {
            "incident_id": inc_id,
            "source_ip": "10.0.0.7",
            "total_alerts": 1,
            "generated_at": "2026-05-15T10:00:00+00:00",
        },
        "alerts": [
            {
                "timestamp_epoch": now_epoch - 30,
                "signature": "SQL Injection",
                "src_ip": "10.0.0.7",
            },
        ],
        "alert_analyses": [
            {"alert_id": "a1", "classification": "true_positive"},
        ],
    }
    storage = _FakeStorage([report])
    tool = make_pattern_stats_tool(mgr, storage)

    out = tool.call({"attack_type": "SQLi"}).output

    # Volume counted once
    _assert(out["total_alerts"] == 1, "alert counted once across in-mem + disk")
    _assert(out["incident_count"] == 1, "incident counted once")
    # But TPR is computed from disk classifications regardless
    _assert(
        out["observed_true_positive_rate"] == 1.0,
        "TPR = 1.0 from single TP classification",
        str(out["observed_true_positive_rate"]),
    )


def test_stats_time_filter() -> None:
    _section("pattern_stats: time window filter excludes old alerts")

    mgr = _new_manager()
    now = time.time()
    mgr.process_alert(_make_alert("10.0.0.1", timestamp_epoch=now - 7200,
                                  signature="SQL Injection"))  # 2h ago
    mgr.process_alert(_make_alert("10.0.0.1", timestamp_epoch=now - 60,
                                  signature="SQL Injection"))  # 1m ago

    tool = make_pattern_stats_tool(mgr, _FakeStorage([]))

    # 30-min window: only recent
    out = tool.call({"attack_type": "SQLi", "hours": 1}).output
    _assert(out["total_alerts"] == 1, "only recent alert in 1-hour window")
    _assert(out["lookback_hours"] == 1, "hours passed through")


def test_stats_invalid_attack_type_rejected() -> None:
    _section("pattern_stats: invalid attack_type rejected by enum")

    tool = make_pattern_stats_tool(_new_manager(), _FakeStorage([]))
    result = tool.call({"attack_type": "NotARealType"})
    _assert(not result.succeeded, "validation rejected")
    _assert(
        result.error is not None and "NotARealType" in result.error,
        "error mentions invalid value",
        result.error or "",
    )


def test_stats_hours_range_enforced() -> None:
    _section("pattern_stats: hours range enforced")

    tool = make_pattern_stats_tool(_new_manager(), _FakeStorage([]))

    r1 = tool.call({"attack_type": "SQLi", "hours": 0})
    _assert(not r1.succeeded, "hours=0 rejected")

    r2 = tool.call({"attack_type": "SQLi", "hours": 200})
    _assert(not r2.succeeded, "hours=200 rejected (>168)")


def test_stats_null_storage() -> None:
    _section("pattern_stats: None storage works, no TPR")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1", signature="XSS"))
    tool = make_pattern_stats_tool(mgr, storage=None)

    out = tool.call({"attack_type": "XSS"}).output
    _assert(out["total_alerts"] == 1, "in-memory XSS counted")
    _assert("observed_true_positive_rate" not in out,
            "TPR field omitted when storage is None")


def test_stats_broken_storage_graceful() -> None:
    _section("pattern_stats: storage exception is non-fatal")

    class _BrokenStorage:
        def list_reports(self):
            raise RuntimeError("disk on fire")

    mgr = _new_manager()
    mgr.process_alert(_make_alert("10.0.0.1", signature="SQL Injection"))
    tool = make_pattern_stats_tool(mgr, storage=_BrokenStorage())

    out = tool.call({"attack_type": "SQLi"}).output
    _assert(out["total_alerts"] == 1, "in-memory still counted")
    _assert("observed_true_positive_rate" not in out,
            "TPR field omitted when disk read failed")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main() -> int:
    tests = [
        test_get_alerts_for_ip_filters_by_ip,
        test_get_alerts_for_ip_filters_by_time,
        test_get_incident_count_for_ip,
        test_get_all_incidents,
        test_history_empty_returns_zero_defaults,
        test_history_in_memory_only,
        test_history_disk_only,
        test_history_combined_dedupe_by_incident_id,
        test_history_time_filter_excludes_old_alerts,
        test_history_no_match_for_different_ip,
        test_history_null_storage,
        test_history_validation_rejects_missing_src_ip,
        test_history_validation_clamps_hours,
        test_history_disk_read_exception_handled,
        test_history_attack_types_excludes_other,
        # Environment lookup
        test_env_empty_entries_no_match,
        test_env_exact_ip_match,
        test_env_exact_ip_miss,
        test_env_cidr_outside_subnet,
        test_env_cidr_with_non_ip_query,
        test_env_url_prefix_match,
        test_env_url_prefix_miss,
        test_env_url_contains_match,
        test_env_unknown_match_type_skipped,
        test_env_invalid_cidr_skipped,
        test_env_first_match_wins,
        test_env_ipv6_cidr,
        test_env_empty_query,
        test_env_missing_query_rejected,
        # Attack pattern stats
        test_stats_empty_returns_zeros,
        test_stats_in_memory_matching_type,
        test_stats_non_matching_type_excluded,
        test_stats_disk_classifications_compute_tpr,
        test_stats_dedup_by_incident_id,
        test_stats_time_filter,
        test_stats_invalid_attack_type_rejected,
        test_stats_hours_range_enforced,
        test_stats_null_storage,
        test_stats_broken_storage_graceful,
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
