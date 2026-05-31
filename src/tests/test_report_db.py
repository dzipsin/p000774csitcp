"""
test_report_db.py - Manual test harness for ReportDatabase.

Plain-Python tests against a real SQLite file in a tempdir. Run:

    python src/test_report_db.py

Covers:
  - Schema bootstrap (idempotent, WAL pragma applied)
  - save -> load_raw round trip preserves the full template payload
  - list_reports ordering: newest first
  - clear_all removes incidents + their alerts (cascade)
  - list_by_source_ip / list_by_attack_type / list_by_severity filters
  - aggregate_stats counts by status / severity / attack_type + repeat
  - cleanup_expired drops rows older than the cutoff
  - save() upserts when called twice for the same incident_id
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# tests/ sits one level below src/, so reach up twice for the import root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
from report_db import ReportDatabase


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_report(
    incident_id: str,
    source_ip: str = "192.168.56.1",
    severity: str = "high",
    repeat_offender: bool = False,
    detected: list = None,
    generated_at: str = None,
    status: str = "open",
) -> IncidentReport:
    detected = detected if detected is not None else ["SQLi"]
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()

    return IncidentReport(
        incident_summary=IncidentSummary(
            incident_id=incident_id,
            report_id=f"rep_{incident_id[:8]}",
            report_version="v1",
            incident_status=status,
            generated_at=generated_at,
            last_updated_at=generated_at,
            first_seen="2026-05-20 10:00:00 UTC",
            last_seen="2026-05-20 10:04:30 UTC",
            source_ip=source_ip,
            total_alerts=1,
            classification_counts={"true_positive": 1, "likely_false_positive": 0, "error": 0},
            detected_attacks=list(detected),
            overall_severity=severity,
            overall_cvss_estimate=7.5,
            repeat_offender=repeat_offender,
        ),
        alerts=[{
            "timestamp_raw": "2026-05-20T10:00:00Z",
            "timestamp_epoch": time.time(),
            "src_ip": source_ip,
            "src_port": "12345",
            "dst_ip": "172.18.0.3",
            "dst_port": "80",
            "proto": "TCP",
            "app_proto": "http",
            "signature": "ET WEB_SERVER SQL Injection Attempt",
            "signature_id": 2010963,
            "severity_label": "high",
            "category": "Web Application Attack",
            "action": "allowed",
            "flow_id": 42,
            "in_iface": "br-test",
            "http_url": "/sqli/?id=1",
            "http_method": "GET",
        }],
        incident_summary_description=IncidentSummaryDescription(
            overview="An incident occurred.",
            attack_vectors=["URL parameter"],
            overall_attack_stage="Initial Access",
            ai_suggestions=["Block IP"],
        ),
        alert_analyses=[
            AlertAnalysis(
                alert_id="42",
                attack_type_classified="SQLi",
                payload_observed="/sqli/?id=1",
                payload_classification="UNION-based SQL injection",
                likely_intent="credential extraction",
                confidence_score=0.9,
                classification="true_positive",
                severity=severity,
                recommendation="block_source_ip",
                classification_status="complete",
            )
        ],
        information_exposure=InformationExposure(
            exposure_detected=True,
            exposure_types=["user credentials"],
            affected_systems=["web app"],
            data_sensitive_rating="confidential",
            indicators_of_compromise=[{"type": "ip", "value": source_ip}],
        ),
        alert_exposures=[
            AlertExposure(alert_id="42", affected_data_fields=["id"], cvss_estimate=7.5)
        ],
        information_exposure_description=InformationExposureDescription(
            exposure_summary="Possible exposure.",
            impact_assessment="High if exploited.",
        ),
        model_used="qwen2.5:3b",
        provider_type="ollama",
        generation_status="complete",
    )


def _tmp_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="report-db-test-"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_schema_bootstrap_idempotent():
    print("\n=== Test 1: schema bootstrap is idempotent ===")
    d = _tmp_dir()
    try:
        db1 = ReportDatabase(db_path=str(d / "reports.db"))
        db2 = ReportDatabase(db_path=str(d / "reports.db"))   # re-open same file
        # Both should succeed; same tables exist
        rows = db2._connection().execute(
            "SELECT name FROM sqlite_master WHERE type='table';"
        ).fetchall()
        names = {r["name"] for r in rows}
        assert "incidents" in names, names
        assert "alerts" in names, names
        assert "schema_version" in names, names
        # WAL mode active
        mode = db2._connection().execute(
            "PRAGMA journal_mode;"
        ).fetchone()[0]
        assert mode.lower() == "wal", f"journal_mode={mode}"
        print(f"    PASS: tables={sorted(names)}, journal_mode=wal")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_save_and_load_round_trip():
    print("\n=== Test 2: save + load_raw preserves the full payload ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        report = _make_report(incident_id="aaa11111-test-0001")
        path = db.save(report)
        assert path is not None, "save returned None"

        loaded = db.load_raw("aaa11111-test-0001")
        assert loaded is not None, "load_raw returned None"
        # Template-shape: top-level has incident_summary
        assert "incident_summary" in loaded
        assert loaded["incident_summary"]["incident_id"] == "aaa11111-test-0001"
        assert loaded["incident_summary"]["source_ip"] == "192.168.56.1"
        # Alerts preserved
        assert len(loaded["alerts"]) == 1
        # Alert_analyses preserved
        assert len(loaded["alert_analyses"]) == 1
        assert loaded["alert_analyses"][0]["classification"] == "true_positive"
        print("    PASS: round-trip preserved incident_summary, alerts, analyses")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_list_reports_newest_first():
    print("\n=== Test 3: list_reports orders newest first ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        # Save 3 reports with explicit timestamps
        now = datetime.now(timezone.utc)
        for i in range(3):
            ts = (now - timedelta(minutes=10 - i * 5)).isoformat()
            db.save(_make_report(
                incident_id=f"inc_{i:03d}",
                generated_at=ts,
            ))
        listed = db.list_reports()
        assert len(listed) == 3
        # Newest (i=2) should be first
        assert listed[0]["incident_summary"]["incident_id"] == "inc_002"
        assert listed[2]["incident_summary"]["incident_id"] == "inc_000"
        print(f"    PASS: 3 reports listed newest-first")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_save_upserts_same_incident_id():
    print("\n=== Test 4: save() upserts on second call with same incident_id ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        r1 = _make_report(incident_id="same-id-001", severity="low")
        db.save(r1)
        r2 = _make_report(incident_id="same-id-001", severity="critical")
        db.save(r2)
        # Only 1 row
        assert len(db.list_reports()) == 1
        loaded = db.load_raw("same-id-001")
        assert loaded["incident_summary"]["overall_severity"] == "critical", (
            "second save did not overwrite the severity field"
        )
        print("    PASS: upsert preserved single row with updated content")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_clear_all_drops_everything():
    print("\n=== Test 5: clear_all drops incidents + cascaded alerts ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        for i in range(5):
            db.save(_make_report(incident_id=f"clear_{i}"))
        assert len(db.list_reports()) == 5

        count = db.clear_all()
        assert count == 5, f"expected 5 cleared, got {count}"
        assert len(db.list_reports()) == 0
        # Cascade — alerts table should be empty too
        rows = db._connection().execute(
            "SELECT COUNT(*) AS n FROM alerts;"
        ).fetchone()
        assert rows["n"] == 0, f"alerts table not cleared, has {rows['n']} rows"
        print("    PASS: incidents + alerts both empty after clear_all")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_list_by_source_ip():
    print("\n=== Test 6: list_by_source_ip filters correctly ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        db.save(_make_report(incident_id="a1", source_ip="192.168.56.1"))
        db.save(_make_report(incident_id="a2", source_ip="192.168.56.1"))
        db.save(_make_report(incident_id="b1", source_ip="10.0.0.1"))

        a = db.list_by_source_ip("192.168.56.1")
        assert len(a) == 2, f"expected 2 for .56.1, got {len(a)}"
        b = db.list_by_source_ip("10.0.0.1")
        assert len(b) == 1
        c = db.list_by_source_ip("172.18.0.99")
        assert len(c) == 0
        print("    PASS: filter by source_ip returned 2/1/0 matches")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_list_by_attack_type():
    print("\n=== Test 7: list_by_attack_type matches inside JSON array ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        db.save(_make_report(incident_id="sqli_only", detected=["SQLi"]))
        db.save(_make_report(incident_id="both", detected=["SQLi", "XSS"]))
        db.save(_make_report(incident_id="xss_only", detected=["XSS"]))

        sqli = db.list_by_attack_type("SQLi")
        assert len(sqli) == 2, f"expected 2 SQLi-tagged, got {len(sqli)}"
        xss = db.list_by_attack_type("XSS")
        assert len(xss) == 2
        recon = db.list_by_attack_type("Reconnaissance")
        assert len(recon) == 0
        print("    PASS: filter inside JSON array returned 2/2/0 matches")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_list_by_severity():
    print("\n=== Test 8: list_by_severity ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        db.save(_make_report(incident_id="c1", severity="critical"))
        db.save(_make_report(incident_id="h1", severity="high"))
        db.save(_make_report(incident_id="l1", severity="low"))
        db.save(_make_report(incident_id="c2", severity="critical"))

        assert len(db.list_by_severity("critical")) == 2
        assert len(db.list_by_severity("high")) == 1
        assert len(db.list_by_severity("low")) == 1
        print("    PASS: severity filter returned 2/1/1 matches")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_aggregate_stats():
    print("\n=== Test 9: aggregate_stats groups by status / severity / attack_type ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        db.save(_make_report(incident_id="s1", severity="critical", status="open",
                             detected=["SQLi"], repeat_offender=True))
        db.save(_make_report(incident_id="s2", severity="critical", status="closed",
                             detected=["SQLi", "XSS"], repeat_offender=False))
        db.save(_make_report(incident_id="s3", severity="low", status="closed",
                             detected=["Reconnaissance"], repeat_offender=False))

        stats = db.aggregate_stats()
        assert stats["total_incidents"] == 3
        assert stats["by_status"].get("open") == 1
        assert stats["by_status"].get("closed") == 2
        assert stats["by_severity"].get("critical") == 2
        assert stats["by_severity"].get("low") == 1
        assert stats["by_attack_type"].get("SQLi") == 2
        assert stats["by_attack_type"].get("XSS") == 1
        assert stats["by_attack_type"].get("Reconnaissance") == 1
        assert stats["repeat_offenders"] == 1
        print(f"    PASS: stats = {json.dumps({k:v for k,v in stats.items() if k!='since_epoch'}, default=str)[:200]}")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_cleanup_expired():
    print("\n=== Test 10: cleanup_expired drops rows older than cutoff ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"), retention_days=7)
        now = datetime.now(timezone.utc)
        # Three records: old, ancient, fresh
        db.save(_make_report(
            incident_id="ancient",
            generated_at=(now - timedelta(days=30)).isoformat(),
        ))
        db.save(_make_report(
            incident_id="old",
            generated_at=(now - timedelta(days=10)).isoformat(),
        ))
        db.save(_make_report(
            incident_id="fresh",
            generated_at=(now - timedelta(days=1)).isoformat(),
        ))
        assert len(db.list_reports()) == 3

        dropped = db.cleanup_expired()    # default retention_days=7
        assert dropped == 2, f"expected 2 dropped, got {dropped}"
        remaining = {r["incident_summary"]["incident_id"] for r in db.list_reports()}
        assert remaining == {"fresh"}
        print("    PASS: 2 expired incidents dropped, 1 fresh kept")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_cleanup_disabled_when_retention_zero():
    print("\n=== Test 11: cleanup_expired is no-op when retention_days = 0 ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"), retention_days=0)
        now = datetime.now(timezone.utc)
        db.save(_make_report(
            incident_id="ancient",
            generated_at=(now - timedelta(days=365)).isoformat(),
        ))
        dropped = db.cleanup_expired()
        assert dropped == 0, "retention_days=0 should disable cleanup"
        assert len(db.list_reports()) == 1
        print("    PASS: retention=0 disables cleanup")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_retention_sweeper_starts_and_stops():
    print("\n=== Test 12.5: retention sweeper starts + cleans + stops cleanly ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"), retention_days=1)
        # Insert one expired row
        now = datetime.now(timezone.utc)
        db.save(_make_report(
            incident_id="ancient_for_sweeper",
            generated_at=(now - timedelta(days=30)).isoformat(),
        ))
        # Short interval so we see the loop tick during the test
        db.start_retention_sweeper(interval_seconds=0.5)
        # First-pass cleanup happens IMMEDIATELY at sweeper start
        time.sleep(0.2)
        # Already gone via initial cleanup
        assert len(db.list_reports()) == 0, (
            "expected the initial sweep to drop the expired row"
        )

        # Insert a fresh row — should survive
        db.save(_make_report(incident_id="fresh_for_sweeper"))
        time.sleep(1.2)   # let the sweeper tick once more
        ids = [r["incident_summary"]["incident_id"] for r in db.list_reports()]
        assert ids == ["fresh_for_sweeper"], (
            f"sweeper deleted the fresh row, leaving: {ids}"
        )

        db.stop_retention_sweeper(timeout=2.0)
        assert db._sweeper_thread is None
        print("    PASS: sweeper started, dropped expired, preserved fresh, stopped")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_retention_sweeper_skips_when_retention_zero():
    print("\n=== Test 12.6: retention sweeper does not start when retention=0 ===")
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"), retention_days=0)
        db.start_retention_sweeper(interval_seconds=0.1)
        assert db._sweeper_thread is None, "sweeper should NOT start with retention=0"
        print("    PASS: retention=0 leaves sweeper disabled")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_public_interface_smoke():
    print("\n=== Test 12: public storage interface smoke ===")
    # ReportGenerator + the web layer rely on these four methods plus the
    # `directory` property staying callable. Asserting it here keeps a
    # regression from silently breaking those consumers if a refactor drops
    # one of them.
    d = _tmp_dir()
    try:
        db = ReportDatabase(db_path=str(d / "reports.db"))
        assert callable(getattr(db, "save", None))
        assert callable(getattr(db, "list_reports", None))
        assert callable(getattr(db, "load_raw", None))
        assert callable(getattr(db, "clear_all", None))
        assert getattr(db, "directory", None) is not None
        # save() returns the database Path on success.
        path = db.save(_make_report(incident_id="compat1"))
        assert isinstance(path, Path)
        print("    PASS: public interface intact")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    tests = [
        test_schema_bootstrap_idempotent,
        test_save_and_load_round_trip,
        test_list_reports_newest_first,
        test_save_upserts_same_incident_id,
        test_clear_all_drops_everything,
        test_list_by_source_ip,
        test_list_by_attack_type,
        test_list_by_severity,
        test_aggregate_stats,
        test_cleanup_expired,
        test_cleanup_disabled_when_retention_zero,
        test_retention_sweeper_starts_and_stops,
        test_retention_sweeper_skips_when_retention_zero,
        test_public_interface_smoke,
    ]
    failed = []
    for t in tests:
        try:
            t()
        except AssertionError as e:
            print(f"    FAIL: {e}")
            failed.append((t.__name__, str(e)))
        except Exception as e:
            import traceback
            traceback.print_exc()
            failed.append((t.__name__, f"{type(e).__name__}: {e}"))

    print("\n" + "=" * 60)
    if failed:
        print(f"{len(failed)} of {len(tests)} report_db tests FAILED")
        return 1
    print(f"All {len(tests)} report_db tests PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
