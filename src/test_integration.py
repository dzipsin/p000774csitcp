"""
test_integration.py - End-to-end integration test for the full pipeline.

Simulates the components talking to each other the way app.py would wire them,
without needing Flask, Ollama, or an actual eve.json file.

Covers:
  1. AlertRecord → IncidentManager → ReportGenerator → server-style callback
  2. Multiple alerts from same IP group into one incident
  3. Force-regenerate triggers a new report
  4. Incident closes via sweeper and fires a final regeneration
  5. Full pipeline runs without threading deadlocks

Run:
    python src/test_integration.py
"""

from __future__ import annotations

import json
import logging
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from log_monitor import AlertRecord
from incident_manager import IncidentManager
from report_generator import ReportGenerator
from storage import ReportStorage
from model_provider import ModelProvider, ProviderType


logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)


class FakeProvider(ModelProvider):
    """Returns fixed valid JSON for both stages."""
    @property
    def provider_type(self): return ProviderType.OLLAMA
    @property
    def model_name(self): return "test-fake"

    def complete(self, prompt: str) -> str:
        return self._canned()

    def complete_json(self, prompt: str, system_prompt=None) -> str:
        return self._canned(has_system=system_prompt is not None)

    def _canned(self, has_system=False):
        if has_system:
            # Stage 1
            return json.dumps({
                "classification": "true_positive",
                "severity": "High",
                "summary": "SQLi attempt captured",
                "recommendation": "block_source_ip",
                "reasoning": "Clear UNION SELECT payload targeting users table.",
            })
        else:
            # Stage 2
            return json.dumps({
                "overview": "Attacker launched a SQLi campaign against DVWA.",
                "attack_vectors": ["URL parameter"],
                "overall_attack_stage": "Initial Access",
                "ai_suggestions": ["Block the source IP", "Review webapp logs"],
                "exposure_detected": True,
                "exposure_types": ["user credentials"],
                "affected_systems": ["web application"],
                "exposure_summary": "Credential data potentially accessed.",
                "impact_assessment": "High impact if attack succeeded.",
            })


def _make_alert(src_ip="192.168.56.1", sig="ET WEB_SERVER SQL Injection Attempt"):
    return AlertRecord(
        timestamp_raw="2026-04-14T10:00:00Z",
        timestamp_display="10:00:00",
        timestamp_epoch=time.time(),
        severity_level=1,
        severity_label="critical",
        src_ip=src_ip,
        src_port="54321",
        dst_ip="172.18.0.3",
        dst_port="80",
        proto="TCP",
        signature=sig,
        signature_id=2010963,
        category="Web Application Attack",
        action="allowed",
        flow_id=int(time.time() * 1000) % 1000000,
        app_proto="http",
        in_iface="br-test",
        raw_event={
            "http": {"url": "/sqli/?id=1' UNION SELECT user FROM users#", "http_method": "GET"},
            "alert": {"metadata": {"mitre_tactic_name": ["Initial_Access"]}},
        },
    )


# ============================================================================
# Tests
# ============================================================================

def test_pipeline_basic_flow():
    print("\n=== Test 1: Full pipeline generates an incident report ===")

    received_reports = []
    received_lock = threading.Lock()

    def fake_server_push(report):
        """Simulates Server.push_incident_report."""
        with received_lock:
            received_reports.append(report)

    storage_dir = tempfile.mkdtemp(prefix="int-test-")
    try:
        storage = ReportStorage(storage_dir)

        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=0.5,   # 30 seconds
            debounce_seconds=0.5,
            sweep_interval_seconds=1.0,
        )

        generator = ReportGenerator(
            provider=FakeProvider(),
            storage=storage,
            is_repeat_offender=manager.is_repeat_offender,
            on_report_ready=fake_server_push,
        )
        manager.set_regenerate_callback(generator.generate)
        manager.start()

        # Send 3 alerts from same source
        for _ in range(3):
            manager.process_alert(_make_alert())
            time.sleep(0.1)

        # Wait for debounce + generation
        time.sleep(2.0)

        with received_lock:
            assert len(received_reports) >= 1, (
                f"Expected at least 1 report received, got {len(received_reports)}"
            )
            report = received_reports[-1]

        assert report.incident_summary.total_alerts == 3
        assert report.incident_summary.source_ip == "192.168.56.1"
        assert report.incident_summary.classification_counts["true_positive"] == 3
        assert report.incident_summary.overall_severity == "High"

        # File should be on disk
        files = list(Path(storage_dir).glob("inc_*.json"))
        assert len(files) == 1, f"Expected 1 file, got {len(files)}"

        manager.stop(close_open=True)
        time.sleep(0.5)  # let final regen flush

        print("    PASS: pipeline flowed from alert → incident → generated report → server callback")

    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


def test_pipeline_force_regenerate():
    print("\n=== Test 2: Force regenerate triggers report ===")

    received = []

    def capture(report):
        received.append(report)

    storage_dir = tempfile.mkdtemp(prefix="int-test-")
    try:
        storage = ReportStorage(storage_dir)
        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=5.0,
            debounce_seconds=60.0,   # long — so debounce doesn't fire
        )
        generator = ReportGenerator(
            provider=FakeProvider(),
            storage=storage,
            on_report_ready=capture,
        )
        manager.set_regenerate_callback(generator.generate)
        manager.start()

        manager.process_alert(_make_alert())

        # Nothing should have regenerated yet
        time.sleep(0.5)
        pre_count = len(received)

        # Force it
        count = manager.force_regenerate_all()
        assert count == 1, f"Expected 1 regen, got {count}"

        time.sleep(1.0)
        assert len(received) > pre_count, "Expected additional report after force"

        manager.stop(close_open=True)
        print(f"    PASS: force regenerate produced reports (got {len(received)} total)")

    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


def test_pipeline_sweeper_closes_incident():
    print("\n=== Test 3: Sweeper closes expired incident and fires final regen ===")

    received = []

    def capture(report):
        received.append(report)

    storage_dir = tempfile.mkdtemp(prefix="int-test-")
    try:
        storage = ReportStorage(storage_dir)
        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=0.03,   # ~2 seconds
            debounce_seconds=0.3,
            sweep_interval_seconds=0.5,
        )
        generator = ReportGenerator(
            provider=FakeProvider(),
            storage=storage,
            on_report_ready=capture,
        )
        manager.set_regenerate_callback(generator.generate)
        manager.start()

        manager.process_alert(_make_alert())

        # Wait for debounce + sweeper close
        time.sleep(4.0)

        # We should see at least one report, and the latest should be closed
        assert len(received) >= 1
        latest = received[-1]
        assert latest.incident_summary.incident_status == "closed", (
            f"Expected closed, got {latest.incident_summary.incident_status}"
        )

        manager.stop(close_open=False)
        print(f"    PASS: sweeper closed incident and fired final regen")

    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


def test_pipeline_parallel_incidents():
    print("\n=== Test 4: Parallel incidents for different source IPs ===")

    received = []
    lock = threading.Lock()

    def capture(report):
        with lock:
            received.append(report)

    storage_dir = tempfile.mkdtemp(prefix="int-test-")
    try:
        storage = ReportStorage(storage_dir)
        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=0.5,
            debounce_seconds=0.4,
        )
        generator = ReportGenerator(
            provider=FakeProvider(),
            storage=storage,
            on_report_ready=capture,
        )
        manager.set_regenerate_callback(generator.generate)
        manager.start()

        # Fire alerts from 3 different IPs nearly simultaneously
        for ip in ["10.0.0.1", "10.0.0.2", "10.0.0.3"]:
            manager.process_alert(_make_alert(src_ip=ip))

        time.sleep(2.0)

        with lock:
            incident_ids = {r.incident_summary.incident_id for r in received}

        assert len(incident_ids) == 3, (
            f"Expected 3 distinct incidents, got {len(incident_ids)}"
        )

        manager.stop(close_open=True)
        print(f"    PASS: 3 parallel incidents produced distinct reports")

    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


def test_repeat_offender_flag():
    print("\n=== Test 5: repeat_offender flag set on second incident from same IP ===")

    received = []

    def capture(report):
        received.append(report)

    storage_dir = tempfile.mkdtemp(prefix="int-test-")
    try:
        storage = ReportStorage(storage_dir)
        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=0.02,   # ~1 second
            debounce_seconds=0.3,
            sweep_interval_seconds=0.3,
        )
        generator = ReportGenerator(
            provider=FakeProvider(),
            storage=storage,
            is_repeat_offender=manager.is_repeat_offender,
            on_report_ready=capture,
        )
        manager.set_regenerate_callback(generator.generate)
        manager.start()

        # First incident
        manager.process_alert(_make_alert(src_ip="10.0.0.99"))
        time.sleep(3.0)  # let first incident close

        # Same IP again — should be flagged
        manager.process_alert(_make_alert(src_ip="10.0.0.99"))
        time.sleep(2.0)

        manager.stop(close_open=True)
        time.sleep(0.5)

        # Find reports for this IP
        my_reports = [r for r in received if r.incident_summary.source_ip == "10.0.0.99"]
        assert len(my_reports) >= 2, f"Expected at least 2 reports for the IP, got {len(my_reports)}"

        # Latest one should have repeat_offender=True
        last = my_reports[-1]
        assert last.incident_summary.repeat_offender is True, (
            "Expected repeat_offender=True on second-incident report"
        )

        print("    PASS: repeat_offender flag set correctly")

    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


# ============================================================================
# Runner
# ============================================================================

def main():
    tests = [
        test_pipeline_basic_flow,
        test_pipeline_force_regenerate,
        test_pipeline_sweeper_closes_incident,
        test_pipeline_parallel_incidents,
        test_repeat_offender_flag,
    ]

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"    FAIL: {e}")
            failed.append((test.__name__, str(e)))
        except Exception as e:
            import traceback
            traceback.print_exc()
            failed.append((test.__name__, f"{type(e).__name__}: {e}"))

    print("\n" + "=" * 60)
    if not failed:
        print(f"All {len(tests)} integration tests PASSED")
        return 0
    else:
        print(f"{len(failed)} of {len(tests)} integration tests FAILED:")
        for n, m in failed:
            print(f"  - {n}: {m}")
        return 1


if __name__ == "__main__":
    sys.exit(main())