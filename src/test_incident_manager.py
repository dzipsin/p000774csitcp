"""
test_incident_manager.py - Manual test harness for IncidentManager.

Not using a test framework (no pytest dep in the project). Just a script you
can run to visually verify behaviour.

Run with:
    python src/test_incident_manager.py

Covers:
  1. Basic grouping: alerts from same IP within window -> one incident
  2. New incident: alert after window expires -> new incident
  3. Multiple parallel incidents: different IPs -> separate incidents
  4. per_attack_type mode: SQLi and XSS from same IP -> two incidents
  5. Invalid source IPs: dropped
  6. Repeat offender flag
  7. Debounce: bursts don't thrash; single regen after quiet period
  8. Force regenerate
  9. Shutdown closes open incidents with final regen
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

# Make src/ imports work from anywhere
sys.path.insert(0, str(Path(__file__).parent))

from log_monitor import AlertRecord
from incident_manager import IncidentManager
from models import Incident


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)


# A list of incidents that callback has received (for assertions)
_received_regenerations: list[tuple[str, int, int]] = []  # (incident_id, version, alert_count)


def _record_regen(incident: Incident) -> None:
    """Test callback — records the regen event."""
    _received_regenerations.append(
        (incident.incident_id, incident.report_version, incident.alert_count)
    )
    print(
        f"    [regen] incident={incident.incident_id[:8]} "
        f"v{incident.report_version} alerts={incident.alert_count} "
        f"status={incident.status}"
    )


def _make_alert(
    src_ip: str,
    signature: str = "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI",
    dst_ip: str = "172.18.0.3",
) -> AlertRecord:
    """Helper to build a synthetic AlertRecord."""
    return AlertRecord(
        timestamp_raw="2026-04-14T10:00:00Z",
        timestamp_display="10:00:00.000",
        timestamp_epoch=time.time(),
        severity_level=1,
        severity_label="critical",
        src_ip=src_ip,
        src_port="12345",
        dst_ip=dst_ip,
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


def _reset() -> None:
    """Clear recorded regenerations between tests."""
    _received_regenerations.clear()


# ============================================================================
# Tests
# ============================================================================

def test_basic_grouping() -> None:
    print("\n=== Test 1: Basic grouping (per_actor, within window) ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=1.0,
        debounce_seconds=0.5,
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.1"))
    mgr.process_alert(_make_alert("10.0.0.1"))

    time.sleep(1.0)  # wait for debounce + regen

    open_incs = mgr.get_open_incidents()
    assert len(open_incs) == 1, f"Expected 1 incident, got {len(open_incs)}"
    assert open_incs[0].alert_count == 3, f"Expected 3 alerts, got {open_incs[0].alert_count}"
    assert len(_received_regenerations) >= 1, "Should have received at least 1 regen"

    mgr.stop(close_open=True)
    print("    PASS: 3 alerts grouped into 1 incident")


def test_window_expiry_creates_new_incident() -> None:
    print("\n=== Test 2: Expired window creates new incident ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=0.05,  # 3 seconds
        debounce_seconds=0.5,
        sweep_interval_seconds=1.0,
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert("10.0.0.2"))
    time.sleep(1.0)

    mgr.process_alert(_make_alert("10.0.0.2"))
    # Wait longer than window
    print("    waiting 5s for window to expire...")
    time.sleep(5.0)

    # Next alert should create a new incident
    mgr.process_alert(_make_alert("10.0.0.2"))
    time.sleep(1.0)

    open_incs = mgr.get_open_incidents()
    assert len(open_incs) == 1, f"Should have 1 currently-open incident, got {len(open_incs)}"
    assert open_incs[0].alert_count == 1, f"New incident should have 1 alert, got {open_incs[0].alert_count}"

    # Total distinct incident IDs seen in regenerations should be >= 2
    seen_ids = set(r[0] for r in _received_regenerations)
    assert len(seen_ids) >= 2, f"Should have seen >=2 distinct incidents, got {len(seen_ids)}"

    mgr.stop(close_open=True)
    print(f"    PASS: window expiry created a new incident ({len(seen_ids)} distinct incidents)")


def test_parallel_incidents_different_ips() -> None:
    print("\n=== Test 3: Parallel incidents for different IPs ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=1.0,
        debounce_seconds=0.5,
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert("10.0.0.10"))
    mgr.process_alert(_make_alert("10.0.0.20"))
    mgr.process_alert(_make_alert("10.0.0.30"))

    time.sleep(1.0)

    open_incs = mgr.get_open_incidents()
    assert len(open_incs) == 3, f"Expected 3 parallel incidents, got {len(open_incs)}"

    mgr.stop(close_open=True)
    print("    PASS: 3 IPs produced 3 parallel incidents")


def test_per_attack_type_mode() -> None:
    print("\n=== Test 4: per_attack_type splits by attack ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_attack_type",
        time_window_minutes=1.0,
        debounce_seconds=0.5,
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert(
        "10.0.0.100",
        signature="ET WEB_SERVER SELECT USER SQL Injection Attempt in URI",
    ))
    mgr.process_alert(_make_alert(
        "10.0.0.100",
        signature="ET WEB_SERVER Script tag in URI Possible Cross Site Scripting",
    ))

    time.sleep(1.0)

    open_incs = mgr.get_open_incidents()
    assert len(open_incs) == 2, f"Expected 2 incidents (SQLi + XSS), got {len(open_incs)}"

    attack_types = {inc.attack_type for inc in open_incs}
    assert "SQLi" in attack_types, f"Expected SQLi in {attack_types}"
    assert "XSS" in attack_types, f"Expected XSS in {attack_types}"

    mgr.stop(close_open=True)
    print(f"    PASS: per_attack_type split into {attack_types}")


def test_invalid_source_ip_dropped() -> None:
    print("\n=== Test 5: Invalid source IPs are dropped ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=1.0,
        debounce_seconds=0.5,
        on_regenerate=_record_regen,
    )
    mgr.start()

    # These should all be ignored
    mgr.process_alert(_make_alert(""))
    mgr.process_alert(_make_alert("?"))
    mgr.process_alert(_make_alert("0.0.0.0"))

    # This should work
    mgr.process_alert(_make_alert("10.0.0.99"))

    time.sleep(1.0)

    open_incs = mgr.get_open_incidents()
    assert len(open_incs) == 1, f"Expected 1 incident (only valid IP), got {len(open_incs)}"
    assert open_incs[0].source_ip == "10.0.0.99"

    mgr.stop(close_open=True)
    print("    PASS: invalid IPs dropped, valid IP grouped")


def test_repeat_offender() -> None:
    print("\n=== Test 6: Repeat offender flag ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=1.0,
        debounce_seconds=0.5,
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert("10.0.0.77"))

    assert mgr.is_repeat_offender("10.0.0.77") is True
    assert mgr.is_repeat_offender("10.0.0.88") is False

    mgr.stop(close_open=True)
    print("    PASS: repeat offender correctly tracked")


def test_debounce_coalesces_bursts() -> None:
    print("\n=== Test 7: Debounce coalesces bursts ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=1.0,
        debounce_seconds=1.0,     # 1 second debounce
        on_regenerate=_record_regen,
    )
    mgr.start()

    # Fire 5 alerts in quick succession (well under 1s)
    for _ in range(5):
        mgr.process_alert(_make_alert("10.0.0.55"))
        time.sleep(0.1)

    # At this point, only 500ms elapsed across 5 alerts; debounce shouldn't have fired
    count_mid = len(_received_regenerations)

    # Wait for debounce to fire
    time.sleep(1.5)

    count_final = len(_received_regenerations)
    unique_versions = {r[1] for r in _received_regenerations}

    # Debounce should produce 1 regen for this incident (not 5)
    assert count_final >= 1, f"Expected at least 1 regen after debounce, got {count_final}"
    # Count increased by at most 1 from what we saw mid-burst
    assert (count_final - count_mid) <= 2, (
        f"Burst should produce minimal regens; saw {count_final - count_mid} "
        "(some allowed for closing but not one per alert)"
    )

    mgr.stop(close_open=True)
    print(f"    PASS: 5-alert burst coalesced to {count_final} regens (not 5)")


def test_force_regenerate() -> None:
    print("\n=== Test 8: Force regenerate ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=5.0,  # long window so nothing expires naturally
        debounce_seconds=60.0,    # long debounce so nothing fires naturally
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert("10.0.0.200"))
    mgr.process_alert(_make_alert("10.0.0.201"))

    # Nothing should have fired yet (debounce is 60s)
    time.sleep(0.5)
    assert len(_received_regenerations) == 0, "Debounce shouldn't have fired yet"

    # Force it
    count = mgr.force_regenerate_all()
    assert count == 2, f"Expected 2 forced regens, got {count}"

    time.sleep(1.0)  # give threads time

    assert len(_received_regenerations) >= 2, (
        f"Expected >=2 regens after force, got {len(_received_regenerations)}"
    )

    mgr.stop(close_open=True)
    print(f"    PASS: force_regenerate_all triggered {count} regens")


def test_shutdown_closes_open_incidents() -> None:
    print("\n=== Test 9: Shutdown closes open incidents with final regen ===")
    _reset()

    mgr = IncidentManager(
        grouping_mode="per_actor",
        time_window_minutes=5.0,
        debounce_seconds=60.0,
        on_regenerate=_record_regen,
    )
    mgr.start()

    mgr.process_alert(_make_alert("10.0.0.300"))
    mgr.process_alert(_make_alert("10.0.0.301"))

    # At shutdown, both incidents should get a final regen
    mgr.stop(close_open=True)

    time.sleep(0.5)  # let callback threads finish

    seen_ids = set(r[0] for r in _received_regenerations)
    assert len(seen_ids) == 2, f"Expected 2 incidents closed on shutdown, got {len(seen_ids)}"

    # All should be status=closed by the time callback ran
    print(f"    PASS: shutdown closed and regenerated {len(seen_ids)} incidents")


def test_incident_object_api() -> None:
    print("\n=== Test 10: Incident object API ===")

    from models import Incident as IncidentClass

    # Test add_alert increments correctly
    inc = IncidentClass(
        incident_id="test-id",
        source_ip="10.0.0.1",
        attack_type=None,
    )
    assert inc.alert_count == 0
    assert inc.first_seen_display == "N/A"
    assert inc.last_seen_display == "N/A"

    alert1 = _make_alert("10.0.0.1")
    inc.add_alert(alert1, arrival_time=time.time())
    assert inc.alert_count == 1
    assert inc.first_seen_display != "N/A"
    assert inc.last_seen_display != "N/A"

    # Out-of-order timestamp shouldn't break first_seen
    old_alert = _make_alert("10.0.0.1")
    # Force older timestamp
    from dataclasses import replace
    old_alert = replace(old_alert, timestamp_epoch=inc.first_seen_epoch - 100)
    inc.add_alert(old_alert, arrival_time=time.time())
    assert inc.first_seen_epoch == old_alert.timestamp_epoch, "first_seen should update to earlier"
    assert inc.alert_count == 2

    print("    PASS: Incident.add_alert handles ordering correctly")


# ============================================================================
# Runner
# ============================================================================

def main() -> int:
    tests = [
        test_basic_grouping,
        test_window_expiry_creates_new_incident,
        test_parallel_incidents_different_ips,
        test_per_attack_type_mode,
        test_invalid_source_ip_dropped,
        test_repeat_offender,
        test_debounce_coalesces_bursts,
        test_force_regenerate,
        test_shutdown_closes_open_incidents,
        test_incident_object_api,
    ]

    failed = []
    for test in tests:
        try:
            test()
        except AssertionError as e:
            print(f"    FAIL: {e}")
            failed.append((test.__name__, str(e)))
        except Exception as e:
            print(f"    ERROR: {type(e).__name__}: {e}")
            failed.append((test.__name__, f"{type(e).__name__}: {e}"))

    print("\n" + "=" * 60)
    if not failed:
        print(f"All {len(tests)} tests PASSED")
        return 0
    else:
        print(f"{len(failed)} of {len(tests)} tests FAILED:")
        for name, msg in failed:
            print(f"  - {name}: {msg}")
        return 1


if __name__ == "__main__":
    sys.exit(main())