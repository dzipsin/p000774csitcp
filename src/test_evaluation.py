"""
test_evaluation.py - Sanity tests for the Phase 4 evaluation harness.

Doesn't hit DVWA or a real LLM. Simulates the whole pipeline in-process:
  1. Builds fake AlertRecords that look like they came from firing scenarios
  2. Runs them through IncidentManager + ReportGenerator (with a mock LLM)
  3. Exports the reports to dict form (simulating a /api/incidents response)
  4. Runs the correlator + metrics
  5. Asserts the expected outcomes

Run:
    python src/test_evaluation.py
"""

from __future__ import annotations

import dataclasses
import json
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from log_monitor import AlertRecord
from incident_manager import IncidentManager
from report_generator import ReportGenerator
from model_provider import ModelProvider, ProviderType
from evaluation.attack_runner import FireResult
from evaluation.result_collector import (
    ScenarioResult, compute_metrics, confusion_matrix, correlate,
)
from evaluation.scenarios import SCENARIOS, find_scenario

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)


# ============================================================================
# Mock LLM that classifies based on scenario eval_id embedded in the URL
# ============================================================================

class ScenarioAwareProvider(ModelProvider):
    """Returns classifications appropriate to whatever eval_id it sees in the prompt.

    This simulates an LLM that always gets the classification right, so we can
    verify the correlation and metrics machinery end-to-end without worrying
    about LLM correctness.
    """

    @property
    def provider_type(self): return ProviderType.OLLAMA
    @property
    def model_name(self): return "test-scenario-aware"

    def complete(self, prompt: str) -> str:
        return self.complete_json(prompt)

    def complete_json(self, prompt: str, system_prompt=None) -> str:
        if system_prompt is not None:
            return self._stage1(prompt)
        return self._stage2(prompt)

    def _stage1(self, prompt: str) -> str:
        # Find the eval_id in the prompt and look up its expected label
        eval_id = _extract_eval_id(prompt)
        scenario = find_scenario(eval_id) if eval_id else None

        if scenario is None:
            # Unknown scenario — default to "true_positive High"
            return json.dumps({
                "classification": "true_positive",
                "severity": "High",
                "summary": "unknown test scenario",
                "recommendation": "escalate_tier2",
                "reasoning": "no matching eval_id",
            })

        return json.dumps({
            "classification": scenario.expected_classification,
            "severity": scenario.expected_severity,
            "summary": f"simulated: {scenario.description}",
            "recommendation": (
                "block_source_ip"
                if scenario.expected_classification == "true_positive"
                and scenario.expected_severity == "High"
                else "escalate_tier2"
                if scenario.expected_classification == "true_positive"
                else "continue_monitoring"
            ),
            "reasoning": f"mock: expected to be {scenario.expected_classification}",
        })

    def _stage2(self, prompt: str) -> str:
        return json.dumps({
            "overview": "Simulated incident narrative.",
            "attack_vectors": ["URL parameter"],
            "overall_attack_stage": "Initial Access",
            "ai_suggestions": ["Block source", "Investigate"],
            "exposure_detected": True,
            "exposure_types": ["user data"],
            "affected_systems": ["web app"],
            "exposure_summary": "Simulated exposure.",
            "impact_assessment": "Simulated impact.",
        })


def _extract_eval_id(prompt: str) -> str:
    """Pull eval_id=<value> out of the prompt's alert data."""
    marker = "eval_id="
    i = prompt.find(marker)
    if i < 0:
        return ""
    start = i + len(marker)
    end = start
    while end < len(prompt) and prompt[end] not in (" ", "&", '"', "\\", "\n", ",", "}"):
        end += 1
    return prompt[start:end]


# ============================================================================
# Synthetic alert builder: produces an AlertRecord that looks like Suricata
# detected the corresponding scenario.
# ============================================================================

def _synthetic_alert_for(scenario) -> AlertRecord:
    """Build an AlertRecord with the scenario's eval_id in its URL."""
    # Build a URL with the eval_id marker + the scenario's actual payload
    base = scenario.path
    params = dict(scenario.query_params)
    params["eval_id"] = scenario.eval_id
    from urllib.parse import urlencode
    query = urlencode(params)
    url = f"{base}?{query}"

    # Pick a Suricata signature appropriate to the attack type
    signature = {
        "SQLi":            "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI",
        "XSS":             "ET WEB_SERVER Script tag in URI Possible Cross Site Scripting Attempt",
        "CommandInjection":"ET WEB_SERVER Command Injection Attempt",
        "FileInclusion":   "ET WEB_SERVER ../../ in URI - Possible Directory Traversal Attempt",
        "PathTraversal":   "ET WEB_SERVER ../../ in URI - Possible Directory Traversal Attempt",
        "Reconnaissance":  "ET SCAN Suspicious inbound to web server",
        "Benign":          "ET POLICY Possible User-Agent",
    }.get(scenario.category, "ET POLICY Unknown")

    return AlertRecord(
        timestamp_raw=time.strftime("%Y-%m-%dT%H:%M:%S"),
        timestamp_display=time.strftime("%H:%M:%S"),
        timestamp_epoch=time.time(),
        severity_level=1 if scenario.expected_severity == "High" else 2 if scenario.expected_severity == "Medium" else 3,
        severity_label=scenario.expected_severity.lower() if scenario.expected_severity else "low",
        src_ip="192.168.56.1",
        src_port="54321",
        dst_ip="172.18.0.2",
        dst_port="80",
        proto="TCP",
        signature=signature,
        signature_id=2010963,
        category="Web Application Attack",
        action="allowed",
        flow_id=hash(scenario.eval_id) & 0xFFFFFFFF,
        app_proto="http",
        in_iface="br-test",
        raw_event={
            "http": {
                "url": url,
                "http_method": scenario.method,
                "status": 200,
            },
            "alert": {"metadata": {"mitre_tactic_name": ["Initial_Access"]}},
        },
    )


# ============================================================================
# Tests
# ============================================================================

def test_scenarios_fire_and_correlate():
    print("\n=== Test 1: Synthetic fire → IncidentManager → ReportGenerator → correlate ===")

    from storage import ReportStorage
    import tempfile

    storage_dir = tempfile.mkdtemp(prefix="eval-test-")
    try:
        # Build pipeline with a mock provider
        provider = ScenarioAwareProvider()
        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=0.5,
            debounce_seconds=0.3,
            sweep_interval_seconds=0.5,
        )
        # Capture reports in-memory
        reports_captured = []

        def capture(report):
            reports_captured.append(report)

        generator = ReportGenerator(
            provider=provider,
            storage=ReportStorage(storage_dir),
            summary_mode="template",  # avoid relying on the mock for stage 2
            max_retries=0,
            on_report_ready=capture,
        )
        manager.set_regenerate_callback(generator.generate)
        manager.start()

        # Pick a small representative subset so the test runs fast.
        # Use different source IPs so they don't all group together.
        subset = [
            SCENARIOS[0],   # SQLi UNION (TP/High)
            SCENARIOS[8],   # XSS script (TP/High)
            SCENARIOS[22],  # Benign home (FP/Low)
        ]

        scenario_results = []
        for i, sc in enumerate(subset):
            fr = FireResult(
                eval_id=sc.eval_id,
                sent_at_epoch=time.time(),
                sent_at_iso=time.strftime("%Y-%m-%dT%H:%M:%S"),
                http_status=200,
                url_fired=f"http://fake{sc.path}",
            )
            sr = ScenarioResult(scenario=sc, fire=fr)
            scenario_results.append(sr)

            # Feed a synthetic alert into the manager with a unique source IP
            # per scenario so each gets its own incident
            alert = _synthetic_alert_for(sc)
            alert = dataclasses.replace(alert, src_ip=f"10.0.0.{10 + i}")
            manager.process_alert(alert)

            time.sleep(1.5)  # allow debounce + generation

        manager.stop(close_open=True)
        time.sleep(1.0)

        # Convert reports to dict form (simulating /api/incidents response)
        incidents_dicts = [dataclasses.asdict(r) for r in reports_captured]

        # De-duplicate: report_generator emits versioned reports; keep latest per incident
        latest = {}
        for inc in incidents_dicts:
            iid = inc["incident_summary"]["incident_id"]
            latest[iid] = inc
        incidents_dicts = list(latest.values())

        correlate(scenario_results, incidents_dicts)

        # Assertions
        print(f"  Captured {len(reports_captured)} reports, {len(incidents_dicts)} distinct incidents")
        for sr in scenario_results:
            print(f"  {sr.scenario.eval_id}: status={sr.status}, "
                  f"predicted={sr.actual_classification}, "
                  f"expected={sr.scenario.expected_classification}")

        matched = [sr for sr in scenario_results if sr.matched]
        assert len(matched) >= 2, (
            f"Expected at least 2 of 3 scenarios to match, got {len(matched)}. "
            "Check synthetic alert URL has eval_id in it."
        )

        correct = [sr for sr in matched if sr.correct_classification]
        assert len(correct) == len(matched), (
            f"ScenarioAwareProvider should get all classifications right; "
            f"got {len(correct)}/{len(matched)}"
        )

        print(f"    PASS: {len(matched)}/{len(subset)} matched, {len(correct)} correct")

    finally:
        import shutil
        shutil.rmtree(storage_dir, ignore_errors=True)


def test_metrics_computation():
    print("\n=== Test 2: Metrics computation from fabricated results ===")

    # Build synthetic scenario_results that exercise every metric
    from evaluation.scenarios import Scenario

    def sr(expected, predicted, severity_exp="High", severity_act="High"):
        scenario = Scenario(
            eval_id=f"test_{id(predicted)}",
            category="SQLi",
            description="test",
            method="GET",
            path="/",
            expected_classification=expected,
            expected_severity=severity_exp,
            expected_attack_type="SQLi",
        )
        fr = FireResult(
            eval_id=scenario.eval_id,
            sent_at_epoch=time.time(),
            sent_at_iso="",
            http_status=200,
            url_fired="",
        )
        r = ScenarioResult(scenario=scenario, fire=fr)
        if predicted is None:
            r.status = "no_detection"
        else:
            r.matched = True
            r.status = "matched"
            r.classification = {
                "classification": predicted,
                "severity": severity_act,
                "attack_type": "SQLi",
                "confidence_score": 0.9,
                "status": "complete",
            }
        return r

    results = [
        sr("true_positive", "true_positive"),       # TP correct
        sr("true_positive", "true_positive"),       # TP correct
        sr("true_positive", "likely_false_positive"),  # TP missed
        sr("likely_false_positive", "likely_false_positive"),  # FP correct
        sr("likely_false_positive", "true_positive"),  # FP incorrect
        sr("true_positive", None),                  # no detection
    ]

    metrics = compute_metrics(results)

    assert metrics.tp_correct == 2, f"Expected 2 TP correct, got {metrics.tp_correct}"
    assert metrics.tp_missed == 1, f"Expected 1 TP missed, got {metrics.tp_missed}"
    assert metrics.fp_correct == 1, f"Expected 1 FP correct, got {metrics.fp_correct}"
    assert metrics.fp_incorrect == 1, f"Expected 1 FP incorrect, got {metrics.fp_incorrect}"
    assert metrics.no_detection == 1, f"Expected 1 no_detection, got {metrics.no_detection}"

    # Precision = TP / (TP + FP_incorrect) = 2 / (2+1) = 0.667
    assert abs(metrics.precision - 2/3) < 0.001, f"Precision wrong: {metrics.precision}"
    # Recall = TP / (TP + TP_missed) = 2 / (2+1) = 0.667
    assert abs(metrics.recall - 2/3) < 0.001, f"Recall wrong: {metrics.recall}"

    matrix = confusion_matrix(results)
    assert matrix["true_positive"]["true_positive"] == 2
    assert matrix["true_positive"]["likely_false_positive"] == 1
    assert matrix["likely_false_positive"]["likely_false_positive"] == 1
    assert matrix["likely_false_positive"]["true_positive"] == 1

    print(f"    PASS: P={metrics.precision:.3f} R={metrics.recall:.3f} F1={metrics.f1:.3f}")


def test_report_writer():
    print("\n=== Test 3: Markdown report writes without error ===")

    import tempfile
    from evaluation.report_writer import write_markdown_report
    from evaluation.scenarios import Scenario

    s = Scenario(
        eval_id="test_001",
        category="SQLi",
        description="test scenario",
        method="GET",
        path="/",
        expected_classification="true_positive",
        expected_severity="High",
        expected_attack_type="SQLi",
    )
    fr = FireResult(
        eval_id="test_001", sent_at_epoch=time.time(), sent_at_iso="",
        http_status=200, url_fired="http://test/",
    )
    result = ScenarioResult(scenario=s, fire=fr)
    result.matched = True
    result.status = "matched"
    result.classification = {
        "classification": "true_positive",
        "severity": "High",
        "attack_type": "SQLi",
        "confidence_score": 0.9,
        "status": "complete",
    }

    from evaluation.result_collector import compute_metrics, confusion_matrix
    metrics = compute_metrics([result])
    matrix = confusion_matrix([result])

    class FakeArgs:
        base_url = "http://test:8080"
        dashboard = "http://localhost:5000"
        repeats = 1
        settle_time = 30.0

    outpath = Path(tempfile.mkdtemp()) / "report.md"
    write_markdown_report(outpath, "test", [result], metrics, matrix, FakeArgs())
    assert outpath.exists(), "Report file not written"
    content = outpath.read_text()
    assert "# Evaluation Report" in content
    assert "test_001" in content
    assert "Precision" in content
    print(f"    PASS: report written ({len(content)} chars)")


def main():
    tests = [
        test_scenarios_fire_and_correlate,
        test_metrics_computation,
        test_report_writer,
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
        print(f"{len(failed)} of {len(tests)} evaluation tests FAILED")
        return 1
    print(f"All {len(tests)} evaluation tests PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())