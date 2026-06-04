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

# tests/ sits one level below src/, so reach up twice for the import root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
            # Unknown scenario - default to "true_positive high"
            return json.dumps({
                "classification": "true_positive",
                "severity": "high",
                "summary": "unknown test scenario",
                "recommendation": "escalate_tier2",
                "reasoning": "no matching eval_id",
            })

        # Only auto-block at the critical tier (P1 equivalent). High tier still
        # warrants escalation but not an immediate block from a mock.
        return json.dumps({
            "classification": scenario.expected_classification,
            "severity": scenario.expected_severity,
            "summary": f"simulated: {scenario.description}",
            "recommendation": (
                "block_source_ip"
                if scenario.expected_classification == "true_positive"
                and scenario.expected_severity == "critical"
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
        # Suricata-style severity_level: 1 = critical, 2 = high, 3 = low.
        # expected_severity already uses the lowercase 3-tier scale, so the
        # severity_label is a straight passthrough.
        severity_level=(
            1 if scenario.expected_severity == "critical"
            else 2 if scenario.expected_severity == "high"
            else 3
        ),
        severity_label=scenario.expected_severity or "low",
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
    print("\n=== Test 1: Synthetic fire -> IncidentManager -> ReportGenerator -> correlate ===")

    from report_db import ReportDatabase
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

        # retention_days=0 disables the background sweeper; we don't want a
        # daemon thread firing inside a short-lived test.
        storage = ReportDatabase(
            db_path=str(Path(storage_dir) / "reports.db"),
            retention_days=0,
        )
        generator = ReportGenerator(
            provider=provider,
            storage=storage,
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

    def sr(expected, predicted, severity_exp="critical", severity_act="critical"):
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
        expected_severity="critical",
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
        "severity": "critical",
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


def test_combined_report_builds_staircase():
    print("\n=== Test 4: Combined ablation report builds across mock runs ===")

    import tempfile
    from evaluation.run_combined_report import (
        load_raw_results,
        order_runs,
        aggregate_step_metrics,
        render_markdown,
    )

    indir = Path(tempfile.mkdtemp(prefix="combined-eval-"))
    try:
        # Synthesise 3 reps for each of 3 steps. Metrics improve across
        # the staircase so the delta column should read positive.
        steps = [
            ("baseline",     0.80, 0.70, 0.75, 0.78),
            ("react",        0.90, 0.85, 0.87, 0.86),
            ("custom_rules", 0.95, 0.95, 0.95, 0.93),
        ]

        for step, precision, recall, f1, accuracy in steps:
            for rep in range(3):
                fname = f"p6_{step}_run{rep}_20260518_raw.json"
                payload = {
                    "label": f"p6_{step}_run{rep}",
                    "timestamp": f"2026-05-18T10:{rep:02d}:00",
                    "config": {"base_url": "x", "dashboard": "y", "repeats": 1,
                               "settle_time": 30, "final_wait": 45},
                    "config_dimensions": {"step": step,
                                          "model": "qwen2.5:3b",
                                          "agent_mode": "react"},
                    "metrics": {
                        "precision": precision,
                        "recall": recall,
                        "f1": f1,
                        "accuracy": accuracy,
                        "total_scenarios": 30,
                        "matched_to_incident": 25,
                        "tp_correct": 18,
                        "fp_correct": 7,
                        "classification_errors": 0,
                    },
                    "confusion_matrix": {},
                    "scenario_results": [],
                }
                with open(indir / fname, "w", encoding="utf-8") as f:
                    json.dump(payload, f)

        # Add an unrelated run to confirm label_prefix filtering works
        with open(indir / "other_unrelated_raw.json", "w", encoding="utf-8") as f:
            json.dump({"label": "other", "timestamp": "x", "config": {},
                       "metrics": {"precision": 0.0, "recall": 0.0, "f1": 0.0,
                                   "accuracy": 0.0, "total_scenarios": 0,
                                   "matched_to_incident": 0, "tp_correct": 0,
                                   "fp_correct": 0, "classification_errors": 0},
                       "confusion_matrix": {}, "scenario_results": []}, f)

        # Load with prefix filter - should return 9 runs, not 10
        runs = load_raw_results(indir, label_prefix="p6_")
        assert len(runs) == 9, f"expected 9 prefixed runs, got {len(runs)}"

        # Order them - staircase order
        order = ["baseline", "react", "custom_rules"]
        ordered = order_runs(runs, order)
        assert len(ordered) == 9

        # Aggregate one step
        baseline_runs = [r for r in ordered
                         if (r.get("config_dimensions") or {}).get("step") == "baseline"]
        agg = aggregate_step_metrics(baseline_runs)
        assert agg["reps"] == 3
        assert abs(agg["f1_mean"] - 0.75) < 1e-9, f"f1_mean={agg['f1_mean']}"

        # Render
        outpath = indir / "combined.md"
        render_markdown(ordered, order, outpath)
        assert outpath.exists(), "combined report not written"
        content = outpath.read_text(encoding="utf-8")
        assert "staircase ablation" in content.lower(), "header missing"
        assert "Baseline" in content, "baseline row missing"
        assert "+ ReAct" in content, "react row missing"
        assert "+ Custom XSS" in content, "custom_rules row missing"
        # Delta column should show a positive change for react step
        assert "+0.120" in content, f"expected +0.120 F1 delta, content was: {content[:500]}"

        print(f"    PASS: combined report rendered ({len(content)} chars)")
    finally:
        import shutil
        shutil.rmtree(indir, ignore_errors=True)


def main():
    tests = [
        test_scenarios_fire_and_correlate,
        test_metrics_computation,
        test_report_writer,
        test_combined_report_builds_staircase,
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