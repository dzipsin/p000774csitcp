"""
run_evaluation.py - Entrypoint to run the Phase 4 evaluation harness.

Usage:
    # App must be running in another terminal first:
    #   python src/app.py
    # DVWA and Suricata must also be up.

    python -m src.evaluation.run_evaluation

Optional flags:
    --base-url http://192.168.56.101:8080   DVWA URL
    --dashboard http://127.0.0.1:5000       Running app URL
    --repeats 1                             How many times to run the full suite
    --settle-time 30                        Seconds to wait after each attack for
                                            the pipeline to catch up before firing
                                            the next. Spacing attacks avoids clustering
                                            them into one incident.
    --outdir eval_results                   Where to write the report + raw JSON
    --skip-clear                            Don't clear existing incidents first
    --label default                         Tag for this run (used in filenames)

Process:
    1. Verify dashboard is reachable
    2. Verify DVWA login works
    3. Clear existing incidents (unless --skip-clear)
    4. For each scenario:
         - fire request
         - sleep `settle_time` seconds so the pipeline has time to debounce +
           generate the report before the next attack starts a new incident
    5. Force-regenerate any still-open incidents so their reports are current
    6. Wait a final settle period, then fetch incidents
    7. Correlate scenarios → reports, compute metrics
    8. Write raw results + human-readable report to outdir

The script NEVER modifies your config. Run it against each configuration
(e.g. `include_lab_context=true` vs `false`) by editing `app.config`,
restarting the app, and passing `--label <name>` to tag the output.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
import time
from pathlib import Path
from typing import List

# Support both `python -m src.evaluation.run_evaluation` and direct invocation.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from evaluation.attack_runner import DVWAClient
    from evaluation.result_collector import (
        DashboardClient, ScenarioResult, compute_metrics,
        confusion_matrix, correlate,
    )
    from evaluation.scenarios import SCENARIOS
    from evaluation.report_writer import write_markdown_report
else:
    from .attack_runner import DVWAClient
    from .result_collector import (
        DashboardClient, ScenarioResult, compute_metrics,
        confusion_matrix, correlate,
    )
    from .scenarios import SCENARIOS
    from .report_writer import write_markdown_report


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)

log = logging.getLogger("eval")


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", default="http://192.168.56.101:8080",
                   help="DVWA base URL")
    p.add_argument("--dashboard", default="http://127.0.0.1:5000",
                   help="Running app base URL")
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="password")
    p.add_argument("--repeats", type=int, default=1,
                   help="Run the full suite this many times (for consistency measurement)")
    p.add_argument("--settle-time", type=float, default=30.0,
                   help="Seconds to wait between attacks. Must exceed debounce + expected LLM time.")
    p.add_argument("--outdir", default="eval_results")
    p.add_argument("--skip-clear", action="store_true",
                   help="Don't clear existing incidents before running")
    p.add_argument("--label", default="default",
                   help="Label for this run (included in output filenames)")
    p.add_argument("--final-wait", type=float, default=45.0,
                   help="Seconds to wait after last attack before fetching results")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    log.info("Evaluation starting: label=%s, repeats=%d", args.label, args.repeats)
    log.info("DVWA target: %s", args.base_url)
    log.info("Dashboard  : %s", args.dashboard)

    dashboard = DashboardClient(args.dashboard)
    dvwa = DVWAClient(
        base_url=args.base_url,
        username=args.username,
        password=args.password,
    )

    # -------- Pre-flight checks --------
    log.info("Pre-flight: checking dashboard reachability...")
    if not _check_dashboard(dashboard):
        log.error("Dashboard not reachable. Is the app running at %s?", args.dashboard)
        return 2

    log.info("Pre-flight: logging into DVWA...")
    try:
        dvwa.login()
    except RuntimeError as e:
        log.error("DVWA login failed: %s", e)
        return 3

    # Optional clear
    if not args.skip_clear:
        log.info("Clearing existing incidents...")
        dashboard.clear_incidents()
        time.sleep(1.0)

    # -------- Run the scenario suite --------
    all_scenario_results: List[ScenarioResult] = []

    for rep in range(1, args.repeats + 1):
        log.info("=" * 60)
        log.info("Repetition %d of %d", rep, args.repeats)
        log.info("=" * 60)

        for i, scenario in enumerate(SCENARIOS, start=1):
            log.info(
                "[%d/%d] Firing %s (%s)",
                i, len(SCENARIOS), scenario.eval_id, scenario.category,
            )
            fire = dvwa.fire(scenario)
            if fire.error:
                log.warning("  fired with error: %s", fire.error)
            else:
                log.info("  HTTP %d → %s", fire.http_status, fire.url_fired[:90])

            sr = ScenarioResult(scenario=scenario, fire=fire)
            all_scenario_results.append(sr)

            # Space out requests so each scenario produces its own incident.
            # If attacks fire too close together they cluster into a single
            # incident per source IP, making per-scenario matching harder.
            # We skip the sleep on the very last scenario.
            is_last = (rep == args.repeats) and (i == len(SCENARIOS))
            if not is_last:
                log.debug("  sleeping %.1fs for pipeline to settle...", args.settle_time)
                time.sleep(args.settle_time)

    # -------- Final settle + force regenerate --------
    log.info("Final wait: %.1fs (allowing pipeline to catch up)...", args.final_wait)
    time.sleep(args.final_wait)

    log.info("Force regenerating any open incidents...")
    dashboard.force_regenerate()
    time.sleep(10.0)  # brief pause for the regeneration to complete

    # -------- Fetch and correlate --------
    log.info("Fetching incidents from dashboard...")
    incidents = dashboard.list_incidents()
    log.info("Fetched %d incident(s)", len(incidents))

    log.info("Correlating scenarios → reports...")
    correlate(all_scenario_results, incidents)

    metrics = compute_metrics(all_scenario_results)
    matrix = confusion_matrix(all_scenario_results)

    log.info("-" * 60)
    log.info("SUMMARY")
    log.info("-" * 60)
    log.info("Total scenarios        : %d", metrics.total_scenarios)
    log.info("Fired successfully     : %d", metrics.fired_successfully)
    log.info("Matched to incident    : %d", metrics.matched_to_incident)
    log.info("No detection           : %d", metrics.no_detection)
    log.info("Classification errors  : %d", metrics.classification_errors)
    log.info("TP correct  : %d",  metrics.tp_correct)
    log.info("TP missed   : %d",  metrics.tp_missed)
    log.info("FP correct  : %d",  metrics.fp_correct)
    log.info("FP incorrect: %d",  metrics.fp_incorrect)
    log.info("Precision   : %.3f", metrics.precision)
    log.info("Recall      : %.3f", metrics.recall)
    log.info("F1          : %.3f", metrics.f1)
    log.info("Accuracy    : %.3f", metrics.accuracy)

    # -------- Write outputs --------
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    base_name = f"{args.label}_{timestamp}"

    raw_path = outdir / f"{base_name}_raw.json"
    _write_raw(raw_path, all_scenario_results, metrics, matrix, args)
    log.info("Raw results: %s", raw_path)

    report_path = outdir / f"{base_name}_report.md"
    write_markdown_report(
        path=report_path,
        label=args.label,
        scenario_results=all_scenario_results,
        metrics=metrics,
        matrix=matrix,
        args=args,
    )
    log.info("Report     : %s", report_path)

    log.info("Evaluation complete.")
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _check_dashboard(dashboard: DashboardClient) -> bool:
    try:
        # Any reachable response is good enough
        dashboard.list_incidents()
        return True
    except Exception:
        return False


def _write_raw(path, scenario_results, metrics, matrix, args) -> None:
    """Serialise all raw results for post-hoc analysis."""
    payload = {
        "label": args.label,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "config": {
            "base_url": args.base_url,
            "dashboard": args.dashboard,
            "repeats": args.repeats,
            "settle_time": args.settle_time,
            "final_wait": args.final_wait,
        },
        "metrics": metrics.as_dict(),
        "confusion_matrix": matrix,
        "scenario_results": [_sr_to_dict(sr) for sr in scenario_results],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def _sr_to_dict(sr) -> dict:
    return {
        "eval_id": sr.scenario.eval_id,
        "category": sr.scenario.category,
        "description": sr.scenario.description,
        "expected_classification": sr.scenario.expected_classification,
        "expected_severity": sr.scenario.expected_severity,
        "expected_attack_type": sr.scenario.expected_attack_type,
        "expected_to_trigger_suricata": sr.scenario.expected_to_trigger_suricata,
        "fire": dataclasses.asdict(sr.fire),
        "matched": sr.matched,
        "status": sr.status,
        "incident_id": sr.incident_id,
        "classification": sr.classification,
    }


if __name__ == "__main__":
    sys.exit(main())