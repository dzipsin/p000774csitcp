"""
run_combined_report.py - Aggregate per-config evaluation runs into one ablation report.

The Phase 6 staircase ablation runs each configuration in series (operator
swaps app.config and Suricata setup between configs, runs the harness,
and labels the output). This script reads back all the per-config raw
JSON files in an output directory and produces:

  - A markdown table comparing metrics across configs in operator-defined
    order (so the staircase reads top-to-bottom as each capability is added)
  - A delta column showing F1 / recall improvement vs the previous row

Usage:
    python -m src.evaluation.run_combined_report \\
        --indir eval_results \\
        --label-prefix p6_ \\
        --out eval_results/p6_combined_report.md \\
        --order baseline,model_swap,react,enrich,custom_rules

The --order argument matters: configs are listed in the report in that
order so the staircase narrative reads correctly. Each comma-separated
value should match the `step` field of one config_dimensions block -see
docs/RUNBOOK Phase 6 procedure for the conventional labels.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("combined-eval")


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_raw_results(indir: Path, label_prefix: Optional[str]) -> List[Dict[str, Any]]:
    """Read every <indir>/*_raw.json. Optionally filter to filenames starting
    with `label_prefix` so the operator can mix multiple eval campaigns in
    the same directory."""
    out: List[Dict[str, Any]] = []
    for raw_path in sorted(indir.glob("*_raw.json")):
        if label_prefix and not raw_path.name.startswith(label_prefix):
            continue
        try:
            with open(raw_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.warning("Skipping unreadable %s: %s", raw_path.name, e)
            continue
        payload["_source_file"] = raw_path.name
        out.append(payload)
    return out


# ---------------------------------------------------------------------------
# Ordering + grouping
# ---------------------------------------------------------------------------

def order_runs(
    runs: List[Dict[str, Any]],
    step_order: List[str],
) -> List[Dict[str, Any]]:
    """Sort runs into the operator-specified staircase order.

    A run is matched to a step by looking at:
      1. config_dimensions["step"]  (canonical, if present)
      2. label                       (fallback -best-effort prefix match)

    Runs that don't match any step go to the end with a warning. Within a
    step, runs are sorted by timestamp ascending.
    """
    by_step: Dict[str, List[Dict[str, Any]]] = {step: [] for step in step_order}
    unmatched: List[Dict[str, Any]] = []

    for run in runs:
        dims = run.get("config_dimensions") or {}
        step_value = dims.get("step")
        if step_value in by_step:
            by_step[step_value].append(run)
            continue

        # Fallback: try to match by label prefix
        label = run.get("label", "")
        matched = False
        for step in step_order:
            if label.startswith(step):
                by_step[step].append(run)
                matched = True
                break
        if not matched:
            unmatched.append(run)
            log.warning(
                "Run %s (label=%s) did not match any step in --order; appending"
                " to the end.",
                run.get("_source_file"), label,
            )

    ordered: List[Dict[str, Any]] = []
    for step in step_order:
        # Sort runs within a step by timestamp ascending so repeated runs
        # appear in chronological order.
        ordered.extend(sorted(
            by_step[step],
            key=lambda r: r.get("timestamp", ""),
        ))
    ordered.extend(unmatched)
    return ordered


def aggregate_step_metrics(
    runs: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Average each metric across multiple runs of the same step (3 reps).

    Returns the mean for precision, recall, F1, accuracy. Counts are summed.
    """
    n = len(runs)
    if n == 0:
        return {}

    sum_precision = 0.0
    sum_recall = 0.0
    sum_f1 = 0.0
    sum_accuracy = 0.0
    sum_total = 0
    sum_matched = 0
    sum_tp = 0
    sum_fp = 0
    sum_errors = 0

    for run in runs:
        m = run.get("metrics") or {}
        sum_precision += float(m.get("precision", 0.0) or 0.0)
        sum_recall    += float(m.get("recall", 0.0) or 0.0)
        sum_f1        += float(m.get("f1", 0.0) or 0.0)
        sum_accuracy  += float(m.get("accuracy", 0.0) or 0.0)
        sum_total     += int(m.get("total_scenarios", 0) or 0)
        sum_matched   += int(m.get("matched_to_incident", 0) or 0)
        sum_tp        += int(m.get("tp_correct", 0) or 0)
        sum_fp        += int(m.get("fp_correct", 0) or 0)
        sum_errors    += int(m.get("classification_errors", 0) or 0)

    return {
        "reps": n,
        "precision_mean": sum_precision / n,
        "recall_mean":    sum_recall / n,
        "f1_mean":        sum_f1 / n,
        "accuracy_mean":  sum_accuracy / n,
        "total_scenarios_avg": sum_total / n,
        "matched_to_incident_avg": sum_matched / n,
        "tp_correct_avg": sum_tp / n,
        "fp_correct_avg": sum_fp / n,
        "errors_avg": sum_errors / n,
    }


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

_HUMAN_STEP_LABELS = {
    "baseline":     "Baseline -llama3.2:3b / single-shot / no enrichment / default rules",
    "model_swap":   "+ Model swap -qwen2.5:3b / single-shot / no enrichment / default rules",
    "react":        "+ ReAct loop -qwen2.5:3b / react / no enrichment / default rules",
    "enrich":       "+ Auto-enrichment -qwen2.5:3b / react / enrichment ON / default rules",
    "custom_rules": "+ Custom XSS rules -qwen2.5:3b / react / enrichment ON / custom rules",
}


def render_markdown(
    ordered_runs: List[Dict[str, Any]],
    step_order: List[str],
    out_path: Path,
) -> None:
    """Write the combined ablation report to disk.

    Groups runs by step, averages metrics within a step, computes deltas
    vs the previous step's F1 / recall, and writes a single markdown table
    plus a per-step detail section.
    """
    # Group runs by step in the SAME order they appeared in step_order
    by_step: Dict[str, List[Dict[str, Any]]] = {step: [] for step in step_order}
    for run in ordered_runs:
        dims = run.get("config_dimensions") or {}
        step_value = dims.get("step")
        if step_value in by_step:
            by_step[step_value].append(run)
            continue
        label = run.get("label", "")
        for step in step_order:
            if label.startswith(step):
                by_step[step].append(run)
                break

    aggregated: List[Dict[str, Any]] = []
    for step in step_order:
        runs = by_step[step]
        agg = aggregate_step_metrics(runs)
        if not agg:
            continue
        agg["step"] = step
        agg["label_text"] = _HUMAN_STEP_LABELS.get(step, step)
        aggregated.append(agg)

    lines: List[str] = []
    lines.append("# Combined evaluation -staircase ablation\n")
    lines.append(
        "Each row adds one capability to the prior row. Metrics are means "
        "across 3 reps unless noted otherwise. Delta column reports the "
        "change in F1 vs the previous row (positive = improvement).\n"
    )
    lines.append("## Summary table\n")
    lines.append("| Step | Reps | Precision | Recall | F1 | Accuracy | dF1 |")
    lines.append("|------|------|-----------|--------|----|----------|-----|")

    prev_f1: Optional[float] = None
    for agg in aggregated:
        delta = (
            f"{agg['f1_mean'] - prev_f1:+.3f}"
            if prev_f1 is not None else "-"
        )
        lines.append(
            f"| {agg['label_text']} | {agg['reps']} | "
            f"{agg['precision_mean']:.3f} | {agg['recall_mean']:.3f} | "
            f"{agg['f1_mean']:.3f} | {agg['accuracy_mean']:.3f} | {delta} |"
        )
        prev_f1 = agg["f1_mean"]

    lines.append("")
    lines.append("## Per-step detail\n")
    for agg in aggregated:
        lines.append(f"### {agg['label_text']}")
        lines.append(f"- reps: {agg['reps']}")
        lines.append(f"- precision (mean): {agg['precision_mean']:.3f}")
        lines.append(f"- recall (mean): {agg['recall_mean']:.3f}")
        lines.append(f"- F1 (mean): {agg['f1_mean']:.3f}")
        lines.append(f"- accuracy (mean): {agg['accuracy_mean']:.3f}")
        lines.append(
            f"- avg per run: total scenarios {agg['total_scenarios_avg']:.1f}, "
            f"matched incidents {agg['matched_to_incident_avg']:.1f}, "
            f"TP correct {agg['tp_correct_avg']:.1f}, "
            f"FP correct {agg['fp_correct_avg']:.1f}, "
            f"errors {agg['errors_avg']:.1f}"
        )
        lines.append("")

    if not aggregated:
        lines.append(
            "**No runs matched the steps in `--order`.** Either no runs are "
            "present in the input directory or none of them have a "
            "`config_dimensions.step` field. Re-run evaluations with "
            "`--config-dim '{\"step\":\"baseline\",...}'` etc.\n"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log.info("Combined report written to %s", out_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--indir", default="eval_results",
        help="Directory containing per-config <label>_<ts>_raw.json files",
    )
    p.add_argument(
        "--label-prefix", default=None,
        help="Filter inputs by label prefix (e.g. 'p6_'). Default: include all.",
    )
    p.add_argument(
        "--order",
        default="baseline,model_swap,react,enrich,custom_rules",
        help=(
            "Comma-separated step order -controls the row order of the "
            "ablation table. Must match the `step` field passed to each "
            "run via --config-dim."
        ),
    )
    p.add_argument(
        "--out", default="eval_results/combined_report.md",
        help="Markdown report output path",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    indir = Path(args.indir)
    if not indir.exists():
        log.error("--indir does not exist: %s", indir)
        return 2
    step_order = [s.strip() for s in args.order.split(",") if s.strip()]
    if not step_order:
        log.error("--order is empty")
        return 2

    log.info("Reading raw results from %s (prefix=%s)", indir, args.label_prefix)
    runs = load_raw_results(indir, args.label_prefix)
    log.info("Found %d run(s)", len(runs))

    if not runs:
        log.error(
            "No raw result files found. Did you run "
            "run_evaluation.py with --label first?"
        )
        return 3

    ordered = order_runs(runs, step_order)
    render_markdown(ordered, step_order, Path(args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
