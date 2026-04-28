"""
report_writer.py - Formats evaluation results as a Markdown report.

The output is designed to be directly usable in the capstone report:
- A headline summary block with precision/recall/F1/accuracy
- A confusion matrix
- Per-category breakdown
- A table of every scenario and its outcome

Kept entirely self-contained (no extra dependencies).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List, Optional

from .result_collector import RunMetrics, ScenarioResult


def write_markdown_report(
    path: Path,
    label: str,
    scenario_results: List[ScenarioResult],
    metrics: RunMetrics,
    matrix: Dict[str, Dict[str, int]],
    args,
) -> None:
    """Write the full evaluation report to `path`."""
    md = _render(label, scenario_results, metrics, matrix, args)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)


def _render(label, scenario_results, metrics, matrix, args) -> str:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    lines: List[str] = []

    # -------- Header --------
    lines.append(f"# Evaluation Report — `{label}`")
    lines.append("")
    lines.append(f"*Generated {timestamp}*")
    lines.append("")
    lines.append(f"- DVWA target     : `{args.base_url}`")
    lines.append(f"- Dashboard       : `{args.dashboard}`")
    lines.append(f"- Repetitions     : {args.repeats}")
    lines.append(f"- Settle-time     : {args.settle_time}s between scenarios")
    lines.append("")

    # -------- Headline summary --------
    lines.append("## Headline metrics")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Total scenarios        | {metrics.total_scenarios} |")
    lines.append(f"| Fired successfully     | {metrics.fired_successfully} |")
    lines.append(f"| Matched to incident    | {metrics.matched_to_incident} |")
    lines.append(f"| No detection           | {metrics.no_detection} |")
    lines.append(f"| Classification errors  | {metrics.classification_errors} |")
    lines.append(f"| **Precision** (TP class) | **{metrics.precision:.3f}** |")
    lines.append(f"| **Recall** (TP class)    | **{metrics.recall:.3f}** |")
    lines.append(f"| **F1** (TP class)        | **{metrics.f1:.3f}** |")
    lines.append(f"| Accuracy               | {metrics.accuracy:.3f} |")
    lines.append("")

    # -------- Definitions --------
    lines.append("### Definitions")
    lines.append("")
    lines.append("- **Matched to incident**: scenario's HTTP request was correlated with a generated incident report via the `eval_id` marker.")
    lines.append("- **No detection**: scenario fired but Suricata did not produce an alert. Many benign scenarios are expected to fall here, as they should; mild attacks (very short payloads, obscure encodings) may also fall here due to Suricata rule coverage limits.")
    lines.append("- **Classification errors**: alert was generated but the AI pipeline failed to produce a valid Stage 1 verdict.")
    lines.append("- **Precision / Recall / F1**: computed against the positive class `true_positive`. A high precision means few false alarms; a high recall means few missed attacks.")
    lines.append("- **Accuracy**: fraction of all matched classifications that matched ground truth.")
    lines.append("")

    # -------- Confusion matrix --------
    lines.append("## Confusion matrix")
    lines.append("")
    lines.append("Rows are ground-truth labels; columns are AI predictions. Only successfully-matched scenarios appear here.")
    lines.append("")
    lines.append("| expected \\ predicted | `true_positive` | `likely_false_positive` |")
    lines.append("|---|---|---|")
    tp_row = matrix.get("true_positive", {})
    fp_row = matrix.get("likely_false_positive", {})
    lines.append(
        f"| **`true_positive`** (attacks)    | "
        f"{tp_row.get('true_positive', 0)} ✓ | "
        f"{tp_row.get('likely_false_positive', 0)} ✗ |"
    )
    lines.append(
        f"| **`likely_false_positive`** (benign) | "
        f"{fp_row.get('true_positive', 0)} ✗ | "
        f"{fp_row.get('likely_false_positive', 0)} ✓ |"
    )
    lines.append("")

    # -------- Per-category breakdown --------
    lines.append("## Per-category breakdown")
    lines.append("")
    lines.append("| Category | Total | Matched | Classified correctly | Missed | False alarms | Accuracy |")
    lines.append("|---|---|---|---|---|---|---|")
    for category, stats in _per_category_stats(scenario_results).items():
        acc = (stats["correct"] / stats["matched"]) if stats["matched"] else 0.0
        lines.append(
            f"| {category} | {stats['total']} | {stats['matched']} | "
            f"{stats['correct']} | {stats['missed']} | {stats['false_alarm']} | "
            f"{acc:.2f} |"
        )
    lines.append("")

    # -------- Severity accuracy (TPs only) --------
    tp_correctly_classified = metrics.tp_correct
    if tp_correctly_classified > 0:
        lines.append("## Severity & attack-type accuracy (successfully-matched TPs only)")
        lines.append("")
        lines.append(f"- Exact severity match     : {metrics.severity_exact} / {tp_correctly_classified}")
        lines.append(f"- Severity within one step : {metrics.severity_within_one} / {tp_correctly_classified}")
        lines.append(f"- Attack type exact match  : {metrics.attack_type_exact} / {tp_correctly_classified}")
        lines.append("")

    # -------- Detailed scenario table --------
    lines.append("## Detailed results")
    lines.append("")
    lines.append("| # | eval_id | Category | Expected | Predicted | Severity | Attack type | Status |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for i, sr in enumerate(scenario_results, 1):
        c = sr.classification or {}
        predicted = c.get("classification") or "—"
        severity = c.get("severity") or "—"
        attack_type = c.get("attack_type") or "—"
        status_icon = _status_icon(sr)
        lines.append(
            f"| {i} | `{sr.scenario.eval_id}` | {sr.scenario.category} | "
            f"{sr.scenario.expected_classification} | {predicted} | "
            f"{severity} | {attack_type} | {status_icon} {sr.status} |"
        )
    lines.append("")

    # -------- Notable misclassifications --------
    mistakes = _interesting_mistakes(scenario_results)
    if mistakes:
        lines.append("## Notable misclassifications")
        lines.append("")
        for sr in mistakes:
            lines.append(f"- **`{sr.scenario.eval_id}`** ({sr.scenario.category}): "
                         f"expected `{sr.scenario.expected_classification}`, "
                         f"got `{(sr.classification or {}).get('classification', '—')}`")
            lines.append(f"  - Description: {sr.scenario.description}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _status_icon(sr: ScenarioResult) -> str:
    if sr.status == "matched":
        return "✓" if sr.correct_classification else "✗"
    if sr.status == "no_detection":
        # Expected benign with no detection is the CORRECT outcome
        if sr.scenario.expected_classification == "likely_false_positive":
            return "✓"
        if not sr.scenario.expected_to_trigger_suricata:
            return "○"  # acknowledged limitation
        return "?"
    if sr.status == "classification_error":
        return "!"
    if sr.status == "fire_failed":
        return "✗"
    return "?"


def _per_category_stats(results: List[ScenarioResult]) -> Dict[str, Dict[str, int]]:
    stats: Dict[str, Dict[str, int]] = {}
    for sr in results:
        cat = sr.scenario.category
        if cat not in stats:
            stats[cat] = {
                "total": 0, "matched": 0, "correct": 0,
                "missed": 0, "false_alarm": 0,
            }
        s = stats[cat]
        s["total"] += 1
        if sr.status != "matched":
            continue
        s["matched"] += 1
        actual = (sr.classification or {}).get("classification")
        expected = sr.scenario.expected_classification
        if actual == expected:
            s["correct"] += 1
        elif expected == "true_positive":
            s["missed"] += 1
        else:
            s["false_alarm"] += 1
    return stats


def _interesting_mistakes(results: List[ScenarioResult]) -> List[ScenarioResult]:
    """Pick out scenarios worth calling out in the report."""
    mistakes = []
    for sr in results:
        if sr.status != "matched":
            continue
        if not sr.correct_classification:
            mistakes.append(sr)
    return mistakes[:10]  # cap at 10 to keep reports readable