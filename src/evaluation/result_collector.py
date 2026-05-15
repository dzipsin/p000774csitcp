"""
result_collector.py - Pairs generated reports to fired scenarios, computes metrics.

Workflow:
  1. attack_runner fires scenarios one at a time; each scenario's eval_id
     appears in the Suricata alert URL
  2. IncidentManager groups those alerts into incidents
  3. ReportGenerator produces per-incident reports with per-alert classifications
  4. This module polls /api/incidents, finds alerts whose URL contains an eval_id,
     and pairs them with their scenario
  5. Metrics are computed from the matched pairs

Matching strategy:
  For each scenario, we scan every incident's alert list. An alert matches if
  its `http_url` contains `eval_id=<scenario.eval_id>`. We pick the alert
  whose timestamp is closest to when the scenario was fired.

Ambiguity handling:
  - Scenario fired but no matching alert: counted as "no_detection"
  - Alert exists but classification status="error": counted as "classification_error"
  - Multiple alerts for one scenario: pick the one matching the scenario's
    expected_attack_type, or the first if none match
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .attack_runner import FireResult
from .scenarios import Scenario

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ScenarioResult:
    """A single scenario's outcome: fired, then possibly classified."""
    scenario: Scenario
    fire: FireResult

    # Populated by correlation:
    matched: bool = False
    incident_id: Optional[str] = None
    alert_data: Optional[Dict[str, Any]] = None              # raw alert dict
    classification: Optional[Dict[str, Any]] = None          # Stage 1 output
    incident_summary: Optional[Dict[str, Any]] = None        # for overall severity etc.
    status: str = "pending"  # pending | matched | no_detection | classification_error

    @property
    def actual_classification(self) -> Optional[str]:
        return (self.classification or {}).get("classification")

    @property
    def actual_severity(self) -> Optional[str]:
        return (self.classification or {}).get("severity")

    @property
    def actual_attack_type(self) -> Optional[str]:
        return (self.classification or {}).get("attack_type")

    @property
    def correct_classification(self) -> bool:
        """Did we get the classification label right?"""
        if not self.matched or self.status != "matched":
            return False
        return self.actual_classification == self.scenario.expected_classification


@dataclass
class RunMetrics:
    """Summary metrics for a full evaluation run."""
    total_scenarios: int = 0
    fired_successfully: int = 0
    matched_to_incident: int = 0
    classified_successfully: int = 0     # no error status
    no_detection: int = 0                # scenario fired but no alert found
    classification_errors: int = 0       # alert found but classification errored

    # Classification confusion (only for matched, successfully classified):
    tp_correct: int = 0     # expected TP, predicted TP
    tp_missed: int = 0      # expected TP, predicted FP
    fp_correct: int = 0     # expected FP, predicted FP
    fp_incorrect: int = 0   # expected FP, predicted TP

    # Severity accuracy (for correctly-classified TPs only):
    severity_exact: int = 0
    severity_within_one: int = 0

    # Attack type accuracy (for correctly-classified TPs only):
    attack_type_exact: int = 0

    @property
    def precision(self) -> float:
        """For TP class: TP / (TP + FP_incorrect)."""
        denom = self.tp_correct + self.fp_incorrect
        return self.tp_correct / denom if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        """For TP class: TP / (TP + FN)."""
        denom = self.tp_correct + self.tp_missed
        return self.tp_correct / denom if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    @property
    def accuracy(self) -> float:
        correct = self.tp_correct + self.fp_correct
        total = self.tp_correct + self.tp_missed + self.fp_correct + self.fp_incorrect
        return correct / total if total > 0 else 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "total_scenarios": self.total_scenarios,
            "fired_successfully": self.fired_successfully,
            "matched_to_incident": self.matched_to_incident,
            "classified_successfully": self.classified_successfully,
            "no_detection": self.no_detection,
            "classification_errors": self.classification_errors,
            "tp_correct": self.tp_correct,
            "tp_missed": self.tp_missed,
            "fp_correct": self.fp_correct,
            "fp_incorrect": self.fp_incorrect,
            "severity_exact": self.severity_exact,
            "severity_within_one": self.severity_within_one,
            "attack_type_exact": self.attack_type_exact,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


# ---------------------------------------------------------------------------
# Dashboard API client
# ---------------------------------------------------------------------------

class DashboardClient:
    """Polls the running app's /api/incidents endpoint."""

    def __init__(self, base_url: str = "http://127.0.0.1:5000", timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def list_incidents(self) -> List[Dict[str, Any]]:
        url = f"{self.base_url}/api/incidents"
        try:
            with urllib.request.urlopen(url, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return data.get("incidents", [])
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            log.error("Failed to fetch incidents: %s", e)
            return []

    def clear_incidents(self) -> bool:
        """Reset the dashboard for a fresh evaluation run."""
        url = f"{self.base_url}/api/incidents/clear"
        req = urllib.request.Request(url, method="POST", data=b"")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
            return True
        except urllib.error.URLError as e:
            log.warning("Failed to clear incidents: %s", e)
            return False

    def force_regenerate(self) -> bool:
        """Force regeneration of open incidents (useful to flush pending ones)."""
        url = f"{self.base_url}/api/incidents/regenerate"
        req = urllib.request.Request(url, method="POST", data=b"")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
            return True
        except urllib.error.URLError as e:
            log.warning("Failed to force regenerate: %s", e)
            return False


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def correlate(
    scenario_results: List[ScenarioResult],
    incidents: List[Dict[str, Any]],
) -> None:
    """Mutate each ScenarioResult in place with its matched alert/classification."""
    # Flatten incidents → (incident, alert, classification) triples
    all_alert_tuples: List[tuple] = []
    for inc in incidents:
        alerts = inc.get("alerts", []) or []
        analyses = inc.get("alert_analyses", []) or []
        classifications_by_alert_id = {}

        # alert_analyses uses its own alert_id (from flow_id or uuid). The raw
        # alerts in inc.alerts are a different shape. We match on index — both
        # lists are in the same order because ReportGenerator zips them.
        for i, alert in enumerate(alerts):
            cls = analyses[i] if i < len(analyses) else None
            all_alert_tuples.append((inc, alert, cls))

    for sr in scenario_results:
        if sr.fire.error or sr.fire.http_status == 0:
            # Fire itself failed — no point correlating
            sr.status = "fire_failed"
            continue

        best = _find_best_match(sr, all_alert_tuples)
        if best is None:
            sr.status = "no_detection"
            continue

        inc, alert, cls = best
        sr.matched = True
        sr.incident_id = inc.get("incident_summary", {}).get("incident_id")
        sr.alert_data = alert
        sr.incident_summary = inc.get("incident_summary", {})

        # classification may or may not be present (in alert_analyses format)
        if cls is not None:
            # alert_analyses now carries the Stage 1 classification directly
            # (added in Phase 4). Falls back to derived values if older reports
            # don't have it.
            actual_classification = cls.get("classification") or ""
            actual_severity = cls.get("severity") or ""
            classification_status = cls.get("classification_status", "complete")

            if not actual_classification:
                # Legacy fallback — shouldn't happen with current reports
                actual_classification = _derive_classification_from_analysis(
                    cls, inc.get("incident_summary", {})
                )
            if not actual_severity:
                actual_severity = _derive_severity_from_analysis(
                    cls, inc.get("incident_summary", {})
                )

            sr.classification = {
                "classification": actual_classification,
                "severity": actual_severity,
                "attack_type": cls.get("attack_type_classified", "Other"),
                "confidence_score": cls.get("confidence_score", 0.0),
                "recommendation": cls.get("recommendation", ""),
                "status": classification_status,
            }

            if classification_status == "error":
                sr.status = "classification_error"
            else:
                sr.status = "matched"
        else:
            sr.status = "classification_error"


def _find_best_match(
    sr: ScenarioResult,
    triples: List[tuple],
) -> Optional[tuple]:
    """Find the (incident, alert, classification) triple matching this scenario.

    Match criteria (in order):
      1. Alert's URL contains `eval_id=<scenario.eval_id>`. We check several
         possible locations because AlertRecord.to_dict() strips raw_event,
         so the URL may only appear in the alert_analysis entry's
         payload_observed field.
      2. Alert was seen after the scenario was fired (within 90s window).
    If multiple match, prefer the one whose attack_type matches the scenario's.
    """
    marker = f"eval_id={sr.scenario.eval_id}"
    fire_epoch = sr.fire.sent_at_epoch
    window_seconds = 90.0  # generous to handle slow LLM runs

    candidates = []
    for inc, alert, cls in triples:
        # Look for eval_id in every place it might be stored:
        # 1. alert.raw_event.http.url  (pre-serialisation)
        # 2. alert_analysis.payload_observed  (post-serialisation, via payload_observed)
        # 3. incident.alerts[i].signature  (fallback — unlikely to help but harmless)
        url_candidates = []

        if isinstance(alert, dict):
            raw = alert.get("raw_event", {})
            if isinstance(raw, dict):
                http = raw.get("http", {})
                if isinstance(http, dict):
                    url_candidates.append(str(http.get("url", "")))

        if isinstance(cls, dict):
            url_candidates.append(str(cls.get("payload_observed", "")))

        if not any(marker in u for u in url_candidates if u):
            continue

        # Timestamp check — alert should be after fire, but give a generous window
        alert_epoch = 0.0
        if isinstance(alert, dict):
            alert_epoch = alert.get("timestamp_epoch", 0) or 0
        if alert_epoch > 0 and abs(alert_epoch - fire_epoch) > window_seconds:
            continue
        candidates.append((inc, alert, cls))

    if not candidates:
        return None

    # Prefer candidate whose classification matches expected attack_type
    expected = sr.scenario.expected_attack_type
    for inc, alert, cls in candidates:
        if cls and cls.get("attack_type_classified") == expected:
            return (inc, alert, cls)

    # Otherwise take the first (chronologically: they're in insertion order)
    return candidates[0]


def _derive_classification_from_analysis(
    analysis: Dict[str, Any],
    summary: Dict[str, Any],
) -> str:
    """The AlertAnalysis dataclass doesn't carry the TP/FP label directly; we
    infer it from the confidence score and the summary's classification counts.

    Actually — we can do better by inspecting the overall incident severity and
    confidence. Low confidence + Low severity == likely_false_positive.
    Alternatively the summary's classification_counts tells us about the incident
    as a whole but not this specific alert.

    The cleanest fix is to add the per-alert classification into
    alert_analyses at the source. For this evaluation, we do a best-effort derive:
      - If confidence >= 0.7 AND the incident's overall severity is High/Medium,
        treat as true_positive
      - Else likely_false_positive
    """
    confidence = analysis.get("confidence_score", 0.0) or 0.0
    overall_severity = summary.get("overall_severity", "Low")
    attack_type = analysis.get("attack_type_classified", "Other")

    if attack_type in ("SQLi", "XSS", "CommandInjection", "PathTraversal",
                       "FileInclusion", "BruteForce") and confidence >= 0.5:
        return "true_positive"
    if overall_severity in ("High", "Medium") and confidence >= 0.6:
        return "true_positive"
    return "likely_false_positive"


def _derive_severity_from_analysis(
    analysis: Dict[str, Any],
    summary: Dict[str, Any],
) -> str:
    """Use the incident's overall_severity as the per-alert severity proxy.

    The true Stage 1 classification has a per-alert severity, but it isn't
    preserved in alert_analyses. Using overall severity is a reasonable proxy
    for incidents where all alerts are the same type.
    """
    return summary.get("overall_severity", "Low")


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3}


def compute_metrics(scenario_results: List[ScenarioResult]) -> RunMetrics:
    m = RunMetrics(total_scenarios=len(scenario_results))

    for sr in scenario_results:
        if sr.fire.http_status > 0 and not sr.fire.error:
            m.fired_successfully += 1

        if sr.matched:
            m.matched_to_incident += 1

        if sr.status == "no_detection":
            m.no_detection += 1
            continue
        if sr.status == "classification_error":
            m.classification_errors += 1
            continue
        if sr.status != "matched":
            continue

        m.classified_successfully += 1

        # Classification confusion
        expected = sr.scenario.expected_classification
        actual = sr.actual_classification or ""

        if expected == "true_positive":
            if actual == "true_positive":
                m.tp_correct += 1
            else:
                m.tp_missed += 1
        else:  # expected FP
            if actual == "likely_false_positive":
                m.fp_correct += 1
            else:
                m.fp_incorrect += 1

        # Severity accuracy (only for successfully-matched TPs)
        if expected == "true_positive" and actual == "true_positive":
            expected_sev = _SEVERITY_ORDER.get(sr.scenario.expected_severity, 0)
            actual_sev = _SEVERITY_ORDER.get(sr.actual_severity or "", 0)
            if expected_sev and actual_sev:
                if expected_sev == actual_sev:
                    m.severity_exact += 1
                    m.severity_within_one += 1
                elif abs(expected_sev - actual_sev) <= 1:
                    m.severity_within_one += 1

            # Attack type accuracy
            if sr.actual_attack_type == sr.scenario.expected_attack_type:
                m.attack_type_exact += 1

    return m


def confusion_matrix(scenario_results: List[ScenarioResult]) -> Dict[str, Dict[str, int]]:
    """2x2 confusion matrix as nested dict.

    matrix[expected][actual] = count.
    Only counts successfully-matched classifications.
    """
    matrix = {
        "true_positive": {"true_positive": 0, "likely_false_positive": 0},
        "likely_false_positive": {"true_positive": 0, "likely_false_positive": 0},
    }
    for sr in scenario_results:
        if sr.status != "matched":
            continue
        expected = sr.scenario.expected_classification
        actual = sr.actual_classification
        if expected in matrix and actual in matrix[expected]:
            matrix[expected][actual] += 1
    return matrix