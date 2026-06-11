# rule_engine.py - Deterministic derivations, JSON parse/validate, and fallback narrative.

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from log_monitor import AlertRecord
from models import (
    AlertClassification,
    Incident,
    extract_attack_type,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_CLASSIFICATIONS = {"true_positive", "likely_false_positive"}
# Severity scale matches the custom Suricata rule priority tiers
# (P1 = critical, P2 = high, P3 = low). No medium tier - neither the
# Suricata rules nor the dashboard render one.
_VALID_SEVERITIES = {"critical", "high", "low"}
_VALID_RECOMMENDATIONS = {"block_source_ip", "escalate_tier2", "continue_monitoring"}


def _parse_json_response(raw: str) -> dict:
    """Parse a JSON response from the LLM, stripping markdown fences if present."""
    if not isinstance(raw, str):
        raise ValueError(f"Expected string response, got {type(raw).__name__}")

    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("Empty response from LLM")

    # Strip markdown code fences
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    return json.loads(cleaned)


def _validate_stage1_response(data: dict) -> dict:
    """Validate and normalise a Stage 1 LLM response. Raises ValueError on failure."""
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict, got {type(data).__name__}")

    errors = []

    # Classification (case-insensitive)
    classification = str(data.get("classification", "")).strip().lower()
    if classification not in _VALID_CLASSIFICATIONS:
        errors.append(
            f"Invalid classification '{data.get('classification')}'. "
            f"Expected one of: {_VALID_CLASSIFICATIONS}"
        )
    data["classification"] = classification

    # Severity - fold common model dialects into the canonical lowercase
    # tier names. "medium" is a relic from a previous 4-tier scale; we
    # bucket it to "high" since that's where the Suricata P2 rules sit.
    severity_raw = str(data.get("severity", "")).strip().lower()
    severity_map = {
        "info":          "low",
        "informational": "low",
        "medium":        "high",
    }
    normalised = severity_map.get(severity_raw, severity_raw)
    if normalised not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{data.get('severity')}'. "
            f"Expected one of: {_VALID_SEVERITIES}"
        )
    data["severity"] = normalised

    # Recommendation
    recommendation = str(data.get("recommendation", "")).strip().lower()
    if recommendation not in _VALID_RECOMMENDATIONS:
        errors.append(
            f"Invalid recommendation '{data.get('recommendation')}'. "
            f"Expected one of: {_VALID_RECOMMENDATIONS}"
        )
    data["recommendation"] = recommendation

    # Summary and reasoning are required but we don't hard-enforce length
    summary = str(data.get("summary", "")).strip()
    reasoning = str(data.get("reasoning", "")).strip()
    if not summary:
        errors.append("Missing 'summary' field")
    if not reasoning:
        errors.append("Missing 'reasoning' field")
    data["summary"] = summary
    data["reasoning"] = reasoning

    if errors:
        raise ValueError("; ".join(errors))

    return data


# ---------------------------------------------------------------------------
# Rule-based derivations
# ---------------------------------------------------------------------------

# CVSS estimate per severity tier. Values picked to sit roughly inside the
# CVSS v3 base-score bands (critical 9.0+, high 7.0-8.9, low 0.1-3.9) so the
# dashboard shows a sensible number alongside the verdict.
_SEVERITY_TO_CVSS = {
    "critical": 9.0,
    "high":     7.5,
    "low":      3.0,
}

# Endpoint path patterns to data sensitivity ratings.
# Ordered: more specific patterns first.
_DATA_SENSITIVITY_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"/login|/auth|/signin|/oauth", re.I), "restricted"),
    (re.compile(r"/admin|/config|/settings", re.I), "restricted"),
    (re.compile(r"/user|/users|/account|/profile", re.I), "confidential"),
    (re.compile(r"/sqli|/xss|/brute|/csrf|/upload|/fi", re.I), "confidential"),
    (re.compile(r"/api/", re.I), "internal"),
    (re.compile(r"/vulnerabilities/", re.I), "confidential"),
]


def _severity_to_cvss(severity: str) -> float:
    """Deterministic mapping from severity label to CVSS estimate."""
    return _SEVERITY_TO_CVSS.get(severity, 0.0)


def _data_sensitivity_from_alerts(alerts: List[AlertRecord]) -> str:
    """Rule-based: derive highest applicable data sensitivity rating from alert URLs.

    Returns one of: public, internal, confidential, restricted, unknown.
    """
    # Priority: higher index in this list = more sensitive
    priority = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
    best = "unknown"

    for alert in alerts:
        http = (alert.raw_event or {}).get("http", {})
        if not isinstance(http, dict):
            continue
        url = str(http.get("url", ""))
        if not url:
            continue

        for pattern, rating in _DATA_SENSITIVITY_PATTERNS:
            if pattern.search(url):
                if best == "unknown" or priority.get(rating, 0) > priority.get(best, 0):
                    best = rating
                break  # first match wins for this alert

    return best


def _confidence_score(alert: AlertRecord, classification: Optional[AlertClassification]) -> float:
    """Rule-based confidence score in [0.0, 1.0].

    Higher when: clear HTTP payload, MITRE tag present, known attack signature,
                 classification succeeded without error.
    Lower when: generic signature, missing HTTP data, classification errored.
    """
    if classification is not None and classification.status == "error":
        return 0.2

    score = 0.5  # baseline

    raw = alert.raw_event or {}

    # HTTP context present -> clearer picture
    if isinstance(raw.get("http"), dict) and raw["http"].get("url"):
        score += 0.15

    # MITRE mapping -> high-confidence signature
    alert_meta = raw.get("alert", {}).get("metadata", {}) if isinstance(raw.get("alert"), dict) else {}
    if "mitre_technique_name" in alert_meta:
        score += 0.2

    # Known attack type (not "Other") -> classifier had a hit
    attack_type = extract_attack_type(alert.signature, alert.signature_id)
    if attack_type != "Other":
        score += 0.1

    # Suricata internal severity 1 or 2 -> strong rule match
    if alert.severity_level in (1, 2):
        score += 0.05

    return round(min(score, 1.0), 2)


def _extract_affected_data_fields(alert: AlertRecord) -> List[str]:
    """Rule-based: parse URL query string to list parameter names.

    For SQLi/XSS alerts, the affected fields are the query parameters the
    attacker injected into.
    """
    http = (alert.raw_event or {}).get("http", {})
    if not isinstance(http, dict):
        return []
    url = str(http.get("url", ""))
    if not url:
        return []

    try:
        # URLs from Suricata are relative; prepend a dummy host for parsing
        parsed = urlparse(url if "://" in url else f"http://x{url}")
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            return sorted(params.keys())
    except Exception as e:
        log.debug("URL parse failed for '%s': %s", url[:100], e)
    return []


def _build_iocs(alerts: List[AlertRecord]) -> List[Dict[str, str]]:
    """Rule-based: extract indicators of compromise from raw alerts.

    Types: ip (source IP), signature (Suricata rule), url (HTTP request target).
    Deduplicated.
    """
    iocs: List[Dict[str, str]] = []
    seen: set = set()

    def add(ioc_type: str, value: str) -> None:
        if not value:
            return
        key = (ioc_type, value)
        if key in seen:
            return
        seen.add(key)
        iocs.append({"type": ioc_type, "value": value})

    for alert in alerts:
        add("ip", alert.src_ip)
        add("signature", alert.signature)
        http = (alert.raw_event or {}).get("http", {})
        if isinstance(http, dict):
            url = str(http.get("url", ""))
            if url:
                # Truncate excessively long URLs in IoC list
                if len(url) > 300:
                    url = url[:300] + "...[truncated]"
                add("url", url)

    return iocs


def _classify_payload(alert: AlertRecord, attack_type: str) -> str:
    """Rule-based: classify the payload technique from signature + URL patterns.

    Returns human-readable technique label.
    """
    sig = alert.signature.upper()
    http = (alert.raw_event or {}).get("http", {})
    url = str(http.get("url", "")) if isinstance(http, dict) else ""
    url_lower = url.lower()

    if attack_type == "SQLi":
        if "UNION" in sig or "union+select" in url_lower or "union%20select" in url_lower:
            return "UNION-based SQL injection"
        if "BLIND" in sig:
            return "Blind SQL injection"
        if "ERROR" in sig:
            return "Error-based SQL injection"
        return "SQL injection attempt"

    if attack_type == "XSS":
        if "STORED" in sig:
            return "stored XSS"
        if "DOM" in sig:
            return "DOM-based XSS"
        if "<script" in url_lower or "%3cscript" in url_lower:
            return "reflected XSS"
        return "cross-site scripting attempt"

    if attack_type == "Reconnaissance":
        return "network or port reconnaissance"

    if attack_type == "CommandInjection":
        return "command injection attempt"

    if attack_type == "PathTraversal":
        return "directory/path traversal attempt"

    return f"{attack_type} attempt" if attack_type != "Other" else "unclassified"


# ---------------------------------------------------------------------------
# Template-based fallback narrative
# ---------------------------------------------------------------------------

def _template_stage2_output(
    incident: Incident,
    classifications: List[AlertClassification],
    tp_count: int,
    fp_count: int,
    error_count: int,
    detected_attacks: List[str],
) -> dict:
    """Deterministic fallback for Stage 2 when the LLM call fails or is disabled.

    Produces the same shape as the Stage 2 LLM response so downstream code
    doesn't need to branch.
    """
    # Block-worthy IPs: the IPs behind any confirmed critical-tier (P1
    # equivalent) true positive. high-tier alerts still get a suggestion
    # but aren't auto-blocked here.
    high_tp_ips = sorted({
        c.src_ip for c in classifications
        if c.classification == "true_positive" and c.severity == "critical"
    })

    # Overview
    overview_parts = [
        f"Incident involving source IP {incident.source_ip} with "
        f"{incident.alert_count} alert(s)."
    ]
    if tp_count > 0:
        overview_parts.append(
            f"{tp_count} classified as true positive(s), "
            f"{fp_count} as likely false positive(s)."
        )
    if detected_attacks:
        overview_parts.append(f"Detected attack types: {', '.join(detected_attacks)}.")
    overview = " ".join(overview_parts)

    # Attack vectors - inferred from alert data
    vectors: List[str] = []
    for alert in incident.alerts:
        http = (alert.raw_event or {}).get("http", {})
        if isinstance(http, dict) and http.get("url"):
            if "?" in str(http.get("url", "")):
                if "URL parameter" not in vectors:
                    vectors.append("URL parameter")
        if alert.proto == "TCP" and alert.dst_port not in ("80", "443"):
            if "network service" not in vectors:
                vectors.append("network service")
    if not vectors:
        vectors = ["unspecified"]

    # Attack stage - pick based on attack types
    stage = "Reconnaissance"
    if any(a in detected_attacks for a in ("SQLi", "XSS", "CommandInjection", "PathTraversal")):
        stage = "Initial Access"

    # Suggestions
    suggestions: List[str] = []
    if high_tp_ips:
        suggestions.append(
            f"Block source IP(s) {', '.join(high_tp_ips)} - "
            "confirmed high-severity attack traffic."
        )
    if tp_count > 0:
        suggestions.append("Review all true positive alerts and validate attack impact.")
    if fp_count > 0:
        suggestions.append(
            "Consider tuning IDS rules to suppress known false positive patterns."
        )
    if error_count > 0:
        suggestions.append("Investigate classification errors in the pipeline.")
    suggestions.append("Continue monitoring for follow-up activity from this source.")

    # Exposure: only flag exposure when at least one true positive sits at
    # the critical or high tier - low-tier TPs are detection signals but
    # don't on their own imply confirmed exposure.
    exposure_detected = tp_count > 0 and any(
        c.severity in ("critical", "high")
        for c in classifications if c.classification == "true_positive"
    )
    exposure_types = []
    if "SQLi" in detected_attacks:
        exposure_types.append("database contents")
    if "XSS" in detected_attacks:
        exposure_types.append("session tokens")
    affected_systems = []
    if any(alert.dst_port == "80" for alert in incident.alerts):
        affected_systems.append("web application")
    if any(alert.dst_port == "3306" for alert in incident.alerts):
        affected_systems.append("database server")

    exposure_summary = (
        f"{'Potential' if exposure_detected else 'No confirmed'} data exposure based on "
        f"{len([c for c in classifications if c.classification == 'true_positive'])} true-positive alert(s)."
    )
    impact_assessment = (
        f"If the attack(s) succeeded, impact ranges across the affected systems. "
        f"Detected severity level is {'high' if exposure_detected else 'low to moderate'}."
    )

    return {
        "overview": overview,
        "attack_vectors": vectors,
        "overall_attack_stage": stage,
        "ai_suggestions": suggestions,
        "exposure_detected": exposure_detected,
        "exposure_types": exposure_types,
        "affected_systems": affected_systems,
        "exposure_summary": exposure_summary,
        "impact_assessment": impact_assessment,
    }


# ---------------------------------------------------------------------------
# MITRE tactic override helpers
# ---------------------------------------------------------------------------

# Rule-based MITRE ATT&CK tactic override. qwen2.5:3b often labels SQLi /
# XSS incidents as "Reconnaissance" or "Execution" despite the explicit
# mapping table in the Stage 2 prompt. This deterministic post-process
# corrects the tactic when known attack types are present.

_ATTACK_TYPE_TO_MITRE = {
    "SQLi":             "Initial Access",
    "XSS":              "Initial Access",
    "CommandInjection": "Execution",
    "PathTraversal":    "Discovery",
    "FileInclusion":    "Initial Access",
    "BruteForce":       "Credential Access",
    "CSRF":             "Initial Access",
    "WebAttack":        "Initial Access",
    "Reconnaissance":   "Reconnaissance",
}

# Higher = "more severe / later-stage". Used to pick a single tactic when
# multiple attack types are present in an incident.
_MITRE_PRIORITY = {
    "Credential Access":  5,
    "Execution":          4,
    "Initial Access":     3,
    "Discovery":          2,
    "Persistence":        3,
    "Reconnaissance":     1,
}


_CREDENTIAL_KEYWORDS = (
    "USER", "PASS", "PASSWD", "CRED", "TOKEN", "LOGIN", "AUTH", "SECRET",
)


def _alert_mentions_credentials(alert: AlertRecord) -> bool:
    """True if the alert's signature msg OR the HTTP URL names a credential token.

    Our custom SQLi rule msgs are generic ("P1 - SQLi UNION SELECT in URI")
    so credential intent only shows up in the URL payload (e.g.
    ``?id=1' UNION SELECT user,password FROM users#``). Scanning both
    keeps coverage for ET Open rules whose msg already names USER/PASS.
    """
    sig_upper = (alert.signature or "").upper()
    if any(k in sig_upper for k in _CREDENTIAL_KEYWORDS):
        return True
    raw = alert.raw_event or {}
    if not isinstance(raw, dict):
        return False
    http = raw.get("http") or {}
    if isinstance(http, dict):
        url_upper = str(http.get("url", "") or "").upper()
        if any(k in url_upper for k in _CREDENTIAL_KEYWORDS):
            return True
    return False


def _override_mitre_tactic(
    detected_attacks: List[str],
    current_tactic: str,
    incident_alerts: Optional[List[AlertRecord]] = None,
) -> Tuple[str, bool]:
    """Override the LLM's MITRE tactic when alerts contain known attack types.

    Logic:
      1. Map each detected attack type to its canonical MITRE tactic.
      2. If SQLi present AND any alert signature OR URL names credentials,
         bump to "Credential Access" (subsumes Initial Access).
      3. If current_tactic is already in the candidate set, preserve it
         (LLM picked something valid; no override needed).
      4. Otherwise pick the highest-priority tactic and override.

    Returns (final_tactic, was_overridden).
    """
    if not detected_attacks:
        return current_tactic, False

    candidates: set = set()
    for atk in detected_attacks:
        mapped = _ATTACK_TYPE_TO_MITRE.get(atk)
        if mapped:
            candidates.add(mapped)

    if not candidates:
        return current_tactic, False

    # SQLi payload (signature or URL) names credentials -> Credential Access
    if "SQLi" in detected_attacks and incident_alerts:
        if any(_alert_mentions_credentials(a) for a in incident_alerts):
            candidates.add("Credential Access")
            candidates.discard("Initial Access")

    # Preserve LLM's tactic when it is already in the candidate set
    if current_tactic in candidates:
        return current_tactic, False

    chosen = max(candidates, key=lambda t: _MITRE_PRIORITY.get(t, 0))
    return chosen, chosen != current_tactic


# Ordering for max() reduction. Matches the Suricata rule priority tiers.
_SEVERITY_ORDER = {"critical": 3, "high": 2, "low": 1}


def _compute_overall_severity(classifications: List[AlertClassification]) -> str:
    """Return the highest severity across all successful classifications.

    Defaults to 'low' if no successful classifications exist.
    """
    highest = 0
    label = "low"
    for c in classifications:
        if c.status != "complete":
            continue
        rank = _SEVERITY_ORDER.get(c.severity, 0)
        if rank > highest:
            highest = rank
            label = c.severity
    return label


def _summarise_enrichment(classifications: List[AlertClassification]) -> str:
    """Build a compact, human-readable summary of the auto-enrichment results.

    Pulls observations from the first classification's reasoning_trace whose
    `source == "system"`. We use the first classification because all alerts
    in an incident share the same source IP (and so the cached enrichment
    results are identical) - pulling once is sufficient and keeps the
    Stage 2 prompt small.

    Returns "(no enrichment data)" when the report was produced in
    single-shot mode or auto-enrichment was disabled.
    """
    if not classifications:
        return "(no enrichment data - no classifications produced)"

    # Find the first classification with a non-empty reasoning_trace
    trace: List = []
    for c in classifications:
        if c.reasoning_trace:
            trace = c.reasoning_trace
            break
    if not trace:
        return "(no enrichment data - single-shot or auto-enrichment disabled)"

    lines: List[str] = []
    for step in trace:
        if getattr(step, "source", "model") != "system":
            continue
        if not step.action:
            continue
        # Decode the observation JSON if possible so the model can read key
        # facts instead of a serialised blob.
        obs_text = step.observation or ""
        decoded_obs: Any = obs_text
        try:
            decoded_obs = json.loads(obs_text)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        if step.action == "get_alert_history" and isinstance(decoded_obs, dict):
            lines.append(
                f"- prior activity: {decoded_obs.get('total_prior_alerts', 0)} "
                f"alert(s) in last {decoded_obs.get('lookback_hours', 24)}h, "
                f"attack types {decoded_obs.get('attack_types_seen', [])}, "
                f"repeat offender this session = "
                f"{decoded_obs.get('is_repeat_offender_this_session', False)}"
            )
        elif step.action == "lookup_environment_context" and isinstance(decoded_obs, dict):
            if decoded_obs.get("match_found"):
                lines.append(
                    f"- environment lookup: source IP matched "
                    f"'{decoded_obs.get('matched_pattern')}' "
                    f"(role={decoded_obs.get('role')}, "
                    f"hint={decoded_obs.get('classification_hint')})"
                )
            else:
                lines.append(
                    "- environment lookup: source IP not in known map "
                    "(treat as unknown)"
                )
        elif step.action == "get_attack_pattern_stats" and isinstance(decoded_obs, dict):
            tpr = decoded_obs.get("observed_true_positive_rate")
            tpr_txt = f"observed TPR {tpr:.2f}" if isinstance(tpr, (int, float)) else "no historical TPR"
            lines.append(
                f"- attack pattern stats: {decoded_obs.get('total_alerts', 0)} "
                f"alert(s) of type {decoded_obs.get('attack_type')} from "
                f"{decoded_obs.get('unique_source_ips', 0)} unique IP(s) in "
                f"last {decoded_obs.get('lookback_hours', 24)}h; {tpr_txt}"
            )
        else:
            # Generic fallback so unknown future enrichment tools still appear
            lines.append(f"- {step.action}: {obs_text[:160]}")

    if not lines:
        return "(no enrichment data - no system steps in trace)"
    return "\n".join(lines)


def _ensure_list_of_strings(value) -> List[str]:
    """Coerce LLM-returned list fields into a clean list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        # LLM sometimes returns a comma-separated string instead of a list
        return [v.strip() for v in value.split(",") if v.strip()]
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _default_intent(attack_type: str) -> str:
    """Fallback 'likely_intent' when LLM classification was unavailable."""
    intents = {
        "SQLi": "database access or data extraction",
        "XSS": "session hijacking or client-side code execution",
        "CommandInjection": "remote code execution",
        "PathTraversal": "unauthorised file access",
        "CSRF": "forged user actions",
        "FileInclusion": "remote code execution or file disclosure",
        "BruteForce": "credential theft",
        "Reconnaissance": "target enumeration",
        "WebAttack": "web application compromise",
    }
    return intents.get(attack_type, "unknown")
