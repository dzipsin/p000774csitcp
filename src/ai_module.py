"""
ai_module.py - AI-powered alert classification and report generation

Responsibilities:
  - Classify individual Suricata alerts as true_positive / likely_false_positive
  - Assign severity levels (Low / Medium / High) per alert
  - Generate per-alert response recommendations
  - Aggregate classifications into a structured AlertReport
  - Generate an executive summary (LLM-based or template-based)

Depends on:
  log_monitor.AlertRecord      - input data contract
  model_provider.ModelProvider  - LLM backend abstraction (local or remote)
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from log_monitor import AlertRecord
from model_provider import ModelProvider

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-alert classification (Step 1 output)
# ---------------------------------------------------------------------------

@dataclass
class AlertClassification:
    """AI-generated verdict for a single Suricata alert."""

    alert_id: str                   # flow_id as string, or generated UUID
    timestamp: str                  # original alert timestamp
    classification: str             # "true_positive" | "likely_false_positive"
    severity: str                   # "Low" | "Medium" | "High"
    summary: str                    # one-line description of what happened
    recommendation: str             # "block_source_ip" | "escalate_tier2" | "continue_monitoring"
    reasoning: str                  # LLM's explanation for the classification

    # Pass-through fields for traceability
    signature: str
    signature_id: int
    category: str
    src_ip: str
    dst_ip: str
    src_port: str
    dst_port: str

    # Metadata
    status: str = "complete"        # "complete" | "error"
    error: Optional[str] = None     # populated when status == "error"


# ---------------------------------------------------------------------------
# Batch report (Step 2 output — aggregated)
# ---------------------------------------------------------------------------

@dataclass
class ThreatActor:
    """Aggregated view of a single source IP across an alert batch."""
    ip: str
    alert_count: int
    signatures: List[str]
    severity_labels: List[str]
    targeted_ports: List[str]


@dataclass
class SignatureHit:
    """Aggregated view of a single Suricata signature across an alert batch."""
    signature: str
    signature_id: int
    category: str
    hit_count: int
    severity_label: str
    source_ips: List[str]


@dataclass
class AlertReport:
    """Structured output produced by AIAnalyzer.analyse().

    Contains both per-alert classifications and aggregated intelligence.
    """

    # Identity
    report_id: str
    generated_at: str

    # Time window
    period_start_epoch: float
    period_end_epoch: float
    period_start_display: str
    period_end_display: str

    # Input summary
    alert_count: int
    severity_breakdown: Dict[str, int]

    # Per-alert classifications
    classifications: List[AlertClassification]
    true_positive_count: int
    false_positive_count: int
    error_count: int

    # Aggregated intelligence
    top_threat_actors: List[ThreatActor]
    top_signatures: List[SignatureHit]
    unique_source_ips: List[str]
    unique_categories: List[str]

    # AI narrative
    threat_summary: str
    recommendations: List[str]

    # Model metadata
    model_used: Optional[str]
    provider_type: Optional[str]
    raw_ai_response: Optional[str]

    # Status
    status: str
    error: Optional[str]


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_BASE = """You are an expert Tier-1 SOC (Security Operations Centre) analyst.
Your task is to classify a single IDS (Intrusion Detection System) alert and provide a structured assessment.

CLASSIFICATION RULES:
- "true_positive": The alert represents a genuine security threat or attack attempt.
  Examples: SQL injection payloads in HTTP requests, XSS script tags in URLs, known exploit signatures targeting application vulnerabilities.
- "likely_false_positive": The alert is benign or expected infrastructure behaviour that is not an actual attack.
  Examples: routine internal service communication, normal database connections, scanner noise from monitoring tools.

SEVERITY SCALE:
- "High": Active confirmed attack with potential for data exfiltration, system compromise, or service disruption. Requires immediate attention.
  Examples: successful SQL injection extracting data, command injection, authenticated exploit attempts.
- "Medium": Suspicious activity that may indicate reconnaissance or an attack attempt, but impact is uncertain.
  Examples: basic SQLi probes, simple XSS tests, unusual traffic patterns that could be automated scanning.
- "Low": Informational alerts with minimal risk. Likely benign or very low confidence attack indicators.
  Examples: failed attack attempts, generic traffic anomalies, informational signatures.

RECOMMENDATIONS:
- "block_source_ip": The source IP is clearly malicious and should be blocked at the firewall.
  Use for: confirmed high-severity attacks, repeated exploit attempts from the same IP.
- "escalate_tier2": The alert needs deeper investigation by a senior analyst before action is taken.
  Use for: medium-severity alerts, ambiguous situations, potential advanced threats.
- "continue_monitoring": No immediate action needed. Log and monitor for patterns.
  Use for: low-severity alerts, likely false positives, informational events.

You MUST respond with ONLY a JSON object in this exact schema. No other text, no markdown, no explanation outside the JSON:
{
  "classification": "true_positive" or "likely_false_positive",
  "severity": "Low" or "Medium" or "High",
  "summary": "One sentence describing what this alert represents",
  "recommendation": "block_source_ip" or "escalate_tier2" or "continue_monitoring",
  "reasoning": "2-3 sentences explaining your classification logic"
}"""

_LAB_CONTEXT = """

LAB ENVIRONMENT CONTEXT:
This is a controlled lab environment with the following known infrastructure:
- A Docker network (172.18.0.0/16) hosts a vulnerable web application (DVWA) and a MariaDB database.
- 172.18.0.2 is the MariaDB database server (port 3306). Traffic between 172.18.0.3 and 172.18.0.2 on port 3306 is EXPECTED internal database communication and should be classified as likely_false_positive.
- 172.18.0.3 is the DVWA web application container (port 80).
- External IPs (e.g. 192.168.56.x) accessing port 80 on 172.18.0.3 represent user/attacker traffic to the web application.
- Alerts about "Suspicious inbound to mySQL port 3306" between Docker-internal IPs are normal infrastructure noise, NOT attacks."""

_SUMMARY_PROMPT_TEMPLATE = """You are a senior SOC analyst writing an executive summary of a batch of security alerts.

Based on the following analysis results, write:
1. A concise executive summary paragraph (3-5 sentences) describing the overall threat landscape observed.
2. A list of 3-5 actionable recommendations for the SOC team.

ANALYSIS RESULTS:
- Total alerts analysed: {alert_count}
- True positives: {tp_count}
- Likely false positives: {fp_count}
- Errors: {error_count}
- Severity breakdown: {severity_breakdown}
- Top threat actors (by alert count): {threat_actors}
- Top triggered signatures: {signatures}
- Unique categories: {categories}
- Time window: {period_start} to {period_end}

Respond with ONLY a JSON object:
{{
  "executive_summary": "Your 3-5 sentence summary here",
  "recommendations": ["recommendation 1", "recommendation 2", "recommendation 3"]
}}"""


def _build_system_prompt(include_lab_context: bool = True) -> str:
    """Build the system prompt, optionally including lab environment context.

    Args:
        include_lab_context: If True, includes Docker infrastructure details
            that help the LLM distinguish false positives from real attacks.
            Set to False for a more realistic (but less accurate) evaluation.
    """
    prompt = _SYSTEM_PROMPT_BASE
    if include_lab_context:
        prompt += _LAB_CONTEXT
    return prompt


def _build_alert_prompt(alert: AlertRecord) -> str:
    """Build the user prompt for a single alert classification."""
    fields: Dict[str, object] = {
        "timestamp": alert.timestamp_raw,
        "source_ip": alert.src_ip,
        "source_port": alert.src_port,
        "destination_ip": alert.dst_ip,
        "destination_port": alert.dst_port,
        "protocol": alert.proto,
        "signature": alert.signature,
        "signature_id": alert.signature_id,
        "category": alert.category,
        "severity_from_ids": alert.severity_label,
        "action": alert.action,
        "app_protocol": alert.app_proto,
    }

    # Include HTTP context if available (critical for web attack classification)
    raw = alert.raw_event
    if "http" in raw:
        http = raw["http"]
        fields["http_url"] = http.get("url", "")
        fields["http_method"] = http.get("http_method", "")
        fields["http_status"] = http.get("status", "")
        fields["http_user_agent"] = http.get("http_user_agent", "")

    # Include MITRE ATT&CK info if available
    alert_meta = raw.get("alert", {}).get("metadata", {})
    if "mitre_technique_name" in alert_meta:
        fields["mitre_technique"] = alert_meta["mitre_technique_name"]
    if "mitre_tactic_name" in alert_meta:
        fields["mitre_tactic"] = alert_meta["mitre_tactic_name"]

    formatted = json.dumps(fields, indent=2)
    return f"Classify the following IDS alert:\n\n{formatted}"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

_VALID_CLASSIFICATIONS = {"true_positive", "likely_false_positive"}
_VALID_SEVERITIES = {"Low", "Medium", "High"}
_VALID_RECOMMENDATIONS = {"block_source_ip", "escalate_tier2", "continue_monitoring"}


def _validate_classification(data: dict) -> dict:
    """Validate and normalise LLM classification output.

    Raises ValueError if required fields are missing or have invalid values.
    """
    errors: List[str] = []

    classification = data.get("classification", "").strip().lower()
    if classification not in _VALID_CLASSIFICATIONS:
        errors.append(
            f"Invalid classification '{data.get('classification')}'. "
            f"Expected one of: {_VALID_CLASSIFICATIONS}"
        )
    data["classification"] = classification

    severity = data.get("severity", "").strip()
    severity_normalised = severity.capitalize()
    if severity_normalised not in _VALID_SEVERITIES:
        errors.append(
            f"Invalid severity '{data.get('severity')}'. "
            f"Expected one of: {_VALID_SEVERITIES}"
        )
    data["severity"] = severity_normalised

    recommendation = data.get("recommendation", "").strip().lower()
    if recommendation not in _VALID_RECOMMENDATIONS:
        errors.append(
            f"Invalid recommendation '{data.get('recommendation')}'. "
            f"Expected one of: {_VALID_RECOMMENDATIONS}"
        )
    data["recommendation"] = recommendation

    if not data.get("summary"):
        errors.append("Missing 'summary' field")

    if not data.get("reasoning"):
        errors.append("Missing 'reasoning' field")

    if errors:
        raise ValueError("; ".join(errors))

    return data


def _parse_json_response(raw: str) -> dict:
    """Parse a JSON response from the LLM, stripping markdown fences if present."""
    cleaned = raw.strip()

    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = [line for line in lines if not line.strip().startswith("```")]
        cleaned = "\n".join(lines).strip()

    return json.loads(cleaned)


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _aggregate_threat_actors(
    classifications: List[AlertClassification], top_n: int
) -> List[ThreatActor]:
    """Group classifications by source IP and return the top N."""
    by_ip: Dict[str, List[AlertClassification]] = {}
    for c in classifications:
        if c.status != "complete":
            continue
        by_ip.setdefault(c.src_ip, []).append(c)

    actors = []
    for ip, alerts in by_ip.items():
        actors.append(ThreatActor(
            ip=ip,
            alert_count=len(alerts),
            signatures=sorted(set(a.signature for a in alerts)),
            severity_labels=sorted(set(a.severity for a in alerts)),
            targeted_ports=sorted(set(a.dst_port for a in alerts)),
        ))

    actors.sort(key=lambda a: a.alert_count, reverse=True)
    return actors[:top_n]


def _aggregate_signatures(
    classifications: List[AlertClassification], top_n: int
) -> List[SignatureHit]:
    """Group classifications by signature and return the top N."""
    by_sig: Dict[str, List[AlertClassification]] = {}
    for c in classifications:
        if c.status != "complete":
            continue
        by_sig.setdefault(c.signature, []).append(c)

    hits = []
    for sig, alerts in by_sig.items():
        hits.append(SignatureHit(
            signature=sig,
            signature_id=alerts[0].signature_id,
            category=alerts[0].category,
            hit_count=len(alerts),
            severity_label=alerts[0].severity,
            source_ips=sorted(set(a.src_ip for a in alerts)),
        ))

    hits.sort(key=lambda h: h.hit_count, reverse=True)
    return hits[:top_n]


def _build_template_summary(
    classifications: List[AlertClassification],
    tp_count: int,
    fp_count: int,
    error_count: int,
) -> tuple[str, List[str]]:
    """Generate an executive summary using deterministic templates (no LLM).

    Returns (summary_text, recommendations_list).
    """
    total = len(classifications)

    high_tp = [c for c in classifications
               if c.classification == "true_positive" and c.severity == "High"]
    unique_attackers = set(
        c.src_ip for c in classifications if c.classification == "true_positive"
    )

    parts = [f"Analysed {total} IDS alerts."]

    if tp_count > 0:
        parts.append(
            f"Identified {tp_count} true positive(s) "
            f"({len(high_tp)} high severity) from "
            f"{len(unique_attackers)} unique source IP(s)."
        )
    if fp_count > 0:
        parts.append(
            f"{fp_count} alert(s) classified as likely false positives "
            f"(infrastructure noise)."
        )
    if error_count > 0:
        parts.append(f"{error_count} alert(s) could not be classified due to errors.")

    summary = " ".join(parts)

    recs: List[str] = []
    if high_tp:
        attacker_ips = sorted(set(c.src_ip for c in high_tp))
        recs.append(
            f"Block source IP(s) {', '.join(attacker_ips)} — "
            f"confirmed high-severity attack traffic."
        )
    if tp_count > 0:
        recs.append("Review all true positive alerts and validate attack impact.")
    if fp_count > 0:
        recs.append(
            "Consider tuning IDS rules to suppress known false positive signatures "
            "(e.g. internal Docker MySQL traffic on port 3306)."
        )
    if error_count > 0:
        recs.append("Investigate classification errors — may indicate LLM issues or malformed alerts.")
    recs.append("Continue monitoring for new attack patterns.")

    return summary, recs


# ---------------------------------------------------------------------------
# Main analyser
# ---------------------------------------------------------------------------

class AIAnalyzer:
    """Produces an AlertReport from a batch of AlertRecords via a ModelProvider.

    Usage::

        from model_provider import create_provider, ModelConfig, ProviderType

        cfg      = ModelConfig(provider=ProviderType.OLLAMA, model="llama3.2")
        provider = create_provider(cfg)
        analyzer = AIAnalyzer(provider)
        report   = analyzer.analyse(alerts)

    Configuration options:
        include_lab_context : bool  - Include Docker infrastructure details
                                      in the system prompt (default True).
        summary_mode        : str   - "llm" for AI-generated executive summary,
                                      "template" for deterministic template-based
                                      summary (default "llm").
    """

    def __init__(
        self,
        provider: ModelProvider,
        top_n: int = 10,
        include_lab_context: bool = True,
        summary_mode: str = "llm",
        max_retries: int = 1,
    ):
        self._provider = provider
        self.top_n = top_n
        self.include_lab_context = include_lab_context
        self.summary_mode = summary_mode
        self.max_retries = max_retries

        # Build and cache the classification system prompt
        self._classification_prompt = _build_system_prompt(include_lab_context)

        log.info(
            "AIAnalyzer initialised: lab_context=%s, summary_mode=%s, retries=%d",
            include_lab_context, summary_mode, max_retries,
        )

    # ----- Per-alert classification -----

    def _classify_single(self, alert: AlertRecord) -> AlertClassification:
        """Classify a single alert. Retries on failure up to max_retries."""

        alert_id = str(alert.flow_id) if alert.flow_id else str(uuid.uuid4())
        prompt = _build_alert_prompt(alert)
        raw_response = ""  # initialise to avoid unbound variable

        last_error = ""
        for attempt in range(1 + self.max_retries):
            try:
                log.debug(
                    "Classifying alert %s (attempt %d/%d): %s",
                    alert_id, attempt + 1, 1 + self.max_retries, alert.signature,
                )

                raw_response = self._provider.complete_json(
                    prompt,
                    system_prompt=self._classification_prompt,
                )
                log.debug("Raw LLM response: %s", raw_response[:500])

                parsed = _parse_json_response(raw_response)
                validated = _validate_classification(parsed)

                return AlertClassification(
                    alert_id=alert_id,
                    timestamp=alert.timestamp_raw,
                    classification=validated["classification"],
                    severity=validated["severity"],
                    summary=validated["summary"],
                    recommendation=validated["recommendation"],
                    reasoning=validated["reasoning"],
                    signature=alert.signature,
                    signature_id=alert.signature_id,
                    category=alert.category,
                    src_ip=alert.src_ip,
                    dst_ip=alert.dst_ip,
                    src_port=alert.src_port,
                    dst_port=alert.dst_port,
                    status="complete",
                )

            except json.JSONDecodeError as e:
                last_error = f"JSON parse error: {e}"
                log.warning(
                    "Alert %s attempt %d: %s | Raw: %s",
                    alert_id, attempt + 1, last_error, raw_response[:200],
                )
            except ValueError as e:
                last_error = f"Validation error: {e}"
                log.warning(
                    "Alert %s attempt %d: %s",
                    alert_id, attempt + 1, last_error,
                )
            except RuntimeError as e:
                last_error = f"Provider error: {e}"
                log.error(
                    "Alert %s attempt %d: %s",
                    alert_id, attempt + 1, last_error,
                )
                # Don't retry on provider errors (network/timeout) — likely persistent
                break

        log.error(
            "Alert %s classification failed after %d attempt(s): %s",
            alert_id, 1 + self.max_retries, last_error,
        )

        return AlertClassification(
            alert_id=alert_id,
            timestamp=alert.timestamp_raw,
            classification="",
            severity="",
            summary="",
            recommendation="",
            reasoning="",
            signature=alert.signature,
            signature_id=alert.signature_id,
            category=alert.category,
            src_ip=alert.src_ip,
            dst_ip=alert.dst_ip,
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            status="error",
            error=last_error,
        )

    # ----- Executive summary -----

    def _generate_llm_summary(
        self,
        classifications: List[AlertClassification],
        tp_count: int,
        fp_count: int,
        error_count: int,
        threat_actors: List[ThreatActor],
        signatures: List[SignatureHit],
        categories: List[str],
        period_start: str,
        period_end: str,
    ) -> tuple[str, List[str]]:
        """Generate executive summary using the LLM."""

        prompt = _SUMMARY_PROMPT_TEMPLATE.format(
            alert_count=len(classifications),
            tp_count=tp_count,
            fp_count=fp_count,
            error_count=error_count,
            severity_breakdown=json.dumps(
                dict(Counter(
                    c.severity for c in classifications if c.status == "complete"
                ))
            ),
            threat_actors=", ".join(
                f"{a.ip} ({a.alert_count} alerts)" for a in threat_actors[:5]
            ) or "None",
            signatures=", ".join(
                f"{s.signature} ({s.hit_count} hits)" for s in signatures[:5]
            ) or "None",
            categories=", ".join(categories) or "None",
            period_start=period_start,
            period_end=period_end,
        )

        try:
            raw = self._provider.complete_json(prompt)
            parsed = _parse_json_response(raw)

            summary = parsed.get("executive_summary", "")
            recs = parsed.get("recommendations", [])

            if not summary:
                raise ValueError("Empty executive_summary in LLM response")

            log.info("LLM-generated executive summary: %d chars", len(summary))
            return summary, recs

        except Exception as e:
            log.warning(
                "LLM summary generation failed: %s — falling back to template", e
            )
            return _build_template_summary(
                classifications, tp_count, fp_count, error_count
            )

    # ----- Main analysis pipeline -----

    def analyse(self, alerts: List[AlertRecord]) -> AlertReport:
        """Analyse a batch of alerts and return a structured AlertReport.

        Pipeline:
          1. Classify each alert individually (LLM call per alert)
          2. Aggregate classifications into threat actors and signatures
          3. Generate executive summary (LLM or template)
          4. Assemble and return the AlertReport
        """
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        if not alerts:
            log.warning("analyse() called with empty alert list")
            return AlertReport(
                report_id=report_id,
                generated_at=now,
                period_start_epoch=0,
                period_end_epoch=0,
                period_start_display="N/A",
                period_end_display="N/A",
                alert_count=0,
                severity_breakdown={},
                classifications=[],
                true_positive_count=0,
                false_positive_count=0,
                error_count=0,
                top_threat_actors=[],
                top_signatures=[],
                unique_source_ips=[],
                unique_categories=[],
                threat_summary="No alerts to analyse.",
                recommendations=[],
                model_used=self._provider.model_name,
                provider_type=self._provider.provider_type.value,
                raw_ai_response=None,
                status="complete",
                error=None,
            )

        log.info("Starting analysis of %d alert(s) [report=%s]", len(alerts), report_id)

        # --- Step 1: Per-alert classification ---
        classifications: List[AlertClassification] = []
        for i, alert in enumerate(alerts):
            log.info(
                "Classifying alert %d/%d: %s (sig=%s)",
                i + 1, len(alerts), alert.src_ip, alert.signature,
            )
            result = self._classify_single(alert)
            classifications.append(result)

        # --- Step 2: Count results ---
        tp_count = sum(
            1 for c in classifications if c.classification == "true_positive"
        )
        fp_count = sum(
            1 for c in classifications if c.classification == "likely_false_positive"
        )
        error_count = sum(
            1 for c in classifications if c.status == "error"
        )

        severity_breakdown = dict(Counter(
            c.severity for c in classifications if c.status == "complete"
        ))

        # --- Step 3: Aggregate ---
        threat_actors = _aggregate_threat_actors(classifications, self.top_n)
        signatures = _aggregate_signatures(classifications, self.top_n)
        unique_ips = sorted(set(c.src_ip for c in classifications))
        unique_cats = sorted(set(
            c.category for c in classifications if c.category != "-"
        ))

        # --- Time window ---
        epochs = [a.timestamp_epoch for a in alerts if a.timestamp_epoch > 0]
        if epochs:
            start_epoch = min(epochs)
            end_epoch = max(epochs)
            start_display = datetime.fromtimestamp(
                start_epoch, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
            end_display = datetime.fromtimestamp(
                end_epoch, tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            start_epoch = end_epoch = 0.0
            start_display = end_display = "N/A"

        # --- Step 4: Executive summary ---
        if self.summary_mode == "llm":
            summary_text, rec_list = self._generate_llm_summary(
                classifications, tp_count, fp_count, error_count,
                threat_actors, signatures, unique_cats,
                start_display, end_display,
            )
        else:
            summary_text, rec_list = _build_template_summary(
                classifications, tp_count, fp_count, error_count,
            )

        # --- Assemble report ---
        now = datetime.now(timezone.utc).isoformat()

        report = AlertReport(
            report_id=report_id,
            generated_at=now,
            period_start_epoch=start_epoch,
            period_end_epoch=end_epoch,
            period_start_display=start_display,
            period_end_display=end_display,
            alert_count=len(alerts),
            severity_breakdown=severity_breakdown,
            classifications=classifications,
            true_positive_count=tp_count,
            false_positive_count=fp_count,
            error_count=error_count,
            top_threat_actors=threat_actors,
            top_signatures=signatures,
            unique_source_ips=unique_ips,
            unique_categories=unique_cats,
            threat_summary=summary_text,
            recommendations=rec_list,
            model_used=self._provider.model_name,
            provider_type=self._provider.provider_type.value,
            raw_ai_response=None,
            status="complete",
            error=None,
        )

        log.info(
            "Analysis complete [report=%s]: %d TP, %d FP, %d errors",
            report_id, tp_count, fp_count, error_count,
        )

        return report