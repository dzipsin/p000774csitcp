"""
report_generator.py - Produces IncidentReports from Incidents via two-stage LLM pipeline.

Pipeline:
  Stage 1 (per-alert): classify each alert - true/false positive, severity,
                       recommendation, reasoning. N LLM calls per incident.
  Stage 2 (incident):  narrative summary, attack vectors, attack stage,
                       recommendations, exposure assessment. 1 LLM call.
  Rule-based:          CVSS, confidence_score, data_sensitive_rating,
                       indicators_of_compromise. Deterministic derivations
                       from the alert data (no LLM).

Design principles:
  - Graceful degradation: if Stage 2 fails, fall back to template-based
    narrative. If individual alert classifications fail, continue with
    what succeeded.
  - Rule-based for anything requiring calibrated numbers or domain knowledge
    the LLM lacks.
  - Prompt injection defense: system prompt explicitly instructs the model
    to treat alert data fields as untrusted content.

Depends on:
  models.*                     - dataclasses
  model_provider.ModelProvider  - LLM backend interface
  report_db.ReportDatabase     - SQLite-backed persistence

The frontend consumes the per-incident output of this module via
/api/incidents/*; there is no batch-mode classification path any more.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from react_agent import ReActAgent

from log_monitor import AlertRecord
from model_provider import ModelProvider
from models import (
    AlertAnalysis,
    AlertClassification,
    AlertExposure,
    Incident,
    IncidentReport,
    IncidentSummary,
    IncidentSummaryDescription,
    InformationExposure,
    InformationExposureDescription,
    extract_attack_type,
)
from report_db import ReportDatabase

from prompts import (
    _STAGE2_PROMPT_TEMPLATE,
    _build_stage1_system_prompt,
    _build_stage1_user_prompt,
)
from rule_engine import (
    _build_iocs,
    _classify_payload,
    _compute_overall_severity,
    _confidence_score,
    _data_sensitivity_from_alerts,
    _default_intent,
    _ensure_list_of_strings,
    _extract_affected_data_fields,
    _override_mitre_tactic,
    _parse_json_response,
    _severity_to_cvss,
    _summarise_enrichment,
    _template_stage2_output,
    _validate_stage1_response,
)
from suggestions import (
    _dedup_near_duplicates,
    _extract_enrichment_facts,
    _filter_generic_llm_suggestions,
    _filter_llm_against_enrichment,
    _generate_rule_based_suggestions,
    _merge_suggestions,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generates an IncidentReport for an Incident via the two-stage LLM pipeline.

    Usage::

        generator = ReportGenerator(
            provider=my_ollama_provider,
            storage=ReportDatabase(db_path="data/reports.db"),
            include_lab_context=True,
            summary_mode="llm",
        )

        # Bind as the IncidentManager callback:
        incident_manager.set_regenerate_callback(generator.generate)

    Thread safety: generate() is safe to call from multiple threads because
    the generator itself is stateless - state lives in the Incident (passed in)
    and the Storage (thread-safe).
    """

    def __init__(
        self,
        provider: ModelProvider,
        storage: Optional[ReportDatabase] = None,
        include_lab_context: bool = True,
        summary_mode: str = "llm",
        max_retries: int = 1,
        is_repeat_offender: Optional[Callable[[str], bool]] = None,
        on_report_ready: Optional[Callable[[IncidentReport], None]] = None,
        agent_mode: str = "single_shot",
        react_agent: Optional[ReActAgent] = None,
        env_entries: Optional[List[Dict[str, Any]]] = None,
    ):
        """
        Args:
            provider: LLM backend (any ModelProvider implementation)
            storage: ReportDatabase for persisting reports (None = don't persist)
            include_lab_context: include Docker lab details in Stage 1 prompt
            summary_mode: "llm" or "template" for Stage 2
            max_retries: retries per LLM call on parse/validation failures
            is_repeat_offender: callable(source_ip) -> bool for repeat flag
            on_report_ready: callable(IncidentReport) -> None called after save
            agent_mode: "single_shot" (default) keeps original behavior.
                        "react" delegates per-alert classification to react_agent.
            react_agent: a ReActAgent instance. Required when agent_mode='react'.
            env_entries: [[agent.environment.entries]] from app.config. Used
                         by the rule-based suggestion generator and the
                         LLM-suggestion filter to derive env facts from
                         the incident's source_ip even when auto_enrichment
                         is off (i.e. single_shot or react+no-enrich modes).
                         Optional - when None, fallback is disabled and
                         filters operate on whatever the reasoning trace
                         contains.
        """
        if summary_mode not in ("llm", "template"):
            log.warning(
                "Invalid summary_mode '%s', defaulting to 'template'", summary_mode,
            )
            summary_mode = "template"

        if agent_mode not in ("single_shot", "react"):
            log.warning(
                "Invalid agent_mode '%s', defaulting to 'single_shot'", agent_mode,
            )
            agent_mode = "single_shot"
        if agent_mode == "react" and react_agent is None:
            log.warning(
                "agent_mode='react' but no react_agent supplied - "
                "falling back to single_shot",
            )
            agent_mode = "single_shot"

        self._provider = provider
        self._storage = storage
        self.include_lab_context = include_lab_context
        self.summary_mode = summary_mode
        self.max_retries = max_retries
        self._is_repeat_offender = is_repeat_offender or (lambda _: False)
        self._on_report_ready = on_report_ready

        self._agent_mode = agent_mode
        self._react_agent = react_agent
        # Cached env_entries so the rule-based + filter code can derive
        # facts without a reasoning trace (single_shot mode fallback).
        self._env_entries = list(env_entries or [])

        self._stage1_system_prompt = _build_stage1_system_prompt(
            include_lab_context, self._env_entries
        )

        log.info(
            "ReportGenerator ready: agent_mode=%s, lab_context=%s, "
            "summary_mode=%s, retries=%d",
            agent_mode, include_lab_context, summary_mode, max_retries,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, incident: Incident) -> IncidentReport:
        """Produce an IncidentReport for the given Incident.

        Never raises on expected failures - instead marks generation_status
        and returns a (partial) report. This keeps the pipeline alive when
        the LLM misbehaves.
        """
        try:
            return self._generate_unsafe(incident)
        except Exception as e:
            log.exception("Unexpected error generating report for %s", incident.incident_id)
            return self._build_error_report(incident, str(e))

    def _generate_unsafe(self, incident: Incident) -> IncidentReport:
        """Actual generation logic; may raise on truly unexpected errors."""
        if incident is None:
            raise ValueError("Cannot generate report from None incident")

        log.info(
            "Generating report for incident %s (v%d, alerts=%d, status=%s)",
            incident.incident_id, incident.report_version,
            incident.alert_count, incident.status,
        )

        if incident.alert_count == 0:
            log.warning("Incident %s has 0 alerts", incident.incident_id)
            return self._build_error_report(incident, "Incident has no alerts")

        # --- Stage 1: per-alert classification ---
        classifications = self._run_stage1(incident.alerts)

        # --- Counts ---
        tp_count = sum(1 for c in classifications if c.classification == "true_positive")
        fp_count = sum(1 for c in classifications if c.classification == "likely_false_positive")
        error_count = sum(1 for c in classifications if c.status == "error")

        classification_counts = {
            "true_positive": tp_count,
            "likely_false_positive": fp_count,
            "error": error_count,
        }

        # --- Derive attack types and severities ---
        detected_attacks = sorted({
            extract_attack_type(a.signature, a.signature_id) for a in incident.alerts
        } - {"Other"}) or ["Other"]

        overall_severity = _compute_overall_severity(classifications)

        # --- Stage 2: incident narrative ---
        stage2 = self._run_stage2(
            incident=incident,
            classifications=classifications,
            tp_count=tp_count,
            fp_count=fp_count,
            error_count=error_count,
            detected_attacks=detected_attacks,
        )

        # MITRE tactic override - deterministic correction for known attack
        # types the small LLM commonly mis-tags. Honest engineering:
        # rule-based for what we KNOW, LLM judgment for everything else.
        original_tactic = stage2.get("overall_attack_stage", "")
        fixed_tactic, was_overridden = _override_mitre_tactic(
            detected_attacks=detected_attacks,
            current_tactic=original_tactic,
            incident_alerts=incident.alerts,
        )
        if was_overridden:
            log.info(
                "Stage 2 MITRE tactic overridden: '%s' -> '%s' "
                "(detected_attacks=%s)",
                original_tactic, fixed_tactic, detected_attacks,
            )
            stage2["overall_attack_stage"] = fixed_tactic

        # Hybrid suggestion policy (Option C, tightened):
        #   1. rule-based recommendations from playbook patterns (always specific)
        #   2. LLM suggestions filtered through three layers:
        #        a. drop generic platitudes by banned-starter regex
        #        b. drop suggestions that contradict enrichment data
        #           (e.g. "Block 172.18.0.2" when the source is documented
        #           internal infrastructure)
        #        c. drop near-duplicates of rule-based (same verb + same IP)
        #   3. merge rule-based first, dedup'd, capped at 6 total.
        rule_based_suggestions = _generate_rule_based_suggestions(
            incident=incident,
            classifications=classifications,
            detected_attacks=detected_attacks,
            tp_count=tp_count,
            fp_count=fp_count,
            env_entries=self._env_entries,
            repeat_offender_checker=self._is_repeat_offender,
        )

        raw_llm = stage2.get("ai_suggestions", []) or []
        llm_after_generic = _filter_generic_llm_suggestions(raw_llm)

        # Compute facts with the SAME fallback so single_shot mode also
        # benefits from the enrichment-aware filter.
        facts = _extract_enrichment_facts(
            classifications=classifications,
            incident=incident,
            env_entries=self._env_entries,
            repeat_offender_checker=self._is_repeat_offender,
        )
        llm_after_enrichment = _filter_llm_against_enrichment(
            llm_after_generic, facts,
        )

        llm_after_dedup = _dedup_near_duplicates(
            rule_based_suggestions, llm_after_enrichment,
        )

        stage2["ai_suggestions"] = _merge_suggestions(
            rule_based=rule_based_suggestions,
            llm=llm_after_dedup,
            max_total=6,
        )

        if rule_based_suggestions or raw_llm:
            log.info(
                "Suggestions: %d rule-based, %d LLM raw -> %d after generic "
                "filter -> %d after enrichment filter -> %d after dedup; "
                "%d total emitted",
                len(rule_based_suggestions),
                len(raw_llm),
                len(llm_after_generic),
                len(llm_after_enrichment),
                len(llm_after_dedup),
                len(stage2.get("ai_suggestions", [])),
            )

        # --- Rule-based fields ---
        data_sensitivity = _data_sensitivity_from_alerts(incident.alerts)
        iocs = _build_iocs(incident.alerts)

        # --- Assemble alert-level sections ---
        alert_analyses = self._build_alert_analyses(incident.alerts, classifications)
        alert_exposures = self._build_alert_exposures(incident.alerts, classifications)

        # --- Timestamps ---
        now_iso = datetime.now(timezone.utc).isoformat()

        # --- Summary section ---
        summary = IncidentSummary(
            incident_id=incident.incident_id,
            report_id=str(uuid.uuid4()),
            report_version=f"v{incident.report_version}",
            incident_status=incident.status,
            generated_at=now_iso,
            last_updated_at=now_iso,
            first_seen=incident.first_seen_display,
            last_seen=incident.last_seen_display,
            source_ip=incident.source_ip,
            total_alerts=incident.alert_count,
            classification_counts=classification_counts,
            detected_attacks=detected_attacks,
            overall_severity=overall_severity,
            overall_cvss_estimate=_severity_to_cvss(overall_severity),
            repeat_offender=bool(self._is_repeat_offender(incident.source_ip)),
        )

        narrative = IncidentSummaryDescription(
            overview=stage2.get("overview", ""),
            attack_vectors=stage2.get("attack_vectors", []),
            overall_attack_stage=stage2.get("overall_attack_stage", ""),
            ai_suggestions=stage2.get("ai_suggestions", []),
        )

        exposure = InformationExposure(
            exposure_detected=bool(stage2.get("exposure_detected", False)),
            exposure_types=stage2.get("exposure_types", []),
            affected_systems=stage2.get("affected_systems", []),
            data_sensitive_rating=data_sensitivity,
            indicators_of_compromise=iocs,
        )

        exposure_desc = InformationExposureDescription(
            exposure_summary=stage2.get("exposure_summary", ""),
            impact_assessment=stage2.get("impact_assessment", ""),
        )

        # Determine overall generation status
        gen_status = "complete"
        if error_count > 0 and error_count == len(classifications):
            gen_status = "error"
        elif error_count > 0 or stage2.get("_fallback") is True:
            gen_status = "partial"

        report = IncidentReport(
            incident_summary=summary,
            alerts=[a.to_dict() for a in incident.alerts],
            incident_summary_description=narrative,
            alert_analyses=alert_analyses,
            information_exposure=exposure,
            alert_exposures=alert_exposures,
            information_exposure_description=exposure_desc,
            model_used=self._provider.model_name,
            provider_type="ollama",
            generation_status=gen_status,
            generation_error=None if gen_status != "error" else "All alert classifications failed",
        )

        # Persist
        if self._storage is not None:
            self._storage.save(report)

        # Notify listener (dashboard push, etc.)
        if self._on_report_ready is not None:
            try:
                self._on_report_ready(report)
            except Exception as e:
                log.exception("on_report_ready callback raised: %s", e)

        log.info(
            "Report ready: incident=%s version=%s status=%s (TP=%d FP=%d err=%d)",
            incident.incident_id[:8], summary.report_version,
            gen_status, tp_count, fp_count, error_count,
        )
        return report

    # ------------------------------------------------------------------
    # Stage 1: per-alert classification
    # ------------------------------------------------------------------

    def _run_stage1(self, alerts: List[AlertRecord]) -> List[AlertClassification]:
        """Classify each alert. Returns one AlertClassification per alert.

        Failed classifications get status='error' but the pipeline continues.
        """
        results: List[AlertClassification] = []
        for i, alert in enumerate(alerts):
            log.debug(
                "Stage 1 classifying alert %d/%d: %s",
                i + 1, len(alerts), alert.signature[:80],
            )
            results.append(self._classify_single(alert))
        return results

    def _classify_single(self, alert: AlertRecord) -> AlertClassification:
        """Classify a single alert.

        Dispatches based on agent_mode:
          - "react"       -> ReActAgent.classify(alert) which runs the tool-using
                             loop; produces an AlertClassification with
                             reasoning_trace populated.
          - "single_shot" -> existing path (kept verbatim under
                             _classify_single_singleshot). Used as the baseline
                             for evaluation and as the fallback inside ReActAgent
                             itself.
        """
        if self._agent_mode == "react" and self._react_agent is not None:
            cls = self._react_agent.classify(alert)
            # ReActAgent doesn't populate confidence_score (it lives on the
            # report-generator rule layer). Fill it in now.
            cls.confidence_score = _confidence_score(alert, cls)
            return cls
        return self._classify_single_singleshot(alert)

    def _classify_single_singleshot(self, alert: AlertRecord) -> AlertClassification:
        """Classify a single alert with retry on parse/validation failure."""
        alert_id = str(alert.flow_id) if alert.flow_id else str(uuid.uuid4())
        attack_type = extract_attack_type(alert.signature, alert.signature_id)
        user_prompt = _build_stage1_user_prompt(alert)

        last_error = ""
        raw_response = ""

        for attempt in range(1 + self.max_retries):
            try:
                raw_response = self._provider.complete_json(
                    user_prompt,
                    system_prompt=self._stage1_system_prompt,
                )
                parsed = _parse_json_response(raw_response)
                validated = _validate_stage1_response(parsed)

                cls = AlertClassification(
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
                    attack_type=attack_type,
                    confidence_score=0.0,  # filled in below
                    status="complete",
                )
                cls.confidence_score = _confidence_score(alert, cls)
                return cls

            except json.JSONDecodeError as e:
                last_error = f"JSON parse error: {e}"
                log.warning(
                    "Alert %s attempt %d: %s | Raw: %s",
                    alert_id, attempt + 1, last_error, raw_response[:200],
                )
            except ValueError as e:
                last_error = f"Validation error: {e}"
                log.warning(
                    "Alert %s attempt %d: %s", alert_id, attempt + 1, last_error,
                )
            except RuntimeError as e:
                # Provider-level failure (network, timeout) - don't retry
                last_error = f"Provider error: {e}"
                log.error("Alert %s attempt %d: %s", alert_id, attempt + 1, last_error)
                break
            except Exception as e:
                last_error = f"Unexpected error: {type(e).__name__}: {e}"
                log.exception("Alert %s attempt %d unexpected error", alert_id, attempt + 1)
                break

        # All attempts failed
        log.error(
            "Alert %s classification failed after %d attempt(s): %s",
            alert_id, 1 + self.max_retries, last_error,
        )

        error_cls = AlertClassification(
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
            attack_type=attack_type,
            confidence_score=0.2,  # low confidence on error
            status="error",
            error=last_error,
        )
        return error_cls

    # ------------------------------------------------------------------
    # Stage 2: incident narrative
    # ------------------------------------------------------------------

    def _run_stage2(
        self,
        incident: Incident,
        classifications: List[AlertClassification],
        tp_count: int,
        fp_count: int,
        error_count: int,
        detected_attacks: List[str],
    ) -> dict:
        """Generate incident-level narrative. Falls back to template on failure.

        Returns a dict with keys matching the Stage 2 schema. Sets _fallback=True
        if the LLM path failed and template was used.
        """
        if self.summary_mode == "template":
            log.info("Stage 2 using template mode")
            result = _template_stage2_output(
                incident, classifications, tp_count, fp_count, error_count, detected_attacks,
            )
            return result

        # LLM mode
        severity_breakdown = dict(Counter(
            c.severity for c in classifications if c.status == "complete"
        ))

        # Top signatures
        sig_counts = Counter(a.signature for a in incident.alerts)
        top_sigs = [f"{sig} ({count})" for sig, count in sig_counts.most_common(5)]

        # Endpoints seen
        endpoints: set = set()
        for a in incident.alerts:
            http = (a.raw_event or {}).get("http", {})
            if isinstance(http, dict):
                url = str(http.get("url", ""))
                if url:
                    # Keep just the path portion for brevity
                    path = url.split("?")[0]
                    if path:
                        endpoints.add(path)
                        if len(endpoints) >= 10:
                            break

        # Per-alert summary lines (truncated)
        summaries = []
        for c in classifications[:15]:  # cap to avoid massive prompts
            line = (
                f"- [{c.severity or 'unknown'}] {c.classification or 'error'}: "
                f"{c.signature[:80]} (src={c.src_ip})"
            )
            summaries.append(line)
        summary_block = "\n".join(summaries) if summaries else "(none)"

        # Enrichment summary aggregated from Stage 1 reasoning traces.
        # Lets the narrative reference concrete facts (prior alert counts,
        # environment role) instead of just "the agent classified X as Y".
        enrichment_summary = _summarise_enrichment(classifications)

        prompt = _STAGE2_PROMPT_TEMPLATE.format(
            source_ip=incident.source_ip,
            repeat_offender=self._is_repeat_offender(incident.source_ip),
            alert_count=incident.alert_count,
            tp_count=tp_count,
            fp_count=fp_count,
            error_count=error_count,
            severity_breakdown=json.dumps(severity_breakdown),
            detected_attacks=", ".join(detected_attacks) if detected_attacks else "None",
            first_seen=incident.first_seen_display,
            last_seen=incident.last_seen_display,
            top_signatures=", ".join(top_sigs) if top_sigs else "None",
            endpoints=", ".join(sorted(endpoints)) if endpoints else "None",
            enrichment_summary=enrichment_summary,
            classification_summaries=summary_block,
        )

        last_error = ""
        for attempt in range(1 + self.max_retries):
            try:
                raw = self._provider.complete_json(prompt)
                parsed = _parse_json_response(raw)

                # Basic shape validation - don't be too strict so LLM has room
                if not isinstance(parsed, dict):
                    raise ValueError("Stage 2 response is not a dict")

                # Coerce expected keys - missing ones default to empty
                result = {
                    "overview": str(parsed.get("overview", "")),
                    "attack_vectors": _ensure_list_of_strings(parsed.get("attack_vectors", [])),
                    "overall_attack_stage": str(parsed.get("overall_attack_stage", "")),
                    "ai_suggestions": _ensure_list_of_strings(parsed.get("ai_suggestions", [])),
                    "exposure_detected": bool(parsed.get("exposure_detected", False)),
                    "exposure_types": _ensure_list_of_strings(parsed.get("exposure_types", [])),
                    "affected_systems": _ensure_list_of_strings(parsed.get("affected_systems", [])),
                    "exposure_summary": str(parsed.get("exposure_summary", "")),
                    "impact_assessment": str(parsed.get("impact_assessment", "")),
                }

                if not result["overview"].strip():
                    raise ValueError("Empty overview in Stage 2 response")

                return result

            except (json.JSONDecodeError, ValueError) as e:
                last_error = f"{type(e).__name__}: {e}"
                log.warning("Stage 2 attempt %d: %s", attempt + 1, last_error)
            except RuntimeError as e:
                last_error = f"Provider error: {e}"
                log.error("Stage 2 attempt %d: %s", attempt + 1, last_error)
                break
            except Exception as e:
                last_error = f"Unexpected: {type(e).__name__}: {e}"
                log.exception("Stage 2 attempt %d unexpected", attempt + 1)
                break

        log.warning(
            "Stage 2 LLM failed (%s) - falling back to template", last_error,
        )
        result = _template_stage2_output(
            incident, classifications, tp_count, fp_count, error_count, detected_attacks,
        )
        result["_fallback"] = True
        return result

    # ------------------------------------------------------------------
    # Alert-level sections
    # ------------------------------------------------------------------

    def _build_alert_analyses(
        self,
        alerts: List[AlertRecord],
        classifications: List[AlertClassification],
    ) -> List[AlertAnalysis]:
        """Build the alert_analyses array (one entry per alert)."""
        results: List[AlertAnalysis] = []

        # Pair each alert with its classification by index
        for alert, cls in zip(alerts, classifications):
            attack_type = extract_attack_type(alert.signature, alert.signature_id)
            http = (alert.raw_event or {}).get("http", {})
            payload = ""
            if isinstance(http, dict):
                payload = str(http.get("url", ""))[:500]
            if not payload:
                payload = alert.signature[:500]

            # Intent inference: prefer LLM summary if we have one; else rule-based
            if cls.summary:
                intent = cls.summary
            else:
                intent = _default_intent(attack_type)

            results.append(AlertAnalysis(
                alert_id=cls.alert_id,
                attack_type_classified=attack_type,
                payload_observed=payload,
                payload_classification=_classify_payload(alert, attack_type),
                likely_intent=intent,
                confidence_score=cls.confidence_score,
                classification=cls.classification,
                severity=cls.severity,
                recommendation=cls.recommendation,
                classification_status=cls.status,
                # ReAct metadata - None/defaults for single-shot path
                reasoning_trace=cls.reasoning_trace,
                agent_mode=cls.agent_mode,
                parse_failure_count=cls.parse_failure_count,
                tool_calls=cls.tool_calls,
            ))

        return results

    def _build_alert_exposures(
        self,
        alerts: List[AlertRecord],
        classifications: List[AlertClassification],
    ) -> List[AlertExposure]:
        """Build the alert_exposures array (one entry per alert)."""
        results: List[AlertExposure] = []

        for alert, cls in zip(alerts, classifications):
            cvss = _severity_to_cvss(cls.severity) if cls.severity else 0.0
            fields = _extract_affected_data_fields(alert)
            results.append(AlertExposure(
                alert_id=cls.alert_id,
                affected_data_fields=fields,
                cvss_estimate=cvss,
            ))

        return results

    # ------------------------------------------------------------------
    # Defensive error reports
    # ------------------------------------------------------------------

    def _build_error_report(self, incident: Incident, error_msg: str) -> IncidentReport:
        """Produce a minimal report when generation fails catastrophically."""
        now_iso = datetime.now(timezone.utc).isoformat()

        summary = IncidentSummary(
            incident_id=incident.incident_id,
            report_id=str(uuid.uuid4()),
            report_version=f"v{incident.report_version}",
            incident_status=incident.status,
            generated_at=now_iso,
            last_updated_at=now_iso,
            first_seen=incident.first_seen_display,
            last_seen=incident.last_seen_display,
            source_ip=incident.source_ip,
            total_alerts=incident.alert_count,
            classification_counts={"true_positive": 0, "likely_false_positive": 0, "error": incident.alert_count},
            detected_attacks=["unknown"],
            overall_severity="low",
            overall_cvss_estimate=0.0,
            repeat_offender=bool(self._is_repeat_offender(incident.source_ip)),
        )

        report = IncidentReport(
            incident_summary=summary,
            alerts=[a.to_dict() for a in incident.alerts],
            incident_summary_description=IncidentSummaryDescription(
                overview=f"Report generation failed: {error_msg}",
                attack_vectors=[],
                overall_attack_stage="",
                ai_suggestions=["Review logs for the generation error"],
            ),
            alert_analyses=[],
            information_exposure=InformationExposure(
                exposure_detected=False,
                exposure_types=[],
                affected_systems=[],
                data_sensitive_rating="unknown",
                indicators_of_compromise=_build_iocs(incident.alerts),
            ),
            alert_exposures=[],
            information_exposure_description=InformationExposureDescription(
                exposure_summary="Unable to assess exposure due to generation error.",
                impact_assessment="Unable to assess impact due to generation error.",
            ),
            model_used=getattr(self._provider, "model_name", None),
            provider_type="ollama",
            generation_status="error",
            generation_error=error_msg,
        )

        if self._storage is not None:
            self._storage.save(report)

        return report
