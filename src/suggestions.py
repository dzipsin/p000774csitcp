# suggestions.py - AI suggestion quality control (hybrid rule-based + LLM filter).

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Any, Callable, Dict, List, Optional

from log_monitor import AlertRecord
from models import AlertClassification, Incident, extract_attack_type

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# AI suggestion quality control (hybrid rule-based + LLM filter)
# ---------------------------------------------------------------------------
#
# qwen2.5:3b reliably produces generic platitudes for `ai_suggestions`
# regardless of how specific the alert data is. To compensate:
#   1. Generate deterministic, playbook-style suggestions from the
#      enrichment data + signatures (covers the predictable cases).
#   2. Filter LLM-emitted suggestions to drop known generic starters.
#   3. Merge: rule-based first, surviving LLM after, dedup'd.
# This matches the MITRE-tactic override pattern below - rule for what we
# KNOW, LLM judgment for the rest.

_BANNED_SUGGESTION_STARTERS = re.compile(
    r"^\s*(implement additional|review and update|enhance monitoring|"
    r"consider implementing|consider using|educate developers|"
    r"regularly update|implement input validation|"
    r"implement a web application firewall)",
    re.IGNORECASE,
)


def _extract_enrichment_facts(
    classifications: List["AlertClassification"],
    incident: Optional["Incident"] = None,
    env_entries: Optional[List[Dict[str, Any]]] = None,
    repeat_offender_checker: Optional[Callable[[str], bool]] = None,
) -> Dict[str, Any]:
    """Build the flat fact dict the rule-based generator + LLM filter consume.

    Two ways to populate the facts, applied in order:

      1. Walk the Stage 1 reasoning traces. System-driven enrichment
         steps carry both get_alert_history (prior counts, repeat
         offender) and lookup_environment_context (env role, hint)
         results. This is the path the React+Enrichment configuration
         takes.

      2. Fall back to deterministic derivation from the incident's
         source_ip. In single-shot mode (or react+no-enrich), no
         reasoning trace exists - but the same env config used by the
         enrichment tool is available, and the IncidentManager's repeat
         offender flag is callable. Filling these in here means the
         filter + rule-based generator work IDENTICALLY across all
         modes.

    Optional `incident` + `env_entries` + `repeat_offender_checker`
    enable the fallback. Without them the function reverts to old
    trace-only behaviour.
    """
    facts: Dict[str, Any] = {
        "is_repeat_offender": False,
        "prior_alert_count": 0,
        "env_match_found": False,
        "env_hint": "",
        "env_role": "",
        "is_internal_only": False,
        "is_untrusted_external": False,
    }

    # --- Path 1: reasoning trace from auto-enrichment ---
    for cls in classifications:
        trace = getattr(cls, "reasoning_trace", None)
        if not trace:
            continue

        for step in trace:
            if getattr(step, "source", "model") != "system":
                continue
            obs_raw = step.observation
            if not obs_raw:
                continue
            try:
                obs = json.loads(obs_raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(obs, dict):
                continue

            if step.action == "get_alert_history":
                facts["is_repeat_offender"] = bool(
                    obs.get("is_repeat_offender_this_session", False),
                )
                try:
                    facts["prior_alert_count"] = int(obs.get("total_prior_alerts", 0) or 0)
                except (TypeError, ValueError):
                    facts["prior_alert_count"] = 0

            elif step.action == "lookup_environment_context":
                if obs.get("match_found"):
                    facts["env_match_found"] = True
                    facts["env_hint"] = str(obs.get("classification_hint", "") or "")
                    facts["env_role"] = str(obs.get("role", "") or "")
                    if facts["env_hint"] == "untrusted_source_likely_attacker":
                        facts["is_untrusted_external"] = True
                    if facts["env_hint"] == "likely_false_positive_if_internal_only":
                        facts["is_internal_only"] = True

        # Facts are identical across alerts in the same incident - first
        # populated trace wins.
        if any(facts[k] for k in ("env_match_found", "is_repeat_offender")):
            break

    # --- Path 2: deterministic fallback from incident.source_ip ---
    # Applied per-field - if Path 1 already set a field, leave it alone.
    if incident is not None and incident.source_ip:
        # Env lookup
        if not facts["env_match_found"] and env_entries:
            try:
                from agent_tools import lookup_environment_for_query
                match = lookup_environment_for_query(env_entries, incident.source_ip)
            except ImportError:  # pragma: no cover - defensive
                match = None
            if match:
                facts["env_match_found"] = True
                facts["env_hint"] = str(match.get("classification_hint", "") or "")
                facts["env_role"] = str(match.get("role", "") or "")
                if facts["env_hint"] == "untrusted_source_likely_attacker":
                    facts["is_untrusted_external"] = True
                if facts["env_hint"] == "likely_false_positive_if_internal_only":
                    facts["is_internal_only"] = True

        # Repeat offender - IncidentManager carries the in-session state
        if not facts["is_repeat_offender"] and repeat_offender_checker is not None:
            try:
                if repeat_offender_checker(incident.source_ip):
                    facts["is_repeat_offender"] = True
            except Exception:  # noqa: BLE001 - never let fallback raise
                pass

    return facts


def _generate_rule_based_suggestions(
    incident: "Incident",
    classifications: List["AlertClassification"],
    detected_attacks: List[str],
    tp_count: int,
    fp_count: int,
    env_entries: Optional[List[Dict[str, Any]]] = None,
    repeat_offender_checker: Optional[Callable[[str], bool]] = None,
) -> List[str]:
    """Deterministic SOC-playbook style suggestions.

    Reads enrichment facts via _extract_enrichment_facts and emits specific,
    actionable recommendations matching common incident patterns:

      - Repeat offender + untrusted external -> block + pentest-tracker hint
      - SQLi targeting credentials -> rotate credentials
      - XSS confirmed -> audit endpoint output encoding
      - Command injection -> investigate target host
      - Any TP -> open Tier-2 ticket
      - All FP from internal-only IP -> tune Suricata to suppress

    Order matters - most operationally urgent first.

    Optional `env_entries` + `repeat_offender_checker` are forwarded to
    _extract_enrichment_facts so the generator produces meaningful
    suggestions even in single_shot mode (no reasoning trace).
    """
    suggestions: List[str] = []
    facts = _extract_enrichment_facts(
        classifications=classifications,
        incident=incident,
        env_entries=env_entries,
        repeat_offender_checker=repeat_offender_checker,
    )
    src_ip = incident.source_ip or "<unknown>"
    incident_short = incident.incident_id[:8] if incident.incident_id else "?"

    has_tp = tp_count > 0
    detected_set = set(detected_attacks or [])

    # Did any alert signature target credentials specifically?
    has_sqli_creds = False
    if "SQLi" in detected_set:
        for a in incident.alerts:
            sig_upper = (a.signature or "").upper()
            if "SQL" in sig_upper and (
                "USER" in sig_upper or "PASS" in sig_upper or "CREDENTIAL" in sig_upper
            ):
                has_sqli_creds = True
                break

    # XSS endpoints actually targeted (drop empty + dedupe + sort)
    xss_endpoints: List[str] = []
    if "XSS" in detected_set:
        seen_eps: set = set()
        for a in incident.alerts:
            if extract_attack_type(a.signature, a.signature_id) != "XSS":
                continue
            http = (a.raw_event or {}).get("http", {})
            if not isinstance(http, dict):
                continue
            url = str(http.get("url", "") or "")
            path = url.split("?")[0] if url else ""
            if path and path not in seen_eps:
                seen_eps.add(path)
                xss_endpoints.append(path)

    # --- 1. Block source IP (highest urgency for confirmed external attacks) ---
    if has_tp and facts["is_untrusted_external"]:
        if facts["is_repeat_offender"] and facts["prior_alert_count"] > 0:
            suggestions.append(
                f"Block {src_ip} at the perimeter firewall - repeat offender "
                f"with {facts['prior_alert_count']} prior alert(s) this session "
                f"from UNTRUSTED EXTERNAL network."
            )
        else:
            suggestions.append(
                f"Block {src_ip} at the perimeter firewall - confirmed "
                f"{', '.join(sorted(detected_set)) or 'attack'} from "
                f"UNTRUSTED EXTERNAL network."
            )

    # --- 2. Credential rotation for SQLi targeting USER/PASS ---
    if has_tp and has_sqli_creds:
        suggestions.append(
            f"Rotate credentials for any account active between "
            f"{incident.first_seen_display} and {incident.last_seen_display} "
            f"- SQL injection observed targeting the users table (credential "
            f"exfiltration intent)."
        )

    # --- 3. XSS endpoint audit ---
    if has_tp and xss_endpoints:
        ep_list = ", ".join(xss_endpoints[:3])
        suggestions.append(
            f"Audit output encoding on {ep_list} - reflected XSS payload "
            f"observed; ensure user-controlled parameters are HTML-escaped "
            f"on render and add Content-Security-Policy headers."
        )

    # --- 4. Command injection -> host investigation ---
    if "CommandInjection" in detected_set and has_tp:
        suggestions.append(
            "Investigate the targeted host for evidence of code execution "
            "- payload contains shell metacharacters; check new processes, "
            "modified files, outbound connections in the alert time window."
        )

    # --- 5. Open Tier-2 ticket for any confirmed attack ---
    if has_tp:
        suggestions.append(
            f"Open a Tier-2 ticket for incident {incident_short} - confirmed "
            f"{', '.join(sorted(detected_set)) or 'attack'} from {src_ip}; "
            f"include the full reasoning trace from this report."
        )

    # --- 6. Pentest documentation hint (only when external + TP) ---
    if has_tp and facts["is_untrusted_external"]:
        suggestions.append(
            f"If this traffic is from an authorized penetration test, "
            f"document incident {incident_short} in the pentest tracker so "
            f"it can be filtered from operational SLA metrics."
        )

    # --- 7. Suricata tuning for internal-only FP cluster ---
    all_fp_internal = (
        tp_count == 0 and fp_count > 0 and facts["is_internal_only"]
    )
    if all_fp_internal:
        sig_counts = Counter(a.signature for a in incident.alerts if a.signature)
        if sig_counts:
            dominant_sig, _ = sig_counts.most_common(1)[0]
            internal_cidr = next(
                (e["pattern"] for e in (env_entries or [])
                 if e.get("match_type") == "cidr"
                 and e.get("classification_hint") != "untrusted_source_likely_attacker"),
                "the documented internal network",
            )
            suggestions.append(
                f"Tune Suricata to suppress \"{dominant_sig}\" when both src "
                f"and dst are within {internal_cidr} - documented internal "
                f"traffic; all {fp_count} alert(s) classified false_positive."
            )

    return suggestions


def _filter_generic_llm_suggestions(suggestions: List[str]) -> List[str]:
    """Drop LLM-emitted suggestions that begin with known generic starters.

    Not too aggressive - only blocks unambiguously vague verbs (the ones the
    model defaults to when uncertain). Specific suggestions that happen to
    contain "implement" mid-sentence are kept.
    """
    kept: List[str] = []
    for s in suggestions:
        if not isinstance(s, str):
            continue
        if _BANNED_SUGGESTION_STARTERS.match(s):
            log.debug("Dropping generic LLM suggestion: %s", s[:100])
            continue
        kept.append(s)
    return kept


# IP / Docker-bridge / verb patterns used by the enrichment-aware filter
# and the near-duplicate dedup helper below.
_DOCKER_BRIDGE_IP_RE = re.compile(r"\b172\.18\.\d{1,3}\.\d{1,3}\b")
_IPV4_RE = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_VERB_AND_IP_RE = re.compile(
    r"^\s*(\w+)\b.*?\b((?:\d{1,3}\.){3}\d{1,3})\b",
    re.IGNORECASE,
)


def _filter_llm_against_enrichment(
    suggestions: List[str],
    facts: Dict[str, Any],
) -> List[str]:
    """Drop LLM suggestions that contradict the agent's enrichment data.

    Two failure modes observed in smoke testing on qwen2.5:3b:

      A. "Block 172.18.0.2 ..." or "Investigate 172.18.0.2 ..." when
         enrichment marked the source as internal_database. Following
         this advice would break the lab.

      B. "Tune Suricata to suppress <attack signature> ..." when the
         source is UNTRUSTED EXTERNAL. Suppressing signatures from real
         attackers is dangerously wrong (signatures should only be
         suppressed for known-benign internal traffic patterns).

    Both classes of bad suggestions are detectable from the enrichment
    facts alone, so this filter runs deterministically before merge.
    """
    kept: List[str] = []
    for s in suggestions:
        if not isinstance(s, str):
            continue

        s_lower = s.lower()
        s_lead = s.lstrip().lower()

        # Failure mode A: don't block / investigate internal infra.
        if facts.get("is_internal_only"):
            starts_with_action = (
                s_lead.startswith("block ")
                or s_lead.startswith("investigate ")
            )
            mentions_internal_ip = bool(_DOCKER_BRIDGE_IP_RE.search(s))
            if starts_with_action and mentions_internal_ip:
                log.debug(
                    "Dropping LLM suggestion (would target internal infra): %s",
                    s[:100],
                )
                continue

        # Failure mode B: don't suggest suppressing signatures coming
        # from a confirmed adversary network.
        if facts.get("is_untrusted_external"):
            if "suppress" in s_lower and (
                "suricata" in s_lower or "signature" in s_lower or "rule" in s_lower
            ):
                log.debug(
                    "Dropping LLM suggestion (would suppress attack signature "
                    "from untrusted external source): %s",
                    s[:100],
                )
                continue

        kept.append(s)
    return kept


def _dedup_near_duplicates(
    rule_based: List[str],
    llm: List[str],
) -> List[str]:
    """Drop LLM suggestions that share (first verb, first IP) with any
    rule-based suggestion.

    Example: rule-based emits "Block 192.168.56.1 at the perimeter firewall
    - ...". LLM emits "Block 192.168.56.1 at the WAF - ...". Both share
    (Block, 192.168.56.1) - the LLM one is dropped as a near-duplicate.

    LLM suggestions that share a verb but a different IP, or a different
    verb against the same IP, are kept (different recommendation).
    """
    rb_keys: set = set()
    for s in rule_based:
        if not isinstance(s, str):
            continue
        m = _VERB_AND_IP_RE.match(s)
        if m:
            rb_keys.add((m.group(1).lower(), m.group(2)))

    kept: List[str] = []
    for s in llm:
        if not isinstance(s, str):
            kept.append(s)
            continue
        m = _VERB_AND_IP_RE.match(s)
        if m and (m.group(1).lower(), m.group(2)) in rb_keys:
            log.debug(
                "Dropping LLM near-duplicate (verb=%s, ip=%s): %s",
                m.group(1), m.group(2), s[:100],
            )
            continue
        kept.append(s)
    return kept


def _merge_suggestions(
    rule_based: List[str],
    llm: List[str],
    max_total: int = 8,
) -> List[str]:
    """Merge rule-based + LLM suggestions, rule-based first, dedup'd by
    exact string, capped at max_total entries."""
    out: List[str] = []
    seen: set = set()
    for s in list(rule_based) + list(llm):
        if not isinstance(s, str):
            continue
        s_norm = s.strip()
        if not s_norm or s_norm in seen:
            continue
        seen.add(s_norm)
        out.append(s_norm)
        if len(out) >= max_total:
            break
    return out
