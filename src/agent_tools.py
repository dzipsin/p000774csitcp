"""
agent_tools.py - Tool implementations for the ReAct triage agent.

Each tool is exposed via a factory function that captures the application
state it needs (IncidentManager, ReportStorage, configuration) in a closure
and returns a ToolDefinition ready for registration with the ToolRegistry.

Tools are pure read functions. They never mutate state. They never make
external network calls. All data comes from existing app structures
(in-memory incidents + persisted JSON reports + config).

Public surface:
    make_alert_history_tool(incident_manager, storage) -> ToolDefinition
    make_environment_lookup_tool(env_entries)         -> ToolDefinition  (Phase 2 step 3)
    make_pattern_stats_tool(incident_manager, storage) -> ToolDefinition  (Phase 2 step 4)
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from log_monitor import AlertRecord  # for type clarity
from models import extract_attack_type
from tool_registry import ToolDefinition

log = logging.getLogger(__name__)


# ===========================================================================
# Tool 1: get_alert_history
# ===========================================================================

_ALERT_HISTORY_DESCRIPTION = (
    "Look up prior alerts from a specific source IP within a time window. "
    "Use this when you need to determine if the source IP is a repeat "
    "offender or part of a sustained attack campaign. Returns aggregate "
    "counts, attack types observed, and the time bounds of activity."
)

_ALERT_HISTORY_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "src_ip": {
            "type": "string",
            "description": (
                "The source IP address to look up (e.g. '192.168.56.1'). "
                "Must be the IP from the alert you are classifying."
            ),
        },
        "hours": {
            "type": "integer",
            "description": (
                "Lookback window in hours. Default 24. Maximum 168 (1 week)."
            ),
            "default": 24,
            "minimum": 1,
            "maximum": 168,
        },
    },
    "required": ["src_ip"],
}


def _aggregate_alert_history(
    src_ip: str,
    hours: int,
    incident_manager: Any,
    storage: Any,
) -> Dict[str, Any]:
    """Compute the alert_history aggregate for a source IP.

    Combines in-memory alerts (open + recently-closed incidents) with
    persisted reports on disk, deduping by incident_id so an incident
    that is both in memory and persisted is counted once.
    """
    now = time.time()
    since = now - (hours * 3600.0)

    # --- In-memory alerts (open + recently-closed incidents) ---
    in_memory_alerts: List[AlertRecord] = incident_manager.get_alerts_for_ip(
        source_ip=src_ip,
        since_epoch=since,
    )
    in_memory_incident_count = incident_manager.get_incident_count_for_ip(src_ip)

    # Track incident IDs in memory so we don't double-count when reading disk
    in_memory_incident_ids = {
        inc.incident_id
        for inc in incident_manager.get_open_incidents()
        if inc.source_ip == src_ip
    }
    # _recently_closed isn't surfaced via a public iterator, but get_alerts_for_ip
    # already aggregated those alerts; dedup at the incident level is best-effort.
    # The risk of mild double-counting is acceptable for this tool's purpose.

    # --- Disk alerts (persisted reports), excluding in-memory incidents ---
    disk_alert_records: List[Dict[str, Any]] = []
    disk_incident_count = 0
    try:
        for report in storage.list_reports():
            summary = report.get("incident_summary", {}) or {}
            if summary.get("source_ip") != src_ip:
                continue
            incident_id = summary.get("incident_id", "")
            if incident_id and incident_id in in_memory_incident_ids:
                continue  # already counted in memory
            disk_incident_count += 1
            for raw in report.get("alerts", []) or []:
                try:
                    ts = float(raw.get("timestamp_epoch", 0) or 0)
                except (TypeError, ValueError):
                    ts = 0.0
                if ts <= 0 or ts < since:
                    continue
                disk_alert_records.append({
                    "timestamp_epoch": ts,
                    "signature": str(raw.get("signature", "")),
                })
    except Exception as e:  # noqa: BLE001 — defensive boundary; tool must not raise
        log.warning("get_alert_history: disk read failed: %s", e)

    # --- Aggregate ---
    timestamps: List[float] = []
    attack_types: set = set()

    for a in in_memory_alerts:
        if a.timestamp_epoch > 0:
            timestamps.append(a.timestamp_epoch)
        atype = extract_attack_type(a.signature)
        if atype != "Other":
            attack_types.add(atype)

    for d in disk_alert_records:
        ts = d["timestamp_epoch"]
        if ts > 0:
            timestamps.append(ts)
        atype = extract_attack_type(d["signature"])
        if atype != "Other":
            attack_types.add(atype)

    total_alerts = len(in_memory_alerts) + len(disk_alert_records)

    if total_alerts == 0:
        return {
            "src_ip": src_ip,
            "lookback_hours": hours,
            "total_prior_alerts": 0,
            "attack_types_seen": [],
            "first_seen_iso": None,
            "last_seen_iso": None,
            "prior_incident_count": 0,
            "is_repeat_offender_this_session": bool(
                incident_manager.is_repeat_offender(src_ip)
            ),
        }

    first_iso = (
        datetime.fromtimestamp(min(timestamps), tz=timezone.utc).isoformat()
        if timestamps else None
    )
    last_iso = (
        datetime.fromtimestamp(max(timestamps), tz=timezone.utc).isoformat()
        if timestamps else None
    )

    return {
        "src_ip": src_ip,
        "lookback_hours": hours,
        "total_prior_alerts": total_alerts,
        "attack_types_seen": sorted(attack_types),
        "first_seen_iso": first_iso,
        "last_seen_iso": last_iso,
        "prior_incident_count": in_memory_incident_count + disk_incident_count,
        "is_repeat_offender_this_session": bool(
            incident_manager.is_repeat_offender(src_ip)
        ),
    }


def make_alert_history_tool(
    incident_manager: Any,
    storage: Any,
) -> ToolDefinition:
    """Build the get_alert_history ToolDefinition.

    Args:
        incident_manager: must expose get_alerts_for_ip(), get_open_incidents(),
                          get_incident_count_for_ip(), is_repeat_offender().
        storage:          must expose list_reports() returning a list of report
                          dicts. May be None — in that case disk-side history
                          is skipped silently.
    """
    # Adapter so missing storage doesn't blow up the tool
    class _NullStorage:
        def list_reports(self):
            return []

    storage_or_null = storage if storage is not None else _NullStorage()

    def fn(args: Dict[str, Any]) -> Dict[str, Any]:
        src_ip = args["src_ip"]
        hours = int(args.get("hours", 24))
        return _aggregate_alert_history(
            src_ip=src_ip,
            hours=hours,
            incident_manager=incident_manager,
            storage=storage_or_null,
        )

    return ToolDefinition(
        name="get_alert_history",
        description=_ALERT_HISTORY_DESCRIPTION,
        parameters_schema=_ALERT_HISTORY_SCHEMA,
        function=fn,
    )


# ===========================================================================
# Tool 2: lookup_environment_context
# ===========================================================================

_ENV_LOOKUP_DESCRIPTION = (
    "Look up known facts about an IP address, CIDR, hostname, or URL in "
    "the lab environment. Use this when the alert involves an IP or URL "
    "you are uncertain about, to determine if it is expected internal "
    "infrastructure (which suggests a false positive) or untrusted "
    "external traffic (which is more likely a real attack). Returns "
    "match_found=false if the query is not in the known map."
)

_ENV_LOOKUP_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": (
                "The IP address, CIDR, hostname, or URL path fragment to "
                "look up. Examples: '172.18.0.2', '192.168.56.0/24', "
                "'/vulnerabilities/sqli/'."
            ),
        },
    },
    "required": ["query"],
}

# Supported entry match types — anything else is rejected at compile time.
_VALID_MATCH_TYPES = {"exact_ip", "cidr", "url_prefix", "url_contains"}


def _compile_env_entries(
    raw_entries: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Validate environment entries once, at factory time.

    Bad entries (missing pattern, unknown match_type, malformed CIDR) are
    logged at warning level and skipped — the tool never crashes at runtime
    because of a config error.

    For CIDR entries, the ip_network is pre-compiled and cached on the
    entry so per-query matching is fast.
    """
    compiled: List[Dict[str, Any]] = []

    for i, entry in enumerate(raw_entries):
        pattern = str(entry.get("pattern", "")).strip()
        match_type = str(entry.get("match_type", "")).strip()

        if not pattern:
            log.warning("Environment entry %d: missing pattern; skipping", i)
            continue
        if match_type not in _VALID_MATCH_TYPES:
            log.warning(
                "Environment entry %d (pattern=%r): unknown match_type %r; "
                "skipping. Valid types: %s",
                i, pattern, match_type, sorted(_VALID_MATCH_TYPES),
            )
            continue

        compiled_entry: Dict[str, Any] = {
            "pattern": pattern,
            "match_type": match_type,
            "role": str(entry.get("role", "")),
            "description": str(entry.get("description", "")),
            "classification_hint": str(entry.get("classification_hint", "")),
        }

        if match_type == "cidr":
            try:
                compiled_entry["_network"] = ipaddress.ip_network(
                    pattern, strict=False,
                )
            except (ValueError, TypeError) as e:
                log.warning(
                    "Environment entry %d (pattern=%r): invalid CIDR: %s; "
                    "skipping",
                    i, pattern, e,
                )
                continue

        compiled.append(compiled_entry)

    return compiled


def _env_entry_matches(entry: Dict[str, Any], query: str) -> bool:
    """Test whether a single compiled entry matches the query string."""
    match_type = entry["match_type"]
    pattern = entry["pattern"]

    if match_type == "exact_ip":
        return query == pattern

    if match_type == "cidr":
        net = entry.get("_network")
        if net is None:
            return False
        try:
            return ipaddress.ip_address(query) in net
        except (ValueError, TypeError):
            # Query isn't a parseable IP — not a CIDR match.
            return False

    if match_type == "url_prefix":
        return query.startswith(pattern)

    if match_type == "url_contains":
        return pattern in query

    # Unknown match type was rejected at compile; shouldn't reach here.
    return False


def lookup_environment_for_query(
    env_entries: List[Dict[str, Any]],
    query: str,
) -> Optional[Dict[str, Any]]:
    """Pure-function form of make_environment_lookup_tool.

    Returns the matched entry dict (with role / description /
    classification_hint / matched_pattern / match_type), or None if no
    match. Lets ReportGenerator derive environment facts deterministically
    from a source IP without needing the ReAct tool path to have run —
    so the rule-based suggestion generator and the LLM-suggestion filter
    keep working in single_shot mode and react+no-enrich mode.

    Re-uses the same compile + match helpers as the agent tool so the
    matching semantics stay identical across both code paths.
    """
    if not env_entries or not query:
        return None
    compiled = _compile_env_entries(env_entries)
    q = str(query).strip()
    if not q:
        return None
    for entry in compiled:
        if _env_entry_matches(entry, q):
            return {
                "matched_pattern":    entry["pattern"],
                "match_type":         entry["match_type"],
                "role":               entry.get("role", ""),
                "description":        entry.get("description", ""),
                "classification_hint": entry.get("classification_hint", ""),
            }
    return None


def make_environment_lookup_tool(
    env_entries: List[Dict[str, Any]],
) -> ToolDefinition:
    """Build the lookup_environment_context ToolDefinition.

    Args:
        env_entries: list of entry dicts from app.config under
                     [[agent.environment.entries]]. Each entry should have
                     at minimum 'pattern' and 'match_type' (one of:
                     exact_ip, cidr, url_prefix, url_contains).
                     Optional: 'role', 'description', 'classification_hint'.

                     Bad entries are logged + skipped at factory time. The
                     tool itself always returns a structured response and
                     never raises.
    """
    compiled = _compile_env_entries(env_entries or [])

    if env_entries and not compiled:
        log.warning(
            "Environment lookup tool: all %d configured entries were "
            "rejected. Tool will always return match_found=false.",
            len(env_entries),
        )

    def fn(args: Dict[str, Any]) -> Dict[str, Any]:
        query = str(args["query"]).strip()
        if not query:
            return {
                "query": query,
                "match_found": False,
                "reason": "empty query",
            }

        for entry in compiled:
            if _env_entry_matches(entry, query):
                return {
                    "query": query,
                    "match_found": True,
                    "matched_pattern": entry["pattern"],
                    "match_type": entry["match_type"],
                    "role": entry["role"],
                    "description": entry["description"],
                    "classification_hint": entry["classification_hint"],
                }

        return {"query": query, "match_found": False}

    return ToolDefinition(
        name="lookup_environment_context",
        description=_ENV_LOOKUP_DESCRIPTION,
        parameters_schema=_ENV_LOOKUP_SCHEMA,
        function=fn,
    )


# ===========================================================================
# Tool 3: get_attack_pattern_stats
# ===========================================================================

_PATTERN_STATS_DESCRIPTION = (
    "Get aggregate statistics for a specific attack type over a recent "
    "time window. Use this when you want to gauge whether an attack type "
    "is currently active in the environment, which helps calibrate "
    "severity. Returns alert volume, unique source IPs, incident count, "
    "and (when classification history is available on disk) the observed "
    "true-positive rate."
)

# Must match the enum used by extract_attack_type() in models.py.
_VALID_ATTACK_TYPES = [
    "SQLi",
    "XSS",
    "CommandInjection",
    "PathTraversal",
    "CSRF",
    "FileInclusion",
    "BruteForce",
    "Reconnaissance",
    "WebAttack",
]

_PATTERN_STATS_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "attack_type": {
            "type": "string",
            "description": (
                "The attack type label to aggregate over. Must match the "
                "extract_attack_type() taxonomy."
            ),
            "enum": _VALID_ATTACK_TYPES,
        },
        "hours": {
            "type": "integer",
            "description": (
                "Lookback window in hours. Default 24. Maximum 168 (1 week)."
            ),
            "default": 24,
            "minimum": 1,
            "maximum": 168,
        },
    },
    "required": ["attack_type"],
}


def _aggregate_pattern_stats(
    attack_type: str,
    hours: int,
    incident_manager: Any,
    storage: Any,
) -> Dict[str, Any]:
    """Aggregate volume + classification stats for one attack type.

    Combines in-memory incidents with persisted disk reports. Deduplicates
    by incident_id so an incident persisted to disk while still in memory
    is counted once.

    true_positive_rate is computed only from disk-side classifications
    (in-memory alerts have not yet been classified). Documented circularity:
    the rate reflects past LLM verdicts, not ground truth. Useful as
    relative signal, not absolute accuracy.
    """
    now = time.time()
    since = now - (hours * 3600.0)

    total_alerts = 0
    unique_ips: set = set()
    incident_ids_seen: set = set()
    most_recent_ts = 0.0

    classified_total = 0
    tp_total = 0

    # --- In-memory side ---
    in_memory_incidents = incident_manager.get_all_incidents()
    for incident in in_memory_incidents:
        for alert in incident.alerts:
            if extract_attack_type(alert.signature) != attack_type:
                continue
            ts = alert.timestamp_epoch
            if ts <= 0 or ts < since:
                continue
            total_alerts += 1
            unique_ips.add(alert.src_ip)
            incident_ids_seen.add(incident.incident_id)
            if ts > most_recent_ts:
                most_recent_ts = ts

    # --- Disk side, dedup'd by incident_id ---
    try:
        for report in storage.list_reports():
            summary = report.get("incident_summary", {}) or {}
            incident_id = summary.get("incident_id", "")

            disk_alerts = report.get("alerts", []) or []
            disk_analyses = report.get("alert_analyses", []) or []

            # If we already counted this incident in memory, skip its alerts
            # but still inspect analyses for TPR (analyses persist whether
            # or not the incident is still in memory).
            already_in_memory = incident_id in incident_ids_seen

            for i, raw_alert in enumerate(disk_alerts):
                sig = str(raw_alert.get("signature", ""))
                if extract_attack_type(sig) != attack_type:
                    continue
                try:
                    ts = float(raw_alert.get("timestamp_epoch", 0) or 0)
                except (TypeError, ValueError):
                    ts = 0.0
                if ts <= 0 or ts < since:
                    continue

                # Volume metrics only count once
                if not already_in_memory:
                    total_alerts += 1
                    unique_ips.add(str(raw_alert.get("src_ip", "")))
                    incident_ids_seen.add(incident_id)
                    if ts > most_recent_ts:
                        most_recent_ts = ts

                # Classification metrics always count (disk-only signal)
                if i < len(disk_analyses):
                    cls = str(disk_analyses[i].get("classification", ""))
                    if cls in ("true_positive", "likely_false_positive"):
                        classified_total += 1
                        if cls == "true_positive":
                            tp_total += 1
    except Exception as e:  # noqa: BLE001 — defensive boundary
        log.warning("get_attack_pattern_stats: disk read failed: %s", e)

    out: Dict[str, Any] = {
        "attack_type": attack_type,
        "lookback_hours": hours,
        "total_alerts": total_alerts,
        "unique_source_ips": len(unique_ips),
        "incident_count": len(incident_ids_seen),
        "most_recent_alert_iso": (
            datetime.fromtimestamp(most_recent_ts, tz=timezone.utc).isoformat()
            if most_recent_ts > 0 else None
        ),
    }

    # Only emit observed_true_positive_rate when we have classified data on
    # disk to compute from. On fresh runs (or single-shot evaluation runs
    # with no disk history) the field would otherwise be a noisy `null`
    # in every report.
    if classified_total > 0:
        out["observed_true_positive_rate"] = round(tp_total / classified_total, 3)

    return out


def make_pattern_stats_tool(
    incident_manager: Any,
    storage: Any,
) -> ToolDefinition:
    """Build the get_attack_pattern_stats ToolDefinition.

    Args:
        incident_manager: must expose get_all_incidents() returning a list
                          of Incident objects (open + recently-closed).
        storage:          must expose list_reports(). May be None — in that
                          case observed_true_positive_rate is always None
                          and disk-side counts are skipped.
    """
    class _NullStorage:
        def list_reports(self):
            return []

    storage_or_null = storage if storage is not None else _NullStorage()

    def fn(args: Dict[str, Any]) -> Dict[str, Any]:
        return _aggregate_pattern_stats(
            attack_type=args["attack_type"],
            hours=int(args.get("hours", 24)),
            incident_manager=incident_manager,
            storage=storage_or_null,
        )

    return ToolDefinition(
        name="get_attack_pattern_stats",
        description=_PATTERN_STATS_DESCRIPTION,
        parameters_schema=_PATTERN_STATS_SCHEMA,
        function=fn,
    )
