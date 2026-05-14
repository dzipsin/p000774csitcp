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

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

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
