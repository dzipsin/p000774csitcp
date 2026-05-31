"""
report_db.py - SQLite-backed persistence for IncidentReports.

The single storage backend for the dashboard, evaluation harness, and agent
history tools. Exposes `save`, `list_reports`, `load_raw`, `clear_all` for
the core CRUD path and extra query methods (`list_by_source_ip`,
`list_by_attack_type`, `list_by_severity`, `aggregate_stats`,
`cleanup_expired`) for cross-run history features.

Design decisions (locked in docs/HANDOFF.md):
  - Hybrid schema: indexed columns for the fields commonly filtered or
    sorted on (incident_id PK, source_ip, status, severity,
    generated_at, repeat_offender) PLUS a `full_report_json` blob with
    the entire template_v1 payload. Cheap reads for the dashboard's
    "show full report" case, fast filtered queries for cross-run views.
  - NO migration from existing JSON files. Fresh database on first run.
  - Thread-safe via `threading.local` connection cache. Each thread
    gets its own SQLite connection with WAL mode + foreign keys enabled.
  - Optional retention sweeper drops incidents older than
    `retention_days` (0 = never expire).

Threading model:
  - All writes are short transactions. SQLite WAL handles concurrent
    writers from multiple threads correctly.
  - Reads are non-blocking under WAL.
  - The thread-local connection cache means worker threads don't
    re-open connections per call.

Schema bootstrap is idempotent — running on an existing DB is a no-op.

Depends on:
    stdlib only (sqlite3, threading, json, contextlib)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from models import IncidentReport

try:
    from report_serializer import to_template_v1, validate_template_v1
    _TEMPLATE_SERIALIZER_AVAILABLE = True
except ImportError:  # pragma: no cover — defensive only
    _TEMPLATE_SERIALIZER_AVAILABLE = False

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = 1

# Note on choice of indexed columns: each represents a filter or sort that
# the dashboard / API / evaluation harness actually performs. Adding more
# (e.g. detected_attacks as a side table) is straightforward later if a
# new query pattern emerges.
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL PRIMARY KEY
);

INSERT OR IGNORE INTO schema_version (version) VALUES ({version});

CREATE TABLE IF NOT EXISTS incidents (
    incident_id        TEXT    PRIMARY KEY,
    source_ip          TEXT    NOT NULL,
    status             TEXT    NOT NULL,
    overall_severity   TEXT    NOT NULL,
    overall_cvss       REAL    NOT NULL,
    repeat_offender    INTEGER NOT NULL,
    total_alerts       INTEGER NOT NULL,
    detected_attacks   TEXT    NOT NULL,         -- JSON array of strings
    generated_at       TEXT    NOT NULL,         -- ISO-8601 UTC
    last_updated_at    TEXT    NOT NULL,
    first_seen         TEXT,
    last_seen          TEXT,
    report_version     TEXT,
    classification_counts TEXT NOT NULL,         -- JSON object
    model_used         TEXT,
    provider_type      TEXT,
    generation_status  TEXT,
    full_report_json   TEXT    NOT NULL          -- entire template_v1 payload
);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip   ON incidents(source_ip);
CREATE INDEX IF NOT EXISTS idx_incidents_status      ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_generated   ON incidents(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_severity    ON incidents(overall_severity);
CREATE INDEX IF NOT EXISTS idx_incidents_repeat      ON incidents(repeat_offender);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id        TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    src_ip          TEXT,
    signature       TEXT,
    signature_id    INTEGER,
    timestamp       TEXT,
    attack_type     TEXT,
    classification  TEXT,
    severity        TEXT,
    PRIMARY KEY (alert_id, incident_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alerts_src_ip      ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_attack_type ON alerts(attack_type);
CREATE INDEX IF NOT EXISTS idx_alerts_signature   ON alerts(signature_id);
""".strip().format(version=_SCHEMA_VERSION)


# ---------------------------------------------------------------------------
# ReportDatabase
# ---------------------------------------------------------------------------

class ReportDatabase:
    """SQLite-backed storage for IncidentReports.

    Core CRUD methods:
        save(report)       -> Optional[Path]    (returns db_path on success)
        list_reports()     -> List[dict]
        load_raw(id)       -> Optional[dict]
        clear_all()        -> int               (rows deleted)

    Additional query methods:
        list_by_source_ip(ip, since_epoch=None) -> List[dict]
        list_by_attack_type(at, since_epoch=None) -> List[dict]
        list_by_severity(sev) -> List[dict]
        aggregate_stats(since_epoch=None) -> dict
        cleanup_expired(retention_days) -> int
    """

    def __init__(
        self,
        db_path: str = "data/reports.db",
        retention_days: int = 90,
    ) -> None:
        self._db_path = Path(db_path).expanduser().resolve()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._retention_days = max(0, int(retention_days))
        # Per-thread connection cache. SQLite connections are not safe to
        # share across threads by default; each thread gets its own and
        # we close them on shutdown via the connection objects' own lifetime.
        self._tls = threading.local()
        # Retention sweeper thread state (started via start_retention_sweeper).
        self._sweeper_thread: Optional[threading.Thread] = None
        self._sweeper_stop = threading.Event()
        # Bootstrap schema on the main thread before any worker can race.
        self._bootstrap_schema()
        log.info(
            "ReportDatabase ready at %s (retention=%d days)",
            self._db_path, self._retention_days,
        )

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        conn = getattr(self._tls, "conn", None)
        if conn is not None:
            return conn

        conn = sqlite3.connect(
            str(self._db_path),
            isolation_level=None,           # autocommit; we'll use explicit BEGIN/COMMIT
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = sqlite3.Row
        # WAL: concurrent readers + a single writer at a time, no blocking
        # for the dashboard reads while reports are being saved.
        conn.execute("PRAGMA journal_mode=WAL;")
        # Required for ON DELETE CASCADE on the alerts table.
        conn.execute("PRAGMA foreign_keys=ON;")
        # Reasonable durability for a demo workload; flushes after each commit.
        conn.execute("PRAGMA synchronous=NORMAL;")
        self._tls.conn = conn
        return conn

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
        conn = self._connection()
        conn.execute("BEGIN;")
        try:
            yield conn
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
            raise

    def _bootstrap_schema(self) -> None:
        """Run the schema DDL. Idempotent — safe to invoke on an existing DB."""
        conn = self._connection()
        # executescript() runs multiple statements without explicit BEGIN.
        # We don't wrap in a transaction; CREATE TABLE IF NOT EXISTS is
        # idempotent and concurrent bootstraps from different processes
        # don't corrupt anything.
        conn.executescript(_SCHEMA_SQL)
        log.debug("Schema v%d bootstrapped at %s", _SCHEMA_VERSION, self._db_path)

    # ------------------------------------------------------------------
    # Core CRUD
    # ------------------------------------------------------------------

    @property
    def directory(self) -> Path:
        """The directory containing the SQLite file. Kept so log lines that
        want to print "storage at X" stay one-liners."""
        return self._db_path.parent

    def save(self, report: IncidentReport) -> Optional[Path]:
        """Upsert a report. Newer reports for the same incident_id replace
        older ones — `save()` is also the in-place update path used when an
        incident is regenerated.

        Returns the database path on success, None on failure. Errors are
        logged but not raised so the pipeline survives a transient DB error.
        """
        try:
            payload = (
                to_template_v1(report)
                if _TEMPLATE_SERIALIZER_AVAILABLE
                else _asdict_fallback(report)
            )
            if _TEMPLATE_SERIALIZER_AVAILABLE:
                try:
                    validate_template_v1(payload)
                except Exception as ve:  # noqa: BLE001 — log + write anyway
                    log.warning(
                        "Template v1 schema validation failed for incident %s: %s",
                        report.incident_summary.incident_id, ve,
                    )

            summary = payload.get("incident_summary", {}) or {}
            incident_id = summary.get("incident_id", "")
            if not incident_id:
                log.error("Cannot save report with empty incident_id")
                return None

            with self._txn() as conn:
                # Upsert the incident row
                conn.execute(
                    """
                    INSERT INTO incidents (
                        incident_id, source_ip, status, overall_severity,
                        overall_cvss, repeat_offender, total_alerts,
                        detected_attacks, generated_at, last_updated_at,
                        first_seen, last_seen, report_version,
                        classification_counts, model_used, provider_type,
                        generation_status, full_report_json
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    ON CONFLICT(incident_id) DO UPDATE SET
                        source_ip           = excluded.source_ip,
                        status              = excluded.status,
                        overall_severity    = excluded.overall_severity,
                        overall_cvss        = excluded.overall_cvss,
                        repeat_offender     = excluded.repeat_offender,
                        total_alerts        = excluded.total_alerts,
                        detected_attacks    = excluded.detected_attacks,
                        generated_at        = excluded.generated_at,
                        last_updated_at     = excluded.last_updated_at,
                        first_seen          = excluded.first_seen,
                        last_seen           = excluded.last_seen,
                        report_version      = excluded.report_version,
                        classification_counts = excluded.classification_counts,
                        model_used          = excluded.model_used,
                        provider_type       = excluded.provider_type,
                        generation_status   = excluded.generation_status,
                        full_report_json    = excluded.full_report_json
                    """,
                    (
                        incident_id,
                        str(summary.get("source_ip", "")),
                        str(summary.get("incident_status", "open")),
                        str(summary.get("overall_severity", "low")),
                        float(summary.get("overall_cvss_estimate", 0.0) or 0.0),
                        1 if summary.get("repeat_offender") else 0,
                        int(summary.get("total_alerts", 0) or 0),
                        json.dumps(list(summary.get("detected_attacks", []) or [])),
                        str(summary.get("generated_at", "")),
                        str(summary.get("last_updated_at", "")),
                        str(summary.get("first_seen", "") or ""),
                        str(summary.get("last_seen", "") or ""),
                        str(summary.get("report_version", "") or ""),
                        json.dumps(dict(summary.get("classification_counts", {}) or {})),
                        str(payload.get("model_used", "") or ""),
                        str(payload.get("provider_type", "") or ""),
                        str(payload.get("generation_status", "") or ""),
                        json.dumps(payload, ensure_ascii=False, default=str),
                    ),
                )

                # Refresh the alerts table for this incident. Simplest correct
                # approach: delete + reinsert. Alerts list is bounded (<100
                # per incident typically) so this is cheap and avoids stale
                # rows when the incident is regenerated with a smaller set.
                conn.execute(
                    "DELETE FROM alerts WHERE incident_id = ?;",
                    (incident_id,),
                )
                analyses = {
                    a.get("alert_id"): a
                    for a in payload.get("alert_analyses", []) or []
                    if isinstance(a, dict) and a.get("alert_id")
                }
                for raw_alert in payload.get("alerts", []) or []:
                    if not isinstance(raw_alert, dict):
                        continue
                    aid = str(raw_alert.get("alert_id", "") or "")
                    if not aid:
                        continue
                    analysis = analyses.get(aid, {})
                    try:
                        sig_id = int(raw_alert.get("suricata_rule_id", 0) or 0)
                    except (TypeError, ValueError):
                        sig_id = 0
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO alerts (
                            alert_id, incident_id, src_ip, signature,
                            signature_id, timestamp, attack_type,
                            classification, severity
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """,
                        (
                            aid,
                            incident_id,
                            str(raw_alert.get("source_ip", "") or ""),
                            str(raw_alert.get("alert_msg", "") or ""),
                            sig_id,
                            str(raw_alert.get("event_timestamp", "") or ""),
                            str(analysis.get("attack_type_classified", "") or ""),
                            str(analysis.get("classification", "") or ""),
                            str(analysis.get("severity", "") or ""),
                        ),
                    )

            log.info(
                "Report saved: incident=%s, version=%s (model=%s, status=%s)",
                incident_id[:8],
                summary.get("report_version", "?"),
                payload.get("model_used", "?"),
                payload.get("generation_status", "?"),
            )
            return self._db_path

        except Exception as e:  # noqa: BLE001 — defensive boundary
            log.exception(
                "Failed to save report for incident %s: %s",
                getattr(getattr(report, "incident_summary", None), "incident_id", "?"), e,
            )
            return None

    def list_reports(self) -> List[dict]:
        """Return all stored reports as full template_v1 dicts, newest first.

        Consumed by the evaluation harness, the dashboard cache rebuilder,
        and the get_alert_history agent tool.
        """
        try:
            conn = self._connection()
            rows = conn.execute(
                """
                SELECT full_report_json FROM incidents
                ORDER BY generated_at DESC;
                """
            ).fetchall()
            out: List[dict] = []
            for row in rows:
                try:
                    out.append(json.loads(row["full_report_json"]))
                except (TypeError, ValueError, json.JSONDecodeError) as e:
                    log.warning("Skipping unparseable stored report: %s", e)
            return out
        except sqlite3.Error as e:
            log.error("list_reports failed: %s", e)
            return []

    def load_raw(self, incident_id: str) -> Optional[dict]:
        """Look up a single report by incident_id."""
        try:
            conn = self._connection()
            row = conn.execute(
                "SELECT full_report_json FROM incidents WHERE incident_id = ?;",
                (incident_id,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(row["full_report_json"])
        except (sqlite3.Error, json.JSONDecodeError) as e:
            log.error("load_raw(%s) failed: %s", incident_id, e)
            return None

    def clear_all(self) -> int:
        """Delete every incident (and via cascade, every alert).

        Returns the count of incidents removed. Backs the operator-triggered
        "Clear Incidents" button on the dashboard.
        """
        try:
            with self._txn() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM incidents;"
                ).fetchone()
                count = int(row["n"] if row else 0)
                conn.execute("DELETE FROM incidents;")
                # Alerts go via FK cascade. Vacuum is overkill for the demo.
            log.info("Cleared %d incident(s)", count)
            return count
        except sqlite3.Error as e:
            log.error("clear_all failed: %s", e)
            return 0

    # ------------------------------------------------------------------
    # New query methods (Phase 10 feature additions)
    # ------------------------------------------------------------------

    def list_by_source_ip(
        self, source_ip: str, since_epoch: Optional[float] = None,
    ) -> List[dict]:
        """All incidents from a given source IP, newest first. Optionally
        bounded by `since_epoch` (POSIX seconds — incidents with
        generated_at parsed to before this point are excluded)."""
        try:
            conn = self._connection()
            if since_epoch is None:
                rows = conn.execute(
                    """
                    SELECT full_report_json FROM incidents
                    WHERE source_ip = ?
                    ORDER BY generated_at DESC;
                    """,
                    (source_ip,),
                ).fetchall()
            else:
                since_iso = datetime.fromtimestamp(
                    since_epoch, tz=timezone.utc,
                ).isoformat()
                rows = conn.execute(
                    """
                    SELECT full_report_json FROM incidents
                    WHERE source_ip = ? AND generated_at >= ?
                    ORDER BY generated_at DESC;
                    """,
                    (source_ip, since_iso),
                ).fetchall()
            return [json.loads(r["full_report_json"]) for r in rows]
        except (sqlite3.Error, json.JSONDecodeError) as e:
            log.error("list_by_source_ip(%s) failed: %s", source_ip, e)
            return []

    def list_by_attack_type(
        self, attack_type: str, since_epoch: Optional[float] = None,
    ) -> List[dict]:
        """All incidents whose `detected_attacks` includes the given type."""
        try:
            conn = self._connection()
            # detected_attacks is stored as a JSON array. SQLite's json_each
            # would be cleaner but isn't universally available; use LIKE on
            # the JSON-quoted form which is good enough for the demo.
            like_pattern = f'%"{attack_type}"%'
            if since_epoch is None:
                rows = conn.execute(
                    """
                    SELECT full_report_json FROM incidents
                    WHERE detected_attacks LIKE ?
                    ORDER BY generated_at DESC;
                    """,
                    (like_pattern,),
                ).fetchall()
            else:
                since_iso = datetime.fromtimestamp(
                    since_epoch, tz=timezone.utc,
                ).isoformat()
                rows = conn.execute(
                    """
                    SELECT full_report_json FROM incidents
                    WHERE detected_attacks LIKE ? AND generated_at >= ?
                    ORDER BY generated_at DESC;
                    """,
                    (like_pattern, since_iso),
                ).fetchall()
            return [json.loads(r["full_report_json"]) for r in rows]
        except (sqlite3.Error, json.JSONDecodeError) as e:
            log.error("list_by_attack_type(%s) failed: %s", attack_type, e)
            return []

    def list_by_severity(self, severity: str) -> List[dict]:
        try:
            conn = self._connection()
            rows = conn.execute(
                """
                SELECT full_report_json FROM incidents
                WHERE overall_severity = ?
                ORDER BY generated_at DESC;
                """,
                (severity,),
            ).fetchall()
            return [json.loads(r["full_report_json"]) for r in rows]
        except (sqlite3.Error, json.JSONDecodeError) as e:
            log.error("list_by_severity(%s) failed: %s", severity, e)
            return []

    def aggregate_stats(
        self, since_epoch: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Counts grouped by status / severity / attack-type within an
        optional time window."""
        try:
            conn = self._connection()
            params: List[Any] = []
            where = ""
            if since_epoch is not None:
                since_iso = datetime.fromtimestamp(
                    since_epoch, tz=timezone.utc,
                ).isoformat()
                where = " WHERE generated_at >= ?"
                params = [since_iso]

            total = conn.execute(
                f"SELECT COUNT(*) AS n FROM incidents{where};",
                params,
            ).fetchone()["n"]

            by_status = {
                r["status"]: r["n"]
                for r in conn.execute(
                    f"SELECT status, COUNT(*) AS n FROM incidents{where} "
                    f"GROUP BY status;",
                    params,
                ).fetchall()
            }
            by_severity = {
                r["overall_severity"]: r["n"]
                for r in conn.execute(
                    f"SELECT overall_severity, COUNT(*) AS n FROM incidents{where} "
                    f"GROUP BY overall_severity;",
                    params,
                ).fetchall()
            }
            # detected_attacks is a JSON column — aggregate by reading then
            # tallying in Python. Cheap for demo volumes.
            attack_counter: Dict[str, int] = {}
            for r in conn.execute(
                f"SELECT detected_attacks FROM incidents{where};",
                params,
            ).fetchall():
                try:
                    attacks = json.loads(r["detected_attacks"])
                    for a in attacks or []:
                        attack_counter[a] = attack_counter.get(a, 0) + 1
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue

            repeat_offenders = conn.execute(
                f"SELECT COUNT(*) AS n FROM incidents{where + (' AND' if where else ' WHERE')} repeat_offender = 1;",
                params,
            ).fetchone()["n"]

            return {
                "total_incidents":   int(total),
                "by_status":         by_status,
                "by_severity":       by_severity,
                "by_attack_type":    dict(attack_counter),
                "repeat_offenders":  int(repeat_offenders),
                "since_epoch":       since_epoch,
            }
        except sqlite3.Error as e:
            log.error("aggregate_stats failed: %s", e)
            return {}

    # ------------------------------------------------------------------
    # Background retention sweeper
    # ------------------------------------------------------------------

    def start_retention_sweeper(self, interval_seconds: float) -> None:
        """Start a background thread that calls cleanup_expired periodically.

        Idempotent — calling twice is a no-op while the thread is alive.
        Set interval_seconds <= 0 OR retention_days = 0 to skip starting.
        """
        if interval_seconds <= 0 or self._retention_days <= 0:
            log.info(
                "Retention sweeper disabled (interval=%.0fs, retention=%d days)",
                interval_seconds, self._retention_days,
            )
            return
        if self._sweeper_thread is not None and self._sweeper_thread.is_alive():
            return

        self._sweeper_stop.clear()

        def _loop():
            log.info(
                "Retention sweeper started (interval=%.0fs, retention=%d days)",
                interval_seconds, self._retention_days,
            )
            # First pass at startup — clear anything already past its window.
            try:
                self.cleanup_expired()
            except Exception as e:  # noqa: BLE001 — sweeper must not crash
                log.exception("Initial retention sweep raised: %s", e)
            while not self._sweeper_stop.is_set():
                # wait() with timeout = sleep that can be cancelled cleanly
                if self._sweeper_stop.wait(timeout=interval_seconds):
                    break
                try:
                    self.cleanup_expired()
                except Exception as e:  # noqa: BLE001
                    log.exception("Retention sweep raised: %s", e)
            log.info("Retention sweeper stopped")

        self._sweeper_thread = threading.Thread(
            target=_loop, name="report-db-retention", daemon=True,
        )
        self._sweeper_thread.start()

    def stop_retention_sweeper(self, timeout: float = 2.0) -> None:
        """Signal the sweeper to exit and wait briefly for it to do so."""
        self._sweeper_stop.set()
        thread = self._sweeper_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        self._sweeper_thread = None

    def cleanup_expired(self, retention_days: Optional[int] = None) -> int:
        """Delete incidents older than retention_days. 0 = never expire.

        Returns the count of incidents deleted.
        """
        days = retention_days if retention_days is not None else self._retention_days
        if days <= 0:
            return 0
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_iso = cutoff.isoformat()
            with self._txn() as conn:
                row = conn.execute(
                    "SELECT COUNT(*) AS n FROM incidents WHERE generated_at < ?;",
                    (cutoff_iso,),
                ).fetchone()
                count = int(row["n"] if row else 0)
                conn.execute(
                    "DELETE FROM incidents WHERE generated_at < ?;",
                    (cutoff_iso,),
                )
            if count:
                log.info(
                    "Retention cleanup: dropped %d incident(s) older than %d days",
                    count, days,
                )
            return count
        except sqlite3.Error as e:
            log.error("cleanup_expired failed: %s", e)
            return 0


# ---------------------------------------------------------------------------
# Fallback serializer for environments without report_serializer
# ---------------------------------------------------------------------------

def _asdict_fallback(report: IncidentReport) -> Dict[str, Any]:
    """Build a minimal dict from the dataclass if report_serializer can't be
    imported. This is a defensive path; in normal operation the serializer
    is always available."""
    from dataclasses import asdict
    data = asdict(report)
    return data
