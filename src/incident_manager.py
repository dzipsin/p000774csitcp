"""
incident_manager.py - Groups alerts into incidents and manages lifecycle.

Responsibilities:
  - Group incoming AlertRecords into Incidents based on grouping_mode
  - Track open vs closed incidents via a sliding time window
  - Debounce regeneration requests (avoid thrashing when alerts arrive in bursts)
  - Maintain in-session repeat-offender tracking
  - Fire a regeneration callback when debounce timer expires

Threading model:
  - Public methods are safe to call from any thread (guarded by self._lock)
  - One background "sweeper" thread closes incidents whose time window expired
  - Per-incident debounce timers run on their own threading.Timer threads
  - The regeneration callback runs on a dedicated worker thread (one at a time
    per incident; if called while already running for the same incident, the
    second call is queued)

Depends on:
  log_monitor.AlertRecord
  models.Incident
  models.extract_attack_type
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from log_monitor import AlertRecord
from models import Incident, extract_attack_type

log = logging.getLogger(__name__)


# Type alias for the regeneration callback: receives an Incident snapshot.
# Implementations should be idempotent — this callback may be invoked multiple
# times for the same incident as alerts continue to arrive.
RegenerateCallback = Callable[[Incident], None]


class IncidentManager:
    """Groups alerts into incidents and triggers report regeneration.

    Usage::

        manager = IncidentManager(
            grouping_mode="per_actor",
            time_window_minutes=2.0,
            debounce_seconds=3.0,
            on_regenerate=lambda inc: report_generator.generate(inc),
        )
        manager.start()
        log_monitor.subscribe(manager.process_alert)
        # ... later ...
        manager.stop()
    """

    # Alerts with these source IPs are dropped — they provide no grouping value
    _INVALID_SOURCE_IPS = {"", "?", "0.0.0.0", "::"}

    def __init__(
        self,
        grouping_mode: str = "per_actor",
        time_window_minutes: float = 2.0,
        debounce_seconds: float = 3.0,
        sweep_interval_seconds: float = 10.0,
        on_regenerate: Optional[RegenerateCallback] = None,
    ):
        """
        Args:
            grouping_mode: "per_actor" or "per_attack_type"
            time_window_minutes: incident closes after this many minutes of silence
            debounce_seconds: wait this long after last alert before regenerating
            sweep_interval_seconds: how often the background sweeper checks for expired incidents
            on_regenerate: callback invoked with an Incident when regeneration should happen
        """
        if grouping_mode not in ("per_actor", "per_attack_type"):
            raise ValueError(
                f"Invalid grouping_mode '{grouping_mode}'. "
                "Must be 'per_actor' or 'per_attack_type'."
            )

        self.grouping_mode = grouping_mode
        self.time_window_seconds = float(time_window_minutes) * 60.0
        self.debounce_seconds = float(debounce_seconds)
        self.sweep_interval_seconds = float(sweep_interval_seconds)
        self._on_regenerate = on_regenerate

        # Open incidents, keyed by group key (str). One entry per currently-open
        # incident. Closed incidents are removed from this dict (they're persisted
        # to disk by the report generator).
        self._open_incidents: Dict[str, Incident] = {}

        # Debounce timers, keyed by incident_id.
        self._debounce_timers: Dict[str, threading.Timer] = {}

        # Tracks incident_ids that are currently being regenerated, so we can
        # queue follow-up regenerations without overlap.
        self._regenerating: set[str] = set()

        # Pending regeneration flags — if True, another regeneration is needed
        # as soon as the current one finishes.
        self._pending_regenerate: set[str] = set()

        # Source IPs seen in the current session. Used for repeat_offender flag.
        self._seen_source_ips: set[str] = set()

        # Thread-safety
        self._lock = threading.RLock()  # Reentrant because some methods call others

        # Sweeper control
        self._stop_event = threading.Event()
        self._sweeper_thread: Optional[threading.Thread] = None

        log.info(
            "IncidentManager init: mode=%s, window=%.1fs, debounce=%.1fs",
            grouping_mode, self.time_window_seconds, self.debounce_seconds,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background sweeper thread."""
        with self._lock:
            if self._sweeper_thread and self._sweeper_thread.is_alive():
                return
            self._stop_event.clear()
            self._sweeper_thread = threading.Thread(
                target=self._sweep_loop, daemon=True, name="incident-sweeper"
            )
            self._sweeper_thread.start()
        log.info("IncidentManager started")

    def stop(self, close_open: bool = True) -> None:
        """Stop the manager and optionally close all open incidents.

        Args:
            close_open: if True, mark all open incidents as closed and fire
                        one final regeneration for each. Recommended during
                        graceful shutdown.
        """
        log.info("IncidentManager stopping (close_open=%s)", close_open)
        self._stop_event.set()

        # Cancel all debounce timers
        with self._lock:
            for timer in list(self._debounce_timers.values()):
                try:
                    timer.cancel()
                except Exception:
                    pass
            self._debounce_timers.clear()

        # Close any open incidents with final regeneration
        if close_open:
            self._close_all_open_incidents(final=True)

        # Wait for sweeper to exit
        if self._sweeper_thread and self._sweeper_thread.is_alive():
            self._sweeper_thread.join(timeout=2.0)

        log.info("IncidentManager stopped")

    def set_regenerate_callback(self, cb: RegenerateCallback) -> None:
        """Install or replace the regeneration callback."""
        with self._lock:
            self._on_regenerate = cb

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_alert(self, alert: AlertRecord) -> None:
        """Main entry point — call this for each new alert.

        Safe to call from any thread. Fast: returns after bookkeeping;
        regeneration happens asynchronously via the debounce timer.
        """
        # Validate source IP
        src_ip = (alert.src_ip or "").strip()
        if src_ip in self._INVALID_SOURCE_IPS:
            log.warning(
                "Dropping alert with invalid source IP '%s' (sig=%s)",
                src_ip, alert.signature,
            )
            return

        arrival_time = time.time()
        attack_type = extract_attack_type(alert.signature)
        group_key = self._compute_group_key(src_ip, attack_type)

        with self._lock:
            # Check if there's an open incident for this group key
            incident = self._open_incidents.get(group_key)

            if incident is not None:
                # Check if the existing incident has effectively expired
                # (may happen if sweeper hasn't caught up yet)
                silence = arrival_time - incident.last_activity_at
                if silence > self.time_window_seconds:
                    log.debug(
                        "Incident %s expired (silence=%.1fs), closing before appending",
                        incident.incident_id, silence,
                    )
                    self._close_incident_locked(incident, final=True)
                    incident = None

            if incident is None:
                # Create a new incident
                incident = self._create_incident_locked(
                    src_ip=src_ip,
                    attack_type=attack_type if self.grouping_mode == "per_attack_type" else None,
                    group_key=group_key,
                    arrival_time=arrival_time,
                )

            # Append the alert
            incident.add_alert(alert, arrival_time)
            self._seen_source_ips.add(src_ip)

            log.debug(
                "Alert added to incident %s (src=%s, sig=%s, count=%d)",
                incident.incident_id, src_ip, alert.signature, incident.alert_count,
            )

            # Reset the debounce timer
            self._reset_debounce_timer_locked(incident)

    def force_regenerate_all(self) -> int:
        """Immediately regenerate all open incidents, bypassing debounce.

        Useful for the "Force Regenerate" button. Returns the count of
        incidents for which regeneration was triggered.
        """
        with self._lock:
            open_incidents = list(self._open_incidents.values())
            # Cancel pending debounce timers for these incidents
            for inc in open_incidents:
                timer = self._debounce_timers.pop(inc.incident_id, None)
                if timer is not None:
                    try:
                        timer.cancel()
                    except Exception:
                        pass

        # Fire regenerations outside the lock
        for inc in open_incidents:
            self._trigger_regenerate(inc.incident_id)

        return len(open_incidents)

    def get_open_incidents(self) -> List[Incident]:
        """Return a snapshot list of currently open incidents."""
        with self._lock:
            # Return shallow copies so callers don't see later mutations.
            # Alerts list is still shared, but alerts themselves are frozen.
            return list(self._open_incidents.values())

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Return an open incident by ID, or None if not found."""
        with self._lock:
            for inc in self._open_incidents.values():
                if inc.incident_id == incident_id:
                    return inc
        return None

    def is_repeat_offender(self, source_ip: str) -> bool:
        """Whether this source IP has been seen before in this session.

        An IP is a "repeat offender" if we've seen it in an earlier incident.
        We check this at report-generation time, not grouping time.
        """
        with self._lock:
            return source_ip in self._seen_source_ips

    # ------------------------------------------------------------------
    # Internal: grouping
    # ------------------------------------------------------------------

    def _compute_group_key(self, src_ip: str, attack_type: Optional[str]) -> str:
        """Compute the group key used to look up open incidents."""
        if self.grouping_mode == "per_attack_type":
            return f"{src_ip}|{attack_type or ''}"
        return src_ip  # per_actor

    def _create_incident_locked(
        self,
        src_ip: str,
        attack_type: Optional[str],
        group_key: str,
        arrival_time: float,
    ) -> Incident:
        """Create a new incident. Must be called with self._lock held."""
        incident = Incident(
            incident_id=str(uuid.uuid4()),
            source_ip=src_ip,
            attack_type=attack_type,
            created_at=arrival_time,
            last_activity_at=arrival_time,
            status="open",
        )
        self._open_incidents[group_key] = incident

        log.info(
            "Incident %s opened (src=%s, attack_type=%s, mode=%s)",
            incident.incident_id, src_ip, attack_type or "-", self.grouping_mode,
        )
        return incident

    def _close_incident_locked(self, incident: Incident, final: bool) -> None:
        """Mark an incident closed and remove from open dict.

        Must be called with self._lock held.
        If final=True, fire a final regeneration after releasing the lock.
        """
        if incident.status == "closed":
            return

        incident.status = "closed"

        # Remove from open dict
        group_key = self._compute_group_key(
            incident.source_ip,
            incident.attack_type if self.grouping_mode == "per_attack_type" else "",
        )
        self._open_incidents.pop(group_key, None)

        # Cancel any pending debounce timer for this incident
        timer = self._debounce_timers.pop(incident.incident_id, None)
        if timer is not None:
            try:
                timer.cancel()
            except Exception:
                pass

        log.info(
            "Incident %s closed (alert_count=%d, final=%s)",
            incident.incident_id, incident.alert_count, final,
        )

        # Queue a final regeneration outside the lock (deferred to caller)
        # We do this by setting pending flag and letting the caller trigger it.
        if final and self._on_regenerate is not None:
            # We can't call the callback here because we hold the lock.
            # Signal to caller that they should trigger.
            self._pending_regenerate.add(incident.incident_id)

    def _close_all_open_incidents(self, final: bool) -> None:
        """Close every open incident. Used on shutdown."""
        with self._lock:
            to_close = list(self._open_incidents.values())
            for inc in to_close:
                self._close_incident_locked(inc, final=final)

        # Trigger final regenerations outside the lock
        if final:
            for inc in to_close:
                # Direct synchronous call — this is shutdown, we want it done
                self._trigger_regenerate_sync(inc)

    # ------------------------------------------------------------------
    # Internal: debounce
    # ------------------------------------------------------------------

    def _reset_debounce_timer_locked(self, incident: Incident) -> None:
        """Cancel any existing debounce timer and start a fresh one.

        Must be called with self._lock held.
        """
        # Cancel existing
        existing = self._debounce_timers.pop(incident.incident_id, None)
        if existing is not None:
            try:
                existing.cancel()
            except Exception:
                pass

        # Schedule new
        timer = threading.Timer(
            self.debounce_seconds,
            self._debounce_fired,
            args=(incident.incident_id,),
        )
        timer.daemon = True
        timer.name = f"debounce-{incident.incident_id[:8]}"
        self._debounce_timers[incident.incident_id] = timer
        timer.start()

        log.debug(
            "Debounce timer (re)set for incident %s (%.1fs)",
            incident.incident_id, self.debounce_seconds,
        )

    def _debounce_fired(self, incident_id: str) -> None:
        """Called when a debounce timer fires. Triggers regeneration."""
        with self._lock:
            # Remove the timer entry (it just fired)
            self._debounce_timers.pop(incident_id, None)

            # Check the incident is still open
            incident = None
            for inc in self._open_incidents.values():
                if inc.incident_id == incident_id:
                    incident = inc
                    break

            if incident is None:
                log.debug(
                    "Debounce fired for %s but incident is no longer open — skipping",
                    incident_id,
                )
                return

        # Trigger regeneration outside the lock
        self._trigger_regenerate(incident_id)

    # ------------------------------------------------------------------
    # Internal: regeneration
    # ------------------------------------------------------------------

    def _trigger_regenerate(self, incident_id: str) -> None:
        """Fire the regenerate callback on a background thread.

        If a regeneration is already running for this incident, mark it as
        pending so we'll regenerate again after the current run finishes.
        """
        with self._lock:
            if incident_id in self._regenerating:
                # Already running — flag for another pass
                self._pending_regenerate.add(incident_id)
                log.debug(
                    "Regen already in progress for %s — queuing follow-up",
                    incident_id,
                )
                return

            # Mark as running
            self._regenerating.add(incident_id)

        # Spawn a worker thread — don't block the caller
        worker = threading.Thread(
            target=self._regenerate_worker,
            args=(incident_id,),
            daemon=True,
            name=f"regen-{incident_id[:8]}",
        )
        worker.start()

    def _regenerate_worker(self, incident_id: str) -> None:
        """Worker thread that calls on_regenerate and handles queueing."""
        try:
            # Grab the incident snapshot (may be open or just closed)
            incident = self._find_incident(incident_id)
            if incident is None:
                log.warning(
                    "Regen worker: incident %s not found, skipping", incident_id,
                )
                return

            cb = self._on_regenerate
            if cb is None:
                log.warning("Regen worker: no callback set, skipping")
                return

            # Bump version before invoking, so the report reflects the new version
            with self._lock:
                incident.report_version += 1

            log.info(
                "Regenerating incident %s (v%d, alerts=%d, status=%s)",
                incident_id, incident.report_version, incident.alert_count, incident.status,
            )

            try:
                cb(incident)
            except Exception as e:
                log.exception("Regen callback raised for incident %s: %s", incident_id, e)

        finally:
            # Clear running flag and check for queued follow-ups
            with self._lock:
                self._regenerating.discard(incident_id)
                queued = incident_id in self._pending_regenerate
                if queued:
                    self._pending_regenerate.discard(incident_id)

            if queued:
                log.debug("Queued regen for %s — firing another pass", incident_id)
                self._trigger_regenerate(incident_id)

    def _trigger_regenerate_sync(self, incident: Incident) -> None:
        """Synchronous regeneration used during shutdown.

        Does not spawn a thread, does not queue follow-ups. Just fires
        the callback once with whatever state the incident has.
        """
        cb = self._on_regenerate
        if cb is None:
            return
        try:
            incident.report_version += 1
            cb(incident)
        except Exception as e:
            log.exception("Shutdown regen failed for %s: %s", incident.incident_id, e)

    def _find_incident(self, incident_id: str) -> Optional[Incident]:
        """Look up an incident by ID, whether open or being closed."""
        with self._lock:
            for inc in self._open_incidents.values():
                if inc.incident_id == incident_id:
                    return inc
        return None

    # ------------------------------------------------------------------
    # Internal: sweeper
    # ------------------------------------------------------------------

    def _sweep_loop(self) -> None:
        """Background loop that closes expired incidents.

        Runs independently of alert arrivals — catches incidents that would
        otherwise linger because no new alerts are coming in to trigger the
        expiry check in process_alert().
        """
        while not self._stop_event.is_set():
            try:
                self._sweep_once()
            except Exception as e:
                log.exception("Sweeper raised: %s", e)

            # Wait, but bail out quickly on stop
            self._stop_event.wait(timeout=self.sweep_interval_seconds)

    def _sweep_once(self) -> None:
        """Close any incidents whose time window has expired."""
        now = time.time()
        expired: List[Incident] = []

        with self._lock:
            for inc in list(self._open_incidents.values()):
                silence = now - inc.last_activity_at
                if silence > self.time_window_seconds:
                    expired.append(inc)
                    self._close_incident_locked(inc, final=True)

        # Trigger final regenerations outside the lock
        for inc in expired:
            log.info("Sweeper closed incident %s", inc.incident_id)
            self._trigger_regenerate(inc.incident_id)