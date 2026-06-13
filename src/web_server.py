"""
web_server.py - Flask + Socket.IO dashboard for Suricata alerts and incidents

Responsibilities:
  - Serve the HTML/CSS/JS frontend
  - Receive AlertRecord objects via push_alert() from LogMonitor
  - Receive IncidentReport objects via push_incident_report() from ReportGenerator
  - Push alerts and incidents to browsers in real-time over WebSocket
  - Expose REST endpoints to query buffered alerts and incidents

Depends on:
  log_monitor.AlertRecord    - consumed via push_alert()
  models.IncidentReport      - per-incident report type
  incident_manager           - (optional) wired to support /api/incidents/regenerate
"""

import dataclasses
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from log_monitor import AlertRecord
from models import IncidentReport

log = logging.getLogger(__name__)


def _parse_hours(raw: Optional[str]) -> Optional[float]:
    """Convert `?hours=N` query string into a since_epoch.

    Returns None if missing or invalid (caller treats None as "all time").
    Negative or zero values also return None.
    """
    if raw is None or raw == "":
        return None
    try:
        hours = float(raw)
    except (TypeError, ValueError):
        return None
    if hours <= 0:
        return None
    return time.time() - (hours * 3600.0)


class Server:
    """Flask + Socket.IO dashboard server.

    Usage::

        server = Server(host="0.0.0.0", port=5000, secret_key="...")
        server.set_incident_force_regenerate(incident_manager.force_regenerate_all)
        server.set_storage(storage)
        monitor.subscribe(server.push_alert)
        report_generator_on_ready = server.push_incident_report
        server.run()   # blocking
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5000,
        secret_key: str = "suricata-dashboard",
        cors_origins: str = "*",
        max_buffer: int = 5000,
        max_incident_buffer: int = 500,
    ):
        self.host = host
        self.port = port
        self.max_buffer = max_buffer
        self.max_incident_buffer = max_incident_buffer

        # Rolling buffer of alerts (for browser reconnect)
        self._buffer: List[AlertRecord] = []
        self._buffer_lock = threading.Lock()

        # Rolling cache of recent incident reports, keyed by incident_id.
        # Holds the LATEST version of each incident. When an incident updates,
        # the entry is replaced. On disconnect/reconnect the client gets this
        # snapshot.
        self._incidents: Dict[str, Dict] = {}
        self._incidents_lock = threading.Lock()

        # Optional integrations
        self._incident_force_regenerate: Optional[Callable[[], int]] = None
        self._incident_clear_all: Optional[Callable[[], int]] = None
        # Drops the IncidentManager's in-memory incident state so a cleared
        # incident isn't regenerated back onto disk by a pending debounce/sweep.
        self._incident_reset: Optional[Callable[[], int]] = None
        # Phase 10: query-capable storage backend (ReportDatabase). Endpoints
        # that require SQLite-only methods (list_by_*, aggregate_stats) check
        # `hasattr` before calling, so a JSON-backed deployment still works
        # (those endpoints just return 503).
        self._storage: Optional[Any] = None

        # Flask app + Socket.IO
        self._app = Flask(__name__)
        self._app.config["SECRET_KEY"] = secret_key
        self._socketio = SocketIO(self._app, cors_allowed_origins=cors_origins)

        self._register_routes()
        self._register_socket_events()

    # ------------------------------------------------------------------
    # Integration points
    # ------------------------------------------------------------------

    def set_incident_force_regenerate(self, fn: Callable[[], int]) -> None:
        """Attach IncidentManager.force_regenerate_all."""
        self._incident_force_regenerate = fn

    def set_incident_clear_all(self, fn: Callable[[], int]) -> None:
        """Attach a callable that clears incident storage (on-disk reports)."""
        self._incident_clear_all = fn

    def set_incident_reset(self, fn: Callable[[], int]) -> None:
        """Attach IncidentManager.clear_all_incidents - drops in-memory state."""
        self._incident_reset = fn

    def set_storage(self, storage: Any) -> None:
        """Attach the storage backend. When it exposes the Phase 10 query
        methods (list_by_source_ip / list_by_attack_type / list_by_severity
        / aggregate_stats), the corresponding HTTP endpoints become live.
        JSON-backed storage works but those endpoints return 503."""
        self._storage = storage

    # ------------------------------------------------------------------
    # Inbound: alerts
    # ------------------------------------------------------------------

    def push_alert(self, alert: AlertRecord) -> None:
        """Store and broadcast a new alert. Called from LogMonitor thread."""
        with self._buffer_lock:
            self._buffer.append(alert)
            if len(self._buffer) > self.max_buffer:
                self._buffer.pop(0)

        try:
            self._socketio.emit("alert", alert.to_dict())
        except Exception as e:
            log.exception("Failed to emit alert: %s", e)

    # ------------------------------------------------------------------
    # Inbound: incident reports
    # ------------------------------------------------------------------

    def push_incident_report(self, report: IncidentReport) -> None:
        """Cache and broadcast an incident report update.

        Called from ReportGenerator's worker thread after a report is generated.

        Emits the template-v1-compliant JSON shape so the persisted reports
        (via ReportDatabase), the cache, the /api/incidents endpoint, and the
        WebSocket push all use one consistent format. Internal extras
        (incident_id, classification per alert, reasoning trace) are
        preserved alongside template-required fields.
        """
        try:
            from report_serializer import to_template_v1
            report_dict = to_template_v1(report)
        except Exception as e:
            log.exception("Failed to serialise IncidentReport: %s", e)
            # Fallback to raw asdict so the dashboard at least gets something.
            try:
                report_dict = dataclasses.asdict(report)
            except Exception:
                return

        incident_id = report.incident_summary.incident_id

        with self._incidents_lock:
            self._incidents[incident_id] = report_dict
            # Cap cache size - drop oldest if we exceed the limit
            if len(self._incidents) > self.max_incident_buffer:
                oldest_key = next(iter(self._incidents))
                self._incidents.pop(oldest_key, None)

        try:
            self._socketio.emit("incident_updated", report_dict)
        except Exception as e:
            log.exception("Failed to emit incident_updated: %s", e)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def run(self) -> None:
        """Start the server. Blocks until the server stops."""
        log.info("Dashboard starting at http://%s:%d", self.host, self.port)
        # allow_unsafe_werkzeug=True is needed for some flask-socketio versions
        # when not running under eventlet/gevent. We use the dev server anyway.
        try:
            self._socketio.run(
                self._app,
                host=self.host,
                port=self.port,
                debug=False,
                allow_unsafe_werkzeug=True,
            )
        except TypeError:
            # Older flask-socketio doesn't accept allow_unsafe_werkzeug
            self._socketio.run(self._app, host=self.host, port=self.port, debug=False)

    # ------------------------------------------------------------------
    # Routes: alerts (existing)
    # ------------------------------------------------------------------

    def _register_routes(self) -> None:
        app = self._app

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/api/alerts/recent")
        def api_recent_alerts():
            """Return the last N alerts from the buffer as JSON.

            Query param: ?n=N (default 100, capped at max_buffer)
            """
            try:
                n = min(int(request.args.get("n", 100)), self.max_buffer)
            except (TypeError, ValueError):
                n = 100

            with self._buffer_lock:
                recent = [a.to_dict() for a in self._buffer[-n:]]
            return jsonify({"alerts": recent, "total_buffered": len(self._buffer)})

        @app.route("/api/alerts/clear", methods=["POST"])
        def api_clear_alerts():
            """Empty the server-side alert buffer and notify clients."""
            with self._buffer_lock:
                count = len(self._buffer)
                self._buffer.clear()
            try:
                self._socketio.emit("clear")
            except Exception:
                log.exception("Failed to emit clear event")
            return jsonify({"cleared": count})

        @app.route("/api/status")
        def api_status():
            """Simple health-check endpoint."""
            with self._buffer_lock:
                buffered = len(self._buffer)
            with self._incidents_lock:
                inc_count = len(self._incidents)
            return jsonify({
                "status":               "ok",
                "buffered_alerts":      buffered,
                "cached_incidents":     inc_count,
                "incident_pipeline":    self._incident_force_regenerate is not None,
            })

        # ------------------------------------------------------------------
        # Routes: incidents (new)
        # ------------------------------------------------------------------

        @app.route("/api/incidents")
        def api_list_incidents():
            """Return all cached incident reports, newest first."""
            with self._incidents_lock:
                incidents = list(self._incidents.values())

            # Sort by generated_at descending
            incidents.sort(
                key=lambda r: r.get("incident_summary", {}).get("generated_at", ""),
                reverse=True,
            )
            return jsonify({"incidents": incidents, "total": len(incidents)})

        @app.route("/api/incidents/<incident_id>")
        def api_get_incident(incident_id: str):
            """Return a single incident report by ID, or 404 if not found."""
            with self._incidents_lock:
                report = self._incidents.get(incident_id)

            if report is None:
                return jsonify({"error": f"incident {incident_id} not found"}), 404
            return jsonify(report)

        @app.route("/api/incidents/regenerate", methods=["POST"])
        def api_regenerate_incidents():
            """Force-regenerate all open incidents immediately.

            Bypasses the debounce timer. Returns the count of incidents
            for which regeneration was triggered.
            """
            if self._incident_force_regenerate is None:
                return jsonify({
                    "error": "Incident pipeline not configured."
                }), 503

            try:
                count = self._incident_force_regenerate()
                return jsonify({"regenerated": count})
            except Exception as e:
                log.exception("force_regenerate_all failed")
                return jsonify({"error": str(e)}), 500

        @app.route("/api/incidents/clear", methods=["POST"])
        def api_clear_incidents():
            """Clear incidents everywhere - completely bomb them.

            Order matters:
              1. Drop the IncidentManager's in-memory incidents (and cancel
                 pending debounce/sweep + regen executors) so nothing
                 regenerates a row back onto disk after we delete it.
              2. Clear the web-server snapshot cache served to clients.
              3. Delete every incident + cascaded alert from SQLite.
            """
            # 1. IncidentManager in-memory state.
            manager_dropped = 0
            if self._incident_reset is not None:
                try:
                    manager_dropped = self._incident_reset()
                except Exception:
                    log.exception("IncidentManager reset failed")

            # 2. Web-server snapshot cache.
            with self._incidents_lock:
                mem_count = len(self._incidents)
                self._incidents.clear()

            # 3. On-disk SQLite rows (incidents + alerts via FK cascade).
            disk_count = 0
            if self._incident_clear_all is not None:
                try:
                    disk_count = self._incident_clear_all()
                except Exception as e:
                    log.exception("Disk clear failed: %s", e)

            try:
                self._socketio.emit("incidents_cleared")
            except Exception:
                log.exception("Failed to emit incidents_cleared event")

            log.info(
                "Clear incidents: manager_dropped=%d, cache=%d, disk=%d",
                manager_dropped, mem_count, disk_count,
            )
            return jsonify({
                "cleared_memory": mem_count,
                "cleared_disk": disk_count,
                "manager_dropped": manager_dropped,
            })

        # ------------------------------------------------------------------
        # Routes: incident history queries (SQLite-backed)
        #
        # These endpoints depend on the ReportDatabase query methods. The
        # _require_query_backend guard below still uses hasattr() so an
        # alternate backend without one of the methods would degrade to 503
        # instead of crashing - defensive but cheap.
        # ------------------------------------------------------------------

        def _require_query_backend(method_name: str):
            """Return None if the backend supports method_name, otherwise a
            (response, status) tuple suitable for `return` in the handler."""
            if self._storage is None:
                return jsonify({
                    "error": "Storage backend not attached.",
                }), 503
            if not hasattr(self._storage, method_name):
                return jsonify({
                    "error": (
                        f"Backend does not support history queries "
                        f"(method `{method_name}` unavailable). Set "
                        f"[storage].backend = \"sqlite\" in app.config."
                    ),
                }), 503
            return None

        @app.route("/api/incidents/by-ip/<path:source_ip>")
        def api_incidents_by_ip(source_ip: str):
            """All incidents from a given source IP across all sessions.

            Query params:
                hours = N  -> only incidents whose generated_at is within
                             the last N hours.
            """
            err = _require_query_backend("list_by_source_ip")
            if err is not None:
                return err
            since_epoch = _parse_hours(request.args.get("hours"))
            try:
                results = self._storage.list_by_source_ip(
                    source_ip=source_ip, since_epoch=since_epoch,
                )
                return jsonify({
                    "source_ip": source_ip,
                    "since_epoch": since_epoch,
                    "incidents": results,
                    "total": len(results),
                })
            except Exception as e:
                log.exception("by-ip query failed: %s", e)
                return jsonify({"error": str(e)}), 500

        @app.route("/api/incidents/by-attack/<path:attack_type>")
        def api_incidents_by_attack(attack_type: str):
            """All incidents whose detected_attacks list contains attack_type.

            Query params:
                hours = N
            """
            err = _require_query_backend("list_by_attack_type")
            if err is not None:
                return err
            since_epoch = _parse_hours(request.args.get("hours"))
            try:
                results = self._storage.list_by_attack_type(
                    attack_type=attack_type, since_epoch=since_epoch,
                )
                return jsonify({
                    "attack_type": attack_type,
                    "since_epoch": since_epoch,
                    "incidents": results,
                    "total": len(results),
                })
            except Exception as e:
                log.exception("by-attack query failed: %s", e)
                return jsonify({"error": str(e)}), 500

        @app.route("/api/incidents/by-severity/<severity>")
        def api_incidents_by_severity(severity: str):
            """All incidents with the given overall severity."""
            err = _require_query_backend("list_by_severity")
            if err is not None:
                return err
            try:
                results = self._storage.list_by_severity(severity=severity)
                return jsonify({
                    "severity": severity,
                    "incidents": results,
                    "total": len(results),
                })
            except Exception as e:
                log.exception("by-severity query failed: %s", e)
                return jsonify({"error": str(e)}), 500

        @app.route("/api/incidents/stats")
        def api_incidents_stats():
            """Aggregate counts of incidents by status / severity / attack
            type plus repeat-offender count. Query params:
                hours = N  -> bound the window."""
            err = _require_query_backend("aggregate_stats")
            if err is not None:
                return err
            since_epoch = _parse_hours(request.args.get("hours"))
            try:
                stats = self._storage.aggregate_stats(since_epoch=since_epoch)
                return jsonify(stats)
            except Exception as e:
                log.exception("aggregate_stats failed: %s", e)
                return jsonify({"error": str(e)}), 500

        @app.route("/api/incidents/cleanup", methods=["POST"])
        def api_incidents_cleanup():
            """Manually trigger retention cleanup. Drops incidents older
            than the configured retention. Returns the count dropped."""
            err = _require_query_backend("cleanup_expired")
            if err is not None:
                return err
            try:
                count = self._storage.cleanup_expired()
                return jsonify({"dropped": count})
            except Exception as e:
                log.exception("cleanup_expired failed: %s", e)
                return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------------
    # Socket.IO events
    # ------------------------------------------------------------------

    def _register_socket_events(self) -> None:
        @self._socketio.on("connect")
        def on_connect():
            log.info("Browser connected")

        @self._socketio.on("disconnect")
        def on_disconnect():
            log.info("Browser disconnected")