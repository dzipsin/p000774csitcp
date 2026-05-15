"""
web_server.py - Flask + Socket.IO dashboard for Suricata alerts and incidents

Responsibilities:
  - Serve the HTML/CSS/JS frontend
  - Receive AlertRecord objects via push_alert() from LogMonitor
  - Receive IncidentReport objects via push_incident_report() from ReportGenerator
  - Push alerts and incidents to browsers in real-time over WebSocket
  - Expose REST endpoints to query buffered alerts, incidents, and trigger analysis

Depends on:
  log_monitor.AlertRecord    - consumed via push_alert()
  ai_module.AIAnalyzer       - called on demand via /api/analyse (legacy batch mode)
  ai_module.AlertReport      - legacy return type of /api/analyse
  models.IncidentReport      - new per-incident report type
  incident_manager           - (optional) wired to support /api/incidents/regenerate
"""

import dataclasses
import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from log_monitor import AlertRecord
from ai_module import AIAnalyzer, AlertReport
from models import IncidentReport

log = logging.getLogger(__name__)


class Server:
    """Flask + Socket.IO dashboard server.

    Usage::

        server = Server(host="0.0.0.0", port=5000, secret_key="...")
        server.set_analyser(analyser)
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
        self._analyser: Optional[AIAnalyzer] = None
        self._incident_force_regenerate: Optional[Callable[[], int]] = None
        self._incident_clear_all: Optional[Callable[[], int]] = None

        # Flask app + Socket.IO
        self._app = Flask(__name__)
        self._app.config["SECRET_KEY"] = secret_key
        self._socketio = SocketIO(self._app, cors_allowed_origins=cors_origins)

        self._register_routes()
        self._register_socket_events()

    # ------------------------------------------------------------------
    # Integration points
    # ------------------------------------------------------------------

    def set_analyser(self, analyser: AIAnalyzer) -> None:
        """Attach the legacy AIAnalyzer (for /api/analyse batch mode)."""
        self._analyser = analyser

    def set_incident_force_regenerate(self, fn: Callable[[], int]) -> None:
        """Attach IncidentManager.force_regenerate_all."""
        self._incident_force_regenerate = fn

    def set_incident_clear_all(self, fn: Callable[[], int]) -> None:
        """Attach a callable that clears incident storage (on-disk reports)."""
        self._incident_clear_all = fn

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
        """
        try:
            report_dict = dataclasses.asdict(report)
        except Exception as e:
            log.exception("Failed to serialise IncidentReport: %s", e)
            return

        incident_id = report.incident_summary.incident_id

        with self._incidents_lock:
            self._incidents[incident_id] = report_dict
            # Cap cache size — drop oldest if we exceed the limit
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

        @app.route("/api/analyse", methods=["GET", "POST"])
        def api_analyse():
            """Legacy batch-mode analysis endpoint.

            Kept for backward compatibility with the old "Analyse" button.
            New flow uses /api/incidents/* endpoints.
            """
            if self._analyser is None:
                return jsonify({"error": "AI analyser not configured."}), 503

            body = request.get_json(silent=True) or {}
            last_n = int(body.get("last_n", self.max_buffer))

            with self._buffer_lock:
                batch = list(self._buffer[-last_n:])

            try:
                report: AlertReport = self._analyser.analyse(batch)
                return jsonify(dataclasses.asdict(report))
            except Exception as e:
                log.exception("Legacy /api/analyse failed")
                return jsonify({"error": str(e)}), 500

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
                "ai_ready":             self._analyser is not None,
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
            """Clear cached incidents from memory AND delete on-disk reports."""
            with self._incidents_lock:
                mem_count = len(self._incidents)
                self._incidents.clear()

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

            return jsonify({
                "cleared_memory": mem_count,
                "cleared_disk": disk_count,
            })

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