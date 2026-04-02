"""
web_server.py - Flask + Socket.IO dashboard for Suricata alerts

Responsibilities:
  - Serve the HTML/CSS/JS frontend
  - Receive AlertRecord objects from LogMonitor via push_alert()
  - Push alerts to browsers in real-time over WebSocket
  - Expose REST endpoints to query buffered alerts and trigger AI analysis

Depends on:
  log_monitor.AlertRecord   consumed via push_alert(); no LogMonitor import
  ai_module.AIAnalyzer      called on demand via /api/analyse
  ai_module.AlertReport     serialised to JSON and returned by /api/analyse
"""

import dataclasses
import threading
from typing import List, Optional

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

from log_monitor import AlertRecord
from ai_module import AIAnalyzer, AlertReport


class Server:
    """Flask + Socket.IO dashboard server.

    Usage::

        server = WebServer(host="0.0.0.0", port=5000, secret_key="...")
        server.set_analyser(analyser)        # optional
        monitor.subscribe(server.push_alert)
        server.run()                         # blocking
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 5000,
        secret_key: str = "suricata-dashboard",
        cors_origins: str = "*",
        max_buffer: int = 5000,
    ):
        self.host = host
        self.port = port
        self.max_buffer = max_buffer

        # The rolling list of recent alerts and a lock to protect it
        self._buffer: List[AlertRecord] = []
        self._buffer_lock = threading.Lock()

        # AI analyser - set via set_analyser()
        self._analyser: Optional[AIAnalyzer] = None

        # Flask app and Socket.IO instance
        self._app = Flask(__name__)
        self._app.config["SECRET_KEY"] = secret_key
        self._socketio = SocketIO(self._app, cors_allowed_origins=cors_origins)

        self._register_routes()
        self._register_socket_events()

    def set_analyser(self, analyser: AIAnalyzer):
        """Attach an AIAnalyzer"""
        self._analyser = analyser

    def push_alert(self, alert: AlertRecord):
        """Store the alert and broadcast it to all connected browsers.

        This is subscribed to the LogMonitor and is called from its background
        thread whenever a new alert arrives.
        """
        # Add to buffer, dropping the oldest entry when full
        with self._buffer_lock:
            self._buffer.append(alert)
            if len(self._buffer) > self.max_buffer:
                self._buffer.pop(0)

        # Broadcast to every open browser tab
        self._socketio.emit("alert", alert.to_dict())

    # Lifecycle
    def run(self) -> None:
        """Start the server. This call blocks until the server stops."""
        print(f"[WebServer] dashboard at http://{self.host}:{self.port}")
        self._socketio.run(self._app, host=self.host, port=self.port, debug=False)

    # Routes
    def _register_routes(self) -> None:
        app = self._app

        @app.route("/")
        def index():
            return render_template("index.html")

        @app.route("/api/alerts/recent")
        def api_recent_alerts():
            """Return the last N alerts from the buffer as JSON.

            Query param: ?n=N (default 100, capped at max_buffer)

            Response format:
                { "alerts": [...], "total_buffered": N }
            """
            n = min(int(request.args.get("n", 100)), self.max_buffer)
            with self._buffer_lock:
                recent = [a.to_dict() for a in self._buffer[-n:]]
            return jsonify({"alerts": recent, "total_buffered": len(self._buffer)})

        @app.route("/api/alerts/clear", methods=["POST"])
        def api_clear_alerts():
            """Empty the server-side alert buffer.

            Response: { "cleared": N }
            """
            with self._buffer_lock:
                count = len(self._buffer)
                self._buffer.clear()
            return jsonify({"cleared": count})

        @app.route("/api/analyse", methods=["GET", "POST"])
        def api_analyse():
            """Run AI analysis on the buffered alerts and return a report.

            GET:  analyse the full buffer (used by the browser tab button).
            POST: optionally pass { "last_n": N } to limit the batch size.

            Returns 503 if no AI analyser is configured.
            """
            if self._analyser is None:
                return jsonify({"error": "AI analyser not configured."}), 503

            body = request.get_json(silent=True) or {}
            last_n = int(body.get("last_n", self.max_buffer))

            with self._buffer_lock:
                batch = list(self._buffer[-last_n:])

            report: AlertReport = self._analyser.analyse(batch)
            return jsonify(dataclasses.asdict(report))

        @app.route("/api/status")
        def api_status():
            """Simple health-check endpoint.

            Example response:
                { "status": "ok", "buffered_alerts": N, "ai_ready": false }
            """
            with self._buffer_lock:
                buffered = len(self._buffer)
            return jsonify({
                "status":          "ok",
                "buffered_alerts": buffered,
                "ai_ready":        self._analyser is not None,
            })

    # Socket.IO events

    def _register_socket_events(self):
        @self._socketio.on("connect")
        def on_connect():
            print("[WebServer] browser connected")

        @self._socketio.on("disconnect")
        def on_disconnect():
            print("[WebServer] browser disconnected")
