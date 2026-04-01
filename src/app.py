#!/usr/bin/env python3
"""
Suricata Alert Dashboard
Tails /var/log/suricata/eve.json and streams alerts to the browser via WebSockets.
"""

import json
import os
import threading
import time
from datetime import datetime

from flask import Flask, render_template
from flask_socketio import SocketIO

EVE_LOG = "/var/log/suricata/eve.json"

app = Flask(__name__)
app.config["SECRET_KEY"] = "suricata-dashboard"
socketio = SocketIO(app, cors_allowed_origins="*")


def parse_alert(line: str):
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    severity = {1: "critical", 2: "high", 3: "medium"}.get(alert.get("severity", 4), "low")

    ts = event.get("timestamp", "")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        ts = dt.strftime("%H:%M:%S.%f")[:-3]
    except ValueError:
        pass

    return {
        "timestamp": ts,
        "severity":  severity,
        "src_ip":    event.get("src_ip", "?"),
        "src_port":  event.get("src_port", "?"),
        "dst_ip":    event.get("dest_ip", "?"),
        "dst_port":  event.get("dest_port", "?"),
        "signature": alert.get("signature", "Unknown"),
        "category":  alert.get("category", "-"),
    }


def tail_eve_log():
    while not os.path.exists(EVE_LOG):
        print(f"[*] Waiting for {EVE_LOG} ...")
        time.sleep(2)

    print(f"[*] Tailing {EVE_LOG}")
    with open(EVE_LOG, "r") as f:
        f.seek(0, 2)  # start at end — only new alerts
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            alert = parse_alert(line)
            if alert:
                socketio.emit("alert", alert)


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    threading.Thread(target=tail_eve_log, daemon=True).start()
    print("[*] Dashboard running at http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
