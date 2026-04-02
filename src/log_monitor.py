"""
log_monitor.py - Suricata eve.json follow, parse, and emit

Responsibilities:
  - Watch /var/log/suricata/eve.json (or a configurable path)
  - Parse raw JSON lines into structured AlertRecord objects
  - Deliver AlertRecords to registered callbacks (fan-out)

Public surface:
  AlertRecord:   immutable dataclass representing one parsed alert
  LogMonitor:    starts a background thread; callers register via .subscribe()
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Callable, List, Optional


@dataclass(frozen=True)
class AlertRecord:
    """One fully-parsed Suricata alert event.

    All consumers receive this type.
    Fields are intentionally verbose so downstream code never has to
    re-parse or guess at units.
    """

    # --- Timing ---
    timestamp_raw: str          # Original ISO-8601 string from eve.json
    timestamp_display: str      # "HH:MM:SS.mmm" local-friendly label
    timestamp_epoch: float      # POSIX seconds; use for ordering / bucketing

    # --- Severity ---
    severity_level: int         # Suricata native: 1=critical … 4=informational
    severity_label: str         # "critical" | "high" | "medium" | "low"

    # --- Network tuple ---
    src_ip: str
    src_port: str               # str to accommodate "?" on parse failure
    dst_ip: str
    dst_port: str
    proto: str                  # "TCP" | "UDP" | "ICMP" | …

    # --- Signature ---
    signature: str
    signature_id: int           # Suricata sid; 0 if missing
    category: str
    action: str                 # "allowed" | "blocked" | ""

    # --- Flow context (may be empty strings / 0 if not present) ---
    flow_id: int                # Suricata flow_id for correlation; 0 if absent
    app_proto: str              # "http" | "tls" | "dns" | … | ""
    in_iface: str               # capturing interface name

    # --- Full original event for extensibility ---
    raw_event: dict = field(compare=False)  # mutable but excluded from hash

    def to_dict(self) -> dict:
        """Serialise to a plain dict (JSON-safe, raw_event excluded)."""
        d = asdict(self)
        d.pop("raw_event", None)
        return d



_SEVERITY_MAP = {1: "critical", 2: "high", 3: "medium"}


def _parse_line(line: str) -> Optional[AlertRecord]:
    """Parse one eve.json line.  Returns None if not an alert or malformed."""
    line = line.strip()
    if not line:
        return None

    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    alert_obj = event.get("alert", {})

    # --- Timestamp ---
    ts_raw = event.get("timestamp", "")
    ts_display = ts_raw
    ts_epoch = 0.0
    try:
        dt = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
        ts_display = dt.strftime("%H:%M:%S.%f")[:-3]
        ts_epoch = dt.timestamp()
    except (ValueError, AttributeError):
        pass

    # --- Severity ---
    sev_level = int(alert_obj.get("severity", 4))
    sev_label = _SEVERITY_MAP.get(sev_level, "low")

    return AlertRecord(
        timestamp_raw=ts_raw,
        timestamp_display=ts_display,
        timestamp_epoch=ts_epoch,
        severity_level=sev_level,
        severity_label=sev_label,
        src_ip=str(event.get("src_ip", "?")),
        src_port=str(event.get("src_port", "?")),
        dst_ip=str(event.get("dest_ip", "?")),
        dst_port=str(event.get("dest_port", "?")),
        proto=str(event.get("proto", "")).upper(),
        signature=alert_obj.get("signature", "Unknown"),
        signature_id=int(alert_obj.get("signature_id", 0)),
        category=alert_obj.get("category", "-"),
        action=alert_obj.get("action", ""),
        flow_id=int(event.get("flow_id", 0)),
        app_proto=str(event.get("app_proto", "")),
        in_iface=str(event.get("in_iface", "")),
        raw_event=event,
    )


class LogMonitor:
    """Follows an eve.json file and provides AlertRecords to subscribers.

    Usage::

        monitor = LogMonitor("/var/log/suricata/eve.json")
        monitor.subscribe(my_callback)   # callback(alert: AlertRecord) -> None
        monitor.start()                  # non-blocking; runs daemon thread
        #...
        monitor.stop()

    Multiple subscribers are supported.  Each callback is called synchronously
    in the monitor thread, so keep callbacks fast (hand off to a queue if needed).
    """

    def __init__(
            self,
            eve_log_path: str = "/var/log/suricata/eve.json",
            poll_interval: float = 0.5
        ):
        self.eve_log_path = eve_log_path
        self.poll_interval = poll_interval
        self._subscribers: List[Callable[[AlertRecord], None]] = []
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # Subscription
    def subscribe(self, callback: Callable[[AlertRecord], None]) -> None:
        """Register a callable to receive AlertRecord on each new alert."""
        self._subscribers.append(callback)

    def unsubscribe(self, callback: Callable[[AlertRecord], None]) -> None:
        """Unregister a previously subscribed callable"""
        self._subscribers = [s for s in self._subscribers if s is not callback]

    # Lifecycle
    def start(self) -> None:
        """Start the background tail thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="log-monitor")
        self._thread.start()

    def stop(self) -> None:
        """Signal the thread to stop (best-effort; thread is daemon)."""
        self._stop_event.set()

    # Internal
    def _notify(self, alert: AlertRecord) -> None:
        for cb in list(self._subscribers):
            try:
                cb(alert)
            except Exception as e:
                print(f"[LogMonitor] subscriber {cb} raised: {e}")

    def _run(self) -> None:
        # Wait for the log file to appear
        while not os.path.exists(self.eve_log_path):
            if self._stop_event.is_set():
                return
            print(f"[LogMonitor] waiting for {self.eve_log_path}...")
            time.sleep(2)

        print(f"[LogMonitor] tailing {self.eve_log_path}")
        with open(self.eve_log_path, "r") as alert_log:
            alert_log.seek(0, io.SEEK_END)
            while not self._stop_event.is_set():
                line = alert_log.readline()
                if not line:
                    time.sleep(self.poll_interval)
                    continue
                alert = _parse_line(line)
                if alert:
                    self._notify(alert)
