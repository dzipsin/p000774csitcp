#!/usr/bin/env python3
"""
app.py - Entrypoint: loads app.config, wires modules, starts the server.

Startup order (matters — each step assumes the previous ones completed):
  1. Parse config and set up logging
  2. Create all objects (no starts yet)
  3. Wire callbacks between them
  4. Start background services (IncidentManager sweeper, LogMonitor tail)
  5. server.run()  — blocks until Ctrl+C

Resolution order for sensitive/environment values:
  1. Environment variable (e.g. EVE_LOG_PATH, API_KEY)
  2. app.config value
  3. Hardcoded default
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import tomllib
from pathlib import Path

from log_monitor import LogMonitor
from web_server import Server
from ai_module import AIAnalyzer
from model_provider import ModelConfig, ProviderType, create_provider
from incident_manager import IncidentManager
from report_generator import ReportGenerator
from storage import ReportStorage

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)

for mod in (
    "ai_module", "model_provider", "log_monitor",
    "incident_manager", "report_generator", "storage", "web_server",
):
    logging.getLogger(mod).setLevel(logging.INFO)

log = logging.getLogger("app")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_CONFIG_PATH = Path(__file__).parent.parent / "app.config"

if not _CONFIG_PATH.exists():
    log.error("config file not found at %s", _CONFIG_PATH)
    sys.exit(1)

with open(_CONFIG_PATH, "rb") as _f:
    _cfg = tomllib.load(_f)


def _get(section: str, key: str, fallback=None):
    """Retrieve a value from the parsed config, with an optional fallback."""
    return _cfg.get(section, {}).get(key, fallback)


# ---------------------------------------------------------------------------
# Server config
# ---------------------------------------------------------------------------

HOST       = _get("server", "host",       "0.0.0.0")
PORT       = int(_get("server", "port",   5000))
SECRET     = _get("server", "secret_key", "suricata-dashboard")


# ---------------------------------------------------------------------------
# Monitor config (EVE_LOG_PATH env var takes precedence)
# ---------------------------------------------------------------------------

EVE_LOG       = os.getenv("EVE_LOG_PATH") or _get("monitor", "eve_log", "/var/log/suricata/eve.json")
POLL_INTERVAL = float(_get("monitor", "poll_interval", 0.5))


# ---------------------------------------------------------------------------
# Incident pipeline config
# ---------------------------------------------------------------------------

GROUPING_MODE         = _get("incident", "grouping_mode", "per_actor")
TIME_WINDOW_MINUTES   = float(_get("incident", "time_window_minutes", 2.0))
DEBOUNCE_SECONDS      = float(_get("incident", "debounce_seconds", 3.0))
REPORTS_DIR           = _get("incident", "reports_dir", "reports")
SWEEP_INTERVAL        = float(_get("incident", "sweep_interval_seconds", 10.0))

# Sanity-check grouping_mode (IncidentManager would raise otherwise, but nicer
# to catch it early with a readable message)
if GROUPING_MODE not in ("per_actor", "per_attack_type"):
    log.warning(
        "Invalid grouping_mode '%s' in config, defaulting to 'per_actor'",
        GROUPING_MODE,
    )
    GROUPING_MODE = "per_actor"


# ---------------------------------------------------------------------------
# Analysis config
# ---------------------------------------------------------------------------

_analysis_cfg       = _cfg.get("analysis", {})
INCLUDE_LAB_CONTEXT = bool(_analysis_cfg.get("include_lab_context", True))
SUMMARY_MODE        = _analysis_cfg.get("summary_mode", "llm")
MAX_RETRIES         = int(_analysis_cfg.get("max_retries", 1))


# ---------------------------------------------------------------------------
# Model config
# ---------------------------------------------------------------------------

_model_cfg     = _cfg.get("model", {})
_provider_name = _model_cfg.get("provider", "ollama").lower()

try:
    _provider_type = ProviderType(_provider_name)
except ValueError:
    log.error("Unknown provider '%s' in config", _provider_name)
    sys.exit(1)

_provider_cfg = _model_cfg.get(_provider_name, {})
_model_name   = _provider_cfg.get("model_name", "")
_api_key      = os.getenv("API_KEY") or _provider_cfg.get("api_key", "")

model_config = ModelConfig(
    provider        = _provider_type,
    model           = _model_name,
    max_tokens      = int(_model_cfg.get("max_tokens",  1024)),
    temperature     = float(_model_cfg.get("temperature", 0.0)),
    system_prompt   = _model_cfg.get("system_prompt") or None,
    api_key         = _api_key,
    base_url        = _provider_cfg.get("base_url", ""),
    request_timeout = int(_provider_cfg.get("request_timeout", 120)),
)


# ---------------------------------------------------------------------------
# Object creation (no side effects yet)
# ---------------------------------------------------------------------------

monitor = LogMonitor(eve_log_path=EVE_LOG, poll_interval=POLL_INTERVAL)
server  = Server(host=HOST, port=PORT, secret_key=SECRET)

# Resolve reports_dir relative to repo root (parent of src/) unless absolute
_reports_path = Path(REPORTS_DIR)
if not _reports_path.is_absolute():
    _reports_path = Path(__file__).parent.parent / _reports_path

storage = ReportStorage(str(_reports_path))
log.info("Reports directory: %s", storage.directory)

# Incident manager starts with no callback; we set it after creating the generator
incident_manager = IncidentManager(
    grouping_mode=GROUPING_MODE,
    time_window_minutes=TIME_WINDOW_MINUTES,
    debounce_seconds=DEBOUNCE_SECONDS,
    sweep_interval_seconds=SWEEP_INTERVAL,
    on_regenerate=None,
)

log.info(
    "Incident pipeline: mode=%s, window=%.1fmin, debounce=%.1fs",
    GROUPING_MODE, TIME_WINDOW_MINUTES, DEBOUNCE_SECONDS,
)


# ---------------------------------------------------------------------------
# Provider + AI wiring (non-fatal if Ollama is unreachable at startup)
# ---------------------------------------------------------------------------

report_generator = None

try:
    provider = create_provider(model_config)

    # Legacy AIAnalyzer (for backward-compatible /api/analyse)
    analyser = AIAnalyzer(
        provider,
        include_lab_context=INCLUDE_LAB_CONTEXT,
        summary_mode=SUMMARY_MODE,
    )
    server.set_analyser(analyser)

    # New ReportGenerator for incidents
    report_generator = ReportGenerator(
        provider=provider,
        storage=storage,
        include_lab_context=INCLUDE_LAB_CONTEXT,
        summary_mode=SUMMARY_MODE,
        max_retries=MAX_RETRIES,
        is_repeat_offender=incident_manager.is_repeat_offender,
        on_report_ready=server.push_incident_report,
    )

    # Wire IncidentManager -> ReportGenerator
    incident_manager.set_regenerate_callback(report_generator.generate)

    # Hook up the force-regenerate endpoint
    server.set_incident_force_regenerate(incident_manager.force_regenerate_all)
    server.set_incident_clear_all(storage.clear_all)

    log.info("Model provider : %s", model_config.provider.value)
    log.info("Model          : %s", model_config.model)
    log.info("Lab context    : %s", INCLUDE_LAB_CONTEXT)
    log.info("Summary mode   : %s", SUMMARY_MODE)

except Exception as e:
    log.warning(
        "AI analysis disabled (provider/generator init failed): %s. "
        "Dashboard will show alerts only.", e,
    )
    # Even without the AI, we keep the IncidentManager running so the
    # dashboard can at least track alert groupings. It just won't
    # produce reports (callback stays None → IncidentManager logs and skips).


# ---------------------------------------------------------------------------
# Callback wiring
# ---------------------------------------------------------------------------

# Every alert goes to BOTH the server (raw alerts tab) and the incident manager
monitor.subscribe(server.push_alert)
monitor.subscribe(incident_manager.process_alert)


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

def _graceful_shutdown(signum, frame):
    """Stop background services cleanly on Ctrl+C."""
    log.info("Shutdown signal received — stopping services...")
    try:
        monitor.stop()
    except Exception:
        log.exception("Error stopping LogMonitor")

    try:
        # close_open=True means open incidents get a final regen before exit
        incident_manager.stop(close_open=True)
    except Exception:
        log.exception("Error stopping IncidentManager")

    log.info("Shutdown complete")
    sys.exit(0)


# SIGINT is Ctrl+C; SIGTERM is the standard stop signal.
# On Windows, SIGTERM isn't fully supported, but SIGINT works.
signal.signal(signal.SIGINT, _graceful_shutdown)
try:
    signal.signal(signal.SIGTERM, _graceful_shutdown)
except (AttributeError, ValueError):
    # Windows may not support SIGTERM the same way
    pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Start background services BEFORE the server.
    # IncidentManager first so its sweeper is live when alerts arrive.
    incident_manager.start()
    monitor.start()

    # Blocks until server stops (Ctrl+C triggers _graceful_shutdown above)
    server.run()