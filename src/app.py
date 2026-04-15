#!/usr/bin/env python3
"""
app.py - Entrypoint: loads app.config, wires modules, starts the server.

Resolution order for sensitive values (e.g. api_key):
  1. Environment variable
  2. app.config value
"""

from __future__ import annotations

import logging
import os
import sys
import tomllib
from pathlib import Path

from log_monitor import LogMonitor
from web_server import Server
from ai_module import AIAnalyzer
from model_provider import ModelConfig, ProviderType, create_provider

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
    datefmt="%H:%M:%S",
)

# Set DEBUG for our modules when needed (change INFO -> DEBUG here)
for mod in ("ai_module", "model_provider", "log_monitor"):
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
# Model config
# ---------------------------------------------------------------------------

_model_cfg     = _cfg.get("model", {})
_provider_name = _model_cfg.get("provider", "ollama").lower()
_provider_type = ProviderType(_provider_name)

_provider_cfg  = _cfg.get("model", {}).get(_provider_name, {})
_model_name    = _provider_cfg.get("model_name", "")
_api_key       = os.getenv("API_KEY") or _provider_cfg.get("api_key", "")

model_config = ModelConfig(
    provider        = _provider_type,
    model           = _model_name,
    max_tokens      = int(_model_cfg.get("max_tokens",  1024)),
    temperature     = float(_model_cfg.get("temperature", 0.2)),
    system_prompt   = _model_cfg.get("system_prompt") or None,
    api_key         = _api_key,
    base_url        = _provider_cfg.get("base_url", ""),
    request_timeout = int(_provider_cfg.get("request_timeout", 120)),
)

# ---------------------------------------------------------------------------
# Analysis config
# ---------------------------------------------------------------------------

_analysis_cfg = _cfg.get("analysis", {})
INCLUDE_LAB_CONTEXT = _analysis_cfg.get("include_lab_context", True)
SUMMARY_MODE        = _analysis_cfg.get("summary_mode", "llm")

# ---------------------------------------------------------------------------
# Wire everything together
# ---------------------------------------------------------------------------

monitor = LogMonitor(eve_log_path=EVE_LOG, poll_interval=POLL_INTERVAL)
server  = Server(host=HOST, port=PORT, secret_key=SECRET)

try:
    provider = create_provider(model_config)
    analyser = AIAnalyzer(
        provider,
        include_lab_context=INCLUDE_LAB_CONTEXT,
        summary_mode=SUMMARY_MODE,
    )
    server.set_analyser(analyser)
    log.info("model provider : %s", model_config.provider.value)
    log.info("model          : %s", model_config.model)
    log.info("lab context    : %s", INCLUDE_LAB_CONTEXT)
    log.info("summary mode   : %s", SUMMARY_MODE)
except Exception as e:
    log.warning("AI analysis disabled: %s", e)

monitor.subscribe(server.push_alert)

if __name__ == "__main__":
    monitor.start()
    server.run()