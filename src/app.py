#!/usr/bin/env python3
"""
app.py - Entrypoint: loads app.config, wires modules, starts the server.

Resolution order for sensitive values (e.g. api_key):
  1. Environment variable
  2. app.config value
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

from log_monitor import LogMonitor
from web_server import Server
from ai_module import AIAnalyzer
from model_provider import ModelConfig, ProviderType, create_provider

# Load config file
_CONFIG_PATH = Path(__file__).parent.parent / "app.config"

if not _CONFIG_PATH.exists():
    print(f"[app] ERROR: config file not found at {_CONFIG_PATH}", file=sys.stderr)
    sys.exit(1)

with open(_CONFIG_PATH, "rb") as _f:
    _cfg = tomllib.load(_f)

def _get(section: str, key: str, fallback=None):
    """Retrieve a value from the parsed config, with an optional fallback."""
    return _cfg.get(section, {}).get(key, fallback)


# Server config
HOST       = _get("server", "host",       "0.0.0.0")
PORT       = int(_get("server", "port",   5000))
SECRET     = _get("server", "secret_key", "suricata-dashboard")

# Monitor config
EVE_LOG       = _get("monitor", "eve_log",       "/var/log/suricata/eve.json")
POLL_INTERVAL = float(_get("monitor", "poll_interval", 0.5))

# Model config
_model_cfg     = _cfg.get("model", {})
_provider_name = _model_cfg.get("provider", "ollama").lower()
_provider_type = ProviderType(_provider_name)

# Load the provider-specific sub-section
_provider_cfg  = _cfg.get("model", {}).get(_provider_name, {})
_model_name    = _provider_cfg.get("model_name", "")
_api_key = os.getenv("API_KEY") or _provider_cfg.get("api_key", "")

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

monitor = LogMonitor(eve_log_path=EVE_LOG, poll_interval=POLL_INTERVAL)
server  = Server(host=HOST, port=PORT, secret_key=SECRET)

try:
    provider = create_provider(model_config)
    analyser = AIAnalyzer(provider)
    server.set_analyser(analyser)
    print(f"[app] model provider : {model_config.provider.value}")
    print(f"[app] model          : {model_config.model}")
except Exception as e:
    print(f"[app] AI analysis disabled: {e}")

monitor.subscribe(server.push_alert)

if __name__ == "__main__":
    monitor.start()
    server.run()
