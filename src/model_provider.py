"""
model_provider.py - Local LLM backend (Ollama)

Capstone constraint: no paid / remote APIs. Local-only.

Public surface:
  ModelConfig     all provider configuration in one dataclass
  OllamaProvider  local: Ollama REST API (http://localhost:11434)
"""

from __future__ import annotations

import json as _json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class ModelConfig:
    """All configuration needed to instantiate OllamaProvider.

    Environment-variable defaults are resolved at instantiation time.
    """

    model: str = "llama3"
    """Model identifier, e.g. 'qwen2.5:3b', 'llama3.2', 'mistral'."""

    max_tokens: int = 1024
    """Maximum tokens in the completion response."""

    temperature: float = 0.2
    """Sampling temperature (0.0 = deterministic, 1.0 = creative)."""

    system_prompt: Optional[str] = None
    """Optional system prompt prepended to every request."""

    base_url: str = field(default_factory=lambda: os.getenv("LOCAL_MODEL_URL", ""))
    """Base URL of the Ollama server (default http://localhost:11434).
    Override via LOCAL_MODEL_URL env var.
    """

    request_timeout: int = 120
    """HTTP request timeout in seconds."""


class OllamaProvider:
    """Calls a local Ollama server via its REST API.

    Ollama must be running and the requested model must be pulled, e.g.:
        ollama pull qwen2.5:3b

    API reference: https://github.com/ollama/ollama/blob/main/docs/api.md

    Thread-safe: complete() and complete_json() are stateless reads of
    self._config and self._base, which are set once in __init__.
    """

    def __init__(self, config: ModelConfig):
        if not config.base_url:
            raise ValueError(
                "OllamaProvider requires a base_url. "
                "Set base_url in [model.ollama] in app.config or via LOCAL_MODEL_URL."
            )
        self._config = config
        self._base = config.base_url.rstrip("/")

    @property
    def model_name(self) -> str:
        return self._config.model

    def _call_ollama(
        self,
        prompt: str,
        json_mode: bool = False,
        system_prompt: Optional[str] = None,
    ) -> str:
        cfg = self._config
        messages = []

        sys = system_prompt if system_prompt is not None else cfg.system_prompt
        if sys:
            messages.append({"role": "system", "content": sys})
        messages.append({"role": "user", "content": prompt})

        payload: dict = {
            "model": cfg.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": cfg.temperature,
                "num_predict": cfg.max_tokens,
            },
        }

        if json_mode:
            payload["format"] = "json"

        data = _json.dumps(payload).encode()
        url = f"{self._base}/api/chat"
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        log.debug("Ollama request to %s (json_mode=%s)", url, json_mode)

        try:
            with urllib.request.urlopen(req, timeout=cfg.request_timeout) as resp:
                body = _json.loads(resp.read())
        except Exception as e:
            raise RuntimeError(f"Ollama request to {url} failed: {e}") from e

        try:
            return body["message"]["content"]
        except (KeyError, TypeError) as e:
            raise RuntimeError(f"Unexpected Ollama response: {body}") from e

    def complete(self, prompt: str) -> str:
        """Send prompt to the model and return the completion text."""
        return self._call_ollama(prompt, json_mode=False)

    def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Send prompt and request JSON-formatted output via Ollama's native JSON mode."""
        return self._call_ollama(prompt, json_mode=True, system_prompt=system_prompt)
