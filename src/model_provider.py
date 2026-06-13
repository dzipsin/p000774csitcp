"""
model_provider.py - LLM backend interface + Ollama implementation

Provides a ModelProvider abstraction so the rest of the codebase never has to
know which model server it is talking to.  Adding a new backend (Anthropic,
llama.cpp, vLLM, …) requires only:
  1. A new ProviderType enum member.
  2. A class that extends ModelProvider.
  3. A branch in create_provider().
  4. A [model.<name>] section in app.config.

Public surface:
  ProviderType          enum of supported backends ("ollama", …)
  ModelConfig           all provider configuration in one dataclass
  ModelProvider         abstract base; complete() + complete_json()
  OllamaProvider        local: Ollama REST API (http://localhost:11434)
  create_provider(cfg)  factory; returns the right provider for a ModelConfig
"""

from __future__ import annotations

import json as _json
import logging
import os
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger(__name__)


class ProviderType(str, Enum):
    OLLAMA = "ollama"


@dataclass
class ModelConfig:
    """All configuration needed to instantiate any supported ModelProvider.

    Only fields relevant to the chosen ``provider`` are used; the rest are
    ignored, so a single config object can be kept in app.py and swapped by
    changing only ``provider``.

    Environment-variable defaults are resolved at instantiation time.
    """

    provider: ProviderType = ProviderType.OLLAMA

    model: str = "llama3"
    """Model identifier, e.g. 'qwen2.5:3b', 'llama3.2', 'claude-sonnet-4-6'."""

    max_tokens: int = 1024
    """Maximum tokens in the completion response."""

    temperature: float = 0.2
    """Sampling temperature (0.0 = deterministic, 1.0 = creative)."""

    system_prompt: Optional[str] = None
    """Optional system prompt prepended to every request."""

    base_url: str = field(default_factory=lambda: os.getenv("LOCAL_MODEL_URL", ""))
    """Base URL of the model server.  Override via LOCAL_MODEL_URL env var."""

    request_timeout: int = 120
    """HTTP request timeout in seconds."""


class ModelProvider(ABC):
    """Single-method interface for any LLM backend.

    Implementors must be thread-safe (the AI analyser calls complete() from
    worker threads).
    """

    @abstractmethod
    def complete(self, prompt: str) -> str:
        """Send *prompt* to the model and return the completion text.

        Raises:
            RuntimeError if the backend returns an error or is unreachable.
        """

    def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Send *prompt* and request JSON-formatted output.

        Default implementation prepends the system prompt as plain text and
        calls complete().  Providers with native JSON mode (e.g. Ollama) should
        override this for more reliable structured output.

        Raises:
            RuntimeError if the backend returns an error or is unreachable.
        """
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        return self.complete(full_prompt)

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The model identifier string (e.g. 'qwen2.5:3b')."""


class OllamaProvider(ModelProvider):
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
        """Use Ollama's native JSON mode for reliable structured output."""
        return self._call_ollama(prompt, json_mode=True, system_prompt=system_prompt)


def create_provider(cfg: ModelConfig) -> ModelProvider:
    """Factory: return the correct ModelProvider for the given config.

    Raises:
        ValueError if cfg.provider is not a known ProviderType.
    """
    if cfg.provider == ProviderType.OLLAMA:
        return OllamaProvider(cfg)
    raise ValueError(f"Unknown provider: {cfg.provider!r}")
