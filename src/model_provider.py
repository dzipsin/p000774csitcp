"""
model_provider.py - Local LLM backend interface

Provides a ModelProvider abstraction so the rest of the codebase never has to
know which local model server it is talking to. Currently only Ollama is
wired in; the abstract base + factory are kept so a second local backend
(llama.cpp, vLLM, etc.) can drop in without touching every call site.

Capstone constraint: no paid / remote APIs. Local-only.

Public surface:
  ModelConfig           all provider configuration in one dataclass
  ModelProvider         abstract base; one method: .complete(prompt) -> str
  OllamaProvider        local: Ollama REST API  (http://localhost:11434)
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
from typing import Dict, Optional, Type

log = logging.getLogger(__name__)


class ProviderType(str, Enum):
    """Enum of supported provider names.

    Only OLLAMA ships today. The enum is kept (rather than a bare string)
    so config validation in app.py catches typos at startup time.
    """
    OLLAMA = "ollama"       # Local


@dataclass
class ModelConfig:
    """All configuration needed to instantiate any supported ModelProvider.

    Only fields relevant to the chosen ``provider`` are used; the rest are
    ignored, so a single config object can be kept in app.py and swapped by
    changing only ``provider``.

    Environment-variable defaults are resolved at instantiation time.
    """

    provider: ProviderType = ProviderType.OLLAMA

    # --- Shared ---
    model: str = "llama3"
    """Model identifier.
    Ollama: e.g. 'qwen2.5:3b', 'llama3.2', 'mistral'.
    """

    max_tokens: int = 1024
    """Maximum tokens in the completion response."""

    temperature: float = 0.2
    """Sampling temperature (0.0 = deterministic, 1.0 = creative)."""

    system_prompt: Optional[str] = None
    """Optional system / instruction prompt prepended to every request."""

    # --- Local server ---
    base_url: str = field(default_factory=lambda: os.getenv("LOCAL_MODEL_URL", ""))
    """Base URL of the local model server (default http://localhost:11434).
    Override via LOCAL_MODEL_URL env var.
    """

    request_timeout: int = 120
    """HTTP request timeout in seconds for local model calls."""


class ModelProvider(ABC):
    """Single-method interface for any LLM backend.

    Implementors must be thread-safe (the AI analyser may call complete()
    from a worker thread).
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

        Args:
            prompt: The user prompt.
            system_prompt: Optional system prompt for this specific call.
                           Does NOT mutate the provider's default config.

        Default implementation falls back to complete(). Providers that
        support native JSON mode (e.g. Ollama) override this for
        more reliable structured output.

        Raises:
            RuntimeError if the backend returns an error or is unreachable.
        """
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        return self.complete(full_prompt)

    @property
    @abstractmethod
    def provider_type(self) -> ProviderType:
        """The ProviderType this instance represents."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        """The model identifier string (e.g. 'llama3.2', 'claude-sonnet-4-6')."""


class OllamaProvider(ModelProvider):
    """Calls a local Ollama server via its REST API.

    Ollama must be running and the requested model must be pulled, e.g.:
        ollama pull llama3

    API reference: https://github.com/ollama/ollama/blob/main/docs/api.md
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
    def provider_type(self) -> ProviderType:
        return ProviderType.OLLAMA

    @property
    def model_name(self) -> str:
        return self._config.model

    def _call_ollama(
        self,
        prompt: str,
        json_mode: bool = False,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Internal method that handles both text and JSON mode requests.

        Args:
            prompt: The user prompt.
            json_mode: If True, set Ollama's format to "json".
            system_prompt: If provided, used as the system message for this
                           call only. Does not mutate config.
        """
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
        return self._call_ollama(prompt, json_mode=False)

    def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Use Ollama's native JSON mode for reliable structured output."""
        return self._call_ollama(
            prompt, json_mode=True, system_prompt=system_prompt,
        )


# Provider registry. Add new entries when wiring additional local backends.
_PROVIDER_MAP: Dict[ProviderType, Type[ModelProvider]] = {
    ProviderType.OLLAMA: OllamaProvider,
}


def create_provider(config: ModelConfig) -> ModelProvider:
    """Instantiate and return the correct ModelProvider for *config*.

    Usage::

        cfg = ModelConfig(provider=ProviderType.OLLAMA, model="llama3")
        provider = create_provider(cfg)
        response = provider.complete("Explain this alert …")

    Raises:
        ValueError if config.provider is not a known ProviderType.
    """
    provider_class = _PROVIDER_MAP.get(config.provider)
    if provider_class is None:
        raise ValueError(
            f"Unknown provider '{config.provider}'. "
            f"Valid options: {[p.value for p in ProviderType]}"
        )
    # _PROVIDER_MAP only contains concrete subclasses; Pylance can't narrow
    # abstract Type[ModelProvider] here so we silence the false positive.
    return provider_class(config)  # type: ignore[abstract]