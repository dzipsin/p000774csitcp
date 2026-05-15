"""
model_provider.py - Unified interface for local and remote LLM backends

Provides a single ModelProvider abstraction so the rest of the codebase never
has to know whether it is talking to Anthropic's API, a local Ollama instance,
or a llama.cpp HTTP server.

Public surface:
  ModelConfig           all provider configuration in one dataclass
  ModelProvider         abstract base; one method: .complete(prompt) -> str
  AnthropicProvider     remote: Anthropic Messages API
  OllamaProvider        local: Ollama REST API  (http://localhost:11434)
  LlamaCppProvider      local: llama.cpp HTTP server (http://localhost:8080)
  create_provider(cfg)  factory; returns the right provider for a ModelConfig

Configuration:
  The simplest integration is via environment variables fed into ModelConfig.
  See ModelConfig field docstrings for the expected variable names.
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
    """Enum of Provider Names"""
    ANTHROPIC  = "anthropic"    # Remote
    OLLAMA     = "ollama"       # Local
    LLAMACPP   = "llamacpp"     # Local


@dataclass
class ModelConfig:
    """All configuration needed to instantiate any supported ModelProvider.

    Only fields relevant to the chosen ``provider`` are used; the rest are
    ignored, so a single config object can be kept in app.py and swapped by
    changing only ``provider``.

    Environment-variable defaults are resolved at instantiation time.
    """

    provider: ProviderType = ProviderType.ANTHROPIC

    # --- Shared ---
    model: str = "llama3"
    """Model identifier.
    Anthropic  : e.g. 'claude-opus-4-6', 'claude-sonnet-4-6'
    Ollama     : e.g. 'llama3', 'mistral', 'gemma2'
    llama.cpp  : ignored (model is loaded at server start)
    """

    max_tokens: int = 1024
    """Maximum tokens in the completion response."""

    temperature: float = 0.2
    """Sampling temperature (0.0 = deterministic, 1.0 = creative)."""

    system_prompt: Optional[str] = None
    """Optional system / instruction prompt prepended to every request."""

    # --- Remote ---
    api_key: str = field(default_factory=lambda: os.getenv("API_KEY", ""))
    """API key. Defaults to API_KEY env var."""

    # --- Local ---
    base_url: str = field(default_factory=lambda: os.getenv("LOCAL_MODEL_URL", ""))
    """Base URL of the local model server.
    Ollama    default : http://localhost:11434
    llama.cpp default : http://localhost:8080
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


class AnthropicProvider(ModelProvider):
    """Calls the Anthropic Messages API.

    Requires:
        pip install anthropic

    The ``anthropic`` package is imported lazily so the rest of the codebase
    does not break when it is not installed.
    """

    def __init__(self, config: ModelConfig):
        self._config = config
        if not config.api_key:
            raise ValueError(
                "AnthropicProvider requires an API key. "
                "Set API_KEY or pass api_key in ModelConfig."
            )
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "anthropic package not installed. Run: pip install anthropic"
            ) from e
        self._client = anthropic.Anthropic(api_key=config.api_key)

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.ANTHROPIC

    @property
    def model_name(self) -> str:
        return self._config.model

    def complete(self, prompt: str) -> str:
        cfg = self._config
        kwargs: dict = dict(
            model=cfg.model,
            max_tokens=cfg.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        if cfg.system_prompt:
            kwargs["system"] = cfg.system_prompt
        if cfg.temperature is not None:
            kwargs["temperature"] = cfg.temperature

        message = self._client.messages.create(**kwargs)
        return message.content[0].text

    def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        cfg = self._config
        kwargs: dict = dict(
            model=cfg.model,
            max_tokens=cfg.max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        sys_prompt = system_prompt or cfg.system_prompt
        if sys_prompt:
            kwargs["system"] = sys_prompt
        if cfg.temperature is not None:
            kwargs["temperature"] = cfg.temperature

        message = self._client.messages.create(**kwargs)
        return message.content[0].text


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


class LlamaCppProvider(ModelProvider):
    """Calls a llama.cpp HTTP server (--server mode).

    Start the server with:
        ./llama-server -m model.gguf --port 8080

    API reference: https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md
    """

    def __init__(self, config: ModelConfig):
        if not config.base_url:
            raise ValueError(
                "LlamaCppProvider requires a base_url. "
                "Set base_url in [model.llamacpp] in app.config or via LOCAL_MODEL_URL."
            )
        self._config = config
        self._base = config.base_url.rstrip("/")

    @property
    def provider_type(self) -> ProviderType:
        return ProviderType.LLAMACPP

    @property
    def model_name(self) -> str:
        return self._config.model

    def _call_llamacpp(
        self,
        prompt: str,
        json_mode: bool = False,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Internal method that handles both text and JSON mode requests."""
        cfg = self._config

        sys = system_prompt if system_prompt is not None else cfg.system_prompt
        full_prompt = prompt
        if sys:
            full_prompt = f"{sys}\n\n{prompt}"

        payload: dict = {
            "prompt": full_prompt,
            "n_predict": cfg.max_tokens,
            "temperature": cfg.temperature,
            "stop": [],
        }

        if json_mode:
            payload["json_schema"] = {"type": "object"}

        data = _json.dumps(payload).encode()
        url = f"{self._base}/completion"
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=cfg.request_timeout) as resp:
                body = _json.loads(resp.read())
        except Exception as e:
            raise RuntimeError(f"llama.cpp request to {url} failed: {e}") from e

        try:
            return body["content"]
        except (KeyError, TypeError) as e:
            raise RuntimeError(f"Unexpected llama.cpp response shape: {body}") from e

    def complete(self, prompt: str) -> str:
        return self._call_llamacpp(prompt, json_mode=False)

    def complete_json(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        """Use llama.cpp's JSON schema mode for structured output."""
        return self._call_llamacpp(
            prompt, json_mode=True, system_prompt=system_prompt,
        )


_PROVIDER_MAP: Dict[ProviderType, Type[ModelProvider]] = {
    ProviderType.ANTHROPIC: AnthropicProvider,
    ProviderType.OLLAMA:    OllamaProvider,
    ProviderType.LLAMACPP:  LlamaCppProvider,
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