"""
ai_module.py - Data contracts and analyser interface for AI-generated reports

Responsibilities:
  - Define the AlertReport output schema (ThreatActor, SignatureHit, AlertReport)
  - Define AIAnalyzer, which accepts a ModelProvider and a list of AlertRecords
    and returns an AlertReport

Depends on:
  log_monitor.AlertRecord      - input data contract
  model_provider.ModelProvider - LLM backend abstraction (local or remote)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from log_monitor import AlertRecord
from model_provider import ModelProvider


# Output data contracts

@dataclass
class ThreatActor:
    """Aggregated view of a single source IP across an alert batch."""
    ip: str
    alert_count: int
    signatures: List[str]       # distinct signatures seen from this IP
    severity_labels: List[str]  # distinct severity labels seen
    targeted_ports: List[str]   # distinct destination ports targeted


@dataclass
class SignatureHit:
    """Aggregated view of a single Suricata signature across an alert batch."""
    signature: str
    signature_id: int
    category: str
    hit_count: int
    severity_label: str
    source_ips: List[str]       # distinct source IPs that triggered this sig


@dataclass
class AlertReport:
    """Structured output produced by AIAnalyzer.analyse().

    Consumers (web server, etc.) treat this as read-only.
    ``status`` signals whether analysis completed successfully.
    """

    # Identity
    report_id: str              # UUID4 string
    generated_at: str           # ISO-8601 UTC timestamp

    # Time window covered by this report
    period_start_epoch: float   # earliest alert.timestamp_epoch in the batch
    period_end_epoch: float     # latest  alert.timestamp_epoch in the batch
    period_start_display: str   # human-readable (e.g. "2025-01-01 12:00:00 UTC")
    period_end_display: str

    # Input summary
    alert_count: int
    severity_breakdown: dict    # {"critical": N, "high": N, "medium": N, "low": N}

    # Aggregated intelligence (populated before the LLM call)
    top_threat_actors: List[ThreatActor]
    top_signatures: List[SignatureHit]
    unique_source_ips: List[str]
    unique_categories: List[str]

    # AI narrative (populated after the LLM call)
    threat_summary: str         # executive summary from the model
    recommendations: List[str]  # actionable bullet points from the model

    # Model metadata
    model_used: Optional[str]
    provider_type: Optional[str]
    raw_ai_response: Optional[str]

    # Status
    status: str                 # "complete" | "error" | "pending"
    error: Optional[str]        # populated when status == "error"


class AIAnalyzer:
    """Produces an AlertReport from a batch of AlertRecords via a ModelProvider.

    Usage::

        from model_provider import create_provider, ModelConfig, ProviderType

        cfg      = ModelConfig(provider=ProviderType.OLLAMA, model="llama3")
        provider = create_provider(cfg)
        analyzer = AIAnalyzer(provider)
        report   = analyzer.analyse(alerts)

    Swapping between local and remote is entirely a ModelConfig concern. AIAnalyzer itself is provider-agnostic.
    """

    def __init__(self, provider: ModelProvider, top_n: int = 10):
        """
        Args:
            provider : A ModelProvider instance.
            top_n    : How many top threat actors / signatures to surface.
        """
        self._provider = provider
        self.top_n = top_n

    def analyse(self, alerts: List[AlertRecord]) -> AlertReport:
        """Analyse *alerts* and return an AlertReport.
        """
        raise NotImplementedError(
            "AIAnalyzer.analyse() is not yet implemented."
        )
