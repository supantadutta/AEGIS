"""Provider adapter interface.

Agents are provider-agnostic: they build a canonical `Prompt`, call
`generate()`, and consume a canonical `ProviderResponse`. Each adapter knows
how to turn the canonical SessionState/Prompt into its own request format and
map the raw response back into canonical CanonicalMessage events — which is
what makes a session resumable with a different model at any step.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

from orchestrator.core.state import CanonicalMessage, SessionState, utcnow


class ProviderConfigError(RuntimeError):
    """Raised when a real provider is selected but not configured (no key)."""


class Prompt(BaseModel):
    """Canonical, provider-independent request built by an agent."""

    agent: str
    task_type: str
    system: str = ""
    instruction: str = ""
    context: dict[str, Any] = Field(default_factory=dict)
    response_hint: str = ""  # short description of the structure expected back


class ProviderResponse(BaseModel):
    """Canonical response. `structured` carries any JSON the agent asked for."""

    model: str
    text: str = ""
    structured: dict[str, Any] | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float = 0.0
    latency_ms: float = 0.0
    raw: dict[str, Any] | None = None
    timestamp: Any = Field(default_factory=utcnow)


class ProviderAdapter(ABC):
    """Base class every provider (and the mock) implements."""

    #: provider key as used in models.yaml (e.g. "openai", "anthropic", "mock")
    provider: str = "base"

    def __init__(self, model_id: str) -> None:
        self.model_id = model_id

    @abstractmethod
    def is_available(self) -> bool:
        """True when this adapter can actually make calls (key/url present)."""

    @abstractmethod
    def generate(
        self,
        session: SessionState,
        prompt: Prompt,
        tools: list[Any] | None = None,
    ) -> ProviderResponse:
        """Run one model turn and return a canonical response."""

    @abstractmethod
    def to_provider_format(self, session: SessionState, prompt: Prompt) -> dict[str, Any]:
        """Render SessionState + Prompt into this provider's request payload."""

    @abstractmethod
    def from_provider_format(self, raw: dict[str, Any], prompt: Prompt) -> list[CanonicalMessage]:
        """Map a raw provider response into canonical events."""

    # --- shared helpers ---
    @staticmethod
    def _approx_tokens(text: str) -> int:
        # Rough heuristic: ~4 chars/token. Good enough for accounting/tests.
        return max(1, len(text) // 4)

    def _timed(self):  # pragma: no cover - tiny helper
        return time.perf_counter()
