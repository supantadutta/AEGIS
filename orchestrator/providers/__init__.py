"""Provider registry and factory.

`get_provider(model_id)` returns the right adapter for a model id from
models.yaml (e.g. "anthropic/claude-sonnet"). `get_available_provider` adds
graceful degradation to the MockProvider when a real provider has no key,
which keeps the whole pipeline runnable with zero configuration.
"""

from __future__ import annotations

from orchestrator.providers.anthropic_provider import AnthropicAdapter
from orchestrator.providers.base import (
    Prompt,
    ProviderAdapter,
    ProviderConfigError,
    ProviderResponse,
)
from orchestrator.providers.gemini_provider import GeminiAdapter
from orchestrator.providers.mock_provider import MockProvider
from orchestrator.providers.ollama_provider import OllamaAdapter
from orchestrator.providers.openai_provider import OpenAICompatibleAdapter
from orchestrator.providers.openrouter_provider import OpenRouterAdapter

__all__ = [
    "Prompt",
    "ProviderAdapter",
    "ProviderConfigError",
    "ProviderResponse",
    "MockProvider",
    "get_provider",
    "get_available_provider",
]

_PREFIX_MAP: dict[str, type[ProviderAdapter]] = {
    "openai": OpenAICompatibleAdapter,
    "anthropic": AnthropicAdapter,
    "google": GeminiAdapter,
    "openrouter": OpenRouterAdapter,
    "ollama": OllamaAdapter,
    "mock": MockProvider,
}


def get_provider(model_id: str) -> ProviderAdapter:
    """Instantiate the adapter for a model id without any availability check."""
    prefix = model_id.split("/", 1)[0]
    cls = _PREFIX_MAP.get(prefix)
    if cls is None:
        raise ValueError(f"unknown provider prefix in model id: {model_id!r}")
    return cls(model_id)


def get_available_provider(
    model_id: str, *, allow_mock_fallback: bool = True
) -> tuple[ProviderAdapter, bool]:
    """Return (adapter, degraded_to_mock).

    If the requested adapter is not available (no key) and fallback is allowed,
    transparently return the MockProvider so the pipeline keeps running.
    """
    adapter = get_provider(model_id)
    if adapter.is_available():
        return adapter, False
    if allow_mock_fallback:
        return MockProvider(), True
    raise ProviderConfigError(f"{model_id} is not configured and mock fallback is disabled")
