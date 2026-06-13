"""OpenRouter adapter — OpenAI-compatible API at a different base URL."""

from __future__ import annotations

from orchestrator.providers.openai_provider import OpenAICompatibleAdapter


class OpenRouterAdapter(OpenAICompatibleAdapter):
    provider = "openrouter"
    api_key_env = "OPENROUTER_API_KEY"
    default_base_url = "https://openrouter.ai/api/v1"
