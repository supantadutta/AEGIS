"""Ollama local adapter. Uses the OpenAI-compatible endpoint Ollama exposes at
/v1/chat/completions, so no API key is required — only a reachable base URL.
"""

from __future__ import annotations

import os

from orchestrator.providers.openai_provider import OpenAICompatibleAdapter


class OllamaAdapter(OpenAICompatibleAdapter):
    provider = "ollama"
    api_key_env = "OLLAMA_API_KEY"  # usually unused

    @property
    def base_url(self) -> str:
        root = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        return f"{root}/v1"

    @property
    def api_key(self) -> str | None:
        # Ollama needs no key; a dummy token keeps the OpenAI client happy.
        return os.getenv(self.api_key_env, "ollama")

    def is_available(self) -> bool:
        # Available whenever a base URL is configured (default localhost).
        return bool(os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"))
