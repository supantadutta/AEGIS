"""Phase 3: every adapter conforms to the ProviderAdapter interface and the
MockProvider produces valid canonical events with zero configuration.
"""

from __future__ import annotations

import pytest

from orchestrator.core.state import CanonicalMessage, SessionState
from orchestrator.providers import get_available_provider, get_provider
from orchestrator.providers.base import Prompt, ProviderAdapter, ProviderConfigError
from orchestrator.providers.mock_provider import MockProvider

ALL_MODELS = [
    "openai/gpt-5.5",
    "anthropic/claude-sonnet",
    "google/gemini-pro",
    "openrouter/deepseek",
    "ollama/llama",
    "mock/mock-model",
]


def _prompt(agent="SOCInvestigatorAgent"):
    return Prompt(
        agent=agent,
        task_type="triage",
        instruction="Triage this alert",
        context={"alert_name": "Brute force", "source_ip": "45.143.220.0",
                 "username": "admin", "failed_logins": 47},
    )


@pytest.mark.parametrize("model_id", ALL_MODELS)
def test_adapter_conforms(model_id):
    adapter = get_provider(model_id)
    assert isinstance(adapter, ProviderAdapter)
    assert hasattr(adapter, "generate")
    assert hasattr(adapter, "to_provider_format")
    assert hasattr(adapter, "from_provider_format")
    assert isinstance(adapter.is_available(), bool)
    # to_provider_format works offline for every adapter.
    payload = adapter.to_provider_format(SessionState(user_goal="x"), _prompt())
    assert isinstance(payload, dict)


def test_mock_always_available_and_valid():
    mock = MockProvider()
    assert mock.is_available() is True
    state = SessionState(user_goal="investigate")
    resp = mock.generate(state, _prompt())
    assert resp.model == "mock/mock-model"
    assert resp.text
    assert resp.structured is not None
    assert resp.structured["classification"]
    assert 0.0 <= resp.structured["confidence"] <= 1.0
    # canonical event mapping
    events = mock.from_provider_format(resp.raw, _prompt())
    assert events and isinstance(events[0], CanonicalMessage)
    assert events[0].role == "assistant"


def test_mock_deterministic():
    mock = MockProvider()
    state = SessionState(user_goal="x")
    a = mock.generate(state, _prompt())
    b = mock.generate(state, _prompt())
    assert a.text == b.text
    assert a.structured == b.structured


def test_real_adapter_without_key_raises():
    adapter = get_provider("openai/gpt-5.5")
    if not adapter.is_available():  # no key in CI
        with pytest.raises(ProviderConfigError):
            adapter.generate(SessionState(user_goal="x"), _prompt())


def test_degrades_to_mock_without_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    adapter, degraded = get_available_provider("openai/gpt-5.5")
    assert degraded is True
    assert isinstance(adapter, MockProvider)
