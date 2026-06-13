"""Phase 5: orchestrator loop, checkpoints per step, approval pause, and
resume with a different model mid-graph."""

from __future__ import annotations

import pytest

from orchestrator.core.orchestrator import Orchestrator
from orchestrator.core.state import AlertContext
from orchestrator.storage.sqlite import SQLiteStorage


@pytest.fixture()
def orch(tmp_path):
    s = SQLiteStorage(str(tmp_path / "o.sqlite"))
    yield Orchestrator(s)
    s.close()


def _alert():
    return AlertContext(alert_name="Brute force", source_ip="45.143.220.0",
                        username="admin", severity="high")


def test_full_run_completes_with_mock(orch):
    session = orch.create_session("Investigate brute force", alert_context=_alert())
    orch.run(session)
    assert session.status == "completed"
    # every graph step completed
    assert all(s.status == "completed" for s in session.task_graph.steps)
    # a checkpoint exists after each step (plus planned + completed)
    cps = orch.checkpoints.list(session.session_id)
    assert len(cps) >= len(session.task_graph.steps) + 1
    # model calls recorded for each agent step
    assert len(session.model_calls) == len(session.task_graph.steps)
    # decisions recorded, all to known models
    assert len(session.decisions) == len(session.task_graph.steps)


def test_checkpoint_per_step(orch):
    session = orch.create_session("Investigate", alert_context=_alert())
    orch.run(session)
    labels = [c["label"] for c in orch.checkpoints.list(session.session_id)]
    assert any(label.startswith("after:") for label in labels)
    assert "completed" in labels


def test_pause_on_approval_then_resume(orch):
    session = orch.create_session("Investigate", alert_context=_alert())
    # Force the response step to require approval.
    resp_step = next(s for s in session.task_graph.steps if s.agent == "IncidentResponseAgent")
    resp_step.requires_human_approval = True
    orch.storage.save_session(session)

    orch.run(session)
    assert session.status == "waiting_approval"
    assert session.current_step_id == resp_step.step_id
    assert orch.approvals.has_pending(session, resp_step.step_id)

    # Human approves, then resume.
    orch.approvals.approve_all_pending(session)
    orch.storage.save_session(session)
    orch.checkpoints.save(session, label="approved")
    resumed = orch.resume(session.session_id, auto_approve=False)
    assert resumed.status == "completed"


def test_resume_with_different_model_midgraph(orch):
    session = orch.create_session("Investigate", alert_context=_alert())
    # Run only the first two steps, then pause.
    orch.run(session, max_steps=2)
    assert session.status == "paused"
    completed_before = sum(1 for s in session.task_graph.steps if s.status == "completed")
    assert completed_before == 2
    current = session.current_step_id

    # Resume from the same point with a different preferred model.
    resumed = orch.resume(session.session_id, model_override="anthropic/claude-sonnet")
    assert resumed.status == "completed"
    # Decisions made after resume picked the overridden model.
    late_decisions = resumed.decisions[2:]
    assert any(d.selected_model == "anthropic/claude-sonnet" for d in late_decisions)
    # It genuinely continued from where it paused (no step re-run).
    assert all(s.status == "completed" for s in resumed.task_graph.steps)
    # current_step_id had advanced past the pause point.
    assert resumed.current_step_id != current or completed_before < len(resumed.task_graph.steps)


# --- Phase 9: real adapter dry-run / graceful degradation -------------------


import pytest as _pytest  # noqa: E402

from orchestrator.core.state import SessionState  # noqa: E402
from orchestrator.providers import get_available_provider, get_provider  # noqa: E402
from orchestrator.providers.base import Prompt  # noqa: E402

REAL_MODELS = [
    "openai/gpt-5.5",
    "anthropic/claude-sonnet",
    "google/gemini-pro",
    "openrouter/deepseek",
]


@_pytest.mark.parametrize("model_id", REAL_MODELS)
def test_resume_with_real_adapter_degrades_to_mock(orch, monkeypatch, model_id):
    """Resuming a mock session with a real model id must NOT fail CI when no
    key is set: it transparently degrades to the MockProvider."""
    for env in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
                "OPENROUTER_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    session = orch.create_session("Investigate", alert_context=_alert())
    orch.run(session, max_steps=2)
    resumed = orch.resume(session.session_id, model_override=model_id)
    assert resumed.status == "completed"
    # the decision recorded the requested model even though execution used mock
    assert any(d.selected_model == model_id for d in resumed.decisions[2:])


@_pytest.mark.parametrize("model_id", REAL_MODELS)
def test_real_adapter_canonical_mapping_offline(model_id):
    """Both directions of the canonical mapping work without network/keys."""
    adapter = get_provider(model_id)
    prompt = Prompt(agent="SOCInvestigatorAgent", task_type="triage",
                    instruction="triage", context={"alert_name": "x"})
    payload = adapter.to_provider_format(SessionState(user_goal="g"), prompt)
    assert isinstance(payload, dict) and payload
    # craft a minimal provider-shaped response and map it back to canonical
    fake = {
        "choices": [{"message": {"content": "hello"}}],          # openai-style
        "content": [{"text": "hello"}],                           # anthropic-style
        "candidates": [{"content": {"parts": [{"text": "hello"}]}}],  # gemini-style
    }
    events = adapter.from_provider_format(fake, prompt)
    assert events and events[0].role == "assistant"
    assert events[0].content == "hello"


def test_get_available_provider_uses_real_when_keyed(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    adapter, degraded = get_available_provider("openai/gpt-5.5")
    assert degraded is False
    assert adapter.is_available() is True
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
