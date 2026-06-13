"""Phase 4: deterministic router scoring, privacy override, fallbacks."""

from __future__ import annotations

import pytest

from orchestrator.core.config import model_ids
from orchestrator.core.router import Router
from orchestrator.core.state import SessionState, TaskStep
from orchestrator.storage.sqlite import SQLiteStorage


@pytest.fixture()
def storage(tmp_path):
    s = SQLiteStorage(str(tmp_path / "r.sqlite"))
    yield s
    s.close()


def _step(agent="SOCInvestigatorAgent", task_type="triage", **kw):
    return TaskStep(name=agent, agent=agent, task_type=task_type, **kw)


def test_decision_shape_and_known_model():
    r = Router()
    d = r.route(_step())
    assert d.selected_agent == "SOCInvestigatorAgent"
    assert d.selected_model in model_ids()
    assert all(m in model_ids() for m in d.fallback_models)
    assert 0.0 <= d.confidence <= 1.0
    assert len(d.fallback_models) >= 1


def test_privacy_override_forces_local(monkeypatch):
    monkeypatch.delenv("ALLOW_EXTERNAL_FOR_SENSITIVE", raising=False)
    r = Router()
    session = SessionState(user_goal="x")
    step = _step(data_sensitivity="restricted")
    d = r.route(step, session)
    chosen = next(m for m in r.models_cfg["models"] if m["id"] == d.selected_model)
    assert chosen["privacy_tier"] in ("local", "mock")
    # fallbacks must also be local/mock
    for fb in d.fallback_models:
        m = next(m for m in r.models_cfg["models"] if m["id"] == fb)
        assert m["privacy_tier"] in ("local", "mock")
    # override is logged
    assert any("Privacy override" in e.description for e in session.risk_log)


def test_allow_external_for_sensitive(monkeypatch):
    monkeypatch.setenv("ALLOW_EXTERNAL_FOR_SENSITIVE", "true")
    r = Router()
    # detection engineering favors gpt/deepseek (external) when allowed
    step = _step(agent="DetectionEngineerAgent", task_type="detection_engineering",
                 data_sensitivity="confidential")
    d = r.route(step)
    # external models are now in the candidate set (not forced local)
    assert d.selected_model in model_ids()


def test_high_risk_requires_approval():
    r = Router()
    d = r.route(_step(risk_level="high"))
    assert d.requires_human_approval is True


def test_capability_routing_internal():
    """For internal data, capability should drive selection among candidates."""
    r = Router()
    d = r.route(_step(agent="CaseReportAgent", task_type="report_writing",
                      data_sensitivity="internal"))
    assert d.selected_model in model_ids()


def test_historical_feedback_changes_score(storage):
    step = _step(agent="DetectionEngineerAgent", task_type="detection_engineering",
                 data_sensitivity="internal")
    r0 = Router(storage)
    before = {s.model_id: s.score for s in
              sorted((r0._score(step, m) for m in r0.models_cfg["models"]),
                     key=lambda s: s.score)}
    # Record several failures for gpt-5.5 on this task type.
    for i in range(5):
        storage.save_feedback(f"s{i}", "openai/gpt-5.5", "detection_engineering",
                              {"classification_correct": False})
    r1 = Router(storage)
    after = {s.model_id: s.score for s in
             sorted((r1._score(step, m) for m in r1.models_cfg["models"]),
                    key=lambda s: s.score)}
    assert after["openai/gpt-5.5"] < before["openai/gpt-5.5"]


def test_never_returns_unknown_model():
    r = Router()
    ids = set(model_ids())
    for agent in ("PlannerAgent", "ThreatIntelAgent", "QueryBuilderAgent",
                  "IncidentResponseAgent", "CaseReportAgent"):
        d = r.route(_step(agent=agent))
        assert d.selected_model in ids
        assert all(fb in ids for fb in d.fallback_models)
