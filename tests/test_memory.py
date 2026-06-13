"""Phase 10: continuous learning (feedback -> routing) + threat-intel local-first."""

from __future__ import annotations

import pytest

from orchestrator.core.memory import Memory
from orchestrator.core.orchestrator import Orchestrator
from orchestrator.core.router import Router
from orchestrator.core.state import AlertContext, TaskStep
from orchestrator.storage.sqlite import SQLiteStorage
from orchestrator.tools.threat_intel import enrich, local_threat_intel_lookup


@pytest.fixture()
def storage(tmp_path):
    s = SQLiteStorage(str(tmp_path / "m.sqlite"))
    yield s
    s.close()


def _detection_step():
    return TaskStep(name="det", agent="DetectionEngineerAgent",
                    task_type="detection_engineering", data_sensitivity="internal")


def test_feedback_changes_router_score_before_after(storage):
    step = _detection_step()
    router_before = Router(storage)
    score_before = next(s.score for s in
                        (router_before._score(step, m) for m in router_before.models_cfg["models"])
                        if s.model_id == "openai/gpt-5.5")

    # Run a session, then record negative feedback for its decisions.
    orch = Orchestrator(storage)
    session = orch.create_session(
        "Investigate", alert_context=AlertContext(alert_name="x", source_ip="1.2.3.4"),
        security_task_type="detection_engineering")
    orch.run(session)
    # Force the relevant model/task into feedback as failures.
    for _ in range(5):
        storage.save_feedback(session.session_id, "openai/gpt-5.5",
                              "detection_engineering", {"classification_correct": False})

    router_after = Router(storage)
    score_after = next(s.score for s in
                       (router_after._score(step, m) for m in router_after.models_cfg["models"])
                       if s.model_id == "openai/gpt-5.5")
    assert score_after < score_before


def test_memory_records_feedback_for_each_decision(storage):
    orch = Orchestrator(storage)
    session = orch.create_session("Investigate",
                                  alert_context=AlertContext(alert_name="x"))
    orch.run(session)
    n = Memory(storage).record_feedback(session, classification_correct=True,
                                        tuning="raise threshold to 15")
    assert n == len(session.decisions) > 0
    # tuning promoted into knowledge base
    kb = Memory(storage).get_knowledge("tuning:soc_investigation")
    assert any("threshold" in k for k in kb)


def test_threat_intel_local_first(storage):
    # Blocklisted IP -> malicious; allowlisted -> benign; unknown -> unknown.
    assert local_threat_intel_lookup("45.143.220.0").verdict == "malicious"
    assert local_threat_intel_lookup("8.8.8.8").verdict == "benign"
    assert local_threat_intel_lookup("203.0.113.77").verdict == "unknown"


def test_external_sources_disabled_but_present(monkeypatch):
    for env in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "MISP_API_KEY"):
        monkeypatch.delenv(env, raising=False)
    results = enrich("45.143.220.0", "ip")
    sources = {r.source for r in results}
    # local result present and malicious
    assert "local_blocklist" in sources
    # disabled external sources appear with verdict=unknown + clear summary
    disabled = [r for r in results if r.summary == "disabled: no API key configured"]
    assert disabled, "disabled external sources must still be reported"
    assert all(r.verdict == "unknown" for r in disabled)


def test_knowledge_base_roundtrip(storage):
    m = Memory(storage)
    m.add_knowledge("playbook:brute-force", "lockout after 5 fails", "s1")
    assert "lockout after 5 fails" in m.get_knowledge("playbook:brute-force")
