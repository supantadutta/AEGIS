"""Phase 2: storage + checkpoint save/load/rollback round trips."""

from __future__ import annotations

import pytest

from orchestrator.core.checkpoints import CheckpointManager
from orchestrator.core.state import IOC, Finding, SessionState, TaskGraph, TaskStep
from orchestrator.storage.postgres import PostgresStorage
from orchestrator.storage.sqlite import SQLiteStorage


@pytest.fixture()
def storage(tmp_path):
    s = SQLiteStorage(str(tmp_path / "test.sqlite"))
    yield s
    s.close()


def _state() -> SessionState:
    step = TaskStep(name="Triage", agent="SOCInvestigatorAgent", task_type="triage")
    st = SessionState(user_goal="investigate", task_graph=TaskGraph(steps=[step]))
    st.current_step_id = step.step_id
    return st


def test_session_save_load(storage):
    st = _state()
    storage.save_session(st)
    loaded = storage.load_session(st.session_id)
    assert loaded.session_id == st.session_id
    assert loaded.user_goal == "investigate"
    assert any(s["session_id"] == st.session_id for s in storage.list_sessions())


def test_checkpoint_save_load(storage):
    cm = CheckpointManager(storage)
    st = _state()
    storage.save_session(st)
    ref1 = cm.save(st, label="after-intake")

    st.indicators_of_compromise.append(IOC(type="ip", value="45.143.220.0"))
    st.investigation_findings.append(Finding(title="bf", detail="many fails"))
    ref2 = cm.save(st, label="after-triage")

    cps = cm.list(st.session_id)
    assert len(cps) == 2
    restored1 = cm.load(ref1.checkpoint_id)
    restored2 = cm.load(ref2.checkpoint_id)
    assert len(restored1.indicators_of_compromise) == 0
    assert len(restored2.indicators_of_compromise) == 1
    assert "indicators_of_compromise:0->1" in ref2.diff_summary


def test_rollback(storage):
    cm = CheckpointManager(storage)
    st = _state()
    storage.save_session(st)
    ref1 = cm.save(st, label="clean")

    st.indicators_of_compromise.append(IOC(type="ip", value="1.2.3.4"))
    cm.save(st, label="dirty")
    storage.save_session(st)
    assert len(storage.load_session(st.session_id).indicators_of_compromise) == 1

    restored = cm.rollback(st.session_id, ref1.checkpoint_id)
    assert len(restored.indicators_of_compromise) == 0
    # Live session reflects the rollback.
    assert len(storage.load_session(st.session_id).indicators_of_compromise) == 0
    # Rollback itself is recorded as a new checkpoint (history preserved).
    assert len(cm.list(st.session_id)) == 3


def test_feedback_success_rate(storage):
    assert storage.feedback_success_rate("mock/mock-model", "triage") is None
    storage.save_feedback("s1", "mock/mock-model", "triage", {"classification_correct": True})
    storage.save_feedback("s2", "mock/mock-model", "triage", {"classification_correct": False})
    rate = storage.feedback_success_rate("mock/mock-model", "triage")
    assert rate == 0.5


def test_postgres_stub_raises():
    with pytest.raises(NotImplementedError):
        PostgresStorage("postgres://x")
