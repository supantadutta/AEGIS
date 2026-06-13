"""Phase 11: dashboard serves a working UI/API against the SQLite DB."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from orchestrator.core.orchestrator import Orchestrator  # noqa: E402
from orchestrator.core.state import AlertContext  # noqa: E402
from orchestrator.storage.sqlite import SQLiteStorage  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db = str(tmp_path / "dash.sqlite")
    monkeypatch.setenv("AEGIS_DB_PATH", db)
    storage = SQLiteStorage(db)
    orch = Orchestrator(storage)
    session = orch.create_session(
        "Investigate", alert_context=AlertContext(
            alert_name="Brute force", source_ip="45.143.220.0", username="admin",
            severity="high", destination_host="DC01"))
    orch.run(session)
    storage.close()
    from orchestrator.dashboard.app import app
    return TestClient(app), session.session_id


def test_index_lists_sessions(client):
    c, sid = client
    res = c.get("/")
    assert res.status_code == 200
    assert sid[:8] in res.text


def test_session_detail_renders(client):
    c, sid = client
    res = c.get(f"/session/{sid}")
    assert res.status_code == 200
    assert "Task Graph" in res.text
    assert "MITRE" in res.text
    assert "45.143.220.0" in res.text
    assert "Analyst Report" in res.text


def test_api_session_json(client):
    c, sid = client
    res = c.get(f"/api/session/{sid}")
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"] == sid
    assert data["status"] == "completed"


def test_api_sessions_list(client):
    c, sid = client
    assert any(s["session_id"] == sid for s in c.get("/api/sessions").json())


def test_api_report(client):
    c, sid = client
    res = c.get(f"/api/session/{sid}/report", params={"type": "executive"})
    assert res.status_code == 200
    assert "Executive Summary" in res.json()["body"]


def test_feedback_post(client):
    c, sid = client
    res = c.post(f"/session/{sid}/feedback", data={"note": "looks good"},
                 follow_redirects=False)
    assert res.status_code == 303


def test_404_for_missing_session(client):
    c, _sid = client
    assert c.get("/api/session/does-not-exist").status_code == 404
