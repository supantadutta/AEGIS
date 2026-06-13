"""AEGIS dashboard — FastAPI backend + server-rendered HTML.

Reads the same SQLite DB the CLI writes (AEGIS_DB_PATH). Shows sessions, the
task graph, router decisions, model calls, IOCs, timeline, evidence, MITRE
mapping, queries, detections, the approval queue, the report, and a feedback
form. Run: `uvicorn orchestrator.dashboard.app:app`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from orchestrator.core.approvals import ApprovalManager
from orchestrator.core.memory import Memory
from orchestrator.core.state import SessionState
from orchestrator.storage.sqlite import SQLiteStorage
from orchestrator.tools.reports import REPORT_TYPES, render_report

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(["html"]),
)


def _render(name: str, **ctx: Any) -> HTMLResponse:
    return HTMLResponse(_env.get_template(name).render(**ctx))


app = FastAPI(title="AEGIS Dashboard", version="0.1.0")


def _storage() -> SQLiteStorage:
    return SQLiteStorage(os.getenv("AEGIS_DB_PATH", "aegis.sqlite"))


def _load(session_id: str) -> SessionState:
    storage = _storage()
    try:
        try:
            return storage.load_session(session_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="session not found") from exc
    finally:
        storage.close()


# --- HTML pages -------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> Any:
    storage = _storage()
    try:
        sessions = storage.list_sessions()
    finally:
        storage.close()
    return _render("index.html", sessions=sessions)


@app.get("/session/{session_id}", response_class=HTMLResponse)
def session_detail(request: Request, session_id: str) -> Any:
    session = _load(session_id)
    report = ""
    try:
        report = render_report(session, "analyst")
    except Exception:  # noqa: BLE001
        pass
    pending = [a for a in session.approval_log if a.status == "pending"]
    return _render("session.html", s=session, report=report,
                   pending=pending, report_types=REPORT_TYPES)


# --- JSON API ---------------------------------------------------------------


@app.get("/api/sessions")
def api_sessions() -> Any:
    storage = _storage()
    try:
        return storage.list_sessions()
    finally:
        storage.close()


@app.get("/api/session/{session_id}")
def api_session(session_id: str) -> Any:
    return JSONResponse(content=_load(session_id).model_dump(mode="json"))


@app.get("/api/session/{session_id}/report")
def api_report(session_id: str, type: str = "analyst") -> Any:
    session = _load(session_id)
    try:
        return {"type": type, "body": render_report(session, type)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/session/{session_id}/checkpoints")
def api_checkpoints(session_id: str) -> Any:
    storage = _storage()
    try:
        return storage.list_checkpoints(session_id)
    finally:
        storage.close()


@app.post("/session/{session_id}/approve")
def approve(session_id: str) -> Any:
    storage = _storage()
    try:
        session = storage.load_session(session_id)
        ApprovalManager().approve_all_pending(session, decided_by="dashboard")
        storage.append_audit(session_id, "dashboard", "approval_granted", "via dashboard")
        storage.save_session(session)
    finally:
        storage.close()
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/session/{session_id}/feedback")
def feedback(
    session_id: str,
    classification_correct: bool = Form(True),
    severity_correct: bool = Form(True),
    action_useful: bool = Form(True),
    note: str = Form(""),
) -> Any:
    storage = _storage()
    try:
        session = storage.load_session(session_id)
        Memory(storage).record_feedback(
            session, classification_correct=classification_correct,
            severity_correct=severity_correct, action_useful=action_useful, note=note)
    finally:
        storage.close()
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)
