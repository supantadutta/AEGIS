"""Service helpers shared by the dashboard routes.

Keeps the FastAPI app thin and unit-testable: investigation runs, provider/
integration status, and overview stats live here rather than in the route
handlers.
"""

from __future__ import annotations

import os
from typing import Any

from orchestrator.core.config import load_models, model_ids, runtime_flags
from orchestrator.core.orchestrator import Orchestrator
from orchestrator.core.state import SessionState
from orchestrator.providers import get_provider
from orchestrator.storage.sqlite import SQLiteStorage
from orchestrator.tools.parsers import parse_alert


def db_path() -> str:
    return os.getenv("AEGIS_DB_PATH", "aegis.sqlite")


def storage() -> SQLiteStorage:
    return SQLiteStorage(db_path())


# --- investigations ---------------------------------------------------------


def run_investigation(text: str, *, fmt: str = "auto", sensitivity: str = "internal",
                      auto_approve: bool = False) -> SessionState:
    """Parse an alert and run it end-to-end through the orchestrator."""
    store = storage()
    try:
        orch = Orchestrator(store)
        alert = parse_alert(text, fmt=fmt)
        goal = f"Investigate alert: {alert.alert_name or 'pasted text'}"
        session = orch.create_session(
            goal, alert_context=alert, security_task_type="soc_investigation",
            data_sensitivity=sensitivity,
        )
        orch.run(session, auto_approve=auto_approve)
        return session
    finally:
        store.close()


def resume_session(session_id: str, *, model: str | None = None,
                   auto_approve: bool = False) -> SessionState:
    store = storage()
    try:
        return Orchestrator(store).resume(session_id, model_override=model, auto_approve=auto_approve)
    finally:
        store.close()


# --- status / stats ---------------------------------------------------------


def provider_status() -> list[dict[str, Any]]:
    """One row per model: provider, tiers, and whether it can really run."""
    rows: list[dict[str, Any]] = []
    for m in load_models().get("models", []):
        mid = m["id"]
        try:
            available = get_provider(mid).is_available()
        except Exception:  # noqa: BLE001
            available = False
        rows.append({
            "id": mid,
            "provider": m.get("provider", ""),
            "cost_tier": m.get("cost_tier", ""),
            "privacy_tier": m.get("privacy_tier", ""),
            "available": available,
            "strengths": m.get("strengths", []),
        })
    return rows


def overview_stats() -> dict[str, Any]:
    store = storage()
    try:
        sessions = store.list_sessions()
    finally:
        store.close()
    by_status: dict[str, int] = {}
    for s in sessions:
        by_status[s["status"]] = by_status.get(s["status"], 0) + 1
    providers = provider_status()
    return {
        "total_sessions": len(sessions),
        "by_status": by_status,
        "recent": sessions[:8],
        "models_total": len(providers),
        "models_available": sum(1 for p in providers if p["available"]),
        "flags": runtime_flags(),
        "known_models": model_ids(),
    }
