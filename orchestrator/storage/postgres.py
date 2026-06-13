"""Postgres storage backend (interface-complete stub).

Implements the same `Storage` interface as SQLiteStorage so callers can swap
backends without changes. Wiring up psycopg/asyncpg is deferred; every method
raises NotImplementedError with a clear, actionable message.
"""

from __future__ import annotations

from typing import Any

from orchestrator.core.state import SessionState
from orchestrator.storage.base import Storage

_MSG = (
    "PostgresStorage is not implemented in the MVP. Use SQLiteStorage "
    "(AEGIS_DB_PATH) for now. To enable Postgres, implement this class against "
    "the same Storage interface and set the connection via DATABASE_URL."
)


class PostgresStorage(Storage):
    def __init__(self, dsn: str | None = None) -> None:
        self.dsn = dsn
        raise NotImplementedError(_MSG)

    def init_db(self) -> None:
        raise NotImplementedError(_MSG)

    def save_session(self, state: SessionState) -> None:
        raise NotImplementedError(_MSG)

    def load_session(self, session_id: str) -> SessionState:
        raise NotImplementedError(_MSG)

    def list_sessions(self) -> list[dict[str, Any]]:
        raise NotImplementedError(_MSG)

    def save_checkpoint(
        self, session_id: str, state: SessionState, label: str = "", diff_summary: str = ""
    ) -> str:
        raise NotImplementedError(_MSG)

    def load_checkpoint(self, checkpoint_id: str) -> SessionState:
        raise NotImplementedError(_MSG)

    def list_checkpoints(self, session_id: str) -> list[dict[str, Any]]:
        raise NotImplementedError(_MSG)

    def latest_checkpoint_id(self, session_id: str) -> str | None:
        raise NotImplementedError(_MSG)

    def append_audit(self, session_id: str, actor: str, action: str, detail: str = "") -> None:
        raise NotImplementedError(_MSG)

    def cache_threat_intel(self, source: str, observable: str, payload: str) -> None:
        raise NotImplementedError(_MSG)

    def get_cached_threat_intel(self, source: str, observable: str) -> str | None:
        raise NotImplementedError(_MSG)

    def save_detection_rule(self, session_id: str, rule_json: str) -> None:
        raise NotImplementedError(_MSG)

    def save_feedback(self, session_id: str, model_id: str, task_type: str, payload: dict) -> None:
        raise NotImplementedError(_MSG)

    def feedback_success_rate(self, model_id: str, task_type: str) -> float | None:
        raise NotImplementedError(_MSG)

    def add_knowledge(self, topic: str, content: str, source_session: str | None = None) -> None:
        raise NotImplementedError(_MSG)

    def get_knowledge(self, topic: str) -> list[str]:
        raise NotImplementedError(_MSG)

    def close(self) -> None:
        raise NotImplementedError(_MSG)
