"""Abstract storage interface. SQLite (MVP) and Postgres (later) both
implement this so callers never depend on the concrete backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from orchestrator.core.state import SessionState


class Storage(ABC):
    """Persistence contract for sessions, checkpoints and supporting tables."""

    @abstractmethod
    def init_db(self) -> None: ...

    # --- sessions ---
    @abstractmethod
    def save_session(self, state: SessionState) -> None: ...

    @abstractmethod
    def load_session(self, session_id: str) -> SessionState: ...

    @abstractmethod
    def list_sessions(self) -> list[dict[str, Any]]: ...

    # --- checkpoints ---
    @abstractmethod
    def save_checkpoint(
        self, session_id: str, state: SessionState, label: str = "", diff_summary: str = ""
    ) -> str: ...

    @abstractmethod
    def load_checkpoint(self, checkpoint_id: str) -> SessionState: ...

    @abstractmethod
    def list_checkpoints(self, session_id: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    def latest_checkpoint_id(self, session_id: str) -> str | None: ...

    # --- audit ---
    @abstractmethod
    def append_audit(self, session_id: str, actor: str, action: str, detail: str = "") -> None: ...

    # --- threat-intel cache ---
    @abstractmethod
    def cache_threat_intel(self, source: str, observable: str, payload: str) -> None: ...

    @abstractmethod
    def get_cached_threat_intel(self, source: str, observable: str) -> str | None: ...

    # --- detection rules ---
    @abstractmethod
    def save_detection_rule(self, session_id: str, rule_json: str) -> None: ...

    # --- analyst feedback / continuous learning ---
    @abstractmethod
    def save_feedback(self, session_id: str, model_id: str, task_type: str, payload: dict) -> None: ...

    @abstractmethod
    def feedback_success_rate(self, model_id: str, task_type: str) -> float | None: ...

    # --- knowledge base ---
    @abstractmethod
    def add_knowledge(self, topic: str, content: str, source_session: str | None = None) -> None: ...

    @abstractmethod
    def get_knowledge(self, topic: str) -> list[str]: ...

    @abstractmethod
    def close(self) -> None: ...
