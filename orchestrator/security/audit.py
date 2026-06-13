"""Audit logging. Every tool call, model call, approval decision and policy
override is recorded to the SessionState and the SQLite audit_log table, with
secrets redacted first (Section 12.3)."""

from __future__ import annotations

from orchestrator.core.state import AuditEntry, SessionState
from orchestrator.security.redaction import redact


class AuditLogger:
    def __init__(self, storage=None) -> None:
        self.storage = storage

    def log(self, session: SessionState, actor: str, action: str, detail: str = "",
            step_id: str | None = None) -> None:
        safe_detail = redact(detail)
        session.audit_log.append(
            AuditEntry(actor=actor, action=action, detail=safe_detail, step_id=step_id)
        )
        session.touch()
        if self.storage is not None:
            self.storage.append_audit(session.session_id, actor, action, safe_detail)
