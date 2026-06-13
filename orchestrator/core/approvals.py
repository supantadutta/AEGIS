"""Human-approval gating (Sections 12/13).

Risky actions and high/critical-risk steps cannot proceed until a human
approves. The orchestrator pauses (status="waiting_approval"); the CLI/dashboard
records the decision; resume re-enters the loop at the same step.
"""

from __future__ import annotations

from orchestrator.core.config import load_security
from orchestrator.core.state import ApprovalEntry, SessionState, utcnow


def approval_required_actions() -> list[str]:
    return load_security().get("approval_required_actions", [])


def action_requires_approval(action: str) -> bool:
    return action in approval_required_actions()


class ApprovalManager:
    """Tracks approval requests/decisions on a SessionState."""

    def request(self, session: SessionState, action: str, step_id: str | None = None,
                note: str = "") -> ApprovalEntry:
        existing = self.pending_for_step(session, step_id, action)
        if existing:
            return existing
        entry = ApprovalEntry(action=action, step_id=step_id, note=note, status="pending")
        session.approval_log.append(entry)
        session.touch()
        return entry

    def pending_for_step(self, session: SessionState, step_id: str | None,
                         action: str | None = None) -> ApprovalEntry | None:
        for e in session.approval_log:
            if e.status == "pending" and e.step_id == step_id and (action is None or e.action == action):
                return e
        return None

    def is_approved(self, session: SessionState, step_id: str | None) -> bool:
        """True if every approval entry for this step has been approved and none
        remain pending."""
        relevant = [e for e in session.approval_log if e.step_id == step_id]
        if not relevant:
            return False
        return all(e.status == "approved" for e in relevant) and any(
            e.status == "approved" for e in relevant
        )

    def has_pending(self, session: SessionState, step_id: str | None) -> bool:
        return self.pending_for_step(session, step_id) is not None

    def decide(self, session: SessionState, *, approve: bool, step_id: str | None = None,
               approval_id: str | None = None, decided_by: str = "human",
               note: str = "") -> list[ApprovalEntry]:
        decided: list[ApprovalEntry] = []
        for e in session.approval_log:
            if e.status != "pending":
                continue
            if approval_id and e.approval_id != approval_id:
                continue
            if approval_id is None and step_id is not None and e.step_id != step_id:
                continue
            e.status = "approved" if approve else "rejected"
            e.decided_at = utcnow()
            e.decided_by = decided_by
            if note:
                e.note = note
            decided.append(e)
        session.touch()
        return decided

    def approve_all_pending(self, session: SessionState, decided_by: str = "human") -> list[ApprovalEntry]:
        return self.decide(session, approve=True, decided_by=decided_by)
