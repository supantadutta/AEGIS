"""Checkpoint management: save/load/list/rollback full SessionState snapshots.

Every checkpoint is a complete SessionState snapshot plus lightweight diff
metadata against the previous checkpoint, which is what lets a session be
resumed (or rolled back) at any step, with any model.
"""

from __future__ import annotations

from orchestrator.core.state import CheckpointRef, SessionState, utcnow
from orchestrator.storage.base import Storage

# Top-level list fields whose lengths we summarize in the diff metadata.
_COUNTED_FIELDS = [
    "completed_steps", "indicators_of_compromise", "evidence_items",
    "timeline_events", "investigation_findings", "detection_rules",
    "generated_queries", "threat_intel_results", "mitre_attack_mapping",
    "model_calls", "tool_calls", "artifacts", "decisions",
]


def _diff_summary(previous: SessionState | None, current: SessionState) -> str:
    """Human-readable summary of what changed vs the previous checkpoint."""
    parts: list[str] = []
    for field in _COUNTED_FIELDS:
        cur = len(getattr(current, field))
        prev = len(getattr(previous, field)) if previous else 0
        if cur != prev:
            parts.append(f"{field}:{prev}->{cur}")
    if previous and previous.current_step_id != current.current_step_id:
        parts.append(f"step:{previous.current_step_id}->{current.current_step_id}")
    if previous and previous.status != current.status:
        parts.append(f"status:{previous.status}->{current.status}")
    return ", ".join(parts) if parts else "no structural change"


class CheckpointManager:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def save(self, state: SessionState, label: str = "") -> CheckpointRef:
        """Snapshot the current state, record a CheckpointRef on it, persist."""
        prev = self._latest_state(state.session_id)
        diff = _diff_summary(prev, state)
        checkpoint_id = self.storage.save_checkpoint(
            state.session_id, state, label=label, diff_summary=diff
        )
        ref = CheckpointRef(
            checkpoint_id=checkpoint_id,
            step_id=state.current_step_id,
            label=label,
            created_at=utcnow(),
            diff_summary=diff,
        )
        state.checkpoints.append(ref)
        self.storage.append_audit(
            state.session_id, "orchestrator", "checkpoint_saved",
            f"{checkpoint_id} ({label or 'auto'}): {diff}",
        )
        # Persist the session row too so it reflects the new checkpoint ref.
        self.storage.save_session(state)
        return ref

    def load(self, checkpoint_id: str) -> SessionState:
        return self.storage.load_checkpoint(checkpoint_id)

    def list(self, session_id: str) -> list[dict]:
        return self.storage.list_checkpoints(session_id)

    def rollback(self, session_id: str, checkpoint_id: str) -> SessionState:
        """Restore a prior checkpoint as the live session state.

        The restored state is re-saved as the current session and a fresh
        checkpoint records the rollback (evidence is never destroyed).
        """
        restored = self.storage.load_checkpoint(checkpoint_id)
        if restored.session_id != session_id:
            raise ValueError("checkpoint does not belong to this session")
        restored.touch()
        self.storage.append_audit(
            session_id, "human", "rollback",
            f"rolled back to checkpoint {checkpoint_id} (step {restored.current_step_id})",
        )
        self.storage.save_session(restored)
        self.save(restored, label=f"rollback->{checkpoint_id[:8]}")
        return restored

    def _latest_state(self, session_id: str) -> SessionState | None:
        cp_id = self.storage.latest_checkpoint_id(session_id)
        if cp_id is None:
            return None
        return self.storage.load_checkpoint(cp_id)
