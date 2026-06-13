"""Continuous learning (Section 18). NOT model fine-tuning — this improves
routing (historical success rates), memory summaries, and an analyst-approved
local knowledge base. All SQLite-backed via the Storage interface.
"""

from __future__ import annotations

from orchestrator.core.state import SessionState
from orchestrator.storage.base import Storage


class Memory:
    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    # --- analyst feedback -> router historical success ---
    def record_feedback(self, session: SessionState, *, classification_correct: bool = True,
                        severity_correct: bool = True, action_useful: bool = True,
                        detection_worked: bool | None = None,
                        false_positive_reason: str = "", tuning: str = "",
                        note: str = "") -> int:
        """Record analyst feedback against every routing decision in the session
        (model_id, task_type). Returns the number of feedback rows written."""
        payload = {
            "classification_correct": classification_correct,
            "severity_correct": severity_correct,
            "action_useful": action_useful,
            "detection_worked": detection_worked,
            "false_positive_reason": false_positive_reason,
            "tuning": tuning,
            "note": note,
        }
        written = 0
        for d in session.decisions:
            task_type = next(
                (s.task_type for s in session.task_graph.steps if s.step_id == d.step_id),
                session.security_task_type,
            )
            self.storage.save_feedback(session.session_id, d.selected_model, task_type, payload)
            written += 1
        self.storage.append_audit(session.session_id, "human", "feedback_recorded", note)
        # Promote a tuning recommendation into the knowledge base if provided.
        if tuning:
            self.add_knowledge(f"tuning:{session.security_task_type}", tuning,
                               session.session_id)
        return written

    def historical_success(self, model_id: str, task_type: str) -> float:
        rate = self.storage.feedback_success_rate(model_id, task_type)
        return 0.5 if rate is None else float(rate)

    # --- knowledge base ---
    def add_knowledge(self, topic: str, content: str, source_session: str | None = None) -> None:
        self.storage.add_knowledge(topic, content, source_session)

    def get_knowledge(self, topic: str) -> list[str]:
        return self.storage.get_knowledge(topic)

    # --- memory summary ---
    def update_memory_summary(self, session: SessionState) -> str:
        iocs = ", ".join(f"{i.type}:{i.value}" for i in session.indicators_of_compromise[:8])
        mitre = ", ".join(m.technique_id for m in session.mitre_attack_mapping)
        summary = (
            f"{session.user_goal} | class={session.classification} | "
            f"IOCs=[{iocs}] | MITRE=[{mitre}] | "
            f"{len(session.timeline_events)} timeline event(s), "
            f"{len(session.detection_rules)} detection(s)."
        )
        session.memory_summary = summary
        session.touch()
        return summary
