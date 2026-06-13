"""IncidentResponseAgent — drafts containment / eradication / recovery plans
and lessons learned. All active response actions are recommendations requiring
human approval; nothing is executed here."""

from __future__ import annotations

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import ResponseAction, SessionState, TaskStep
from orchestrator.providers.base import ProviderResponse


class IncidentResponseAgent(BaseAgent):
    name = "IncidentResponseAgent"

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        s = response.structured or {}
        for desc in s.get("containment", []):
            session.containment_actions.append(ResponseAction(
                description=desc, category="containment",
                requires_human_approval=True, risk_level="high"))
        for desc in s.get("eradication", []):
            session.eradication_actions.append(ResponseAction(
                description=desc, category="eradication",
                requires_human_approval=True, risk_level="high"))
        for desc in s.get("recovery", []):
            session.recovery_actions.append(ResponseAction(
                description=desc, category="recovery",
                requires_human_approval=True, risk_level="medium"))
        for lesson in s.get("lessons_learned", []):
            if lesson not in session.lessons_learned:
                session.lessons_learned.append(lesson)

        # Monitoring recommendations are non-destructive and need no approval.
        session.recommended_actions.append(
            "Increase monitoring on the affected accounts/assets for recurrence.")
        n = (len(session.containment_actions) + len(session.eradication_actions)
             + len(session.recovery_actions))
        return f"Recommended {n} response action(s) (all approval-gated)."
