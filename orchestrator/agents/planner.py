"""PlannerAgent agent wrapper. Planning normally runs deterministically before
the loop (core/planner.Planner). When a plan step is dispatched (e.g. detection
or generic workflows), this agent records the planning rationale as an artifact.
"""

from __future__ import annotations

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import Artifact, SessionState, TaskStep
from orchestrator.providers.base import ProviderResponse


class PlannerAgent(BaseAgent):
    name = "PlannerAgent"

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        plan = " -> ".join(s.name for s in session.task_graph.steps)
        session.artifacts.append(Artifact(
            name="investigation_plan", type="plan",
            content=f"{response.text}\n\nPlanned steps: {plan}",
            created_by_agent=self.name, created_by_model=response.model, step_id=step.step_id,
        ))
        return f"Planning rationale recorded ({len(session.task_graph.steps)} steps)."
