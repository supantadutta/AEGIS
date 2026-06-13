"""Main orchestration loop.

For each pending step: route -> (approval gate) -> dispatch to the selected
agent via the selected provider -> append results -> checkpoint -> advance.
Pauses on approval-gated / high-risk steps. Resumable from any checkpoint with
any configured model.
"""

from __future__ import annotations

import os

from orchestrator.agents import AgentServices, get_agent
from orchestrator.core.approvals import ApprovalManager
from orchestrator.core.checkpoints import CheckpointManager
from orchestrator.core.events import audit, record_decision, record_model_call
from orchestrator.core.planner import Planner
from orchestrator.core.router import Router
from orchestrator.core.state import AlertContext, SessionState, TaskStep
from orchestrator.providers import get_available_provider


class Orchestrator:
    def __init__(self, storage, router: Router | None = None) -> None:
        self.storage = storage
        self.router = router or Router(storage)
        self.checkpoints = CheckpointManager(storage)
        self.planner = Planner()
        self.approvals = ApprovalManager()
        self.services = AgentServices(storage=storage)

    # --- session lifecycle ---
    def create_session(
        self,
        goal: str,
        *,
        alert_context: AlertContext | None = None,
        security_task_type: str = "soc_investigation",
        data_sensitivity: str = "internal",
    ) -> SessionState:
        session = SessionState(
            user_goal=goal,
            security_task_type=security_task_type,
            alert_context=alert_context,
            data_sensitivity=data_sensitivity,  # type: ignore[arg-type]
        )
        self.planner.plan(session)
        self.storage.save_session(session)
        audit(session, "orchestrator", "session_created", goal)
        self.checkpoints.save(session, label="planned")
        return session

    def run(self, session: SessionState, *, auto_approve: bool = False,
            max_steps: int | None = None) -> SessionState:
        """Run the loop until completion, an approval gate, or max_steps."""
        session.status = "running"
        steps_run = 0
        while True:
            step = self._next_step(session)
            if step is None:
                session.status = "completed"
                session.touch()
                self.storage.save_session(session)
                audit(session, "orchestrator", "session_completed", "")
                self.checkpoints.save(session, label="completed")
                break

            if max_steps is not None and steps_run >= max_steps:
                session.status = "paused"
                self.storage.save_session(session)
                break

            paused = self._run_step(session, step, auto_approve=auto_approve)
            steps_run += 1
            if paused:
                break
        return session

    def _next_step(self, session: SessionState) -> TaskStep | None:
        for step in session.task_graph.steps:
            if step.status in ("completed", "skipped"):
                continue
            # dependencies satisfied?
            if all(self._dep_done(session, dep) for dep in step.depends_on):
                return step
        return None

    def _dep_done(self, session: SessionState, dep_id: str) -> bool:
        dep = session.task_graph.get(dep_id)
        return dep is None or dep.status in ("completed", "skipped")

    def _run_step(self, session: SessionState, step: TaskStep, *, auto_approve: bool) -> bool:
        """Execute one step. Returns True if the loop should pause."""
        session.current_step_id = step.step_id
        decision = self.router.route(
            step, session, user_preference=os.getenv("AEGIS_MODEL_PREFERENCE")
        )
        record_decision(session, decision)
        step.selected_model = decision.selected_model
        audit(session, "router", "model_selected",
              f"{step.name} -> {decision.selected_model}", step_id=step.step_id)

        # Approval gate.
        if decision.requires_human_approval and not self.approvals.is_approved(session, step.step_id):
            if auto_approve:
                self.approvals.request(session, action=f"step:{step.task_type}", step_id=step.step_id)
                self.approvals.decide(session, approve=True, step_id=step.step_id,
                                      decided_by="auto_approve")
            else:
                self.approvals.request(session, action=f"step:{step.task_type}",
                                       step_id=step.step_id,
                                       note=f"Step '{step.name}' requires approval (risk={step.risk_level}).")
                session.status = "waiting_approval"
                audit(session, "orchestrator", "approval_required", step.name, step_id=step.step_id)
                self.storage.save_session(session)
                self.checkpoints.save(session, label=f"waiting:{step.name}")
                return True

        # Dispatch to the agent via the selected (or mock-fallback) provider.
        provider, degraded = get_available_provider(decision.selected_model)
        if degraded:
            audit(session, "orchestrator", "provider_degraded",
                  f"{decision.selected_model} unavailable -> mock", step_id=step.step_id)
        agent = get_agent(step.agent, self.services)
        step.status = "running"
        try:
            prompt = agent.build_prompt(session, step)
            response = provider.generate(session, prompt)
            from orchestrator.core.events import record_message
            for msg in provider.from_provider_format(response.raw or {}, prompt):
                msg.step_id = step.step_id
                record_message(session, msg)
            summary = agent.apply_result(session, step, response)
            step.selected_model = response.model
            step.result_summary = summary
            record_model_call(session, prompt, response, step.step_id)
            step.status = "completed"
            session.completed_steps.append(step)
            session.pending_steps = [s for s in session.pending_steps if s.step_id != step.step_id]
        except Exception as exc:  # noqa: BLE001 - record failure, don't crash loop
            step.status = "failed"
            session.failed_steps.append(step)
            audit(session, "orchestrator", "step_failed", f"{step.name}: {exc}",
                  step_id=step.step_id)
            session.status = "failed"
            self.storage.save_session(session)
            self.checkpoints.save(session, label=f"failed:{step.name}")
            return True

        self.storage.save_session(session)
        self.checkpoints.save(session, label=f"after:{step.name}")
        return False

    # --- resume ---
    def resume(self, session_id: str, *, model_override: str | None = None,
               auto_approve: bool = False, max_steps: int | None = None) -> SessionState:
        """Resume from the latest checkpoint, optionally with a different model."""
        cp_id = self.storage.latest_checkpoint_id(session_id)
        session = (self.storage.load_checkpoint(cp_id) if cp_id
                   else self.storage.load_session(session_id))
        if model_override:
            os.environ["AEGIS_MODEL_PREFERENCE"] = model_override
            audit(session, "human", "resume_with_model",
                  f"resuming with preferred model {model_override}")
        # If we paused at an approval gate that the human has since approved,
        # the loop will pick the same current step back up and proceed.
        audit(session, "human", "resume", f"from checkpoint {cp_id}")
        self.storage.save_session(session)
        try:
            return self.run(session, auto_approve=auto_approve, max_steps=max_steps)
        finally:
            if model_override:
                os.environ.pop("AEGIS_MODEL_PREFERENCE", None)
