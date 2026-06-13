"""PlannerAgent — decomposes a goal/alert into a safe, ordered TaskGraph.

Deterministic by design (no model call required), so planning is reproducible
and safe. Each step carries its agent, task type, risk level and data
sensitivity, which the Router and approval gates consume.
"""

from __future__ import annotations

from orchestrator.core.state import DataSensitivity, SessionState, TaskGraph, TaskStep


def _step(name: str, agent: str, task_type: str, sensitivity: DataSensitivity,
          depends_on: list[str], risk: str = "low", approval: bool = False) -> TaskStep:
    return TaskStep(
        name=name, agent=agent, task_type=task_type,
        data_sensitivity=sensitivity, depends_on=depends_on,
        risk_level=risk, requires_human_approval=approval,
    )


class Planner:
    """Builds the investigation task graph for a session."""

    def plan(self, session: SessionState) -> TaskGraph:
        sens = session.data_sensitivity
        task = session.security_task_type
        if task in ("soc_investigation", "incident_response"):
            steps = self._investigation_steps(sens)
        elif task == "detection_engineering":
            steps = self._detection_steps(sens)
        elif task == "threat_intel":
            steps = self._intel_steps(sens)
        else:
            steps = self._generic_steps(sens)

        graph = TaskGraph(goal=session.user_goal, steps=steps)
        session.task_graph = graph
        session.pending_steps = list(steps)
        session.current_step_id = steps[0].step_id if steps else None
        session.status = "planning"
        return graph

    def _investigation_steps(self, sens: DataSensitivity) -> list[TaskStep]:
        s1 = _step("Intake & Triage", "SOCInvestigatorAgent", "triage", sens, [])
        s2 = _step("Threat Intel Enrichment", "ThreatIntelAgent", "enrichment", sens, [s1.step_id])
        s3 = _step("Timeline Construction", "LogAnalysisAgent", "log_analysis", sens, [s2.step_id])
        s4 = _step("Detection Engineering", "DetectionEngineerAgent",
                   "detection_engineering", sens, [s3.step_id])
        s5 = _step("Response Recommendation", "IncidentResponseAgent", "response",
                   sens, [s4.step_id], risk="medium")
        s6 = _step("Reporting", "CaseReportAgent", "report_writing", sens, [s5.step_id])
        return [s1, s2, s3, s4, s5, s6]

    def _detection_steps(self, sens: DataSensitivity) -> list[TaskStep]:
        s1 = _step("Plan Detection Coverage", "PlannerAgent", "planning", sens, [])
        s2 = _step("Author Detections", "DetectionEngineerAgent",
                   "detection_engineering", sens, [s1.step_id])
        s3 = _step("Safety Review", "SecurityReviewAgent", "security_review", sens, [s2.step_id])
        return [s1, s2, s3]

    def _intel_steps(self, sens: DataSensitivity) -> list[TaskStep]:
        s1 = _step("Enrich Observables", "ThreatIntelAgent", "enrichment", sens, [])
        s2 = _step("Summarize Intel", "SummarizerAgent", "summarization", sens, [s1.step_id])
        return [s1, s2]

    def _generic_steps(self, sens: DataSensitivity) -> list[TaskStep]:
        s1 = _step("Plan", "PlannerAgent", "planning", sens, [])
        s2 = _step("Execute", "SOCInvestigatorAgent", "analysis", sens, [s1.step_id])
        s3 = _step("Report", "CaseReportAgent", "report_writing", sens, [s2.step_id])
        return [s1, s2, s3]
