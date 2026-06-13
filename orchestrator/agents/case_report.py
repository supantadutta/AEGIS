"""CaseReportAgent — writes the analyst note + closure summary and stashes
rendered reports into final_output and evidence."""

from __future__ import annotations

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import Artifact, EvidenceItem, SessionState, TaskStep
from orchestrator.providers.base import ProviderResponse
from orchestrator.tools.reports import render_report


class CaseReportAgent(BaseAgent):
    name = "CaseReportAgent"

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        s = response.structured or {}
        closure = s.get("closure_note", "Investigation complete; see analyst note.")
        if not session.false_positive_reasoning and not session.true_positive_reasoning:
            session.true_positive_reasoning = closure

        reports: dict[str, str] = {}
        for report_type in ("analyst", "incident", "executive"):
            try:
                reports[report_type] = render_report(session, report_type)
            except Exception:  # noqa: BLE001 - never fail the case on a template
                continue

        for report_type, body in reports.items():
            session.artifacts.append(Artifact(
                name=f"{report_type}_report", type="report", content=body,
                created_by_agent=self.name, created_by_model=response.model,
                step_id=step.step_id,
            ))
        session.evidence_items.append(EvidenceItem(
            type="report", source="CaseReportAgent",
            content=reports.get("analyst", "")[:500],
            chain_of_custody_note="Rendered from canonical SessionState.",
            created_by_agent=self.name, created_by_model=response.model,
            related_step_id=step.step_id,
        ))
        session.final_output = {
            "classification": session.classification,
            "severity": (session.severity_assessment.severity
                         if session.severity_assessment else None),
            "closure_note": closure,
            "reports": reports,
            "ioc_count": len(session.indicators_of_compromise),
            "mitre": [m.technique_id for m in session.mitre_attack_mapping],
        }
        return f"Authored {len(reports)} report(s); closure recorded."
