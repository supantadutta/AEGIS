"""LogAnalysisAgent — parses provided logs into a chronological timeline and
flags suspicious sequences."""

from __future__ import annotations

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import EvidenceItem, Finding, SessionState, TaskStep
from orchestrator.providers.base import ProviderResponse
from orchestrator.tools.timeline import build_timeline


class LogAnalysisAgent(BaseAgent):
    name = "LogAnalysisAgent"

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        ac = session.alert_context
        raw = ac.raw_log if ac else None
        events = build_timeline(raw, ac)
        session.timeline_events.extend(events)

        # Flag a failures-then-success sequence (classic brute-force tell).
        outcomes = [e.event_type for e in events]
        if "authentication_failure" in outcomes and "authentication_success" in outcomes:
            fail_idx = outcomes.index("authentication_failure")
            succ_idx = outcomes.index("authentication_success")
            if succ_idx > fail_idx:
                session.investigation_findings.append(Finding(
                    title="Failed logins followed by success",
                    detail="Authentication failures preceding a success indicate a "
                           "successful brute-force or password-guessing attempt.",
                    severity="high", confidence=0.85,
                ))

        if events:
            session.evidence_items.append(EvidenceItem(
                type="timeline", source="LogAnalysisAgent",
                content=f"Built timeline with {len(events)} event(s).",
                chain_of_custody_note="Derived from provided raw logs.",
                created_by_agent=self.name, created_by_model=response.model,
                related_step_id=step.step_id,
            ))
        return f"Built timeline with {len(events)} event(s)."
