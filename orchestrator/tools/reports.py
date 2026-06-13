"""Report rendering from SessionState using report_templates.yaml (Jinja2)."""

from __future__ import annotations

from typing import Any

from jinja2 import Template

from orchestrator.core.config import load_report_templates
from orchestrator.core.state import SessionState, utcnow

REPORT_TYPES = ["analyst", "incident", "customer", "executive"]


def available_report_types() -> list[str]:
    return list(load_report_templates().get("templates", {}).keys())


def build_context(session: SessionState) -> dict[str, Any]:
    ac = session.alert_context
    sev = (session.severity_assessment.severity if session.severity_assessment
           else (ac.severity if ac and ac.severity else "medium"))
    evidence = [f"{e.type}: {e.content[:120]}" for e in session.evidence_items[:10]]
    if ac and ac.raw_log and not evidence:
        evidence = [f"raw_log: {ac.raw_log[:120]}"]
    steps = [s.name for s in session.task_graph.steps]
    findings = [f"{f.title}: {f.detail}" for f in session.investigation_findings]
    return {
        "session_id": session.session_id,
        "generated_at": utcnow().isoformat(),
        "status": session.status,
        "alert_name": (ac.alert_name if ac else None) or session.user_goal,
        "source_tool": (ac.source_tool if ac else None) or "AEGIS",
        "severity": sev,
        "confidence": session.confidence_assessment or 0.7,
        "classification": session.classification or "Needs More Information",
        "alert_summary": (session.memory_summary
                          or (session.investigation_findings[0].detail
                              if session.investigation_findings else session.user_goal)),
        "evidence": evidence,
        "steps": steps,
        "findings": findings,
        "mitre": session.mitre_attack_mapping,
        "recommended_actions": session.recommended_actions or [
            a.description for a in session.containment_actions
        ],
        "recommended_summary": "; ".join(
            a.description for a in session.containment_actions[:3]
        ) or "Continue monitoring; no active response required yet.",
        "closure_note": session.false_positive_reasoning or session.true_positive_reasoning
        or "Investigation complete.",
        "timeline": session.timeline_events,
        "affected_assets": ", ".join(
            a.hostname or a.ip or "" for a in session.affected_assets
        ) or "None identified",
        "affected_users": ", ".join(session.affected_users) or "None identified",
        "root_cause": (session.investigation_findings[-1].detail
                       if session.investigation_findings else "Under investigation."),
        "impact": (session.severity_assessment.impact
                   if session.severity_assessment else "See findings."),
        "containment": [a.description for a in session.containment_actions],
        "eradication": [a.description for a in session.eradication_actions],
        "recovery": [a.description for a in session.recovery_actions],
        "lessons_learned": session.lessons_learned,
        "customer_action": "Review the affected accounts/assets and confirm any "
                           "expected activity with the SOC.",
        "business_impact": (ac.business_impact if ac and ac.business_impact
                            else "Potential security impact under assessment."),
        "decision_required": "Approve recommended containment actions." if (
            session.containment_actions) else "No decision required at this time.",
        "next_steps": session.recommended_actions or [
            "Monitor for recurrence", "Validate detection coverage",
        ],
    }


def render_report(session: SessionState, report_type: str = "analyst") -> str:
    templates = load_report_templates().get("templates", {})
    if report_type not in templates:
        raise ValueError(f"unknown report type '{report_type}'. Known: {', '.join(templates)}")
    body = templates[report_type]["body"]
    return Template(body).render(**build_context(session))
