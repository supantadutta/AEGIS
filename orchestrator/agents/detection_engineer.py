"""DetectionEngineerAgent — recommends detection coverage and hunting queries
for the observed behavior, with false-positive notes and validation steps."""

from __future__ import annotations

from typing import Any

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import EvidenceItem, SessionState, TaskStep
from orchestrator.providers.base import ProviderResponse
from orchestrator.tools.detections import (
    available_use_cases,
    generate_detection_rule,
    generate_query,
)

# Infer a detection use-case slug from alert/MITRE keywords.
_USE_CASE_KEYWORDS = [
    (("brute", "4625", "failed login"), "successful-login-after-failures"),
    (("password spray",), "password-spraying"),
    (("powershell", "-enc", "encoded"), "suspicious-powershell"),
    (("traversal", "../"), "directory-traversal"),
    (("sql injection", "union select"), "sql-injection"),
    (("lateral",), "lateral-movement"),
    (("rdp",), "suspicious-rdp"),
    (("ssh",), "suspicious-ssh"),
    (("dns tunnel",), "dns-tunneling"),
    (("c2", "beacon"), "c2-beaconing"),
    (("exfil",), "data-exfiltration"),
    (("first", "unusual server"), "unusual-server-access"),
    (("waf", "block"), "waf-block-allow-analysis"),
]

# Platforms we routinely emit (covers >=3 distinct query languages).
_DEFAULT_PLATFORMS = ["sigma", "splunk", "kql"]


class DetectionEngineerAgent(BaseAgent):
    name = "DetectionEngineerAgent"

    def context(self, session: SessionState, step: TaskStep) -> dict[str, Any]:
        ctx = super().context(session, step)
        ctx["use_case"] = self._infer_use_case(session)
        return ctx

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        use_case = self._infer_use_case(session)
        # Primary detection rule (Sigma) + cross-platform hunting queries.
        rule = generate_detection_rule(use_case, fmt="sigma")
        session.detection_rules.append(rule)
        if self.services.storage:
            self.services.storage.save_detection_rule(session.session_id, rule.model_dump_json())

        for platform in _DEFAULT_PLATFORMS:
            try:
                gq = generate_query(platform, use_case)
            except (KeyError, ValueError):
                continue
            session.generated_queries.append(gq)

        session.recommended_actions.append(
            f"Deploy/tune detection for '{use_case}' ({rule.title}); "
            f"see false-positive notes before enabling in production."
        )
        session.evidence_items.append(EvidenceItem(
            type="detection_rule", source="DetectionEngineerAgent",
            content=f"Generated {use_case} detection + {len(_DEFAULT_PLATFORMS)} queries.",
            chain_of_custody_note="Rendered from detection_templates.yaml.",
            created_by_agent=self.name, created_by_model=response.model,
            related_step_id=step.step_id,
        ))
        return f"Generated detection for '{use_case}' + {len(session.generated_queries)} quer(ies)."

    def _infer_use_case(self, session: SessionState) -> str:
        text = " ".join(filter(None, [
            session.alert_context.alert_name if session.alert_context else None,
            session.alert_context.detection_name if session.alert_context else None,
            session.alert_context.command_line if session.alert_context else None,
            " ".join(m.technique_name for m in session.mitre_attack_mapping),
        ])).lower()
        for keywords, slug in _USE_CASE_KEYWORDS:
            if any(k in text for k in keywords) and slug in available_use_cases():
                return slug
        return "brute-force"
