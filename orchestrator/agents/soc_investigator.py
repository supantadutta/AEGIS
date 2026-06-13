"""SOCInvestigatorAgent — intake + triage: extract entities/IOCs, classify the
alert, assess severity, form findings, and map to MITRE ATT&CK.
"""

from __future__ import annotations

import re
from typing import Any

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import (
    Asset,
    EvidenceItem,
    Finding,
    Hypothesis,
    MitreMapping,
    SessionState,
    SeverityAssessment,
    TaskStep,
)
from orchestrator.providers.base import ProviderResponse
from orchestrator.tools.inventory import asset_inventory_lookup
from orchestrator.tools.ioc import extract_iocs

# Keyword -> MITRE technique. Deterministic, evidence-backed mapping.
_MITRE_KEYWORDS = [
    (("brute", "failed login", "password guess", "4625"),
     ("Credential Access", "T1110", "Brute Force")),
    (("password spray",), ("Credential Access", "T1110.003", "Password Spraying")),
    (("powershell", "encoded", "-enc"), ("Execution", "T1059.001", "PowerShell")),
    (("rdp",), ("Lateral Movement", "T1021.001", "Remote Desktop Protocol")),
    (("ssh",), ("Lateral Movement", "T1021.004", "SSH")),
    (("lateral",), ("Lateral Movement", "T1021", "Remote Services")),
    (("traversal", "../", "directory traversal"),
     ("Initial Access", "T1190", "Exploit Public-Facing Application")),
    (("sql injection", "union select"),
     ("Initial Access", "T1190", "Exploit Public-Facing Application")),
    (("dns tunnel", "exfil"), ("Exfiltration", "T1048", "Exfil Over Alt Protocol")),
    (("c2", "beacon", "command and control"),
     ("Command and Control", "T1071", "Application Layer Protocol")),
    (("new admin", "account created", "4720"),
     ("Persistence", "T1136", "Create Account")),
]


class SOCInvestigatorAgent(BaseAgent):
    name = "SOCInvestigatorAgent"

    def context(self, session: SessionState, step: TaskStep) -> dict[str, Any]:
        ctx = super().context(session, step)
        text = self._alert_text(session)
        failed = len(re.findall(r"(4625|outcome=failure|action=failure)", text, re.IGNORECASE))
        success = len(re.findall(r"(4624|outcome=success|action=success)", text, re.IGNORECASE))
        ctx["failed_logins"] = failed
        ctx["successful_logins"] = success
        ctx["suggested_classification"] = self._suggest_classification(text, failed, success)
        ctx["extracted_iocs"] = [i.value for i in extract_iocs(text)]
        return ctx

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        ac = session.alert_context
        text = self._alert_text(session)
        s = response.structured or {}

        # 1. IOCs
        existing = {(i.type, i.value) for i in session.indicators_of_compromise}
        for ioc in extract_iocs(text):
            if (ioc.type, ioc.value) not in existing:
                ioc.source = "soc_triage"
                session.indicators_of_compromise.append(ioc)

        # 2. Entities -> affected users / assets (enriched from inventory)
        if ac and ac.username and ac.username not in session.affected_users:
            session.affected_users.append(ac.username)
        for host_ident in filter(None, [ac.destination_host if ac else None,
                                         ac.source_host if ac else None,
                                         ac.destination_ip if ac else None]):
            row = asset_inventory_lookup(host_ident)
            if row and not any(a.hostname == row.get("hostname") for a in session.affected_assets):
                session.affected_assets.append(Asset(
                    hostname=row.get("hostname"), ip=row.get("ip"),
                    criticality=row.get("criticality"), owner=row.get("owner"),
                    business_unit=row.get("business_unit"), note=row.get("note"),
                ))

        # 3. Classification + severity + confidence
        session.classification = s.get("classification") or self._suggest_classification(
            text, response.structured.get("failed_logins", 0) if response.structured else 0, 0
        )
        sev = s.get("severity") or (ac.severity if ac and ac.severity else "medium")
        session.severity_assessment = SeverityAssessment(
            severity=sev,
            rationale=response.text[:300],
            impact=(ac.business_impact if ac and ac.business_impact else "See findings."),
            scope=f"{len(session.affected_users)} user(s), {len(session.affected_assets)} asset(s).",
        )
        session.confidence_assessment = float(s.get("confidence", 0.7))
        if session.classification.startswith("True Positive") or session.classification == "Confirmed Incident":
            session.true_positive_reasoning = s.get(
                "true_positive_reasoning", "Behavior consistent with the mapped technique.")
        elif session.classification == "False Positive":
            session.false_positive_reasoning = "No malicious behavior corroborated by evidence."

        # 4. Findings
        for f in s.get("findings", []):
            session.investigation_findings.append(Finding(
                title=f.get("title", "Finding"), detail=f.get("detail", ""),
                severity=f.get("severity", sev),
                related_entities=[ac.username] if ac and ac.username else [],
            ))
        if not session.investigation_findings:
            session.investigation_findings.append(Finding(
                title=f"Triage of {ac.alert_name if ac else 'alert'}",
                detail=response.text[:300], severity=sev,
            ))

        # 5. Hypotheses
        session.hypotheses.append(Hypothesis(
            statement=f"The activity represents {session.classification.lower()}.",
            likelihood=session.confidence_assessment,
            supporting_evidence=[response.text[:160]],
        ))

        # 6. MITRE mapping
        for tactic, tid, tname in self._mitre(text):
            if not any(m.technique_id == tid for m in session.mitre_attack_mapping):
                session.mitre_attack_mapping.append(MitreMapping(
                    tactic=tactic, technique_id=tid, technique_name=tname,
                    confidence=session.confidence_assessment,
                    evidence=[f"Keywords in alert '{ac.alert_name if ac else ''}'/logs."],
                    explanation=f"Observed behavior matches {tname}.",
                ))

        # 7. Evidence (chain of custody)
        session.evidence_items.append(EvidenceItem(
            type="note", source="SOCInvestigatorAgent",
            content=f"Triage summary: {response.text[:400]}",
            related_entity=ac.alert_id if ac else None,
            chain_of_custody_note="Generated by SOCInvestigatorAgent during triage.",
            created_by_agent=self.name, created_by_model=response.model,
            related_step_id=step.step_id,
        ))
        return f"Classified as '{session.classification}' (sev={sev}); " \
               f"{len(session.indicators_of_compromise)} IOC(s)."

    # --- helpers ---
    def _alert_text(self, session: SessionState) -> str:
        ac = session.alert_context
        if not ac:
            return session.user_goal
        parts = [ac.alert_name, ac.detection_name, ac.command_line, ac.url,
                 ac.domain, ac.analyst_notes, ac.raw_log, ac.business_impact]
        return "\n".join(p for p in parts if p)

    def _suggest_classification(self, text: str, failed: int, success: int) -> str:
        low = text.lower()
        if failed >= 5 and success >= 1:
            return "Confirmed Incident"
        if failed >= 5:
            return "True Positive - Actionable"
        if "block" in low and "403" in low:
            return "True Positive - Risk Already Managed"
        if "first" in low and "access" in low:
            return "Suspicious - Monitoring Required"
        return "Suspicious - Monitoring Required"

    def _mitre(self, text: str) -> list[tuple[str, str, str]]:
        low = text.lower()
        out: list[tuple[str, str, str]] = []
        for keywords, mapping in _MITRE_KEYWORDS:
            if any(k in low for k in keywords):
                out.append(mapping)
        return out
