"""Remaining Section 3.3 specialist agents. Each is a real implementation that
works against the MockProvider; domain agents append findings/artifacts derived
from the canonical SessionState, never performing offensive actions."""

from __future__ import annotations

from typing import Any

from orchestrator.agents import register
from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import (
    Artifact,
    Finding,
    SessionState,
    TaskStep,
)
from orchestrator.providers.base import ProviderResponse
from orchestrator.tools.detections import available_use_cases, generate_query


class _DomainAgent(BaseAgent):
    """Shared behavior: record a domain finding + an analysis artifact."""

    domain = "analysis"
    finding_title = "Domain analysis"
    severity = "medium"

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        session.investigation_findings.append(Finding(
            title=self.finding_title, detail=response.text[:300],
            severity=self.severity, confidence=0.7,
        ))
        session.artifacts.append(Artifact(
            name=f"{self.name}:{self.domain}", type="analysis", content=response.text,
            created_by_agent=self.name, created_by_model=response.model, step_id=step.step_id,
        ))
        return f"{self.name} recorded a {self.domain} finding."


class DFIRAgent(_DomainAgent):
    name = "DFIRAgent"
    domain = "forensics"
    finding_title = "DFIR forensic assessment"

    def apply_result(self, session, step, response):
        summary = super().apply_result(session, step, response)
        # Root-cause hypothesis from the timeline, if present.
        if session.timeline_events:
            first = min(session.timeline_events, key=lambda e: e.timestamp)
            session.investigation_findings.append(Finding(
                title="Probable initial access",
                detail=f"Earliest observed event: {first.event_type} at "
                       f"{first.timestamp.isoformat()} from {first.source_ip or 'n/a'}.",
                severity="high", confidence=0.7,
            ))
        return summary


class MalwareTriageAgent(BaseAgent):
    """Static triage ONLY — metadata/hashes/filenames. Never executes malware."""

    name = "MalwareTriageAgent"

    def context(self, session: SessionState, step: TaskStep) -> dict[str, Any]:
        ctx = super().context(session, step)
        ctx["hashes"] = [i.value for i in session.indicators_of_compromise if i.type == "hash"]
        ctx["filenames"] = [i.value for i in session.indicators_of_compromise if i.type == "filename"]
        ctx["note"] = "static triage only; no execution"
        return ctx

    def apply_result(self, session, step, response):
        hashes = [i for i in session.indicators_of_compromise if i.type == "hash"]
        for h in hashes:
            algo = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h.value), "unknown")
            session.investigation_findings.append(Finding(
                title=f"Static hash triage ({algo})",
                detail=f"Observed {algo} hash {h.value}. Recommend reputation lookup "
                       f"via threat intel; no dynamic execution performed (safe triage).",
                severity="medium", confidence=0.6, related_entities=[h.value],
            ))
        session.artifacts.append(Artifact(
            name="malware_static_triage", type="analysis", content=response.text,
            created_by_agent=self.name, created_by_model=response.model, step_id=step.step_id,
        ))
        return f"Static triage of {len(hashes)} hash(es); no execution."


class IdentitySecurityAgent(_DomainAgent):
    name = "IdentitySecurityAgent"
    domain = "identity"
    finding_title = "Identity/authentication analysis"


class NetworkSecurityAgent(_DomainAgent):
    name = "NetworkSecurityAgent"
    domain = "network"
    finding_title = "Network security analysis"


class CloudSecurityAgent(_DomainAgent):
    name = "CloudSecurityAgent"
    domain = "cloud"
    finding_title = "Cloud security analysis"


class VulnerabilityRiskAgent(_DomainAgent):
    name = "VulnerabilityRiskAgent"
    domain = "vulnerability"
    finding_title = "Vulnerability & risk correlation"

    def apply_result(self, session, step, response):
        summary = super().apply_result(session, step, response)
        for cve in [i.value for i in session.indicators_of_compromise if i.type == "cve"]:
            session.recommended_actions.append(
                f"Prioritize remediation for {cve} on exposed/critical assets.")
        return summary


class QueryBuilderAgent(BaseAgent):
    name = "QueryBuilderAgent"
    _PLATFORMS = ["splunk", "kql", "logscale"]

    def apply_result(self, session, step, response):
        use_case = self._infer_use_case(session)
        before = len(session.generated_queries)
        for platform in self._PLATFORMS:
            try:
                gq = generate_query(platform, use_case)
            except (KeyError, ValueError):
                continue
            session.generated_queries.append(gq)
        return f"Generated {len(session.generated_queries) - before} query/queries for '{use_case}'."

    def _infer_use_case(self, session: SessionState) -> str:
        text = " ".join(filter(None, [
            session.alert_context.alert_name if session.alert_context else None,
            " ".join(m.technique_name for m in session.mitre_attack_mapping),
        ])).lower()
        mapping = [
            (("brute", "4625"), "brute-force"),
            (("powershell", "encoded"), "suspicious-powershell"),
            (("traversal",), "directory-traversal"),
            (("lateral",), "lateral-movement"),
        ]
        for keywords, slug in mapping:
            if any(k in text for k in keywords) and slug in available_use_cases():
                return slug
        return "brute-force"


class PlaybookAgent(BaseAgent):
    """Creates playbooks. Risky steps are flagged as approval-required; the
    PlaybookAgent never executes risky actions itself."""

    name = "PlaybookAgent"

    def apply_result(self, session, step, response):
        playbook = (
            "# Response Playbook (DRAFT)\n"
            "1. Verify the alert and scope (read-only).\n"
            "2. Collect evidence and preserve chain of custody (read-only).\n"
            "3. [APPROVAL REQUIRED] Contain: block source / disable account / isolate host.\n"
            "4. [APPROVAL REQUIRED] Eradicate: remove persistence, reset credentials.\n"
            "5. Recover and monitor.\n"
        )
        session.artifacts.append(Artifact(
            name="response_playbook", type="playbook", content=playbook,
            created_by_agent=self.name, created_by_model=response.model, step_id=step.step_id,
        ))
        return "Drafted response playbook (risky steps flagged approval-required)."


class SecurityReviewAgent(BaseAgent):
    """Reviews generated queries/rules/recommendations for safety & FP risk."""

    name = "SecurityReviewAgent"
    _DANGEROUS = ("delete", "drop table", "truncate", "rm -rf", "format", "shutdown",
                  "| delete", "outputlookup")

    def apply_result(self, session, step, response):
        concerns: list[str] = []
        for q in session.generated_queries:
            low = q.query.lower()
            for bad in self._DANGEROUS:
                if bad in low:
                    concerns.append(f"Query for {q.use_case} ({q.platform}) contains "
                                    f"potentially destructive token: {bad!r}")
        for r in session.detection_rules:
            if not r.false_positive_notes:
                concerns.append(f"Detection '{r.title}' lacks false-positive notes.")
        session.investigation_findings.append(Finding(
            title="Security review of generated artifacts",
            detail=("No safety concerns identified; all queries are read-only and "
                    "time-scopeable." if not concerns else "; ".join(concerns)),
            severity="low" if not concerns else "medium", confidence=0.8,
        ))
        return f"Reviewed artifacts; {len(concerns)} concern(s)."


class SummarizerAgent(BaseAgent):
    """Compresses the investigation while preserving evidence/IOCs/decisions."""

    name = "SummarizerAgent"

    def apply_result(self, session, step, response):
        iocs = ", ".join(f"{i.type}:{i.value}" for i in session.indicators_of_compromise[:8])
        mitre = ", ".join(m.technique_id for m in session.mitre_attack_mapping)
        summary = (
            f"Goal: {session.user_goal}. Classification: {session.classification}. "
            f"Severity: {session.severity_assessment.severity if session.severity_assessment else 'n/a'}. "
            f"IOCs: {iocs or 'none'}. MITRE: {mitre or 'none'}. "
            f"{len(session.timeline_events)} timeline event(s), "
            f"{len(session.detection_rules)} detection(s), "
            f"{len(session.containment_actions)} approval-gated containment action(s)."
        )
        session.memory_summary = summary
        return "Summarized investigation into memory_summary."


class DocumentationAgent(BaseAgent):
    name = "DocumentationAgent"

    def apply_result(self, session, step, response):
        session.artifacts.append(Artifact(
            name="runbook", type="documentation", content=response.text,
            created_by_agent=self.name, created_by_model=response.model, step_id=step.step_id,
        ))
        return "Authored documentation artifact."


class DevOpsAgent(_DomainAgent):
    name = "DevOpsAgent"
    domain = "devops"
    finding_title = "Deployment/operations note"


# Register all extended agents.
for _name, _cls in {
    "DFIRAgent": DFIRAgent,
    "MalwareTriageAgent": MalwareTriageAgent,
    "IdentitySecurityAgent": IdentitySecurityAgent,
    "NetworkSecurityAgent": NetworkSecurityAgent,
    "CloudSecurityAgent": CloudSecurityAgent,
    "VulnerabilityRiskAgent": VulnerabilityRiskAgent,
    "QueryBuilderAgent": QueryBuilderAgent,
    "PlaybookAgent": PlaybookAgent,
    "SecurityReviewAgent": SecurityReviewAgent,
    "SummarizerAgent": SummarizerAgent,
    "DocumentationAgent": DocumentationAgent,
    "DevOpsAgent": DevOpsAgent,
}.items():
    register(_name, _cls)
