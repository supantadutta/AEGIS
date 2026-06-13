"""Deterministic, offline MockProvider.

This is what makes AEGIS runnable with zero API keys. It never makes a network
call. Given an agent + task type + context, it returns stable narrative text
and a small structured payload that the agent maps into SessionState. Heavy
structured work (IOC extraction, timeline, detections) is done by the agents'
deterministic tools — the provider supplies reasoning narrative and decisions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from orchestrator.core.state import CanonicalMessage, SessionState
from orchestrator.providers.base import Prompt, ProviderAdapter, ProviderResponse


def _stable_conf(seed: str, lo: float = 0.7, hi: float = 0.92) -> float:
    """Deterministic pseudo-confidence in [lo, hi] derived from a seed."""
    h = int(hashlib.sha256(seed.encode()).hexdigest(), 16)
    return round(lo + (h % 1000) / 1000.0 * (hi - lo), 2)


class MockProvider(ProviderAdapter):
    provider = "mock"

    def __init__(self, model_id: str = "mock/mock-model") -> None:
        super().__init__(model_id)

    def is_available(self) -> bool:
        return True

    def to_provider_format(self, session: SessionState, prompt: Prompt) -> dict[str, Any]:
        return {
            "model": self.model_id,
            "system": prompt.system,
            "messages": [{"role": "user", "content": prompt.instruction}],
            "context": prompt.context,
        }

    def from_provider_format(self, raw: dict[str, Any], prompt: Prompt) -> list[CanonicalMessage]:
        return [
            CanonicalMessage(
                role="assistant",
                content=raw.get("text", ""),
                agent=prompt.agent,
                model=self.model_id,
                metadata={"structured": raw.get("structured")},
            )
        ]

    def generate(
        self, session: SessionState, prompt: Prompt, tools: list[Any] | None = None
    ) -> ProviderResponse:
        builder = _DISPATCH.get(prompt.agent, _generic)
        text, structured = builder(prompt, session)
        return ProviderResponse(
            model=self.model_id,
            text=text,
            structured=structured,
            prompt_tokens=self._approx_tokens(prompt.instruction + json.dumps(prompt.context)),
            completion_tokens=self._approx_tokens(text),
            cost_usd=0.0,
            latency_ms=1.0,
            raw={"text": text, "structured": structured},
        )


# --- per-agent deterministic builders --------------------------------------
# Each returns (narrative_text, structured_dict).


def _ctx(prompt: Prompt, *keys: str) -> dict:
    return {k: prompt.context.get(k) for k in keys}


def _planner(prompt: Prompt, session: SessionState):
    text = (
        "Decomposed the security task into an ordered investigation plan: "
        "intake, triage, enrichment, timeline, detection engineering, response, report."
    )
    return text, {"plan_rationale": text}


def _soc(prompt: Prompt, session: SessionState):
    alert = prompt.context.get("alert_name", "the alert")
    src = prompt.context.get("source_ip")
    user = prompt.context.get("username")
    n_fail = prompt.context.get("failed_logins")
    seed = f"{alert}|{src}|{user}"
    classification = prompt.context.get("suggested_classification", "Suspicious - Monitoring Required")
    severity = prompt.context.get("severity") or "medium"
    text = (
        f"Triage of '{alert}': observed activity involving "
        f"{'source IP ' + str(src) if src else 'an unknown source'}"
        f"{' and user ' + str(user) if user else ''}. "
        f"{'Repeated authentication failures (' + str(n_fail) + ') preceding a success are consistent with brute force. ' if n_fail else ''}"
        f"Initial classification: {classification}."
    )
    return text, {
        "classification": classification,
        "severity": severity,
        "confidence": _stable_conf(seed),
        "findings": [
            {"title": f"Entities involved in {alert}",
             "detail": f"src_ip={src}, user={user}", "severity": severity},
        ],
        "true_positive_reasoning": "Pattern matches known malicious behavior for this alert type.",
    }


def _threat_intel(prompt: Prompt, session: SessionState):
    return (
        "Enrichment complete. Local allow/blocklists consulted; external sources "
        "report disabled unless an API key is configured.",
        {"summary": "local-first enrichment performed"},
    )


def _log(prompt: Prompt, session: SessionState):
    return (
        "Parsed provided logs and assembled a chronological timeline across "
        "authentication and related event sources; suspicious sequences flagged.",
        {"summary": "timeline assembled"},
    )


def _detection(prompt: Prompt, session: SessionState):
    uc = prompt.context.get("use_case", "the observed behavior")
    return (
        f"Recommended detection coverage and tuning for {uc}. Generated rules/queries "
        "with false-positive notes and validation steps.",
        {"summary": f"detections for {uc}"},
    )


def _incident(prompt: Prompt, session: SessionState):
    return (
        "Drafted response plan. Containment, eradication and recovery actions are "
        "recommendations only; any active action requires human approval.",
        {
            "containment": [
                "Recommend (approval-gated) blocking the malicious source IP at the perimeter",
                "Recommend (approval-gated) resetting credentials for the targeted account",
            ],
            "eradication": ["Remove any persistence mechanisms identified during DFIR"],
            "recovery": ["Restore affected accounts and verify clean state before re-enabling"],
            "lessons_learned": ["Enforce MFA and lockout thresholds on privileged accounts"],
        },
    )


def _report(prompt: Prompt, session: SessionState):
    return (
        "Authored analyst note and closure summary from the canonical SessionState, "
        "preserving evidence, timeline, IOCs and MITRE mapping.",
        {"closure_note": "Investigation complete; see analyst note for details."},
    )


def _security_review(prompt: Prompt, session: SessionState):
    return (
        "Reviewed generated queries and rules: no destructive operations, time-scoped, "
        "false-positive guidance present. No safety concerns identified.",
        {"approved": True, "concerns": []},
    )


def _summarizer(prompt: Prompt, session: SessionState):
    return (
        "Condensed the investigation while preserving timestamps, IOCs, affected assets "
        "and key decisions.",
        {"summary": "investigation summarized"},
    )


def _generic(prompt: Prompt, session: SessionState):
    return (
        f"[{prompt.agent}] processed task '{prompt.task_type}'. "
        f"{prompt.instruction[:160]}",
        {"summary": f"{prompt.agent} completed {prompt.task_type}"},
    )


_DISPATCH = {
    "PlannerAgent": _planner,
    "SOCInvestigatorAgent": _soc,
    "ThreatIntelAgent": _threat_intel,
    "LogAnalysisAgent": _log,
    "DetectionEngineerAgent": _detection,
    "QueryBuilderAgent": _detection,
    "IncidentResponseAgent": _incident,
    "CaseReportAgent": _report,
    "DocumentationAgent": _report,
    "SecurityReviewAgent": _security_review,
    "SummarizerAgent": _summarizer,
}
