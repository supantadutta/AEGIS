"""ThreatIntelAgent — enriches IOCs/observables. Local sources always on;
external sources no-op (disabled) unless configured."""

from __future__ import annotations

from typing import Any

from orchestrator.agents.base import BaseAgent
from orchestrator.core.state import EvidenceItem, SessionState, TaskStep
from orchestrator.providers.base import ProviderResponse
from orchestrator.tools.threat_intel import enrich

# Which IOC types are worth sending to threat-intel enrichment.
_ENRICHABLE = {"ip", "domain", "url", "hash", "email"}


class ThreatIntelAgent(BaseAgent):
    name = "ThreatIntelAgent"

    def context(self, session: SessionState, step: TaskStep) -> dict[str, Any]:
        ctx = super().context(session, step)
        ctx["observables"] = [
            {"type": i.type, "value": i.value}
            for i in session.indicators_of_compromise if i.type in _ENRICHABLE
        ]
        return ctx

    def apply_result(self, session: SessionState, step: TaskStep, response: ProviderResponse) -> str:
        malicious = 0
        seen = {(r.source, r.observable) for r in session.threat_intel_results}
        for ioc in session.indicators_of_compromise:
            if ioc.type not in _ENRICHABLE:
                continue
            for result in enrich(ioc.value, ioc.type):
                if (result.source, result.observable) in seen:
                    continue
                seen.add((result.source, result.observable))
                session.threat_intel_results.append(result)
                if result.verdict == "malicious":
                    malicious += 1
                    # Cache and record evidence for malicious hits.
                    if self.services.storage:
                        self.services.storage.cache_threat_intel(
                            result.source, result.observable, result.model_dump_json())
                    session.evidence_items.append(EvidenceItem(
                        type="threat_intel", source=result.source,
                        content=f"{result.observable}: {result.summary}",
                        related_entity=result.observable,
                        chain_of_custody_note="Local threat-intel match.",
                        created_by_agent=self.name, created_by_model=response.model,
                        related_step_id=step.step_id,
                    ))
        return f"Enriched {len(session.indicators_of_compromise)} IOC(s); {malicious} malicious."
