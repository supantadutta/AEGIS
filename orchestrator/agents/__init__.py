"""Agent registry. Maps agent name -> agent class. Specialized agents register
themselves here; names without a specialized class fall back to BaseAgent.
"""

from __future__ import annotations

from orchestrator.agents.base import AgentServices, BaseAgent

# Populated by register(); see _bootstrap below.
_REGISTRY: dict[str, type[BaseAgent]] = {}

# Every agent name from the spec (Section 3.3). Defaults to BaseAgent until a
# specialized implementation registers itself.
ALL_AGENT_NAMES = [
    "PlannerAgent", "SOCInvestigatorAgent", "IncidentResponseAgent",
    "DetectionEngineerAgent", "ThreatIntelAgent", "LogAnalysisAgent",
    "DFIRAgent", "MalwareTriageAgent", "IdentitySecurityAgent",
    "NetworkSecurityAgent", "CloudSecurityAgent", "VulnerabilityRiskAgent",
    "CaseReportAgent", "QueryBuilderAgent", "PlaybookAgent",
    "SecurityReviewAgent", "SummarizerAgent", "DocumentationAgent",
    "DevOpsAgent",
]


def register(name: str, cls: type[BaseAgent]) -> None:
    _REGISTRY[name] = cls


def get_agent(name: str, services: AgentServices | None = None) -> BaseAgent:
    cls = _REGISTRY.get(name, BaseAgent)
    agent = cls(services)
    agent.name = name
    return agent


def _bootstrap() -> None:
    """Import specialized agents so they register. Safe if modules are absent."""
    try:
        from orchestrator.agents import specialized  # noqa: F401
    except ImportError:
        pass


_bootstrap()
