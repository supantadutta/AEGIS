"""Imports and registers all specialized agents. Imported lazily by the agent
registry's bootstrap so agent names resolve to real implementations."""

from __future__ import annotations

from orchestrator.agents import register
from orchestrator.agents.case_report import CaseReportAgent
from orchestrator.agents.detection_engineer import DetectionEngineerAgent
from orchestrator.agents.incident_response import IncidentResponseAgent
from orchestrator.agents.log_analysis import LogAnalysisAgent
from orchestrator.agents.soc_investigator import SOCInvestigatorAgent
from orchestrator.agents.threat_intel import ThreatIntelAgent

# MVP-flow agents (Phase 6). Remaining specialists register in Phase 8.
register("SOCInvestigatorAgent", SOCInvestigatorAgent)
register("ThreatIntelAgent", ThreatIntelAgent)
register("LogAnalysisAgent", LogAnalysisAgent)
register("DetectionEngineerAgent", DetectionEngineerAgent)
register("IncidentResponseAgent", IncidentResponseAgent)
register("CaseReportAgent", CaseReportAgent)


def register_phase8_agents() -> None:
    """Register the remaining Section 3.3 specialists (added in Phase 8)."""
    try:
        from orchestrator.agents import extended  # noqa: F401
    except ImportError:
        pass


register_phase8_agents()
