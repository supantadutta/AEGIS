"""Phase 8: report rendering + remaining-agent registration."""

from __future__ import annotations

import pytest

from orchestrator.agents import ALL_AGENT_NAMES, get_agent
from orchestrator.agents.base import BaseAgent
from orchestrator.core.orchestrator import Orchestrator
from orchestrator.core.state import AlertContext
from orchestrator.storage.sqlite import SQLiteStorage
from orchestrator.tools.reports import REPORT_TYPES, render_report


@pytest.fixture()
def completed_session(tmp_path):
    storage = SQLiteStorage(str(tmp_path / "rep.sqlite"))
    orch = Orchestrator(storage)
    ac = AlertContext(alert_name="Brute force", source_ip="45.143.220.0",
                      username="admin", severity="high", destination_host="DC01",
                      business_impact="DC targeted", event_time="2026-06-12T03:14:22Z",
                      raw_log="2026-06-12T03:02:10Z EventID=4625 user=admin "
                              "src_ip=45.143.220.0 dst=DC01 outcome=failure\n"
                              "2026-06-12T03:14:22Z EventID=4624 user=admin "
                              "src_ip=45.143.220.0 dst=DC01 outcome=success")
    session = orch.create_session("Investigate", alert_context=ac)
    orch.run(session)
    yield session
    storage.close()


@pytest.mark.parametrize("report_type", REPORT_TYPES)
def test_render_each_report_type(completed_session, report_type):
    body = render_report(completed_session, report_type)
    assert body.strip()
    assert "Brute force" in body or "AEGIS" in body


def test_analyst_report_contains_sections(completed_session):
    body = render_report(completed_session, "analyst")
    assert "SOC Analyst Note" in body
    assert "MITRE" in body
    assert "Recommended Actions" in body


def test_executive_report(completed_session):
    body = render_report(completed_session, "executive")
    assert "Executive Summary" in body
    assert "Business impact" in body


def test_unknown_report_type_raises(completed_session):
    with pytest.raises(ValueError):
        render_report(completed_session, "nope")


def test_all_agents_resolve():
    """Every Section 3.3 agent name resolves to a real (specialized) agent."""
    specialized = 0
    for name in ALL_AGENT_NAMES:
        agent = get_agent(name)
        assert isinstance(agent, BaseAgent)
        if type(agent) is not BaseAgent:
            specialized += 1
    # All 19 agent names should have specialized implementations.
    assert specialized == len(ALL_AGENT_NAMES)
