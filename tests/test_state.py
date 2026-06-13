"""Phase 1: SessionState schema round-trips and alert parsing."""

from __future__ import annotations

import json

from orchestrator.core.state import (
    IOC,
    Finding,
    MitreMapping,
    RouterDecision,
    SessionState,
    TaskGraph,
    TaskStep,
    TimelineEvent,
    utcnow,
)
from orchestrator.tools.parsers import parse_alert


def _rich_state() -> SessionState:
    step = TaskStep(name="Triage", agent="SOCInvestigatorAgent", task_type="triage")
    return SessionState(
        user_goal="Investigate brute force alert",
        security_task_type="soc_investigation",
        task_graph=TaskGraph(goal="brute force", steps=[step]),
        current_step_id=step.step_id,
        indicators_of_compromise=[IOC(type="ip", value="45.143.220.0")],
        timeline_events=[
            TimelineEvent(
                timestamp=utcnow(), source="auth", event_type="login_failure",
                explanation="failed login", confidence=0.9,
            )
        ],
        investigation_findings=[Finding(title="Brute force", detail="many fails")],
        mitre_attack_mapping=[
            MitreMapping(tactic="Credential Access", technique_id="T1110",
                         technique_name="Brute Force", confidence=0.86)
        ],
    )


def test_session_state_roundtrip():
    state = _rich_state()
    dumped = state.to_json()
    reloaded = SessionState.from_json(dumped)
    assert reloaded.session_id == state.session_id
    assert reloaded.current_step_id == state.current_step_id
    assert reloaded.indicators_of_compromise[0].value == "45.143.220.0"
    assert reloaded.mitre_attack_mapping[0].technique_id == "T1110"
    # Full structural equality after a round trip.
    assert reloaded.model_dump() == state.model_dump()


def test_session_state_defaults():
    state = SessionState(user_goal="x")
    assert state.status == "created"
    assert state.data_sensitivity == "internal"
    assert state.completed_steps == []
    assert state.costs.total_usd == 0.0
    assert state.token_usage.prompt_tokens == 0


def test_router_decision_shape():
    decision = RouterDecision(
        selected_agent="SOCInvestigatorAgent",
        selected_model="anthropic/claude-sonnet",
        reason="High reasoning depth needed for triage",
        confidence=0.86,
        fallback_models=["openai/gpt-5.5", "mock/mock-model"],
    )
    payload = json.loads(decision.model_dump_json())
    for key in ("selected_agent", "selected_model", "reason", "confidence",
                "fallback_models", "requires_human_approval", "risk_level",
                "data_sensitivity"):
        assert key in payload


def test_alert_parse_json():
    text = json.dumps({"alert_name": "Brute force", "src_ip": "1.2.3.4", "user": "admin"})
    ctx = parse_alert(text)
    assert ctx.alert_name == "Brute force"
    assert ctx.source_ip == "1.2.3.4"
    assert ctx.username == "admin"
    assert "destination_ip" in ctx.missing_fields


def test_alert_parse_markdown():
    text = "**Alert Name:** Suspicious PowerShell\n- src_ip: 9.9.9.9\n- user: arossi"
    ctx = parse_alert(text)
    assert ctx.alert_name == "Suspicious PowerShell"
    assert ctx.source_ip == "9.9.9.9"


def test_alert_parse_csv():
    text = "alert_name,src_ip,user\nDNS tunneling,8.8.8.8,svc-backup"
    ctx = parse_alert(text, fmt="csv")
    assert ctx.alert_name == "DNS tunneling"
    assert ctx.source_ip == "8.8.8.8"


def test_alert_parse_text_fallback():
    text = "We saw user=jsmith logging in from src_ip=5.5.5.5 repeatedly."
    ctx = parse_alert(text)
    assert ctx.username == "jsmith"
    assert ctx.source_ip == "5.5.5.5"
    assert ctx.raw_log is not None


def test_alert_context_missing_fields_tracked():
    ctx = parse_alert(json.dumps({"alert_name": "x"}))
    assert "source_ip" in ctx.missing_fields
    assert "alert_name" not in ctx.missing_fields
