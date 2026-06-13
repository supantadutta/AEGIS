"""Phase 7: tool registry approval gating and policy enforcement."""

from __future__ import annotations

import pytest

from orchestrator.core.state import SessionState
from orchestrator.storage.sqlite import SQLiteStorage
from orchestrator.tools.registry import build_default_registry


@pytest.fixture()
def reg_session(tmp_path):
    storage = SQLiteStorage(str(tmp_path / "t.sqlite"))
    registry = build_default_registry(storage)
    session = SessionState(user_goal="x")
    yield registry, session
    storage.close()


def test_shell_denied_without_approval(reg_session):
    registry, session = reg_session
    res = registry.execute("run_shell_command", {"command": "echo hi"}, session)
    assert res.success is False
    assert res.error == "approval_required"
    # tool call recorded as not approved
    assert session.tool_calls[-1].tool == "run_shell_command"
    assert session.tool_calls[-1].approved is False


def test_shell_denied_by_policy_even_with_approval(reg_session):
    registry, session = reg_session
    res = registry.execute("run_shell_command", {"command": "rm -rf /"},
                           session, approved=True)
    assert res.success is False
    assert "policy_denied" in res.error
    assert any(a.action == "policy_violation" for a in session.audit_log)


def test_shell_empty_allowlist_blocks_even_approved(reg_session):
    registry, session = reg_session
    # 'echo hi' is not denylisted but allowlist is empty => denied by policy.
    res = registry.execute("run_shell_command", {"command": "echo hi"},
                           session, approved=True)
    assert res.success is False
    assert "policy_denied" in res.error


def test_read_file_low_risk_no_approval(reg_session, tmp_path):
    registry, session = reg_session
    f = tmp_path / "x.txt"
    f.write_text("hello")
    res = registry.execute("read_file", {"path": str(f)}, session)
    assert res.success is True
    assert "hello" in res.output


def test_write_file_requires_approval(reg_session, tmp_path):
    registry, session = reg_session
    target = str(tmp_path / "out.txt")
    res = registry.execute("write_file", {"path": target, "content": "data"}, session)
    assert res.success is False and res.error == "approval_required"
    # with approval it writes
    res2 = registry.execute("write_file", {"path": target, "content": "data"},
                            session, approved=True)
    assert res2.success is True


def test_audit_and_redaction_on_tool_calls(reg_session, tmp_path):
    registry, session = reg_session
    f = tmp_path / "s.txt"
    f.write_text('api_key="ABCDEFGHIJKLMNOP1234567"')
    registry.execute("read_file", {"path": str(f)}, session)
    # output summary in the tool call record must be redacted
    rec = session.tool_calls[-1]
    assert "ABCDEFGHIJKLMNOP" not in rec.output_summary
    assert any(a.action == "tool_executed" for a in session.audit_log)


def test_unknown_tool(reg_session):
    registry, session = reg_session
    res = registry.execute("nonexistent", {}, session)
    assert res.success is False and "unknown tool" in res.error
