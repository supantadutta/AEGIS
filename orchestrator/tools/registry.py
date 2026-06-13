"""Tool registry. Tools are callable by agents ONLY through the orchestrator's
registry, which enforces approval gates, shell policy, secret redaction and
audit logging on every call (Section 10/12)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from orchestrator.core.state import SessionState, ToolCallRecord
from orchestrator.security.approvals import tool_requires_approval
from orchestrator.security.audit import AuditLogger
from orchestrator.security.policy import command_denied_reason
from orchestrator.security.redaction import redact


class ToolResult(BaseModel):
    success: bool = True
    output: str = ""
    error: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolDefinition(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: str
    description: str
    input_schema: type[BaseModel]
    output_schema: type[BaseModel] = ToolResult
    risk_level: str = "low"
    approval_required: bool = False
    execution_fn: Callable[..., ToolResult] = Field(exclude=True)


class ToolRegistry:
    def __init__(self, storage=None) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        self.audit = AuditLogger(storage)

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def list(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def execute(
        self,
        name: str,
        params: dict[str, Any] | BaseModel,
        session: SessionState,
        *,
        agent: str = "",
        step_id: str | None = None,
        approved: bool = False,
    ) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(success=False, error=f"unknown tool: {name}")

        model_in = params if isinstance(params, BaseModel) else tool.input_schema(**params)
        input_summary = redact(str(model_in.model_dump()))[:300]

        # Approval gate (declared OR config-gated action name).
        needs_approval = tool_requires_approval(name, tool.approval_required)
        if needs_approval and not approved:
            self._record(session, name, agent, step_id, input_summary,
                         "approval required — not executed", success=False,
                         approved=False, risk=tool.risk_level)
            self.audit.log(session, agent or "agent", "tool_denied",
                           f"{name}: approval required", step_id)
            return ToolResult(success=False, error="approval_required",
                              metadata={"requires_approval": True})

        # Shell policy is enforced even when approved.
        if name == "run_shell_command":
            cmd = getattr(model_in, "command", "")
            reason = command_denied_reason(cmd)
            if reason:
                self._record(session, name, agent, step_id, input_summary,
                             f"denied by policy: {reason}", success=False,
                             approved=approved, risk=tool.risk_level)
                self.audit.log(session, agent or "agent", "policy_violation",
                               f"{name}: {reason}", step_id)
                return ToolResult(success=False, error=f"policy_denied: {reason}")

        try:
            result = tool.execution_fn(model_in)
        except Exception as exc:  # noqa: BLE001 - surface as a failed ToolResult
            result = ToolResult(success=False, error=str(exc))

        out_summary = redact(result.output or result.error)[:300]
        self._record(session, name, agent, step_id, input_summary, out_summary,
                     success=result.success, approved=(approved if needs_approval else None),
                     risk=tool.risk_level)
        self.audit.log(session, agent or "agent", "tool_executed",
                       f"{name}: success={result.success}", step_id)
        return result

    def _record(self, session: SessionState, tool: str, agent: str, step_id: str | None,
                input_summary: str, output_summary: str, *, success: bool,
                approved: bool | None, risk: str) -> None:
        session.tool_calls.append(ToolCallRecord(
            tool=tool, agent=agent, step_id=step_id, input_summary=input_summary,
            output_summary=output_summary, success=success, approved=approved,
            risk_level=risk,
        ))
        session.touch()


def build_default_registry(storage=None) -> ToolRegistry:
    """Construct a registry with all MVP tools registered."""
    registry = ToolRegistry(storage)
    from orchestrator.tools import filesystem, git, shell
    filesystem.register(registry)
    shell.register(registry)
    git.register(registry)
    return registry
