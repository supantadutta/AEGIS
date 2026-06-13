"""Helpers for appending canonical events/records to a SessionState.

Centralizing this keeps the orchestrator and agents from duplicating the
bookkeeping for messages, model calls, tool calls, decisions and audit.
"""

from __future__ import annotations

from orchestrator.core.state import (
    AuditEntry,
    CanonicalMessage,
    ModelCallRecord,
    RouterDecision,
    SessionState,
    ToolCallRecord,
)
from orchestrator.providers.base import Prompt, ProviderResponse


def record_message(session: SessionState, message: CanonicalMessage) -> None:
    session.canonical_messages.append(message)
    session.touch()


def record_model_call(
    session: SessionState, prompt: Prompt, response: ProviderResponse, step_id: str | None
) -> ModelCallRecord:
    rec = ModelCallRecord(
        model=response.model,
        agent=prompt.agent,
        step_id=step_id,
        prompt_chars=len(prompt.instruction),
        response_chars=len(response.text),
        prompt_tokens=response.prompt_tokens,
        completion_tokens=response.completion_tokens,
        cost_usd=response.cost_usd,
        latency_ms=response.latency_ms,
    )
    session.model_calls.append(rec)
    # roll up costs / tokens
    session.costs.total_usd = round(session.costs.total_usd + response.cost_usd, 6)
    session.costs.by_model[response.model] = round(
        session.costs.by_model.get(response.model, 0.0) + response.cost_usd, 6
    )
    session.token_usage.prompt_tokens += response.prompt_tokens
    session.token_usage.completion_tokens += response.completion_tokens
    session.token_usage.by_model[response.model] = (
        session.token_usage.by_model.get(response.model, 0)
        + response.prompt_tokens + response.completion_tokens
    )
    session.touch()
    return rec


def record_tool_call(session: SessionState, rec: ToolCallRecord) -> None:
    session.tool_calls.append(rec)
    session.touch()


def record_decision(session: SessionState, decision: RouterDecision) -> None:
    session.decisions.append(decision)
    session.touch()


def audit(session: SessionState, actor: str, action: str, detail: str = "",
          step_id: str | None = None) -> None:
    session.audit_log.append(
        AuditEntry(actor=actor, action=action, detail=detail, step_id=step_id)
    )
    session.touch()
