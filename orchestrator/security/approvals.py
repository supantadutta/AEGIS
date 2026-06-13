"""Security-layer approval helpers. Thin wrappers over the configured
approval_required_actions used by the tool registry to gate execution."""

from __future__ import annotations

from orchestrator.core.approvals import action_requires_approval, approval_required_actions

__all__ = ["action_requires_approval", "approval_required_actions", "tool_requires_approval"]


def tool_requires_approval(tool_name: str, declared: bool) -> bool:
    """A tool needs approval if it declares so OR its name maps to a gated
    action in configs/security.yaml."""
    return declared or action_requires_approval(tool_name)
