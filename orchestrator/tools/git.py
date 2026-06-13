"""Read-only git tools: status and diff."""

from __future__ import annotations

import subprocess

from pydantic import BaseModel

from orchestrator.tools.registry import ToolDefinition, ToolRegistry, ToolResult


class GitInput(BaseModel):
    repo: str = "."


def _git(repo: str, *args: str) -> ToolResult:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed git args, read-only
            ["git", "-C", repo, *args],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except FileNotFoundError:
        return ToolResult(success=False, error="git not installed")
    return ToolResult(success=proc.returncode == 0,
                      output=(proc.stdout or "") + (proc.stderr or ""),
                      metadata={"returncode": proc.returncode})


def _git_status(inp: GitInput) -> ToolResult:
    return _git(inp.repo, "status", "--short", "--branch")


def _git_diff(inp: GitInput) -> ToolResult:
    return _git(inp.repo, "diff", "--stat")


def register(registry: ToolRegistry) -> None:
    registry.register(ToolDefinition(
        name="git_status", description="Show git working-tree status (read-only).",
        input_schema=GitInput, risk_level="low", approval_required=False,
        execution_fn=_git_status))
    registry.register(ToolDefinition(
        name="git_diff", description="Show git diff stat (read-only).",
        input_schema=GitInput, risk_level="low", approval_required=False,
        execution_fn=_git_diff))
