"""Shell tool — APPROVAL REQUIRED and policy-gated. Default posture denies
everything (empty allowlist). Execution only happens after the registry has
verified approval AND the command passes the allow/deny policy."""

from __future__ import annotations

import shlex
import subprocess

from pydantic import BaseModel

from orchestrator.tools.registry import ToolDefinition, ToolRegistry, ToolResult


class ShellInput(BaseModel):
    command: str
    timeout: int = 30


def _run_shell(inp: ShellInput) -> ToolResult:
    # The registry has already enforced approval + allow/deny policy before
    # we get here. We still run without shell=True and capture output safely.
    try:
        proc = subprocess.run(  # noqa: S603 - policy-gated, no shell expansion
            shlex.split(inp.command),
            capture_output=True, text=True, timeout=inp.timeout, check=False,
        )
    except (FileNotFoundError, ValueError) as exc:
        return ToolResult(success=False, error=f"could not run command: {exc}")
    except subprocess.TimeoutExpired:
        return ToolResult(success=False, error="command timed out")
    output = (proc.stdout or "") + (proc.stderr or "")
    return ToolResult(success=proc.returncode == 0, output=output,
                      metadata={"returncode": proc.returncode})


def register(registry: ToolRegistry) -> None:
    registry.register(ToolDefinition(
        name="run_shell_command",
        description="Run a shell command. REQUIRES human approval and must pass "
                    "the allow/deny policy in configs/security.yaml.",
        input_schema=ShellInput, risk_level="high", approval_required=True,
        execution_fn=_run_shell))
