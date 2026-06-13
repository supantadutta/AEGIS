"""Filesystem tools: read/list/search (low risk) and write (gated)."""

from __future__ import annotations

import fnmatch
from pathlib import Path

from pydantic import BaseModel

from orchestrator.tools.registry import ToolDefinition, ToolRegistry, ToolResult


class ReadFileInput(BaseModel):
    path: str
    max_bytes: int = 200_000


class WriteFileInput(BaseModel):
    path: str
    content: str


class ListFilesInput(BaseModel):
    directory: str = "."
    pattern: str = "*"


class SearchFilesInput(BaseModel):
    directory: str = "."
    query: str
    glob: str = "*"


def _read_file(inp: ReadFileInput) -> ToolResult:
    p = Path(inp.path)
    if not p.is_file():
        return ToolResult(success=False, error=f"not a file: {inp.path}")
    data = p.read_text(errors="replace")[: inp.max_bytes]
    return ToolResult(output=data, metadata={"bytes": len(data)})


def _write_file(inp: WriteFileInput) -> ToolResult:
    p = Path(inp.path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(inp.content)
    return ToolResult(output=f"wrote {len(inp.content)} bytes to {inp.path}")


def _list_files(inp: ListFilesInput) -> ToolResult:
    base = Path(inp.directory)
    if not base.is_dir():
        return ToolResult(success=False, error=f"not a directory: {inp.directory}")
    matches = [str(p) for p in base.rglob("*")
               if p.is_file() and fnmatch.fnmatch(p.name, inp.pattern)]
    return ToolResult(output="\n".join(matches[:500]), metadata={"count": len(matches)})


def _search_files(inp: SearchFilesInput) -> ToolResult:
    base = Path(inp.directory)
    hits: list[str] = []
    for p in base.rglob("*"):
        if not p.is_file() or not fnmatch.fnmatch(p.name, inp.glob):
            continue
        try:
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if inp.query in line:
                    hits.append(f"{p}:{n}: {line.strip()[:160]}")
        except OSError:
            continue
    return ToolResult(output="\n".join(hits[:300]), metadata={"count": len(hits)})


def register(registry: ToolRegistry) -> None:
    registry.register(ToolDefinition(
        name="read_file", description="Read a text file (read-only).",
        input_schema=ReadFileInput, risk_level="low", approval_required=False,
        execution_fn=_read_file))
    registry.register(ToolDefinition(
        name="write_file", description="Write a text file (modifies the filesystem).",
        input_schema=WriteFileInput, risk_level="medium", approval_required=True,
        execution_fn=_write_file))
    registry.register(ToolDefinition(
        name="list_files", description="List files under a directory.",
        input_schema=ListFilesInput, risk_level="low", approval_required=False,
        execution_fn=_list_files))
    registry.register(ToolDefinition(
        name="search_files", description="Search files for a substring.",
        input_schema=SearchFilesInput, risk_level="low", approval_required=False,
        execution_fn=_search_files))
