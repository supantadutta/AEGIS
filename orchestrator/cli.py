"""AEGIS CLI (`blue-orchestrator`). Local-first, mock by default."""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from orchestrator.core.config import env_bool, load_models, model_ids
from orchestrator.core.orchestrator import Orchestrator
from orchestrator.core.state import SessionState
from orchestrator.storage.sqlite import SQLiteStorage
from orchestrator.tools.detections import available_use_cases, generate_query, generate_sigma
from orchestrator.tools.parsers import parse_alert
from orchestrator.tools.reports import render_report

app = typer.Typer(
    name="blue-orchestrator",
    help="AEGIS — Multi-AI Blue Team Orchestrator (defensive, local-first).",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


def _db_path() -> str:
    return os.getenv("AEGIS_DB_PATH", "aegis.sqlite")


def _storage() -> SQLiteStorage:
    return SQLiteStorage(_db_path())


def _orch(storage: SQLiteStorage) -> Orchestrator:
    return Orchestrator(storage)


def _print_summary(session: SessionState) -> None:
    console.print(Panel(
        f"[bold]Session[/bold] {session.session_id}\n"
        f"status=[green]{session.status}[/green]  "
        f"classification={session.classification}  "
        f"severity={session.severity_assessment.severity if session.severity_assessment else 'n/a'}\n"
        f"IOCs={len(session.indicators_of_compromise)}  "
        f"timeline={len(session.timeline_events)}  "
        f"detections={len(session.detection_rules)}  "
        f"queries={len(session.generated_queries)}  "
        f"MITRE={[m.technique_id for m in session.mitre_attack_mapping]}",
        title="AEGIS investigation", border_style="cyan",
    ))


def _run_investigation(text: str, fmt: str, sensitivity: str, auto_approve: bool) -> SessionState:
    storage = _storage()
    try:
        orch = _orch(storage)
        alert = parse_alert(text, fmt=fmt)
        goal = f"Investigate alert: {alert.alert_name or 'pasted text'}"
        session = orch.create_session(
            goal, alert_context=alert, security_task_type="soc_investigation",
            data_sensitivity=sensitivity,
        )
        orch.run(session, auto_approve=auto_approve)
        _print_summary(session)
        if session.status == "waiting_approval":
            console.print("[yellow]Paused for human approval. Approve and run "
                          f"`blue-orchestrator resume {session.session_id}`.[/yellow]")
        return session
    finally:
        storage.close()


# --- commands ---------------------------------------------------------------


@app.command()
def init() -> None:
    """Initialize the local SQLite database and print configuration."""
    storage = _storage()
    storage.close()
    console.print(Panel(
        f"Initialized AEGIS database at [bold]{_db_path()}[/bold]\n"
        f"ROUTER_MODE={os.getenv('ROUTER_MODE', 'rules')}  "
        f"ORCH_ENABLE_PARALLEL={env_bool('ORCH_ENABLE_PARALLEL')}  "
        f"ALLOW_EXTERNAL_FOR_SENSITIVE={env_bool('ALLOW_EXTERNAL_FOR_SENSITIVE')}\n"
        f"Models: {', '.join(model_ids())}",
        title="AEGIS init", border_style="green",
    ))


@app.command()
def investigate(
    alert_file: Path = typer.Argument(..., help="Path to alert JSON/CSV/markdown/text"),
    sensitivity: str = typer.Option("internal", help="public|internal|confidential|restricted"),
    auto_approve: bool = typer.Option(False, "--auto-approve", help="Auto-approve gated steps"),
) -> None:
    """Investigate an alert file end-to-end."""
    if not alert_file.exists():
        console.print(f"[red]File not found: {alert_file}[/red]")
        raise typer.Exit(1)
    fmt = {"json": "json", "csv": "csv", "md": "markdown"}.get(
        alert_file.suffix.lstrip("."), "auto")
    _run_investigation(alert_file.read_text(), fmt, sensitivity, auto_approve)


@app.command("investigate-text")
def investigate_text(
    text: str = typer.Argument(..., help="Pasted alert text"),
    sensitivity: str = typer.Option("internal"),
    auto_approve: bool = typer.Option(False, "--auto-approve"),
) -> None:
    """Investigate a pasted free-form alert."""
    _run_investigation(text, "text", sensitivity, auto_approve)


@app.command()
def run(
    task: str = typer.Argument(..., help="Free-form security task"),
    task_type: str = typer.Option("soc_investigation"),
    sensitivity: str = typer.Option("internal"),
    auto_approve: bool = typer.Option(False, "--auto-approve"),
) -> None:
    """Run an arbitrary security task through the orchestrator."""
    storage = _storage()
    try:
        orch = _orch(storage)
        session = orch.create_session(task, security_task_type=task_type,
                                      data_sensitivity=sensitivity)
        orch.run(session, auto_approve=auto_approve)
        _print_summary(session)
    finally:
        storage.close()


@app.command()
def sessions() -> None:
    """List all sessions."""
    storage = _storage()
    try:
        rows = storage.list_sessions()
        table = Table(title="AEGIS sessions")
        for col in ("session_id", "status", "task_type", "goal", "updated_at"):
            table.add_column(col)
        for r in rows:
            table.add_row(r["session_id"][:8], r["status"], r["security_task_type"],
                          (r["user_goal"] or "")[:40], r["updated_at"][:19])
        console.print(table)
    finally:
        storage.close()


@app.command()
def inspect(session_id: str) -> None:
    """Show details for a session (task graph, decisions, findings)."""
    storage = _storage()
    try:
        session = _resolve(storage, session_id)
        _print_summary(session)
        table = Table(title="Task graph")
        for col in ("step", "agent", "status", "model"):
            table.add_column(col)
        for s in session.task_graph.steps:
            table.add_row(s.name, s.agent, s.status, s.selected_model or "-")
        console.print(table)
        if session.investigation_findings:
            console.print("[bold]Findings:[/bold]")
            for f in session.investigation_findings:
                console.print(f"  • [{f.severity}] {f.title}: {f.detail[:100]}")
    finally:
        storage.close()


@app.command()
def resume(
    session_id: str,
    model: str = typer.Option(None, "--model", help="Resume with a different model"),
    auto_approve: bool = typer.Option(False, "--auto-approve"),
) -> None:
    """Resume a paused session, optionally with a different model."""
    if model and model not in model_ids():
        console.print(f"[red]Unknown model '{model}'. Known: {', '.join(model_ids())}[/red]")
        raise typer.Exit(1)
    storage = _storage()
    try:
        orch = _orch(storage)
        session = orch.resume(session_id, model_override=model, auto_approve=auto_approve)
        _print_summary(session)
    finally:
        storage.close()


@app.command()
def rollback(session_id: str, checkpoint_id: str) -> None:
    """Roll a session back to a prior checkpoint (history preserved)."""
    storage = _storage()
    try:
        orch = _orch(storage)
        session = orch.checkpoints.rollback(session_id, checkpoint_id)
        console.print(f"[green]Rolled back {session_id[:8]} to {checkpoint_id[:8]}.[/green]")
        _print_summary(session)
    finally:
        storage.close()


@app.command()
def checkpoints(session_id: str) -> None:
    """List checkpoints for a session."""
    storage = _storage()
    try:
        table = Table(title="Checkpoints")
        for col in ("seq", "checkpoint_id", "label", "diff"):
            table.add_column(col)
        for c in storage.list_checkpoints(session_id):
            table.add_row(str(c["seq"]), c["checkpoint_id"][:8], c["label"],
                          (c["diff_summary"] or "")[:50])
        console.print(table)
    finally:
        storage.close()


@app.command()
def export(session_id: str, out: Path = typer.Option(..., "--out")) -> None:
    """Export a full session to a JSON case file."""
    storage = _storage()
    try:
        session = storage.load_session(session_id)
        out.write_text(session.to_json())
        console.print(f"[green]Exported session to {out}[/green]")
    finally:
        storage.close()


@app.command("import")
def import_case(case_file: Path) -> None:
    """Import a session from a JSON case file."""
    storage = _storage()
    try:
        session = SessionState.from_json(case_file.read_text())
        storage.save_session(session)
        console.print(f"[green]Imported session {session.session_id}[/green]")
    finally:
        storage.close()


@app.command()
def models() -> None:
    """List configured models and their capabilities."""
    table = Table(title="Models (configs/models.yaml)")
    for col in ("id", "provider", "cost", "privacy", "strengths"):
        table.add_column(col)
    for m in load_models().get("models", []):
        table.add_row(m["id"], m["provider"], m.get("cost_tier", ""),
                      m.get("privacy_tier", ""), ", ".join(m.get("strengths", []))[:50])
    console.print(table)


@app.command()
def iocs(session_id: str) -> None:
    """List IOCs extracted in a session."""
    storage = _storage()
    try:
        session = _resolve(storage, session_id)
        table = Table(title="IOCs")
        for col in ("type", "value", "source"):
            table.add_column(col)
        for i in session.indicators_of_compromise:
            table.add_row(i.type, i.value, i.source)
        console.print(table)
    finally:
        storage.close()


@app.command()
def timeline(session_id: str) -> None:
    """Show the investigation timeline."""
    storage = _storage()
    try:
        session = _resolve(storage, session_id)
        table = Table(title="Timeline")
        for col in ("timestamp", "source", "event_type", "actor", "outcome"):
            table.add_column(col)
        for e in session.timeline_events:
            table.add_row(e.timestamp.isoformat()[:19], e.source, e.event_type,
                          e.actor or "-", e.outcome or "-")
        console.print(table)
    finally:
        storage.close()


@app.command()
def report(
    session_id: str,
    type: str = typer.Option("analyst", "--type", help="analyst|incident|customer|executive"),
) -> None:
    """Render a report for a session."""
    storage = _storage()
    try:
        session = _resolve(storage, session_id)
        console.print(render_report(session, type))
    finally:
        storage.close()


@app.command("generate-query")
def generate_query_cmd(
    platform: str = typer.Option(..., "--platform"),
    use_case: str = typer.Option(..., "--use-case"),
) -> None:
    """Generate a SIEM query for a platform + use case."""
    try:
        gq = generate_query(platform, use_case)
    except (KeyError, ValueError) as exc:
        console.print(f"[red]{exc}[/red]")
        console.print(f"Use cases: {', '.join(available_use_cases())}")
        raise typer.Exit(1) from exc
    console.print(Panel(gq.query, title=f"{platform} / {use_case}", border_style="cyan"))
    if gq.notes:
        console.print(f"[dim]False-positive notes: {gq.notes}[/dim]")


@app.command("generate-sigma")
def generate_sigma_cmd(use_case: str = typer.Option(..., "--use-case")) -> None:
    """Generate a Sigma rule for a use case."""
    try:
        rule = generate_sigma(use_case)
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        console.print(f"Use cases: {', '.join(available_use_cases())}")
        raise typer.Exit(1) from exc
    console.print(Panel(rule.logic, title=f"Sigma / {use_case}", border_style="cyan"))


@app.command()
def feedback(
    session_id: str,
    classification_correct: bool = typer.Option(True, "--classification-correct/--classification-wrong"),
    severity_correct: bool = typer.Option(True, "--severity-correct/--severity-wrong"),
    action_useful: bool = typer.Option(True, "--action-useful/--action-not-useful"),
    note: str = typer.Option("", "--note"),
) -> None:
    """Record analyst feedback (feeds router historical success)."""
    storage = _storage()
    try:
        session = storage.load_session(session_id)
        model_id = session.decisions[0].selected_model if session.decisions else "mock/mock-model"
        for d in session.decisions:
            payload = {
                "classification_correct": classification_correct,
                "severity_correct": severity_correct,
                "action_useful": action_useful,
                "note": note,
            }
            task_type = next((s.task_type for s in session.task_graph.steps
                              if s.step_id == d.step_id), "triage")
            storage.save_feedback(session.session_id, d.selected_model, task_type, payload)
        storage.append_audit(session.session_id, "human", "feedback_recorded", note)
        console.print(f"[green]Recorded feedback for {len(session.decisions)} decision(s).[/green]")
        _ = model_id
    finally:
        storage.close()


@app.command()
def config() -> None:
    """Show effective configuration and safety posture."""
    console.print(Panel(
        f"DB: {_db_path()}\n"
        f"ROUTER_MODE={os.getenv('ROUTER_MODE', 'rules')}\n"
        f"ORCH_ENABLE_PARALLEL={env_bool('ORCH_ENABLE_PARALLEL')}\n"
        f"ALLOW_EXTERNAL_FOR_SENSITIVE={env_bool('ALLOW_EXTERNAL_FOR_SENSITIVE')}\n"
        f"Providers available: {_available_providers()}\n"
        f"Read-only by default; risky actions require human approval.",
        title="AEGIS config", border_style="green",
    ))


def _available_providers() -> str:
    from orchestrator.providers import get_provider
    out = []
    for mid in model_ids():
        try:
            if get_provider(mid).is_available():
                out.append(mid)
        except Exception:  # noqa: BLE001
            pass
    return ", ".join(out) or "mock/mock-model"


def _resolve(storage: SQLiteStorage, session_id: str) -> SessionState:
    """Resolve a full or short (prefix) session id."""
    try:
        return storage.load_session(session_id)
    except KeyError:
        for r in storage.list_sessions():
            if r["session_id"].startswith(session_id):
                return storage.load_session(r["session_id"])
        raise


def main() -> None:
    app()


if __name__ == "__main__":
    app()
