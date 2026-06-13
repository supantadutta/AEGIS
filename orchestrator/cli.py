"""AEGIS CLI entry point. Full command set is implemented in Phase 6."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="blue-orchestrator",
    help="AEGIS — Multi-AI Blue Team Orchestrator (defensive, local-first).",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print the AEGIS version."""
    typer.echo("AEGIS 0.1.0")


if __name__ == "__main__":
    app()
