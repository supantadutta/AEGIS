"""Programmatic entry point. See orchestrator.cli for the command-line app."""

from __future__ import annotations

from orchestrator.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
