#!/bin/bash
# AEGIS — SessionStart hook for Claude Code on the web.
# Installs the package + dev tooling so pytest / ruff / mypy work in-session.
set -euo pipefail

# Only run in the remote (web) environment; local sessions manage their own env.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-.}"

# Editable install with dev extras (pytest, pytest-cov, ruff, mypy, types-PyYAML).
# Editable + cached container state makes re-runs fast and idempotent.
python -m pip install -e ".[dev]"

echo "AEGIS dev environment ready: pytest / ruff / mypy installed."
