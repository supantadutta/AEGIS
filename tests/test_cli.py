"""Phase 6: CLI commands run end-to-end against MockProvider."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from orchestrator.cli import app

runner = CliRunner()


def _env(tmp_path):
    return {"AEGIS_DB_PATH": str(tmp_path / "cli.sqlite")}


def test_init(tmp_path):
    res = runner.invoke(app, ["init"], env=_env(tmp_path))
    assert res.exit_code == 0
    assert "Initialized" in res.stdout


def test_investigate_completes(tmp_path):
    res = runner.invoke(
        app, ["investigate", "examples/alerts/brute_force_alert.json"], env=_env(tmp_path)
    )
    assert res.exit_code == 0
    assert "status=completed" in res.stdout
    assert "T1110" in res.stdout


def test_investigate_text(tmp_path):
    res = runner.invoke(
        app, ["investigate-text", "user=admin failed login src_ip=45.143.220.0 repeatedly"],
        env=_env(tmp_path),
    )
    assert res.exit_code == 0
    assert "status=completed" in res.stdout


def test_sessions_and_inspect(tmp_path):
    env = _env(tmp_path)
    runner.invoke(app, ["investigate", "examples/alerts/brute_force_alert.json"], env=env)
    res = runner.invoke(app, ["sessions"], env=env)
    assert res.exit_code == 0
    res2 = runner.invoke(app, ["inspect", "--help"], env=env)
    assert res2.exit_code == 0


def test_generate_sigma(tmp_path):
    res = runner.invoke(app, ["generate-sigma", "--use-case", "suspicious-powershell"],
                        env=_env(tmp_path))
    assert res.exit_code == 0
    assert "powershell" in res.stdout.lower()


def test_generate_query(tmp_path):
    res = runner.invoke(app, ["generate-query", "--platform", "splunk",
                              "--use-case", "brute-force"], env=_env(tmp_path))
    assert res.exit_code == 0
    assert "stats count" in res.stdout


def test_models(tmp_path):
    res = runner.invoke(app, ["models"], env=_env(tmp_path))
    assert res.exit_code == 0
    assert "mock/mock-model" in res.stdout


def test_export_import(tmp_path):
    env = _env(tmp_path)
    runner.invoke(app, ["investigate", "examples/alerts/brute_force_alert.json"], env=env)
    # find the session id
    import sqlite3
    conn = sqlite3.connect(env["AEGIS_DB_PATH"])
    sid = conn.execute("SELECT session_id FROM sessions LIMIT 1").fetchone()[0]
    conn.close()
    out = tmp_path / "case.json"
    res = runner.invoke(app, ["export", sid, "--out", str(out)], env=env)
    assert res.exit_code == 0
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["session_id"] == sid
    res2 = runner.invoke(app, ["import", str(out)], env=env)
    assert res2.exit_code == 0
