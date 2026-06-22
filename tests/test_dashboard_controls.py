"""Dashboard control-panel: run investigations, edit settings/config, manage
integrations and lists — all from the browser, against isolated temp configs."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

REPO_CONFIGS = Path(__file__).resolve().parents[1] / "configs"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    # Isolate configs (so saves don't touch the repo), DB, and settings file.
    cfg_dir = tmp_path / "configs"
    shutil.copytree(REPO_CONFIGS, cfg_dir)
    monkeypatch.setenv("AEGIS_CONFIG_DIR", str(cfg_dir))
    monkeypatch.setenv("AEGIS_DB_PATH", str(tmp_path / "dash.sqlite"))
    monkeypatch.setenv("AEGIS_SETTINGS_PATH", str(tmp_path / "settings.json"))
    for env in ("OPENAI_API_KEY", "ABUSEIPDB_API_KEY", "ORCH_ENABLE_PARALLEL"):
        monkeypatch.delenv(env, raising=False)
    from orchestrator.core.config import clear_cache
    clear_cache()
    from orchestrator.dashboard.app import app
    yield TestClient(app)
    clear_cache()


def test_pages_render(client):
    for path in ["/", "/sessions", "/investigate", "/detections",
                 "/intel", "/integrations", "/settings", "/healthz"]:
        assert client.get(path).status_code == 200, path


def test_investigate_runs_from_dashboard(client):
    r = client.post("/investigate", data={
        "alert_text": "user=admin failed login src_ip=45.143.220.0 then success",
        "fmt": "text", "sensitivity": "internal", "auto_approve": "on"},
        follow_redirects=False)
    assert r.status_code == 303
    sid = r.headers["location"].split("/session/")[-1].split("?")[0]
    detail = client.get(f"/session/{sid}")
    assert detail.status_code == 200
    assert "45.143.220.0" in detail.text


def test_investigate_empty_is_rejected(client):
    r = client.post("/investigate", data={"alert_text": "  "}, follow_redirects=False)
    assert r.status_code == 303
    assert "err=" in r.headers["location"]


def test_provider_settings_saved_and_masked(client):
    client.post("/settings/providers", data={"OPENAI_API_KEY": "sk-secret-7890"},
                follow_redirects=False)
    import os
    assert os.getenv("OPENAI_API_KEY") == "sk-secret-7890"
    page = client.get("/settings").text
    assert "sk-secret" not in page          # raw secret never shown
    assert "7890" in page                    # masked tail shown


def test_flags_saved(client):
    client.post("/settings/flags", data={"ROUTER_MODE": "rules",
                "ORCH_ENABLE_PARALLEL": "on", "AEGIS_DB_PATH": "x.sqlite"},
                follow_redirects=False)
    import os
    assert os.getenv("ORCH_ENABLE_PARALLEL") == "true"


def test_integration_save_and_test(client):
    # Save a key + enable AbuseIPDB; it should become configured.
    client.post("/integrations/save", data={"name": "AbuseIPDB",
                "api_key": "abc123", "enabled": "on"}, follow_redirects=False)
    import os
    assert os.getenv("ABUSEIPDB_API_KEY") == "abc123"
    from orchestrator.tools import intel_sources
    cfgs = {c["name"]: c for c in intel_sources.source_configs()}
    assert cfgs["AbuseIPDB"]["configured"] is True
    # Test button renders a result row (network call may fail in CI — that's fine).
    r = client.post("/integrations/test", data={"name": "AbuseIPDB"})
    assert r.status_code == 200
    assert "AbuseIPDB" in r.text


def test_intel_lookup_local_blocklist(client):
    r = client.post("/intel/lookup", data={"observable": "45.143.220.0", "obs_type": "ip"})
    assert r.status_code == 200
    assert "malicious" in r.text


def test_allowlist_add_and_remove(client):
    client.post("/intel/list/add", data={"which": "allow", "indicator": "9.9.9.9",
                "obs_type": "ip", "note": "quad9"}, follow_redirects=False)
    from orchestrator.tools import threat_intel
    assert any(e["indicator"] == "9.9.9.9" for e in threat_intel.list_entries("allow"))
    client.post("/intel/list/remove", data={"which": "allow", "indicator": "9.9.9.9"},
                follow_redirects=False)
    assert not any(e["indicator"] == "9.9.9.9" for e in threat_intel.list_entries("allow"))


def test_config_editor_round_trip(client):
    page = client.get("/settings/config/security")
    assert page.status_code == 200
    assert "denylist" in page.text
    # Save valid YAML.
    r = client.post("/settings/config/security",
                    data={"content": "shell:\n  allowlist: []\n  denylist: []\n"},
                    follow_redirects=False)
    assert r.status_code == 303 and "msg=" in r.headers["location"]
    # Invalid YAML is rejected with an error flash, not a crash.
    r = client.post("/settings/config/security", data={"content": "::: not yaml :::"},
                    follow_redirects=False)
    assert "err=" in r.headers["location"]


def test_detection_generation(client):
    r = client.post("/detections", data={"kind": "query", "platform": "splunk",
                                         "use_case": "brute-force"})
    assert r.status_code == 200
    assert "splunk" in r.text.lower()
