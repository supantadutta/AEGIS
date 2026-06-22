"""Runtime settings store: persistence, env overlay, masking, clearing."""

from __future__ import annotations

import pytest

from orchestrator.core import settings


@pytest.fixture()
def settings_file(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setenv("AEGIS_SETTINGS_PATH", str(path))
    # Ensure a clean process env for the keys under test.
    for key in ("OPENAI_API_KEY", "ROUTER_MODE", "FOO"):
        monkeypatch.delenv(key, raising=False)
    return path


def test_update_persists_and_applies_live(settings_file):
    settings.update({"OPENAI_API_KEY": "sk-abc123", "ROUTER_MODE": "llm"})
    import os
    assert os.getenv("OPENAI_API_KEY") == "sk-abc123"  # live in-process
    assert settings.load()["ROUTER_MODE"] == "llm"      # persisted to disk
    assert settings_file.exists()


def test_empty_value_clears(settings_file):
    settings.update({"FOO": "bar"})
    assert settings.get("FOO") == "bar"
    settings.update({"FOO": ""})
    import os
    assert os.getenv("FOO") is None
    assert "FOO" not in settings.load()


def test_apply_to_environ_does_not_override_real_env(settings_file, monkeypatch):
    settings.update({"OPENAI_API_KEY": "from-file"})
    monkeypatch.setenv("OPENAI_API_KEY", "from-real-env")
    settings.apply_to_environ()  # real env must win
    import os
    assert os.getenv("OPENAI_API_KEY") == "from-real-env"


def test_apply_to_environ_override(settings_file, monkeypatch):
    settings.update({"ROUTER_MODE": "llm"})
    monkeypatch.setenv("ROUTER_MODE", "rules")
    settings.apply_to_environ(override=True)
    import os
    assert os.getenv("ROUTER_MODE") == "llm"


def test_secret_detection_and_mask():
    assert settings.is_secret_key("ANTHROPIC_API_KEY")
    assert settings.is_secret_key("SOME_TOKEN")
    assert not settings.is_secret_key("OLLAMA_BASE_URL")
    assert settings.mask("sk-1234567890") == "•" * 9 + "7890"
    assert settings.mask("") == ""
    assert settings.mask("ab") == "••"


def test_file_is_chmod_600(settings_file):
    import os
    import stat
    settings.update({"OPENAI_API_KEY": "secret"})
    mode = stat.S_IMODE(os.stat(settings_file).st_mode)
    assert mode == 0o600
