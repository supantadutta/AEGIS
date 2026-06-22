"""Runtime settings store — makes AEGIS configurable from the dashboard.

Everything that used to require hand-editing `.env` (provider API keys,
integration keys, feature flags, DB path) is now stored in a single JSON file
and overlaid onto ``os.environ`` so the rest of the codebase keeps reading
plain environment variables. The dashboard writes here; the change takes effect
immediately (live) and persists across restarts.

Precedence: a variable already present in the real environment WINS over the
settings file (so container/CI-injected secrets are never clobbered). Values set
through the dashboard are written to the file *and* pushed into ``os.environ``
right away so the running process sees them without a restart.

The settings file may contain secrets, so it is created ``0600`` and is
git-ignored. Secret values are masked whenever they are surfaced in the UI.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

# --- where the file lives ---------------------------------------------------


def settings_path() -> Path:
    return Path(os.getenv("AEGIS_SETTINGS_PATH", "aegis_settings.json"))


# --- secret handling --------------------------------------------------------

_SECRET_MARKERS = ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "_KEY")


def is_secret_key(key: str) -> bool:
    k = key.upper()
    return any(marker in k for marker in _SECRET_MARKERS)


def mask(value: str | None) -> str:
    """Mask a secret for display: keep the last 4 chars, star the rest."""
    if not value:
        return ""
    if len(value) <= 4:
        return "•" * len(value)
    return "•" * (len(value) - 4) + value[-4:]


# --- load / save ------------------------------------------------------------


def load() -> dict[str, str]:
    path = settings_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return {str(k): "" if v is None else str(v) for k, v in data.items()}


def _atomic_write(path: Path, data: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".aegis_settings_")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - non-POSIX filesystems
            pass
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply_to_environ(*, override: bool = False) -> None:
    """Overlay the persisted settings onto ``os.environ``.

    Call once at process start (dashboard / CLI). Real environment variables win
    by default so externally-injected secrets are preserved.
    """
    for key, value in load().items():
        if value == "":
            continue
        if override or key not in os.environ:
            os.environ[key] = value


def update(changes: dict[str, str]) -> dict[str, str]:
    """Persist a set of changes and apply them to the live process.

    An empty-string value clears the setting (removes the key from the file and
    from ``os.environ``). Returns the full, updated settings dict.
    """
    data = load()
    for key, value in changes.items():
        key = key.strip()
        if not key:
            continue
        value = "" if value is None else str(value)
        if value == "":
            data.pop(key, None)
            os.environ.pop(key, None)
        else:
            data[key] = value
            os.environ[key] = value
    _atomic_write(settings_path(), data)
    return data


def get(key: str, default: str | None = None) -> str | None:
    return os.environ.get(key, load().get(key, default))


def is_set(key: str) -> bool:
    return bool(get(key))
