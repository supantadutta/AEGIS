"""Configuration loading. All model/agent/router/security/template config is
read from YAML in the configs/ directory — never hardcoded in business logic.
"""

from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any

import yaml

# Logical name -> filename for every editable config document. The dashboard
# config editor and `save_config()` both use this allow-list so callers can
# never write to an arbitrary path.
CONFIG_FILES: dict[str, str] = {
    "models": "models.yaml",
    "router": "router.yaml",
    "agents": "agents.yaml",
    "security": "security.yaml",
    "integrations": "integrations.yaml",
    "detection_templates": "detection_templates.yaml",
    "report_templates": "report_templates.yaml",
}


def configs_dir() -> Path:
    """Locate the configs directory. Honors AEGIS_CONFIG_DIR, else walks up
    from this file to the repo root."""
    env = os.getenv("AEGIS_CONFIG_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / "configs"
        if candidate.is_dir():
            return candidate
    return Path("configs")


def _load(name: str) -> dict[str, Any]:
    path = configs_dir() / name
    with open(path) as f:
        return yaml.safe_load(f) or {}


@functools.cache
def load_models() -> dict[str, Any]:
    return _load("models.yaml")


@functools.cache
def load_router() -> dict[str, Any]:
    return _load("router.yaml")


@functools.cache
def load_agents() -> dict[str, Any]:
    return _load("agents.yaml")


@functools.cache
def load_security() -> dict[str, Any]:
    return _load("security.yaml")


@functools.cache
def load_integrations() -> dict[str, Any]:
    return _load("integrations.yaml")


@functools.cache
def load_detection_templates() -> dict[str, Any]:
    return _load("detection_templates.yaml")


@functools.cache
def load_report_templates() -> dict[str, Any]:
    return _load("report_templates.yaml")


def model_ids() -> list[str]:
    return [m["id"] for m in load_models().get("models", [])]


def model_by_id(model_id: str) -> dict[str, Any] | None:
    return next((m for m in load_models().get("models", []) if m["id"] == model_id), None)


def env_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


_LOADERS = {
    "models": load_models,
    "router": load_router,
    "agents": load_agents,
    "security": load_security,
    "integrations": load_integrations,
    "detection_templates": load_detection_templates,
    "report_templates": load_report_templates,
}


def load_config(name: str) -> dict[str, Any]:
    """Load a named config document (see ``CONFIG_FILES``)."""
    loader = _LOADERS.get(name)
    if loader is None:
        raise KeyError(f"unknown config: {name!r}")
    return loader()


def save_config(name: str, data: dict[str, Any]) -> Path:
    """Write a named config document back to its YAML file and refresh caches.

    Only names in ``CONFIG_FILES`` are accepted. Returns the written path.
    """
    fname = CONFIG_FILES.get(name)
    if fname is None:
        raise KeyError(f"unknown config: {name!r}")
    path = configs_dir() / fname
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False, allow_unicode=True, default_flow_style=False)
    clear_cache()
    return path


def runtime_flags() -> dict[str, Any]:
    """The effective runtime feature flags (env-driven, dashboard-editable)."""
    return {
        "ROUTER_MODE": os.getenv("ROUTER_MODE", "rules"),
        "ORCH_ENABLE_PARALLEL": env_bool("ORCH_ENABLE_PARALLEL"),
        "ALLOW_EXTERNAL_FOR_SENSITIVE": env_bool("ALLOW_EXTERNAL_FOR_SENSITIVE"),
        "AEGIS_DB_PATH": os.getenv("AEGIS_DB_PATH", "aegis.sqlite"),
    }


def clear_cache() -> None:
    for fn in (load_models, load_router, load_agents, load_security,
               load_integrations, load_detection_templates, load_report_templates):
        fn.cache_clear()
