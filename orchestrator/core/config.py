"""Configuration loading. All model/agent/router/security/template config is
read from YAML in the configs/ directory — never hardcoded in business logic.
"""

from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any

import yaml


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


@functools.lru_cache(maxsize=None)
def load_models() -> dict[str, Any]:
    return _load("models.yaml")


@functools.lru_cache(maxsize=None)
def load_router() -> dict[str, Any]:
    return _load("router.yaml")


@functools.lru_cache(maxsize=None)
def load_agents() -> dict[str, Any]:
    return _load("agents.yaml")


@functools.lru_cache(maxsize=None)
def load_security() -> dict[str, Any]:
    return _load("security.yaml")


@functools.lru_cache(maxsize=None)
def load_integrations() -> dict[str, Any]:
    return _load("integrations.yaml")


@functools.lru_cache(maxsize=None)
def load_detection_templates() -> dict[str, Any]:
    return _load("detection_templates.yaml")


@functools.lru_cache(maxsize=None)
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


def clear_cache() -> None:  # pragma: no cover - test helper
    for fn in (load_models, load_router, load_agents, load_security,
               load_integrations, load_detection_templates, load_report_templates):
        fn.cache_clear()
