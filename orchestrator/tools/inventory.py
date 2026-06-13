"""Local asset/user inventory lookups from configs/data CSVs."""

from __future__ import annotations

import csv
import functools
from pathlib import Path

from orchestrator.core.config import configs_dir, load_integrations


def _read_csv(rel_path: str) -> list[dict[str, str]]:
    path = Path(rel_path)
    if not path.is_absolute():
        # Resolve relative to the repo root (parent of configs/).
        path = configs_dir().parent / rel_path
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


@functools.cache
def _assets() -> list[dict[str, str]]:
    cfg = load_integrations().get("local_sources", {})
    return _read_csv(cfg.get("asset_inventory_csv", "configs/data/asset_inventory.csv"))


@functools.cache
def _users() -> list[dict[str, str]]:
    cfg = load_integrations().get("local_sources", {})
    return _read_csv(cfg.get("user_inventory_csv", "configs/data/user_inventory.csv"))


def asset_inventory_lookup(identifier: str | None) -> dict[str, str] | None:
    if not identifier:
        return None
    ident = identifier.strip().lower()
    for row in _assets():
        if row.get("hostname", "").lower() == ident or row.get("ip", "").lower() == ident:
            return row
    return None


def user_inventory_lookup(username: str | None) -> dict[str, str] | None:
    if not username:
        return None
    uname = username.strip().lower()
    for row in _users():
        if row.get("username", "").lower() == uname:
            return row
    return None


def clear_cache() -> None:  # pragma: no cover - test helper
    _assets.cache_clear()
    _users.cache_clear()
