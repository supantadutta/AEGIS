"""Threat-intel enrichment. Local-first and always-on (allow/blocklist CSVs);
external sources are adapters that no-op with a clear "disabled" result unless
their API key is configured (Section 9).
"""

from __future__ import annotations

import csv
import functools
import ipaddress
from pathlib import Path

from orchestrator.core.config import configs_dir, load_integrations
from orchestrator.core.state import ThreatIntelResult


def _read_csv(rel_path: str) -> list[dict[str, str]]:
    path = Path(rel_path)
    if not path.is_absolute():
        path = configs_dir().parent / rel_path
    if not path.exists():
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


@functools.cache
def _allowlist() -> list[dict[str, str]]:
    cfg = load_integrations().get("local_sources", {})
    return _read_csv(cfg.get("allowlist_csv", "configs/data/allowlist.csv"))


@functools.cache
def _blocklist() -> list[dict[str, str]]:
    cfg = load_integrations().get("local_sources", {})
    return _read_csv(cfg.get("blocklist_csv", "configs/data/blocklist.csv"))


def _match(observable: str, rows: list[dict[str, str]]) -> dict[str, str] | None:
    obs = observable.strip().lower()
    for row in rows:
        ind = row.get("indicator", "").strip().lower()
        if not ind:
            continue
        if ind == obs:
            return row
        # CIDR allow/block entries.
        if "/" in ind:
            try:
                if ipaddress.ip_address(obs) in ipaddress.ip_network(ind, strict=False):
                    return row
            except ValueError:
                pass
    return None


def allowlist_lookup(observable: str) -> dict[str, str] | None:
    return _match(observable, _allowlist())


def local_threat_intel_lookup(observable: str, obs_type: str = "") -> ThreatIntelResult:
    """Always-on local check: blocklist (malicious) > allowlist (benign) > unknown."""
    block = _match(observable, _blocklist())
    if block:
        return ThreatIntelResult(
            source="local_blocklist", observable=observable, verdict="malicious",
            confidence=0.95, tags=["blocklist"],
            summary=f"Matched local blocklist: {block.get('note', '')}".strip(),
        )
    allow = _match(observable, _allowlist())
    if allow:
        return ThreatIntelResult(
            source="local_allowlist", observable=observable, verdict="benign",
            confidence=0.9, tags=["allowlist"],
            summary=f"Matched local allowlist: {allow.get('note', '')}".strip(),
        )
    return ThreatIntelResult(
        source="local", observable=observable, verdict="unknown", confidence=0.0,
        summary="No local allow/blocklist match.",
    )


def _external_results(observable: str, obs_type: str, *, live: bool) -> list[ThreatIntelResult]:
    """Run each configured external source.

    When ``live`` is on, *configured* sources (enabled + client + credentials)
    are queried for real; everything else still emits a clear status result so a
    source is never silently omitted. When ``live`` is off, behaviour is the
    classic safe default: disabled (no key) or enabled-but-gated summaries.
    """
    # Lazy import avoids any import cycle and keeps httpx clients out of the
    # hot path when live querying is off.
    from orchestrator.tools.intel_sources import live_lookup, source_configs

    results: list[ThreatIntelResult] = []
    for cfg in source_configs():
        supports = cfg["supports"]
        if obs_type and supports and obs_type not in supports:
            continue
        name = cfg["name"]
        if live and cfg["configured"]:
            results.append(live_lookup(name, observable, obs_type))
        elif cfg["has_key"] or cfg["has_base_url"]:
            results.append(ThreatIntelResult(
                source=name, observable=observable, verdict="unknown", confidence=0.0,
                tags=["enabled"],
                summary="enabled: turn on AEGIS_AUTO_LIVE_INTEL or approve "
                        "external_enrichment_api to query live",
            ))
        else:
            results.append(ThreatIntelResult(
                source=name, observable=observable, verdict="unknown", confidence=0.0,
                summary="disabled: no API key configured",
            ))
    return results


def enrich(observable: str, obs_type: str = "", *, include_external: bool = True,
           live: bool | None = None) -> list[ThreatIntelResult]:
    """Enrich a single observable. Local result always first.

    ``live`` defaults to the ``AEGIS_AUTO_LIVE_INTEL`` runtime flag; pass it
    explicitly (e.g. from the dashboard) to force a real lookup.
    """
    if live is None:
        from orchestrator.tools.intel_sources import auto_live_enabled
        live = auto_live_enabled()
    results = [local_threat_intel_lookup(observable, obs_type)]
    if include_external:
        results.extend(_external_results(observable, obs_type, live=live))
    return results


def clear_cache() -> None:  # pragma: no cover - test helper
    _allowlist.cache_clear()
    _blocklist.cache_clear()


# --- allow/block list management (dashboard-editable) -----------------------

_LIST_FILES = {"allow": "allowlist_csv", "block": "blocklist_csv"}
_LIST_DEFAULTS = {"allow": "configs/data/allowlist.csv", "block": "configs/data/blocklist.csv"}
_LIST_FIELDS = ["indicator", "type", "note"]


def _list_path(which: str) -> Path:
    cfg = load_integrations().get("local_sources", {})
    rel = cfg.get(_LIST_FILES[which], _LIST_DEFAULTS[which])
    path = Path(rel)
    if not path.is_absolute():
        path = configs_dir().parent / rel
    return path


def list_entries(which: str) -> list[dict[str, str]]:
    """Return the rows of the allow ('allow') or block ('block') list."""
    return _read_csv(str(_list_path(which)))


def _write_list(which: str, rows: list[dict[str, str]]) -> None:
    path = _list_path(which)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_LIST_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in _LIST_FIELDS})
    clear_cache()


def add_entry(which: str, indicator: str, obs_type: str = "", note: str = "") -> bool:
    """Add an indicator to the allow/block list. Returns False if a duplicate."""
    indicator = indicator.strip()
    if not indicator:
        return False
    rows = list_entries(which)
    if any(r.get("indicator", "").strip().lower() == indicator.lower() for r in rows):
        return False
    rows.append({"indicator": indicator, "type": obs_type.strip(), "note": note.strip()})
    _write_list(which, rows)
    return True


def remove_entry(which: str, indicator: str) -> bool:
    """Remove an indicator from the allow/block list. Returns True if removed."""
    indicator = indicator.strip().lower()
    rows = list_entries(which)
    kept = [r for r in rows if r.get("indicator", "").strip().lower() != indicator]
    if len(kept) == len(rows):
        return False
    _write_list(which, kept)
    return True
