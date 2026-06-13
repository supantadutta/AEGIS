"""Threat-intel enrichment. Local-first and always-on (allow/blocklist CSVs);
external sources are adapters that no-op with a clear "disabled" result unless
their API key is configured (Section 9).
"""

from __future__ import annotations

import csv
import functools
import ipaddress
import os
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


def _external_results(observable: str, obs_type: str) -> list[ThreatIntelResult]:
    """Run each configured external source. Disabled (no key) sources still
    return a result with verdict=unknown and a clear summary — never omitted."""
    results: list[ThreatIntelResult] = []
    for src in load_integrations().get("external_sources", []):
        name = src.get("name", "unknown")
        supports = src.get("supports", [])
        if obs_type and supports and obs_type not in supports:
            continue
        key_env = src.get("api_key_env")
        has_key = bool(key_env and os.getenv(key_env))
        if not has_key:
            results.append(ThreatIntelResult(
                source=name, observable=observable, verdict="unknown", confidence=0.0,
                summary="disabled: no API key configured",
            ))
            continue
        # A key is present but live API wiring is intentionally deferred and
        # gated behind explicit approval (external_enrichment_api). Report it
        # as enabled-but-not-queried rather than silently calling out.
        results.append(ThreatIntelResult(
            source=name, observable=observable, verdict="unknown", confidence=0.0,
            tags=["enabled"],
            summary="enabled: external query requires approval (external_enrichment_api)",
        ))
    return results


def enrich(observable: str, obs_type: str = "", *, include_external: bool = True) -> list[ThreatIntelResult]:
    """Enrich a single observable. Local result always first."""
    results = [local_threat_intel_lookup(observable, obs_type)]
    if include_external:
        results.extend(_external_results(observable, obs_type))
    return results


def clear_cache() -> None:  # pragma: no cover - test helper
    _allowlist.cache_clear()
    _blocklist.cache_clear()
