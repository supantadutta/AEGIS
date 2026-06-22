"""Live external threat-intel source clients.

Each client turns one observable into a canonical :class:`ThreatIntelResult` by
calling a real provider API. Clients are intentionally small, defensive and
fail-safe: any network/parse error degrades to ``verdict="unknown"`` with the
error in the summary — a source is never allowed to crash an investigation.

Safety: live external calls are an explicit, opt-in action. The automated
pipeline only performs them when the operator turns on ``AEGIS_AUTO_LIVE_INTEL``
(or approves the ``external_enrichment_api`` gate); the dashboard "Lookup" /
"Test" buttons are themselves explicit human actions. Keys and base URLs are
resolved from the runtime settings store, so everything is configurable from the
dashboard with no file editing.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import httpx

from orchestrator.core.config import env_bool, load_integrations
from orchestrator.core.state import ThreatIntelResult

DEFAULT_TIMEOUT = 12.0

# A safe, well-known observable used only for "test connection" probes.
_TEST_OBSERVABLE = {"ip": "8.8.8.8", "domain": "example.com", "url": "http://example.com",
                    "hash": "44d88612fea8a8f36de82e1278abb02f"}

SourceClient = Callable[..., ThreatIntelResult]
_CLIENTS: dict[str, SourceClient] = {}


def register(name: str) -> Callable[[SourceClient], SourceClient]:
    def deco(fn: SourceClient) -> SourceClient:
        _CLIENTS[name] = fn
        return fn
    return deco


# --- source metadata (merges integrations.yaml + runtime settings) ----------


def source_configs() -> list[dict[str, Any]]:
    """One descriptor per external source, enriched with live status.

    Fields: name, supports, enabled (from yaml), api_key_env, base_url_env,
    requires_key, has_key, has_base_url, has_client, configured (ready to call).
    """
    out: list[dict[str, Any]] = []
    for src in load_integrations().get("external_sources", []):
        name = src.get("name", "unknown")
        key_env = src.get("api_key_env")
        url_env = src.get("base_url_env")
        requires_key = bool(key_env)
        has_key = bool(key_env and os.getenv(key_env))
        has_url = bool(url_env and os.getenv(url_env))
        has_client = name in _CLIENTS
        # "configured" = enabled, has a live client, and credentials present.
        needs_url = bool(url_env)
        configured = (
            bool(src.get("enabled"))
            and has_client
            and (has_key or not requires_key)
            and (has_url or not needs_url)
        )
        out.append({
            "name": name,
            "supports": src.get("supports", []),
            "enabled": bool(src.get("enabled")),
            "api_key_env": key_env,
            "base_url_env": url_env,
            "requires_key": requires_key,
            "needs_base_url": needs_url,
            "has_key": has_key,
            "has_base_url": has_url,
            "has_client": has_client,
            "configured": configured,
        })
    return out


def _config_for(name: str) -> dict[str, Any] | None:
    return next((c for c in source_configs() if c["name"] == name), None)


def auto_live_enabled() -> bool:
    """Whether the automated pipeline may make live external calls."""
    return env_bool("AEGIS_AUTO_LIVE_INTEL")


# --- helpers ----------------------------------------------------------------


def _result(name: str, observable: str, *, verdict: str = "unknown", confidence: float = 0.0,
            summary: str = "", tags: list[str] | None = None,
            ref: str | None = None) -> ThreatIntelResult:
    return ThreatIntelResult(
        source=name, observable=observable, verdict=verdict,  # type: ignore[arg-type]
        confidence=confidence, summary=summary, tags=tags or [], raw_reference=ref,
    )


def _get(url: str, *, headers: dict[str, str] | None = None,
         params: dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT) -> httpx.Response:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        return client.get(url, headers=headers, params=params)


def _post(url: str, *, headers: dict[str, str] | None = None, json: dict[str, Any] | None = None,
          data: dict[str, Any] | None = None, timeout: float = DEFAULT_TIMEOUT) -> httpx.Response:
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        return client.post(url, headers=headers, json=json, data=data)


# --- keyless clients --------------------------------------------------------


@register("ASN_GEO")
def _asn_geo(observable: str, obs_type: str, **kw: Any) -> ThreatIntelResult:
    r = _get(f"http://ip-api.com/json/{observable}",
             params={"fields": "status,country,isp,org,as,query"}, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    data = r.json()
    if data.get("status") != "success":
        return _result("ASN_GEO", observable, summary=f"no data: {data.get('message', 'unknown')}")
    tags = [t for t in (data.get("country"), data.get("as"), data.get("isp")) if t]
    return _result("ASN_GEO", observable, verdict="unknown", confidence=0.0,
                   summary=f"{data.get('as', '')} · {data.get('isp', '')} · {data.get('country', '')}".strip(" ·"),
                   tags=tags, ref=f"http://ip-api.com/json/{observable}")


@register("WHOIS_RDAP")
def _rdap(observable: str, obs_type: str, **kw: Any) -> ThreatIntelResult:
    kind = "ip" if obs_type == "ip" else "domain"
    r = _get(f"https://rdap.org/{kind}/{observable}", timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code >= 400:
        return _result("WHOIS_RDAP", observable, summary=f"no RDAP record (HTTP {r.status_code})")
    data = r.json()
    handle = data.get("handle") or data.get("ldhName") or ""
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    reg = events.get("registration", "")
    return _result("WHOIS_RDAP", observable, summary=f"handle={handle} registered={reg}".strip(),
                   tags=[s for s in data.get("status", [])], ref=f"https://rdap.org/{kind}/{observable}")


# --- key-based clients ------------------------------------------------------


@register("AbuseIPDB")
def _abuseipdb(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    r = _get("https://api.abuseipdb.com/api/v2/check",
             headers={"Key": api_key or "", "Accept": "application/json"},
             params={"ipAddress": observable, "maxAgeInDays": 90},
             timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    data = r.json().get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))
    verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "benign"
    return _result("AbuseIPDB", observable, verdict=verdict, confidence=score / 100.0,
                   summary=f"abuse score {score}/100, reports={data.get('totalReports', 0)}, "
                           f"country={data.get('countryCode', '?')}",
                   tags=["tor"] if data.get("isTor") else [],
                   ref=f"https://www.abuseipdb.com/check/{observable}")


@register("VirusTotal")
def _virustotal(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    path = {"ip": "ip_addresses", "domain": "domains", "url": "urls", "hash": "files"}.get(obs_type)
    if path is None:
        return _result("VirusTotal", observable, summary=f"unsupported type: {obs_type}")
    ident = observable
    if obs_type == "url":
        import base64
        ident = base64.urlsafe_b64encode(observable.encode()).decode().strip("=")
    r = _get(f"https://www.virustotal.com/api/v3/{path}/{ident}",
             headers={"x-apikey": api_key or ""}, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code == 404:
        return _result("VirusTotal", observable, verdict="unknown", summary="not found in VirusTotal")
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal = int(stats.get("malicious", 0))
    susp = int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values()) or 1
    verdict = "malicious" if mal >= 3 else "suspicious" if mal + susp > 0 else "benign"
    return _result("VirusTotal", observable, verdict=verdict, confidence=min(1.0, (mal + susp) / total),
                   summary=f"{mal} malicious / {susp} suspicious / {total} engines",
                   ref=f"https://www.virustotal.com/gui/search/{observable}")


@register("GreyNoise")
def _greynoise(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    r = _get(f"https://api.greynoise.io/v3/community/{observable}",
             headers={"key": api_key or "", "Accept": "application/json"},
             timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code == 404:
        return _result("GreyNoise", observable, verdict="unknown", summary="not seen scanning the internet")
    data = r.json()
    classification = data.get("classification", "unknown")
    verdict = {"malicious": "malicious", "benign": "benign"}.get(classification, "suspicious")
    return _result("GreyNoise", observable, verdict=verdict, confidence=0.6,
                   summary=f"{classification}: {data.get('name', 'unknown actor')}",
                   tags=["noise"] if data.get("noise") else [], ref=data.get("link"))


@register("Shodan")
def _shodan(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    r = _get(f"https://api.shodan.io/shodan/host/{observable}",
             params={"key": api_key or ""}, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code >= 400:
        return _result("Shodan", observable, summary=f"no host data (HTTP {r.status_code})")
    data = r.json()
    ports = data.get("ports", [])
    return _result("Shodan", observable, verdict="unknown", confidence=0.0,
                   summary=f"{len(ports)} open ports: {ports[:12]} · {data.get('org', '')}",
                   tags=data.get("tags", []), ref=f"https://www.shodan.io/host/{observable}")


@register("AlienVaultOTX")
def _otx(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    section = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}.get(obs_type)
    if section is None:
        return _result("AlienVaultOTX", observable, summary=f"unsupported type: {obs_type}")
    r = _get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{observable}/general",
             headers={"X-OTX-API-KEY": api_key or ""}, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code >= 400:
        return _result("AlienVaultOTX", observable, summary=f"no data (HTTP {r.status_code})")
    pulses = r.json().get("pulse_info", {}).get("count", 0)
    verdict = "malicious" if pulses >= 3 else "suspicious" if pulses > 0 else "unknown"
    return _result("AlienVaultOTX", observable, verdict=verdict, confidence=min(1.0, pulses / 10.0),
                   summary=f"{pulses} OTX pulse(s) reference this indicator",
                   ref=f"https://otx.alienvault.com/indicator/{section.lower()}/{observable}")


@register("ThreatFox")
def _threatfox(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    headers = {"Auth-Key": api_key} if api_key else None
    r = _post("https://threatfox-api.abuse.ch/api/v1/", headers=headers,
              json={"query": "search_ioc", "search_term": observable},
              timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    data = r.json()
    if data.get("query_status") != "ok" or not data.get("data"):
        return _result("ThreatFox", observable, verdict="unknown", summary="no ThreatFox match")
    first = data["data"][0]
    return _result("ThreatFox", observable, verdict="malicious", confidence=0.85,
                   summary=f"{first.get('malware_printable', 'malware')} · {first.get('threat_type', '')}",
                   tags=first.get("tags") or [], ref=f"https://threatfox.abuse.ch/ioc/{first.get('id', '')}")


@register("MalwareBazaar")
def _malwarebazaar(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    headers = {"Auth-Key": api_key} if api_key else None
    r = _post("https://mb-api.abuse.ch/api/v1/", headers=headers,
              data={"query": "get_info", "hash": observable}, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    data = r.json()
    if data.get("query_status") != "ok" or not data.get("data"):
        return _result("MalwareBazaar", observable, verdict="unknown", summary="hash not in MalwareBazaar")
    first = data["data"][0]
    return _result("MalwareBazaar", observable, verdict="malicious", confidence=0.9,
                   summary=f"{first.get('signature', 'malware')} · {first.get('file_type', '')}",
                   tags=first.get("tags") or [], ref=f"https://bazaar.abuse.ch/sample/{first.get('sha256_hash', '')}")


@register("URLScan")
def _urlscan(observable: str, obs_type: str, *, api_key: str | None = None, **kw: Any) -> ThreatIntelResult:
    field = "page.url" if obs_type == "url" else "page.domain"
    r = _get("https://urlscan.io/api/v1/search/", params={"q": f"{field}:{observable}", "size": 1},
             headers={"API-Key": api_key} if api_key else None, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code >= 400:
        return _result("URLScan", observable, summary=f"search failed (HTTP {r.status_code})")
    results = r.json().get("results", [])
    if not results:
        return _result("URLScan", observable, verdict="unknown", summary="no prior URLScan submissions")
    first = results[0]
    verdict = "malicious" if first.get("verdicts", {}).get("overall", {}).get("malicious") else "unknown"
    return _result("URLScan", observable, verdict=verdict, confidence=0.5,
                   summary=f"{len(results)} prior scan(s); last by {first.get('task', {}).get('source', '?')}",
                   ref=first.get("result"))


@register("MISP")
def _misp(observable: str, obs_type: str, *, api_key: str | None = None,
          base_url: str | None = None, **kw: Any) -> ThreatIntelResult:
    if not base_url:
        return _result("MISP", observable, summary="MISP base URL not configured")
    r = _post(f"{base_url.rstrip('/')}/attributes/restSearch",
              headers={"Authorization": api_key or "", "Accept": "application/json",
                       "Content-Type": "application/json"},
              json={"value": observable, "limit": 5}, timeout=kw.get("timeout", DEFAULT_TIMEOUT))
    if r.status_code >= 400:
        return _result("MISP", observable, summary=f"MISP query failed (HTTP {r.status_code})")
    attrs = r.json().get("response", {}).get("Attribute", [])
    if not attrs:
        return _result("MISP", observable, verdict="unknown", summary="no MISP attributes match")
    return _result("MISP", observable, verdict="malicious", confidence=0.7,
                   summary=f"{len(attrs)} MISP attribute(s); category={attrs[0].get('category', '')}",
                   tags=[t.get("name") for t in attrs[0].get("Tag", []) if t.get("name")])


# --- dispatch ---------------------------------------------------------------


def _resolve_credentials(name: str) -> tuple[str | None, str | None]:
    cfg: dict[str, Any] = next(
        (s for s in load_integrations().get("external_sources", []) if s.get("name") == name), {})
    key_env = cfg.get("api_key_env")
    url_env = cfg.get("base_url_env")
    key = os.getenv(key_env) if key_env else None
    url = os.getenv(url_env) if url_env else None
    return key, url


def live_lookup(name: str, observable: str, obs_type: str = "",
                *, timeout: float = DEFAULT_TIMEOUT) -> ThreatIntelResult:
    """Call one named source for one observable. Always returns a result."""
    client = _CLIENTS.get(name)
    if client is None:
        return _result(name, observable, summary="no live client implemented for this source")
    api_key, base_url = _resolve_credentials(name)
    try:
        return client(observable, obs_type, api_key=api_key, base_url=base_url, timeout=timeout)
    except httpx.HTTPError as exc:
        return _result(name, observable, summary=f"request error: {type(exc).__name__}")
    except (ValueError, KeyError, TypeError) as exc:  # JSON / shape errors
        return _result(name, observable, summary=f"parse error: {exc}")


def live_enrich(observable: str, obs_type: str = "",
                *, timeout: float = DEFAULT_TIMEOUT) -> list[ThreatIntelResult]:
    """Query every *configured* source that supports this observable type."""
    results: list[ThreatIntelResult] = []
    for cfg in source_configs():
        if not cfg["configured"]:
            continue
        if obs_type and cfg["supports"] and obs_type not in cfg["supports"]:
            continue
        results.append(live_lookup(cfg["name"], observable, obs_type, timeout=timeout))
    return results


def test_source(name: str) -> dict[str, Any]:
    """Probe a source with a benign indicator. Returns {ok, message}."""
    cfg = _config_for(name)
    if cfg is None:
        return {"ok": False, "message": f"unknown source: {name}"}
    if name not in _CLIENTS:
        return {"ok": False, "message": "no live client implemented"}
    if cfg["requires_key"] and not cfg["has_key"]:
        return {"ok": False, "message": f"missing API key ({cfg['api_key_env']})"}
    if cfg["needs_base_url"] and not cfg["has_base_url"]:
        return {"ok": False, "message": f"missing base URL ({cfg['base_url_env']})"}
    supports = cfg["supports"] or ["ip"]
    obs_type = "ip" if "ip" in supports else supports[0]
    probe = _TEST_OBSERVABLE.get(obs_type, "8.8.8.8")
    res = live_lookup(name, probe, obs_type, timeout=8.0)
    failed = res.summary.startswith(("request error", "parse error", "MISP query failed",
                                     "search failed", "no host data"))
    return {"ok": not failed, "message": res.summary or "ok", "verdict": res.verdict,
            "probe": f"{obs_type}:{probe}"}
