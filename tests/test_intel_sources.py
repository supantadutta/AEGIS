"""Live threat-intel source clients: metadata, gating, dispatch, test probe."""

from __future__ import annotations

import pytest

from orchestrator.tools import intel_sources, threat_intel


class FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _clean_intel_env(monkeypatch):
    for env in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY",
                "OTX_API_KEY", "SHODAN_API_KEY", "MISP_API_KEY", "AEGIS_AUTO_LIVE_INTEL"):
        monkeypatch.delenv(env, raising=False)
    from orchestrator.core.config import clear_cache
    clear_cache()


def test_source_configs_reports_unconfigured_by_default():
    cfgs = {c["name"]: c for c in intel_sources.source_configs()}
    assert "AbuseIPDB" in cfgs
    abuse = cfgs["AbuseIPDB"]
    assert abuse["requires_key"] is True
    assert abuse["has_key"] is False
    assert abuse["has_client"] is True
    assert abuse["configured"] is False  # disabled + no key


def test_test_source_requires_key():
    res = intel_sources.test_source("AbuseIPDB")
    assert res["ok"] is False
    assert "missing API key" in res["message"]


def test_live_lookup_unknown_source_is_safe():
    res = intel_sources.live_lookup("NoSuchSource", "8.8.8.8", "ip")
    assert res.verdict == "unknown"
    assert "no live client" in res.summary


def test_abuseipdb_client_maps_score(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    monkeypatch.setattr(intel_sources, "_get",
                        lambda *a, **k: FakeResp({"data": {"abuseConfidenceScore": 90,
                                                            "totalReports": 12, "countryCode": "RU"}}))
    res = intel_sources.live_lookup("AbuseIPDB", "45.143.220.0", "ip")
    assert res.source == "AbuseIPDB"
    assert res.verdict == "malicious"
    assert "90/100" in res.summary


def test_keyless_asn_geo(monkeypatch):
    monkeypatch.setattr(intel_sources, "_get",
                        lambda *a, **k: FakeResp({"status": "success", "country": "US",
                                                  "isp": "Google", "as": "AS15169", "query": "8.8.8.8"}))
    res = intel_sources.live_lookup("ASN_GEO", "8.8.8.8", "ip")
    assert res.source == "ASN_GEO"
    assert "AS15169" in res.summary


def test_http_error_degrades_to_unknown(monkeypatch):
    import httpx

    def boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    monkeypatch.setattr(intel_sources, "_get", boom)
    res = intel_sources.live_lookup("AbuseIPDB", "45.143.220.0", "ip")
    assert res.verdict == "unknown"
    assert "request error" in res.summary


def test_enrich_default_offline_preserves_disabled_summaries():
    # No keys, auto-live off: external sources still reported as disabled.
    results = threat_intel.enrich("45.143.220.0", "ip")
    assert any(r.source == "local_blocklist" for r in results)
    assert any(r.summary == "disabled: no API key configured" for r in results)


def test_enrich_live_flag_queries_configured_sources(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "key")
    # Enable AbuseIPDB in the in-memory integrations config.
    from orchestrator.core import config

    cfg = config.load_integrations()
    for src in cfg["external_sources"]:
        if src["name"] == "AbuseIPDB":
            src["enabled"] = True
    monkeypatch.setattr(config, "load_integrations", lambda: cfg)
    monkeypatch.setattr(intel_sources, "load_integrations", lambda: cfg)
    monkeypatch.setattr(intel_sources, "_get",
                        lambda *a, **k: FakeResp({"data": {"abuseConfidenceScore": 80,
                                                            "totalReports": 3, "countryCode": "RU"}}))
    results = threat_intel.enrich("45.143.220.0", "ip", live=True)
    abuse = [r for r in results if r.source == "AbuseIPDB"]
    assert abuse and abuse[0].verdict == "malicious"
