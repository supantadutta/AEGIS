"""Phase 7: IOC extraction."""

from __future__ import annotations

from orchestrator.tools.ioc import extract_iocs, refang


def _types(text):
    return {(i.type, i.value) for i in extract_iocs(text)}


def test_extract_ip_domain_url_hash():
    text = ("Connection from 45.143.220.0 to http://malware-drop.example/p.ps1 "
            "hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "contact bad@evil.example")
    found = _types(text)
    assert ("ip", "45.143.220.0") in found
    assert ("url", "http://malware-drop.example/p.ps1") in found
    assert ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") in found
    assert ("email", "bad@evil.example") in found


def test_private_ip_excluded():
    found = {v for _t, v in _types("internal host 10.0.0.10 and 192.168.1.5")}
    assert "10.0.0.10" not in found
    assert "192.168.1.5" not in found


def test_defang_refang():
    assert refang("hxxp://evil[.]com") == "http://evil.com"
    found = _types("beacon to hxxp://evil[.]com/x")
    assert any(t == "url" for t, _v in found)


def test_cve_and_registry():
    found = _types("Exploited CVE-2021-44228 via HKLM\\Software\\Run\\evil")
    assert ("cve", "CVE-2021-44228") in found
    assert any(t == "registry_key" for t, _v in found)


def test_dedup():
    iocs = extract_iocs("1.2.3.4 1.2.3.4 1.2.3.4")
    assert len([i for i in iocs if i.type == "ip"]) == 1


def test_empty():
    assert extract_iocs(None) == []
    assert extract_iocs("") == []
