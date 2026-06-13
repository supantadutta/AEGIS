"""IOC extraction from free text / logs. Pure, deterministic, offline."""

from __future__ import annotations

import ipaddress
import re

from orchestrator.core.state import IOC

# Defanged indicators are common in alerts/intel; refang before matching.
_REFANG = [("[.]", "."), ("(.)", "."), ("hxxp", "http"), ("[:]", ":"), ("[at]", "@")]

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")
_URL = re.compile(r"\bhttps?://[^\s\"'<>)]+", re.IGNORECASE)
_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_REG = re.compile(r"\bHK(?:LM|CU|CR|U|CC)\\[^\s\"']+", re.IGNORECASE)

# Common file extensions worth flagging as filename IOCs.
_FILENAME = re.compile(
    r"\b[\w\-.]+\.(?:exe|dll|ps1|bat|vbs|js|jar|scr|lnk|doc[xm]?|xls[xm]?|pdf|zip|7z|rar|sh|py)\b",
    re.IGNORECASE,
)


def refang(text: str) -> str:
    for a, b in _REFANG:
        text = text.replace(a, b)
    return text


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False


def extract_iocs(text: str | None) -> list[IOC]:
    """Extract de-duplicated IOCs from text. Order: hashes/urls/emails first so
    their substrings aren't double-counted as domains."""
    if not text:
        return []
    text = refang(text)
    found: dict[tuple[str, str], IOC] = {}

    def add(ioc_type: str, value: str, context: str = "") -> None:
        key = (ioc_type, value.lower())
        if key not in found:
            found[key] = IOC(type=ioc_type, value=value, context=context or ioc_type)

    for m in _URL.finditer(text):
        add("url", m.group(0))
    for m in _EMAIL.finditer(text):
        add("email", m.group(0))
    for m in _SHA256.finditer(text):
        add("hash", m.group(0), "sha256")
    for m in _SHA1.finditer(text):
        add("hash", m.group(0), "sha1")
    for m in _MD5.finditer(text):
        add("hash", m.group(0), "md5")
    for m in _CVE.finditer(text):
        add("cve", m.group(0).upper())
    for m in _REG.finditer(text):
        add("registry_key", m.group(0))

    # Collect URL/email substrings to avoid re-flagging their domains/ips.
    consumed = " ".join(i.value for i in found.values() if i.type in ("url", "email"))

    for m in _IPV4.finditer(text):
        val = m.group(0)
        if val in consumed:
            continue
        if _is_public_ip(val):
            add("ip", val, "public ip")
    for m in _FILENAME.finditer(text):
        add("filename", m.group(0))
    for m in _DOMAIN.finditer(text):
        val = m.group(0)
        # Skip things already captured (urls/emails) and bare IPs.
        if val in consumed or _IPV4.fullmatch(val):
            continue
        # Skip filenames matched as domains (e.g. p.ps1).
        if _FILENAME.fullmatch(val):
            continue
        add("domain", val)

    return list(found.values())
