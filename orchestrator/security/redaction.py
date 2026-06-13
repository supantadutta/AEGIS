"""Secret detection & redaction. Runs before any model/tool call or artifact
is logged or stored (Section 12.3)."""

from __future__ import annotations

import math
import re
from typing import Any

from orchestrator.core.config import load_security

_PLACEHOLDER = "[REDACTED]"


def _compiled_patterns() -> list[tuple[str, re.Pattern[str]]]:
    out: list[tuple[str, re.Pattern[str]]] = []
    for p in load_security().get("redaction", {}).get("patterns", []):
        try:
            out.append((p["name"], re.compile(p["regex"])))
        except re.error:
            continue
    return out


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _entropy_cfg() -> tuple[float, int]:
    r = load_security().get("redaction", {})
    return float(r.get("entropy_threshold", 4.0)), int(r.get("entropy_min_length", 20))


# Token candidates for the entropy heuristic (long opaque strings).
_TOKEN = re.compile(r"[A-Za-z0-9+/_\-=]{16,}")


def redact(text: str | None) -> str:
    """Redact known secret patterns and high-entropy tokens from text."""
    if not text:
        return text or ""
    redacted = text
    for _name, pattern in _compiled_patterns():
        redacted = pattern.sub(_PLACEHOLDER, redacted)

    threshold, min_len = _entropy_cfg()

    def _maybe_redact(m: re.Match[str]) -> str:
        tok = m.group(0)
        if len(tok) >= min_len and _shannon_entropy(tok) >= threshold:
            return _PLACEHOLDER
        return tok

    return _TOKEN.sub(_maybe_redact, redacted)


def contains_secret(text: str | None) -> bool:
    if not text:
        return False
    return redact(text) != text


def redact_obj(obj: Any) -> Any:
    """Recursively redact strings within dicts/lists."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    return obj
