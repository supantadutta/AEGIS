"""Alert ingestion parsers. Normalize JSON / markdown / CSV / pasted text into
a single canonical AlertContext, recording which fields were missing.
"""

from __future__ import annotations

import csv
import io
import json
import re

from orchestrator.core.state import AlertContext

# Canonical alert fields (Section 7). Used to compute missing_fields and to
# map loosely-named input keys onto the canonical schema.
ALERT_FIELDS = [
    "alert_id", "alert_name", "severity", "source_tool", "detection_name",
    "detection_id", "event_time", "start_time", "end_time", "source_ip",
    "destination_ip", "source_host", "destination_host", "username",
    "process_name", "command_line", "file_hash", "url", "domain",
    "user_agent", "raw_log", "analyst_notes", "customer_context",
    "asset_criticality", "business_impact",
]

# Common aliases seen across SIEM exports -> canonical field name.
_ALIASES = {
    "name": "alert_name",
    "title": "alert_name",
    "rule_name": "detection_name",
    "rule_id": "detection_id",
    "src_ip": "source_ip",
    "srcip": "source_ip",
    "dst_ip": "destination_ip",
    "dest_ip": "destination_ip",
    "dstip": "destination_ip",
    "src_host": "source_host",
    "dst_host": "destination_host",
    "dest_host": "destination_host",
    "host": "source_host",
    "user": "username",
    "account": "username",
    "process": "process_name",
    "cmd": "command_line",
    "cmdline": "command_line",
    "hash": "file_hash",
    "sha256": "file_hash",
    "md5": "file_hash",
    "ua": "user_agent",
    "notes": "analyst_notes",
    "tool": "source_tool",
    "source": "source_tool",
    "time": "event_time",
    "timestamp": "event_time",
}

_LIST_FIELDS = {"evidence_links", "screenshots"}


def _canon_key(key: str) -> str:
    k = key.strip().lower().replace(" ", "_").replace("-", "_")
    return _ALIASES.get(k, k)


def _from_mapping(data: dict) -> AlertContext:
    fields: dict = {}
    for raw_key, value in data.items():
        key = _canon_key(str(raw_key))
        if key in _LIST_FIELDS and isinstance(value, str):
            value = [v.strip() for v in value.split(",") if v.strip()]
        if key in AlertContext.model_fields and value not in (None, "", []):
            fields[key] = value
    ctx = AlertContext(**fields)
    ctx.missing_fields = [f for f in ALERT_FIELDS if not getattr(ctx, f, None)]
    return ctx


def parse_json(text: str) -> AlertContext:
    data = json.loads(text)
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        raise ValueError("JSON alert must be an object or list of objects")
    return _from_mapping(data)


def parse_csv(text: str) -> AlertContext:
    reader = csv.DictReader(io.StringIO(text.strip()))
    rows = list(reader)
    if not rows:
        raise ValueError("CSV alert contained no data rows")
    return _from_mapping(rows[0])


def parse_markdown(text: str) -> AlertContext:
    """Parse a markdown alert. Supports `**Key:** value`, `- key: value`,
    `| key | value |` table rows, and `key: value` lines."""
    data: dict = {}
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Markdown table row: | key | value |
        if line.startswith("|") and line.count("|") >= 2:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) >= 2 and cells[0] and cells[0].lower() not in ("field", "key", "---"):
                data.setdefault(cells[0], cells[1])
            continue
        # Strip bold/code markers first, then leading list markers, so that
        # "**Key:**" does not leave a stray "*" behind.
        cleaned = line.replace("**", "").replace("`", "")
        cleaned = re.sub(r"^[-*]\s*", "", cleaned)
        m = re.match(r"^([A-Za-z0-9_ \-]+?)\s*[:=]\s*(.+)$", cleaned)
        if m:
            data.setdefault(m.group(1), m.group(2))
    if not data:
        raise ValueError("No key/value pairs found in markdown alert")
    return _from_mapping(data)


def parse_text(text: str) -> AlertContext:
    """Best-effort parse of free-form pasted alert text. Extracts key:value
    pairs where present and stashes the whole blob in raw_log/analyst_notes."""
    try:
        return parse_json(text)
    except (json.JSONDecodeError, ValueError):
        pass
    data: dict = {}
    for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]{1,30})\s*[:=]\s*([^\s,;]+)", text):
        data.setdefault(m.group(1).strip(), m.group(2).strip())
    ctx = _from_mapping(data) if data else AlertContext()
    if not ctx.raw_log:
        ctx.raw_log = text.strip()
    if not ctx.alert_name:
        ctx.alert_name = "Pasted alert text"
    ctx.missing_fields = [f for f in ALERT_FIELDS if not getattr(ctx, f, None)]
    return ctx


def parse_alert(text: str, fmt: str = "auto") -> AlertContext:
    """Dispatch to the right parser. fmt: auto|json|csv|markdown|text."""
    text = text.strip()
    if fmt == "json":
        return parse_json(text)
    if fmt == "csv":
        return parse_csv(text)
    if fmt == "markdown":
        return parse_markdown(text)
    if fmt == "text":
        return parse_text(text)
    # auto-detect
    if text.startswith("{") or text.startswith("["):
        return parse_json(text)
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if "," in first_line and "\n" in text and ":" not in first_line:
        try:
            return parse_csv(text)
        except ValueError:
            pass
    if "|" in text or "**" in text or re.search(r"^[-*]\s", text, re.M):
        try:
            return parse_markdown(text)
        except ValueError:
            pass
    return parse_text(text)
