"""Timeline construction from raw logs / alert context. Deterministic parser
for common `key=value` SIEM log lines with leading ISO timestamps.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from orchestrator.core.state import AlertContext, TimelineEvent

_TS = re.compile(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def _parse_ts(raw: str) -> datetime | None:
    raw = raw.strip().replace(" ", "T")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _kv(line: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in _KV.findall(line):
        out[k.lower()] = v.strip('"')
    return out


def _event_type(fields: dict[str, str]) -> str:
    eid = fields.get("eventid") or fields.get("eventcode")
    outcome = (fields.get("outcome") or "").lower()
    if eid == "4625" or "fail" in outcome:
        return "authentication_failure"
    if eid == "4624" or "success" in outcome:
        return "authentication_success"
    if fields.get("process") or fields.get("cmd") or fields.get("command_line"):
        return "process_execution"
    if fields.get("uri") or fields.get("url"):
        return "web_request"
    return "log_event"


def build_timeline(raw_log: str | None, alert: AlertContext | None = None) -> list[TimelineEvent]:
    """Parse raw log lines into ordered TimelineEvents. Falls back to the
    alert's event_time when individual lines lack timestamps."""
    events: list[TimelineEvent] = []
    if raw_log:
        for line in raw_log.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _TS.search(line)
            ts = _parse_ts(m.group(1)) if m else None
            fields = _kv(line)
            etype = _event_type(fields)
            outcome = fields.get("outcome")
            confidence = 0.85 if etype.startswith("authentication") else 0.6
            events.append(TimelineEvent(
                timestamp=ts or datetime.now(UTC),
                source=fields.get("source") or (alert.source_tool if alert else "log") or "log",
                event_type=etype,
                actor=fields.get("user") or fields.get("username"),
                source_ip=fields.get("src_ip") or fields.get("source_ip"),
                source_host=fields.get("src_host") or fields.get("host"),
                destination_ip=fields.get("dst_ip") or fields.get("dest_ip"),
                destination_host=fields.get("dst") or fields.get("dst_host") or fields.get("dest_host"),
                process=fields.get("process"),
                command_line=fields.get("cmd") or fields.get("command_line"),
                outcome=outcome,
                raw_reference=line[:200],
                explanation=f"Parsed {etype} from log line.",
                confidence=confidence,
            ))
    if not events and alert and alert.event_time:
        ts = _parse_ts(alert.event_time) or datetime.now(UTC)
        events.append(TimelineEvent(
            timestamp=ts, source=alert.source_tool or "alert", event_type="alert_raised",
            actor=alert.username, source_ip=alert.source_ip,
            destination_host=alert.destination_host,
            explanation=f"Alert '{alert.alert_name}' raised.", confidence=0.7,
        ))
    events.sort(key=lambda e: e.timestamp)
    return events
