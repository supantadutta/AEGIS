"""Phase 7: timeline building."""

from __future__ import annotations

from orchestrator.core.state import AlertContext
from orchestrator.tools.timeline import build_timeline

RAW = (
    "2026-06-12T03:02:10Z EventID=4625 user=admin src_ip=45.143.220.0 dst=DC01 outcome=failure\n"
    "2026-06-12T03:02:14Z EventID=4625 user=admin src_ip=45.143.220.0 dst=DC01 outcome=failure\n"
    "2026-06-12T03:14:22Z EventID=4624 user=admin src_ip=45.143.220.0 dst=DC01 outcome=success logon_type=3"
)


def test_build_timeline_orders_events():
    events = build_timeline(RAW, None)
    assert len(events) == 3
    assert events == sorted(events, key=lambda e: e.timestamp)
    assert events[0].event_type == "authentication_failure"
    assert events[-1].event_type == "authentication_success"
    assert events[0].actor == "admin"
    assert events[0].source_ip == "45.143.220.0"


def test_fallback_to_alert_event_time():
    alert = AlertContext(alert_name="x", event_time="2026-06-12T03:14:22Z",
                         source_tool="Splunk")
    events = build_timeline(None, alert)
    assert len(events) == 1
    assert events[0].event_type == "alert_raised"


def test_empty_inputs():
    assert build_timeline(None, None) == []
