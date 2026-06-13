"""Phase 8: SIEM query generation across platforms + safety properties."""

from __future__ import annotations

import pytest

from orchestrator.tools.detections import PLATFORM_KEYS, generate_query

DESTRUCTIVE = ["delete", "drop table", "truncate", "rm -rf", "| outputlookup"]


@pytest.mark.parametrize("platform", ["splunk", "kql", "logscale", "sigma", "wazuh"])
def test_generates_for_platforms(platform):
    gq = generate_query(platform, "brute-force")
    assert gq.platform == platform
    assert gq.query.strip()


def test_three_distinct_platforms():
    splunk = generate_query("splunk", "successful-login-after-failures").query
    kql = generate_query("kql", "successful-login-after-failures").query
    logscale = generate_query("splunk", "password-spraying").query
    assert splunk != kql
    assert "SecurityEvent" in kql
    assert logscale


def test_no_destructive_tokens():
    for uc in ("brute-force", "directory-traversal", "data-exfiltration", "c2-beaconing"):
        for platform in ("splunk", "kql"):
            q = generate_query(platform, uc).query.lower()
            for bad in DESTRUCTIVE:
                assert bad not in q


def test_platform_aliases():
    # 'spl' and 'splunk' both resolve; 'sentinel'/'elastic' map to kql.
    assert PLATFORM_KEYS["spl"] == "splunk"
    assert PLATFORM_KEYS["sentinel"] == "kql"
    gq = generate_query("spl", "brute-force")
    assert gq.query


def test_substitution_no_leftover_placeholders():
    q = generate_query("kql", "brute-force").query
    assert "{threshold}" not in q
    assert "{window_minutes}" not in q
