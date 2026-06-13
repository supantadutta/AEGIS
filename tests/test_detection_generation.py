"""Phase 8: detection rule generation across formats."""

from __future__ import annotations

import pytest
import yaml

from orchestrator.tools.detections import (
    available_use_cases,
    generate_detection_rule,
    generate_query,
    generate_sigma,
)


def test_sigma_is_valid_yaml():
    rule = generate_sigma("suspicious-powershell")
    assert rule.format == "sigma"
    doc = yaml.safe_load(rule.logic)
    assert doc["title"] == "Suspicious PowerShell Execution"
    assert "detection" in doc
    assert rule.false_positive_notes
    assert rule.validation_steps
    assert rule.mitre_mapping and "T1059.001" in rule.mitre_mapping[0]


def test_detection_rule_metadata_complete():
    rule = generate_detection_rule("brute-force", fmt="sigma")
    assert rule.title and rule.description and rule.data_source
    assert rule.required_fields
    assert rule.severity in ("info", "low", "medium", "high", "critical")
    assert rule.tuning_recommendations


def test_all_use_cases_render_sigma():
    for uc in available_use_cases():
        rule = generate_sigma(uc)
        assert rule.logic  # never empty
        yaml.safe_load(rule.logic)  # valid yaml


def test_splunk_query_has_threshold():
    gq = generate_query("splunk", "brute-force")
    assert "stats count" in gq.query
    assert "> 10" in gq.query  # threshold substituted, no leftover {threshold}
    assert "{" not in gq.query


def test_unknown_use_case_raises():
    with pytest.raises(KeyError):
        generate_sigma("does-not-exist")


def test_unknown_platform_raises():
    with pytest.raises(ValueError):
        generate_query("notaplatform", "brute-force")
