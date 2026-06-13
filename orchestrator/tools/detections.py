"""Detection rule & SIEM query generation from configs/detection_templates.yaml.

Renders Sigma / Splunk SPL / Elastic-Sentinel KQL / LogScale CQL / Wazuh /
Suricata / YARA for a given use case. All output is read-only detection logic —
never a destructive or active-response action.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import yaml

from orchestrator.core.config import load_detection_templates
from orchestrator.core.state import DetectionRule, GeneratedQuery

# Map the spec's platform names onto the template keys we store.
PLATFORM_KEYS = {
    "sigma": "sigma",
    "splunk": "splunk",
    "spl": "splunk",
    "kql": "kql",
    "sentinel": "kql",
    "elastic": "kql",
    "logscale": "logscale",
    "cql": "logscale",
    "humio": "logscale",
    "wazuh": "wazuh",
    "suricata": "suricata",
    "snort": "suricata",
}


class UnknownUseCase(KeyError):
    pass


def available_use_cases() -> list[str]:
    return list(load_detection_templates().get("use_cases", {}).keys())


def _use_case(name: str) -> dict[str, Any]:
    cases = load_detection_templates().get("use_cases", {})
    if name not in cases:
        raise UnknownUseCase(f"unknown use case '{name}'. Known: {', '.join(cases)}")
    return cases[name]


def _render_vars(uc: dict[str, Any], overrides: dict[str, Any] | None) -> dict[str, Any]:
    defaults = dict(load_detection_templates().get("defaults", {}))
    values = defaultdict(str)
    values.update(defaults)
    for key in ("threshold", "window_minutes"):
        if key in uc:
            values[key] = uc[key]
    if "window_minutes" in uc:
        values["window_seconds"] = int(uc["window_minutes"]) * 60
    if overrides:
        values.update(overrides)
    return values


def _format(template: str, values: dict[str, Any]) -> str:
    return template.format_map(defaultdict(str, values))


def _sigma_yaml(uc: dict[str, Any], title: str) -> str:
    mitre = uc.get("mitre", {})
    doc = {
        "title": title,
        "status": "experimental",
        "description": uc.get("description", ""),
        "logsource": uc.get("sigma_logsource", {"product": "windows"}),
        "detection": uc.get("sigma_detection", {"selection": {}, "condition": "selection"}),
        "level": uc.get("severity", "medium"),
        "tags": [f"attack.{mitre.get('technique_id', '').lower()}"] if mitre else [],
        "falsepositives": [uc.get("false_positive_notes", "")],
    }
    return yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)


def generate_query(platform: str, use_case: str, overrides: dict[str, Any] | None = None) -> GeneratedQuery:
    """Render a SIEM query string for a platform + use case."""
    key = PLATFORM_KEYS.get(platform.lower())
    if key is None:
        raise ValueError(f"unsupported platform '{platform}'. Known: {sorted(set(PLATFORM_KEYS))}")
    uc = _use_case(use_case)
    values = _render_vars(uc, overrides)
    if key == "sigma":
        query = _sigma_yaml(uc, uc.get("title", use_case))
    else:
        template = uc.get(key)
        if not template:
            # Fall back to a readable, time-scoped placeholder query.
            query = (
                f"# {platform} query for '{use_case}' ({uc.get('title','')})\n"
                f"# data_source={uc.get('data_source','')} fields={uc.get('required_fields',[])}\n"
                f"# No platform-specific template defined; scope to last 24h and "
                f"filter on the required fields above."
            )
        else:
            query = _format(template, values).strip()
    notes = uc.get("false_positive_notes", "")
    return GeneratedQuery(platform=platform, use_case=use_case, query=query, notes=notes)


def generate_detection_rule(use_case: str, fmt: str = "sigma",
                            overrides: dict[str, Any] | None = None) -> DetectionRule:
    """Render a full DetectionRule (with metadata) for a use case + format."""
    uc = _use_case(use_case)
    gq = generate_query(fmt, use_case, overrides)
    mitre = uc.get("mitre", {})
    mitre_str = (
        f"{mitre.get('technique_id','')} {mitre.get('technique_name','')} "
        f"({mitre.get('tactic','')})".strip()
    ) if mitre else ""
    return DetectionRule(
        format=PLATFORM_KEYS.get(fmt.lower(), fmt.lower()),
        title=uc.get("title", use_case),
        description=uc.get("description", ""),
        logic=gq.query,
        data_source=uc.get("data_source", ""),
        required_fields=uc.get("required_fields", []),
        false_positive_notes=uc.get("false_positive_notes", ""),
        severity=uc.get("severity", "medium"),
        mitre_mapping=[mitre_str] if mitre_str else [],
        test_data=uc.get("description", ""),
        validation_steps=[
            "Load representative test events into a non-production index.",
            "Confirm the rule fires on true-positive samples.",
            "Confirm benign samples (see false-positive notes) do not fire.",
        ],
        tuning_recommendations=[
            f"Tune thresholds/time windows for your environment "
            f"(current: threshold={uc.get('threshold', 'n/a')}, "
            f"window={uc.get('window_minutes', 'n/a')}m).",
        ],
    )


def generate_sigma(use_case: str, overrides: dict[str, Any] | None = None) -> DetectionRule:
    return generate_detection_rule(use_case, fmt="sigma", overrides=overrides)
