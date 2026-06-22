# AEGIS — Deliverables & Walkthrough

## File tree (source)

```
AEGIS/
├── README.md  SECURITY.md  PROGRESS.md  DELIVERABLES.md
├── pyproject.toml  .env.example  .gitignore  docker-compose.yml
├── configs/
│   ├── models.yaml  router.yaml  agents.yaml  security.yaml
│   ├── integrations.yaml  detection_templates.yaml  report_templates.yaml
│   └── data/ (allowlist.csv, blocklist.csv, asset_inventory.csv, user_inventory.csv)
├── orchestrator/
│   ├── cli.py  main.py
│   ├── core/   (state, orchestrator, router, planner, checkpoints, memory,
│   │            events, approvals, config, settings)
│   ├── agents/ (base + planner, soc_investigator, threat_intel, log_analysis,
│   │            detection_engineer, incident_response, case_report, extended,
│   │            specialized registry)
│   ├── providers/ (base, mock, openai, anthropic, gemini, openrouter, ollama)
│   ├── tools/  (registry, filesystem, shell, git, parsers, ioc, timeline,
│   │            threat_intel, intel_sources, detections, reports, inventory)
│   ├── security/ (redaction, policy, audit, approvals)
│   ├── storage/  (base, sqlite, postgres-stub)
│   └── dashboard/ (app.py, service.py + templates/: index, sessions, session,
│                   investigate, detections, intel, integrations, settings,
│                   config_edit)
├── tests/   (state, checkpoints, router, resume, security, ioc_extraction,
│             timeline, detection_generation, reports, provider_interface,
│             tool_approval, query_generation, cli, memory, dashboard,
│             dashboard_controls, settings, intel_sources)
└── examples/ (alerts/, detections/, reports/)
```

## Setup

```bash
uv sync                      # or: pip install -e ".[dev]"
```

## Run

```bash
blue-orchestrator init
blue-orchestrator investigate examples/alerts/brute_force_alert.json
uvicorn orchestrator.dashboard.app:app          # dashboard at :8000
```

## Test / lint / types

```bash
pytest                 # 136 tests, all passing
ruff check orchestrator tests          # clean
mypy orchestrator                      # clean
```

## Example investigation walkthrough (MockProvider, zero keys)

`blue-orchestrator investigate examples/alerts/brute_force_alert.json`

1. Alert parsed → `AlertContext` (missing fields tracked).
2. **Planner** builds a 6-step `TaskGraph`.
3. **Router** selects a model per step (mock-first when no keys; privacy override
   forces local/mock on sensitive data).
4. **SOCInvestigatorAgent** (triage): extracts IOC `45.143.220.0`, classifies
   **Confirmed Incident** (sev high), maps **MITRE T1110 Brute Force**,
   identifies asset **DC01** (critical) from inventory. *Checkpoint.*
5. **ThreatIntelAgent**: local blocklist → `45.143.220.0` = **malicious**;
   external sources reported `disabled: no API key configured`. *Checkpoint.*
6. **LogAnalysisAgent**: 4-event timeline; flags failures-then-success. *Checkpoint.*
7. **DetectionEngineerAgent**: Sigma + Splunk + KQL for
   `successful-login-after-failures`. *Checkpoint.*
8. **IncidentResponseAgent**: containment/eradication/recovery (all
   approval-gated). *Checkpoint.*
9. **CaseReportAgent**: analyst + incident + executive reports → `final_output`.
10. `status=completed`.

Outputs are saved to SQLite and viewable via `inspect`, `iocs`, `timeline`,
`report`, or the dashboard.

## Example generated SIEM queries (3+ platforms)

- `examples/detections/brute_force.splunk` — Splunk SPL
- `examples/detections/password_spraying.logscale` — CrowdStrike LogScale/CQL
- `examples/detections/lateral_movement.kql` — Sentinel/Elastic KQL
- `examples/detections/suspicious_powershell.sigma.yml` — Sigma

```bash
blue-orchestrator generate-query --platform splunk   --use-case brute-force
blue-orchestrator generate-query --platform logscale --use-case password-spraying
blue-orchestrator generate-query --platform kql      --use-case lateral-movement
blue-orchestrator generate-sigma --use-case suspicious-powershell
```

## Example reports

- `examples/reports/analyst_report.md`
- `examples/reports/incident_report.md`
- `examples/reports/executive_summary.md`

## Example: resume with a different model

```bash
# Pause partway, then continue from current_step_id with another model:
blue-orchestrator resume <SESSION_ID> --model anthropic/claude-sonnet
```

The canonical `SessionState` is converted into the new provider's format and
the loop resumes; the decision log records the model switch. Without a key, the
adapter degrades cleanly to the MockProvider (no failure).

## Known limitations

- Real provider calls are implemented but only exercised when keys are set; CI
  runs entirely on the MockProvider.
- Live external threat-intel clients (VirusTotal, AbuseIPDB, GreyNoise, Shodan,
  OTX, URLScan, ThreatFox, MalwareBazaar, MISP, ASN/Geo, RDAP) are implemented
  and dashboard-configurable; they stay opt-in (`AEGIS_AUTO_LIVE_INTEL` or the
  `external_enrichment_api` approval gate) and CI mocks the HTTP layer.
- `parse_evtx_placeholder` is a placeholder; EVTX/PCAP parsing is not
  implemented (logs are parsed as text/`key=value`).
- `ROUTER_MODE=llm` is specced but rules mode is the implemented default.
- `PostgresStorage` is an interface-complete stub (raises `NotImplementedError`).
- MockProvider narratives are templated (deterministic), not model-generated.
- Editing a YAML config from the dashboard rewrites it via `yaml.safe_dump`,
  which drops file comments (the structure/values are preserved).

## Suggested next improvements

- Per-source response caching + rate-limit handling for live threat-intel.
- Implement `ROUTER_MODE=llm` using the shared `RouterDecision` schema.
- Real EVTX/PCAP/Zeek parsers feeding the timeline.
- Implement `PostgresStorage` for multi-user deployments.
- Cost-aware routing using real per-model pricing tables.
- Purple-team validation harness (local lab only, explicitly authorized).
