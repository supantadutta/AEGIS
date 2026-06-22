# AEGIS — Build Progress

Multi-AI Blue Team Orchestrator. Local-first, mock-mode by default.

## Phase checklist

- [x] Phase 0 — Bootstrap (repo skeleton, pyproject, configs, examples)
- [x] Phase 1 — Core schemas (SessionState, AlertContext, Router output)
- [x] Phase 2 — Storage & checkpoints (SQLite)
- [x] Phase 3 — Providers & MockProvider
- [x] Phase 4 — Router (rules mode)
- [x] Phase 5 — Orchestrator core loop + Planner + Approvals
- [x] Phase 6 — MVP agent set + CLI
- [x] Phase 7 — IOC extraction, timeline, tool registry, security layer
- [x] Phase 8 — Remaining agents + detections + reports + queries
- [x] Phase 9 — Real provider adapters (wired up)
- [x] Phase 10 — Threat intel integrations + continuous learning
- [x] Phase 11 — Dashboard
- [x] Phase 12 — Test completion, docs, deliverables

## v0.2 — Operator control panel

- [x] Runtime settings store (`aegis_settings.json`, 0600, env overlay, masking)
- [x] Dashboard configures everything: provider keys, feature flags, every YAML
      config — no file editing required
- [x] Run investigations, approve gates, and resume (with model override) from
      the browser
- [x] Live threat-intel integrations (VirusTotal, AbuseIPDB, GreyNoise, Shodan,
      OTX, URLScan, ThreatFox, MalwareBazaar, MISP, ASN/Geo, RDAP) — enable, key,
      and test from the Integrations tab; opt-in for the automated pipeline
- [x] On-demand IOC lookups + allow/block list management from the UI
- [x] Fixed `.gitignore` bug that excluded `configs/data/*.csv` from the repo

## Notes / limitations

- Mock-mode is the default and fully functional with zero API keys.
- Real provider adapters degrade cleanly to mock when no key is set.
- Safety boundaries (Section 12): shell commands & risky actions are
  approval-gated; offensive capability is never implemented.
