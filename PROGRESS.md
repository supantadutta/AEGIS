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
- [ ] Phase 8 — Remaining agents + detections + reports + queries
- [ ] Phase 9 — Real provider adapters (wired up)
- [ ] Phase 10 — Threat intel integrations + continuous learning
- [ ] Phase 11 — Dashboard
- [ ] Phase 12 — Test completion, docs, deliverables

## Notes / limitations

- Mock-mode is the default and fully functional with zero API keys.
- Real provider adapters degrade cleanly to mock when no key is set.
- Safety boundaries (Section 12): shell commands & risky actions are
  approval-gated; offensive capability is never implemented.
