# AEGIS — Build Progress

Multi-AI Blue Team Orchestrator. Local-first, mock-mode by default.

## Phase checklist

- [x] Phase 0 — Bootstrap (repo skeleton, pyproject, configs, examples)
- [ ] Phase 1 — Core schemas (SessionState, AlertContext, Router output)
- [ ] Phase 2 — Storage & checkpoints (SQLite)
- [ ] Phase 3 — Providers & MockProvider
- [ ] Phase 4 — Router (rules mode)
- [ ] Phase 5 — Orchestrator core loop + Planner + Approvals
- [ ] Phase 6 — MVP agent set + CLI
- [ ] Phase 7 — IOC extraction, timeline, tool registry, security layer
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
