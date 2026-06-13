# AEGIS — Multi-AI Blue Team Orchestrator

> Local-first, defensive-security orchestration. Decomposes a SOC task,
> routes each subtask to the single best AI model/agent, checkpoints after
> every step, and produces analyst-grade output. **Runs end-to-end with zero
> API keys** using a deterministic MockProvider.

This is a **defensive** tool. It is read-only by default and never performs
offensive or destructive actions without explicit human approval. See
[SECURITY.md](SECURITY.md).

## Status

Under active construction — see [PROGRESS.md](PROGRESS.md) for phase status.

## Quick start

```bash
uv sync                      # or: pip install -e ".[dev]"
blue-orchestrator init
blue-orchestrator investigate examples/alerts/brute_force_alert.json
```

Full documentation is filled in as phases complete (Section 22 of the spec).
