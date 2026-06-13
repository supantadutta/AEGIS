"""Deterministic, rules-based Router (Section 11).

Scores every model in models.yaml for a given step and returns a RouterDecision
(Section 4.2) with fallbacks. A hard privacy override runs before scoring:
confidential/restricted data is restricted to local/mock models unless
ALLOW_EXTERNAL_FOR_SENSITIVE=true.
"""

from __future__ import annotations

from dataclasses import dataclass

from orchestrator.core.config import env_bool, load_models, load_router
from orchestrator.core.state import (
    DataSensitivity,
    RiskLevel,
    RouterDecision,
    SessionState,
    TaskStep,
)
from orchestrator.storage.base import Storage

_RISK_PENALTY = {"low": 0.0, "medium": 0.3, "high": 0.7, "critical": 1.0}
_SENS_PENALTY = {"public": 0.0, "internal": 0.2, "confidential": 0.7, "restricted": 1.0}


@dataclass
class ScoredModel:
    model_id: str
    score: float
    breakdown: dict[str, float]


class Router:
    def __init__(self, storage: Storage | None = None) -> None:
        self.storage = storage
        self.models_cfg = load_models()
        self.router_cfg = load_router()
        self.weights = self.router_cfg["weights"]

    # --- public API ---
    def route(
        self,
        step: TaskStep,
        session: SessionState | None = None,
        *,
        user_preference: str | None = None,
    ) -> RouterDecision:
        candidates = self._candidate_models(step, session)
        scored = sorted(
            (self._score(step, m) for m in candidates),
            key=lambda s: (s.score, self._pref_rank(s.model_id)),
            reverse=True,
        )
        # Honor an explicit user preference if it survived the privacy filter.
        if user_preference and any(s.model_id == user_preference for s in scored):
            scored.sort(key=lambda s: (s.model_id != user_preference, -s.score))

        best = scored[0]
        fallbacks = [s.model_id for s in scored[1:4]]
        requires_approval = step.requires_human_approval or step.risk_level in ("high", "critical")
        reason = self._reason(step, best)
        return RouterDecision(
            selected_agent=step.agent,
            selected_model=best.model_id,
            reason=reason,
            confidence=round(min(0.99, 0.5 + best.score / 12.0), 2),
            fallback_models=fallbacks,
            requires_human_approval=requires_approval,
            risk_level=step.risk_level,
            data_sensitivity=step.data_sensitivity,
            step_id=step.step_id,
        )

    # --- privacy override (hard rule, before scoring) ---
    def _candidate_models(self, step: TaskStep, session: SessionState | None) -> list[dict]:
        models = self.models_cfg.get("models", [])
        sensitive = step.data_sensitivity in ("confidential", "restricted")
        allow_external = env_bool("ALLOW_EXTERNAL_FOR_SENSITIVE", False)
        if sensitive and not allow_external:
            restricted = [m for m in models if m.get("privacy_tier") in ("local", "mock")]
            if session is not None:
                from orchestrator.core.state import RiskLogEntry

                session.risk_log.append(
                    RiskLogEntry(
                        description=(
                            f"Privacy override: data_sensitivity={step.data_sensitivity}; "
                            f"restricted routing to local/mock models for step '{step.name}'."
                        ),
                        risk_level="medium",
                        step_id=step.step_id,
                    )
                )
            return restricted or [m for m in models if m.get("provider") == "mock"]
        return models

    # --- scoring ---
    def _score(self, step: TaskStep, model: dict) -> ScoredModel:
        w = self.weights
        cap = self._capability_match(step.agent, model)
        ctx = self.router_cfg["context_tier_scores"].get(model.get("context_tier", "medium"), 0.5)
        cost = self.router_cfg["cost_tier_scores"].get(model.get("cost_tier", "medium"), 0.5)
        lat = self.router_cfg["latency_tier_scores"].get(model.get("cost_tier", "medium"), 0.5)
        priv = self._privacy_fit(step.data_sensitivity, model.get("privacy_tier", "external"))
        hist = self._historical(step.task_type, model["id"])
        risk_pen = _RISK_PENALTY.get(step.risk_level, 0.0)
        sens_pen = _SENS_PENALTY.get(step.data_sensitivity, 0.0)
        # External models incur the sensitivity penalty; local/mock do not.
        if model.get("privacy_tier") in ("local", "mock"):
            sens_pen = 0.0

        score = (
            w["capability_match"] * cap
            + w["context_fit"] * ctx
            + w["cost_fit"] * cost
            + w["latency_fit"] * lat
            + w["privacy_fit"] * priv
            + w["historical_success"] * hist
            - w["risk_penalty"] * risk_pen
            - w["data_sensitivity_penalty"] * sens_pen
        )
        return ScoredModel(
            model_id=model["id"],
            score=round(score, 4),
            breakdown={
                "capability": cap, "context": ctx, "cost": cost, "latency": lat,
                "privacy": priv, "historical": hist,
                "risk_penalty": risk_pen, "sensitivity_penalty": sens_pen,
            },
        )

    def _capability_match(self, agent: str, model: dict) -> float:
        wanted = self.router_cfg.get("agent_capabilities", {}).get(agent, [])
        strengths = set(model.get("strengths", []))
        if not wanted:
            return 0.5
        hits = sum(1 for c in wanted if c in strengths)
        return hits / len(wanted)

    def _privacy_fit(self, sensitivity: DataSensitivity, privacy_tier: str) -> float:
        table = self.router_cfg.get("privacy_fit", {}).get(sensitivity, {})
        return table.get(privacy_tier, 0.5)

    def _historical(self, task_type: str, model_id: str) -> float:
        if self.storage is None:
            return 0.5
        rate = self.storage.feedback_success_rate(model_id, task_type)
        return 0.5 if rate is None else float(rate)

    def _pref_rank(self, model_id: str) -> float:
        order = self.router_cfg.get("preference_order", [])
        try:
            # Higher rank value = more preferred (reverse-sorted).
            return float(len(order) - order.index(model_id))
        except ValueError:
            return 0.0

    def _reason(self, step: TaskStep, best: ScoredModel) -> str:
        b = best.breakdown
        bits = [f"capability={b['capability']:.2f}", f"privacy={b['privacy']:.2f}"]
        if b["sensitivity_penalty"] == 0.0 and step.data_sensitivity in ("confidential", "restricted"):
            bits.append("local/mock enforced for sensitive data")
        return (
            f"Selected {best.model_id} for {step.agent} ({step.task_type}); "
            f"{', '.join(bits)}; data_sensitivity={step.data_sensitivity}, "
            f"risk={step.risk_level}."
        )
