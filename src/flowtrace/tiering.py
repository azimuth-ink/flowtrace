"""FTC §4.2 — consequence-based prioritization.

criticality score (weighted business-impact dimensions) -> tier P0..P3 ->
tier policy (coverage threshold, sampling floor, alert latency, incident-
response SLA). All constants come from the config (flowtrace.yaml, "tiers"
and "criticality_score"); the disclosed concept is the derivation, not the
numbers.

Vocabulary reconciliation (canon §2, resolution C): the companion diagram
spec's deprecated `tier-1 | tier-2 | tier-3` map to `P0 | P1 | P2`; the FTC
v1.0 per-segment vocabulary `critical | high | medium | low` maps to
`P0 | P1 | P2 | P3`. Both are accepted on ingest with a warning, never emitted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .config import TIERS

TIER_ALIASES = {"tier-1": "P0", "tier-2": "P1", "tier-3": "P2"}
V10_CRITICALITY = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3"}


@dataclass(frozen=True)
class TierPolicy:
    tier: str
    coverage_threshold: float
    sampling_floor: float
    alert_latency_s: float
    ir_sla_s: float | None          # None = next business day (P3)
    require_convergent: bool
    answerability_required: bool

    def as_dict(self) -> dict:
        return {
            "tier": self.tier,
            "coverage_threshold": self.coverage_threshold,
            "sampling_floor": self.sampling_floor,
            "alert_latency_s": self.alert_latency_s,
            "ir_sla_s": self.ir_sla_s,
            "require_convergent": self.require_convergent,
            "answerability_required": self.answerability_required,
        }


def normalize_criticality(value: str | None, warnings: list[str] | None = None, where: str = "") -> str | None:
    """P0..P3 from any accepted spelling; appends a deprecation warning for an
    alias. None stays None (per-step 'inherit the flow's')."""
    if value is None:
        return None
    v = str(value)
    if v in TIERS:
        return v
    alias = TIER_ALIASES.get(v) or V10_CRITICALITY.get(v.lower())
    if alias is None:
        raise ValueError(f"unknown criticality {value!r}{(' at ' + where) if where else ''}")
    if warnings is not None:
        warnings.append(f"{where + ': ' if where else ''}criticality '{v}' is a deprecated alias of '{alias}' (R-DEPRECATED; never emitted)")
    return alias


def policy(cfg: Mapping[str, Any], tier: str) -> TierPolicy:
    t = cfg["tiers"][tier]
    return TierPolicy(
        tier=tier,
        coverage_threshold=float(t["coverage_threshold"]),
        sampling_floor=float(t["sampling_floor"]),
        alert_latency_s=float(t["alert_latency_s"]),
        ir_sla_s=None if t.get("ir_sla_s") is None else float(t["ir_sla_s"]),
        require_convergent=bool(t.get("require_convergent", False)),
        answerability_required=bool(t.get("answerability_required", False)),
    )


def score_from_dimensions(dimensions: Mapping[str, Any], cfg: Mapping[str, Any]) -> tuple[float, bool]:
    """Weighted sum of bounded dimension values -> (score, any_dimension_maximal).

    A dimension value may be a scale word (critical/high/medium/low per
    config.criticality_score.scale) or a number already on the 0..max scale.
    Unknown dimension names are ignored (weights are per config)."""
    cs = cfg["criticality_score"]
    weights, scale = cs["dimensions"], cs["scale"]
    maximum = max(float(v) for v in scale.values())
    score, maximal = 0.0, False
    for name, w in weights.items():
        raw = dimensions.get(name)
        if raw is None:
            continue
        if isinstance(raw, bool):
            val = maximum if raw else 0.0
        elif isinstance(raw, (int, float)):
            val = float(raw)
        else:
            if str(raw).lower() not in scale:
                raise ValueError(f"dimension {name}: unknown scale value {raw!r}")
            val = float(scale[str(raw).lower()])
        if not 0.0 <= val <= maximum:
            raise ValueError(f"dimension {name}: value {val} outside 0..{maximum}")
        if val >= maximum:
            maximal = True
        score += float(w) * val
    return score, maximal


def tier_from_score(score: float, cfg: Mapping[str, Any], any_maximal: bool = False) -> str:
    """Highest tier whose score_min the score reaches; any maximal dimension
    forces P0 when config.criticality_score.maximal_dimension_forces_p0."""
    if any_maximal and cfg["criticality_score"].get("maximal_dimension_forces_p0", True):
        return "P0"
    for t in TIERS:                      # P0 first: thresholds descend
        if score >= float(cfg["tiers"][t]["score_min"]):
            return t
    return "P3"


def tier_from_dimensions(dimensions: Mapping[str, Any], cfg: Mapping[str, Any]) -> tuple[str, float]:
    score, maximal = score_from_dimensions(dimensions, cfg)
    return tier_from_score(score, cfg, maximal), score


def step_criticality(step: Mapping[str, Any], flow_criticality: str, warnings: list[str] | None = None) -> str:
    """Per-step criticality where declared, the flow's otherwise (§4.2)."""
    own = normalize_criticality(step.get("criticality"), warnings, f"step {step.get('id')}")
    return own or flow_criticality
