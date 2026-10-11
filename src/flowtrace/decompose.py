"""FTC §4.3 — SLA-to-SLO decomposition, restated over steps (canon D1).

Pure functions: every input is an argument, every constant comes from the
config mapping passed in (flowtrace.yaml "decomposition"), nothing is read
from disk and nothing is cached. The algorithm, step numbers as in the paper:

  1. partition steps into serial and parallel groups
       serial:   flow_p99 >= sum(step_p99)      parallel: flow_p99 >= max(step_p99)
  2. available = target - parallel group's maximum historical contribution
  3. serial base_i = available * hist_i / sum(hist_serial)
  4. x criticality factor (P0 0.8 ... P3 1.2; the step's own criticality
     where declared, the flow's otherwise — the caller resolves that)
  4b. x nondeterminism factor (ND0 0.9, ND1 1.0, ND2 1.1, ND3 1.25; none 1.0)
  5. x safety margin (0.9)
  6. error budget_i = flow_error_budget * error_factor(crit_i) / n_steps
  7. if sum(serial) + max(parallel) > target: scale every allocation by
     target / that sum
  8. other percentiles approximated (p95 ~= 0.7 x p99)

  Availability: base = A ** (1/n) over n serial steps, tightened for higher
  criticality (never loosened — the product constraint must hold) and capped
  at a ceiling (99.99) unless the base itself already exceeds the ceiling.

  Cold start (§4.3 "Cold-start embodiment"): when no history exists, or the
  observed sample is below the configured minimum, step 3 uses an equal split
  of the available budget, a criticality-weighted split (share ∝ factor), or
  a declared prior (asserted shares); the mode is recorded on the result so
  that coverage trends are not misread across the transition.

A segment (edge) term is not modeled separately in 0.1.0: each hop's latency
is counted inside the step that receives it (one of the two treatments the
paper discloses).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .config import TIERS

PERCENTILE_KEYS = ("latency_p95_ms", "latency_p99_ms")


@dataclass(frozen=True)
class StepInput:
    """One step as the allocator sees it (already resolved by the caller)."""
    id: str
    criticality: str = "P2"               # P0..P3 (per-step override already applied)
    nd_class: str | None = None           # ND0..ND3 or None (undeclared -> factor 1.0)
    parallel: bool = False                # member of the parallel group (fan-out siblings)
    asserted: Mapping[str, float] = field(default_factory=dict)   # asserted per-step SLO (wins over derived)


@dataclass(frozen=True)
class StepLatency:
    id: str
    group: str                 # serial | parallel
    hist: float | None         # historical contribution at the target percentile, or None
    share: float               # share of the available budget used at step 3 (serial) / 1.0 (parallel: own hist)
    base: float                # step 3
    criticality_factor: float  # step 4
    nd_factor: float           # step 4b
    safety_margin: float       # step 5
    pre_scale: float           # after 4, 4b, 5
    allocated: float           # after step 7 scaling
    asserted: float | None     # asserted value at this percentile, if any (takes precedence)

    @property
    def effective(self) -> float:
        """Asserted beats derived; the difference remains headroom (§4.3 worked example)."""
        return self.asserted if self.asserted is not None else self.allocated


@dataclass(frozen=True)
class LatencyAllocation:
    target: float
    percentile: str            # "p95" | "p99" | ...
    mode: str                  # history | cold-start:equal_split | cold-start:criticality_weighted | cold-start:declared_prior
    available: float
    parallel_reserved: float   # max historical contribution of the parallel group (step 2)
    scale: float               # step 7 factor (1.0 when the constraint already held)
    serial_sum: float          # sum of allocated serial budgets (after scaling)
    parallel_max: float
    headroom: float            # target - (serial_sum + parallel_max)
    steps: tuple[StepLatency, ...]
    sample_runs: int | None
    min_sample_runs: int

    def by_id(self) -> dict[str, StepLatency]:
        return {s.id: s for s in self.steps}


# ----------------------------------------------------------------------------
def criticality_factor(crit: str, cfg: Mapping[str, Any]) -> float:
    return float(cfg["decomposition"]["criticality_factor"][crit])


def nd_factor(nd_class: str | None, cfg: Mapping[str, Any]) -> float:
    key = nd_class if nd_class else "none"
    return float(cfg["decomposition"]["nd_factor"][key])


def _cold_start(history, sample_runs, min_sample_runs, serial_ids) -> bool:
    if history is None:
        return True
    if any(history.get(s) is None for s in serial_ids):
        return True
    if sample_runs is not None and sample_runs < min_sample_runs:
        return True
    return False


def allocate_latency(target: float, steps: Sequence[StepInput], cfg: Mapping[str, Any],
                     history: Mapping[str, float] | None = None, *, percentile: str = "p99",
                     sample_runs: int | None = None, declared_prior: Mapping[str, float] | None = None,
                     cold_start_strategy: str | None = None) -> LatencyAllocation:
    """Decompose one latency target (any percentile; `history` must be stated
    at the same percentile, in the same unit) across `steps`.

    history: step id -> historical contribution (ms) at that percentile.
    declared_prior: step id -> asserted share (fractions summing to ~1 over
      the serial steps) or absolute budget (if the values sum to > 1.0001 they
      are read as absolute ms and normalized). Used only in cold start.
    """
    if target <= 0:
        raise ValueError("target must be > 0")
    if not steps:
        raise ValueError("at least one step")
    dcfg = cfg["decomposition"]
    safety = float(dcfg["safety_margin"])
    min_runs = int(dcfg["cold_start"]["min_sample_runs"])
    strategy = cold_start_strategy or dcfg["cold_start"]["strategy"]
    serial = [s for s in steps if not s.parallel]
    parallel = [s for s in steps if s.parallel]
    serial_ids = [s.id for s in serial]
    cold = _cold_start(history, sample_runs, min_runs, serial_ids + [p.id for p in parallel])
    hist = dict(history or {})

    # --- steps 1–3: base contributions -------------------------------------
    if not cold:
        mode = "history"
        parallel_reserved = max((float(hist[p.id]) for p in parallel), default=0.0)
        available = max(target - parallel_reserved, 0.0)
        total_hist = sum(float(hist[s.id]) for s in serial)
        shares = {s.id: (float(hist[s.id]) / total_hist if total_hist > 0 else 1.0 / max(len(serial), 1)) for s in serial}
        base = {s.id: available * shares[s.id] for s in serial}
        for p in parallel:
            base[p.id] = float(hist[p.id])
    else:
        # The parallel group's historical contribution is unknown: it takes one
        # slot alongside the serial steps so that sum(serial) + max(parallel)
        # fills the target exactly before factors.
        slots = len(serial) + (1 if parallel else 0)
        parallel_reserved = target / slots if parallel else 0.0
        available = target - parallel_reserved
        if declared_prior and all(declared_prior.get(s.id) is not None for s in serial):
            mode = "cold-start:declared_prior"
            raw = {s.id: float(declared_prior[s.id]) for s in serial}
            tot = sum(raw.values())
            shares = {k: (v / tot if tot > 0 else 1.0 / len(serial)) for k, v in raw.items()}
        elif strategy == "criticality_weighted":
            mode = "cold-start:criticality_weighted"
            f = {s.id: criticality_factor(s.criticality, cfg) for s in serial}
            tot = sum(f.values())
            shares = {k: v / tot for k, v in f.items()}
        else:
            mode = "cold-start:equal_split"
            shares = {s.id: 1.0 / len(serial) for s in serial} if serial else {}
        base = {s.id: available * shares[s.id] for s in serial}
        for p in parallel:
            base[p.id] = parallel_reserved

    # --- steps 4, 4b, 5 --------------------------------------------------------
    pre = {}
    rows = []
    for s in steps:
        cf, nf = criticality_factor(s.criticality, cfg), nd_factor(s.nd_class, cfg)
        pre[s.id] = base[s.id] * cf * nf * safety
        rows.append((s, cf, nf))

    # --- step 7: proportional scaling -----------------------------------------
    serial_sum = sum(pre[s.id] for s in serial)
    parallel_max = max((pre[p.id] for p in parallel), default=0.0)
    total = serial_sum + parallel_max
    scale = target / total if total > target else 1.0
    alloc = {k: v * scale for k, v in pre.items()}
    serial_sum_scaled = sum(alloc[s.id] for s in serial)
    parallel_max_scaled = max((alloc[p.id] for p in parallel), default=0.0)

    key = f"latency_{percentile}_ms"
    out = []
    for s, cf, nf in rows:
        asserted = s.asserted.get(key) if s.asserted else None
        out.append(StepLatency(
            id=s.id, group="parallel" if s.parallel else "serial",
            hist=(float(hist[s.id]) if hist.get(s.id) is not None else None),
            share=(shares.get(s.id, 1.0) if not s.parallel else 1.0),
            base=base[s.id], criticality_factor=cf, nd_factor=nf, safety_margin=safety,
            pre_scale=pre[s.id], allocated=alloc[s.id],
            asserted=(float(asserted) if asserted is not None else None)))
    return LatencyAllocation(
        target=float(target), percentile=percentile, mode=mode, available=available,
        parallel_reserved=parallel_reserved, scale=scale, serial_sum=serial_sum_scaled,
        parallel_max=parallel_max_scaled, headroom=target - (serial_sum_scaled + parallel_max_scaled),
        steps=tuple(out), sample_runs=sample_runs, min_sample_runs=min_runs)


def other_percentile(value: float, from_p: str, to_p: str, cfg: Mapping[str, Any]) -> float:
    """Step 8: p95 ~= ratio x p99 and the inverse. Only p95 <-> p99 in 0.1.0."""
    r = float(cfg["decomposition"]["p95_from_p99"])
    if from_p == to_p:
        return value
    if (from_p, to_p) == ("p99", "p95"):
        return value * r
    if (from_p, to_p) == ("p95", "p99"):
        return value / r
    raise ValueError(f"no approximation from {from_p} to {to_p}")


def allocate_error_budget(error_budget_percent: float, steps: Sequence[StepInput], cfg: Mapping[str, Any]) -> dict[str, float]:
    """Step 6: budget x error_factor(crit_i) / n over all steps (percent)."""
    if error_budget_percent < 0:
        raise ValueError("error budget must be >= 0")
    n = len(steps)
    if n == 0:
        return {}
    ef = cfg["decomposition"]["error_factor"]
    return {s.id: error_budget_percent * float(ef[s.criticality]) / n for s in steps}


def allocate_availability(target_percent: float, steps: Sequence[StepInput], cfg: Mapping[str, Any]) -> dict[str, float]:
    """Availability over serial steps: base = A^(1/n); higher criticality
    tightens (allowed unavailability x factor, factor < 1 only — a factor > 1
    is clamped to 1.0 so the product constraint still holds); capped at the
    ceiling unless the base is already above it. Parallel steps take the base."""
    if not 0 < target_percent <= 100:
        raise ValueError("availability target must be in (0, 100]")
    serial = [s for s in steps if not s.parallel] or list(steps)
    n = len(serial)
    a = target_percent / 100.0
    base = a ** (1.0 / n) * 100.0
    ceiling = float(cfg["decomposition"]["availability_ceiling"])
    out = {}
    for s in steps:
        f = min(1.0, criticality_factor(s.criticality, cfg))
        tightened = 100.0 - (100.0 - base) * f
        out[s.id] = max(base, min(ceiling, tightened))
    return out


# ----------------------------------------------------------------------------
# Convenience over a flow descriptor (flow.spec/v0.2): the synchronous frontier
# and the asynchronous tail, each decomposed from the flow-level SLO that
# covers it (spec.slos.latency_p95_ms: trigger -> sync frontier;
# spec.slos.async_completion_p99_s: trigger -> last step).
def _ordered_steps(flow: Mapping[str, Any]) -> list[dict]:
    return [s for s in (flow.get("spec") or {}).get("steps") or [] if isinstance(s, dict)]


def step_inputs(flow: Mapping[str, Any], cfg: Mapping[str, Any], warnings: list[str] | None = None) -> list[StepInput]:
    from .tiering import normalize_criticality, step_criticality
    flow_crit = normalize_criticality((flow.get("metadata") or {}).get("criticality"), warnings, "metadata") or "P2"
    steps = _ordered_steps(flow)
    # parallel group: successors of a fanout step (siblings run concurrently)
    parallel: set[str] = set()
    for s in steps:
        if s.get("kind") == "fanout":
            parallel.update(s.get("next") or [])
    out = []
    for s in steps:
        out.append(StepInput(id=s["id"], criticality=step_criticality(s, flow_crit, warnings),
                             nd_class=s.get("nd_class"), parallel=s["id"] in parallel,
                             asserted=dict(s.get("slo") or {})))
    return out


def sync_frontier(flow: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """(synchronous step ids, asynchronous step ids) in document order: the
    frontier ends at the first `async` step; everything from it on is the
    asynchronous tail (FTC §4.1: the synchronous frontier is distinguished
    from asynchronous completion)."""
    sync, asyn = [], []
    for s in _ordered_steps(flow):
        if asyn or s.get("kind") == "async":
            asyn.append(s["id"])
        else:
            sync.append(s["id"])
    return sync, asyn


def decompose_flow(flow: Mapping[str, Any], cfg: Mapping[str, Any], history: Mapping[str, Mapping[str, float]] | None = None,
                   sample_runs: int | None = None, warnings: list[str] | None = None) -> dict:
    """Derived per-step SLOs for a descriptor. `history` is
    {"p95": {step: ms}, "p99": {step: ms}} at the percentiles observed.
    Returns a JSON-ready dict (also the report's "decomposition" block)."""
    inputs = {s.id: s for s in step_inputs(flow, cfg, warnings)}
    slos = (flow.get("spec") or {}).get("slos") or {}
    sync_ids, async_ids = sync_frontier(flow)
    result: dict[str, Any] = {"sync_frontier": sync_ids, "async_tail": async_ids, "latency": {}, "steps": {}}
    history = history or {}
    per_step: dict[str, dict] = {sid: {} for sid in inputs}

    def record(alloc: LatencyAllocation, label: str):
        result["latency"][label] = {
            "target_ms": round(alloc.target, 3), "percentile": alloc.percentile, "mode": alloc.mode,
            "available_ms": round(alloc.available, 3), "parallel_reserved_ms": round(alloc.parallel_reserved, 3),
            "scale": round(alloc.scale, 6), "serial_sum_ms": round(alloc.serial_sum, 3),
            "parallel_max_ms": round(alloc.parallel_max, 3), "headroom_ms": round(alloc.headroom, 3),
            "sample_runs": alloc.sample_runs, "min_sample_runs": alloc.min_sample_runs,
        }
        for st in alloc.steps:
            key = f"latency_{alloc.percentile}_ms"
            other = "p95" if alloc.percentile == "p99" else "p99"
            per_step[st.id][key] = {
                "group": st.group, "hist_ms": (None if st.hist is None else round(st.hist, 3)),
                "share": round(st.share, 6), "base_ms": round(st.base, 3),
                "criticality_factor": st.criticality_factor, "nd_factor": st.nd_factor,
                "safety_margin": st.safety_margin, "derived_ms": round(st.allocated, 3),
                "asserted_ms": st.asserted, "effective_ms": round(st.effective, 3),
            }
            # step 8: the other percentile, unless asserted
            okey = f"latency_{other}_ms"
            if okey not in per_step[st.id]:
                asserted_other = inputs[st.id].asserted.get(okey)
                per_step[st.id][okey] = {
                    "approximated_from": key,
                    "derived_ms": round(other_percentile(st.allocated, alloc.percentile, other, cfg), 3),
                    "asserted_ms": asserted_other,
                    "effective_ms": round(float(asserted_other) if asserted_other is not None
                                          else other_percentile(st.allocated, alloc.percentile, other, cfg), 3),
                }

    if "latency_p95_ms" in slos and sync_ids:
        alloc = allocate_latency(float(slos["latency_p95_ms"]), [inputs[s] for s in sync_ids], cfg,
                                 history.get("p95"), percentile="p95", sample_runs=sample_runs)
        record(alloc, "sync_frontier_p95")
        # the frontier's p99 contribution, reserved before the async tail (§4.3 worked example)
        sync_p99 = sum(other_percentile(st.effective, "p95", "p99", cfg) for st in alloc.steps)
        if history.get("p99") and all(history["p99"].get(s) is not None for s in sync_ids) \
                and (sample_runs is None or sample_runs >= alloc.min_sample_runs):
            sync_p99 = sum(float(history["p99"][s]) for s in sync_ids)
    else:
        sync_p99 = 0.0

    if "async_completion_p99_s" in slos and async_ids:
        target_ms = float(slos["async_completion_p99_s"]) * 1000.0
        avail = max(target_ms - sync_p99, 1.0)
        alloc = allocate_latency(avail, [inputs[s] for s in async_ids], cfg,
                                 history.get("p99"), percentile="p99", sample_runs=sample_runs)
        record(alloc, "async_tail_p99")
        result["latency"]["async_tail_p99"]["sync_frontier_reserved_ms"] = round(sync_p99, 3)
        result["latency"]["async_tail_p99"]["flow_target_ms"] = target_ms

    if "availability" in slos:
        a = float(slos["availability"])
        eb = allocate_error_budget(100.0 - a, [inputs[s] for s in sync_ids] or list(inputs.values()), cfg)
        av = allocate_availability(a, [inputs[s] for s in sync_ids] or list(inputs.values()), cfg)
        result["availability"] = {"target_percent": a, "error_budget_percent": round(100.0 - a, 6),
                                  "base_per_step_percent": round((a / 100.0) ** (1.0 / max(len(sync_ids) or len(inputs), 1)) * 100.0, 6)}
        for sid in eb:
            asserted = inputs[sid].asserted.get("error_rate_percent")
            per_step[sid]["error_rate_percent"] = {
                "derived": round(eb[sid], 6), "asserted": asserted,
                "effective": round(float(asserted) if asserted is not None else eb[sid], 6)}
            asserted_av = inputs[sid].asserted.get("availability")
            per_step[sid]["availability"] = {
                "derived": round(av[sid], 6), "asserted": asserted_av,
                "effective": round(float(asserted_av) if asserted_av is not None else av[sid], 6)}
    for sid, inp in inputs.items():
        per_step[sid]["criticality"] = inp.criticality
        per_step[sid]["nd_class"] = inp.nd_class
        per_step[sid]["group"] = "parallel" if inp.parallel else "serial"
    result["steps"] = per_step
    return result
