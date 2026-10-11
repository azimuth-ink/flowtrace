"""FTC §4.3 decomposition: the paper's worked example reproduced, and the
properties the prompt names, checked with hypothesis over random flows."""
import math

import pytest
from hypothesis import given, settings, strategies as st

from flowtrace.decompose import (StepInput, allocate_availability, allocate_error_budget, allocate_latency,
                                 decompose_flow, other_percentile, sync_frontier)

TIERS = ("P0", "P1", "P2", "P3")
ND = (None, "ND0", "ND1", "ND2", "ND3")
EPS = 1e-6


# ----------------------------------------------------------------- worked example (§4.3)
def test_paper_worked_example_sync_frontier(cfg):
    steps = [StepInput("s1", "P0"), StepInput("s2", "P0"), StepInput("s3", "P0"),
             StepInput("s4", "P0", "ND0", asserted={"latency_p99_ms": 120})]
    a = allocate_latency(1800, steps, cfg, {"s1": 90, "s2": 180, "s3": 1170, "s4": 360}, percentile="p95", sample_runs=10_000)
    got = {s.id: round(s.allocated, 1) for s in a.steps}
    assert got == {"s1": 64.8, "s2": 129.6, "s3": 842.4, "s4": 233.3}
    assert a.mode == "history" and a.scale == 1.0
    assert round(a.serial_sum) == 1270 and round(a.headroom) == 530
    assert round(other_percentile(a.by_id()["s4"].allocated, "p95", "p99", cfg)) == 333


def test_paper_worked_example_async_tail_and_error_budget(cfg):
    a = allocate_latency(118_000, [StepInput("s5", "P0", "ND2"), StepInput("s6", "P0")], cfg,
                         {"s5": 94_400, "s6": 23_600}, percentile="p99", sample_runs=10_000)
    assert [round(s.allocated / 1000, 1) for s in a.steps] == [74.8, 17.0]
    steps = [StepInput(f"s{i}", "P0") for i in range(1, 5)]
    assert allocate_error_budget(0.1, steps, cfg) == {s.id: pytest.approx(0.0125) for s in steps}
    av = allocate_availability(99.9, steps, cfg)
    assert all(abs(v - 99.98) < 0.001 for v in av.values())        # 99.975 base, tightened toward the 99.99 ceiling


def test_decompose_flow_over_the_canonical_descriptor(cfg, canon_flow):
    d = decompose_flow(canon_flow.doc, cfg)
    assert d["sync_frontier"] == ["s1", "s2", "s3", "s4"] and d["async_tail"] == ["s5", "s6"]
    assert d["latency"]["sync_frontier_p95"]["mode"] == "cold-start:equal_split"
    s4 = d["steps"]["s4"]
    assert s4["latency_p99_ms"]["asserted_ms"] == 120 and s4["latency_p99_ms"]["effective_ms"] == 120
    assert s4["error_rate_percent"]["asserted"] == 0.01 and s4["error_rate_percent"]["effective"] == 0.01
    assert s4["latency_p95_ms"]["nd_factor"] == 0.9 and d["steps"]["s5"]["latency_p99_ms"]["nd_factor"] == 1.1
    assert sync_frontier({"spec": {"steps": [{"id": "a"}, {"id": "b", "kind": "async"}, {"id": "c", "kind": "sync"}]}}) == (["a"], ["b", "c"])


# ----------------------------------------------------------------- strategies
@st.composite
def flows(draw, min_steps=1, max_steps=8):
    n = draw(st.integers(min_steps, max_steps))
    steps, hist = [], {}
    for i in range(n):
        sid = f"s{i}"
        steps.append(StepInput(sid, draw(st.sampled_from(TIERS)), draw(st.sampled_from(ND)),
                               parallel=draw(st.booleans()) if n > 1 else False))
        hist[sid] = draw(st.floats(1.0, 5000.0, allow_nan=False, allow_infinity=False))
    if all(s.parallel for s in steps):
        steps[0] = StepInput(steps[0].id, steps[0].criticality, steps[0].nd_class, parallel=False)
    target = draw(st.floats(10.0, 20000.0, allow_nan=False, allow_infinity=False))
    with_history = draw(st.booleans())
    return target, steps, (hist if with_history else None)


def _total(alloc):
    serial = sum(s.allocated for s in alloc.steps if s.group == "serial")
    par = max((s.allocated for s in alloc.steps if s.group == "parallel"), default=0.0)
    return serial + par


# ----------------------------------------------------------------- properties
@settings(max_examples=300, deadline=None)
@given(flows())
def test_allocations_sum_within_the_flow_budget_after_scaling(cfg, fl):
    target, steps, hist = fl
    a = allocate_latency(target, steps, cfg, hist, sample_runs=10_000)
    assert _total(a) <= target * (1 + 1e-9) + EPS
    assert all(s.allocated >= 0 for s in a.steps)
    # a serial step gets a positive budget unless the parallel group's history alone consumes the target (step 2)
    if a.available > 0:
        assert all(s.allocated > 0 for s in a.steps)
    assert 0 < a.scale <= 1.0
    assert a.headroom >= -EPS


@settings(max_examples=300, deadline=None)
@given(flows(min_steps=2), st.integers(0, 7))
def test_higher_criticality_gets_a_tighter_budget(cfg, fl, which):
    target, steps, hist = fl
    i = which % len(steps)
    for nd in (steps[i].nd_class,):
        low = [StepInput(s.id, "P3" if j == i else s.criticality, s.nd_class, s.parallel) for j, s in enumerate(steps)]
        high = [StepInput(s.id, "P0" if j == i else s.criticality, s.nd_class, s.parallel) for j, s in enumerate(steps)]
        a_low = allocate_latency(target, low, cfg, hist, sample_runs=10_000).by_id()[steps[i].id]
        a_high = allocate_latency(target, high, cfg, hist, sample_runs=10_000).by_id()[steps[i].id]
        assert a_high.allocated <= a_low.allocated + EPS
        assert a_high.pre_scale <= a_low.pre_scale + EPS


@settings(max_examples=300, deadline=None)
@given(flows(min_steps=2), st.integers(0, 7))
def test_lower_nd_class_gets_a_tighter_budget(cfg, fl, which):
    target, steps, hist = fl
    i = which % len(steps)
    det = [StepInput(s.id, s.criticality, "ND0" if j == i else s.nd_class, s.parallel) for j, s in enumerate(steps)]
    gen = [StepInput(s.id, s.criticality, "ND3" if j == i else s.nd_class, s.parallel) for j, s in enumerate(steps)]
    a_det = allocate_latency(target, det, cfg, hist, sample_runs=10_000).by_id()[steps[i].id]
    a_gen = allocate_latency(target, gen, cfg, hist, sample_runs=10_000).by_id()[steps[i].id]
    assert a_det.allocated <= a_gen.allocated + EPS
    assert a_det.nd_factor == 0.9 and a_gen.nd_factor == 1.25


@settings(max_examples=200, deadline=None)
@given(st.integers(1, 8), st.floats(10.0, 20000.0, allow_nan=False, allow_infinity=False), st.sampled_from(TIERS))
def test_cold_start_equals_equal_split_when_no_history(cfg, n, target, crit):
    steps = [StepInput(f"s{i}", crit) for i in range(n)]
    a = allocate_latency(target, steps, cfg, None)
    assert a.mode == "cold-start:equal_split"
    bases = {round(s.base, 9) for s in a.steps}
    assert len(bases) == 1 and math.isclose(next(iter(bases)), target / n, rel_tol=1e-9)
    allocs = {round(s.allocated, 9) for s in a.steps}
    assert len(allocs) == 1                     # uniform criticality, no classes -> equal after factors too
    # below the minimum sample the history is ignored and cold start applies
    b = allocate_latency(target, steps, cfg, {s.id: 1.0 + i for i, s in enumerate(steps)}, sample_runs=1)
    assert b.mode == "cold-start:equal_split" and {round(s.base, 9) for s in b.steps} == bases


def test_cold_start_variants(cfg):
    steps = [StepInput("a", "P0"), StepInput("b", "P3")]
    w = allocate_latency(1000, steps, cfg, None, cold_start_strategy="criticality_weighted")
    assert w.mode == "cold-start:criticality_weighted"
    assert w.by_id()["a"].share == pytest.approx(0.8 / 2.0) and w.by_id()["b"].share == pytest.approx(1.2 / 2.0)
    p = allocate_latency(1000, steps, cfg, None, declared_prior={"a": 0.25, "b": 0.75})
    assert p.mode == "cold-start:declared_prior" and p.by_id()["a"].base == pytest.approx(250)


@settings(max_examples=200, deadline=None)
@given(st.integers(1, 10), st.floats(50.0, 99.999, allow_nan=False, allow_infinity=False), st.lists(st.sampled_from(TIERS), min_size=1, max_size=10))
def test_availability_nth_root_rule(cfg, n, target, crits):
    steps = [StepInput(f"s{i}", crits[i % len(crits)]) for i in range(n)]
    av = allocate_availability(target, steps, cfg)
    base = (target / 100.0) ** (1.0 / n) * 100.0
    product = math.prod(v / 100.0 for v in av.values()) * 100.0
    assert product >= target - 1e-9                       # serial composition multiplies: the flow target holds
    for s in steps:
        assert av[s.id] >= base - 1e-9
        assert av[s.id] <= max(base, cfg["decomposition"]["availability_ceiling"]) + 1e-9
        if s.criticality == "P2":
            assert math.isclose(av[s.id], base, rel_tol=1e-12)   # factor 1.0: exactly the n-th root
    uniform = allocate_availability(target, [StepInput(f"s{i}", "P2") for i in range(n)], cfg)
    assert all(math.isclose(v, base, rel_tol=1e-12) for v in uniform.values())


@settings(max_examples=100, deadline=None)
@given(st.lists(st.sampled_from(TIERS), min_size=1, max_size=10), st.floats(0.0, 10.0, allow_nan=False))
def test_error_budget_allocation(cfg, crits, budget):
    steps = [StepInput(f"s{i}", c) for i, c in enumerate(crits)]
    eb = allocate_error_budget(budget, steps, cfg)
    ef = cfg["decomposition"]["error_factor"]
    assert sum(eb.values()) == pytest.approx(budget * sum(ef[c] for c in crits) / len(crits))


def test_input_validation(cfg):
    with pytest.raises(ValueError):
        allocate_latency(0, [StepInput("a")], cfg)
    with pytest.raises(ValueError):
        allocate_latency(10, [], cfg)
    with pytest.raises(ValueError):
        allocate_availability(0, [StepInput("a")], cfg)
    with pytest.raises(ValueError):
        other_percentile(1.0, "p50", "p99", cfg)
