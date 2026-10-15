"""D14 — gate authority (binding B12): the companion validator's R14 admits
only ND0/ND1 steps as sources of an on_fail edge to block; the engine does not
re-check it, and the conformance view carries agent-dec's gate-authority note
as a divergence reason when a run's block was reached from a step that is not
(FTC §4.5; spec §6.7, §7.4)."""
import copy

import pytest

from flowtrace.conformance import _reading, evaluate, plan_reading
from flowtrace.coverage import index_runs
from flowtrace.flows import Flow
from test_d11_degradation import PRIMARY, entries, spans


def nd2_gate(degrading_flow, klass):
    """s4's block edge on a step of another class (a flow R14 would reject; a registry may still hold it)."""
    doc = copy.deepcopy(degrading_flow.doc)
    s4 = doc["spec"]["steps"][3]
    s4.pop("method", None)
    if klass is None:
        s4.pop("nd_class", None)
    else:
        s4["nd_class"] = klass
    return Flow(degrading_flow.path, doc, "0" * 64)


def test_block_from_the_nd0_gate_carries_no_reason(degrading_flow):
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:4]), outcome="block")
    assert r["reading"] == "convergent" and not any(d.startswith("gate-authority") for d in r["divergent"])
    assert plan_reading(nd2_gate(degrading_flow, "ND1").doc, entries(PRIMARY[:4]), outcome="block")["reading"] == "convergent"


@pytest.mark.parametrize("klass", ["ND2", "ND3", None])
def test_block_from_a_generative_or_undeclared_step_is_a_divergence_reason(degrading_flow, klass):
    f = nd2_gate(degrading_flow, klass)
    r = plan_reading(f.doc, entries(PRIMARY[:4]), outcome="block")
    assert r["reading"] == "divergent" and r["degraded"] == ["s4 -> outcome block (on_fail)"]
    assert r["divergent"] == [f"gate-authority: block reached from s4, whose declared class is {klass or 'undeclared'} "
                              "(binding B12: only an ND0/ND1 step may be the source of an edge whose target is block)"]
    # review / clarify from such a step are not gate-authority matters
    doc = copy.deepcopy(f.doc)
    doc["spec"]["steps"][3]["on_fail"] = {"outcome": "review"}
    assert plan_reading(doc, entries(PRIMARY[:4]), outcome="review")["reading"] == "convergent"


@pytest.mark.parametrize("klass", ["ND0", "ND2", None])
def test_local_reading_agrees_with_agent_dec_on_gate_authority(degrading_flow, klass):
    vd = pytest.importorskip("agent_dec.verify_dec")
    doc = nd2_gate(degrading_flow, klass).doc
    for case in (dict(realized=entries(PRIMARY[:4]), outcome="block"), dict(realized=entries(PRIMARY[:3]), outcome="review")):
        assert _reading(doc, **case) == vd.conformance_reading(doc, **case)


def test_gate_authority_through_the_engine_from_spans(degrading_flow):
    """From spans a run ending at the block gate is read as having taken it;
    on an ND2 gate the note makes the run divergent (counted under
    non-convergent-runs; no finding code of its own — the engine does not
    re-check R14)."""
    from flowtrace.gate import _reading_findings
    f = nd2_gate(degrading_flow, "ND2")
    r = evaluate(f, index_runs(spans("t1", PRIMARY[:4])), None)
    run = r["runs"][0]
    assert run["reading"] == "divergent" and run["outcome"] == "unknown" and run["vetoed"] is True
    assert run["divergent"][0].startswith("gate-authority: block reached from s4, whose declared class is ND2")
    assert r["summary"]["non_convergent_runs"] == 1 and _reading_findings(r, "fail") == []
    assert evaluate(degrading_flow, index_runs(spans("t1", PRIMARY[:4])), None)["runs"][0]["reading"] == "convergent"
