"""FTC §4.8: window reading, the per-run authorized-plan reading (manifest input
per B6), off-plan steps, loop bounds per on_exceed, and parity between the
local rules and agent-dec's reading."""
import copy

import pytest
import yaml

from conftest import DEC_DIR, TRUST_BUNDLE
from flowtrace.adapters.base import SpanRow
from flowtrace.conformance import _reading, evaluate, plan_reading
from flowtrace.coverage import CertificateIndex, index_runs
from flowtrace.flows import Flow

LOOP_FLOW = yaml.safe_load("""
apiVersion: flow.spec/v0.2
kind: Flow
metadata: {id: reprice, name: "loop", version: 1.0.0, owner: {business: b, technical: t}, criticality: P1}
spec:
  trigger: {type: event}
  steps:
    - {id: s1, component: identity.session, op: authorize, next: [s2]}
    - {id: s2, component: payments.quote-engine, op: reprice, next: [s3]}
    - {id: s3, component: risk.limits-check, op: evaluate, kind: loop, bound: {max: 2, on_exceed: flag}, next: [s2, s4]}
    - {id: s4, component: docs.render, op: generate, kind: async, next: [s5]}
    - {id: s5, component: notify.customer, op: deliver, kind: async}
  telemetry: {required_signals: [trace]}
""")


def spans(trace, seq, flow_id="quote-issue", version="2.0.0"):
    out, prev = [], None
    for i, step in enumerate(seq):
        sid = f"{trace}-{i}"
        out.append(SpanRow(trace, sid, prev, step, "SERVER", i * 10, i * 10 + 5, "OK",
                           {"flow.id": flow_id, "flow.version": version, "flow.step": step}))
        prev = sid
    return out


def runs_of(adapter, flow):
    return index_runs([s for s in adapter.list_spans(flow.id, adapter.extent()) if s.attributes.get("flow.version") == flow.version])


def test_window_readings(canon_flow, adapters):
    index = CertificateIndex([DEC_DIR], TRUST_BUNDLE)
    full = evaluate(canon_flow, runs_of(adapters["full"], canon_flow), index)
    assert full["window"]["reading"] == "convergent" and full["summary"]["by_reading"]["convergent"] == 32
    cert_run = next(r for r in full["runs"] if r["trace_id"] == "b8e06f909fc7110707032a18b942e128")
    assert cert_run["source"] == "manifest:run.dec.json" and cert_run["realized"] == ["s1", "s2", "s3", "s4", "s5", "s6"]
    assert sum(1 for r in full["runs"] if r["source"] == "spans") == 31
    silent = evaluate(canon_flow, runs_of(adapters["s5-silent"], canon_flow), index)
    assert silent["window"]["reading"] == "absent" and silent["window"]["absent"] == ["s5"]
    assert silent["summary"]["by_reading"] == {"convergent": 1, "absent": 31, "divergent": 0, "failed-run": 0}
    assert silent["summary"]["non_convergent_runs"] == 0          # absent is a completeness failure, not off-plan
    empty = evaluate(canon_flow, {}, None)
    assert empty["window"]["reading"] == "absent" and empty["window"]["absent"] == canon_flow.step_ids


def test_off_plan_and_order(canon_flow):
    runs = index_runs(spans("t1", ["s1", "s2", "s3", "s4", "s9", "s5", "s6"]) + spans("t2", ["s1", "s3", "s2", "s4", "s5", "s6"]))
    r = evaluate(canon_flow, runs, None)
    assert r["window"]["reading"] == "divergent" and r["window"]["divergent"] == ["s9"]
    assert r["summary"]["off_plan_steps"] == {"s9": 1} and r["summary"]["non_convergent_runs"] == 2
    by = {x["trace_id"]: x for x in r["runs"]}
    assert by["t1"]["reading"] == "divergent" and by["t1"]["divergent"][0].startswith("off-plan: s9")
    assert by["t2"]["reading"] == "divergent" and any(d.startswith("order: s3 precedes s2") for d in by["t2"]["divergent"])


def test_loop_bound_per_on_exceed(canon_flow):
    flow = Flow(canon_flow.path, LOOP_FLOW, "0" * 64)
    within = [("s1", "s1"), ("s2", "s2"), ("s3", "s3"), ("s2", "s2"), ("s3", "s3"), ("s4", "s4"), ("s5", "s5")]
    assert plan_reading(flow.doc, within)["reading"] == "convergent"
    over = [("s1", "s1")] + [("s2", "s2"), ("s3", "s3")] * 3 + [("s4", "s4"), ("s5", "s5")]
    flagged = plan_reading(flow.doc, over)
    assert flagged["reading"] == "divergent" and flagged["divergent"] == ["loop-exceeded: s3 ran 3 times > bound.max 2 (on_exceed: flag)"]
    hard = copy.deepcopy(LOOP_FLOW)
    hard["spec"]["steps"][2]["bound"]["on_exceed"] = "fail"
    failed = plan_reading(hard, over)
    assert failed["reading"] == "failed-run" and failed["failed"][0].startswith("loop-exceeded")
    # through evaluate(): the hard cap counts as non-convergent
    r = evaluate(Flow(canon_flow.path, hard, "0" * 64), index_runs(spans("t", [s for s, _ in over], "reprice", "1.0.0")), None)
    assert r["summary"]["by_reading"]["failed-run"] == 1 and r["summary"]["non_convergent_runs"] == 1
    # a repeat without a loop step is divergent
    rep = plan_reading(canon_flow.doc, [("s1", "s1"), ("s2", "s2"), ("s2", "s2"), ("s3", "s3"), ("s4", "s4"), ("s5", "s5"), ("s6", "s6")])
    assert rep["reading"] == "divergent" and rep["divergent"][0].startswith("repeat: s2")


def test_unbound_manifest_entries_and_absent(canon_flow):
    r = plan_reading(canon_flow.doc, [("s1", "s1"), ("x", None), ("s2", "s2")])
    assert r["reading"] == "divergent" and "unbound" in r["divergent"][0]
    a = plan_reading(canon_flow.doc, [("s1", "s1"), ("s2", "s2")])
    assert a["reading"] == "absent" and a["absent"] == ["s3", "s4", "s5", "s6"]


CASES = [
    [("s1", "s1"), ("s2", "s2"), ("s3", "s3"), ("s4", "s4"), ("s5", "s5"), ("s6", "s6")],
    [("s1", "s1"), ("s3", "s3"), ("s2", "s2"), ("s4", "s4"), ("s5", "s5"), ("s6", "s6")],
    [("s1", "s1"), ("s2", "s2"), ("s9", "s9"), ("s3", "s3")],
    [("s1", "s1"), ("x", None)],
    [],
]


@pytest.mark.parametrize("realized", CASES)
def test_local_rules_agree_with_agent_dec(canon_flow, realized):
    vd = pytest.importorskip("agent_dec.verify_dec")
    assert _reading(canon_flow.doc, realized) == vd.conformance_reading(canon_flow.doc, realized)
    loop_over = [("s1", "s1")] + [("s2", "s2"), ("s3", "s3")] * 3 + [("s4", "s4"), ("s5", "s5")]
    assert _reading(LOOP_FLOW, loop_over) == vd.conformance_reading(LOOP_FLOW, loop_over)


def test_run_certificate_binding_notes(canon_flow):
    """A run that references the signed run certificate but is not the run it
    certifies keeps its spans as the realized DAG and is noted."""
    index = CertificateIndex([DEC_DIR], TRUST_BUNDLE)
    run_digest = next(iter(index.runs))
    sp = spans("ffff" * 8, ["s1", "s2", "s3", "s4", "s5", "s6"])
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK",
                    dict(sp[0].attributes, **{"dec.run_cert_digest": run_digest}))
    r = evaluate(canon_flow, index_runs(sp), index)
    assert r["runs"][0]["source"] == "spans" and r["summary"]["notes"] and "binds run_id" in r["summary"]["notes"][0]


def test_run_certificate_must_verify_and_be_unambiguous(canon_flow, tmp_path):
    """A tampered run certificate is not the realized DAG; two certificates
    claiming the same run id with no digest on the trigger span are ambiguous."""
    import json
    d = tmp_path / "certs"
    d.mkdir()
    for p in DEC_DIR.glob("*.dec.json"):
        (d / p.name).write_bytes(p.read_bytes())
    run = json.loads((DEC_DIR / "run.dec.json").read_text())
    run["manifest"]["steps"] = run["manifest"]["steps"][:5]          # drop s6: a lie, and the signature no longer matches
    (d / "run-tampered.dec.json").write_text(json.dumps(run))
    index = CertificateIndex([d], TRUST_BUNDLE)
    assert len(index.runs_by_run_id["b8e06f909fc7110707032a18b942e128"]) == 2
    sp = spans("b8e06f909fc7110707032a18b942e128", ["s1", "s2", "s3", "s4", "s5", "s6"])
    r = evaluate(canon_flow, index_runs(sp), index)
    assert r["runs"][0]["source"] == "spans" and "2 distinct run certificates" in r["summary"]["notes"][0]
    # name the tampered one explicitly: it does not verify, so spans remain the realized DAG
    tampered_digest = next(dg for dg, (p, c) in index.runs.items() if p.name == "run-tampered.dec.json")
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": tampered_digest}))
    r = evaluate(canon_flow, index_runs(sp), index)
    assert r["runs"][0]["source"] == "spans" and "does not verify" in r["summary"]["notes"][0]
    # name the genuine one: the manifest is the realized DAG
    genuine = next(dg for dg, (p, c) in index.runs.items() if p.name == "run.dec.json")
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": genuine}))
    r = evaluate(canon_flow, index_runs(sp), index)
    assert r["runs"][0]["source"] == "manifest:run.dec.json" and r["runs"][0]["reading"] == "convergent"
