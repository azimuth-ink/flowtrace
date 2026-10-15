"""D11 — declared outcomes, degradation paths (on_fail / latch), termination and
the two-sided indicators (FTC §4.5, §4.8; spec §6.7, §7.4)."""
import copy

import pytest
import yaml

from conftest import ALERTS, CONFIG, DEGRADING_FLOW, FLOWS
from flowtrace.adapters.base import SpanRow
from flowtrace.conformance import _reading, evaluate, evaluate_slis, plan_reading, sli_band
from flowtrace.coverage import evaluate_detectability, index_runs, load_alerts
from flowtrace.flows import DEFAULT_OUTCOMES, Flow, degradation_edges, degradation_target


def spans(trace, seq, version="2.1.0"):
    out, prev = [], None
    for i, step in enumerate(seq):
        sid = f"{trace}-{i}"
        out.append(SpanRow(trace, sid, prev, step, "SERVER", i * 10, i * 10 + 5, "OK",
                           {"flow.id": "quote-issue", "flow.version": version, "flow.step": step}))
        prev = sid
    return out


def entries(seq):
    """[(step, via?)] -> reading entries; a plain step is via primary."""
    out = []
    for e in seq:
        sid, via = (e, "primary") if isinstance(e, str) else e
        out.append({"step_id": sid, "flow_step": sid, "via": via})
    return out


# ----------------------------------------------------------------- descriptor helpers
def test_outcomes_default_and_declared(canon_flow, degrading_flow):
    assert canon_flow.outcomes == list(DEFAULT_OUTCOMES) and canon_flow.declares_degradation is False
    assert degrading_flow.outcomes == ["allow", "block", "clarify", "review", "error"] and degrading_flow.declares_degradation
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["outcomes"] = ["ok", "stop"]
    assert Flow(degrading_flow.path, doc, "0" * 64).outcomes == ["ok", "stop"]
    doc["spec"].pop("outcomes")
    f = Flow(degrading_flow.path, doc, "0" * 64)
    assert f.outcomes == list(DEFAULT_OUTCOMES) and f.declares_degradation      # on_fail edges alone qualify
    assert degrading_flow.cancel_propagation_s == 30.0 and degrading_flow.max_decision_age_s == 300.0
    assert canon_flow.cancel_propagation_s is None and canon_flow.max_decision_age_s is None
    assert degrading_flow.next_of("s5") == ["s6"] and degrading_flow.next_of("s6") == []


def test_degradation_edges_and_targets(degrading_flow):
    assert degradation_target({"to": "s6"}) == ("to", "s6") and degradation_target({"outcome": "review"}) == ("outcome", "review")
    assert degradation_target("fail") == ("outcome", "error") and degradation_target("flag") == (None, None)
    assert degradation_target(None) == (None, None)
    assert degradation_edges(degrading_flow.step("s3")) == [("on_fail", "outcome", "review", False)]
    assert degradation_edges(degrading_flow.step("s5")) == [("on_fail", "to", "s6", True)]
    # the {to | outcome} forms of bound.on_exceed and attempts.on_exceed are degradation edges too (B9 as read here)
    assert degradation_edges(degrading_flow.step("s6")) == [("attempts.on_exceed", "outcome", "error", False)]
    loop = {"id": "L", "kind": "loop", "bound": {"max": 2, "on_exceed": "fail"}}
    assert degradation_edges(loop) == [("bound.on_exceed", "outcome", "error", False)]
    loop["bound"]["on_exceed"] = "flag"
    assert degradation_edges(loop) == []
    assert degradation_edges({"id": "x"}) == []


# ----------------------------------------------------------------- the reading (manifest input)
PRIMARY = ["s1", "s2", "s3", "s4", "s5", "s6"]


def test_declared_degradation_is_convergent(degrading_flow):
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:5] + [("s6", "on_fail")]), outcome="allow", termination="completed")
    assert r["reading"] == "convergent" and r["degraded"] == ["s5 -> s6 (on_fail, latched)"] and r["absent"] == []
    # s4's block gate: the run ends at s4 with outcome block; s5 and s6 are not absent
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:4]), outcome="block", termination="completed")
    assert r["reading"] == "convergent" and r["degraded"] == ["s4 -> outcome block (on_fail)"] and r["absent"] == []
    # s3's review path
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:3]), outcome="review")
    assert r["reading"] == "convergent" and r["degraded"] == ["s3 -> outcome review (on_fail)"]
    # the primary path with a recorded outcome: nothing degraded
    r = plan_reading(degrading_flow.doc, entries(PRIMARY), outcome="allow", termination="completed")
    assert r["reading"] == "convergent" and r["degraded"] == [] and r["outcome"] == "allow" and r["termination"] == "completed"


def test_divergent_readings_latch_outcome_edge(degrading_flow):
    # latched re-entry: after s5 -> s6 (latched), s5 runs again
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:5] + [("s6", "on_fail"), "s5", "s6"]), outcome="allow")
    assert r["reading"] == "divergent" and any(d.startswith("latched re-entry: s5") for d in r["divergent"])
    # an outcome the flow does not declare
    r = plan_reading(degrading_flow.doc, entries(PRIMARY), outcome="escalate")
    assert r["reading"] == "divergent" and r["divergent"] == ["outcome: escalate is not among the declared outcomes (allow, block, clarify, review, error)"]
    # via on_fail on an edge the flow does not declare (s4 -> s6 is neither next nor on_fail.to)
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:4] + [("s6", "on_fail")]), outcome="allow")
    assert r["reading"] == "divergent" and "no on_fail or on_exceed edge s4 -> s6" in r["divergent"][0]
    # via on_fail with no preceding step
    r = plan_reading(degrading_flow.doc, entries([("s1", "on_fail")]), outcome="allow")
    assert r["reading"] == "divergent" and "no preceding step" in r["divergent"][0]


def test_termination_cancelled_or_expired_leaves_unrun_steps_not_absent(degrading_flow):
    for term in ("cancelled", "expired"):
        r = plan_reading(degrading_flow.doc, entries(PRIMARY[:3]), termination=term)
        assert r["reading"] == "convergent" and r["absent"] == [] and r["notes"] == [f"termination {term} recorded: steps not run are not absent"]
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:3]), termination="completed")
    assert r["reading"] == "absent" and r["absent"] == ["s4", "s5", "s6"]
    r = plan_reading(degrading_flow.doc, entries(PRIMARY[:3]))
    assert r["reading"] == "absent"


def test_loop_on_exceed_object_form(degrading_flow):
    doc = yaml.safe_load("""
apiVersion: flow.spec/v0.2
kind: Flow
metadata: {id: reprice, name: l, version: 1.0.0, owner: {business: b, technical: t}, criticality: P1}
spec:
  trigger: {type: event}
  steps:
    - {id: s1, component: a.b, op: o, next: [s2]}
    - {id: s2, component: a.c, op: o, next: [s3]}
    - {id: s3, component: a.d, op: o, kind: loop, bound: {max: 2, on_exceed: {outcome: error}}, next: [s2, s4]}
    - {id: s4, component: a.e, op: o}
""")
    over = entries(["s1"] + ["s2", "s3"] * 3)
    r = plan_reading(doc, over, outcome="error")
    assert r["reading"] == "convergent" and r["degraded"] == ["s3 -> outcome error (bound.on_exceed after 3 iterations)"]
    r = plan_reading(doc, over, outcome="allow")
    assert r["reading"] == "divergent" and "did not end in the declared on_exceed outcome error" in r["divergent"][0]


READINGS = [
    dict(realized=entries(PRIMARY), outcome="allow", termination="completed"),
    dict(realized=entries(PRIMARY[:5] + [("s6", "on_fail")]), outcome="allow", termination="completed"),
    dict(realized=entries(PRIMARY[:4]), outcome="block", termination="completed"),
    dict(realized=entries(PRIMARY[:3]), outcome="review"),
    dict(realized=entries(PRIMARY[:5] + [("s6", "on_fail"), "s5", "s6"]), outcome="allow"),
    dict(realized=entries(PRIMARY), outcome="escalate"),
    dict(realized=entries(PRIMARY[:4] + [("s6", "on_fail")]), outcome="allow"),
    dict(realized=entries(PRIMARY[:3]), termination="cancelled"),
    dict(realized=entries(PRIMARY[:3]), termination="expired"),
    dict(realized=entries(PRIMARY[:2]), outcome="allow", children_ok=False),
    dict(realized=[("s1", "s1"), ("x", None)]),
]


@pytest.mark.parametrize("case", READINGS)
def test_local_reading_agrees_with_agent_dec_on_degradation(degrading_flow, case):
    vd = pytest.importorskip("agent_dec.verify_dec")
    assert _reading(degrading_flow.doc, **case) == vd.conformance_reading(degrading_flow.doc, **case)


# ----------------------------------------------------------------- the reading from spans
def test_span_reading_records_via_and_shared_target(degrading_flow):
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"][4]["next"] = []                # s5's only edge to s6 is the on_fail edge: spans can tell
    doc["spec"]["steps"][4]["on_fail"] = {"to": "s6"}
    f = Flow(degrading_flow.path, doc, "0" * 64)
    r = evaluate(f, index_runs(spans("t1", PRIMARY)), None)
    run = r["runs"][0]
    assert run["via"] == ["primary"] * 5 + ["on_fail"] and run["realized"][-1] == "->s6" and run["approximate"]
    assert run["reading"] == "convergent" and run["degraded"] == ["s5 -> s6 (on_fail)"] and r["summary"]["degraded_runs"] == 1
    # the canon's s5: s6 is both next and on_fail.to; spans read it as primary and note the shared target
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY)), None)
    run = r["runs"][0]
    assert run["via"] == ["primary"] * 6 and run["degraded"] == [] and run["notes"] and run["notes"][0].startswith("shared-target: s5 -> s6")
    assert r["summary"]["degraded_runs"] == 0


def test_span_reading_of_a_run_ending_at_an_outcome_gate(degrading_flow):
    # ends at s4 (on_fail -> block): read as having taken it; outcome unknown; s5/s6 not absent; counted degraded and vetoed
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY[:4])), None)
    run = r["runs"][0]
    assert run["reading"] == "convergent" and run["absent"] == [] and run["outcome"] == "unknown" and run["termination"] is None
    assert run["degraded"] == ["s4 -> outcome block (on_fail) [spans]"] and run["vetoed"] is True
    assert r["summary"]["degraded_runs"] == 1 and r["summary"]["vetoed_runs"] == 1
    # ends at s3 (on_fail -> review): degraded, not vetoed
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY[:3])), None)
    assert r["runs"][0]["degraded"] == ["s3 -> outcome review (on_fail) [spans]"] and r["runs"][0]["vetoed"] is False
    # ends at s2 (no on_fail): absent s3.., outcome unknown is not recorded
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY[:2])), None)
    assert r["runs"][0]["reading"] == "absent" and r["runs"][0]["outcome"] is None and r["runs"][0]["degraded"] == []


# ----------------------------------------------------------------- the two SLIs
def test_slis_rates_bands_and_sources(degrading_flow, canon_flow, cfg):
    runs = index_runs(spans("a", PRIMARY) + spans("b", PRIMARY[:4]) + spans("c", PRIMARY[:3]) + spans("d", PRIMARY))
    conf = evaluate(degrading_flow, runs, None)
    s = evaluate_slis(degrading_flow, conf, cfg)
    assert s["degradation_rate"]["rate"] == 0.5 and s["degradation_rate"]["degraded_runs"] == 2
    assert s["veto_rate"]["rate"] == 0.25 and s["veto_rate"]["vetoed_runs"] == 1
    assert s["degradation_rate"]["source"] == "spans" and s["degradation_rate"]["approximate"] is True
    assert s["degradation_rate"]["band"] == {"min": 0.0, "max": 1.0, "gate": False} and s["degradation_rate"]["out_of_band"] is None
    assert s["degradation_rate"]["notes"] == [] or s["degradation_rate"]["notes"][0].startswith("shared-target")
    # a flow without outcomes or on_fail reports no indicators
    assert evaluate_slis(canon_flow, evaluate(canon_flow, index_runs(spans("a", PRIMARY, "2.0.0")), None), cfg) is None
    # no runs: rates 0, source none
    s = evaluate_slis(degrading_flow, evaluate(degrading_flow, {}, None), cfg)
    assert s["veto_rate"] == {"rate": 0.0, "band": {"min": 0.0, "max": 1.0, "gate": False}, "source": "none", "approximate": False,
                              "runs": 0, "vetoed_runs": 0, "out_of_band": None, "notes": []}


def test_sli_bands_per_flow_and_out_of_band_both_directions(degrading_flow, cfg):
    over = copy.deepcopy(cfg)
    over["slis"]["veto_rate"]["band"] = {"min": 0.0, "max": 0.1}
    over["slis"]["degradation_rate"]["flows"] = {"quote-issue": {"band": {"min": 0.6, "max": 0.9, "gate": True}}}
    assert sli_band(over, "quote-issue", "veto_rate") == {"min": 0.0, "max": 0.1, "gate": False}
    assert sli_band(over, "quote-issue", "degradation_rate") == {"min": 0.6, "max": 0.9, "gate": True}
    assert sli_band(over, "other", "degradation_rate") == {"min": 0.0, "max": 1.0, "gate": False}
    runs = index_runs(spans("a", PRIMARY) + spans("b", PRIMARY[:4]) + spans("c", PRIMARY[:3]) + spans("d", PRIMARY))
    s = evaluate_slis(degrading_flow, evaluate(degrading_flow, runs, None), over)
    assert s["veto_rate"]["out_of_band"] == "above"            # 0.25 > 0.1: a quality signal
    assert s["degradation_rate"]["out_of_band"] == "below"     # 0.5 < 0.6: a gate that has stopped working


def test_sli_findings_through_the_gate(gate_inputs, tmp_path):
    """The gate reports sli-out-of-band as warn, and fail when the band declares gate: true."""
    import json
    from flowtrace.gate import run_gate
    flows = tmp_path / "flows"
    flows.mkdir()
    doc = yaml.safe_load(DEGRADING_FLOW)
    doc["spec"]["telemetry"].pop("assurance_sampling_floor")          # the stream and class rules are D15's
    for spec in doc["spec"]["steps"][3]["required_telemetry"]["traces"]:
        spec["required_attributes"] = [a["name"] for a in spec["required_attributes"]]
    (flows / "quote-issue.flow.yaml").write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("apiVersion: flowtrace.config/v0.1\nslis:\n  veto_rate:\n    flows: {quote-issue: {band: {min: 0.2, max: 0.9}}}\n")
    report, rc = run_gate(gate_inputs("full", flows=str(flows), config=str(cfg), execution_evidence=None, trust_bundle=None, dec_dirs=[],
                                      telemetry=[str(_window_210(tmp_path))]))
    f = report["flows"][0]
    assert f["slis"]["veto_rate"]["out_of_band"] == "below" and f["slis"]["degradation_rate"]["out_of_band"] is None
    w = [x for x in f["findings"] if x["code"] == "sli-out-of-band"]
    assert len(w) == 1 and w[0]["severity"] == "warn" and "veto_rate 0.0 is below the declared band [0.2, 0.9]" in w[0]["message"]
    assert "sli-out-of-band" not in f["verdict_reasons"]
    cfg.write_text("apiVersion: flowtrace.config/v0.1\nslis:\n  veto_rate:\n    flows: {quote-issue: {band: {min: 0.2, max: 0.9, gate: true}}}\n")
    report, rc = run_gate(gate_inputs("full", flows=str(flows), config=str(cfg), execution_evidence=None, trust_bundle=None, dec_dirs=[],
                                      telemetry=[str(_window_210(tmp_path))]))
    f = report["flows"][0]
    assert rc == 1 and "sli-out-of-band" in f["verdict_reasons"]
    assert json.loads(json.dumps(f["slis"]))["veto_rate"]["band"]["gate"] is True


def test_reading_finding_codes(degrading_flow):
    from flowtrace.gate import _reading_findings
    runs = {}
    for trace, seq, outcome in (("a", PRIMARY[:5] + [("s6", "on_fail"), "s5", "s6"], "allow"), ("b", PRIMARY, "escalate"),
                                ("c", PRIMARY[:4] + [("s6", "on_fail")], "allow"), ("d", PRIMARY[:5] + [("s6", "on_fail"), "s5", "s6"], "allow")):
        r = plan_reading(degrading_flow.doc, entries(seq), outcome=outcome)
        runs[trace] = {"trace_id": trace, "divergent": r["divergent"]}
    conf = {"runs": list(runs.values())}
    codes = {f["code"]: f for f in _reading_findings(conf, "fail")}
    assert set(codes) == {"latched-reentry", "undeclared-outcome", "undeclared-edge"}
    assert codes["latched-reentry"]["message"].startswith("2 run(s): latched re-entry: s5") and codes["latched-reentry"]["severity"] == "fail"
    assert codes["undeclared-outcome"]["message"].startswith("1 run(s): outcome: escalate")
    assert codes["undeclared-edge"]["message"].startswith("1 run(s): degradation: s6 at position 5")
    assert _reading_findings({"runs": [{"trace_id": "x", "divergent": []}]}, "warn") == []


def _window_210(tmp_path):
    """The full window re-labelled flow.version 2.1.0 (the synthetic windows
    carry the version of examples/flows at generation time)."""
    from conftest import telemetry
    src = telemetry("full").read_text(encoding="utf-8")
    out = tmp_path / "full-2.1.0.otlp.jsonl"
    out.write_text(src.replace('{"key":"flow.version","value":{"stringValue":"2.0.0"}}', '{"key":"flow.version","value":{"stringValue":"2.1.0"}}'))
    return out


def test_sli_band_bounds_as_detectability_targets(degrading_flow, cfg, tmp_path):
    over = copy.deepcopy(cfg)
    over["slis"]["degradation_rate"]["band"] = {"min": 0.1, "max": 0.4}
    over["slis"]["veto_rate"]["band"] = {"min": 0.0, "max": 0.2}
    runs = index_runs(spans("a", PRIMARY) + spans("b", PRIMARY[:4]) + spans("c", PRIMARY[:3]) + spans("d", PRIMARY))
    slis = evaluate_slis(degrading_flow, evaluate(degrading_flow, runs, None), over)
    alerts = load_alerts(ALERTS)
    r = evaluate_detectability(degrading_flow, runs, alerts, 60, slis=slis)
    sli_rows = [t for t in r["targets"] if t["slo"] in ("degradation_rate", "veto_rate")]
    assert [(t["slo"], t["bound"], t["target"]) for t in sli_rows] == [("degradation_rate", "max", 0.4), ("degradation_rate", "min", 0.1), ("veto_rate", "max", 0.2)]
    assert all(not t["detectable"] and t["reason"].startswith("no alert configured for the") for t in sli_rows)
    assert [t["breached_in_window"] for t in sli_rows] == [True, False, True]           # 0.5 > 0.4; 0.5 >= 0.1; 0.25 > 0.2
    p = tmp_path / "alerts.yaml"
    p.write_text("apiVersion: flowtrace.alerts/v0.1\nalerts:\n"
                 "  - {id: d-max, flow: quote-issue, scope: flow, slo: degradation_rate, bound: max, threshold: 0.3, evaluation_window_s: 30, notification_latency_s: 15}\n"
                 "  - {id: d-min, flow: quote-issue, scope: flow, slo: degradation_rate, bound: min, threshold: 0.05, evaluation_window_s: 30, notification_latency_s: 15}\n"
                 "  - {id: v-max, flow: quote-issue, scope: flow, slo: veto_rate, threshold: 0.5, evaluation_window_s: 30, notification_latency_s: 15}\n")
    r = evaluate_detectability(degrading_flow, runs, load_alerts(p), 60, slis=slis)
    by = {(t["slo"], t.get("bound")): t for t in r["targets"] if t["slo"] in ("degradation_rate", "veto_rate")}
    assert by[("degradation_rate", "max")]["detectable"] is True                        # 0.3 <= 0.4 and it would have fired on 0.5
    assert by[("degradation_rate", "min")]["detectable"] is False and "looser" in by[("degradation_rate", "min")]["reason"]   # 0.05 < min 0.1
    assert by[("veto_rate", "max")]["detectable"] is False and "looser" in by[("veto_rate", "max")]["reason"]                 # 0.5 > max 0.2
    p.write_text("apiVersion: flowtrace.alerts/v0.1\nalerts:\n  - {flow: quote-issue, slo: veto_rate, threshold: 0.1, bound: sideways}\n")
    with pytest.raises(ValueError, match="bound"):
        load_alerts(p)
    # a whole-range band adds no target
    assert not [t for t in evaluate_detectability(degrading_flow, runs, alerts, 60, slis=evaluate_slis(degrading_flow, evaluate(degrading_flow, runs, None), cfg))["targets"]
                if t["slo"] in ("degradation_rate", "veto_rate")]
