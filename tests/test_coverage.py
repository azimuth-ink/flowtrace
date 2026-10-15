"""FTC §4.5 components over the synthetic windows and hand-built runs."""
import copy
import json

import pytest

from conftest import ALERTS, CERTIFIED_RUN, DEC_DIR, TRUST_BUNDLE
from flowtrace.adapters.base import SpanRow
from flowtrace.coverage import (CertificateIndex, Run, compose, evaluate_completeness, evaluate_cost_attribution,
                                evaluate_detectability, evaluate_execution_evidence, index_runs, load_alerts,
                                observed_slo_values)
from flowtrace.flows import Flow

S4_DIGEST = "sha256:9c2729352e998d16f69920dc726b72bbf722f2bb326d927c6d90146eb87fc143"      # examples/dec/flow-bound/step-s4.dec.json


def runs_of(adapter, flow):
    return index_runs([s for s in adapter.list_spans(flow.id, adapter.extent()) if s.attributes.get("flow.version") == flow.version])


def span(trace, sid, step, parent=None, start=0, end=10, status="OK", **attrs):
    base = {"flow.id": "quote-issue", "flow.version": "2.1.0", "flow.step": step}
    base.update(attrs)
    return SpanRow(trace, sid, parent, f"{step}-span", "SERVER", start, end, status, base)


# ----------------------------------------------------------------- indexing
def test_boundary_spans_exclude_interior_spans(adapters, canon_flow):
    runs = runs_of(adapters["full"], canon_flow)
    assert len(runs) == 32
    run = runs[CERTIFIED_RUN]
    assert len(run.by_step["s3"]) == 2 and len(run.boundaries["s3"]) == 1
    assert run.boundaries["s3"][0].name == "payments.quote-engine/price"
    assert [s for s, _ in run.realized()] == ["s1", "s2", "s3", "s4", "s5", "s6"]
    assert run.trigger.attributes["flow.step"] == "s1" and "dec.run_cert_digest" in run.trigger.attributes
    other = next(r for t, r in runs.items() if t != run.trace_id)
    assert "dec.run_cert_digest" not in other.trigger.attributes


# ----------------------------------------------------------------- completeness
def test_completeness_over_the_three_windows(adapters, canon_flow):
    full = evaluate_completeness(canon_flow, runs_of(adapters["full"], canon_flow), adapters["full"].list_metrics("quote-issue", adapters["full"].extent()), [])
    assert full["score"] == 1.0 and full["blind_spots"] == [] and full["runs_complete"] == 32
    silent = evaluate_completeness(canon_flow, runs_of(adapters["s5-silent"], canon_flow), adapters["s5-silent"].list_metrics("quote-issue", adapters["s5-silent"].extent()), [])
    assert silent["score"] == 0.0 and silent["blind_spots"] == ["s5"]
    assert silent["by_step"]["s5"]["present_runs"] == 0 and silent["by_step"]["s4"]["fraction"] == 1.0
    assert silent["by_step"]["s5"]["missing"] == {"no span carries flow.step=s5": 32}
    missing = evaluate_completeness(canon_flow, runs_of(adapters["s4-missing-attr"], canon_flow), adapters["s4-missing-attr"].list_metrics("quote-issue", adapters["s4-missing-attr"].extent()), [])
    assert missing["score"] == 0.0 and missing["blind_spots"] == []
    assert missing["by_step"]["s4"]["present_runs"] == 32 and missing["by_step"]["s4"]["complete_runs"] == 0
    assert missing["by_step"]["s4"]["missing"] == {"span risk.limits-check/evaluate lacks required attribute risk.decision": 32}


def test_completeness_required_metric_and_b2_attributes(canon_flow, adapters):
    runs = runs_of(adapters["full"], canon_flow)
    # without the metrics the required step_duration_seconds histogram is missing for s4
    r = evaluate_completeness(canon_flow, runs, [], [])
    assert r["score"] == 0.0 and list(r["by_step"]["s4"]["missing"]) == ["metric step_duration_seconds (histogram) with flow.id/flow.step labels"]
    # a span with the wrong flow.version or without flow.version fails B2
    runs2 = index_runs([span("t1", "a", "s1", flow_version="9.9.9")])
    doc = copy.deepcopy(canon_flow.doc)
    doc["spec"]["steps"] = [{"id": "s1", "component": "x.y", "op": "o"}]
    tiny = Flow(canon_flow.path, doc, "0" * 64)
    runs2 = index_runs([SpanRow("t1", "a", None, "n", "SERVER", 0, 1, "OK", {"flow.id": "quote-issue", "flow.version": "9.9.9", "flow.step": "s1"})])
    r = evaluate_completeness(tiny, runs2, [], [])
    assert list(r["by_step"]["s1"]["missing"]) == ["boundary span flow.version 9.9.9 != declared 2.1.0"]
    assert evaluate_completeness(tiny, {}, [], [])["reason"] == "no runs of the flow observed in the window"


def test_required_log_check(canon_flow):
    from flowtrace.adapters.base import LogRow
    doc = copy.deepcopy(canon_flow.doc)
    doc["spec"]["steps"] = [{"id": "s1", "component": "x.y", "op": "o", "required_telemetry": {"logs": [{"level": "ERROR"}]}}]
    f = Flow(canon_flow.path, doc, "0" * 64)
    runs = index_runs([span("t1", "a", "s1")])
    assert evaluate_completeness(f, runs, [], [])["score"] == 0.0
    lg = LogRow(1, "ERROR", "x", {"flow.id": "quote-issue", "flow.step": "s1"})
    assert evaluate_completeness(f, runs, [], [lg])["score"] == 1.0


# ----------------------------------------------------------------- detectability
def test_detectability_targets_and_bounds(canon_flow, adapters):
    alerts = load_alerts(ALERTS)
    runs = runs_of(adapters["full"], canon_flow)
    r = evaluate_detectability(canon_flow, runs, alerts, 60)
    assert r["score"] == 1.0 and [(t["scope"], t["slo"]) for t in r["targets"]] == [
        ("flow", "latency_p95_ms"), ("flow", "async_completion_p99_s"), ("flow", "availability"), ("s4", "latency_p99_ms"), ("s4", "error_rate_percent")]
    assert all(t["breached_in_window"] is False for t in r["targets"])
    # tighter tier bound than the alerts' 45 s detection latency -> nothing detectable
    assert evaluate_detectability(canon_flow, runs, alerts, 30)["score"] == 0.0
    # no alerts at all
    none = evaluate_detectability(canon_flow, runs, None, 60)
    assert none["score"] == 0.0 and none["reason"].startswith("no alert configuration")
    # a looser threshold than the SLO
    loose = [dict(a, threshold=5000) if a["slo"] == "latency_p95_ms" else a for a in alerts]
    r = evaluate_detectability(canon_flow, runs, loose, 60)
    assert r["score"] == 0.8 and "looser" in r["targets"][0]["reason"]


def test_detectability_breach_would_not_have_fired(canon_flow):
    # s4 ran 500 ms (breaches its 120 ms p99); an alert at 800 ms would not have fired
    runs = index_runs([span("t1", "a", "s4", start=0, end=500_000_000)])
    alerts = [{"id": "x", "flow": "quote-issue", "scope": "step", "step": "s4", "slo": "latency_p99_ms",
               "threshold": 800, "evaluation_window_s": 10, "notification_latency_s": 5}]
    r = evaluate_detectability(canon_flow, runs, alerts, 60)
    t = next(t for t in r["targets"] if t["scope"] == "s4" and t["slo"] == "latency_p99_ms")
    assert t["breached_in_window"] is True and t["detectable"] is False and "looser" in t["reason"]
    alerts[0]["threshold"] = 120
    t = next(t for t in evaluate_detectability(canon_flow, runs, alerts, 60)["targets"] if t["scope"] == "s4" and t["slo"] == "latency_p99_ms")
    assert t["detectable"] is True
    obs = observed_slo_values(canon_flow, runs)
    assert obs["s4"]["latency_p99_ms"] == 500.0 and obs["flow"]["availability"] == 100.0
    err = index_runs([span("t2", "b", "s4", status="ERROR")])
    obs = observed_slo_values(canon_flow, err)
    assert obs["s4"]["error_rate_percent"] == 100.0 and obs["flow"]["availability"] == 0.0


def test_detectability_not_applicable_without_targets(canon_flow):
    doc = copy.deepcopy(canon_flow.doc)
    doc["spec"].pop("slos")
    for s in doc["spec"]["steps"]:
        s.pop("slo", None)
    r = evaluate_detectability(Flow(canon_flow.path, doc, "0" * 64), {}, [], 60)
    assert r["applicable"] is False and r["score"] == 1.0


def test_alerts_file_validation(tmp_path):
    p = tmp_path / "a.yaml"
    p.write_text("apiVersion: flowtrace.alerts/v0.1\nalerts:\n  - {flow: f, slo: availability, threshold: 99, scope: step}\n")
    with pytest.raises(ValueError, match="step id"):
        load_alerts(p)
    p.write_text("apiVersion: nope\n")
    with pytest.raises(ValueError):
        load_alerts(p)


# ----------------------------------------------------------------- cost attribution
def test_cost_attribution(canon_flow, adapters, cfg):
    attrs = cfg["cost"]["attributes"]
    full = evaluate_cost_attribution(canon_flow, runs_of(adapters["full"], canon_flow), attrs)
    assert full["score"] == 1.0 and full["flow_attributable"] is True
    assert full["by_step"]["s5"]["attributes_seen"] == ["cost.usd", "llm.usage.total_tokens"]
    assert full["by_step"]["s5"]["cost_usd_total"] > 0
    silent = evaluate_cost_attribution(canon_flow, runs_of(adapters["s5-silent"], canon_flow), attrs)
    assert silent["score"] == pytest.approx(5 / 6) and silent["by_step"]["s5"]["attributable"] is False


# ----------------------------------------------------------------- execution evidence (B7)
@pytest.fixture(scope="module")
def index():
    return CertificateIndex([DEC_DIR], TRUST_BUNDLE)


def test_certificate_index_finds_the_signed_example(index):
    """examples/dec/flow-bound is searched recursively: the §4.4 run, the three
    variants, the cancelled pair and the negatives (several claim one run id)."""
    assert index.errors == [] and S4_DIGEST in index.steps
    # five certificates claim the §4.4 run id: flow-bound/ and the negatives built on it (flow-binding, effect-without-authorization,
    # sod-violation, approval-payload-mismatch) — the trigger span names the one it means by dec.run_cert_digest (B6)
    assert sorted(p.parent.relative_to(DEC_DIR).as_posix() for p, c in index.runs_by_run_id[CERTIFIED_RUN].values()) == [
        ".", "negative", "negative/approval-payload-mismatch", "negative/effect-without-authorization", "negative/sod-violation"]
    assert len(index.runs) == 15 and len(index.steps) == 53 and len(index.authorizations) == 12 and len(index.completions) == 13 and len(index.approvals) == 3
    assert {p.name for p, c in index.steps.values()} >= {"step-s6.attempt-2.dec.json", "step-s5.9.dec.json", "step-s4.flow-step-s3.dec.json"}


def test_execution_evidence_full_window(canon_flow, adapters, index):
    runs = runs_of(adapters["full"], canon_flow)
    r = evaluate_execution_evidence(canon_flow, runs, index, run_binding="warn")
    assert r["score"] == 1.0 and list(r["steps"]) == ["s4"]
    assert r["steps"]["s4"]["verified"] == 32 and r["steps"]["s4"]["run_binding_mismatches"] == 31
    assert r["warnings"] and "strict" in r["warnings"][0]
    strict = evaluate_execution_evidence(canon_flow, runs, index, run_binding="strict")
    assert strict["score"] == pytest.approx(1 / 32) and strict["steps"]["s4"]["statuses"]["run-binding-mismatch"] == 31


def test_execution_evidence_statuses(canon_flow, index, tmp_path):
    good = span(CERTIFIED_RUN, "a", "s4", **{"dec.step_cert_digest": S4_DIGEST})
    assert index.verify_step_digest(S4_DIGEST, good) == ("verified", None)
    # digest not in the index
    assert index.verify_step_digest("sha256:" + "0" * 64, good)[0] == "certificate-not-found"
    # subject.flow must match the span (B7)
    wrong_step = span(good.trace_id, "a", "s3", **{"dec.step_cert_digest": S4_DIGEST})
    assert index.verify_step_digest(S4_DIGEST, wrong_step)[0] == "flow-mismatch"
    # an attestation (ND2) is not execution evidence
    s5_digest = next(d for d, (p, c) in index.steps.items() if p == DEC_DIR / "step-s5.dec.json")
    s5_span = span(good.trace_id, "a", "s5", **{"dec.step_cert_digest": s5_digest})
    assert index.verify_step_digest(s5_digest, s5_span)[0] == "class-mismatch"
    # a tampered certificate: one byte changed -> digest changes; re-indexed under the new digest it fails the signature
    tampered_dir = tmp_path / "tampered"
    tampered_dir.mkdir()
    c = json.loads((DEC_DIR / "step-s4.dec.json").read_text())
    c["subject"]["run_id"] = "0" * 32
    (tampered_dir / "step-s4.dec.json").write_text(json.dumps(c))
    ti = CertificateIndex([tampered_dir], TRUST_BUNDLE)
    (digest,) = ti.steps
    assert ti.verify_step_digest(digest, span("0" * 32, "a", "s4"))[0] == "signature-invalid"
    # no trust bundle: unverifiable
    nb = CertificateIndex([DEC_DIR], None)
    assert nb.verify_step_digest(S4_DIGEST, good)[0] == "unverifiable"
    # missing digest / missing span / no index
    r = evaluate_execution_evidence(canon_flow, index_runs([span("t", "a", "s4")]), index)
    assert r["steps"]["s4"]["statuses"] == {"missing-digest": 1}
    r = evaluate_execution_evidence(canon_flow, index_runs([span("t", "a", "s1")]), index)
    assert r["steps"]["s4"]["statuses"] == {"missing-span": 1}
    r = evaluate_execution_evidence(canon_flow, index_runs([good]), None)
    assert r["score"] == 0.0 and r["steps"]["s4"]["statuses"] == {"unverifiable": 1}


def test_execution_evidence_not_applicable_without_replayable_steps(canon_flow):
    doc = copy.deepcopy(canon_flow.doc)
    for s in doc["spec"]["steps"]:
        s.pop("nd_class", None)
        s.pop("method", None)
        s.pop("effect", None)
        s.pop("attempts", None)
    r = evaluate_execution_evidence(Flow(canon_flow.path, doc, "0" * 64), {}, None)
    assert r["applicable"] is False and r["score"] == 1.0


# ----------------------------------------------------------------- composition
def test_compose_renormalizes_over_applicable_components(cfg):
    from flowtrace.config import weights_for
    w = weights_for(cfg, True)
    comps = {"completeness": {"score": 1.0}, "answerability": {"score": 0.5}, "detectability": {"score": 1.0, "applicable": False},
             "cost_attribution": {"score": 0.0}, "execution_evidence": {"score": 1.0}}
    score, eff = compose(comps, w)
    assert "detectability" not in eff and sum(eff.values()) == pytest.approx(1.0)
    assert score == pytest.approx((0.35 * 1 + 0.25 * 0.5 + 0.10 * 0 + 0.10 * 1) / 0.80)
    assert compose({"completeness": {"score": 1.0}}, {"answerability": 0.3}) == (0.0, {})
