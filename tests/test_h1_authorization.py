"""H1 — effect steps without authorization evidence (binding B10) read as
divergent with agent-dec's finding effect-without-authorization; the
authorization's validity window and freshness findings (authorization-expired,
authorization-stale, B16) are passed through, never re-derived
(FTC §4.8; spec §7.6, §6.6)."""
import json

import pytest

from conftest import w3_dec, w3_flows, w3_methods, w3_trust_bundle
from flowtrace.adapters.base import SpanRow
from flowtrace.conformance import DIVERGENT_FINDINGS, READ_FINDINGS, evaluate
from flowtrace.coverage import CertificateIndex, index_runs
from flowtrace.gate import PASS_THROUGH_CODES, _pass_through_findings, _reading_findings
from test_h4_attempts import PRIMARY, spans


def test_the_findings_this_unit_reads():
    assert "effect-without-authorization" in READ_FINDINGS and "effect-without-authorization" in DIVERGENT_FINDINGS
    assert {"authorization-expired", "authorization-stale"} <= set(PASS_THROUGH_CODES)
    assert {"authorization-expired", "authorization-stale"} <= set(READ_FINDINGS)
    assert not {"authorization-expired", "authorization-stale"} & set(DIVERGENT_FINDINGS)


def test_b10_is_unchecked_from_spans(degrading_flow, canon_flow):
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY) + spans("t2", PRIMARY[:4])), None)
    assert r["summary"]["unchecked"] == ["effect-without-authorization (B10): unchecked for 1 span-sourced run(s) (no certificates to read it from)"]
    assert all(run["findings"] == [] for run in r["runs"])
    # no effect step declared: nothing to check
    import copy
    from flowtrace.flows import Flow
    doc = copy.deepcopy(canon_flow.doc)
    for s in doc["spec"]["steps"]:
        s.pop("effect", None)
        s.pop("attempts", None)
    assert evaluate(Flow(canon_flow.path, doc, "0" * 64), index_runs(spans("t1", PRIMARY)), None)["summary"]["unchecked"] == []


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")
def test_effect_without_authorization_from_the_signed_negative(degrading_flow):
    root = w3_dec()
    index = CertificateIndex([root], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    neg = root / "negative" / "effect-without-authorization"
    vr = index.verifier_result(neg)
    assert vr.verdict == "not-clean" and [f[0] for f in vr.findings] == ["effect-without-authorization"]
    run_id = json.loads((neg / "run.dec.json").read_text())["subject"]["run_id"]
    # the same run id is the clean flow-bound run's: name the negative's run certificate on the trigger span (B6)
    digest = next(d for d, (p, c) in index.runs.items() if p == neg / "run.dec.json")
    sp = spans(run_id, PRIMARY)
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": digest}))
    r = evaluate(degrading_flow, index_runs(sp), index)
    run = r["runs"][0]
    assert run["source"] == "manifest:run.dec.json" and run["reading"] == "divergent"
    assert run["findings"] == [{"code": "effect-without-authorization", "step": "s6", "attempt_id": 1, "file": "step-s6.dec.json",
                                "reason": vr.findings[0][2], "reason_class": "denied"}]
    assert "policy-unavailable" in run["findings"][0]["reason"] and run["divergent"] == [f"effect-without-authorization: {vr.findings[0][2]}"]
    assert r["summary"]["non_convergent_runs"] == 1 and r["summary"]["unchecked"] == []
    codes = {f["code"]: f for f in _reading_findings(r, "fail")}
    assert set(codes) == {"effect-without-authorization"} and codes["effect-without-authorization"]["severity"] == "fail"
    assert _pass_through_findings(r) == []
    # the clean run: no finding, convergent, B16 checked against the flow's max_decision_age_s (the registry resolved)
    clean = next(d for d, (p, c) in index.runs.items() if p == root / "run.dec.json")
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": clean}))
    r = evaluate(degrading_flow, index_runs(sp), index)
    assert r["runs"][0]["reading"] == "convergent" and r["runs"][0]["findings"] == []
    vr = index.verifier_result(root)
    assert "freshness (B16) checked against max_decision_age_s 300" in vr.summaries["step 1d"] and vr.unchecked == []


def test_pass_through_findings_are_warnings(degrading_flow):
    conf = {"runs": [
        {"trace_id": "a", "divergent": [], "findings": [{"code": "authorization-stale", "step": "s6", "attempt_id": 1, "file": "step-s6.dec.json",
                                                        "reason": "the decision's as_of 2026-10-15T06:00:00Z is older than issued_at minus the declared max_decision_age_s 300 (binding B16)"}]},
        {"trace_id": "b", "divergent": [], "findings": [{"code": "authorization-expired", "step": "s6", "attempt_id": 1, "file": "step-s6.dec.json",
                                                        "reason": "the decision's expiry is before the certificate's issued_at"}]},
        {"trace_id": "c", "divergent": [], "findings": [{"code": "authorization-expired", "step": "s6", "attempt_id": 2, "file": "step-s6.attempt-2.dec.json",
                                                        "reason": "x"}]},
    ]}
    out = {f["code"]: f for f in _pass_through_findings(conf)}
    assert set(out) == {"authorization-expired", "authorization-stale"} and all(f["severity"] == "warn" for f in out.values())
    assert out["authorization-stale"]["message"].startswith("1 run(s), from agent-dec's step 1d: the decision's as_of") and out["authorization-stale"]["step"] == "s6"
    assert out["authorization-expired"]["message"].endswith("(first of 2)")
    assert _reading_findings(conf, "fail") == []


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")
def test_authorization_coverage_reads_the_same_verifier_result(degrading_flow):
    """A span carrying the deny record's digest: not covered (§6.6 status
    denied) and divergent (§7.6) — both from one verifier result."""
    from flowtrace.coverage import evaluate_execution_evidence
    root = w3_dec()
    index = CertificateIndex([root], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    neg = root / "negative" / "effect-without-authorization"
    deny = next(d for d, (p, c) in index.authorizations.items() if p == neg / "authorization-s6.dec.json")
    run_id = json.loads((neg / "run.dec.json").read_text())["subject"]["run_id"]
    digest = next(d for d, (p, c) in index.runs.items() if p == neg / "run.dec.json")
    sp = spans(run_id, PRIMARY)
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": digest}))
    sp[5] = SpanRow(sp[5].trace_id, sp[5].span_id, sp[5].parent_span_id, "s6", "SERVER", 50, 55, "OK", dict(sp[5].attributes, **{"dec.authz_cert_digest": deny}))
    runs = index_runs(sp)
    ee = evaluate_execution_evidence(degrading_flow, runs, index)
    assert ee["authorization"]["s6"]["statuses"] == {"denied": 1}
    assert evaluate(degrading_flow, runs, index)["runs"][0]["findings"][0]["reason_class"] == "denied"
    assert len(index._verifier_cache) == 1
