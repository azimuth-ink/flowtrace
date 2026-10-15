"""H2 — dec.approval_digest joined to the human_approval attestation (the
approvals/ directory beside a run's chain, or --approvals); sod-violation (B11)
and approval-payload-mismatch (B15) passed through from agent-dec's step 1d and
read as the authorization status approval-invalid (spec §6.6)."""
import json

import pytest

from conftest import w3_dec, w3_flows, w3_methods, w3_trust_bundle
from flowtrace.adapters.base import SpanRow
from flowtrace.conformance import READ_FINDINGS, evaluate
from flowtrace.coverage import CertificateIndex, evaluate_execution_evidence, index_runs
from flowtrace.gate import PASS_THROUGH_CODES, _pass_through_findings, run_gate
from test_h4_attempts import PRIMARY, spans

pytestmark = pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")


@pytest.fixture(scope="module")
def index():
    root = w3_dec()
    return CertificateIndex([root], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())


def variant(index, rel):
    """(run directory, run id, run certificate digest, authorization digest, approval_ref) of a run directory."""
    d = w3_dec() / rel
    run = json.loads((d / "run.dec.json").read_text())
    run_digest = next(dg for dg, (p, c) in index.runs.items() if p == d / "run.dec.json")
    authz = next(dg for dg, (p, c) in index.authorizations.items() if p == d / "authorization-s6.dec.json")
    return d, run["subject"]["run_id"], run_digest, authz, index.authorizations[authz][1]["decision"]["approval_ref"]


def window(run_id, run_digest, authz, approval):
    sp = spans(run_id, PRIMARY)
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": run_digest}))
    sp[5] = SpanRow(sp[5].trace_id, sp[5].span_id, sp[5].parent_span_id, "s6", "SERVER", 50, 55, "OK",
                    dict(sp[5].attributes, **{"dec.authz_cert_digest": authz, "dec.approval_digest": approval}))
    return index_runs(sp)


def test_approvals_are_indexed_from_the_chains_approvals_directory(index):
    assert set(READ_FINDINGS) >= {"sod-violation", "approval-payload-mismatch"} and set(PASS_THROUGH_CODES) >= {"sod-violation", "approval-payload-mismatch"}
    d, run_id, run_digest, authz, ref = variant(index, "variants/s6-approval")
    assert ref in index.approvals and index.approvals[ref][0] == d / "approvals" / f"{ref.split(':', 1)[1]}.json"
    assert index.approvals[ref][1]["type"] == "human_approval" and len(index.approvals) >= 3


def test_approval_resolves_and_the_variant_is_clean(degrading_flow, index):
    d, run_id, run_digest, authz, ref = variant(index, "variants/s6-approval")
    runs = window(run_id, run_digest, authz, ref)
    ee = evaluate_execution_evidence(degrading_flow, runs, index)
    assert ee["authorization"]["s6"]["statuses"] == {"verified": 1}
    assert ee["authorization"]["s6"]["approval_present"] == {"spans_with_digest": 1, "resolved": 1, "statuses": {"resolved": 1}}
    assert index.approval_for(ref, runs[run_id].boundaries["s6"][0]) == ("resolved", None)
    assert index.approval_for("sha256:" + "0" * 64, runs[run_id].boundaries["s6"][0])[0] == "artifact-not-found"
    # the approval is bound to its own run: another run's span does not resolve it under strict binding
    other = window("ab" * 16, run_digest, authz, ref)
    assert index.approval_for(ref, other["ab" * 16].boundaries["s6"][0])[0] == "run-binding-mismatch"
    assert evaluate_execution_evidence(degrading_flow, other, index, run_binding="strict")["authorization"]["s6"]["approval_present"]["resolved"] == 0
    assert evaluate_execution_evidence(degrading_flow, other, index, run_binding="warn")["authorization"]["s6"]["approval_present"]["resolved"] == 1
    r = evaluate(degrading_flow, runs, index)
    assert r["runs"][0]["reading"] == "convergent" and r["runs"][0]["findings"] == []
    vr = index.verifier_result(d)
    assert vr.verdict == "verified" and "(b) approval checked on 1 decision(s)" in vr.summaries["step 1d"]


@pytest.mark.parametrize("rel,code", [("negative/sod-violation", "sod-violation"), ("negative/approval-payload-mismatch", "approval-payload-mismatch")])
def test_approval_negatives_pass_through(degrading_flow, index, rel, code):
    d, run_id, run_digest, authz, ref = variant(index, rel)
    vr = index.verifier_result(d)
    assert vr.verdict == "not-clean" and [f[0] for f in vr.findings] == [code]
    runs = window(run_id, run_digest, authz, ref)
    ee = evaluate_execution_evidence(degrading_flow, runs, index)
    assert ee["authorization"]["s6"]["statuses"] == {"approval-invalid": 1} and code in ee["authorization"]["s6"]["examples"][0]["reason"]
    r = evaluate(degrading_flow, runs, index)
    run = r["runs"][0]
    assert run["reading"] == "convergent" and [f["code"] for f in run["findings"]] == [code]       # a pass-through, not a divergence
    (w,) = _pass_through_findings(r)
    assert w["code"] == code and w["severity"] == "warn" and w["step"] == "s6"
    if code == "sod-violation":
        # the approval in that directory is signed with the issuing key: it resolves in no approvers[] entry
        assert index.approval_for(ref, runs[run_id].boundaries["s6"][0])[0] == "signature-invalid"
        assert ee["authorization"]["s6"]["approval_present"]["resolved"] == 0
    else:
        assert ee["authorization"]["s6"]["approval_present"]["resolved"] == 1


def test_approvals_flag_through_the_gate(degrading_flow, gate_inputs, index, tmp_path):
    """--approvals names a directory of attestations (joined and passed to the
    verifier); without it the approvals/ beside each chain are used."""
    from test_d15_assurance import otlp_export
    d, run_id, run_digest, authz, ref = variant(index, "variants/s6-approval")
    flows = tmp_path / "flows"
    flows.mkdir()
    (flows / "quote-issue.flow.yaml").write_bytes((w3_flows() / "quote-issue.flow.yaml").read_bytes())
    export = otlp_export(tmp_path / "w.jsonl", window(run_id, run_digest, authz, ref))
    common = dict(flows=str(flows), trust_bundle=str(w3_trust_bundle()), dec_dirs=[str(w3_dec())], methods=str(w3_methods()), alerts=None, queries=[])
    report, rc = run_gate(gate_inputs("full", telemetry=[str(export)], **common))
    assert report["inputs"]["approvals"] is None
    assert report["flows"][0]["components"]["execution_evidence"]["authorization"]["s6"]["approval_present"]["resolved"] == 1
    elsewhere = tmp_path / "approvals"
    elsewhere.mkdir()
    src = index.approvals[ref][0]
    (elsewhere / src.name).write_bytes(src.read_bytes())
    report, rc = run_gate(gate_inputs("full", telemetry=[str(export)], approvals=str(elsewhere), **common))
    assert report["inputs"]["approvals"] == "approvals"
    assert report["flows"][0]["components"]["execution_evidence"]["authorization"]["s6"]["approval_present"]["resolved"] == 1
    assert report["flows"][0]["components"]["execution_evidence"]["authorization"]["s6"]["statuses"] == {"verified": 1}
    with pytest.raises(Exception, match="not found"):
        run_gate(gate_inputs("full", telemetry=[str(export)], approvals="/nonexistent", **common))
