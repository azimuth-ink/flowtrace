"""D13 — hosted set-bounded methods: an ND1 certificate whose method.kind is
hosted (evidence.type configuration_record, replay none) is in the ND0/ND1
population and verifies on the same conditions; the engine never replays and
reports the evidence type (FTC §4.5; spec §6.5)."""
import json

import pytest

from conftest import DEC_DIR, TRUST_BUNDLE, w3_dec, w3_flows, w3_methods, w3_trust_bundle
from flowtrace.adapters.base import SpanRow
from flowtrace.coverage import CertificateIndex, evaluate_execution_evidence, index_runs


def test_evidence_type_is_reported_per_verified_instance(canon_flow, adapters):
    index = CertificateIndex([DEC_DIR], TRUST_BUNDLE)
    runs = index_runs([s for s in adapters["full"].list_spans(canon_flow.id, adapters["full"].extent()) if s.attributes.get("flow.version") == canon_flow.version])
    r = evaluate_execution_evidence(canon_flow, runs, index)
    assert r["steps"]["s4"]["evidence_types"] == {"replay_recipe": 32}
    (digest,) = {b.attributes["dec.step_cert_digest"] for run in runs.values() for b in run.boundaries["s4"]}
    assert index.evidence_type(digest) == "replay_recipe" and index.evidence_type("sha256:" + "0" * 64) is None
    assert evaluate_execution_evidence(canon_flow, runs, None)["steps"]["s4"]["evidence_types"] == {}


def hosted_example():
    root = w3_dec()
    if root is None:
        return None
    cand = root.parent / "hosted"
    return cand if (cand / "run.dec.json").exists() else None


@pytest.mark.skipif(hosted_example() is None, reason="agent-dec's hosted example (examples/hosted/) is not available")
def test_hosted_certificate_is_execution_evidence_without_replay():
    hosted = hosted_example()
    index = CertificateIndex([hosted], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    (digest, (path, cert)) = next(iter(index.steps.items()))
    assert cert["method"]["kind"] == "hosted" and cert["subject"]["class"] == "ND1"
    assert cert["evidence"]["type"] == "configuration_record" and cert["evidence"]["detail"]["replay"] == "none"
    assert index.evidence_type(digest) == "configuration_record"
    # signature and class pass (no replay is attempted); the example run is unbound, so the step binding is what fails
    run_id = cert["subject"]["run_id"]
    span = SpanRow(run_id, "a", None, "s1", "SERVER", 0, 1, "OK", {"flow.id": "quote-dispute", "flow.version": "1.0.0", "flow.step": "s1"})
    status, reason = index.verify_step_digest(digest, span)
    assert status == "flow-mismatch" and "subject.flow" in reason
    # agent-dec's verifier agrees: verified-attested, configuration record validated, no replay
    vr = index.verifier_result(hosted)
    assert vr.verdict == "verified" and vr.findings == [] and vr.exit_code == 0
