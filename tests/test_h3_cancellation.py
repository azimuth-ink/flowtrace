"""H3 — cancellation propagation across runs (binding B14): a cancelled parent
is convergent only when every child run's certificate records termination
cancelled | completed within cancel_propagation_s of the parent's cancellation
(manifest terminated_at, else the run certificate's issued_at); children are
resolved in --dec-dir, then --runs-dir (FTC §4.8; spec §7.7)."""
import copy
import json
import pathlib

import pytest

from conftest import w3_dec, w3_flows, w3_methods, w3_trust_bundle
from flowtrace.adapters.base import SpanRow
from flowtrace.conformance import cancellation_check, evaluate
from flowtrace.coverage import CertificateIndex, index_runs
from flowtrace.flows import Flow
from flowtrace.gate import GateUsageError, _reading_findings, run_gate
from test_h4_attempts import spans

PARENT = {"kind": "run", "issued_at": "2026-10-15T07:17:28Z", "subject": {"run_id": "p" * 32},
          "manifest": {"termination": "cancelled", "terminated_at": "2026-10-15T07:17:28Z",
                       "children": [{"run_id": "c" * 32, "task_grant_commitment": "sha256:" + "1" * 64}], "steps": []}}


class FakeIndex:
    """A certificate index with scripted child certificates (status, closed_at, verifies)."""

    def __init__(self, children, runs_dirs=()):
        self.children, self.runs_dirs, self.resolve = children, list(runs_dirs), object()

    def child_run_certificate(self, run_id):
        hit = self.children.get(run_id)
        if hit is None:
            return None
        term, closed, ok = hit
        doc = {"kind": "run", "issued_at": closed, "subject": {"run_id": run_id}, "manifest": {"termination": term}}
        return pathlib.Path(f"/x/{run_id}/run.dec.json"), doc, "dec-dir"

    def _signed(self, path, doc, klass):
        term, closed, ok = self.children[doc["subject"]["run_id"]]
        return None if ok else ("signature-invalid", f"{path.name}: signature invalid")


def check(flow, children, parent=PARENT, runs_dirs=(), default=30.0):
    return cancellation_check(flow, parent, FakeIndex(children, runs_dirs), cancel_propagation_default=default)


def test_b14_readings(degrading_flow):
    cid = "c" * 32
    ok, findings, rows = check(degrading_flow, {cid: ("cancelled", "2026-10-15T07:17:40Z", True)})
    assert ok is True and findings == [] and rows[0]["status"] == "within-window" and rows[0]["source"] == f"dec-dir:run.dec.json"
    ok, findings, rows = check(degrading_flow, {cid: ("completed", "2026-10-15T07:17:58Z", True)})
    assert ok is True and rows[0]["termination"] == "completed"                              # exactly at the 30 s deadline
    ok, findings, rows = check(degrading_flow, {cid: ("completed", "2026-10-15T07:17:59Z", True)})
    assert ok is False and findings[0]["reason_class"] == "late" and findings[0]["child_run_id"] == cid and rows[0]["status"] == "late"
    assert findings[0]["code"] == "cancellation-not-propagated" and "cancel_propagation_s 30" in findings[0]["reason"]
    for term in ("expired", "failed", None):                                                 # B14 names cancelled and completed only
        ok, findings, rows = check(degrading_flow, {cid: (term, "2026-10-15T07:17:30Z", True)})
        assert ok is False and findings[0]["reason_class"] == "not-terminated" and (term or "unrecorded") in findings[0]["reason"]
    ok, findings, rows = check(degrading_flow, {cid: ("cancelled", "2026-10-15T07:17:30Z", False)})
    assert ok is False and findings[0]["reason_class"] == "certificate-not-found" and "does not verify" in findings[0]["reason"]
    # not found: unchecked without --runs-dir, the finding with it
    ok, findings, rows = check(degrading_flow, {})
    assert ok is None and findings == [] and rows[0]["status"].startswith("certificate-not-found (unchecked")
    ok, findings, rows = check(degrading_flow, {}, runs_dirs=["/somewhere"])
    assert ok is False and findings[0]["reason_class"] == "certificate-not-found"
    # a parent that is not cancelled, or has no children: nothing to read
    assert check(degrading_flow, {}, parent={"manifest": {"termination": "completed", "children": [{"run_id": cid}]}}) == (None, [], [])
    assert check(degrading_flow, {}, parent={"manifest": {"termination": "cancelled"}}) == (None, [], [])


def test_cancellation_instant_and_window_defaults(degrading_flow):
    cid = "c" * 32
    # terminated_at absent: the run certificate's issued_at is the cancellation instant
    parent = copy.deepcopy(PARENT)
    parent["manifest"].pop("terminated_at")
    parent["issued_at"] = "2026-10-15T07:00:00Z"
    ok, findings, _ = check(degrading_flow, {cid: ("cancelled", "2026-10-15T07:00:31Z", True)}, parent=parent)
    assert ok is False and "parent cancelled at 2026-10-15T07:00:00Z" in findings[0]["reason"]
    # a flow that declares no cancel_propagation_s takes the configured default
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"].pop("cancel_propagation_s")
    f = Flow(degrading_flow.path, doc, "0" * 64)
    assert check(f, {cid: ("cancelled", "2026-10-15T07:18:28Z", True)}, default=60)[0] is True
    assert check(f, {cid: ("cancelled", "2026-10-15T07:18:28Z", True)}, default=30)[0] is False


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")
def test_signed_cancelled_pair_and_negative(degrading_flow):
    root = w3_dec()
    index = CertificateIndex([root], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    good = json.loads((root / "cancelled" / "parent" / "run.dec.json").read_text())
    bad = json.loads((root / "negative" / "cancellation-not-propagated" / "parent" / "run.dec.json").read_text())
    runs = index_runs(spans(good["subject"]["run_id"], ["s1", "s2", "s3"]) + spans(bad["subject"]["run_id"], ["s1", "s2", "s3"]))
    r = evaluate(degrading_flow, runs, index)
    by = {x["trace_id"]: x for x in r["runs"]}
    g, b = by[good["subject"]["run_id"]], by[bad["subject"]["run_id"]]
    assert g["source"] == "manifest:run.dec.json" and g["reading"] == "convergent" and g["termination"] == "cancelled" and g["absent"] == []
    assert g["children"] == [{"run_id": "ab026d1673f96f3b9509ff810506802a", "task_grant_commitment": good["manifest"]["children"][0]["task_grant_commitment"],
                              "status": "within-window", "termination": "cancelled", "closed_at": "2026-10-15T07:17:28Z", "source": "dec-dir:run.dec.json"}]
    assert b["reading"] == "divergent" and b["findings"][0]["reason_class"] == "late" and b["findings"][0]["child_run_id"] == "fcc6c3a32bb029fc6a73fb121b414e79"
    assert b["divergent"] == ["cancellation-not-propagated: a child run of this cancelled parent was not cancelled or completed within "
                              "cancel_propagation_s (step 1d(c))"]
    assert b["children"][0]["status"] == "late" and b["children"][0]["closed_at"] == "2026-10-15T07:19:28Z"
    assert r["cross_run"] == {"children_checked": 2, "children_unresolved": 0} and r["summary"]["non_convergent_runs"] == 1
    assert r["summary"]["unchecked"] == []
    codes = {f["code"]: f for f in _reading_findings(r, "fail")}
    assert set(codes) == {"cancellation-not-propagated"} and codes["cancellation-not-propagated"]["message"].startswith("1 run(s): cancellation-not-propagated:")
    # agent-dec reads the negative the same way with --runs-dir
    index2 = CertificateIndex([root / "negative" / "cancellation-not-propagated" / "parent"], w3_trust_bundle(), flows_dir=w3_flows(),
                              methods=w3_methods(), runs_dirs=[root / "negative" / "cancellation-not-propagated"])
    vr = index2.verifier_result(root / "negative" / "cancellation-not-propagated" / "parent")
    assert vr.verdict == "not-clean" and [f[0] for f in vr.findings] == ["cancellation-not-propagated"]


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")
def test_children_resolved_from_runs_dir_or_unchecked(degrading_flow):
    root = w3_dec()
    parent_dir = root / "cancelled" / "parent"
    good = json.loads((parent_dir / "run.dec.json").read_text())
    runs = index_runs(spans(good["subject"]["run_id"], ["s1", "s2", "s3"]))
    # only the parent under --dec-dir, no --runs-dir: the child is unresolved and B14 unchecked (the parent stays convergent)
    index = CertificateIndex([parent_dir], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    r = evaluate(degrading_flow, runs, index)
    assert r["runs"][0]["reading"] == "convergent" and r["runs"][0]["children"][0]["status"] == "certificate-not-found (unchecked: no --runs-dir)"
    assert r["cross_run"] == {"children_checked": 0, "children_unresolved": 1}
    assert r["summary"]["unchecked"] == ["cancellation-not-propagated (B14): unchecked for 1 cancelled parent run(s) whose child certificate(s) "
                                        "were not found under --dec-dir and no --runs-dir was given"]
    # with --runs-dir the child resolves there
    index = CertificateIndex([parent_dir], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods(), runs_dirs=[root / "cancelled"])
    assert index.child_run_certificate(good["manifest"]["children"][0]["run_id"])[2] == "runs-dir"
    r = evaluate(degrading_flow, runs, index)
    assert r["runs"][0]["children"][0]["source"] == "runs-dir:run.dec.json" and r["cross_run"] == {"children_checked": 1, "children_unresolved": 0}
    # with --runs-dir pointing elsewhere the missing child is the finding
    index = CertificateIndex([parent_dir], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods(), runs_dirs=[root / "variants"])
    r = evaluate(degrading_flow, runs, index)
    assert r["runs"][0]["reading"] == "divergent" and r["runs"][0]["findings"][0]["reason_class"] == "certificate-not-found"
    with pytest.raises(ValueError, match="not a directory"):
        CertificateIndex([parent_dir], w3_trust_bundle(), runs_dirs=["/nonexistent/runs"])


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")
def test_runs_dir_through_the_gate(gate_inputs, tmp_path):
    from test_d15_assurance import otlp_export
    root = w3_dec()
    flows = tmp_path / "flows"
    flows.mkdir()
    (flows / "quote-issue.flow.yaml").write_bytes((w3_flows() / "quote-issue.flow.yaml").read_bytes())
    bad = json.loads((root / "negative" / "cancellation-not-propagated" / "parent" / "run.dec.json").read_text())
    export = otlp_export(tmp_path / "w.jsonl", index_runs(spans(bad["subject"]["run_id"], ["s1", "s2", "s3"])))
    common = dict(flows=str(flows), trust_bundle=str(w3_trust_bundle()), dec_dirs=[str(root / "negative" / "cancellation-not-propagated" / "parent")],
                  methods=str(w3_methods()), alerts=None, queries=[], telemetry=[str(export)])
    report, rc = run_gate(gate_inputs("full", runs_dirs=[str(root / "negative" / "cancellation-not-propagated")], **common))
    f = report["flows"][0]
    assert rc == 1 and "cancellation-not-propagated" in f["verdict_reasons"] and report["inputs"]["runs_dirs"] == ["cancellation-not-propagated"]
    assert f["conformance"]["cross_run"] == {"children_checked": 1, "children_unresolved": 0}
    with pytest.raises(GateUsageError, match="not found"):
        run_gate(gate_inputs("full", runs_dirs=[str(tmp_path / "nope")], **common))
    (tmp_path / "afile").write_text("x")
    with pytest.raises(GateUsageError, match="not a directory"):
        run_gate(gate_inputs("full", runs_dirs=[str(tmp_path / "afile")], **common))
