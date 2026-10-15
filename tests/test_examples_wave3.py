"""The running example at 2.1.0 across the repository: the descriptor's bytes,
the vendored signed example set, and the seven synthetic windows read end to
end (the cross-field tests of the revision of 2026-10-11)."""
import hashlib
import json

import pytest
import yaml

from conftest import CANON, CANON_SHA256, CERTIFIED_RUN, DEC_DIR, EXPECTED, FIXTURES, TRUST_BUNDLE, WINDOWS, telemetry
from flowtrace.coverage import CertificateIndex


def test_descriptor_is_the_canon_block_at_2_1_0():
    raw = CANON.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == CANON_SHA256 == hashlib.sha256((FIXTURES / "quote-issue.canon.yaml").read_bytes()).hexdigest()
    doc = yaml.safe_load(raw)
    assert doc["metadata"]["version"] == "2.1.0" and doc["spec"]["outcomes"] == ["allow", "block", "clarify", "review", "error"]
    steps = {s["id"]: s for s in doc["spec"]["steps"]}
    assert steps["s3"]["on_fail"] == {"outcome": "review"} and steps["s4"]["on_fail"] == {"outcome": "block"}
    assert steps["s5"]["on_fail"] == {"to": "s6", "latch": True} and steps["s6"]["effect"] is True
    assert steps["s6"]["attempts"] == {"max": 3, "on_exceed": {"outcome": "error"}}
    assert doc["spec"]["cancel_propagation_s"] == 30 and doc["spec"]["max_decision_age_s"] == 300
    assert doc["spec"]["telemetry"]["sampling_floor"] == 0.10 and doc["spec"]["telemetry"]["assurance_sampling_floor"] == 1.0
    assert [a["class"] for a in steps["s4"]["required_telemetry"]["traces"][0]["required_attributes"]] == ["identifier"] * 4
    assert steps["s4"]["method"]["digest"] == "sha256:fad9362bcab1866e2e08bfb0f98c5a199b01b231ad13b855dcee86444e43d6b6"


def test_descriptor_validates_under_polydiagram_r1_r15(canon_flow):
    pytest.importorskip("polydiagram")
    assert canon_flow.warnings == [] and canon_flow.version == "2.1.0"
    assert canon_flow.effect_steps == ["s6"] and canon_flow.replayable_steps == ["s4"] and canon_flow.declares_assurance_stream


def test_method_artifact_is_byte_exact():
    p = DEC_DIR.parent / "methods" / "limits-check-3.1.0.json"
    assert hashlib.sha256(p.read_bytes()).hexdigest() == "fad9362bcab1866e2e08bfb0f98c5a199b01b231ad13b855dcee86444e43d6b6"


# ----------------------------------------------------------------- the windows, as the gate reads them
@pytest.fixture(scope="module")
def reports():
    return {w: json.loads((EXPECTED / f"quote-issue.{w}.json").read_text())["flows"][0] for w in WINDOWS}


def certified(report):
    (run,) = [r for r in report["conformance"]["runs"] if r["source"] != "spans"]
    return run


def codes(report, severity=None):
    return {f["code"] for f in report["findings"] if severity is None or f["severity"] == severity}


def test_windows_verdicts(reports):
    assert {w: r["verdict"] for w, r in reports.items()} == {
        "full": "pass", "s5-degraded": "pass", "s6-unknown-reconciled": "pass",
        "s5-silent": "fail", "s4-missing-attr": "fail", "s6-retry-unreconciled": "fail", "cancelled-child-late": "fail"}
    for w, r in reports.items():
        assert r["version"] == "2.1.0" and r["streams"]["assurance"]["declared_floor"] == 1.0 and r["effective_sampling"] == 1.0
        assert r["conformance"]["summary"]["manifest_runs"] == 1 and r["runs_sampled"] == 32
        assert r["slis"]["degradation_rate"]["band"] == {"min": 0.0, "max": 0.25, "gate": False}
        assert r["slis"]["veto_rate"]["band"] == {"min": 0.0, "max": 0.1, "gate": False}
        assert "attribute-class-assumed" not in codes(r)
        assert any(u.startswith("effect-without-authorization (B10): unchecked for 31") for u in r["conformance"]["summary"]["unchecked"])


def test_full_window(reports):
    r = reports["full"]
    assert r["score"] == 1.0 and codes(r, "fail") == set()
    ee = r["components"]["execution_evidence"]
    assert ee["certificate_coverage"] == 1.0 and ee["authorization_coverage"] == 1.0 and ee["score"] == 1.0
    assert ee["steps"]["s4"]["evidence_types"] == {"replay_recipe": 32} and ee["authorization"]["s6"]["statuses"] == {"verified": 32}
    assert ee["authorization"]["s6"]["completion_status"] == {"completed": 32} and ee["authorization"]["s6"]["run_binding_mismatches"] == 31
    assert r["components"]["detectability"]["targets"][-2:][0]["slo"] == "degradation_rate" and all(t["detectable"] for t in r["components"]["detectability"]["targets"])
    run = certified(r)
    assert run["trace_id"] == CERTIFIED_RUN and run["outcome"] == "allow" and run["termination"] == "completed" and run["degraded"] == []
    assert run["via"] == ["primary"] * 6 and run["findings"] == [] and run["approximate"] is False
    assert r["slis"]["degradation_rate"]["rate"] == 0.0 and r["slis"]["veto_rate"]["rate"] == 0.0 and r["slis"]["degradation_rate"]["source"] == "mixed"
    assert r["slis"]["degradation_rate"]["notes"][0].startswith("shared-target: s5 -> s6")


def test_degraded_window_is_convergent_by_declaration(reports):
    r = reports["s5-degraded"]
    assert r["score"] == 1.0 and r["conformance"]["summary"]["by_reading"]["convergent"] == 32
    run = certified(r)
    assert run["trace_id"] == "6a1f4b7a721e678ee41e3d5b4c73d5c8" and run["via"][-1] == "on_fail" and run["realized"][-1] == "->s6"
    assert run["degraded"] == ["s5 -> s6 (on_fail, latched)"] and run["reading"] == "convergent"
    assert r["slis"]["degradation_rate"] == {"rate": 0.03125, "band": {"min": 0.0, "max": 0.25, "gate": False}, "source": "mixed",
                                             "approximate": True, "runs": 32, "degraded_runs": 1, "out_of_band": None,
                                             "notes": r["slis"]["degradation_rate"]["notes"]}
    assert r["slis"]["degradation_rate"]["notes"] and "the manifest is the exact source" in r["slis"]["degradation_rate"]["notes"][0]
    assert r["observed_slos"]["flow"]["availability"] == 0.0            # every run's s5 failed (status ERROR) before degrading
    assert "sli-out-of-band" not in codes(r)


def test_reconciled_window(reports):
    r = reports["s6-unknown-reconciled"]
    assert r["score"] == 1.0 and r["verdict"] == "pass"
    run = certified(r)
    assert run["trace_id"] == "7b16047223ba04ca17ea1ca09e68d09f" and run["realized"] == ["s1", "s2", "s3", "s4", "s5", "s6"] and run["findings"] == []
    ee = r["components"]["execution_evidence"]["authorization"]["s6"]
    assert ee["completion_status"] == {"reconciled": 32} and ee["statuses"] == {"verified": 32}
    assert r["conformance"]["attempts"]["s6"] == {"runs_with_retries": 0, "max_attempts_seen": 1, "over_bound": 0, "unreconciled": 0}


def test_retry_window_is_divergent_by_b17(reports):
    r = reports["s6-retry-unreconciled"]
    assert r["score"] == 1.0 and r["verdict"] == "fail" and codes(r, "fail") == {"non-convergent-runs", "retry-without-reconciliation"}
    run = certified(r)
    assert run["trace_id"] == "7b16047223ba04ca17ea1ca09e68d09f" and run["realized"] == ["s1", "s2", "s3", "s4", "s5", "s6×2"]
    assert run["reading"] == "divergent" and run["findings"][0]["code"] == "retry-without-reconciliation" and run["findings"][0]["attempt_id"] == 2
    assert r["conformance"]["attempts"]["s6"] == {"runs_with_retries": 32, "max_attempts_seen": 2, "over_bound": 0, "unreconciled": 1}
    assert any(u.startswith("retry-without-reconciliation (B17): unchecked for 31") for u in r["conformance"]["summary"]["unchecked"])
    spans = [x for x in r["conformance"]["runs"] if x["source"] == "spans"]
    assert all(x["realized"][-1] == "s6×2" and x["reading"] == "convergent" for x in spans)


def test_cancelled_window_is_divergent_by_b14(reports):
    r = reports["cancelled-child-late"]
    assert r["verdict"] == "fail" and {"non-convergent-runs", "cancellation-not-propagated"} <= codes(r, "fail")
    run = certified(r)
    assert run["trace_id"] == "2d5ba81bc8e4ccda198dbecb757b18d1" and run["termination"] == "cancelled" and run["realized"] == ["s1", "s2", "s3"]
    assert run["absent"] == [] and run["reading"] == "divergent"
    assert run["children"] == [{"run_id": "fcc6c3a32bb029fc6a73fb121b414e79", "task_grant_commitment": run["children"][0]["task_grant_commitment"],
                                "status": "late", "termination": "completed", "closed_at": "2026-10-15T07:19:28Z", "source": "dec-dir:run.dec.json"}]
    assert run["findings"][0]["reason_class"] == "late" and run["findings"][0]["child_run_id"] == "fcc6c3a32bb029fc6a73fb121b414e79"
    assert r["conformance"]["cross_run"] == {"children_checked": 1, "children_unresolved": 0}
    (f,) = [x for x in r["findings"] if x["code"] == "cancellation-not-propagated"]
    assert "closed (completed) at 2026-10-15T07:19:28Z" in f["message"] and "cancel_propagation_s 30" in f["message"]
    assert r["components"]["completeness"]["runs_complete"] == 31                   # the cancelled parent ran s1..s3 only


def test_regression_windows(reports):
    silent, missing = reports["s5-silent"], reports["s4-missing-attr"]
    assert silent["score"] == pytest.approx(0.633333, abs=1e-6) and silent["components"]["completeness"]["blind_spots"] == ["s5"]
    assert silent["conformance"]["summary"]["by_reading"] == {"convergent": 1, "absent": 31, "divergent": 0, "failed-run": 0}
    assert missing["score"] == pytest.approx(0.4) and missing["components"]["answerability"]["scenarios"][0]["status"] == "unanswerable"
    assert missing["components"]["answerability"]["scenarios"][0]["stream"] == "assurance"
    assert missing["components"]["completeness"]["by_step"]["s4"]["missing"] == {"span risk.limits-check/evaluate lacks required attribute risk.decision": 32}


# ----------------------------------------------------------------- the digests the spans carry
def span_attrs(window):
    out = {}
    for line in telemetry(window).read_text(encoding="utf-8").splitlines():
        req = json.loads(line)
        for rs in req.get("resourceSpans", []):
            for ss in rs["scopeSpans"]:
                for sp in ss["spans"]:
                    a = {kv["key"]: kv["value"].get("stringValue") for kv in sp["attributes"]}
                    out.setdefault(sp["traceId"], []).append(a)
    return out


@pytest.mark.parametrize("window", WINDOWS)
def test_evidence_digests_on_spans_resolve_to_the_signed_artifacts(window):
    index = CertificateIndex([DEC_DIR], TRUST_BUNDLE)
    attrs = span_attrs(window)
    certified_trace = next(t for t, spans in attrs.items() if any("dec.run_cert_digest" in a for a in spans))
    (run_digest,) = {a["dec.run_cert_digest"] for a in attrs[certified_trace] if "dec.run_cert_digest" in a}
    path, run_cert = index.runs[run_digest]
    assert run_cert["subject"]["trace_id"] == certified_trace
    manifest = {}
    for m in run_cert["manifest"]["steps"]:
        manifest.setdefault(m["flow_step"], []).append(m["cert_digest"])
    for trace, spans in attrs.items():
        by_step = {}
        for a in spans:
            if "dec.step_cert_digest" in a:
                by_step.setdefault(a["flow.step"], []).append(a)
        for sid, rows in by_step.items():
            digests = [a["dec.step_cert_digest"] for a in rows]
            src = manifest if (trace == certified_trace or window != "cancelled-child-late") else None
            if src is not None:
                assert digests == src[sid], (window, trace, sid)
            for a in rows:
                if sid == "s6":
                    authz = index.authorizations[a["dec.authz_cert_digest"]][1]
                    comp = index.completions[a["dec.completion_cert_digest"]][1]
                    assert authz["subject"]["step_id"] == "s6" and comp["subject"]["step_id"] == "s6"
                    assert authz["subject"]["attempt_id"] == comp["subject"]["attempt_id"]
                    assert "dec.approval_digest" not in a
    assert all(a["flow.version"] == "2.1.0" for spans in attrs.values() for a in spans)
