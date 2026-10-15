"""H4 — attempts of an effect step collapse into the declared step; attempts
beyond `attempts.max` follow `on_exceed`; reconciliation before retry (B17)
is read from agent-dec's step 1d (FTC §4.8; spec §7.5)."""
import copy
import json
import pathlib

import pytest

from conftest import w3_dec, w3_flows, w3_methods, w3_trust_bundle
from flowtrace.adapters.base import SpanRow
from flowtrace.conformance import _reading, evaluate, plan_reading
from flowtrace.coverage import CertificateIndex, index_runs
from flowtrace.evidence import VerifierRun, run_verifier, verifier_argv
from flowtrace.flows import Flow

PRIMARY = ["s1", "s2", "s3", "s4", "s5", "s6"]
KEY = "sha256:" + "ab" * 32


def attempt_entries(seq, attempts, via_last="primary"):
    """The primary path with `attempts` consecutive s6 entries sharing one idempotency key."""
    out = [{"step_id": s, "flow_step": s, "via": "primary"} for s in seq]
    for n in range(1, attempts + 1):
        out.append({"step_id": "s6", "flow_step": "s6", "via": "primary", "key": KEY, "attempt": n})
    return out


def spans(trace, seq, version="2.1.0"):
    """A chain of boundary spans; a consecutive repeat of a step is a sibling
    span under the same parent (a retry, not an interior span)."""
    out, prev, parent = [], None, None
    for i, step in enumerate(seq):
        sid = f"{trace}-{i}"
        p = parent if (out and out[-1].attributes["flow.step"] == step) else prev
        out.append(SpanRow(trace, sid, p, step, "SERVER", i * 10, i * 10 + 5, "OK",
                           {"flow.id": "quote-issue", "flow.version": version, "flow.step": step}))
        parent, prev = p, sid
    return out


# ----------------------------------------------------------------- the reading (manifest input)
def test_attempts_collapse_into_the_declared_step(degrading_flow):
    r = plan_reading(degrading_flow.doc, attempt_entries(PRIMARY[:5], 2), outcome="allow")
    assert r["reading"] == "convergent" and r["realized"] == PRIMARY and r["degraded"] == []
    (s6,) = [e for e in r["entries"] if e["flow_step"] == "s6"]
    assert s6["attempts"] == 2 and s6["last_attempt"] == 2
    # three attempts is the bound; the fourth follows on_exceed {outcome: error}
    assert plan_reading(degrading_flow.doc, attempt_entries(PRIMARY[:5], 3), outcome="allow")["reading"] == "convergent"
    r = plan_reading(degrading_flow.doc, attempt_entries(PRIMARY[:5], 4), outcome="error")
    assert r["reading"] == "convergent" and r["degraded"] == ["s6 -> outcome error (attempts.on_exceed after 4 attempts)"]
    r = plan_reading(degrading_flow.doc, attempt_entries(PRIMARY[:5], 4), outcome="allow")
    assert r["reading"] == "divergent" and r["divergent"] == [
        "attempts-exceeded: s6 ran 4 attempts > attempts.max 3 and the run did not end in the declared on_exceed outcome error (outcome: allow)"]
    # without a shared key the repeats are a divergent repetition, as before 2026-10-11
    rep = [{"step_id": s, "flow_step": s, "via": "primary"} for s in PRIMARY + ["s6"]]
    assert plan_reading(degrading_flow.doc, rep, outcome="allow")["divergent"][0].startswith("repeat: s6 ran 2 times")


def test_attempts_without_on_exceed_and_with_a_to_target(degrading_flow):
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"][5]["attempts"] = {"max": 1}
    r = plan_reading(doc, attempt_entries(PRIMARY[:5], 2), outcome="allow")
    assert r["reading"] == "divergent" and r["divergent"] == ["attempts-exceeded: s6 ran 2 attempts > attempts.max 1 (no on_exceed declared)"]
    doc["spec"]["steps"][5].pop("attempts")                      # effect: true without attempts: no bound, collapse still applies
    assert plan_reading(doc, attempt_entries(PRIMARY[:5], 5), outcome="allow")["reading"] == "convergent"
    # on_exceed {to}: the run must continue at that step via on_fail
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"].insert(5, {"id": "s5b", "component": "docs.render", "op": "fallback", "kind": "async", "next": ["s6"]})
    doc["spec"]["steps"][4]["next"] = ["s5b"]
    doc["spec"]["steps"][5]["on_fail"] = {"to": "s6"}
    doc["spec"]["steps"][6] = {"id": "s6", "component": "notify.customer", "op": "deliver", "kind": "async", "effect": True,
                               "attempts": {"max": 1, "on_exceed": {"to": "s5b"}}, "next": []}
    doc["spec"]["steps"][5]["next"] = ["s6"]
    ents = attempt_entries(PRIMARY[:5] + ["s5b"], 2) + [{"step_id": "s5b", "flow_step": "s5b", "via": "on_fail"}]
    r = plan_reading(doc, ents, outcome="allow")
    assert "attempts-exceeded" not in " ".join(r["divergent"])
    r = plan_reading(doc, attempt_entries(PRIMARY[:5] + ["s5b"], 2), outcome="allow")
    assert any(d.startswith("attempts-exceeded: s6 ran 2 attempts > attempts.max 1 and the run did not continue at the declared on_exceed step s5b") for d in r["divergent"])


CASES = [
    dict(realized=attempt_entries(PRIMARY[:5], 2), outcome="allow", termination="completed"),
    dict(realized=attempt_entries(PRIMARY[:5], 4), outcome="error"),
    dict(realized=attempt_entries(PRIMARY[:5], 4), outcome="allow"),
    dict(realized=[{"step_id": s, "flow_step": s, "via": "primary"} for s in PRIMARY + ["s6"]], outcome="allow"),
]


@pytest.mark.parametrize("case", CASES)
def test_local_reading_agrees_with_agent_dec_on_attempts(degrading_flow, case):
    vd = pytest.importorskip("agent_dec.verify_dec")
    assert _reading(degrading_flow.doc, **case) == vd.conformance_reading(degrading_flow.doc, **case)
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"][5]["attempts"] = {"max": 1}
    assert _reading(doc, **case) == vd.conformance_reading(doc, **case)


# ----------------------------------------------------------------- from spans
def test_span_attempts_collapse_and_b17_is_unchecked(degrading_flow):
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY + ["s6"])), None)
    run = r["runs"][0]
    assert run["reading"] == "convergent" and run["realized"] == PRIMARY[:5] + ["s6×2"] and run["via"] == ["primary"] * 6
    assert r["attempts"] == {"s6": {"runs_with_retries": 1, "max_attempts_seen": 2, "over_bound": 0, "unreconciled": 0}}
    assert "retry-without-reconciliation (B17): unchecked for 1 span-sourced run(s) (no certificates to read it from)" in r["summary"]["unchecked"]
    # four attempts from spans: on_exceed {outcome: error} read as taken, outcome unknown
    r = evaluate(degrading_flow, index_runs(spans("t1", PRIMARY + ["s6"] * 3)), None)
    run = r["runs"][0]
    assert run["reading"] == "convergent" and run["outcome"] == "unknown" and run["degraded"] == ["s6 -> outcome error (attempts.on_exceed after 4 attempts) [spans]"]
    assert r["attempts"]["s6"] == {"runs_with_retries": 1, "max_attempts_seen": 4, "over_bound": 0, "unreconciled": 0}
    # a bound without on_exceed: attempts-over-bound
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"][5]["attempts"] = {"max": 1}
    r = evaluate(Flow(degrading_flow.path, doc, "0" * 64), index_runs(spans("t1", PRIMARY + ["s6"])), None)
    assert r["runs"][0]["reading"] == "divergent" and r["attempts"]["s6"]["over_bound"] == 1
    # a repeated non-effect step is still a divergent repeat
    r = evaluate(degrading_flow, index_runs(spans("t1", ["s1", "s2", "s2", "s3", "s4", "s5", "s6"])), None)
    assert r["runs"][0]["reading"] == "divergent" and r["runs"][0]["divergent"][0].startswith("repeat: s2")
    assert not [u for u in r["summary"]["unchecked"] if u.startswith("retry-without-reconciliation")]


def test_attempts_block_absent_without_effect_steps(canon_flow):
    doc = copy.deepcopy(canon_flow.doc)
    for s in doc["spec"]["steps"]:
        s.pop("effect", None)
        s.pop("attempts", None)
    r = evaluate(Flow(canon_flow.path, doc, "0" * 64), index_runs(spans("t1", PRIMARY)), None)
    assert r["attempts"] == {} and r["summary"]["unchecked"] == []


# ----------------------------------------------------------------- the verifier bridge
def test_verifier_output_parsing(tmp_path, monkeypatch):
    import flowtrace.evidence as ev
    text = (
        "verifying x (7 step certificate(s) + 4 evidence artifact(s) + run certificate); keys: b\n"
        "  FAILED    chain-broken           step-s2.dec.json: chain.prev mismatch (expected sha256:…)\n"
        "  NOTE      completion-missing     step-s6.dec.json: effect step s6 attempt 1 has no completion evidence after it\n"
        "  FINDING   retry-without-reconciliation step-s6.attempt-2.dec.json: attempt 2 of s6 is not preceded by a completion for attempt 1 with status failed | reconciled (binding B17; completions seen for attempt 1: unknown)\n"
        "flow binding (step 1b): internal FB1-FB3 passed; registry half FB4 UNCHECKED (no --flow-registry)\n"
        "claims (step 1c): 2 claim(s) on 1 certificate(s): 2 checked, 0 UNCHECKED (path-level without disclosure), 0 finding(s)\n"
        "effect evidence (step 1d): (a) authorization checked on 2 effect step(s); freshness (B16) UNCHECKED (no declaration of max_decision_age_s); (b) approval: no decision cites a human_approval; (d) completion/attempts checked on 2 effect step(s)\n"
        "grants and children (step 1d(c)): (c) grant agreement (B13) checked on 9 member(s)\n"
        "\nRUN VERDICT: NOT CLEAN — evidence verified (run 7b16, 7 steps, chain intact, all signatures valid); 1 finding(s) from steps 1c/1d: retry-without-reconciliation\n")

    class FakeVd:
        @staticmethod
        def main(argv):
            print(text, end="")
            return 3

    monkeypatch.setitem(__import__("sys").modules, "agent_dec.verify_dec", FakeVd)
    monkeypatch.setitem(__import__("sys").modules, "agent_dec", type("M", (), {"verify_dec": FakeVd}))
    vr = ev.run_verifier(tmp_path, ["--dir", str(tmp_path)])
    assert vr.exit_code == 3 and vr.verdict == "not-clean" and vr.ok
    assert vr.findings == [("retry-without-reconciliation", "step-s6.attempt-2.dec.json",
                            "attempt 2 of s6 is not preceded by a completion for attempt 1 with status failed | reconciled (binding B17; completions seen for attempt 1: unknown)")]
    assert vr.findings_for("step-s6.attempt-2.dec.json")[0][0] == "retry-without-reconciliation" and vr.findings_for("step-s1.dec.json") == []
    assert vr.notes == [("completion-missing", "step-s6.dec.json", "effect step s6 attempt 1 has no completion evidence after it")]
    assert vr.failed == [("chain-broken", "step-s2.dec.json", "chain.prev mismatch (expected sha256:…)")]
    assert vr.unchecked == ["step 1b: registry half FB4 UNCHECKED (no --flow-registry)",
                            "step 1d: freshness (B16) UNCHECKED (no declaration of max_decision_age_s)"]
    assert set(vr.summaries) == {"step 1b", "step 1c", "step 1d", "step 1d(c)"}
    assert verifier_argv(pathlib.Path("r"), trust_bundle=pathlib.Path("b"), flows_dir=pathlib.Path("f"), methods=None,
                         approvals=pathlib.Path("a"), runs_dirs=[pathlib.Path("c")]) == [
        "--dir", "r", "--trust-bundle", "b", "--flow-registry", "f", "--approvals", "a", "--runs-dir", "c"]
    assert VerifierRun(tmp_path).ok is False


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available (examples/dec or an agent-dec checkout)")
def test_b17_from_agent_dec_on_the_signed_examples(degrading_flow):
    """The retry-without-reconciliation negative reads divergent with the
    verifier's finding; the reconciled variant reads convergent and clean."""
    root, bundle, flows, methods = w3_dec(), w3_trust_bundle(), w3_flows(), w3_methods()
    index = CertificateIndex([root], bundle, flows_dir=flows, methods=methods)
    neg = root / "negative" / "retry-without-reconciliation"
    vr = index.verifier_result(neg)
    assert vr.verdict == "not-clean" and vr.exit_code == 3 and [f[0] for f in vr.findings] == ["retry-without-reconciliation"]
    run_id = json.loads((neg / "run.dec.json").read_text())["subject"]["run_id"]
    # the window holds that run (trace id = run id); the same run id is claimed by the reconciled variant's
    # certificate too, so the trigger span names the negative's by dec.run_cert_digest (B6): its manifest is the
    # realized DAG, s6×2, divergent by B17
    digest = next(d for d, (p, c) in index.runs.items() if p == neg / "run.dec.json")
    sp = spans(run_id, PRIMARY + ["s6"])
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": digest}))
    r = evaluate(degrading_flow, index_runs(sp), index)
    run = r["runs"][0]
    assert run["source"] == "manifest:run.dec.json" and run["realized"] == PRIMARY[:5] + ["s6×2"]
    assert run["reading"] == "divergent" and run["divergent"] == [f"retry-without-reconciliation: {vr.findings[0][2]}"]
    assert run["findings"] == [{"code": "retry-without-reconciliation", "step": "s6", "attempt_id": 2,
                                "file": "step-s6.attempt-2.dec.json", "reason": vr.findings[0][2]}]
    assert r["attempts"]["s6"] == {"runs_with_retries": 1, "max_attempts_seen": 2, "over_bound": 0, "unreconciled": 1}
    assert r["summary"]["non_convergent_runs"] == 1 and r["summary"]["unchecked"] == []
    # the reconciled variant: attempt 1 unknown -> reconciled, no attempt 2; clean
    var = root / "variants" / "s6-reconciled"
    vr = index.verifier_result(var)
    assert vr.verdict == "verified" and vr.exit_code == 0 and vr.findings == []
    run_id = json.loads((var / "run.dec.json").read_text())["subject"]["run_id"]
    # the same run id as the negative is claimed by two certificates: name the variant's on the trigger span
    digest = next(d for d, (p, c) in index.runs.items() if p == var / "run.dec.json")
    sp = spans(run_id, PRIMARY)
    sp[0] = SpanRow(sp[0].trace_id, sp[0].span_id, None, "s1", "SERVER", 0, 5, "OK", dict(sp[0].attributes, **{"dec.run_cert_digest": digest}))
    r = evaluate(degrading_flow, index_runs(sp), index)
    run = r["runs"][0]
    assert run["source"] == "manifest:run.dec.json" and run["reading"] == "convergent" and run["findings"] == [] and run["realized"] == PRIMARY
    assert r["attempts"]["s6"] == {"runs_with_retries": 0, "max_attempts_seen": 1, "over_bound": 0, "unreconciled": 0}


@pytest.mark.skipif(w3_dec() is None, reason="the 2026-10-11 signed example set is not available")
def test_verifier_is_called_once_per_run_directory(degrading_flow):
    root = w3_dec()
    index = CertificateIndex([root], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    a = index.verifier_result(root)
    b = index.verifier_result(root)
    assert a is b and a.verdict == "verified" and a.findings == []
    assert index.methods is not None and index.methods.is_dir()
