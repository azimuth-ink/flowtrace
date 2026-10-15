"""D15 — attribute classes and the assurance stream (DECISION-R), the effective
floors, the second export, and authorization coverage for effect steps
(FTC §4.4, §4.5, §4.7; spec §2.4, §4.1, §6.6)."""
import copy
import json

import pytest
import yaml

from conftest import DEGRADING_FLOW, QUERIES, telemetry, w3_dec, w3_flows, w3_methods, w3_trust_bundle
from flowtrace.adapters.base import CANONICAL_ATTRIBUTES, EFFECT_STEP_ATTRIBUTES, SpanRow
from flowtrace.adapters.otlp_duckdb import OtlpDuckDBAdapter
from flowtrace.answerability import evaluate as evaluate_answerability, load_query_bindings, scenario_stream
from flowtrace.coverage import (CertificateIndex, classified_attributes, content_attributes, evaluate_completeness,
                                evaluate_execution_evidence, index_runs, resolve_attribute_class)
from flowtrace.flows import Flow, attribute_entries, required_attribute_names
from flowtrace.gate import GateUsageError, Streams, effective_floors, evaluate_flow, run_gate
from flowtrace.tiering import policy

PRIMARY = ["s1", "s2", "s3", "s4", "s5", "s6"]


def span(trace, sid, step, parent=None, start=0, end=10, name=None, version="2.1.0", **attrs):
    base = {"flow.id": "quote-issue", "flow.version": version, "flow.step": step}
    base.update(attrs)
    return SpanRow(trace, sid, parent, name or f"{step}-span", "SERVER", start, end, "OK", base)


# ----------------------------------------------------------------- the namespace table and class resolution
def test_namespace_table_names_the_three_effect_step_digests():
    assert EFFECT_STEP_ATTRIBUTES == ("dec.authz_cert_digest", "dec.completion_cert_digest", "dec.approval_digest")
    assert all(CANONICAL_ATTRIBUTES[a] == "digest" for a in EFFECT_STEP_ATTRIBUTES)
    assert CANONICAL_ATTRIBUTES["dec.step_cert_digest"] == "digest" and CANONICAL_ATTRIBUTES["flow.step"] == "identifier"
    assert "flow.segment.id" not in CANONICAL_ATTRIBUTES and "flow.priority" not in CANONICAL_ATTRIBUTES


def test_attribute_entries_both_forms(degrading_flow, canon_flow):
    spec = degrading_flow.step("s4")["required_telemetry"]["traces"][0]
    assert attribute_entries(spec) == [{"name": "flow.id", "class": "identifier"}, {"name": "flow.step", "class": "identifier"},
                                       {"name": "risk.limit_id", "class": "identifier"}, {"name": "risk.decision", "class": "identifier"}]
    spec = canon_flow.step("s4")["required_telemetry"]["traces"][0]
    names = required_attribute_names(spec)
    assert names == ["flow.id", "flow.step", "risk.limit_id", "risk.decision"]
    assert attribute_entries({"required_attributes": ["a", {"name": "b"}, {"name": "c", "class": "content"}, {"nope": 1}, ""]}) == [
        {"name": "a", "class": None}, {"name": "b", "class": None}, {"name": "c", "class": "content"}]


def test_resolve_attribute_class_declared_namespace_assumed():
    assert resolve_attribute_class("risk.decision", "content") == ("content", "declared")
    assert resolve_attribute_class("flow.id", None) == ("identifier", "namespace")              # the canonical table
    assert resolve_attribute_class("dec.authz_cert_digest", None) == ("digest", "namespace")
    assert resolve_attribute_class("dec.anything", None) == ("digest", "namespace")             # attribute_classes.namespace_defaults
    assert resolve_attribute_class("flow.anything", None) == ("identifier", "namespace")
    assert resolve_attribute_class("risk.decision", None) == ("identifier", "assumed")
    assert resolve_attribute_class("risk.decision", None, {"risk.*": "content"}) == ("content", "namespace")
    assert resolve_attribute_class("risk.decision", None, {}) == ("identifier", "assumed")
    assert resolve_attribute_class("x", "bogus") == ("identifier", "assumed")


def test_classified_attributes_and_streams(degrading_flow, canon_flow):
    c = classified_attributes(degrading_flow)
    assert [(r["name"], r["class"], r["class_source"], r["stream"]) for r in c["s4"]] == [
        ("flow.id", "identifier", "declared", "assurance"), ("flow.step", "identifier", "declared", "assurance"),
        ("risk.limit_id", "identifier", "declared", "assurance"), ("risk.decision", "identifier", "declared", "assurance")]
    assert c["s1"] == [] and content_attributes(degrading_flow) == {sid: set() for sid in PRIMARY}
    c = classified_attributes(canon_flow)
    assert [(r["name"], r["class_source"]) for r in c["s4"]] == [("flow.id", "namespace"), ("flow.step", "namespace"),
                                                                 ("risk.limit_id", "assumed"), ("risk.decision", "assumed")]
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"][3]["required_telemetry"]["traces"][0]["required_attributes"].append({"name": "risk.rationale", "class": "content"})
    f = Flow(degrading_flow.path, doc, "0" * 64)
    assert content_attributes(f)["s4"] == {"risk.rationale"}
    assert classified_attributes(f)["s4"][-1]["stream"] == "sampled"


# ----------------------------------------------------------------- completeness over the two streams
def content_flow(degrading_flow):
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["steps"][3]["required_telemetry"]["traces"][0]["required_attributes"].append({"name": "risk.rationale", "class": "content"})
    doc["spec"]["steps"][3]["required_telemetry"].pop("metrics")
    doc["spec"]["steps"] = [doc["spec"]["steps"][3]]
    doc["spec"]["steps"][0]["next"] = []
    return Flow(degrading_flow.path, doc, "0" * 64)


def s4(trace, **attrs):
    return span(trace, f"{trace}-4", "s4", name="risk.limits-check/evaluate", **{"risk.limit_id": "L1", "risk.decision": "approve", **attrs})


def test_content_attribute_read_from_the_sampled_stream(degrading_flow):
    f = content_flow(degrading_flow)
    # one export: the content attribute is read from the same runs
    runs = index_runs([s4("a", **{"risk.rationale": "within limit"}), s4("b")])
    r = evaluate_completeness(f, runs, [], [])
    assert r["score"] == 0.5 and r["by_step"]["s4"]["missing"] == {"span risk.limits-check/evaluate lacks required attribute risk.rationale (content; sampled stream)": 1}
    assert [a["stream"] for a in r["by_step"]["s4"]["attributes"]] == ["assurance"] * 4 + ["sampled"]
    # two exports: the assurance stream carries no content; the sampled stream holds a subset of the runs
    assurance = index_runs([s4("a"), s4("b"), s4("c")])
    sampled = index_runs([s4("a", **{"risk.rationale": "within limit"}), s4("b")])
    r = evaluate_completeness(f, assurance, [], [], sampled_runs=sampled, assurance_export_distinct=True)
    assert r["runs_sampled"] == 3 and r["runs_complete"] == 2                      # a: complete; b: content missing; c: not evaluated
    assert r["by_step"]["s4"]["not_evaluated"] == {"risk.rationale": 1} and r["content_on_assurance"] == []
    # content carried on the assurance export: reported, not inspected
    assurance = index_runs([s4("a", **{"risk.rationale": "leaked"}), s4("b")])
    r = evaluate_completeness(f, assurance, [], [], sampled_runs=sampled, assurance_export_distinct=True)
    assert r["content_on_assurance"] == [{"step": "s4", "attribute": "risk.rationale", "runs": 1}]
    assert r["class_assumed"] == []


# ----------------------------------------------------------------- answerability streams
def test_scenario_stream_binding_wins_over_the_heuristic():
    sc = {"scenario": "x", "required_data": ["decision by version", "the rationale text (risk.rationale)"]}
    assert scenario_stream(sc, None, {"risk.rationale"}) == "sampled"
    assert scenario_stream(sc, None, set()) == "assurance"
    assert scenario_stream(sc, "assurance", {"risk.rationale"}) == "assurance"
    assert scenario_stream({"scenario": "y"}, "sampled", None) == "sampled"
    assert scenario_stream({"scenario": "y", "required_data": None}, None, {"a"}) == "assurance"


def test_answerability_reads_the_declared_stream(degrading_flow, tmp_path):
    class Rec:
        name, dialects, ingest_warnings = "rec", frozenset({"otel-sql"}), []

        def __init__(self, label):
            self.label, self.calls = label, []

        def query(self, dialect, text, window):
            from flowtrace.adapters.base import QueryResult
            self.calls.append(text)
            return QueryResult(("n",), ((1,),))
    assurance, sampled = Rec("assurance"), Rec("sampled")
    f = content_flow(degrading_flow)
    f.doc["spec"]["steps"][0]["debug_scenarios"].append({"scenario": "Rationale review", "required_data": ["risk.rationale per decision"],
                                                         "verification_query": "SELECT 1 AS n"})
    p = tmp_path / "q.yaml"
    p.write_text("apiVersion: flowtrace.queries/v0.1\nbindings:\n"
                 "  - {flow: quote-issue, step: s4, scenario: \"Limit evaluated against stale reference data\", dialect: otel-sql, text: \"SELECT 2 AS n\", stream: assurance}\n")
    res = evaluate_answerability(f, assurance, None, load_query_bindings([p]), "otel-sql", True, sampled_adapter=sampled,
                                 sampled_window=None, content_attributes=content_attributes(f))
    assert [(s.scenario, s.stream, s.status) for s in res.scenarios] == [
        ("Limit evaluated against stale reference data", "assurance", "answerable"), ("Rationale review", "sampled", "answerable")]
    assert assurance.calls == ["SELECT 2 AS n"] and sampled.calls == ["SELECT 1 AS n"]
    p.write_text("apiVersion: flowtrace.queries/v0.1\nbindings:\n  - {flow: f, step: s, scenario: x, dialect: d, text: t, stream: elsewhere}\n")
    with pytest.raises(ValueError, match="stream"):
        load_query_bindings([p])
    # the shipped binding file carries no stream and still validates against the schema
    from jsonschema import Draft202012Validator
    from conftest import REPO
    schema = json.loads((REPO / "spec" / "schemas" / "verification-query.schema.json").read_text())
    v = Draft202012Validator(schema)
    assert list(v.iter_errors(yaml.safe_load(QUERIES.read_text()))) == []
    assert list(v.iter_errors({"apiVersion": "flowtrace.queries/v0.1", "bindings": [{"flow": "f", "step": "s", "index": 0, "dialect": "d", "text": "t", "stream": "sampled"}]})) == []
    assert list(v.iter_errors({"apiVersion": "flowtrace.queries/v0.1", "bindings": [{"flow": "f", "step": "s", "index": 0, "dialect": "d", "text": "t", "stream": "x"}]})) != []


# ----------------------------------------------------------------- effective floors (spec §2.4)
def test_effective_floors(degrading_flow, canon_flow, cfg):
    p0 = policy(cfg, "P0")
    assert effective_floors(degrading_flow, p0) == {"assurance": 1.0, "sampled": 0.1, "declared_assurance_floor": 1.0, "declared_sampling_floor": 0.1}
    assert effective_floors(canon_flow, p0) == {"assurance": 1.0, "sampled": 1.0, "declared_assurance_floor": None, "declared_sampling_floor": 0.1}
    doc = copy.deepcopy(degrading_flow.doc)
    doc["metadata"]["criticality"] = "P2"
    doc["spec"]["telemetry"]["assurance_sampling_floor"] = 0.3
    assert effective_floors(Flow(degrading_flow.path, doc, "0" * 64), policy(cfg, "P2"))["assurance"] == 0.5     # the tier's 0.5 wins


def gate_flow(flow, cfg, window, **over):
    kw = dict(alerts=None, bindings=[], index=None, exec_enabled=False, sampling_rate=1.0, baseline_flow=None)
    kw.update(over)
    adapter = OtlpDuckDBAdapter([window])
    return evaluate_flow(flow, adapter, adapter.extent(), cfg, **kw)


def test_floor_findings_with_a_declared_assurance_stream(degrading_flow, canon_flow, cfg, tmp_path):
    w = _window_210(tmp_path)
    adapter = OtlpDuckDBAdapter([w])
    win = adapter.extent()
    # a P0 flow assured at 1.0 may sample its full telemetry at 0.10: no finding
    s = Streams(adapter, win, adapter, win, 1.0, 0.1, ["w"], ["w"])
    r = evaluate_flow(degrading_flow, adapter, win, cfg, alerts=None, bindings=[], index=None, exec_enabled=False, sampling_rate=0.1,
                      baseline_flow=None, streams=s)
    codes = {f["code"] for f in r["findings"]}
    assert not codes & {"sampling-below-floor", "assurance-sampling-below-floor", "assurance-floor-below-sampling-floor"}
    assert r["effective_sampling"] == 1.0 and r["streams"]["assurance"]["effective_floor"] == 1.0 and r["streams"]["sampled"]["effective_floor"] == 0.1
    # the assurance stream below its floor
    s = Streams(adapter, win, adapter, win, 0.5, 0.1, ["w"], ["w"])
    r = evaluate_flow(degrading_flow, adapter, win, cfg, alerts=None, bindings=[], index=None, exec_enabled=False, sampling_rate=0.1,
                      baseline_flow=None, streams=s)
    assert {f["code"] for f in r["findings"] if f["severity"] == "fail"} == {"assurance-sampling-below-floor"} and r["verdict"] == "fail"
    # the sampled stream below the flow's own floor
    s = Streams(adapter, win, adapter, win, 1.0, 0.05, ["w"], ["w"])
    r = evaluate_flow(degrading_flow, adapter, win, cfg, alerts=None, bindings=[], index=None, exec_enabled=False, sampling_rate=0.05,
                      baseline_flow=None, streams=s)
    assert {f["code"] for f in r["findings"] if f["severity"] == "fail"} == {"sampling-below-floor"}
    # a descriptor that reached the engine unvalidated: assurance floor below sampling floor
    doc = copy.deepcopy(degrading_flow.doc)
    doc["spec"]["telemetry"]["assurance_sampling_floor"] = 0.05
    bad = Flow(degrading_flow.path, doc, "0" * 64)
    s = Streams(adapter, win, adapter, win, 1.0, 1.0, ["w"], ["w"])
    r = evaluate_flow(bad, adapter, win, cfg, alerts=None, bindings=[], index=None, exec_enabled=False, sampling_rate=1.0, baseline_flow=None, streams=s)
    assert "assurance-floor-below-sampling-floor" in {f["code"] for f in r["findings"] if f["severity"] == "fail"}
    # without an assurance stream the single-stream rule of 2.3 applies (tier floor 1.0 for P0)
    r = gate_flow(canon_flow, cfg, telemetry("full"), sampling_rate=0.5)
    assert {f["code"] for f in r["findings"] if f["severity"] == "fail"} == {"sampling-below-floor"} and r["effective_sampling"] == 0.5
    assert r["streams"]["distinct_exports"] is False and r["streams"]["assurance"]["declared_floor"] is None


def test_attribute_class_assumed_finding_only_without_declared_classes(degrading_flow, canon_flow, cfg, tmp_path):
    r = gate_flow(canon_flow, cfg, telemetry("full"))
    (w,) = [f for f in r["findings"] if f["code"] == "attribute-class-assumed"]
    assert w["severity"] == "warn" and "s4:risk.decision, s4:risk.limit_id" in w["message"]
    off = copy.deepcopy(cfg)
    off["attribute_classes"]["warn_on_assumed"] = False
    assert not [f for f in gate_flow(canon_flow, off, telemetry("full"))["findings"] if f["code"] == "attribute-class-assumed"]
    r = gate_flow(degrading_flow, cfg, _window_210(tmp_path))
    assert not [f for f in r["findings"] if f["code"] == "attribute-class-assumed"]


def _window_210(tmp_path, name="full"):
    src = telemetry(name).read_text(encoding="utf-8")
    out = tmp_path / f"{name}-2.1.0.otlp.jsonl"
    out.write_text(src.replace('{"key":"flow.version","value":{"stringValue":"2.0.0"}}', '{"key":"flow.version","value":{"stringValue":"2.1.0"}}'))
    return out


# ----------------------------------------------------------------- the second export through the gate
def test_gate_with_a_separate_assurance_export(gate_inputs, tmp_path):
    full = str(telemetry("full"))
    report, rc = run_gate(gate_inputs("full", assurance_telemetry=[full], assurance_sampling_rate=1.0, sampling_rate=0.1))
    f = report["flows"][0]
    # the 2.0.0 descriptor declares no assurance stream: one stream, tier floor 1.0, the sampled rate 0.1 fails it
    assert rc == 1 and f["streams"]["distinct_exports"] is True and f["streams"]["assurance"]["source"] == ["quote-issue.full.otlp.jsonl"]
    assert report["inputs"]["assurance_telemetry"] == ["quote-issue.full.otlp.jsonl"] and len(report["inputs"]["assurance_telemetry_sha256"]) == 1
    assert {x["code"] for x in f["findings"] if x["severity"] == "fail"} == {"sampling-below-floor"}
    assert f["components"]["completeness"]["score"] == 1.0
    # non-overlapping windows are a load error (exit 2)
    shifted = tmp_path / "shifted.otlp.jsonl"
    import re
    text = telemetry("full").read_text(encoding="utf-8")
    shifted.write_text(re.sub(r'"(startTimeUnixNano|endTimeUnixNano|timeUnixNano)":"(\d+)"',
                              lambda m: f'"{m.group(1)}":"{int(m.group(2)) + 10 ** 15}"', text))
    with pytest.raises(GateUsageError, match="does not overlap"):
        run_gate(gate_inputs("full", assurance_telemetry=[str(shifted)]))
    with pytest.raises(GateUsageError, match="not found"):
        run_gate(gate_inputs("full", assurance_telemetry=["/nonexistent.jsonl"]))


def test_cli_accepts_the_stream_flags(tmp_path, capsys):
    from flowtrace.cli import main
    from conftest import ALERTS, CONFIG, FLOWS, QUERIES
    rc = main(["gate", "--flows", str(FLOWS), "--config", str(CONFIG), "--alerts", str(ALERTS), "--queries", str(QUERIES),
               "--telemetry", str(telemetry("full")), "--assurance-telemetry", str(telemetry("full")), "--assurance-sampling-rate", "1.0",
               "--reproducible", "--out", str(tmp_path / "r.json")])
    assert rc == 0
    out = capsys.readouterr().out
    assert "streams             assurance rate 1.0" in out and "two exports" in out


# ----------------------------------------------------------------- authorization coverage (spec §6.6)
@pytest.fixture(scope="module")
def w3():
    root = w3_dec()
    if root is None:
        pytest.skip("the 2026-10-11 signed example set is not available (examples/dec or an agent-dec checkout)")
    index = CertificateIndex([root], w3_trust_bundle(), flows_dir=w3_flows(), methods=w3_methods())
    run = json.loads((root / "run.dec.json").read_text())
    digests = {
        "run": run["subject"]["run_id"],
        "authz": next(d for d, (p, c) in index.authorizations.items() if p == root / "authorization-s6.dec.json"),
        "completion": next(d for d, (p, c) in index.completions.items() if p == root / "completion-s6.dec.json"),
        "deny": next(d for d, (p, c) in index.authorizations.items() if p == root / "negative" / "effect-without-authorization" / "authorization-s6.dec.json"),
        "s6": next(m["cert_digest"] for m in run["manifest"]["steps"] if m["step_id"] == "s6"),
        "s4": next(m["cert_digest"] for m in run["manifest"]["steps"] if m["step_id"] == "s4"),
        "approval_authz": next(d for d, (p, c) in index.authorizations.items() if p == root / "variants" / "s6-approval" / "authorization-s6.dec.json"),
    }
    appr = json.loads((root / "variants" / "s6-approval" / "run.dec.json").read_text())
    digests["approval_run"] = appr["subject"]["run_id"]
    digests["approval_ref"] = index.authorizations[digests["approval_authz"]][1]["decision"]["approval_ref"]
    return index, digests


def effect_window(flow, digests, trace, authz=None, completion=None, approval=None, s4=None):
    sp = [span(trace, f"{trace}-{i}", s, parent=(f"{trace}-{i - 1}" if i else None), start=i * 10, end=i * 10 + 5) for i, s in enumerate(PRIMARY[:5])]
    attrs = {}
    if authz:
        attrs["dec.authz_cert_digest"] = authz
    if completion:
        attrs["dec.completion_cert_digest"] = completion
    if approval:
        attrs["dec.approval_digest"] = approval
    sp.append(span(trace, f"{trace}-5", "s6", parent=f"{trace}-4", start=50, end=55, **attrs))
    if s4:
        sp[3] = span(trace, f"{trace}-3", "s4", parent=f"{trace}-2", start=30, end=35, **{"dec.step_cert_digest": s4})
    return index_runs(sp)


def test_authorization_coverage_statuses(degrading_flow, w3):
    index, d = w3
    runs = effect_window(degrading_flow, d, d["run"], authz=d["authz"], completion=d["completion"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, runs, index)
    assert r["populations"] == {"certificates": ["s4"], "authorization": ["s6"], "completion": []}
    assert r["steps"]["s4"]["statuses"] == {"verified": 1} and r["authorization"]["s6"]["statuses"] == {"verified": 1}
    assert r["certificate_coverage"] == 1.0 and r["authorization_coverage"] == 1.0 and r["score"] == 1.0 and r["completion_coverage"] is None
    assert r["authorization"]["s6"]["completion_status"] == {"completed": 1}
    assert r["authorization"]["s6"]["approval_present"] == {"spans_with_digest": 0, "resolved": 0}
    # a deny record verifies and counts as not covered
    runs = effect_window(degrading_flow, d, d["run"], authz=d["deny"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, runs, index)
    assert r["authorization"]["s6"]["statuses"] == {"denied": 1} and r["authorization_coverage"] == 0.0 and r["score"] == 0.5
    assert "policy-unavailable" in r["authorization"]["s6"]["examples"][0]["reason"]
    assert r["authorization"]["s6"]["completion_status"] == {"missing-digest": 1}
    # unknown digests, the wrong kind of artifact, a missing digest, a missing span
    assert index.verify_authorization_digest("sha256:" + "0" * 64, runs[d["run"]].boundaries["s6"][0])[0] == "artifact-not-found"
    assert index.verify_authorization_digest(d["s6"], runs[d["run"]].boundaries["s6"][0])[0] == "artifact-not-found"
    r = evaluate_execution_evidence(degrading_flow, effect_window(degrading_flow, d, d["run"], s4=d["s4"]), index)
    assert r["authorization"]["s6"]["statuses"] == {"missing-digest": 1}
    r = evaluate_execution_evidence(degrading_flow, index_runs([span("t", "a", "s1")]), index)
    assert r["authorization"]["s6"]["statuses"] == {"missing-span": 1} and r["steps"]["s4"]["statuses"] == {"missing-span": 1}
    # the record must bind to the span's flow and step
    wrong = span(d["run"], "x", "s5", **{"dec.authz_cert_digest": d["authz"]})
    assert index.verify_authorization_digest(d["authz"], wrong)[0] == "flow-mismatch"
    # run binding: warn counts it, strict does not
    other = effect_window(degrading_flow, d, "ff" * 16, authz=d["authz"], completion=d["completion"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, other, index, run_binding="warn")
    assert r["authorization"]["s6"]["statuses"] == {"verified": 1} and r["authorization"]["s6"]["run_binding_mismatches"] == 1
    assert any("authorization record(s) do not bind" in w for w in r["warnings"])
    assert r["authorization"]["s6"]["completion_status"] == {"completed": 1} and r["authorization"]["s6"]["completion_run_binding_mismatches"] == 1
    r = evaluate_execution_evidence(degrading_flow, other, index, run_binding="strict")
    assert r["authorization"]["s6"]["statuses"] == {"run-binding-mismatch": 1} and r["authorization"]["s6"]["completion_status"] == {"run-binding-mismatch": 1}
    # no index: unverifiable
    r = evaluate_execution_evidence(degrading_flow, runs, None)
    assert r["authorization"]["s6"]["statuses"] == {"unverifiable": 1} and r["steps"]["s4"]["statuses"] == {"unverifiable": 1}


def test_authorization_coverage_without_a_policy_authority_class(degrading_flow, w3, tmp_path):
    """A dec-trust bundle without policy_authorities[] (the Wave 2 shape) cannot
    resolve the record's issuer: authority-not-trusted."""
    index, d = w3
    bundle = json.loads(w3_trust_bundle().read_text())
    bundle.pop("policy_authorities")
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle))
    bare = CertificateIndex([w3_dec()], p, flows_dir=w3_flows(), methods=w3_methods())
    runs = effect_window(degrading_flow, d, d["run"], authz=d["authz"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, runs, bare)
    assert r["authorization"]["s6"]["statuses"] == {"authority-not-trusted": 1} and r["steps"]["s4"]["statuses"] == {"verified": 1}


def test_count_completion_pools_a_third_population(degrading_flow, w3):
    index, d = w3
    runs = effect_window(degrading_flow, d, d["run"], authz=d["authz"], completion=d["completion"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, runs, index, count_completion=True)
    assert r["completion_coverage"] == 1.0 and r["score"] == 1.0 and r["populations"]["completion"] == ["s6"]
    runs = effect_window(degrading_flow, d, d["run"], authz=d["authz"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, runs, index, count_completion=True)
    assert r["completion_coverage"] == 0.0 and r["score"] == pytest.approx(2 / 3)


def test_approval_digest_is_reported(degrading_flow, w3):
    index, d = w3
    runs = effect_window(degrading_flow, d, d["approval_run"], authz=d["approval_authz"], approval=d["approval_ref"], s4=d["s4"])
    r = evaluate_execution_evidence(degrading_flow, runs, index)
    assert r["authorization"]["s6"]["approval_present"]["spans_with_digest"] == 1


def test_component_applicable_with_effect_steps_only(degrading_flow):
    doc = copy.deepcopy(degrading_flow.doc)
    for s in doc["spec"]["steps"]:
        s.pop("nd_class", None)
        s.pop("method", None)
    f = Flow(degrading_flow.path, doc, "0" * 64)
    r = evaluate_execution_evidence(f, {}, None)
    assert r["applicable"] is True and r["populations"]["certificates"] == [] and r["populations"]["authorization"] == ["s6"]
    for s in doc["spec"]["steps"]:
        s.pop("effect", None)
        s.pop("attempts", None)
    r = evaluate_execution_evidence(Flow(degrading_flow.path, doc, "0" * 64), {}, None)
    assert r["applicable"] is False


def otlp_export(path, runs):
    """Write index_runs()-shaped runs as an OTLP/JSON export (one request per run)."""
    lines = []
    for run in runs.values():
        spans = []
        for s in run.spans:
            sp = {"traceId": s.trace_id, "spanId": s.span_id, "name": s.name, "kind": "SPAN_KIND_SERVER",
                  "startTimeUnixNano": str(s.start_ns + 10 ** 18), "endTimeUnixNano": str(s.end_ns + 10 ** 18),
                  "attributes": [{"key": k, "value": {"stringValue": v}} for k, v in s.attributes.items()],
                  "status": {"code": "STATUS_CODE_OK"}}
            if s.parent_span_id:
                sp["parentSpanId"] = s.parent_span_id
            spans.append(sp)
        lines.append(json.dumps({"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "t"}}]},
                                                    "scopeSpans": [{"scope": {"name": "t"}, "spans": spans}]}]}))
    path.write_text("\n".join(lines) + "\n")
    return path


def test_gate_reports_authorization_coverage_and_findings(gate_inputs, w3, tmp_path):
    index, d = w3
    flows = tmp_path / "flows"
    flows.mkdir()
    (flows / "quote-issue.flow.yaml").write_bytes((w3_flows() / "quote-issue.flow.yaml").read_bytes())
    allow = effect_window(None, d, d["run"], authz=d["authz"], completion=d["completion"], s4=d["s4"])
    deny = effect_window(None, d, "ee" * 16, authz=d["deny"], s4=d["s4"])
    common = dict(flows=str(flows), trust_bundle=str(w3_trust_bundle()), dec_dirs=[str(w3_dec())], methods=str(w3_methods()), alerts=None, queries=[])
    report, rc = run_gate(gate_inputs("full", telemetry=[str(otlp_export(tmp_path / "allow.jsonl", allow))], **common))
    ee = report["flows"][0]["components"]["execution_evidence"]
    assert ee["authorization"]["s6"]["statuses"] == {"verified": 1} and ee["authorization_coverage"] == 1.0 and ee["certificate_coverage"] == 1.0
    assert ee["authorization"]["s6"]["completion_status"] == {"completed": 1}
    assert report["flows"][0]["streams"]["assurance"]["declared_floor"] == 1.0 and report["flows"][0]["effective_sampling"] == 1.0
    assert not [f for f in report["flows"][0]["findings"] if f["code"] in ("authorization-missing", "attribute-class-assumed")]
    report, rc = run_gate(gate_inputs("full", telemetry=[str(otlp_export(tmp_path / "deny.jsonl", deny))], **common))
    f = report["flows"][0]
    ee = f["components"]["execution_evidence"]
    assert ee["authorization"]["s6"]["statuses"] == {"denied": 1} and ee["authorization_coverage"] == 0.0 and ee["score"] == 0.5
    (w,) = [x for x in f["findings"] if x["code"] == "authorization-missing"]
    assert w["severity"] == "warn" and w["step"] == "s6" and "0/1 runs" in w["message"]
