"""FTC §4.6: the gate reproduces the expected reports byte for byte, fails on
the regression windows, prints deltas against a baseline, validates its own
report, and refuses to score execution evidence without the inputs it needs."""
import json
import pathlib

import pytest

from conftest import CONFIG, EXPECTED, FLOWS, WINDOWS, telemetry
from flowtrace.gate import GateUsageError, format_summary, run_gate
from flowtrace.report import dumps, validate_report


def normalize(report: dict) -> dict:
    """What --reproducible does, applied after the fact: drop the timestamp
    and the flow-set commit, reduce input paths to basenames."""
    r = json.loads(json.dumps(report))
    r["generated_at"] = None
    r["inputs"]["flows_commit"] = None
    for k in ("flows_dir", "config", "alerts", "trust_bundle", "baseline", "methods", "approvals"):
        if r["inputs"].get(k):
            r["inputs"][k] = pathlib.Path(r["inputs"][k]).name
    for k in ("telemetry", "queries", "dec_dirs", "assurance_telemetry"):
        r["inputs"][k] = [pathlib.Path(x).name for x in r["inputs"].get(k, [])]
    for f in r["flows"]:
        for st in (f.get("streams") or {}).values():
            if isinstance(st, dict):
                st["source"] = [pathlib.Path(x).name for x in st["source"]]
    return r


@pytest.mark.parametrize("window", WINDOWS)
def test_gate_reproduces_the_expected_report_byte_for_byte(gate_inputs, window, tmp_path):
    baseline = None if window == "full" else str(EXPECTED / "quote-issue.full.json")
    inp = gate_inputs(window, baseline=baseline)
    report, rc = run_gate(inp)
    expected = (EXPECTED / f"quote-issue.{window}.json").read_bytes()
    assert pathlib.Path(inp.out).read_bytes() == expected
    assert dumps(report).encode() == expected
    assert rc == (0 if window == "full" else 1)


@pytest.mark.parametrize("window", WINDOWS)
def test_non_reproducible_report_normalizes_to_the_expected_one(gate_inputs, window):
    baseline = None if window == "full" else str(EXPECTED / "quote-issue.full.json")
    report, _ = run_gate(gate_inputs(window, baseline=baseline, reproducible=False))
    assert report["generated_at"].endswith("Z")
    assert report["inputs"]["flows_commit"] is None or len(report["inputs"]["flows_commit"]) == 40
    assert normalize(report) == json.loads((EXPECTED / f"quote-issue.{window}.json").read_text())


def test_verdicts_and_components(gate_inputs):
    full, rc = run_gate(gate_inputs("full"))
    assert rc == 0 and full["verdict"] == "pass"
    f = full["flows"][0]
    assert f["score"] == 1.0 and f["threshold"] == 1.0 and f["weights"] == {
        "completeness": 0.35, "answerability": 0.25, "detectability": 0.2, "cost_attribution": 0.1, "execution_evidence": 0.1}
    assert f["components"]["execution_evidence"]["steps"]["s4"]["fraction"] == 1.0
    assert f["conformance"]["window"]["reading"] == "convergent"

    silent, rc = run_gate(gate_inputs("s5-silent"))
    s = silent["flows"][0]
    assert rc == 1 and s["verdict"] == "fail" and s["score"] == pytest.approx(0.633333, abs=1e-6)
    assert s["components"]["completeness"]["score"] == 0.0 and s["components"]["completeness"]["blind_spots"] == ["s5"]
    assert s["components"]["cost_attribution"]["score"] == pytest.approx(5 / 6)
    assert s["components"]["answerability"]["score"] == 1.0 and s["components"]["execution_evidence"]["score"] == 1.0
    assert {fd["code"] for fd in s["findings"] if fd["severity"] == "fail"} == {"blind-spot"}
    assert s["verdict_reasons"] == ["score 0.6333 < tier P0 threshold 1.00", "blind-spot"]
    assert s["conformance"]["window"]["absent"] == ["s5"]

    missing, rc = run_gate(gate_inputs("s4-missing-attr"))
    m = missing["flows"][0]
    assert rc == 1 and m["score"] == pytest.approx(0.4)
    assert m["components"]["completeness"]["score"] == 0.0 and m["components"]["answerability"]["score"] == 0.0
    assert m["components"]["completeness"]["blind_spots"] == []
    assert m["components"]["completeness"]["by_step"]["s4"]["missing"] == {"span risk.limits-check/evaluate lacks required attribute risk.decision": 32}
    assert m["components"]["answerability"]["scenarios"][0]["status"] == "unanswerable"
    assert m["components"]["execution_evidence"]["score"] == 1.0 and m["components"]["detectability"]["score"] == 1.0


def test_baseline_deltas_and_regression_finding(gate_inputs, tmp_path):
    full, _ = run_gate(gate_inputs("full", out=str(tmp_path / "base.json")))
    silent, rc = run_gate(gate_inputs("s5-silent", baseline=str(tmp_path / "base.json")))
    d = silent["flows"][0]["delta"]
    assert d["baseline_score"] == 1.0 and d["delta"] == pytest.approx(-0.366667, abs=1e-6)
    assert d["components"]["completeness"]["delta"] == -1.0 and d["components"]["answerability"]["delta"] == 0.0
    assert any(f["code"] == "tier-threshold-regression" for f in silent["flows"][0]["findings"])
    text = format_summary(silent)
    assert "delta vs baseline   score 1.0000 -> 0.6333 (-0.3667)" in text
    assert "GATE quote-issue@2.0.0 [P0]: score 0.6333 < threshold 1.00 — FAIL" in text
    assert "VERDICT: FAIL" in text
    # the same window against itself: no decrease, no regression finding
    again, _ = run_gate(gate_inputs("s5-silent", baseline=str(gate_inputs("s5-silent").out), out=str(tmp_path / "again.json")))
    assert again["flows"][0]["delta"]["delta"] == 0.0
    assert not any(f["code"] in ("tier-threshold-regression", "score-decreased") for f in again["flows"][0]["findings"])
    # no baseline: no delta block
    none, _ = run_gate(gate_inputs("s5-silent"))
    assert none["flows"][0]["delta"] is None


def test_execution_evidence_requires_bundle_and_dec_dir(gate_inputs):
    with pytest.raises(GateUsageError, match="trust-bundle"):
        run_gate(gate_inputs("full", trust_bundle=None))
    with pytest.raises(GateUsageError, match="not found"):
        run_gate(gate_inputs("full", alerts="/nonexistent/alerts.yaml"))
    with pytest.raises(GateUsageError, match="telemetry"):
        run_gate(gate_inputs("full", telemetry=[]))


def test_four_component_mode_without_execution_evidence(gate_inputs):
    report, rc = run_gate(gate_inputs("full", execution_evidence=None, trust_bundle=None, dec_dirs=[]))
    f = report["flows"][0]
    assert rc == 0 and "execution_evidence" not in f["components"] and f["execution_evidence_enabled"] is False
    assert f["weights"] == {"completeness": 0.4, "answerability": 0.3, "detectability": 0.2, "cost_attribution": 0.1}
    assert f["conformance"]["runs"][0]["source"] == "spans"           # no certificates: spans are the realized DAG


def test_sampling_floor_and_missing_alerts(gate_inputs):
    report, rc = run_gate(gate_inputs("full", sampling_rate=0.5, alerts=None))
    f = report["flows"][0]
    assert rc == 1 and {x["code"] for x in f["findings"] if x["severity"] == "fail"} == {"sampling-below-floor"}
    assert f["components"]["detectability"]["score"] == 0.0 and f["components"]["detectability"]["reason"].startswith("no alert configuration")
    assert f["score"] == pytest.approx(0.8)


def test_user_config_overrides_defaults(gate_inputs, tmp_path):
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text("apiVersion: flowtrace.config/v0.1\nscoring:\n  execution_evidence: {enabled: true, run_binding: strict}\n"
                   "tiers:\n  P0: {coverage_threshold: 0.9}\n")
    report, rc = run_gate(gate_inputs("full", config=str(cfg), execution_evidence=None))
    f = report["flows"][0]
    assert f["components"]["execution_evidence"]["score"] == pytest.approx(1 / 32)
    assert f["threshold"] == 0.9 and f["score"] == pytest.approx(0.903125) and rc == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: flowtrace.config/v0.1\nscoring:\n  weights: {completeness: 0.5}\n")
    from flowtrace.config import ConfigError, load_config
    with pytest.raises(ConfigError):
        load_config(bad)


def test_report_schema_rejects_a_broken_report():
    good = json.loads((EXPECTED / "quote-issue.full.json").read_text())
    validate_report(good)
    bad = json.loads(json.dumps(good))
    bad["flows"][0]["score"] = 1.5
    with pytest.raises(ValueError, match="score"):
        validate_report(bad)
    bad = json.loads(json.dumps(good))
    del bad["verdict"]
    with pytest.raises(ValueError):
        validate_report(bad)


def test_flow_validation_failure_is_a_usage_error(gate_inputs, tmp_path):
    pytest.importorskip("polydiagram")
    flows = tmp_path / "flows"
    flows.mkdir()
    bad = (FLOWS / "quote-issue.flow.yaml").read_text().replace("nd_class: ND0\n      method: { ref: methods/limits-check, version: 3.1.0, digest: \"sha256:fad9362bcab1866e2e08bfb0f98c5a199b01b231ad13b855dcee86444e43d6b6\" }\n", "nd_class: ND0\n")
    (flows / "bad.flow.yaml").write_text(bad)
    with pytest.raises(GateUsageError, match="R7"):
        run_gate(gate_inputs("full", flows=str(flows)))
