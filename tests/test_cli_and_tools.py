"""The `flowtrace` CLI (exit codes, subcommands) and the synthetic generator
(seeded, byte-stable, carrying the real certificate digests)."""
import hashlib
import json
import subprocess
import sys

import pytest

from conftest import ALERTS, CONFIG, DEC_DIR, EXPECTED, FLOWS, QUERIES, REPO, TELEMETRY, TRUST_BUNDLE, WINDOWS, telemetry
from flowtrace.cli import main

GATE = ["gate", "--flows", str(FLOWS), "--config", str(CONFIG), "--alerts", str(ALERTS), "--queries", str(QUERIES),
        "--trust-bundle", str(TRUST_BUNDLE), "--dec-dir", str(DEC_DIR), "--execution-evidence", "--reproducible"]


def test_cli_gate_exit_codes(tmp_path, capsys):
    assert main(GATE + ["--telemetry", str(telemetry("full")), "--out", str(tmp_path / "f.json")]) == 0
    out = capsys.readouterr().out
    assert "GATE quote-issue@2.0.0 [P0]: score 1.0000 >= threshold 1.00 — PASS" in out and "VERDICT: PASS" in out
    assert main(GATE + ["--telemetry", str(telemetry("s5-silent")), "--baseline", str(tmp_path / "f.json"), "--out", str(tmp_path / "s.json")]) == 1
    out = capsys.readouterr().out
    assert "FAIL (score 0.6333 < tier P0 threshold 1.00; blind-spot)" in out and "blind spots ['s5']" in out
    assert "delta vs baseline" in out
    # usage error: execution evidence without a bundle
    assert main(["gate", "--flows", str(FLOWS), "--telemetry", str(telemetry("full")), "--execution-evidence", "--out", str(tmp_path / "x.json")]) == 2
    assert "trust-bundle" in capsys.readouterr().err


def test_cli_other_subcommands(tmp_path, capsys):
    assert main(["tier", "--score", "7.2"]) == 0
    assert json.loads(capsys.readouterr().out)["tier"] == "P0"
    assert main(["tier", "--dimension", "revenue_impact=low", "--dimension", "user_impact=medium"]) == 0
    assert json.loads(capsys.readouterr().out)["tier"] == "P3"
    assert main(["tier"]) == 2
    capsys.readouterr()
    assert main(["decompose", "--flows", str(FLOWS)]) == 0
    d = json.loads(capsys.readouterr().out)["quote-issue@2.0.0"]
    assert d["latency"]["sync_frontier_p95"]["mode"] == "cold-start:equal_split"
    assert main(["conformance", "--flows", str(FLOWS), "--telemetry", str(telemetry("s5-silent")), "--dec-dir", str(DEC_DIR), "--require-convergent"]) == 1
    out = capsys.readouterr().out
    assert "window absent absent=['s5']" in out and "[manifest:run.dec.json]: convergent" in out and "[spans]: absent" in out
    assert main(["conformance", "--flows", str(FLOWS), "--telemetry", str(telemetry("full")), "--require-convergent"]) == 0
    capsys.readouterr()
    assert main(["validate-report", str(EXPECTED / "quote-issue.full.json")]) == 0
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["validate-report", str(bad)]) == 1


def test_console_script_is_installed():
    r = subprocess.run([sys.executable, "-m", "flowtrace.cli", "--version"], capture_output=True, text=True, cwd=str(REPO))
    assert r.returncode == 0 and r.stdout.strip() == "flowtrace 0.1.0"


def test_synthetic_generator_is_deterministic_and_matches_examples(tmp_path):
    r = subprocess.run([sys.executable, str(REPO / "tools" / "make_synthetic_telemetry.py"), "--out-dir", str(tmp_path)],
                       capture_output=True, text=True, cwd=str(REPO))
    assert r.returncode == 0, r.stderr
    for w in WINDOWS:
        name = f"quote-issue.{w}.otlp.jsonl"
        assert (tmp_path / name).read_bytes() == (TELEMETRY / name).read_bytes(), name
    # the full window carries the real step-certificate digests and, on the certified run only, the run digest
    run = json.loads((DEC_DIR / "run.dec.json").read_text())
    digests = {m["flow_step"]: m["cert_digest"] for m in run["manifest"]["steps"]}
    seen, run_digest_traces = {}, set()
    for line in (TELEMETRY / "quote-issue.full.otlp.jsonl").read_text().splitlines():
        req = json.loads(line)
        for rs in req.get("resourceSpans", []):
            for ss in rs["scopeSpans"]:
                for sp in ss["spans"]:
                    a = {kv["key"]: kv["value"].get("stringValue") for kv in sp["attributes"]}
                    if "dec.step_cert_digest" in a:
                        seen.setdefault(a["flow.step"], set()).add(a["dec.step_cert_digest"])
                    if "dec.run_cert_digest" in a:
                        run_digest_traces.add(sp["traceId"])
    assert {k: next(iter(v)) for k, v in seen.items()} == digests and all(len(v) == 1 for v in seen.values())
    assert run_digest_traces == {run["subject"]["trace_id"]}
    # the s4-missing-attr window differs from full only by the dropped attribute
    full = (TELEMETRY / "quote-issue.full.otlp.jsonl").read_text()
    miss = (TELEMETRY / "quote-issue.s4-missing-attr.otlp.jsonl").read_text()
    assert "risk.decision" in full and "risk.decision" not in miss
