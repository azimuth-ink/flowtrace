#!/usr/bin/env python3
"""Deterministic synthetic telemetry for the quote-issue running example.

Writes three evaluation windows as OTLP/JSON export files (one export request
per line, the shape the OpenTelemetry Collector's `file` exporter produces —
see src/flowtrace/adapters/otlp_duckdb.py for the accepted shape):

  examples/telemetry/quote-issue.full.otlp.jsonl             every step observable, every
                                                             required attribute present
  examples/telemetry/quote-issue.s5-silent.otlp.jsonl        step s5 (docs.render) emits nothing
  examples/telemetry/quote-issue.s4-missing-attr.otlp.jsonl  step s4's span lacks risk.decision

Every run carries, on each step's boundary span, the REAL `dec.step_cert_digest`
of the signed flow-bound example run in examples/dec/flow-bound/ (copied
byte-for-byte from agent-dec; canon invariant 3: signed artifacts are never
hand-written). The digests are recomputed here with RFC 8785 exactly as
agent-dec's verifier does (sha256 over the JCS bytes of the signed
certificate) and cross-checked against the run certificate's manifest; a
mismatch aborts. The first run of each window reuses the certified run's
trace id, so that run's conformance reading takes the manifest as input
(binding B6); the other runs have their own trace ids, so their certificates
verify under B7 (trust bundle + subject.flow) but do not bind to their run —
see README "Execution evidence in the examples".

Everything is seeded: the same seed produces byte-identical files.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import random
import sys

import rfc8785

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEC_DIR = ROOT / "examples" / "dec" / "flow-bound"
OUT_DIR = ROOT / "examples" / "telemetry"

FLOW_ID, FLOW_VERSION, CRIT = "quote-issue", "2.0.0", "P0"
BASE_TIME = dt.datetime(2026, 10, 11, 2, 0, 0, tzinfo=dt.timezone.utc)
RUN_SPACING_S = 9

STEPS = [  # id, component, op, kind, span kind, nd_class
    ("s1", "edge.api-gateway", "receive", "sync", "SPAN_KIND_SERVER", None),
    ("s2", "identity.session", "authorize", "sync", "SPAN_KIND_SERVER", None),
    ("s3", "payments.quote-engine", "price", "sync", "SPAN_KIND_SERVER", None),
    ("s4", "risk.limits-check", "evaluate", "sync", "SPAN_KIND_SERVER", "ND0"),
    ("s5", "docs.render", "generate", "async", "SPAN_KIND_CONSUMER", "ND2"),
    ("s6", "notify.customer", "deliver", "async", "SPAN_KIND_CONSUMER", None),
]
# duration ranges in ms (uniform); sync frontier always well inside the 1800 ms p95
DURATION_MS = {"s1": (4, 12), "s2": (12, 35), "s3": (420, 880), "s4": (35, 95), "s5": (18000, 55000), "s6": (800, 4000)}
ASYNC_HANDOFF_MS = {"s5": (40, 250), "s6": (20, 120)}
COST_USD = {"s1": (0.00002, 0.00004), "s2": (0.00001, 0.00003), "s3": (0.0004, 0.0009), "s4": (0.0001, 0.0003),
            "s5": (0.012, 0.045), "s6": (0.0006, 0.0012)}


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def load_digests() -> tuple[dict[str, str], str, str]:
    """{step_id: dec.step_cert_digest}, run certificate digest, certified trace id."""
    run = json.loads((DEC_DIR / "run.dec.json").read_text(encoding="utf-8"))
    manifest = {m["flow_step"]: m["cert_digest"] for m in run["manifest"]["steps"]}
    digests = {}
    for p in sorted(DEC_DIR.glob("step-*.dec.json")):
        c = json.loads(p.read_text(encoding="utf-8"))
        d = sha(rfc8785.dumps(c))                    # exactly agent-dec's cert_digest()
        step = c["subject"]["flow"]["step"]
        if manifest.get(step) != d:
            sys.exit(f"{p.name}: recomputed digest {d} != manifest cert_digest {manifest.get(step)} — refusing to emit")
        digests[step] = d
    return digests, sha(rfc8785.dumps(run)), run["subject"]["trace_id"]


def kv(key: str, value) -> dict:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def hex_id(rng: random.Random, nbytes: int) -> str:
    return "".join(f"{rng.randrange(256):02x}" for _ in range(nbytes))


def make_run(k: int, rng: random.Random, trace_id: str, digests: dict[str, str], run_digest: str, variant: str,
             certified: bool):
    """-> (resourceSpans[], metrics dataPoints[], start_ns) for one run."""
    t = int((BASE_TIME + dt.timedelta(seconds=k * RUN_SPACING_S)).timestamp() * 1e9)
    cursor = t
    spans_by_service: dict[str, list[dict]] = {}
    metric_points = []
    prev_span_id = None
    common = [kv("flow.id", FLOW_ID), kv("flow.version", FLOW_VERSION), kv("flow.criticality", CRIT)]
    limit_id = f"LIM-{rng.randrange(1000, 9999)}"
    ref_version = rng.choice(["2026.10.03", "2026.10.03", "2026.10.07"])
    decision = "approve" if rng.random() < 0.85 else "refer"

    for sid, component, op, kind, span_kind, nd in STEPS:
        if variant == "s5-silent" and sid == "s5":
            continue                                   # the step runs, but emits nothing
        if kind == "async":
            lo, hi = ASYNC_HANDOFF_MS[sid]
            cursor += int(rng.uniform(lo, hi) * 1e6)
        lo, hi = DURATION_MS[sid]
        dur_ns = int(rng.uniform(lo, hi) * 1e6)
        start, end = cursor, cursor + dur_ns
        span_id = hex_id(rng, 8)
        attrs = list(common) + [kv("flow.step", sid), kv("dec.step_cert_digest", digests[sid])]
        lo_c, hi_c = COST_USD[sid]
        attrs.append(kv("cost.usd", round(rng.uniform(lo_c, hi_c), 6)))
        if nd:
            attrs.append(kv("flow.step.nd_class", nd))
        if sid == "s1":
            attrs += [kv("http.request.method", "POST"), kv("http.route", "/v2/quotes")]
            if certified:                              # only the certified run carries the run certificate digest
                attrs.append(kv("dec.run_cert_digest", run_digest))
        elif sid == "s2":
            attrs += [kv("session.valid", True), kv("enduser.role", "customer")]
        elif sid == "s3":
            attrs += [kv("quote.sku", f"SKU-{rng.randrange(100, 999)}"), kv("quote.quantity", rng.randrange(1, 12))]
        elif sid == "s4":
            attrs += [kv("risk.limit_id", limit_id), kv("risk.reference_data_version", ref_version)]
            if variant != "s4-missing-attr":
                attrs.append(kv("risk.decision", decision))
        elif sid == "s5":
            attrs += [kv("gen_ai.request.model", "doc-writer-7b"), kv("llm.usage.total_tokens", rng.randrange(900, 2400))]
        elif sid == "s6":
            attrs += [kv("notify.channel", "email")]
        span = {"traceId": trace_id, "spanId": span_id, "name": f"{component}/{op}", "kind": span_kind,
                "startTimeUnixNano": str(start), "endTimeUnixNano": str(end),
                "attributes": attrs, "status": {"code": "STATUS_CODE_OK"}}
        if prev_span_id:
            span["parentSpanId"] = prev_span_id
        spans_by_service.setdefault(component, []).append(span)
        if sid == "s3":                                # an interior span: inherits flow.step, is not a boundary
            inner = {"traceId": trace_id, "spanId": hex_id(rng, 8), "parentSpanId": span_id,
                     "name": "payments.quote-engine/rate-card-lookup", "kind": "SPAN_KIND_INTERNAL",
                     "startTimeUnixNano": str(start + dur_ns // 5), "endTimeUnixNano": str(start + dur_ns // 2),
                     "attributes": list(common) + [kv("flow.step", sid), kv("db.system", "postgresql")],
                     "status": {"code": "STATUS_CODE_OK"}}
            spans_by_service[component].append(inner)
        metric_points.append({"timeUnixNano": str(end), "count": "1", "sum": dur_ns / 1e9,
                              "attributes": [kv("flow.id", FLOW_ID), kv("flow.version", FLOW_VERSION), kv("flow.step", sid)]})
        prev_span_id = span_id
        cursor = end

    resource_spans = []
    for component, spans in spans_by_service.items():
        resource_spans.append({
            "resource": {"attributes": [kv("service.name", component), kv("service.version", "1.0.0"),
                                        kv("deployment.environment.name", "synthetic")]},
            "scopeSpans": [{"scope": {"name": "flowtrace.synthetic", "version": "0.1.0"}, "spans": spans}],
        })
    return resource_spans, metric_points, t


def write_window(variant: str, runs: int, seed: int, out: pathlib.Path, digests, run_digest, cert_trace) -> dict:
    rng = random.Random(f"flowtrace:{seed}:{variant}")
    lines = []
    for k in range(runs):
        trace_id = cert_trace if k == 0 else hashlib.sha256(f"flowtrace:{seed}:{k}".encode()).hexdigest()[:32]
        resource_spans, points, t = make_run(k, rng, trace_id, digests, run_digest, variant, certified=(k == 0))
        lines.append(json.dumps({"resourceSpans": resource_spans}, separators=(",", ":")))
        lines.append(json.dumps({"resourceMetrics": [{
            "resource": {"attributes": [kv("service.name", "flowtrace.synthetic")]},
            "scopeMetrics": [{"scope": {"name": "flowtrace.synthetic", "version": "0.1.0"}, "metrics": [{
                "name": "step_duration_seconds", "unit": "s",
                "histogram": {"aggregationTemporality": "AGGREGATION_TEMPORALITY_DELTA", "dataPoints": points}}]}]}]},
            separators=(",", ":")))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"file": out.name, "runs": runs, "lines": len(lines), "sha256": hashlib.sha256(out.read_bytes()).hexdigest()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--runs", type=int, default=32)
    ap.add_argument("--seed", type=int, default=20261010)
    ap.add_argument("--out-dir", default=str(OUT_DIR))
    args = ap.parse_args(argv)
    digests, run_digest, cert_trace = load_digests()
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for variant in ("full", "s5-silent", "s4-missing-attr"):
        info = write_window(variant, args.runs, args.seed, out_dir / f"quote-issue.{variant}.otlp.jsonl",
                            digests, run_digest, cert_trace)
        print(f"wrote {info['file']}: {info['runs']} runs, {info['lines']} lines, sha256 {info['sha256'][:16]}…")
    print(f"step certificate digests (from {DEC_DIR.relative_to(ROOT)}): " + ", ".join(f"{k}={v[7:19]}…" for k, v in sorted(digests.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
