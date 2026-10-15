#!/usr/bin/env python3
"""Deterministic synthetic telemetry for the quote-issue running example (2.1.0).

Writes seven evaluation windows as OTLP/JSON export files (one export request
per line, the shape the OpenTelemetry Collector's `file` exporter produces —
see src/flowtrace/adapters/otlp_duckdb.py for the accepted shape). Every
window holds 32 runs; the first run of each reuses the trace id of the signed
run it is built on, so that run's conformance reading takes the run
certificate's manifest as input (binding B6; the trigger span names the
certificate by dec.run_cert_digest); the other 31 runs have their own trace
ids, so their certificates verify under B7 (trust bundle + subject.flow) but
do not bind to their run — see README "Execution evidence in the examples".

  quote-issue.full                   every step observable, every required attribute present;
                                     built on examples/dec/flow-bound/ (the §4.4 run, convergent)
  quote-issue.s5-silent              step s5 (docs.render) emits nothing (blind spot; regression)
  quote-issue.s4-missing-attr        step s4's span lacks risk.decision (completeness and answerability fail)
  quote-issue.s5-degraded            s5 fails and the run takes s5's declared on_fail edge to s6
                                     (convergent by declaration; built on variants/s5-degraded, s6 via on_fail)
  quote-issue.s6-unknown-reconciled  s6's first attempt completes `unknown`, a `reconciled` completion follows,
                                     attempt 2 never runs (convergent; built on variants/s6-reconciled)
  quote-issue.s6-retry-unreconciled  s6 is retried after an `unknown` completion with no reconciliation:
                                     two attempts (divergent, binding B17; built on negative/retry-without-reconciliation)
  quote-issue.cancelled-child-late   the first run is a cancelled parent (s1..s3) whose child run completed 120 s
                                     after the cancellation (divergent, binding B14; built on
                                     negative/cancellation-not-propagated/parent); the other 31 runs are full runs

Every run carries, on each step's boundary span, the REAL digests of the
signed artifacts under examples/dec/ (copied byte-for-byte from agent-dec;
canon invariant 3: signed artifacts are never hand-written):
dec.step_cert_digest, dec.run_cert_digest (first run), and on the effect
step s6 dec.authz_cert_digest and dec.completion_cert_digest (per attempt;
dec.approval_digest when the authorization cites an approval — none of the
windowed runs does). The digests are recomputed here with RFC 8785 exactly as
agent-dec's verifier does (sha256 over the JCS bytes of the signed artifact)
and cross-checked against the run certificate's manifest; a mismatch aborts.

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
from dataclasses import dataclass, field

import rfc8785

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEC_ROOT = ROOT / "examples" / "dec"
OUT_DIR = ROOT / "examples" / "telemetry"

FLOW_ID, FLOW_VERSION, CRIT = "quote-issue", "2.1.0", "P0"
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
EFFECT_STEP = "s6"
# duration ranges in ms (uniform); sync frontier always well inside the 1800 ms p95
DURATION_MS = {"s1": (4, 12), "s2": (12, 35), "s3": (420, 880), "s4": (35, 95), "s5": (18000, 55000), "s6": (800, 4000)}
ASYNC_HANDOFF_MS = {"s5": (40, 250), "s6": (20, 120)}
COST_USD = {"s1": (0.00002, 0.00004), "s2": (0.00001, 0.00003), "s3": (0.0004, 0.0009), "s4": (0.0001, 0.0003),
            "s5": (0.012, 0.045), "s6": (0.0006, 0.0012)}

# window name -> (signed run directory under examples/dec/, behaviour)
WINDOWS = {
    "full": ("flow-bound", "full"),
    "s5-silent": ("flow-bound", "s5-silent"),
    "s4-missing-attr": ("flow-bound", "s4-missing-attr"),
    "s5-degraded": ("flow-bound/variants/s5-degraded", "s5-degraded"),
    "s6-unknown-reconciled": ("flow-bound/variants/s6-reconciled", "s6-unknown-reconciled"),
    "s6-retry-unreconciled": ("flow-bound/negative/retry-without-reconciliation", "s6-retry-unreconciled"),
    "cancelled-child-late": ("flow-bound/negative/cancellation-not-propagated/parent", "cancelled-child-late"),
}


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_of(doc: dict) -> str:
    return sha(rfc8785.dumps(doc))                       # exactly agent-dec's cert_digest()


@dataclass
class SignedRun:
    """The digests a signed run directory yields (every value recomputed and cross-checked)."""
    directory: pathlib.Path
    trace_id: str
    run_digest: str
    steps: dict[str, list[str]] = field(default_factory=dict)        # step id -> step certificate digests, one per attempt
    authorization: dict[tuple[str, int], str] = field(default_factory=dict)   # (step, attempt) -> authorization digest
    completion: dict[tuple[str, int], str] = field(default_factory=dict)      # (step, attempt) -> the last completion's digest
    approval: dict[tuple[str, int], str] = field(default_factory=dict)        # (step, attempt) -> the cited approval's digest

    def step_digest(self, sid: str, attempt: int = 1) -> str:
        return self.steps[sid][attempt - 1]


def load_run(rel: str) -> SignedRun:
    d = DEC_ROOT / rel
    run = json.loads((d / "run.dec.json").read_text(encoding="utf-8"))
    members = []
    for p in sorted(d.glob("*.dec.json")):
        if p.name == "run.dec.json":
            continue
        c = json.loads(p.read_text(encoding="utf-8"))
        members.append((c["chain"]["position"], p, c))
    members.sort(key=lambda t: t[0])
    sr = SignedRun(d, run["subject"]["trace_id"], digest_of(run))
    manifest = [m for m in run["manifest"]["steps"]]
    step_certs = [(p, c) for _, p, c in members if "kind" not in c]
    if len(step_certs) != len(manifest):
        sys.exit(f"{d}: manifest lists {len(manifest)} step(s), {len(step_certs)} step certificate(s) found — refusing to emit")
    for m, (p, c) in zip(manifest, step_certs):
        dg = digest_of(c)
        if m["cert_digest"] != dg or m.get("flow_step") != c["subject"]["flow"]["step"]:
            sys.exit(f"{p.name}: recomputed digest {dg} != manifest cert_digest {m['cert_digest']} — refusing to emit")
        sr.steps.setdefault(m["flow_step"], []).append(dg)
    for _, p, c in members:
        kind = c.get("kind")
        if kind not in ("authorization", "completion"):
            continue
        s = c["subject"]
        key = (s["step_id"], int(s.get("attempt_id", 1)))
        dg = digest_of(c)
        if kind == "authorization":
            sr.authorization[key] = dg
            if c["decision"].get("approval_ref"):
                sr.approval[key] = c["decision"]["approval_ref"]
        else:
            sr.completion[key] = dg                      # the last completion for the attempt (chain order) wins
    if run["head"] != digest_of(members[-1][2]):
        sys.exit(f"{d}: run certificate head does not match the last chain member — refusing to emit")
    return sr


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


def make_run(k: int, rng: random.Random, trace_id: str, signed: SignedRun, variant: str, certified: bool):
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
    steps = [s for s in STEPS if s[0] in signed.steps] if (certified and variant == "cancelled-child-late") else STEPS

    for sid, component, op, kind, span_kind, nd in steps:
        if variant == "s5-silent" and sid == "s5":
            continue                                   # the step runs, but emits nothing
        attempts = len(signed.steps.get(sid, [None])) if (sid == EFFECT_STEP and variant == "s6-retry-unreconciled") else 1
        parent_of_attempts = prev_span_id
        for attempt in range(1, attempts + 1):
            if kind == "async":
                lo, hi = ASYNC_HANDOFF_MS[sid]
                cursor += int(rng.uniform(lo, hi) * 1e6)
            lo, hi = DURATION_MS[sid]
            dur_ns = int(rng.uniform(lo, hi) * 1e6)
            start, end = cursor, cursor + dur_ns
            span_id = hex_id(rng, 8)
            attrs = list(common) + [kv("flow.step", sid), kv("dec.step_cert_digest", signed.step_digest(sid, attempt))]
            lo_c, hi_c = COST_USD[sid]
            attrs.append(kv("cost.usd", round(rng.uniform(lo_c, hi_c), 6)))
            if nd:
                attrs.append(kv("flow.step.nd_class", nd))
            status = "STATUS_CODE_OK"
            if sid == "s1":
                attrs += [kv("http.request.method", "POST"), kv("http.route", "/v2/quotes")]
                if certified:                          # only the certified run carries the run certificate digest
                    attrs.append(kv("dec.run_cert_digest", signed.run_digest))
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
                if variant == "s5-degraded":
                    status = "STATUS_CODE_ERROR"      # the render failed; the run delivers without the document (s5 -> s6 on_fail)
            elif sid == "s6":
                attrs += [kv("notify.channel", "email")]
                key = (sid, attempt)
                if key in signed.authorization:        # the effect step's evidence digests (FTC §4.7)
                    attrs.append(kv("dec.authz_cert_digest", signed.authorization[key]))
                if key in signed.completion:
                    attrs.append(kv("dec.completion_cert_digest", signed.completion[key]))
                if key in signed.approval:
                    attrs.append(kv("dec.approval_digest", signed.approval[key]))
                if attempt > 1:
                    attrs.append(kv("notify.attempt", attempt))
            span = {"traceId": trace_id, "spanId": span_id, "name": f"{component}/{op}", "kind": span_kind,
                    "startTimeUnixNano": str(start), "endTimeUnixNano": str(end),
                    "attributes": attrs, "status": {"code": status}}
            parent = parent_of_attempts if attempts > 1 else prev_span_id
            if parent:
                span["parentSpanId"] = parent
            spans_by_service.setdefault(component, []).append(span)
            if sid == "s3":                            # an interior span: inherits flow.step, is not a boundary
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


def write_window(name: str, runs: int, seed: int, out: pathlib.Path, signed: SignedRun, baseline: SignedRun, variant: str) -> dict:
    rng = random.Random(f"flowtrace:{seed}:{variant}")
    lines = []
    for k in range(runs):
        certified = k == 0
        trace_id = signed.trace_id if certified else hashlib.sha256(f"flowtrace:{seed}:{k}".encode()).hexdigest()[:32]
        # the certified run carries its own run's digests; the others reuse the §4.4 run's (one signed run per window)
        src = signed if (certified or variant != "cancelled-child-late") else baseline
        resource_spans, points, t = make_run(k, rng, trace_id, src, variant, certified=certified)
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
    ap.add_argument("--window", action="append", choices=sorted(WINDOWS), help="only these windows (default: all)")
    args = ap.parse_args(argv)
    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    baseline = load_run("flow-bound")
    for name, (rel, variant) in WINDOWS.items():
        if args.window and name not in args.window:
            continue
        signed = baseline if rel == "flow-bound" else load_run(rel)
        info = write_window(name, args.runs, args.seed, out_dir / f"quote-issue.{name}.otlp.jsonl", signed, baseline, variant)
        print(f"wrote {info['file']}: {info['runs']} runs, {info['lines']} lines, sha256 {info['sha256'][:16]}… "
              f"(signed run {rel}, trace {signed.trace_id})")
    print("step certificate digests (flow-bound): " + ", ".join(f"{k}={v[0][7:19]}…" for k, v in sorted(baseline.steps.items())))
    print("s6 evidence (flow-bound): " + ", ".join(f"{k}={v[7:19]}…" for k, v in (("authorization", baseline.authorization[("s6", 1)]),
                                                                                   ("completion", baseline.completion[("s6", 1)]))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
