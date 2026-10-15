"""`flowtrace` command line.

  flowtrace gate --flows DIR --telemetry FILE [--assurance-telemetry FILE] [--config flowtrace.yaml] [--alerts alerts.yaml]
                 [--queries q.yaml] [--trust-bundle B] [--dec-dir D] [--methods M] [--approvals A] [--baseline report.json]
                 [--execution-evidence] [--sampling-rate X] [--assurance-sampling-rate Y] [--out coverage-report.json] [--reproducible]
  flowtrace decompose --flows DIR [--config C] [--history h.yaml] [--sample-runs N]
  flowtrace tier (--score S | --dimension name=value ...) [--config C]
  flowtrace conformance --flows DIR --telemetry FILE [--dec-dir D]
  flowtrace validate-report REPORT.json

Exit codes: 0 pass; 1 gate failure; 2 usage / load error.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__


def _add_common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--config", help="flowtrace.yaml overriding the shipped defaults")


def cmd_gate(args) -> int:
    from .gate import GateInputs, GateUsageError, format_summary, run_gate
    inp = GateInputs(flows=args.flows, telemetry=args.telemetry, config=args.config, alerts=args.alerts,
                     trust_bundle=args.trust_bundle, dec_dirs=args.dec_dir or [], methods=args.methods, approvals=args.approvals,
                     queries=args.queries or [],
                     baseline=args.baseline, execution_evidence=(True if args.execution_evidence else None),
                     sampling_rate=args.sampling_rate, assurance_telemetry=args.assurance_telemetry or [],
                     assurance_sampling_rate=args.assurance_sampling_rate, reproducible=args.reproducible, registry=args.registry,
                     adapter=args.adapter, out=args.out, strict_flows=args.strict)
    try:
        report, rc = run_gate(inp)
    except GateUsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(format_summary(report))
    return rc


def cmd_decompose(args) -> int:
    import yaml
    from .config import load_config
    from .decompose import decompose_flow
    from .flows import FlowError, load_flows
    cfg = load_config(args.config)
    try:
        flows = load_flows(args.flows)
    except FlowError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    history = yaml.safe_load(open(args.history, encoding="utf-8")) if args.history else None
    out = {}
    for f in flows:
        h = (history or {}).get(f.id) if history else None
        out[f"{f.id}@{f.version}"] = decompose_flow(f.doc, cfg, h, sample_runs=args.sample_runs)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def cmd_tier(args) -> int:
    from .config import load_config
    from .tiering import policy, tier_from_dimensions, tier_from_score
    cfg = load_config(args.config)
    if args.score is not None:
        tier, score = tier_from_score(args.score, cfg), args.score
    else:
        dims = {}
        for d in args.dimension or []:
            k, _, v = d.partition("=")
            try:
                dims[k] = float(v)
            except ValueError:
                dims[k] = v
        if not dims:
            print("error: --score or at least one --dimension name=value", file=sys.stderr)
            return 2
        tier, score = tier_from_dimensions(dims, cfg)
    print(json.dumps({"criticality_score": round(score, 4), "tier": tier, "policy": policy(cfg, tier).as_dict()}, indent=2))
    return 0


def cmd_conformance(args) -> int:
    from .adapters import load_adapter
    from .config import load_config
    from .conformance import evaluate
    from .coverage import CertificateIndex, index_runs
    from .flows import FlowError, load_flows
    cfg = load_config(args.config)
    try:
        flows = load_flows(args.flows)
    except FlowError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    adapter = load_adapter(args.adapter, args.telemetry, accept_deprecated_aliases=True)
    index = CertificateIndex(args.dec_dir, args.trust_bundle, flows_dir=args.flows, methods=args.methods) if args.dec_dir else None
    rc = 0
    for f in flows:
        spans = [s for s in adapter.list_spans(f.id, adapter.extent()) if s.attributes.get("flow.version") == f.version]
        res = evaluate(f, index_runs(spans), index)
        w = res["window"]
        print(f"{f.id}@{f.version}: window {w['reading']}"
              + (f" absent={w['absent']}" if w["absent"] else "") + (f" divergent={w['divergent']}" if w["divergent"] else ""))
        for r in res["runs"]:
            recorded = [f"outcome: {r['outcome']}" if r.get("outcome") else "", f"termination: {r['termination']}" if r.get("termination") else ""]
            print(f"  run {r['trace_id']} [{r['source']}]: {r['reading']}  realized: {' '.join(r['realized'])}"
                  + ("  " + "  ".join(x for x in recorded if x) if any(recorded) else ""))
            for d in r["divergent"] + r["failed"]:
                print(f"      {d}")
            if r["absent"]:
                print(f"      absent: {' '.join(r['absent'])}")
            if r.get("degraded"):
                print(f"      degraded: {'; '.join(r['degraded'])}  (declared degradation paths taken; convergent by declaration)")
            for n in r.get("notes") or []:
                print(f"      note: {n}")
        if args.require_convergent and (w["reading"] != "convergent" or res["summary"]["non_convergent_runs"]):
            rc = 1
    return rc


def cmd_validate_report(args) -> int:
    from .report import validate_report
    try:
        validate_report(json.load(open(args.report, encoding="utf-8")))
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(f"OK — {args.report} matches coverage-report.schema.json")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="flowtrace", description="Flow-Based Telemetry Coverage — reference engine")
    ap.add_argument("--version", action="version", version=f"flowtrace {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gate", help="compute coverage, compare with tier thresholds, write coverage-report.json")
    g.add_argument("--flows", required=True, help="directory of *.flow.yaml (flow.spec/v0.2)")
    g.add_argument("--telemetry", required=True, action="append", help="OTLP/JSON export file (.jsonl); repeatable")
    _add_common(g)
    g.add_argument("--alerts", help="alerts.yaml (flowtrace.alerts/v0.1) for breach detectability")
    g.add_argument("--queries", action="append", help="query bindings (flowtrace.queries/v0.1); repeatable")
    g.add_argument("--trust-bundle", help="dec-trust/0.x bundle for execution evidence (B7)")
    g.add_argument("--dec-dir", action="append", help="directory of DEC certificates (*.dec.json), searched recursively; repeatable")
    g.add_argument("--methods", help="method artifacts for agent-dec's ND0 replay when its verifier is called on a run directory "
                                     "(default: methods/ in or beside a --dec-dir)")
    g.add_argument("--approvals", help="directory of human_approval attestations named <sha256 hex>.json, joined to dec.approval_digest "
                                       "and passed to agent-dec's verifier (default: approvals/ beside each run's chain)")
    g.add_argument("--baseline", help="a previous coverage-report.json to print deltas against")
    g.add_argument("--execution-evidence", action="store_true", help="enable the execution-evidence component (also scoring.execution_evidence.enabled)")
    g.add_argument("--sampling-rate", type=float, help="effective trace sampling rate of the export (default: config telemetry.assumed_sampling_rate)")
    g.add_argument("--assurance-telemetry", action="append",
                   help="the assurance stream as a second OTLP/JSON export (spec §4.1); repeatable; without it --telemetry is both streams")
    g.add_argument("--assurance-sampling-rate", type=float,
                   help="effective sampling rate of the assurance stream (default: config telemetry.assumed_assurance_sampling_rate, else --sampling-rate)")
    g.add_argument("--registry", help="polydiagram registry stub for R5 (component resolution)")
    g.add_argument("--strict", action="store_true", help="fail on R-DEPRECATED warnings in the flow descriptors")
    g.add_argument("--adapter", default="otlp_duckdb")
    g.add_argument("--out", default="coverage-report.json")
    g.add_argument("--reproducible", action="store_true", help="omit timestamps/commit and store basenames so two runs produce identical bytes")
    g.set_defaults(func=cmd_gate)

    d = sub.add_parser("decompose", help="derive per-step SLOs from the flow-level SLOs (FTC §4.3)")
    d.add_argument("--flows", required=True)
    _add_common(d)
    d.add_argument("--history", help="YAML {flow-id: {p95: {step: ms}, p99: {step: ms}}}")
    d.add_argument("--sample-runs", type=int, help="observed run count behind --history (cold start below the configured minimum)")
    d.set_defaults(func=cmd_decompose)

    t = sub.add_parser("tier", help="criticality score -> tier -> policy (FTC §4.2)")
    _add_common(t)
    t.add_argument("--score", type=float)
    t.add_argument("--dimension", action="append", metavar="NAME=VALUE", help="e.g. revenue_impact=critical user_impact=7")
    t.set_defaults(func=cmd_tier)

    c = sub.add_parser("conformance", help="convergent / absent / divergent over a window; per-run authorized-plan reading (FTC §4.8)")
    c.add_argument("--flows", required=True)
    c.add_argument("--telemetry", required=True, action="append")
    _add_common(c)
    c.add_argument("--dec-dir", action="append", help="run certificates: the manifest is the realized DAG (B6)")
    c.add_argument("--trust-bundle")
    c.add_argument("--methods", help="method artifacts for agent-dec's ND0 replay (default: methods/ in or beside a --dec-dir)")
    c.add_argument("--adapter", default="otlp_duckdb")
    c.add_argument("--require-convergent", action="store_true", help="exit 1 unless every reading is convergent")
    c.set_defaults(func=cmd_conformance)

    v = sub.add_parser("validate-report", help="validate a coverage-report.json against the schema")
    v.add_argument("report")
    v.set_defaults(func=cmd_validate_report)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
