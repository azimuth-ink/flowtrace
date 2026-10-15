"""FTC §4.6 — the CI coverage gate.

For every flow in --flows: compute the coverage score over the telemetry
window, compare it with the flow's tier threshold, record decomposition and
conformance, and write coverage-report.json (validated against
spec/schemas/coverage-report.schema.json). Exit 1 when any flow fails its
tier (score below threshold, or a fail-class finding such as a named blind
spot on a P0 flow, sampling below the floor, or — where the tier requires
convergence — a non-convergent run); exit 0 otherwise; exit 2 on a usage or
load error. With --baseline, per-component deltas are printed for review
comments and a decrease that stays above the threshold is a warning.
"""
from __future__ import annotations

import datetime as _dt
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Sequence

from . import REPORT_SCHEMA_VERSION, __version__
from .adapters import load_adapter
from .adapters.base import Window
from .answerability import evaluate as evaluate_answerability, load_query_bindings
from .config import load_config, weights_for
from .conformance import SLI_NAMES, evaluate as evaluate_conformance, evaluate_slis
from .coverage import (CertificateIndex, compose, evaluate_completeness, evaluate_cost_attribution,
                       evaluate_detectability, evaluate_execution_evidence, index_runs, load_alerts,
                       observed_slo_values)
from .decompose import decompose_flow
from .flows import Flow, FlowError, git_commit, load_flows
from .report import validate_report, write_report
from .tiering import policy

EPS = 1e-9


@dataclass
class GateInputs:
    flows: str
    telemetry: Sequence[str]
    config: str | None = None
    alerts: str | None = None
    trust_bundle: str | None = None
    dec_dirs: Sequence[str] = field(default_factory=list)
    methods: str | None = None                   # method artifacts for agent-dec's ND0 replay (default: methods/ in or beside a --dec-dir)
    queries: Sequence[str] = field(default_factory=list)
    baseline: str | None = None
    execution_evidence: bool | None = None       # None = per config
    sampling_rate: float | None = None
    reproducible: bool = False
    registry: str | None = None
    adapter: str = "otlp_duckdb"
    out: str = "coverage-report.json"
    strict_flows: bool = False


class GateUsageError(ValueError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _rel(p: str | None, reproducible: bool) -> str | None:
    if p is None:
        return None
    return pathlib.Path(p).name if reproducible else str(p)


def _finding(code: str, severity: str, message: str, step: str | None = None) -> dict:
    f = {"code": code, "severity": severity, "message": message}
    if step:
        f["step"] = step
    return f


# Divergence reasons of the per-run reading that the revision of 2026-10-11
# names as finding codes (spec §9): the prefix the reading writes -> the code.
READING_FINDING_CODES = (
    ("latched re-entry:", "latched-reentry"),                         # [D11]
    ("outcome:", "undeclared-outcome"),                               # [D11]
    ("degradation:", "undeclared-edge"),                              # [D11]
    ("attempts-exceeded:", "attempts-over-bound"),                    # [H4] more attempts than attempts.max and no on_exceed absorbed it
    ("retry-without-reconciliation:", "retry-without-reconciliation"),  # [H4] binding B17, from agent-dec's step 1d
)


def _reading_findings(conformance: dict, severity: str) -> list[dict]:
    """One finding per named code, counting the runs whose reading carries
    that reason; gated exactly as non-convergent-runs."""
    out = []
    for prefix, code in READING_FINDING_CODES:
        hits = [(r["trace_id"], d) for r in conformance["runs"] for d in r["divergent"] if d.startswith(prefix)]
        if hits:
            runs = sorted({t for t, _ in hits})
            out.append(_finding(code, severity, f"{len(runs)} run(s): {hits[0][1]}" + (f" (first of {len(hits)})" if len(hits) > 1 else "")))
    return out


def evaluate_flow(flow: Flow, adapter, window: Window, cfg: dict, *, alerts, bindings, index, exec_enabled: bool,
                  sampling_rate: float, baseline_flow: dict | None) -> dict:
    pol = policy(cfg, flow.criticality)
    spans_all = adapter.list_spans(flow.id, window)
    spans = [s for s in spans_all if s.attributes.get("flow.version") == flow.version]
    other_versions = sorted({s.attributes.get("flow.version") or "<none>" for s in spans_all} - {flow.version})
    runs = index_runs(spans)
    metrics = adapter.list_metrics(flow.id, window, flow.version)
    logs = adapter.list_logs(flow.id, window, flow.version)
    findings: list[dict] = []
    for w in flow.warnings:
        findings.append(_finding("deprecated-alias" if "R-DEPRECATED" in w else "flow-warning", "warn", w))
    if other_versions:
        findings.append(_finding("other-flow-versions", "warn",
                                 f"{len(spans_all) - len(spans)} span(s) carry flow.version in {other_versions}; evaluated {flow.version} only"))

    # --- conformance and the two-sided indicators (§7, §6.7) --------------------
    conformance = evaluate_conformance(flow, runs, index)
    slis = evaluate_slis(flow, conformance, cfg)

    # --- components -----------------------------------------------------------
    completeness = evaluate_completeness(flow, runs, metrics, logs)
    answerability = evaluate_answerability(flow, adapter, window, bindings, cfg["telemetry"]["default_dialect"],
                                           required=pol.answerability_required)
    detectability = evaluate_detectability(flow, runs, alerts, pol.alert_latency_s, slis=slis)
    cost = evaluate_cost_attribution(flow, runs, cfg["cost"]["attributes"])
    components: dict[str, dict] = {
        "completeness": completeness, "answerability": answerability.as_dict(),
        "detectability": detectability, "cost_attribution": cost,
    }
    if exec_enabled:
        components["execution_evidence"] = evaluate_execution_evidence(
            flow, runs, index, run_binding=str(cfg["scoring"]["execution_evidence"].get("run_binding", "warn")))
    weights = weights_for(cfg, exec_enabled)
    score, eff_weights = compose(components, weights)

    # --- findings -------------------------------------------------------------
    for sid in completeness["blind_spots"]:
        findings.append(_finding("blind-spot", "fail", f"step {sid} has no attributable telemetry in the window", sid))
    floor = max(pol.sampling_floor, flow.sampling_floor or 0.0)
    if sampling_rate + EPS < floor:
        findings.append(_finding("sampling-below-floor", "fail",
                                 f"effective sampling {sampling_rate} is below the floor {floor} (tier {pol.tier} / flow sampling_floor)"))
    if pol.answerability_required and not flow.has_answerability_block:
        findings.append(_finding("answerability-block-missing", "fail",
                                 f"tier {pol.tier} requires the answerability block (slo / required_telemetry / debug_scenarios) on at least one step"))
    for sc in answerability.scenarios:
        if sc.status != "answerable":
            findings.append(_finding(f"scenario-{sc.status.replace('_', '-')}", "warn",
                                     f"step {sc.step} scenario '{sc.scenario}': {sc.reason}", sc.step))
    for t in detectability.get("targets", []):
        if not t["detectable"]:
            findings.append(_finding("undetectable-breach", "warn", f"{t['scope']} {t['slo']}: {t['reason']}",
                                     None if t["scope"] == "flow" else t["scope"]))
    if exec_enabled:
        for w in components["execution_evidence"].get("warnings", []):
            findings.append(_finding("evidence-run-binding", "warn", w))
        for sid, st in components["execution_evidence"]["steps"].items():
            if st["fraction"] < 1.0:
                findings.append(_finding("evidence-missing", "warn",
                                         f"step {sid}: {st['verified']}/{st['runs']} runs carry a verifiable dec.step_cert_digest", sid))

    # --- decomposition from the window's own history --------------------------
    observed = observed_slo_values(flow, runs)
    history = {"p95": {sid: v["latency_p95_ms"] for sid, v in observed.items() if sid != "flow"},
               "p99": {sid: v["latency_p99_ms"] for sid, v in observed.items() if sid != "flow"}}
    decomposition = decompose_flow(flow.doc, cfg, history, sample_runs=len(runs))

    # --- conformance and indicator findings -------------------------------------
    for name in SLI_NAMES:
        s = (slis or {}).get(name)
        if s and s["out_of_band"]:
            count = s.get("degraded_runs", s.get("vetoed_runs"))
            findings.append(_finding("sli-out-of-band", "fail" if s["band"]["gate"] else "warn",
                                     f"{name} {s['rate']} is {s['out_of_band']} the declared band "
                                     f"[{s['band']['min']}, {s['band']['max']}] ({count}/{s['runs']} runs; source {s['source']}"
                                     f"{', approximate' if s['approximate'] else ''})"))
    if conformance["window"]["divergent"]:
        findings.append(_finding("off-plan-steps", "fail" if pol.require_convergent else "warn",
                                 f"observed steps not declared by the flow: {conformance['window']['divergent']}"))
    if conformance["summary"]["non_convergent_runs"]:
        findings.append(_finding("non-convergent-runs", "fail" if pol.require_convergent else "warn",
                                 f"{conformance['summary']['non_convergent_runs']} run(s) read divergent or failed against the authorized plan"))
    findings += _reading_findings(conformance, "fail" if pol.require_convergent else "warn")

    # --- verdict --------------------------------------------------------------
    below = score + EPS < pol.coverage_threshold
    fail_findings = [f for f in findings if f["severity"] == "fail"]
    verdict = "fail" if (below or fail_findings) else "pass"
    reasons = []
    if below:
        reasons.append(f"score {score:.4f} < tier {pol.tier} threshold {pol.coverage_threshold:.2f}")
    reasons += [f["code"] for f in fail_findings]

    delta = None
    if baseline_flow:
        b_score = float(baseline_flow.get("score", 0.0))
        delta = {"baseline_score": b_score, "score": score, "delta": round(score - b_score, 6), "components": {}}
        for k, v in components.items():
            bv = (baseline_flow.get("components") or {}).get(k, {}).get("score")
            delta["components"][k] = {"baseline": bv, "score": v["score"],
                                      "delta": None if bv is None else round(float(v["score"]) - float(bv), 6)}
        if score + EPS < b_score and verdict == "pass":
            findings.append(_finding("score-decreased", "warn", f"score decreased {b_score:.4f} -> {score:.4f} (still above threshold)"))
        if score + EPS < b_score and verdict == "fail" and b_score + EPS >= pol.coverage_threshold:
            findings.append(_finding("tier-threshold-regression", "fail",
                                     f"score regressed below the tier threshold: {b_score:.4f} -> {score:.4f} (< {pol.coverage_threshold:.2f})"))

    return {
        "id": flow.id, "version": flow.version, "criticality": flow.criticality, "descriptor": flow.path.name,
        "descriptor_sha256": flow.sha256, "tier_policy": pol.as_dict(),
        "runs_sampled": len(runs), "spans": len(spans), "effective_sampling": sampling_rate,
        "score": score, "threshold": pol.coverage_threshold, "verdict": verdict, "verdict_reasons": reasons,
        "weights": eff_weights, "execution_evidence_enabled": exec_enabled,
        "components": components, "decomposition": decomposition, "conformance": conformance, "slis": slis,
        "observed_slos": {scope: {k: (None if v is None else round(v, 6)) for k, v in vals.items()} for scope, vals in observed.items()},
        "findings": findings, "delta": delta,
    }


def run_gate(inp: GateInputs) -> tuple[dict, int]:
    cfg = load_config(inp.config)
    exec_enabled = bool(cfg["scoring"]["execution_evidence"].get("enabled", False)) if inp.execution_evidence is None else inp.execution_evidence
    if exec_enabled and not (inp.trust_bundle and inp.dec_dirs):
        raise GateUsageError("execution evidence is enabled: pass --trust-bundle and --dec-dir (or disable scoring.execution_evidence)")
    if not inp.telemetry:
        raise GateUsageError("at least one --telemetry file")
    for p in list(inp.telemetry) + [inp.alerts, inp.trust_bundle, inp.baseline, inp.methods] + list(inp.queries) + list(inp.dec_dirs):
        if p and not pathlib.Path(p).exists():
            raise GateUsageError(f"not found: {p}")
    try:
        flows = load_flows(inp.flows, registry=inp.registry, strict=inp.strict_flows)
    except FlowError as e:
        raise GateUsageError(str(e)) from None
    adapter = load_adapter(inp.adapter, inp.telemetry, accept_deprecated_aliases=bool(cfg["telemetry"].get("accept_deprecated_aliases", True)))
    window = adapter.extent()
    alerts = load_alerts(inp.alerts) if inp.alerts else None
    bindings = load_query_bindings(inp.queries) if inp.queries else []
    index = (CertificateIndex(inp.dec_dirs, inp.trust_bundle, flows_dir=inp.flows, methods=inp.methods)
             if (inp.dec_dirs or inp.trust_bundle) else None)
    sampling = float(inp.sampling_rate if inp.sampling_rate is not None else cfg["telemetry"].get("assumed_sampling_rate", 1.0))
    baseline = json.loads(pathlib.Path(inp.baseline).read_text(encoding="utf-8")) if inp.baseline else None
    base_flows = {f["id"]: f for f in (baseline or {}).get("flows", [])}

    results = [evaluate_flow(f, adapter, window, cfg, alerts=alerts, bindings=bindings, index=index,
                             exec_enabled=exec_enabled, sampling_rate=sampling, baseline_flow=base_flows.get(f.id))
               for f in flows]
    counts = adapter.counts() if hasattr(adapter, "counts") else {}
    verdict = "pass" if all(r["verdict"] == "pass" for r in results) else "fail"
    report = {
        "flowtrace": {"version": __version__, "report_schema": REPORT_SCHEMA_VERSION},
        "generated_at": None if inp.reproducible else _now(),
        "inputs": {
            "flows_dir": _rel(inp.flows, inp.reproducible),
            "flows_commit": None if inp.reproducible else git_commit(inp.flows),
            "telemetry": [_rel(t, inp.reproducible) for t in inp.telemetry],
            "telemetry_sha256": [_sha256(t) for t in inp.telemetry],
            "config": _rel(inp.config, inp.reproducible) or "<defaults>",
            "alerts": _rel(inp.alerts, inp.reproducible),
            "queries": [_rel(q, inp.reproducible) for q in inp.queries],
            "trust_bundle": _rel(inp.trust_bundle, inp.reproducible),
            "dec_dirs": [_rel(d, inp.reproducible) for d in inp.dec_dirs],
            "methods": _rel(str(index.methods), inp.reproducible) if (index is not None and index.methods) else None,
            "baseline": _rel(inp.baseline, inp.reproducible),
            "adapter": adapter.name,
            "dialects": sorted(adapter.dialects),
        },
        "window": dict(window.as_dict(), **counts),
        "ingest_warnings": list(adapter.ingest_warnings) + (index.errors if index else []),
        "flows": results,
        "verdict": verdict,
        "exit_code": 0 if verdict == "pass" else 1,
    }
    validate_report(report)
    write_report(report, inp.out)
    return report, report["exit_code"]


def _sha256(path: str) -> str:
    import hashlib
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


# ----------------------------------------------------------------- printing
def format_summary(report: dict) -> str:
    lines = []
    for f in report["flows"]:
        tag = "PASS" if f["verdict"] == "pass" else "FAIL"
        cmp_ = ">=" if f["score"] + EPS >= f["threshold"] else "<"
        lines.append(f"GATE {f['id']}@{f['version']} [{f['criticality']}]: score {f['score']:.4f} {cmp_} threshold {f['threshold']:.2f} — {tag}"
                     + (f" ({'; '.join(f['verdict_reasons'])})" if f["verdict_reasons"] else ""))
        for k, c in f["components"].items():
            w = f["weights"].get(k)
            extra = ""
            if k == "completeness":
                extra = f"  runs {c['runs_complete']}/{c['runs_sampled']} complete" + (f"; blind spots {c['blind_spots']}" if c["blind_spots"] else "")
            elif k == "answerability":
                extra = f"  scenarios {c['answerable']}/{c['declared']} answerable" + (f" ({c['not_evaluated']} not evaluated)" if c["not_evaluated"] else "")
            elif k == "detectability":
                extra = f"  targets {sum(1 for t in c.get('targets', []) if t['detectable'])}/{len(c.get('targets', []))} detectable"
            elif k == "cost_attribution":
                extra = f"  steps {sum(1 for s in c['by_step'].values() if s['attributable'])}/{len(c['by_step'])} attributable"
            elif k == "execution_evidence":
                extra = "  " + ", ".join(f"{sid} {st['verified']}/{st['runs']}" for sid, st in c["steps"].items())
            na = "" if c.get("applicable", True) else "  (not applicable)"
            lines.append(f"  {k:<19} {float(c['score']):.4f}  weight {w if w is not None else '-'}{na}{extra}")
        conf = f["conformance"]
        lines.append(f"  conformance         window {conf['window']['reading']}"
                     + (f" absent={conf['window']['absent']}" if conf["window"]["absent"] else "")
                     + (f" divergent={conf['window']['divergent']}" if conf["window"]["divergent"] else "")
                     + f"; runs {conf['summary']['by_reading']}")
        if f.get("slis"):
            for name, s in f["slis"].items():
                count = s.get("degraded_runs", s.get("vetoed_runs"))
                lines.append(f"  {name:<19} {s['rate']:.4f}  band [{s['band']['min']}, {s['band']['max']}]  {count}/{s['runs']} runs"
                             f"  source {s['source']}{' (approximate)' if s['approximate'] else ''}"
                             + (f"  OUT OF BAND ({s['out_of_band']})" if s["out_of_band"] else ""))
        if f["delta"]:
            d = f["delta"]
            lines.append(f"  delta vs baseline   score {d['baseline_score']:.4f} -> {d['score']:.4f} ({d['delta']:+.4f})")
            for k, c in d["components"].items():
                if c["delta"] is not None and abs(c["delta"]) > EPS:
                    lines.append(f"    {k:<17} {float(c['baseline']):.4f} -> {float(c['score']):.4f} ({c['delta']:+.4f})")
        for fd in f["findings"]:
            lines.append(f"  {fd['severity'].upper():<5} {fd['code']}: {fd['message']}")
    for w in report.get("ingest_warnings", []):
        lines.append(f"  WARN  ingest: {w}")
    lines.append(f"VERDICT: {report['verdict'].upper()} — {len(report['flows'])} flow(s); report written")
    return "\n".join(lines)
