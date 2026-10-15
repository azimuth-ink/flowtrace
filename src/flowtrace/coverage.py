"""FTC §4.5 — the multi-dimensional coverage score.

Components (each returns a score in [0, 1] and whether it is applicable):

  completeness        fraction of sampled runs in which every declared step is
                      observable: a boundary span carrying flow.id / flow.version /
                      flow.step (B2, the minimal completeness check) and, where the
                      step declares required_telemetry, every required span with its
                      required attributes, every required metric and every required
                      log present. Named blind spots: steps with no attributable
                      telemetry at all in the window.
  answerability       answerability.py (§4.4).
  detectability       whether breaches of the asserted SLOs (flow-level and per-step)
                      would be detected by the configured alerts within the tier's
                      alert-latency bound (alerts.yaml, §5.3 of the spec).
  cost_attribution    whether per-step (and so per-flow) cost is attributable from
                      the telemetry: a step is attributable when its boundary spans
                      carry a configured cost attribute.
  execution_evidence  (optional, B7) for steps declared ND0/ND1, the fraction of
                      sampled runs whose boundary span carries a dec.step_cert_digest
                      that verifies: the certificate is found, its signature verifies
                      against the issuer's trust bundle (agent-dec's verifier, called
                      as a library), and its subject.flow equals the span's
                      flow.id / flow.version / flow.step.

Weights come from the config (0.40/0.30/0.20/0.10, or 0.35/0.25/0.20/0.10/0.10
with execution evidence); components that are not applicable are dropped and
the remaining weights renormalized.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from .adapters.base import Adapter, LogRow, MetricRow, SpanRow, Window
from .config import REPLAYABLE_ND_CLASSES
from .flows import Flow, required_log_specs, required_metric_specs, required_trace_specs
from .decompose import sync_frontier

B2_ATTRIBUTES = ("flow.id", "flow.version", "flow.step")
KNOWN_SLO_KEYS = ("latency_p95_ms", "latency_p99_ms", "error_rate_percent", "availability")
FLOW_SLO_KEYS = ("latency_p95_ms", "async_completion_p99_s", "availability")


# =============================================================== run indexing
@dataclass
class Run:
    trace_id: str
    spans: list[SpanRow] = field(default_factory=list)
    by_step: dict[str, list[SpanRow]] = field(default_factory=dict)
    boundaries: dict[str, list[SpanRow]] = field(default_factory=dict)   # per step, ordered by start

    @property
    def start_ns(self) -> int:
        return min(s.start_ns for s in self.spans)

    @property
    def end_ns(self) -> int:
        return max(s.end_ns for s in self.spans)

    @property
    def trigger(self) -> SpanRow | None:
        """The run's root span (no parent inside the trace), earliest start."""
        ids = {s.span_id for s in self.spans}
        roots = [s for s in self.spans if not s.parent_span_id or s.parent_span_id not in ids]
        return min(roots or self.spans, key=lambda s: s.start_ns)

    def realized(self) -> list[tuple[str, int]]:
        """Step executions in start order: [(step_id, start_ns)]; a loop
        iteration is one execution (one boundary span)."""
        out = [(sid, b.start_ns) for sid, bs in self.boundaries.items() for b in bs]
        return sorted(out, key=lambda t: (t[1], t[0]))


def index_runs(spans: Sequence[SpanRow]) -> dict[str, Run]:
    runs: dict[str, Run] = {}
    for s in spans:
        runs.setdefault(s.trace_id, Run(s.trace_id)).spans.append(s)
    for run in runs.values():
        by_id = {s.span_id: s for s in run.spans}
        for s in run.spans:
            sid = s.attributes.get("flow.step")
            if not sid:
                continue
            run.by_step.setdefault(sid, []).append(s)
            parent = by_id.get(s.parent_span_id) if s.parent_span_id else None
            # boundary: first span of the step in its subtree (parent is outside the step)
            if parent is None or parent.attributes.get("flow.step") != sid:
                run.boundaries.setdefault(sid, []).append(s)
        for bs in run.boundaries.values():
            bs.sort(key=lambda s: s.start_ns)
    return runs


def observed_steps(runs: Mapping[str, Run]) -> set[str]:
    return {sid for r in runs.values() for sid in r.boundaries}


# =============================================================== completeness
def _attr_present(span: SpanRow, key: str) -> bool:
    v = span.attributes.get(key)
    return v is not None and v != ""


def evaluate_completeness(flow: Flow, runs: Mapping[str, Run], metrics: Sequence[MetricRow],
                          logs: Sequence[LogRow]) -> dict:
    steps = flow.steps
    step_ids = [s["id"] for s in steps]
    # window-level: required metrics / logs per step
    window_missing: dict[str, list[str]] = {sid: [] for sid in step_ids}
    for s in steps:
        sid = s["id"]
        for m in required_metric_specs(s):
            hit = any(mr.name == m["name"] and mr.attributes.get("flow.id") == flow.id
                      and mr.attributes.get("flow.step") == sid for mr in metrics)
            if not hit:
                window_missing[sid].append(f"metric {m['name']} ({m.get('type', '?')}) with flow.id/flow.step labels")
        for lg in required_log_specs(s):
            level = str(lg.get("level", "")).upper()
            hit = any(lr.attributes.get("flow.id") == flow.id and lr.attributes.get("flow.step") == sid
                      and (not level or lr.severity == level or (level == "WARNING" and lr.severity == "WARN"))
                      for lr in logs)
            if not hit:
                window_missing[sid].append(f"log level {level} with flow.id/flow.step attributes")

    by_step: dict[str, dict] = {sid: {"present_runs": 0, "complete_runs": 0, "missing": {}} for sid in step_ids}
    runs_complete = 0
    for run in runs.values():
        run_ok = True
        for s in steps:
            sid = s["id"]
            missing: list[str] = []
            bounds = run.boundaries.get(sid) or []
            if not bounds:
                missing.append("no span carries flow.step=" + sid)
            else:
                by_step[sid]["present_runs"] += 1
                b = bounds[0]
                for key in B2_ATTRIBUTES:
                    if not _attr_present(b, key):
                        missing.append(f"boundary span lacks {key} (B2)")
                    elif key == "flow.version" and b.attributes[key] != flow.version:
                        missing.append(f"boundary span flow.version {b.attributes[key]} != declared {flow.version}")
                for spec in required_trace_specs(s):
                    cands = [x for x in run.by_step.get(sid, []) if x.name == spec["span_name"]]
                    if not cands:
                        missing.append(f"required span {spec['span_name']} absent")
                        continue
                    for key in spec.get("required_attributes") or []:
                        if not any(_attr_present(x, key) for x in cands):
                            missing.append(f"span {spec['span_name']} lacks required attribute {key}")
            missing += window_missing[sid]
            if missing:
                run_ok = False
                for m in missing:
                    by_step[sid]["missing"][m] = by_step[sid]["missing"].get(m, 0) + 1
            else:
                by_step[sid]["complete_runs"] += 1
        if run_ok:
            runs_complete += 1
    n = len(runs)
    for sid in step_ids:
        d = by_step[sid]
        d["fraction"] = (d["complete_runs"] / n) if n else 0.0
        d["missing"] = dict(sorted(d["missing"].items()))
    blind = [sid for sid in step_ids if by_step[sid]["present_runs"] == 0]
    return {
        "score": (runs_complete / n) if n else 0.0,
        "applicable": True,
        "runs_sampled": n,
        "runs_complete": runs_complete,
        "blind_spots": blind,
        "by_step": by_step,
        "reason": None if n else "no runs of the flow observed in the window",
    }


# =============================================================== detectability
def _percentile(values: Sequence[float], p: float) -> float | None:
    if not values:
        return None
    xs = sorted(values)
    if len(xs) == 1:
        return xs[0]
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def load_alerts(path: str | pathlib.Path) -> list[dict]:
    import yaml
    from . import ALERTS_API_VERSION
    doc = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
    if doc.get("apiVersion") != ALERTS_API_VERSION:
        raise ValueError(f"{path}: apiVersion {doc.get('apiVersion')!r} is not {ALERTS_API_VERSION}")
    alerts = []
    for i, a in enumerate(doc.get("alerts") or []):
        for key in ("flow", "slo", "threshold"):
            if key not in a:
                raise ValueError(f"{path}: alerts[{i}] lacks {key}")
        scope = a.get("scope") or ("step" if a.get("step") else "flow")
        if scope == "step" and not a.get("step"):
            raise ValueError(f"{path}: alerts[{i}] scope step needs a step id")
        if a.get("bound") not in (None, "max", "min"):
            raise ValueError(f"{path}: alerts[{i}] bound must be max or min")
        alerts.append({
            "id": a.get("id") or f"alert-{i}", "flow": a["flow"], "scope": scope, "step": a.get("step"),
            "slo": a["slo"], "threshold": float(a["threshold"]),
            "evaluation_window_s": float(a.get("evaluation_window_s", 0)),
            "notification_latency_s": float(a.get("notification_latency_s", 0)),
            # revision 2026-10-11 (spec §6.7): for slo degradation_rate | veto_rate, which bound of the band the alert watches
            "bound": a.get("bound"),
        })
    return alerts


def observed_slo_values(flow: Flow, runs: Mapping[str, Run]) -> dict[str, dict[str, float | None]]:
    """Observed values per scope ('flow' or step id) per SLO key, from boundary spans."""
    sync_ids, _ = sync_frontier(flow.doc)
    out: dict[str, dict[str, float | None]] = {"flow": {}}
    sync_ms, total_s, error_runs = [], [], 0
    for run in runs.values():
        trig = run.trigger
        if trig is None:
            continue
        sync_ends = [b.end_ns for sid in sync_ids for b in run.boundaries.get(sid, [])]
        all_ends = [b.end_ns for bs in run.boundaries.values() for b in bs]
        if sync_ends:
            sync_ms.append((max(sync_ends) - trig.start_ns) / 1e6)
        if all_ends:
            total_s.append((max(all_ends) - trig.start_ns) / 1e9)
        if any(b.status == "ERROR" for bs in run.boundaries.values() for b in bs):
            error_runs += 1
    n = len(runs)
    out["flow"]["latency_p95_ms"] = _percentile(sync_ms, 0.95)
    out["flow"]["async_completion_p99_s"] = _percentile(total_s, 0.99)
    out["flow"]["availability"] = (100.0 * (1 - error_runs / n)) if n else None
    for s in flow.steps:
        sid = s["id"]
        bounds = [b for r in runs.values() for b in r.boundaries.get(sid, [])]
        durs = [b.duration_ms for b in bounds]
        errs = sum(1 for b in bounds if b.status == "ERROR")
        out[sid] = {
            "latency_p95_ms": _percentile(durs, 0.95),
            "latency_p99_ms": _percentile(durs, 0.99),
            "error_rate_percent": (100.0 * errs / len(bounds)) if bounds else None,
            "availability": (100.0 * (1 - errs / len(bounds))) if bounds else None,
        }
    return out


def _breached(key: str, observed: float | None, target: float) -> bool | None:
    if observed is None:
        return None
    if key == "availability":
        return observed < target
    return observed > target


def _sli_targets(slis: Mapping[str, Any] | None) -> list[tuple[str, str, float, str]]:
    """Spec §6.7: an alert on `degradation_rate` / `veto_rate` makes the
    band's bounds detectability targets — the upper bound when the band
    declares one below 1.0 (`bound: max`), the lower bound when it declares
    one above 0.0 (`bound: min`). Rows: (indicator, bound, bound value, rate)."""
    out = []
    for name, s in (slis or {}).items():
        band = s["band"]
        if band["max"] < 1.0:
            out.append((name, "max", band["max"], s["rate"]))
        if band["min"] > 0.0:
            out.append((name, "min", band["min"], s["rate"]))
    return out


def evaluate_detectability(flow: Flow, runs: Mapping[str, Run], alerts: Sequence[Mapping[str, Any]] | None,
                           alert_latency_bound_s: float, slis: Mapping[str, Any] | None = None) -> dict:
    slos = (flow.doc.get("spec") or {}).get("slos") or {}
    targets: list[tuple[str, str, float]] = [("flow", k, float(slos[k])) for k in FLOW_SLO_KEYS if k in slos]
    for s in flow.steps:
        for k in KNOWN_SLO_KEYS:
            if k in (s.get("slo") or {}):
                targets.append((s["id"], k, float(s["slo"][k])))
    sli_targets = _sli_targets(slis)
    if not targets and not sli_targets:
        return {"score": 1.0, "applicable": False, "targets": [], "reason": "no SLO targets declared; component not applicable"}
    observed = observed_slo_values(flow, runs)
    rows, detectable = [], 0
    for scope, key, target in targets:
        obs = observed.get(scope, {}).get(key)
        breach = _breached(key, obs, target)
        cands = [a for a in (alerts or []) if a["flow"] == flow.id and a["slo"] == key
                 and ((a["scope"] == "flow" and scope == "flow") or (a["scope"] == "step" and a["step"] == scope))]
        row: dict[str, Any] = {"scope": scope, "slo": key, "target": target, "observed": None if obs is None else round(obs, 6),
                               "breached_in_window": breach, "alert": None, "detectable": False, "reason": None}
        if not cands:
            row["reason"] = "no alert configured for this target"
        else:
            a = cands[0]
            latency = a["evaluation_window_s"] + a["notification_latency_s"]
            adequate = (a["threshold"] >= target) if key == "availability" else (a["threshold"] <= target)
            row["alert"] = {"id": a["id"], "threshold": a["threshold"], "detection_latency_s": latency}
            if not adequate:
                row["reason"] = f"alert threshold {a['threshold']} is looser than the SLO target {target}"
            elif latency > alert_latency_bound_s:
                row["reason"] = f"detection latency {latency}s exceeds the tier bound {alert_latency_bound_s}s"
            elif breach and obs is not None and not ((a["threshold"] >= obs) if key == "availability" else (a["threshold"] <= obs)):
                row["reason"] = f"breach observed ({obs}) but the alert would not have fired (threshold {a['threshold']})"
            else:
                row["detectable"] = True
                detectable += 1
        rows.append(row)
    for name, bound, value, rate in sli_targets:
        # an upper bound is breached when the rate rises above it; a lower bound when the rate falls below it
        breach = (rate > value) if bound == "max" else (rate < value)
        cands = [a for a in (alerts or []) if a["flow"] == flow.id and a["slo"] == name and a["scope"] == "flow"
                 and (a.get("bound") or "max") == bound]
        row = {"scope": "flow", "slo": name, "bound": bound, "target": value, "observed": rate,
               "breached_in_window": breach, "alert": None, "detectable": False, "reason": None}
        if not cands:
            row["reason"] = f"no alert configured for the {bound} bound of the {name} band"
        else:
            a = cands[0]
            latency = a["evaluation_window_s"] + a["notification_latency_s"]
            adequate = (a["threshold"] <= value) if bound == "max" else (a["threshold"] >= value)
            fired = (a["threshold"] <= rate) if bound == "max" else (a["threshold"] >= rate)
            row["alert"] = {"id": a["id"], "threshold": a["threshold"], "detection_latency_s": latency}
            if not adequate:
                row["reason"] = f"alert threshold {a['threshold']} is looser than the band's {bound} {value}"
            elif latency > alert_latency_bound_s:
                row["reason"] = f"detection latency {latency}s exceeds the tier bound {alert_latency_bound_s}s"
            elif breach and not fired:
                row["reason"] = f"band breached ({rate}) but the alert would not have fired (threshold {a['threshold']})"
            else:
                row["detectable"] = True
                detectable += 1
        rows.append(row)
    targets = targets + [(name, bound, value) for name, bound, value, _ in sli_targets]
    return {"score": detectable / len(targets), "applicable": True, "targets": rows,
            "alert_latency_bound_s": alert_latency_bound_s,
            "reason": None if alerts is not None else "no alert configuration supplied (--alerts)"}


# =============================================================== cost attribution
def evaluate_cost_attribution(flow: Flow, runs: Mapping[str, Run], cost_attributes: Sequence[str]) -> dict:
    by_step: dict[str, dict] = {}
    attributable = 0
    for s in flow.steps:
        sid = s["id"]
        bounds = [b for r in runs.values() for b in r.boundaries.get(sid, [])]
        seen = sorted({k for b in bounds for k in cost_attributes if _attr_present(b, k)})
        total_usd = None
        if "cost.usd" in seen:
            try:
                total_usd = round(sum(float(b.attributes["cost.usd"]) for b in bounds if _attr_present(b, "cost.usd")), 6)
            except ValueError:
                total_usd = None
        ok = bool(seen)
        attributable += ok
        by_step[sid] = {"attributable": ok, "attributes_seen": seen, "spans": len(bounds), "cost_usd_total": total_usd}
    n = len(flow.steps)
    return {"score": (attributable / n) if n else 0.0, "applicable": True, "by_step": by_step,
            "flow_attributable": attributable == n, "cost_attributes": list(cost_attributes)}


# =============================================================== execution evidence (B7)
class CertificateIndex:
    """Step and run certificates under one or more directories, indexed by
    their JCS-canonical sha256 digest (agent-dec's cert_digest) — the value
    a span carries as dec.step_cert_digest / dec.run_cert_digest. Revision
    2026-10-11: the evidence artifacts (`kind: authorization | completion`)
    and `human_approval` attestations are indexed the same way (the values
    of dec.authz_cert_digest / dec.completion_cert_digest /
    dec.approval_digest), members are also indexed by path, and the step-1d
    readings of a run directory are taken from agent-dec's verifier through
    `verifier_result()` (flowtrace.evidence)."""

    def __init__(self, dirs: Sequence[str | pathlib.Path], trust_bundle: str | pathlib.Path | None, *,
                 flows_dir: str | pathlib.Path | None = None, methods: str | pathlib.Path | None = None):
        try:
            from agent_dec import verify_dec as vd  # type: ignore
        except ImportError:
            raise RuntimeError("execution evidence requires agent-dec (pip install 'flowtrace[companions]')") from None
        self.vd = vd
        self.dirs = [pathlib.Path(d) for d in dirs]
        self.steps: dict[str, tuple[pathlib.Path, dict]] = {}
        self.runs: dict[str, tuple[pathlib.Path, dict]] = {}
        self.runs_by_run_id: dict[str, dict[str, tuple[pathlib.Path, dict]]] = {}   # run_id -> {digest: (path, cert)}
        self.authorizations: dict[str, tuple[pathlib.Path, dict]] = {}
        self.completions: dict[str, tuple[pathlib.Path, dict]] = {}
        self.by_path: dict[pathlib.Path, tuple[str, dict]] = {}                         # member path -> (digest, doc)
        self.errors: list[str] = []
        self.run_binding_notes: list[str] = []
        for root in self.dirs:
            for p in sorted(root.rglob("*.dec.json")):
                try:
                    c = json.loads(p.read_text(encoding="utf-8"))
                    digest = vd.cert_digest(c)
                except (ValueError, TypeError) as e:
                    self.errors.append(f"{p}: unreadable ({str(e)[:60]})")
                    continue
                if not isinstance(c, dict):
                    self.errors.append(f"{p}: not a certificate document")
                    continue
                self.by_path[p.resolve()] = (digest, c)
                kind = c.get("kind")
                if kind == "run":
                    self.runs[digest] = (p, c)
                    rid = (c.get("subject") or {}).get("run_id")
                    if rid:
                        self.runs_by_run_id.setdefault(rid, {})[digest] = (p, c)
                elif kind == "authorization":
                    self.authorizations[digest] = (p, c)
                elif kind == "completion":
                    self.completions[digest] = (p, c)
                elif kind is None:                       # a step certificate (an ND2/ND3 one is the step's attestation)
                    self.steps[digest] = (p, c)
        self.trust_bundle_path = pathlib.Path(trust_bundle) if trust_bundle else None
        self.bundle = vd.load_trust_bundle(self.trust_bundle_path) if trust_bundle else None
        self.resolve = vd.build_resolver(None, self.bundle) if self.bundle else None
        self.flows_dir = pathlib.Path(flows_dir) if flows_dir else None
        self.methods = pathlib.Path(methods) if methods else self._find_methods()
        self._verifier_cache: dict[pathlib.Path, Any] = {}

    def _find_methods(self) -> pathlib.Path | None:
        """The method artifacts agent-dec's ND0 replay needs: `methods/` in a
        --dec-dir or beside it (the installed verifier's own default is
        relative to its package and does not exist outside a checkout)."""
        for root in self.dirs:
            for cand in (root / "methods", root.parent / "methods"):
                if cand.is_dir():
                    return cand
        return None

    def run_directory(self, path: pathlib.Path) -> pathlib.Path:
        """The run directory a chain member belongs to (the directory holding
        its run.dec.json: the member's own directory)."""
        return path.resolve().parent

    def verifier_result(self, run_dir: pathlib.Path):
        """agent-dec's verifier over one run directory (cached): the step-1d
        findings, notes, failures and UNCHECKED parts (flowtrace.evidence)."""
        from .evidence import run_verifier, verifier_argv
        key = run_dir.resolve()
        if key not in self._verifier_cache:
            argv = verifier_argv(key, trust_bundle=self.trust_bundle_path, flows_dir=self.flows_dir, methods=self.methods,
                                 approvals=None, runs_dirs=[])
            self._verifier_cache[key] = run_verifier(key, argv)
        return self._verifier_cache[key]

    def member(self, path: pathlib.Path) -> dict | None:
        hit = self.by_path.get(path.resolve())
        return hit[1] if hit else None

    def verify_step_digest(self, digest: str, span: SpanRow) -> tuple[str, str | None]:
        """-> (status, reason): verified | certificate-not-found | signature-invalid |
        flow-mismatch | class-mismatch | run-binding-mismatch | unverifiable."""
        hit = self.steps.get(digest)
        if hit is None:
            return "certificate-not-found", f"no step certificate with digest {digest[:19]}… under --dec-dir"
        path, cert = hit
        if self.resolve is None:
            return "unverifiable", "no trust bundle supplied"
        key, why = self.resolve(cert)
        if key is None:
            return "signature-invalid", why
        if not self.vd.verify_signature(cert, key):
            return "signature-invalid", f"{path.name}: signature invalid"
        subj = cert.get("subject") or {}
        fl = subj.get("flow") or {}
        want = (span.attributes.get("flow.id"), span.attributes.get("flow.version"), span.attributes.get("flow.step"))
        got = (fl.get("id"), fl.get("version"), fl.get("step"))
        if got != want or subj.get("step_id") != want[2]:
            return "flow-mismatch", f"{path.name}: subject.flow {got} != span {want} (B7)"
        if subj.get("class") not in REPLAYABLE_ND_CLASSES:
            return "class-mismatch", f"{path.name}: certificate class {subj.get('class')} is not ND0/ND1 (an attestation is not execution evidence)"
        if subj.get("run_id") != span.trace_id and span.attributes.get("flow.run_id") != subj.get("run_id"):
            return "run-binding-mismatch", f"{path.name}: subject.run_id {subj.get('run_id')} != span trace {span.trace_id} (B3/B4)"
        return "verified", None

    def run_certificate_for(self, run: Run) -> tuple[pathlib.Path, dict] | None:
        """The run certificate bound to this run (B3/B6): found through
        dec.run_cert_digest on the trigger span, or by subject.run_id equal to
        the trace id (or the span's explicit flow.run_id). A certificate that
        is referenced but whose subject.run_id does not bind to the run is
        rejected and noted in `run_binding_notes` (the spans remain the
        realized DAG)."""
        trig = run.trigger
        run_ids = {run.trace_id}
        if trig is not None and trig.attributes.get("flow.run_id"):
            run_ids.add(trig.attributes["flow.run_id"])
        hit = None
        if trig is not None:
            d = trig.attributes.get("dec.run_cert_digest")
            if d:
                hit = self.runs.get(d)
                if hit is None:
                    self.run_binding_notes.append(f"run {run.trace_id}: dec.run_cert_digest {d[:19]}… not found under --dec-dir")
                elif (hit[1].get("subject") or {}).get("run_id") not in run_ids:
                    self.run_binding_notes.append(
                        f"run {run.trace_id}: referenced run certificate {hit[0].name} binds run_id "
                        f"{(hit[1].get('subject') or {}).get('run_id')}, not this run; realized DAG taken from spans")
                    hit = None
        if hit is None:
            for rid in run_ids:
                cands = self.runs_by_run_id.get(rid) or {}
                if len(cands) == 1:
                    hit = next(iter(cands.values()))
                    break
                if len(cands) > 1:
                    self.run_binding_notes.append(
                        f"run {run.trace_id}: {len(cands)} distinct run certificates claim run_id {rid} and the trigger span "
                        f"names none by dec.run_cert_digest; realized DAG taken from spans")
        if hit is None:
            return None
        # a manifest is only the realized DAG (B6) when the run certificate itself verifies
        if self.resolve is not None:
            key, why = self.resolve(hit[1])
            if key is None or not self.vd.verify_signature(hit[1], key):
                self.run_binding_notes.append(
                    f"run {run.trace_id}: run certificate {hit[0].name} does not verify ({why or 'signature invalid'}); "
                    f"realized DAG taken from spans")
                return None
        return hit


def evaluate_execution_evidence(flow: Flow, runs: Mapping[str, Run], index: CertificateIndex | None,
                                run_binding: str = "warn") -> dict:
    population = flow.replayable_steps
    if not population:
        return {"score": 1.0, "applicable": False, "steps": {}, "reason": "no step declares ND0/ND1; component not applicable"}
    by_step: dict[str, dict] = {}
    total, verified = 0, 0
    warnings: list[str] = []
    for sid in population:
        st = {"runs": 0, "verified": 0, "statuses": {}, "run_binding_mismatches": 0, "examples": []}
        for run in runs.values():
            bounds = run.boundaries.get(sid) or []
            st["runs"] += 1
            total += 1
            if not bounds:
                status, reason = "missing-span", "step not observed in this run"
            else:
                digest = bounds[0].attributes.get("dec.step_cert_digest")
                if not digest:
                    status, reason = "missing-digest", "boundary span carries no dec.step_cert_digest"
                elif index is None:
                    status, reason = "unverifiable", "no --dec-dir / --trust-bundle supplied"
                else:
                    status, reason = index.verify_step_digest(digest, bounds[0])
                    if status == "run-binding-mismatch":
                        st["run_binding_mismatches"] += 1
                        if run_binding != "strict":
                            status = "verified"      # B7 satisfied; run binding reported, not enforced
            if status == "verified":
                verified += 1
                st["verified"] += 1
            st["statuses"][status] = st["statuses"].get(status, 0) + 1
            if status != "verified" and len(st["examples"]) < 3:
                st["examples"].append({"trace_id": run.trace_id, "status": status, "reason": reason})
        st["fraction"] = (st["verified"] / st["runs"]) if st["runs"] else 0.0
        if st["run_binding_mismatches"] and run_binding != "strict":
            warnings.append(f"step {sid}: {st['run_binding_mismatches']} verified certificate(s) do not bind to the span's run "
                            f"(subject.run_id != trace id); counted as evidence because scoring.execution_evidence.run_binding is "
                            f"'{run_binding}' — set 'strict' to enforce B3/B4")
        by_step[sid] = st
    return {"score": (verified / total) if total else 0.0, "applicable": True, "steps": by_step,
            "run_binding": run_binding, "warnings": warnings,
            "reason": None if index is not None else "no certificate index: every digest is unverifiable"}


# =============================================================== composition
def compose(components: Mapping[str, Mapping[str, Any]], weights: Mapping[str, float]) -> tuple[float, dict[str, float]]:
    """Weighted sum over applicable components; weights renormalized over them."""
    applicable = {k: w for k, w in weights.items() if k in components and components[k].get("applicable", True)}
    total_w = sum(applicable.values())
    if total_w <= 0:
        return 0.0, {}
    eff = {k: w / total_w for k, w in applicable.items()}
    score = sum(eff[k] * float(components[k]["score"]) for k in eff)
    return round(score, 6), {k: round(v, 6) for k, v in eff.items()}
