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

from .adapters.base import CANONICAL_ATTRIBUTES, Adapter, LogRow, MetricRow, SpanRow, Window
from .config import REPLAYABLE_ND_CLASSES
from .flows import (ATTRIBUTE_CLASSES, Flow, attribute_entries, required_log_specs, required_metric_specs,
                    required_trace_specs)
from .decompose import sync_frontier

B2_ATTRIBUTES = ("flow.id", "flow.version", "flow.step")
KNOWN_SLO_KEYS = ("latency_p95_ms", "latency_p99_ms", "error_rate_percent", "availability")
FLOW_SLO_KEYS = ("latency_p95_ms", "async_completion_p99_s", "availability")
DEFAULT_NAMESPACE_CLASSES = {"flow.*": "identifier", "dec.*": "digest"}


# =============================================================== attribute classes (FTC §4.4; spec §4.1)
def resolve_attribute_class(name: str, declared: str | None, namespace_defaults: Mapping[str, str] | None = None) -> tuple[str, str]:
    """-> (class, source) with source in declared | namespace | assumed. A
    declared class is taken as declared (the class is declared, never
    inferred, on a flow with an assurance stream — validator R15). A
    name-only entry resolves through the canonical namespace table (FTC
    §4.7: `flow.*` identifiers, `dec.*` digests) and the configured
    `attribute_classes.namespace_defaults`, else to `identifier`, recorded
    as assumed."""
    if declared in ATTRIBUTE_CLASSES:
        return declared, "declared"
    if name in CANONICAL_ATTRIBUTES:
        return CANONICAL_ATTRIBUTES[name], "namespace"
    for pattern, klass in (namespace_defaults if namespace_defaults is not None else DEFAULT_NAMESPACE_CLASSES).items():
        prefix = pattern[:-1] if pattern.endswith("*") else pattern
        if (name.startswith(prefix) if pattern.endswith("*") else name == prefix) and klass in ATTRIBUTE_CLASSES:
            return klass, "namespace"
    return "identifier", "assumed"


def classified_attributes(flow: Flow, namespace_defaults: Mapping[str, str] | None = None) -> dict[str, list[dict]]:
    """Per step: every required attribute of every trace spec with its
    resolved class, whether it was assumed, and the stream it is read from
    (`content` -> sampled; everything else -> assurance)."""
    out: dict[str, list[dict]] = {}
    for s in flow.steps:
        rows = []
        for spec in required_trace_specs(s):
            for e in attribute_entries(spec):
                klass, source = resolve_attribute_class(e["name"], e["class"], namespace_defaults)
                rows.append({"span_name": spec.get("span_name"), "name": e["name"], "class": klass,
                             "class_assumed": source == "assumed", "class_source": source,
                             "stream": "sampled" if klass == "content" else "assurance"})
        out[s["id"]] = rows
    return out


def content_attributes(flow: Flow, namespace_defaults: Mapping[str, str] | None = None) -> dict[str, set[str]]:
    """Per step, the names of its required attributes of class content."""
    return {sid: {r["name"] for r in rows if r["class"] == "content"} for sid, rows in classified_attributes(flow, namespace_defaults).items()}


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
                          logs: Sequence[LogRow], *, sampled_runs: Mapping[str, Run] | None = None,
                          namespace_defaults: Mapping[str, str] | None = None,
                          assurance_export_distinct: bool = False) -> dict:
    """`runs` are the runs of the assurance stream (the sampled traces of FTC
    §4.5 "computation over the assurance stream"); `sampled_runs`, when the
    two streams are distinct exports, are the sampled stream's runs, read for
    required attributes of class `content` and joined by trace id — a run
    absent from the sampled stream is *not evaluated* for such an attribute,
    not missing (spec §4.1). With one export both are the same runs."""
    steps = flow.steps
    step_ids = [s["id"] for s in steps]
    classes = classified_attributes(flow, namespace_defaults)
    sampled = runs if sampled_runs is None else sampled_runs
    not_evaluated: dict[str, dict[str, int]] = {sid: {} for sid in step_ids}
    content_on_assurance: dict[tuple[str, str], int] = {}
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
                    for entry in [c for c in classes[sid] if c["span_name"] == spec["span_name"]]:
                        key = entry["name"]
                        if entry["class"] != "content":
                            if not any(_attr_present(x, key) for x in cands):
                                missing.append(f"span {spec['span_name']} lacks required attribute {key}")
                            continue
                        # a content attribute is read from the sampled stream (FTC §4.4); it must not ride the assurance stream
                        if assurance_export_distinct and any(_attr_present(x, key) for x in cands):
                            content_on_assurance[(sid, key)] = content_on_assurance.get((sid, key), 0) + 1
                        srun = sampled.get(run.trace_id)
                        scands = [x for x in (srun.by_step.get(sid, []) if srun else []) if x.name == spec["span_name"]]
                        if srun is None or not scands:
                            not_evaluated[sid][key] = not_evaluated[sid].get(key, 0) + 1
                        elif not any(_attr_present(x, key) for x in scands):
                            missing.append(f"span {spec['span_name']} lacks required attribute {key} (content; sampled stream)")
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
        d["attributes"] = classes[sid]
        d["not_evaluated"] = dict(sorted(not_evaluated[sid].items()))
    blind = [sid for sid in step_ids if by_step[sid]["present_runs"] == 0]
    return {
        "score": (runs_complete / n) if n else 0.0,
        "applicable": True,
        "runs_sampled": n,
        "runs_complete": runs_complete,
        "blind_spots": blind,
        "by_step": by_step,
        "class_assumed": sorted({f"{sid}:{r['name']}" for sid, rows in classes.items() for r in rows if r["class_assumed"]}),
        "content_on_assurance": [{"step": sid, "attribute": key, "runs": c} for (sid, key), c in sorted(content_on_assurance.items())],
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
                 flows_dir: str | pathlib.Path | None = None, methods: str | pathlib.Path | None = None,
                 approvals: str | pathlib.Path | None = None):
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
        self.approvals: dict[str, tuple[pathlib.Path, dict]] = {}        # human_approval attestations, by digest (unit H2)
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
        # [H2] human_approval attestations: `approvals/<sha256 hex>.json` beside a run's chain (agent-dec's layout;
        # the approval is not a chain member) and every *.json under --approvals, indexed by their digest —
        # the value of dec.approval_digest and of the record's decision.approval_ref
        self.approvals_dir = pathlib.Path(approvals) if approvals else None
        files = [p for root in self.dirs for p in sorted(root.rglob("approvals/*.json"))]
        if self.approvals_dir is not None:
            files += sorted(self.approvals_dir.glob("*.json"))
        for p in files:
            try:
                a = json.loads(p.read_text(encoding="utf-8"))
                digest = vd.cert_digest(a)
            except (ValueError, TypeError) as e:
                self.errors.append(f"{p}: unreadable ({str(e)[:60]})")
                continue
            if isinstance(a, dict) and a.get("kind") == "attestation" and a.get("type") == "human_approval":
                self.approvals[digest] = (p, a)
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
                                 approvals=self.approvals_dir, runs_dirs=[])
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
        # [D13] a hosted method (method.kind: hosted, evidence.type: configuration_record, replay: none) verifies on the
        # same conditions: the engine never attempts replay for any certificate, so nothing here is special-cased.
        if subj.get("run_id") != span.trace_id and span.attributes.get("flow.run_id") != subj.get("run_id"):
            return "run-binding-mismatch", f"{path.name}: subject.run_id {subj.get('run_id')} != span trace {span.trace_id} (B3/B4)"
        return "verified", None

    def evidence_type(self, digest: str) -> str | None:
        """[D13] the certificate's `evidence.type` (replay_recipe, …, or
        configuration_record for a hosted set-bounded method), reported so
        the report shows which evidence is attested by configuration
        provenance rather than replayable; None when the digest is unknown."""
        hit = self.steps.get(digest)
        if hit is None:
            return None
        ev = hit[1].get("evidence") or {}
        return str(ev.get("type")) if ev.get("type") else None

    # ---- revision 2026-10-11 (D15, spec §6.6): authorization evidence of an effect step ----
    def _bind(self, path: pathlib.Path, doc: dict, span: SpanRow) -> tuple[str, str] | None:
        """(status, reason) when the artifact's subject does not bind to the
        span's flow / step / run (B3/B4/B7), else None."""
        subj = doc.get("subject") or {}
        fl = subj.get("flow") or {}
        want = (span.attributes.get("flow.id"), span.attributes.get("flow.version"), span.attributes.get("flow.step"))
        got = (fl.get("id"), fl.get("version"), fl.get("step"))
        if got != want or subj.get("step_id") != want[2]:
            return "flow-mismatch", f"{path.name}: subject.flow {got} != span {want} (B7)"
        if subj.get("run_id") != span.trace_id and span.attributes.get("flow.run_id") != subj.get("run_id"):
            return "run-binding-mismatch", f"{path.name}: subject.run_id {subj.get('run_id')} != span trace {span.trace_id} (B3/B4)"
        return None

    def _signed(self, path: pathlib.Path, doc: dict, klass: str) -> tuple[str, str] | None:
        """(status, reason) when the artifact's signature does not verify in
        the trust-bundle class its kind resolves in, else None."""
        if self.resolve is None:
            return "unverifiable", "no trust bundle supplied"
        key, why = self.resolve(doc, klass)
        if key is None:
            if why and "not in trust bundle class" in why:
                return "authority-not-trusted" if klass == "policy_authorities" else "signature-invalid", f"{path.name}: {why}"
            return "signature-invalid", f"{path.name}: {why}"
        if not self.vd.verify_signature(doc, key):
            return "signature-invalid", f"{path.name}: signature invalid"
        return None

    def verify_authorization_digest(self, digest: str, span: SpanRow) -> tuple[str, str | None]:
        """-> (status, reason) for an effect step's dec.authz_cert_digest (spec
        §6.6): verified | artifact-not-found | signature-invalid |
        authority-not-trusted | flow-mismatch | run-binding-mismatch | denied |
        authorization-expired | authorization-stale | approval-invalid |
        unverifiable. The step-1d checks (order in the chain, validity window,
        freshness, the cited approval) are agent-dec's verifier's, read from
        its result for the run directory; the record is not re-checked here."""
        hit = self.authorizations.get(digest)
        if hit is None:
            return "artifact-not-found", f"no kind: authorization artifact with digest {digest[:19]}… under --dec-dir"
        path, doc = hit
        bad = self._signed(path, doc, "policy_authorities")
        if bad:
            return bad
        bad = self._bind(path, doc, span)
        if bad and bad[0] != "run-binding-mismatch":
            return bad
        binding = bad                                       # None, or the run-binding mismatch to report after the checks
        decision = (doc.get("decision") or {})
        if decision.get("decision") != "allow":
            return "denied", (f"{path.name}: decision {decision.get('decision')}"
                              + (f", reason {decision.get('reason')!r}" if decision.get("reason") else ""))
        vr = self.verifier_result(self.run_directory(path))
        if vr.error or vr.verdict == "error":
            return "unverifiable", f"{path.name}: agent-dec's verifier could not evaluate {path.parent.name}/ ({vr.error or 'no verdict'})"
        step_file = self._effect_certificate_for(path, doc)
        if step_file is None:
            return "unverifiable", f"{path.name}: no step certificate for the same step, key and attempt in {path.parent.name}/"
        for name, reason in vr.findings_for(step_file):
            if name == "authorization-expired":
                return "authorization-expired", f"{step_file}: {reason}"
            if name == "authorization-stale":
                return "authorization-stale", f"{step_file}: {reason}"
            if name in ("sod-violation", "approval-payload-mismatch"):
                return "approval-invalid", f"{step_file}: {name}: {reason}"
            if name == "effect-without-authorization":
                return "unverifiable", f"{step_file}: the verifier does not accept this record as the step's authorization: {reason}"
        if binding:
            return binding
        return "verified", None

    def _effect_certificate_for(self, authz_path: pathlib.Path, authz: dict) -> str | None:
        """The file name of the step certificate in the same run directory with
        the authorization's step id, idempotency key commitment and attempt
        id (the member the verifier attributes the step-1d findings to)."""
        subj = authz.get("subject") or {}
        ident = (subj.get("step_id"), subj.get("idempotency_key_commitment"), subj.get("attempt_id"))
        run_dir = self.run_directory(authz_path)
        for p, (digest, doc) in self.by_path.items():
            if p.parent != run_dir or doc.get("kind") is not None:
                continue
            s = doc.get("subject") or {}
            if (s.get("step_id"), s.get("idempotency_key_commitment"), s.get("attempt_id")) == ident:
                return p.name
        return None

    def approval_for(self, digest: str, span: SpanRow) -> tuple[str, str | None]:
        """[H2] -> (status, reason) for dec.approval_digest: `resolved` when
        the attestation is found, its signature verifies in approvers[] and
        its subject (when it names a flow / run) binds to the span; else
        artifact-not-found | signature-invalid | flow-mismatch |
        run-binding-mismatch | unverifiable. The B11 / B15 checks on the
        approval are the verifier's (sod-violation,
        approval-payload-mismatch), read through the authorization status."""
        hit = self.approvals.get(digest)
        if hit is None:
            return "artifact-not-found", f"no human_approval attestation with digest {digest[:19]}… under --dec-dir / --approvals"
        path, doc = hit
        bad = self._signed(path, doc, "approvers")
        if bad:
            return bad
        subj = doc.get("subject") or {}
        fl = subj.get("flow") or {}
        if fl and (fl.get("id"), fl.get("version"), fl.get("step")) != (span.attributes.get("flow.id"), span.attributes.get("flow.version"), span.attributes.get("flow.step")):
            return "flow-mismatch", f"{path.name}: subject.flow does not bind to the span"
        if subj.get("run_id") and subj["run_id"] != span.trace_id and span.attributes.get("flow.run_id") != subj["run_id"]:
            return "run-binding-mismatch", f"{path.name}: subject.run_id {subj['run_id']} != span trace {span.trace_id} (B3/B4)"
        return "resolved", None

    def completion_status(self, digest: str, span: SpanRow) -> tuple[str, str | None]:
        """-> (status, reason) for dec.completion_cert_digest: the completion's
        `status` (completed | failed | unknown | reconciled) when the artifact
        is found, verifies against keys[] and binds to the span; else
        artifact-not-found | signature-invalid | flow-mismatch |
        run-binding-mismatch | unverifiable."""
        hit = self.completions.get(digest)
        if hit is None:
            return "artifact-not-found", f"no kind: completion artifact with digest {digest[:19]}… under --dec-dir"
        path, doc = hit
        bad = self._signed(path, doc, "keys") or self._bind(path, doc, span)
        if bad and bad[0] != "run-binding-mismatch":
            return bad
        return str(doc.get("status")), (bad[1] if bad else None)

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


def _evidence_population(population: Sequence[str], runs: Mapping[str, Run], index: CertificateIndex | None,
                         run_binding: str, attribute: str, verify, label: str, evidence_type=None) -> tuple[dict[str, dict], int, int, list[str]]:
    """One population of the execution-evidence component (spec §6.5 / §6.6):
    per step and run, the boundary span's digest `attribute` verified by
    `verify(digest, span) -> (status, reason)`; run-binding mismatches count
    as evidence under `warn` and are reported. `evidence_type(digest)`, when
    given, is tallied per verified instance ([D13]: configuration_record
    marks evidence attested by configuration provenance, not replay)."""
    by_step: dict[str, dict] = {}
    total = verified = 0
    warnings: list[str] = []
    for sid in population:
        st = {"runs": 0, "verified": 0, "statuses": {}, "run_binding_mismatches": 0, "examples": []}
        if evidence_type is not None:
            st["evidence_types"] = {}
        for run in runs.values():
            bounds = run.boundaries.get(sid) or []
            st["runs"] += 1
            total += 1
            digest = None
            if not bounds:
                status, reason = "missing-span", "step not observed in this run"
            else:
                digest = bounds[0].attributes.get(attribute)
                if not digest:
                    status, reason = "missing-digest", f"boundary span carries no {attribute}"
                elif index is None:
                    status, reason = "unverifiable", "no --dec-dir / --trust-bundle supplied"
                else:
                    status, reason = verify(digest, bounds[0])
                    if status == "run-binding-mismatch":
                        st["run_binding_mismatches"] += 1
                        if run_binding != "strict":
                            status = "verified"      # B7 satisfied; run binding reported, not enforced
            if status == "verified":
                verified += 1
                st["verified"] += 1
                if evidence_type is not None:
                    et = evidence_type(digest) or "unknown"
                    st["evidence_types"][et] = st["evidence_types"].get(et, 0) + 1
            st["statuses"][status] = st["statuses"].get(status, 0) + 1
            if status != "verified" and len(st["examples"]) < 3:
                st["examples"].append({"trace_id": run.trace_id, "status": status, "reason": reason})
        st["fraction"] = (st["verified"] / st["runs"]) if st["runs"] else 0.0
        if st["run_binding_mismatches"] and run_binding != "strict":
            warnings.append(f"step {sid}: {st['run_binding_mismatches']} verified {label}(s) do not bind to the span's run "
                            f"(subject.run_id != trace id); counted as evidence because scoring.execution_evidence.run_binding is "
                            f"'{run_binding}' — set 'strict' to enforce B3/B4")
        by_step[sid] = st
    return by_step, total, verified, warnings


def _completion_and_approval(sid: str, runs: Mapping[str, Run], index: CertificateIndex | None, run_binding: str) -> dict:
    """Per effect step (spec §6.6): the completion evidence statuses and the
    approval digests the spans carry, resolved and reported, not scored."""
    statuses: dict[str, int] = {}
    approval_statuses: dict[str, int] = {}
    present = resolved = 0
    binding_mismatches = 0
    for run in runs.values():
        bounds = run.boundaries.get(sid) or []
        if not bounds:
            statuses["missing-span"] = statuses.get("missing-span", 0) + 1
            continue
        span = bounds[-1]                                  # the last attempt's span carries the final completion
        digest = span.attributes.get("dec.completion_cert_digest")
        if not digest:
            status = "missing-digest"
        elif index is None:
            status = "unverifiable"
        else:
            status, reason = index.completion_status(digest, span)
            if reason and "B3/B4" in reason:
                binding_mismatches += 1
                if run_binding == "strict":
                    status = "run-binding-mismatch"
        statuses[status] = statuses.get(status, 0) + 1
        approval = span.attributes.get("dec.approval_digest")
        if approval:
            present += 1
            if index is not None:
                a_status, a_reason = index.approval_for(approval, span)
                if a_status == "resolved" or (a_status == "run-binding-mismatch" and run_binding != "strict"):
                    resolved += 1
                approval_statuses[a_status] = approval_statuses.get(a_status, 0) + 1
    return {"completion_status": dict(sorted(statuses.items())), "completion_run_binding_mismatches": binding_mismatches,
            "approval_present": {"spans_with_digest": present, "resolved": resolved, "statuses": dict(sorted(approval_statuses.items()))}}


def evaluate_execution_evidence(flow: Flow, runs: Mapping[str, Run], index: CertificateIndex | None,
                                run_binding: str = "warn", count_completion: bool = False) -> dict:
    """Binding B7 (spec §6.5) over the ND0/ND1 steps (`dec.step_cert_digest`
    -> `certificate_coverage`) and, revision 2026-10-11 (spec §6.6), the
    effect steps (`dec.authz_cert_digest` -> `authorization_coverage`); the
    score is the pooled fraction over both populations' step-run instances.
    With `count_completion` a third population, the effect steps' completion
    evidence with status completed | reconciled, is pooled too."""
    replayable, effect = flow.replayable_steps, flow.effect_steps
    if not replayable and not effect:
        return {"score": 1.0, "applicable": False, "steps": {}, "authorization": {},
                "reason": "no step declares ND0/ND1 and none declares effect: true; component not applicable"}
    verify_step = index.verify_step_digest if index is not None else None
    verify_authz = index.verify_authorization_digest if index is not None else None
    steps, c_total, c_verified, warnings = _evidence_population(replayable, runs, index, run_binding, "dec.step_cert_digest",
                                                                verify_step, "certificate",
                                                                evidence_type=(index.evidence_type if index is not None else (lambda d: None)))
    authz, a_total, a_verified, a_warn = _evidence_population(effect, runs, index, run_binding, "dec.authz_cert_digest",
                                                              verify_authz, "authorization record")
    warnings += a_warn
    for sid in effect:
        authz[sid].update(_completion_and_approval(sid, runs, index, run_binding))
    total, verified = c_total + a_total, c_verified + a_verified
    completion_coverage = None
    if count_completion and effect:
        ok = sum(1 for sid in effect for s, n in authz[sid]["completion_status"].items() if s in ("completed", "reconciled") for _ in range(n))
        completion_coverage = (ok / a_total) if a_total else 0.0
        total += a_total
        verified += ok
    return {"score": (verified / total) if total else 0.0, "applicable": True, "steps": steps, "authorization": authz,
            "certificate_coverage": (c_verified / c_total) if c_total else None,
            "authorization_coverage": (a_verified / a_total) if a_total else None,
            "completion_coverage": completion_coverage,
            "populations": {"certificates": replayable, "authorization": effect, "completion": effect if count_completion else []},
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
