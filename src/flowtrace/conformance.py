"""FTC §4.8 / PD §5 — conformance: convergent, absent, divergent; the authorized plan.

Two readings:

  window (topology)  the declared step set vs the set of steps observed in the
                     window (spans grouped by flow.id / flow.step): absent =
                     declared, unobserved; divergent = observed, undeclared
                     (off-plan). Continuous, per window.
  run (plan)         per run, the realized step DAG against the declared graph
                     (`next`, bounds). Input per binding B6: the run
                     certificate's manifest.steps[] when the run carries one
                     (found through dec.run_cert_digest on the trigger span or
                     subject.run_id == trace id); the run's boundary spans in
                     start order otherwise. Off-plan steps, order violations,
                     repeats without a loop step, loop-bound exceedance per
                     on_exceed (fail -> failed-run; flag -> divergent) and
                     absent declared steps are reported per run.

The per-run rules are agent-dec's `conformance_reading` (spec/01, the
reference reading of a manifest) when agent-dec is installed; the local
`_reading` below implements the same rules so the gate runs without it, and
tests/test_conformance.py asserts the two agree.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .coverage import CertificateIndex, Run, observed_steps
from .flows import Flow


# ----------------------------------------------------------------- local rules
def _dag(doc: Mapping[str, Any]):
    steps = [s for s in (doc.get("spec") or {}).get("steps") or [] if isinstance(s, dict)]
    ids = [s.get("id") for s in steps]
    kinds = {s.get("id"): s.get("kind", "sync") for s in steps}
    adj = {}
    for i, s in enumerate(steps):
        adj[s.get("id")] = [n for n in (s.get("next") or ([ids[i + 1]] if i + 1 < len(ids) else [])) if n in kinds]
    forward = {u: [] for u in ids}
    color: dict[str, int] = {}
    if ids:
        root = ids[0]
        color[root] = 1
        stack = [(root, iter(adj[root]))]
        while stack:
            u, it = stack[-1]
            for v in it:
                if color.get(v) == 1:
                    continue                     # back-edge
                forward[u].append(v)
                if color.get(v) is None:
                    color[v] = 1
                    stack.append((v, iter(adj[v])))
                    break
            else:
                color[u] = 2
                stack.pop()
    reach = {}
    for u in ids:
        seen, todo = set(), list(adj[u])
        while todo:
            v = todo.pop()
            if v in seen:
                continue
            seen.add(v)
            todo.extend(adj[v])
        reach[u] = seen
    return ids, kinds, adj, forward, reach, {s.get("id"): s for s in steps}


def _reading(doc: Mapping[str, Any], realized: Sequence[tuple[str, str | None]]) -> dict:
    ids, kinds, adj, forward, reach, by_id = _dag(doc)
    divergent, absent, failed, seq = [], [], [], []
    for pos, (sid, fs) in enumerate(realized, 1):
        if fs is None:
            divergent.append(f"off-plan: [{sid}] at position {pos} is unbound (no subject.flow)")
        elif fs not in kinds:
            divergent.append(f"off-plan: {fs} at position {pos} is not a step of the declared flow")
        seq.append(fs if fs in kinds else None)
    ran = [s for s in seq if s is not None]
    first, last, count = {}, {}, {}
    for i, s in enumerate(ran):
        first.setdefault(s, i)
        last[s] = i
        count[s] = count.get(s, 0) + 1
    loop_steps = [s for s in ids if kinds[s] == "loop" and s in reach[s]]

    def may_repeat(s):
        return any(s == L or (L in reach[s] and s in reach[L]) for L in loop_steps)

    for s in ids:
        if count.get(s, 0) > 1 and not may_repeat(s):
            divergent.append(f"repeat: {s} ran {count[s]} times without a declared loop step on its cycle")
    for L in loop_steps:
        bound = by_id[L].get("bound") or {}
        mx, on_exceed = bound.get("max"), bound.get("on_exceed", "flag")
        n = count.get(L, 0)
        if isinstance(mx, int) and n > mx:
            msg = f"loop-exceeded: {L} ran {n} times > bound.max {mx} (on_exceed: {on_exceed})"
            (failed if on_exceed == "fail" else divergent).append(msg)
    for u in ids:
        for v in forward[u]:
            if u in first and v in first and (first[u] > first[v] or last[u] > last[v]):
                divergent.append(f"order: {v} precedes {u}, but the declared flow has {u} -> {v}")
    expected, todo = set(), ([ids[0]] if ids else [])
    while todo:
        u = todo.pop()
        if u in expected:
            continue
        expected.add(u)
        succ = forward[u]
        if kinds[u] == "choice":
            taken = [v for v in succ if v in first]
            succ = taken or succ
        todo.extend(succ)
    absent = [s for s in ids if s in expected and s not in first]
    reading = "failed-run" if failed else "divergent" if divergent else "absent" if absent else "convergent"
    return {"reading": reading, "realized": seq, "manifest": list(realized),
            "divergent": divergent, "absent": absent, "failed": failed}


def plan_reading(doc: Mapping[str, Any], realized: Sequence[tuple[str, str | None]]) -> dict:
    """agent-dec's reading when available (one implementation of B6 across
    the three repositories), the local rules otherwise."""
    try:
        from agent_dec import verify_dec as vd  # type: ignore
        return vd.conformance_reading(dict(doc), list(realized))
    except ImportError:
        return _reading(doc, realized)


# ----------------------------------------------------------------- evaluation
def evaluate(flow: Flow, runs: Mapping[str, Run], index: CertificateIndex | None = None) -> dict:
    declared = flow.step_ids
    observed = observed_steps(runs)
    absent = [s for s in declared if s not in observed]
    divergent = sorted(s for s in observed if s not in declared)
    window_reading = "divergent" if divergent else "absent" if absent else "convergent"
    if not runs:
        window_reading = "absent"
    per_run = []
    counts = {"convergent": 0, "absent": 0, "divergent": 0, "failed-run": 0}
    if index is not None:
        index.run_binding_notes.clear()
    off_plan: dict[str, int] = {}
    for trace_id in sorted(runs):
        run = runs[trace_id]
        cert = index.run_certificate_for(run) if index is not None else None
        if cert is not None:
            path, rc = cert
            realized = [(m["step_id"], m.get("flow_step")) for m in (rc.get("manifest") or {}).get("steps") or []]
            source = f"manifest:{path.name}"
        else:
            realized = [(sid, sid) for sid, _ in run.realized()]
            source = "spans"
        r = plan_reading(flow.doc, realized)
        counts[r["reading"]] = counts.get(r["reading"], 0) + 1
        for d in r["divergent"]:
            if d.startswith("off-plan: "):
                key = d.split(" ")[1]
                off_plan[key] = off_plan.get(key, 0) + 1
        per_run.append({"trace_id": trace_id, "source": source,
                        "realized": [fs if fs is not None else f"[{sid}]" for sid, fs in realized],
                        "reading": r["reading"], "divergent": r["divergent"], "absent": r["absent"], "failed": r["failed"]})
    return {
        "window": {"reading": window_reading, "declared": declared, "observed": sorted(observed),
                   "absent": absent, "divergent": divergent},
        "runs": per_run,
        "summary": {"runs": len(runs), "by_reading": counts, "off_plan_steps": dict(sorted(off_plan.items())),
                    # runs with a divergent (off-plan, order, repeat, soft loop bound) or failed (hard loop bound) reading
                    "non_convergent_runs": counts.get("divergent", 0) + counts.get("failed-run", 0),
                    "notes": list(index.run_binding_notes) if index is not None else []},
    }
