"""FTC §4.8 / PD §5 — conformance: convergent, absent, divergent; the authorized plan.

Two readings:

  window (topology)  the declared step set vs the set of steps observed in the
                     window (spans grouped by flow.id / flow.step): absent =
                     declared, unobserved; divergent = observed, undeclared
                     (off-plan). Continuous, per window.
  run (plan)         per run, the realized step DAG against the declared graph
                     (`next`, bounds, and — revision 2026-10-11 — the declared
                     degradation edges). Input per binding B6: the run
                     certificate's manifest.steps[] when the run carries one
                     (found through dec.run_cert_digest on the trigger span or
                     subject.run_id == trace id); the run's boundary spans in
                     start order otherwise. Off-plan steps, order violations,
                     repeats without a loop step, loop-bound exceedance per
                     on_exceed (fail -> failed-run; flag -> divergent) and
                     absent declared steps are reported per run.

Revision 2026-10-11 (spec §7.4, binding B9 as read here): a declared `on_fail`
edge is part of the plan. From a manifest, an entry with `via: on_fail` is
convergent iff the preceding entry's step declares that edge; `outcome` must
be a declared outcome (or one of the default five); a later entry off every
path from a `latch: true` target is a latched re-entry (divergent); a
recorded `termination` of cancelled | expired leaves the unrun steps not
absent. From spans alone the engine records `via: on_fail` itself for a
transition that is a declared `to` edge and not a `next` edge, cannot tell
the two apart where they share a target (the canon's s5 -> s6; note
`shared-target`), and reads a run that ends at a step with an `on_fail
{outcome}` edge as having taken it with `outcome: unknown`. The two-sided
indicators of spec §6.7 (degradation rate, veto rate) are computed from the
same per-run readings.

The per-run rules are agent-dec's `conformance_reading` (spec/01, the
reference reading of a manifest) when agent-dec is installed; the local
`_reading` below implements the same rules so the gate runs without it, and
tests/test_conformance.py asserts the two agree.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .config import REPLAYABLE_ND_CLASSES
from .coverage import CertificateIndex, Run, observed_steps
from .flows import DEFAULT_OUTCOMES, Flow, degradation_edges, degradation_target

SLI_NAMES = ("degradation_rate", "veto_rate")


# ----------------------------------------------------------------- local rules
def _flow_steps(doc: Mapping[str, Any]) -> list[dict]:
    return [s for s in (doc.get("spec") or {}).get("steps") or [] if isinstance(s, dict)]


def _declared_outcomes(doc: Mapping[str, Any]) -> list[str]:
    v = (doc.get("spec") or {}).get("outcomes")
    return list(v) if isinstance(v, list) and v else list(DEFAULT_OUTCOMES)


def _dag(doc: Mapping[str, Any]):
    """Declared step graph: ids in document order, adjacency with the linear
    default (the companion validator's R6) plus resolvable `on_fail.to` edges
    (the validator reads them as step-graph edges too), the forward DAG, the
    back-edges and transitive reachability. `primary` holds the `next` edges
    alone: the path a run takes when nothing degrades."""
    steps = _flow_steps(doc)
    ids = [s.get("id") for s in steps]
    kinds = {s.get("id"): s.get("kind", "sync") for s in steps}
    adj, primary = {}, {}
    for i, s in enumerate(steps):
        nxt = [n for n in (s.get("next") or ([ids[i + 1]] if i + 1 < len(ids) else [])) if n in kinds]
        primary[s.get("id")] = list(nxt)
        on_fail = s.get("on_fail") if isinstance(s.get("on_fail"), dict) else {}
        to = on_fail.get("to")
        if to in kinds and to != s.get("id") and to not in nxt:
            nxt = nxt + [to]
        adj[s.get("id")] = nxt
    forward = {u: [] for u in ids}
    back = set()
    color: dict[str, int] = {}
    if ids:
        root = ids[0]
        color[root] = 1
        stack = [(root, iter(adj[root]))]
        while stack:
            u, it = stack[-1]
            for v in it:
                if color.get(v) == 1:
                    back.add((u, v))                 # back-edge
                    continue
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
    return ids, kinds, adj, forward, back, reach, primary, {s.get("id"): s for s in steps}


def _entries(realized: Sequence) -> list[dict]:
    """Normalize the manifest input: each entry is (step_id, flow_step|None)
    or {step_id, flow_step?, via?, key?, attempt?}; `via` defaults to
    primary (absent means primary)."""
    out = []
    for e in realized:
        if isinstance(e, dict):
            d = {"step_id": e.get("step_id"), "flow_step": e.get("flow_step"),
                 "via": e.get("via") or "primary", "key": e.get("key"), "attempt": e.get("attempt")}
        else:
            sid, fs = e
            d = {"step_id": sid, "flow_step": fs, "via": "primary", "key": None, "attempt": None}
        out.append(d)
    return out


def _collapse_attempts(entries: list[dict]) -> list[dict]:
    """Consecutive entries with the same flow_step whose certificates share
    an idempotency key commitment and carry increasing attempt_id are one
    declared step for the reading; `attempts` counts them (spec §7.5)."""
    out: list[dict] = []
    for e in entries:
        last = out[-1] if out else None
        if (last is not None and e["flow_step"] is not None and e["flow_step"] == last["flow_step"]
                and e["key"] and e["key"] == last["key"] and e["attempt"] and last["last_attempt"]
                and e["attempt"] > last["last_attempt"]):
            last["attempts"] += 1
            last["last_attempt"] = e["attempt"]
            continue
        d = dict(e)
        d["attempts"], d["last_attempt"] = 1, e["attempt"]
        out.append(d)
    return out


def _reading(doc: Mapping[str, Any], realized: Sequence, *, outcome: str | None = None,
             termination: str | None = None, children_ok: bool | None = None) -> dict:
    """The local reading; same rules and same result shape as agent-dec's
    `conformance_reading` (asserted by the test suite)."""
    ids, kinds, adj, forward, back, reach, primary, by_id = _dag(doc)
    entries = _collapse_attempts(_entries(realized))
    divergent, absent, failed, degraded, notes = [], [], [], [], []
    seq = []
    for pos, e in enumerate(entries, 1):
        sid, fs = e["step_id"], e["flow_step"]
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
    exits = []          # (step, edge field) for declared edges to an outcome the run ended in
    for L in loop_steps:
        bound = by_id[L].get("bound") or {}
        mx, on_exceed = bound.get("max"), bound.get("on_exceed", "flag")
        n = count.get(L, 0)
        if isinstance(mx, int) and n > mx:
            kind, value = degradation_target(on_exceed)
            if on_exceed == "fail":
                failed.append(f"loop-exceeded: {L} ran {n} times > bound.max {mx} (on_exceed: fail)")
            elif kind == "outcome":
                if outcome == value:
                    degraded.append(f"{L} -> outcome {value} (bound.on_exceed after {n} iterations)")
                    exits.append((L, "bound.on_exceed"))
                else:
                    divergent.append(f"loop-exceeded: {L} ran {n} times > bound.max {mx} and the run did not end in "
                                     f"the declared on_exceed outcome {value} (outcome: {outcome})")
            elif kind == "to":
                divergent.append(f"loop-exceeded: {L} ran {n} times > bound.max {mx} (on_exceed: to {value})")
            else:
                divergent.append(f"loop-exceeded: {L} ran {n} times > bound.max {mx} (on_exceed: flag)")
    for u in ids:
        for v in forward[u]:
            if u in first and v in first and (first[u] > first[v] or last[u] > last[v]):
                divergent.append(f"order: {v} precedes {u}, but the declared flow has {u} -> {v}")

    # --- declared degradation (B9): via: on_fail entries, latches, outcome ---
    taken = {}          # step -> target it degraded to by a taken `to` edge
    latched = []        # (index of the on_fail entry, source step, target step)
    for i, e in enumerate(entries):
        if e["via"] != "on_fail":
            continue
        fs = e["flow_step"]
        if fs not in kinds:
            continue                                   # already divergent (off-plan)
        prev_entries = [p for p in entries[:i] if p["flow_step"] in kinds]
        if not prev_entries:
            divergent.append(f"degradation: {fs} at position {i + 1} is reached via on_fail with no preceding step")
            continue
        src = prev_entries[-1]["flow_step"]
        edges = [(f, k, v, l) for f, k, v, l in degradation_edges(by_id[src]) if k == "to" and v == fs]
        if not edges:
            divergent.append(f"degradation: {fs} at position {i + 1} is reached via on_fail, but the declared flow has no "
                             f"on_fail or on_exceed edge {src} -> {fs}")
            continue
        field_name, _, _, latch = edges[0]
        taken[src] = fs
        degraded.append(f"{src} -> {fs} ({field_name}{', latched' if latch else ''})")
        if latch:
            latched.append((i, src, fs))
    for i, src, tgt in latched:
        for j, e in enumerate(entries[i + 1:], i + 1):
            fs = e["flow_step"]
            if fs in kinds and fs not in reach.get(tgt, set()):     # off every declared path from the target
                divergent.append(f"latched re-entry: {fs} ran at position {j + 1} after the latched on_fail edge "
                                 f"{src} -> {tgt} was taken")
    if outcome is not None:
        allowed = _declared_outcomes(doc)
        if outcome not in allowed:
            divergent.append(f"outcome: {outcome} is not among the declared outcomes ({', '.join(allowed)})")
        elif ran:
            L = ran[-1]
            for field_name, kind, value, _ in degradation_edges(by_id[L]):
                if field_name == "on_fail" and kind == "outcome" and value == outcome and (L, field_name) not in exits:
                    exits.append((L, field_name))
                    degraded.append(f"{L} -> outcome {value} ({field_name})")
                    reason = _gate_authority_reason(by_id[L], value)
                    if reason:
                        divergent.append(reason)
                    break
    _attempt_rules(entries, kinds, by_id, outcome, degraded, divergent, exits)
    if children_ok is False:
        divergent.append("cancellation-not-propagated: a child run of this cancelled parent was not cancelled or "
                         "completed within cancel_propagation_s (step 1d(c))")

    # --- absent: the primary path, re-routed by the degradation edges the run took ---
    expected, todo = set(), ([ids[0]] if ids else [])
    exited = {s for s, _ in exits}
    while todo:
        u = todo.pop()
        if u in expected:
            continue
        expected.add(u)
        if u in taken:
            succ = [taken[u]]
        elif u in exited and u == (ran[-1] if ran else None):
            succ = []
        else:
            succ = [v for v in forward[u] if v in primary.get(u, [])]
            if kinds[u] == "choice":
                picked = [v for v in succ if v in first]
                succ = picked or succ
        todo.extend(succ)
    if termination in ("cancelled", "expired"):
        absent = []
        notes.append(f"termination {termination} recorded: steps not run are not absent")
    else:
        absent = [s for s in ids if s in expected and s not in first]
    reading = "failed-run" if failed else "divergent" if divergent else "absent" if absent else "convergent"
    return {"reading": reading, "realized": seq, "manifest": realized, "entries": entries,
            "divergent": divergent, "absent": absent, "failed": failed, "degraded": degraded,
            "notes": notes, "outcome": outcome, "termination": termination}


def _gate_authority_reason(step: Mapping[str, Any], outcome: str) -> str | None:
    """Gate authority (D14; binding B12): the rule itself is the companion
    validator's R14 on declarations, which this engine relies on and does not
    enforce (spec §6.7). The reading only carries, as a divergence reason, that
    a `block` outcome was reached by an edge from a step whose declared class
    is not ND0/ND1 — agent-dec's verifier's note, so the conformance view
    says what the certificate layer recorded. Never on the 2.1.0 example,
    whose one block-gate (s4) is ND0."""
    if outcome != "block":
        return None
    dclass = step.get("nd_class")
    if dclass in REPLAYABLE_ND_CLASSES:
        return None
    return (f"gate-authority: block reached from {step.get('id')}, whose declared class is "
            f"{dclass or 'undeclared'} (binding B12: only an ND0/ND1 step may be the source of an edge "
            f"whose target is block)")


def _attempt_rules(entries, kinds, by_id, outcome, degraded, divergent, exits) -> None:
    """Attempts of an effect step against `attempts.max` (spec §7.5): more
    attempts than the bound is the step's `on_exceed` taken (convergent when
    the run ended in the declared outcome, or continued at the declared step
    via on_fail), else divergent (`attempts-exceeded`). Bindings B10/B17 are
    the verifier's step 1d; here only the count is read."""
    for i, e in enumerate(entries):
        fs = e["flow_step"]
        if fs not in kinds or e["attempts"] < 1:
            continue
        attempts = by_id[fs].get("attempts") if isinstance(by_id[fs].get("attempts"), dict) else None
        mx = attempts.get("max") if attempts else None
        if isinstance(mx, int) and e["attempts"] > mx:
            kind, value = degradation_target(attempts.get("on_exceed"))
            if kind == "outcome":
                if outcome == value and (i == len(entries) - 1 or all(x["flow_step"] not in kinds for x in entries[i + 1:])):
                    degraded.append(f"{fs} -> outcome {value} (attempts.on_exceed after {e['attempts']} attempts)")
                    exits.append((fs, "attempts.on_exceed"))
                else:
                    divergent.append(f"attempts-exceeded: {fs} ran {e['attempts']} attempts > attempts.max {mx} and the run "
                                     f"did not end in the declared on_exceed outcome {value} (outcome: {outcome})")
            elif kind == "to":
                nxt = entries[i + 1] if i + 1 < len(entries) else None
                if not (nxt and nxt["flow_step"] == value and nxt["via"] == "on_fail"):
                    divergent.append(f"attempts-exceeded: {fs} ran {e['attempts']} attempts > attempts.max {mx} and the run "
                                     f"did not continue at the declared on_exceed step {value} via on_fail")
            else:
                divergent.append(f"attempts-exceeded: {fs} ran {e['attempts']} attempts > attempts.max {mx} (no on_exceed declared)")


def plan_reading(doc: Mapping[str, Any], realized: Sequence, **kw) -> dict:
    """agent-dec's reading when available (one implementation of B6/B9 across
    the three repositories), the local rules otherwise."""
    try:
        from agent_dec import verify_dec as vd  # type: ignore
        return vd.conformance_reading(dict(doc), list(realized), **kw)
    except ImportError:
        return _reading(doc, realized, **kw)


# ----------------------------------------------------------------- span reading
def _realized_from_spans(flow: Flow, run: Run) -> tuple[list[dict], str | None, list[str]]:
    """The boundary spans in start order as reading entries, with `via`
    recorded by the engine (spec §7.4): a transition X -> Y is `on_fail` iff
    Y is a declared `to` target of X and not in X's `next`; where the target
    is shared with `next` the engine cannot tell and notes it. Returns
    (entries, outcome the run is read as ending in | None, notes)."""
    entries, notes = [], []
    prev = None
    effect = set(flow.effect_steps)
    for sid, _ in run.realized():
        if sid in effect and prev == sid:
            # repeated boundary spans of an effect step are its attempts (spec §7.5): collapsed by the reading
            attempt = (entries[-1]["attempt"] or 1) + 1
            entries.append({"step_id": sid, "flow_step": sid, "via": "primary", "key": f"spans:{sid}", "attempt": attempt})
            continue
        via = "primary"
        if prev is not None:
            step = flow.step(prev)
            to_targets = [v for _, k, v, _ in degradation_edges(step or {}) if k == "to"]
            if sid in to_targets:
                if sid in flow.next_of(prev):
                    notes.append(f"shared-target: {prev} -> {sid} is both a next edge and a declared on_fail/on_exceed "
                                 f"target; spans cannot tell the paths apart, read as primary (the manifest is the exact source)")
                else:
                    via = "on_fail"
        entries.append({"step_id": sid, "flow_step": sid, "via": via,
                        "key": f"spans:{sid}" if sid in effect else None, "attempt": 1 if sid in effect else None})
        prev = sid
    ending_outcome = None
    if entries:
        last_id = entries[-1]["flow_step"]
        last_step = flow.step(last_id) or {}
        trailing = 0
        for e in reversed(entries):
            if e["flow_step"] != last_id:
                break
            trailing += 1
        attempts = last_step.get("attempts") if isinstance(last_step.get("attempts"), dict) else {}
        over_bound = last_id in effect and isinstance(attempts.get("max"), int) and trailing > attempts["max"]
        for field_name, kind, value, _ in degradation_edges(last_step):
            if kind != "outcome":
                continue
            if field_name == "on_fail" or (field_name == "attempts.on_exceed" and over_bound):
                ending_outcome = value          # the run ends at the source step; its successors are not absent
                break
    return entries, ending_outcome, notes


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
    degraded_runs = vetoed_runs = 0
    effect_steps = flow.effect_steps
    attempts_by_step = {sid: {"runs_with_retries": 0, "max_attempts_seen": 0, "over_bound": 0, "unreconciled": 0} for sid in effect_steps}
    unchecked: dict[str, int] = {}          # rule -> span-sourced runs it could not be checked for
    verifier_unchecked: set[str] = set()
    for trace_id in sorted(runs):
        run = runs[trace_id]
        cert = index.run_certificate_for(run) if index is not None else None
        notes: list[str] = []
        approximate = False
        findings: list[dict] = []
        if cert is not None:
            path, rc = cert
            man = rc.get("manifest") or {}
            realized = [_manifest_entry(m, index) for m in man.get("steps") or []]
            source = f"manifest:{path.name}"
            outcome, termination = man.get("outcome"), man.get("termination")
            r = plan_reading(flow.doc, realized, outcome=outcome, termination=termination)
            if effect_steps:
                findings, vu, _ = _verifier_findings(index, index.run_directory(path), READ_FINDINGS)
                verifier_unchecked.update(vu)
                for f in findings:
                    if f["code"] in DIVERGENT_FINDINGS:
                        r["divergent"].append(f"{f['code']}: {f['reason']}")
                if r["divergent"] and r["reading"] != "failed-run":
                    r["reading"] = "divergent"
        else:
            realized, ending, notes = _realized_from_spans(flow, run)
            source = "spans"
            approximate = True
            outcome, termination = None, None
            r = plan_reading(flow.doc, realized, outcome=ending)
            if ending is not None:
                # the engine cannot see the outcome; the run is read as ending at the source step (spec §7.4)
                outcome = "unknown"
                r["degraded"] = [d + " [spans]" for d in r["degraded"]]
        entries = r.get("entries") or _collapse_attempts(_entries(realized))
        if cert is None and any(e["flow_step"] in attempts_by_step for e in entries):
            # [H1] from spans alone B10 cannot be read: the effect step's span is a §6.6 status, the rule is unchecked
            unchecked["effect-without-authorization (B10)"] = unchecked.get("effect-without-authorization (B10)", 0) + 1
        for e in entries:
            sid = e["flow_step"]
            if sid in attempts_by_step:
                st = attempts_by_step[sid]
                st["max_attempts_seen"] = max(st["max_attempts_seen"], e["attempts"])
                if e["attempts"] > 1:
                    st["runs_with_retries"] += 1
                    if cert is None:
                        unchecked["retry-without-reconciliation (B17)"] = unchecked.get("retry-without-reconciliation (B17)", 0) + 1
                if any(d.startswith(f"attempts-exceeded: {sid} ") for d in r["divergent"]):
                    st["over_bound"] += 1
        for f in findings:
            if f["code"] == "retry-without-reconciliation" and f["step"] in attempts_by_step:
                attempts_by_step[f["step"]]["unreconciled"] += 1
        counts[r["reading"]] = counts.get(r["reading"], 0) + 1
        for d in r["divergent"]:
            if d.startswith("off-plan: "):
                key = d.split(" ")[1]
                off_plan[key] = off_plan.get(key, 0) + 1
        degraded = list(r.get("degraded") or [])
        vetoed = (outcome == "block") if cert is not None else (ending == "block" if approximate else False)
        degraded_runs += bool(degraded)
        vetoed_runs += bool(vetoed)
        per_run.append({"trace_id": trace_id, "source": source,
                        "realized": [_entry_text(e) for e in entries],
                        "via": [e["via"] for e in entries],
                        "outcome": outcome, "termination": termination,
                        "reading": r["reading"], "divergent": r["divergent"], "absent": r["absent"], "failed": r["failed"],
                        "degraded": degraded, "vetoed": bool(vetoed), "approximate": approximate,
                        "findings": findings,
                        "notes": notes + list(r.get("notes") or [])})
    unchecked_lines = [f"{rule}: unchecked for {n} span-sourced run(s) (no certificates to read it from)" for rule, n in sorted(unchecked.items())]
    unchecked_lines += sorted(verifier_unchecked)
    return {
        "window": {"reading": window_reading, "declared": declared, "observed": sorted(observed),
                   "absent": absent, "divergent": divergent},
        "runs": per_run,
        "attempts": attempts_by_step,
        "summary": {"runs": len(runs), "by_reading": counts, "off_plan_steps": dict(sorted(off_plan.items())),
                    # runs with a divergent (off-plan, order, repeat, soft loop bound, latched re-entry, undeclared
                    # outcome or edge, or a step-1d finding) or failed (hard loop bound) reading
                    "non_convergent_runs": counts.get("divergent", 0) + counts.get("failed-run", 0),
                    "degraded_runs": degraded_runs, "vetoed_runs": vetoed_runs,
                    "manifest_runs": sum(1 for r in per_run if r["source"] != "spans"),
                    "unchecked": unchecked_lines,
                    "notes": list(index.run_binding_notes) if index is not None else []},
    }


# The step-1d findings this engine reads from agent-dec's verifier: [H4]
# binding B17 (spec §7.5); [H1] binding B10 and the authorization window /
# freshness findings (spec §7.6; the latter two are §6.6 statuses passed
# through, never re-derived). Later units extend the tuples.
READ_FINDINGS = ("retry-without-reconciliation", "effect-without-authorization", "authorization-expired", "authorization-stale",
                 "sod-violation", "approval-payload-mismatch")                       # [H2] bindings B11, B15 (the approval's checks)
DIVERGENT_FINDINGS = ("retry-without-reconciliation", "effect-without-authorization")
UNCHECKED_FROM_SPANS = (("retry-without-reconciliation (B17)", "retries"), ("effect-without-authorization (B10)", "effect"))


def _manifest_entry(m: Mapping[str, Any], index: CertificateIndex | None) -> dict:
    """A manifest entry as a reading entry; the idempotency key commitment and
    attempt id come from the step certificate the entry's cert_digest names
    (attempts collapse on them, spec §7.5)."""
    key = attempt = None
    hit = index.steps.get(m.get("cert_digest")) if index is not None else None
    if hit is not None:
        subj = hit[1].get("subject") or {}
        key, attempt = subj.get("idempotency_key_commitment"), subj.get("attempt_id")
    return {"step_id": m.get("step_id"), "flow_step": m.get("flow_step"), "via": m.get("via"), "key": key, "attempt": attempt}


def _verifier_findings(index: CertificateIndex, run_dir, codes: Sequence[str]) -> tuple[list[dict], list[str], object]:
    """The step-1d findings of a run directory, taken from agent-dec's
    verifier, restricted to `codes`: [{code, step, attempt_id, file, reason}],
    the parts it reported UNCHECKED, and the verifier result itself."""
    vr = index.verifier_result(run_dir)
    out = []
    for name, file_name, reason in vr.findings:
        if name not in codes:
            continue
        doc = index.member(run_dir / file_name) or {}
        subj = doc.get("subject") or {}
        f = {"code": name, "step": subj.get("step_id"), "attempt_id": subj.get("attempt_id"), "file": file_name, "reason": reason}
        if name == "effect-without-authorization":
            # spec §7.6: reason missing | denied — a deny record followed by the certificate, or no accepted allow
            f["reason_class"] = "denied" if " is deny" in reason else "missing"
        out.append(f)
    return out, list(vr.unchecked), vr


def _entry_text(e: Mapping[str, Any]) -> str:
    """The paper's notation: `[sid]` for an unbound entry, `->sid` for an
    entry reached via a declared on_fail edge, `sid×n` for n attempts."""
    txt = e["flow_step"] if e["flow_step"] is not None else f"[{e['step_id']}]"
    if e.get("via") == "on_fail":
        txt = "->" + txt
    if (e.get("attempts") or 1) > 1:
        txt += f"×{e['attempts']}"
    return txt


# ----------------------------------------------------------------- the two SLIs (spec §6.7)
def sli_band(cfg: Mapping[str, Any], flow_id: str, indicator: str) -> dict:
    """{min, max, gate} for an indicator: `slis.<indicator>.flows.<flow>.band`
    over `slis.<indicator>.band` over the whole range."""
    block = ((cfg.get("slis") or {}).get(indicator) or {})
    band = dict(block.get("band") or {})
    band.update((block.get("flows") or {}).get(flow_id, {}).get("band") or {})
    return {"min": float(band.get("min", 0.0)), "max": float(band.get("max", 1.0)), "gate": bool(band.get("gate", False))}


def evaluate_slis(flow: Flow, conformance: Mapping[str, Any], cfg: Mapping[str, Any]) -> dict | None:
    """Degradation rate (runs that took any declared degradation path) and
    veto rate (runs whose outcome is block) over the window's runs, each
    with its band and source. None when the flow declares neither
    `outcomes` nor any `on_fail`."""
    if not flow.declares_degradation:
        return None
    runs = conformance["runs"]
    n = len(runs)
    approximate = any(r["approximate"] for r in runs)
    source = "manifest" if runs and not approximate else "spans" if runs and all(r["approximate"] for r in runs) else "mixed"
    notes = sorted({nt for r in runs for nt in r["notes"] if nt.startswith("shared-target")})
    out = {}
    for name, key in (("degradation_rate", "degraded_runs"), ("veto_rate", "vetoed_runs")):
        count = conformance["summary"][key]
        rate = round(count / n, 6) if n else 0.0
        band = sli_band(cfg, flow.id, name)
        direction = "above" if rate > band["max"] + 1e-9 else "below" if rate < band["min"] - 1e-9 else None
        out[name] = {"rate": rate, "band": band, "source": source if n else "none", "approximate": approximate,
                     "runs": n, key: count, "out_of_band": direction, "notes": notes if name == "degradation_rate" else []}
    return out
