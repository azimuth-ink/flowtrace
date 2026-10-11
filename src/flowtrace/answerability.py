"""FTC §4.4 — answerability by verification-query contract.

A debug scenario is answerable iff its verification query, executed in a
dialect the adapter supports, returns a result that satisfies the declared
expected shape `{min_rows, required_columns[]}`. The engine never interprets
query text; it executes it through the adapter and checks the shape.

Where the query comes from (in precedence order):

  1. a query binding (`--queries FILE`, apiVersion flowtrace.queries/v0.1)
     matching (flow, step, scenario) — the way to run a descriptor whose
     `verification_query` is a natural-language placeholder (the canonical
     quote-issue descriptor carries `"<query returning ...>"`) or carries a
     dialect this adapter does not speak, without editing the descriptor;
  2. the descriptor's own `verification_query` with its `dialect` and
     `expected_shape` (flow.spec/v0.2 fields); a query with no `dialect` is
     `otel-sql` (prompt C3); a query with no `expected_shape` expects
     `{min_rows: 1}`.

A placeholder (`<...>`) that no binding resolves, or a dialect the adapter
does not execute, is reported `not_evaluated` — never answerable (FTC §4.4:
"an evaluator that cannot execute any of a scenario's dialects reports the
scenario as not evaluated rather than as answerable"). For the score a
not-evaluated scenario contributes zero, like an unanswerable one, so that a
P0 flow with unevaluable scenarios cannot pass.
"""
from __future__ import annotations

import pathlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

import yaml

from . import QUERIES_API_VERSION
from .adapters.base import Adapter, QueryError, QueryResult, UnsupportedDialect, Window
from .flows import Flow

PLACEHOLDER_RE = re.compile(r"^\s*<.*>\s*$", re.S)


@dataclass(frozen=True)
class ResolvedQuery:
    dialect: str
    text: str
    expected_shape: dict
    source: str                      # descriptor | binding:<path>


@dataclass
class ScenarioResult:
    step: str
    index: int
    scenario: str
    status: str                      # answerable | unanswerable | not_evaluated
    dialect: str | None = None
    source: str | None = None
    rows: int | None = None
    columns: list[str] = field(default_factory=list)
    reason: str | None = None

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class AnswerabilityResult:
    score: float
    applicable: bool
    scenarios: list[ScenarioResult]
    declared: int
    answerable: int
    not_evaluated: int
    reason: str | None = None

    def as_dict(self) -> dict:
        return {"score": self.score, "applicable": self.applicable, "declared": self.declared,
                "answerable": self.answerable, "not_evaluated": self.not_evaluated, "reason": self.reason,
                "scenarios": [s.as_dict() for s in self.scenarios]}


def is_placeholder(text: str | None) -> bool:
    return bool(text) and bool(PLACEHOLDER_RE.match(text))


# ---------------------------------------------------------------- bindings
def load_query_bindings(paths: Sequence[str | pathlib.Path]) -> list[dict]:
    out = []
    for p in paths:
        p = pathlib.Path(p)
        doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if doc.get("apiVersion") != QUERIES_API_VERSION:
            raise ValueError(f"{p}: apiVersion {doc.get('apiVersion')!r} is not {QUERIES_API_VERSION}")
        for i, b in enumerate(doc.get("bindings") or []):
            for key in ("flow", "step", "dialect", "text"):
                if key not in b:
                    raise ValueError(f"{p}: bindings[{i}] lacks {key}")
            if "scenario" not in b and "index" not in b:
                raise ValueError(f"{p}: bindings[{i}] needs scenario (name) or index")
            out.append(dict(b, _source=f"binding:{p.name}"))
    return out


def resolve_query(flow_id: str, step_id: str, index: int, scenario: Mapping[str, Any],
                  bindings: Sequence[Mapping[str, Any]], default_dialect: str) -> ResolvedQuery | None:
    for b in bindings:
        if b["flow"] != flow_id or b["step"] != step_id:
            continue
        if ("index" in b and int(b["index"]) == index) or ("scenario" in b and b["scenario"] == scenario.get("scenario")):
            return ResolvedQuery(dialect=str(b["dialect"]), text=str(b["text"]),
                                 expected_shape=dict(b.get("expected_shape") or {"min_rows": 1}), source=b["_source"])
    text = scenario.get("verification_query")
    if not isinstance(text, str) or is_placeholder(text):
        return None
    return ResolvedQuery(dialect=str(scenario.get("dialect") or default_dialect), text=text,
                         expected_shape=dict(scenario.get("expected_shape") or {"min_rows": 1}), source="descriptor")


# ---------------------------------------------------------------- the shape check
def check_shape(result: QueryResult, expected: Mapping[str, Any]) -> tuple[bool, str | None]:
    """{min_rows: int >= 0, required_columns: [names]} against a result."""
    min_rows = int(expected.get("min_rows", 1))
    if result.row_count < min_rows:
        return False, f"{result.row_count} row(s) returned, expected at least {min_rows}"
    missing = [c for c in (expected.get("required_columns") or []) if c not in result.columns]
    if missing:
        return False, f"result lacks required column(s) {missing}; has {list(result.columns)}"
    return True, None


# ---------------------------------------------------------------- evaluation
def evaluate(flow: Flow, adapter: Adapter, window: Window, bindings: Sequence[Mapping[str, Any]],
             default_dialect: str, required: bool) -> AnswerabilityResult:
    results: list[ScenarioResult] = []
    for step in flow.steps:
        for i, sc in enumerate(step.get("debug_scenarios") or []):
            name = str(sc.get("scenario", f"scenario[{i}]"))
            q = resolve_query(flow.id, step["id"], i, sc, bindings, default_dialect)
            if q is None:
                results.append(ScenarioResult(step["id"], i, name, "not_evaluated",
                                              reason="verification_query is a placeholder and no query binding resolves it"))
                continue
            if q.dialect not in adapter.dialects:
                results.append(ScenarioResult(step["id"], i, name, "not_evaluated", dialect=q.dialect, source=q.source,
                                              reason=f"adapter {adapter.name} does not execute dialect {q.dialect!r} "
                                                     f"(supports {sorted(adapter.dialects)})"))
                continue
            try:
                res = adapter.query(q.dialect, q.text, window)
            except UnsupportedDialect:
                results.append(ScenarioResult(step["id"], i, name, "not_evaluated", dialect=q.dialect, source=q.source,
                                              reason=f"adapter refused dialect {q.dialect!r}"))
                continue
            except QueryError as e:
                results.append(ScenarioResult(step["id"], i, name, "unanswerable", dialect=q.dialect, source=q.source,
                                              reason=f"query error: {e}"))
                continue
            ok, why = check_shape(res, q.expected_shape)
            results.append(ScenarioResult(step["id"], i, name, "answerable" if ok else "unanswerable",
                                          dialect=q.dialect, source=q.source, rows=res.row_count,
                                          columns=list(res.columns), reason=why))
    declared = len(results)
    answerable = sum(1 for r in results if r.status == "answerable")
    not_eval = sum(1 for r in results if r.status == "not_evaluated")
    if declared == 0:
        if required:
            return AnswerabilityResult(0.0, True, results, 0, 0, 0,
                                       reason="no debug_scenarios declared; the tier requires the answerability block")
        return AnswerabilityResult(1.0, False, results, 0, 0, 0, reason="no debug_scenarios declared; component not applicable")
    return AnswerabilityResult(answerable / declared, True, results, declared, answerable, not_eval)
