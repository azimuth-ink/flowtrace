"""FTC §4.4: placeholders, bindings, the shape check, unsupported dialects."""
import pytest

from conftest import QUERIES
from flowtrace.adapters.base import QueryResult, UnsupportedDialect
from flowtrace.answerability import (check_shape, evaluate, is_placeholder, load_query_bindings, resolve_query)


def test_placeholder_detection():
    assert is_placeholder("<query returning decisions grouped by reference-data version for flow.step=s4 over the window>")
    assert is_placeholder("  <x>\n")
    assert not is_placeholder("SELECT 1")
    assert not is_placeholder("")
    assert not is_placeholder(None)


def test_shape_check():
    r = QueryResult(("a", "b"), ((1, 2), (3, 4)))
    assert check_shape(r, {"min_rows": 1, "required_columns": ["a", "b"]}) == (True, None)
    assert check_shape(r, {"min_rows": 3})[0] is False
    ok, why = check_shape(r, {"required_columns": ["a", "c"]})
    assert not ok and "c" in why
    assert check_shape(QueryResult((), ()), {"min_rows": 0}) == (True, None)
    assert check_shape(QueryResult((), ()), {}) == (False, "0 row(s) returned, expected at least 1")


def test_resolve_query_precedence_and_defaults():
    bindings = load_query_bindings([QUERIES])
    sc = {"scenario": "Limit evaluated against stale reference data", "verification_query": "<placeholder>"}
    q = resolve_query("quote-issue", "s4", 0, sc, bindings, "otel-sql")
    assert q.source.startswith("binding:") and q.dialect == "otel-sql" and "GROUP BY" in q.text
    assert q.expected_shape == {"min_rows": 1, "required_columns": ["reference_data_version", "decision", "n"]}
    # unbound placeholder -> None
    assert resolve_query("quote-issue", "s4", 0, {"scenario": "other", "verification_query": "<p>"}, bindings, "otel-sql") is None
    # descriptor-carried query: dialect defaults to otel-sql, shape to min_rows 1
    q = resolve_query("f", "s", 0, {"verification_query": "SELECT 1"}, [], "otel-sql")
    assert q.source == "descriptor" and q.dialect == "otel-sql" and q.expected_shape == {"min_rows": 1}
    q = resolve_query("f", "s", 0, {"verification_query": "up", "dialect": "promql", "expected_shape": {"min_rows": 2}}, [], "otel-sql")
    assert q.dialect == "promql" and q.expected_shape == {"min_rows": 2}
    # binding by index
    q = resolve_query("f", "s", 3, {"verification_query": "<p>"}, [{"flow": "f", "step": "s", "index": 3, "dialect": "d", "text": "t", "_source": "binding:x"}], "otel-sql")
    assert q.text == "t"


def test_binding_file_validation(tmp_path):
    bad = tmp_path / "q.yaml"
    bad.write_text("apiVersion: flowtrace.queries/v0.9\nbindings: []\n")
    with pytest.raises(ValueError):
        load_query_bindings([bad])
    bad.write_text("apiVersion: flowtrace.queries/v0.1\nbindings:\n  - {flow: f, step: s, dialect: d, text: t}\n")
    with pytest.raises(ValueError, match="scenario"):
        load_query_bindings([bad])


class StubAdapter:
    name = "stub"
    dialects = frozenset({"otel-sql"})
    ingest_warnings: list = []

    def __init__(self, result=None, error=None):
        self.result, self.error = result, error

    def query(self, dialect, text, window):
        if dialect not in self.dialects:
            raise UnsupportedDialect(dialect)
        if self.error:
            raise self.error
        return self.result


def test_evaluate_over_windows(canon_flow, adapters):
    bindings = load_query_bindings([QUERIES])
    full = evaluate(canon_flow, adapters["full"], adapters["full"].extent(), bindings, "otel-sql", required=True)
    assert (full.score, full.declared, full.answerable, full.not_evaluated) == (1.0, 1, 1, 0)
    assert full.scenarios[0].columns == ["reference_data_version", "decision", "n"] and full.scenarios[0].rows >= 2
    missing = evaluate(canon_flow, adapters["s4-missing-attr"], adapters["s4-missing-attr"].extent(), bindings, "otel-sql", required=True)
    assert missing.score == 0.0 and missing.scenarios[0].status == "unanswerable" and "0 row(s)" in missing.scenarios[0].reason
    # without the binding the canonical placeholder is not evaluated — and contributes zero
    unbound = evaluate(canon_flow, adapters["full"], adapters["full"].extent(), [], "otel-sql", required=True)
    assert unbound.score == 0.0 and unbound.not_evaluated == 1 and unbound.scenarios[0].status == "not_evaluated"


def test_evaluate_edge_cases(canon_flow):
    from flowtrace.adapters.base import Window, QueryError
    from flowtrace.flows import Flow
    import copy
    # unsupported dialect -> not_evaluated
    b = [{"flow": "quote-issue", "step": "s4", "index": 0, "dialect": "traceql", "text": "{}", "_source": "binding:t"}]
    r = evaluate(canon_flow, StubAdapter(), Window(), b, "otel-sql", required=True)
    assert r.scenarios[0].status == "not_evaluated" and "traceql" in r.scenarios[0].reason
    # query error -> unanswerable
    b = [{"flow": "quote-issue", "step": "s4", "index": 0, "dialect": "otel-sql", "text": "x", "_source": "binding:t"}]
    r = evaluate(canon_flow, StubAdapter(error=QueryError("syntax")), Window(), b, "otel-sql", required=True)
    assert r.scenarios[0].status == "unanswerable" and "query error" in r.scenarios[0].reason
    # no scenarios: required -> 0 applicable; not required -> not applicable
    doc = copy.deepcopy(canon_flow.doc)
    for s in doc["spec"]["steps"]:
        s.pop("debug_scenarios", None)
    bare = Flow(canon_flow.path, doc, canon_flow.sha256)
    assert evaluate(bare, StubAdapter(), Window(), [], "otel-sql", required=True).score == 0.0
    na = evaluate(bare, StubAdapter(), Window(), [], "otel-sql", required=False)
    assert na.applicable is False and na.score == 1.0
