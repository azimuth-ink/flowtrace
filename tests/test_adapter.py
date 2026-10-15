"""The reference adapter: OTLP/JSON ingest, the otel-sql relational contract,
deprecated-alias mapping, enum/timestamp forms, and the protocol."""
import json

import pytest

from flowtrace.adapters import Adapter, load_adapter
from flowtrace.adapters.base import QueryError, UnsupportedDialect, Window
from flowtrace.adapters.otlp_duckdb import OtlpDuckDBAdapter


def _req(spans, resource=None):
    return {"resourceSpans": [{"resource": {"attributes": resource or [{"key": "service.name", "value": {"stringValue": "svc"}}]},
                               "scopeSpans": [{"scope": {"name": "t"}, "spans": spans}]}]}


def _span(trace, span, name, attrs, parent=None, kind=2, start=1_000, end=2_000, status=1):
    s = {"traceId": trace, "spanId": span, "name": name, "kind": kind, "startTimeUnixNano": start, "endTimeUnixNano": end,
         "attributes": [{"key": k, "value": v} for k, v in attrs.items()], "status": {"code": status}}
    if parent:
        s["parentSpanId"] = parent
    return s


def write(tmp_path, *reqs):
    p = tmp_path / "t.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in reqs) + "\n")
    return p


def test_full_window_loads_with_the_expected_counts(adapters):
    a = adapters["full"]
    c = a.counts()
    assert c["traces"] == 32 and c["spans"] == 32 * 7 and c["metrics"] == 32 * 6 and c["logs"] == 0
    assert a.ingest_warnings == []
    assert isinstance(a, Adapter) and a.dialects == frozenset({"otel-sql"})
    w = a.extent()
    assert w.start_ns == 1791684000000000000 and w.end_ns > w.start_ns
    spans = a.list_spans("quote-issue", w, "2.1.0")
    assert len(spans) == 32 * 7 and all(s.attributes["flow.id"] == "quote-issue" for s in spans)
    assert len(a.list_spans("other", w)) == 0
    assert len(a.list_metrics("quote-issue", w)) == 192


def test_otel_sql_contract(adapters):
    a = adapters["full"]
    r = a.query("otel-sql", "SELECT attributes['flow.step'] AS step, count(*) AS n FROM spans "
                           "WHERE attributes['flow.id'] = 'quote-issue' GROUP BY 1 ORDER BY 1", a.extent())
    assert r.columns == ("step", "n")
    assert dict(r.rows) == {"s1": 32, "s2": 32, "s3": 64, "s4": 32, "s5": 32, "s6": 32}
    r = a.query("otel-sql", "SELECT round(sum(attributes['cost.usd']::DOUBLE), 4) FROM spans WHERE attributes['flow.step'] = 's5'", a.extent())
    assert r.rows[0][0] > 0
    r = a.query("otel-sql", "SELECT name, type, count, sum FROM metrics WHERE attributes['flow.step'] = 's4' LIMIT 1", a.extent())
    assert r.rows[0][:3] == ("step_duration_seconds", "histogram", 1)
    r = a.query("otel-sql", "SELECT service_name, kind, status, duration_ms FROM spans WHERE attributes['flow.step']='s5' LIMIT 1", a.extent())
    assert r.rows[0][:3] == ("docs.render", "CONSUMER", "OK") and r.rows[0][3] > 18000
    r = a.query("otel-sql", "SELECT start_ns, end_ns FROM eval_window", Window(5, 9))
    assert r.rows == ((5, 9),)
    with pytest.raises(UnsupportedDialect):
        a.query("promql", "up", a.extent())
    with pytest.raises(QueryError):
        a.query("otel-sql", "SELECT nope FROM nowhere", a.extent())


def test_deprecated_aliases_are_mapped_with_a_warning(tmp_path):
    p = write(tmp_path, _req([_span("a" * 32, "b" * 16, "x", {
        "flow.id": {"stringValue": "f"}, "flow.version": {"stringValue": "1.0.0"},
        "flow.segment.id": {"stringValue": "s9"}, "flow.priority": {"stringValue": "P1"}})]))
    a = OtlpDuckDBAdapter([p])
    (s,) = a.list_spans("f", a.extent())
    assert s.attributes["flow.step"] == "s9" and s.attributes["flow.criticality"] == "P1"
    assert "flow.segment.id" not in s.attributes and "flow.priority" not in s.attributes
    assert len(a.ingest_warnings) == 2 and all("R-DEPRECATED" in w for w in a.ingest_warnings)
    b = OtlpDuckDBAdapter([p], accept_deprecated_aliases=False)
    (s,) = b.list_spans("f", b.extent())
    assert "flow.step" not in s.attributes and any("dropped" in w for w in b.ingest_warnings)


def test_enum_and_value_forms(tmp_path):
    p = write(tmp_path, _req([_span("a" * 32, "1" * 16, "x", {
        "flow.id": {"stringValue": "f"}, "flow.step": {"stringValue": "s1"},
        "i": {"intValue": "42"}, "d": {"doubleValue": 1.5}, "b": {"boolValue": True},
        "arr": {"arrayValue": {"values": [{"stringValue": "p"}, {"intValue": 2}]}},
        "kv": {"kvlistValue": {"values": [{"key": "k", "value": {"stringValue": "v"}}]}}},
        kind="SPAN_KIND_CLIENT", start="7", end="9", status="STATUS_CODE_ERROR")]),
        {"resourceLogs": [{"scopeLogs": [{"logRecords": [{"timeUnixNano": "8", "severityNumber": 17,
            "body": {"stringValue": "boom"}, "attributes": [{"key": "flow.id", "value": {"stringValue": "f"}},
                                                             {"key": "flow.step", "value": {"stringValue": "s1"}}],
            "traceId": "A" * 32}]}]}]},
        {"somethingElse": 1})
    a = OtlpDuckDBAdapter([p])
    (s,) = a.list_spans("f", a.extent())
    assert (s.kind, s.status, s.start_ns, s.end_ns) == ("CLIENT", "ERROR", 7, 9)
    assert s.attributes["i"] == "42" and s.attributes["d"] == "1.5" and s.attributes["b"] == "true"
    assert s.attributes["arr"] == '["p","2"]' and s.attributes["kv"] == '{"k":"v"}'
    (lg,) = a.list_logs("f", a.extent())
    assert lg.severity == "ERROR" and lg.body == "boom" and lg.trace_id == "a" * 32
    assert any("line ignored" in w for w in a.ingest_warnings)


def test_bad_json_line_is_an_error(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"resourceSpans": []}\nnot json\n')
    with pytest.raises(QueryError):
        OtlpDuckDBAdapter([p])


def test_load_adapter_registry(tmp_path):
    p = write(tmp_path, _req([]))
    assert load_adapter("otlp_duckdb", [p]).name == "otlp_duckdb"
    with pytest.raises(ValueError):
        load_adapter("tempo", [p])


def test_window_filtering(adapters):
    a = adapters["full"]
    ext = a.extent()
    first_run_end = ext.start_ns + 9 * 10**9                 # runs are 9 s apart
    spans = a.list_spans("quote-issue", Window(ext.start_ns, first_run_end))
    assert len({s.trace_id for s in spans}) == 1
    assert Window(1, 5).contains(1) and not Window(1, 5).contains(5) and Window().contains(10**20)
