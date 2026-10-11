"""Reference adapter: OTLP/JSON export files loaded into DuckDB; dialect ``otel-sql``.

Input format
------------
A `.jsonl` file with ONE OTLP/JSON export request per line, exactly as the
OpenTelemetry Collector's `file` exporter writes them:

  * `{"resourceSpans": [...]}`   — ExportTraceServiceRequest
  * `{"resourceMetrics": [...]}` — ExportMetricsServiceRequest
  * `{"resourceLogs": [...]}`    — ExportLogsServiceRequest

Field names follow the OTLP/JSON mapping (lowerCamelCase: `traceId`, `spanId`,
`parentSpanId`, `startTimeUnixNano`, `attributes[] {key, value: {stringValue |
intValue | doubleValue | boolValue | arrayValue | kvlistValue | bytesValue}}`).
Enums are accepted either as integers (`kind: 2`, `status.code: 1`) or as the
proto names (`SPAN_KIND_SERVER`, `STATUS_CODE_OK`). Timestamps are accepted
as strings or integers. A flat shape is NOT accepted: real collector output
is the contract, so that a production export can be replayed through the gate
unchanged.

Attribute values are rendered as strings (ints and floats via `str`, bools as
`true`/`false`, arrays and kvlists as JSON); SQL casts them back
(`attributes['cost.usd']::DOUBLE`). The deprecated aliases `flow.segment.id`
and `flow.priority` (FTC v1.0) are mapped on ingest to `flow.step` and
`flow.criticality` with a warning (resolution C) and are never re-emitted.

Relational schema (the ``otel-sql`` dialect contract — spec §5.2)
-----------------------------------------------------------------
  spans(trace_id VARCHAR, span_id VARCHAR, parent_span_id VARCHAR, name VARCHAR,
        service_name VARCHAR, kind VARCHAR, start_ns BIGINT, end_ns BIGINT,
        duration_ms DOUBLE, status VARCHAR,
        attributes MAP(VARCHAR, VARCHAR), resource MAP(VARCHAR, VARCHAR))
  metrics(name VARCHAR, type VARCHAR, time_ns BIGINT, attributes MAP(VARCHAR, VARCHAR),
          value DOUBLE, count BIGINT, sum DOUBLE)
  logs(time_ns BIGINT, severity VARCHAR, body VARCHAR, attributes MAP(VARCHAR, VARCHAR),
       trace_id VARCHAR, span_id VARCHAR)
  eval_window(start_ns BIGINT, end_ns BIGINT)   -- the evaluation window, one row (joinable)

`attributes['flow.step']` yields the value or NULL. A verification query in
dialect ``otel-sql`` is any single SELECT over these views; the engine
executes it read-only and checks the result shape.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Iterable, Sequence

import duckdb

from .base import LogRow, MetricRow, QueryError, QueryResult, SpanRow, UnsupportedDialect, Window

DIALECT = "otel-sql"
DEPRECATED_ALIASES = {"flow.segment.id": "flow.step", "flow.priority": "flow.criticality"}
_KIND = {0: "UNSPECIFIED", 1: "INTERNAL", 2: "SERVER", 3: "CLIENT", 4: "PRODUCER", 5: "CONSUMER"}
_STATUS = {0: "UNSET", 1: "OK", 2: "ERROR"}


def _enum(value: Any, table: dict[int, str], prefix: str) -> str:
    if value is None:
        return table[0]
    if isinstance(value, bool):
        return table[0]
    if isinstance(value, int):
        return table.get(value, table[0])
    s = str(value)
    if s.startswith(prefix):
        s = s[len(prefix):]
    return s if s in table.values() else table[0]


def _any_value(v: Any) -> str:
    if not isinstance(v, dict):
        return "" if v is None else str(v)
    if "stringValue" in v:
        return str(v["stringValue"])
    if "intValue" in v:
        return str(int(v["intValue"]))
    if "doubleValue" in v:
        d = v["doubleValue"]
        return str(float(d)) if not isinstance(d, str) else d
    if "boolValue" in v:
        return "true" if v["boolValue"] else "false"
    if "bytesValue" in v:
        return str(v["bytesValue"])
    if "arrayValue" in v:
        return json.dumps([_any_value(x) for x in (v["arrayValue"].get("values") or [])], separators=(",", ":"))
    if "kvlistValue" in v:
        return json.dumps({kv["key"]: _any_value(kv.get("value")) for kv in (v["kvlistValue"].get("values") or [])},
                          separators=(",", ":"), sort_keys=True)
    return ""


def _ns(v: Any) -> int:
    if v is None:
        return 0
    return int(v)


class OtlpDuckDBAdapter:
    """Loads one or more OTLP/JSON export files; serves the Adapter protocol."""

    name = "otlp_duckdb"
    dialects = frozenset({DIALECT})

    def __init__(self, paths: Iterable[str | pathlib.Path], accept_deprecated_aliases: bool = True):
        self.paths = [pathlib.Path(p) for p in paths]
        self.accept_deprecated_aliases = accept_deprecated_aliases
        self.ingest_warnings: list[str] = []
        self._alias_hits: dict[str, int] = {}
        self.con = duckdb.connect(database=":memory:")
        self._spans: list[SpanRow] = []
        self._metrics: list[MetricRow] = []
        self._logs: list[LogRow] = []
        self._load()

    # ------------------------------------------------------------------ ingest
    def _attrs(self, items: Any, where: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for kv in items or []:
            if not isinstance(kv, dict) or "key" not in kv:
                continue
            key = str(kv["key"])
            val = _any_value(kv.get("value"))
            if key in DEPRECATED_ALIASES:
                self._alias_hits[key] = self._alias_hits.get(key, 0) + 1
                if self.accept_deprecated_aliases:
                    out.setdefault(DEPRECATED_ALIASES[key], val)
                continue
            out[key] = val
        return out

    def _load(self) -> None:
        for path in self.paths:
            with path.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        req = json.loads(line)
                    except ValueError as e:
                        raise QueryError(f"{path}:{lineno}: not valid JSON ({e})") from None
                    if not isinstance(req, dict):
                        raise QueryError(f"{path}:{lineno}: export request is not an object")
                    where = f"{path.name}:{lineno}"
                    self._load_spans(req.get("resourceSpans") or [], where)
                    self._load_metrics(req.get("resourceMetrics") or [], where)
                    self._load_logs(req.get("resourceLogs") or [], where)
                    if not any(k in req for k in ("resourceSpans", "resourceMetrics", "resourceLogs")):
                        self.ingest_warnings.append(f"{where}: no resourceSpans/resourceMetrics/resourceLogs — line ignored")
        for key, n in sorted(self._alias_hits.items()):
            action = f"mapped to {DEPRECATED_ALIASES[key]}" if self.accept_deprecated_aliases else "dropped (aliases disabled)"
            self.ingest_warnings.append(
                f"R-DEPRECATED: attribute '{key}' seen on {n} record(s); {action}. "
                f"Accepted through flow.spec/v0.x, removed at v1.0, never emitted.")
        self._build_tables()

    def _load_spans(self, resource_spans: list, where: str) -> None:
        for rs in resource_spans:
            resource = self._attrs((rs.get("resource") or {}).get("attributes"), where)
            service = resource.get("service.name", "")
            for ss in rs.get("scopeSpans") or rs.get("instrumentationLibrarySpans") or []:
                for sp in ss.get("spans") or []:
                    self._spans.append(SpanRow(
                        trace_id=str(sp.get("traceId", "")).lower(),
                        span_id=str(sp.get("spanId", "")).lower(),
                        parent_span_id=(str(sp["parentSpanId"]).lower() if sp.get("parentSpanId") else None),
                        name=str(sp.get("name", "")),
                        kind=_enum(sp.get("kind"), _KIND, "SPAN_KIND_"),
                        start_ns=_ns(sp.get("startTimeUnixNano")),
                        end_ns=_ns(sp.get("endTimeUnixNano")),
                        status=_enum((sp.get("status") or {}).get("code"), _STATUS, "STATUS_CODE_"),
                        attributes=self._attrs(sp.get("attributes"), where),
                        resource=dict(resource, **({"service.name": service} if service else {})),
                    ))

    def _load_metrics(self, resource_metrics: list, where: str) -> None:
        for rm in resource_metrics:
            for sm in rm.get("scopeMetrics") or []:
                for m in sm.get("metrics") or []:
                    name = str(m.get("name", ""))
                    for mtype in ("gauge", "sum", "histogram", "summary", "exponentialHistogram"):
                        block = m.get(mtype)
                        if not isinstance(block, dict):
                            continue
                        for dp in block.get("dataPoints") or []:
                            value = dp.get("asDouble", dp.get("asInt"))
                            self._metrics.append(MetricRow(
                                name=name,
                                type={"exponentialHistogram": "exponential_histogram"}.get(mtype, mtype),
                                time_ns=_ns(dp.get("timeUnixNano")),
                                attributes=self._attrs(dp.get("attributes"), where),
                                value=(float(value) if value is not None else None),
                                count=(int(dp["count"]) if dp.get("count") is not None else None),
                                sum=(float(dp["sum"]) if dp.get("sum") is not None else None),
                            ))

    def _load_logs(self, resource_logs: list, where: str) -> None:
        for rl in resource_logs:
            for sl in rl.get("scopeLogs") or []:
                for rec in sl.get("logRecords") or []:
                    sev = str(rec.get("severityText") or "").upper()
                    if not sev and rec.get("severityNumber") is not None:
                        n = int(rec["severityNumber"])
                        sev = ("TRACE" if n <= 4 else "DEBUG" if n <= 8 else "INFO" if n <= 12
                               else "WARN" if n <= 16 else "ERROR" if n <= 20 else "FATAL")
                    self._logs.append(LogRow(
                        time_ns=_ns(rec.get("timeUnixNano") or rec.get("observedTimeUnixNano")),
                        severity=sev, body=_any_value(rec.get("body")),
                        attributes=self._attrs(rec.get("attributes"), where),
                        trace_id=(str(rec["traceId"]).lower() if rec.get("traceId") else None),
                        span_id=(str(rec["spanId"]).lower() if rec.get("spanId") else None),
                    ))

    def _build_tables(self) -> None:
        con = self.con
        con.execute("CREATE TABLE spans_raw(trace_id VARCHAR, span_id VARCHAR, parent_span_id VARCHAR, name VARCHAR, "
                    "service_name VARCHAR, kind VARCHAR, start_ns BIGINT, end_ns BIGINT, status VARCHAR, "
                    "attributes VARCHAR, resource VARCHAR)")
        con.executemany("INSERT INTO spans_raw VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [
            (s.trace_id, s.span_id, s.parent_span_id, s.name, s.resource.get("service.name"), s.kind,
             s.start_ns, s.end_ns, s.status, json.dumps(s.attributes), json.dumps(s.resource))
            for s in self._spans]) if self._spans else None
        con.execute("CREATE VIEW spans AS SELECT trace_id, span_id, parent_span_id, name, service_name, kind, "
                    "start_ns, end_ns, (end_ns - start_ns) / 1e6 AS duration_ms, status, "
                    "CAST(attributes::JSON AS MAP(VARCHAR, VARCHAR)) AS attributes, "
                    "CAST(resource::JSON AS MAP(VARCHAR, VARCHAR)) AS resource FROM spans_raw")
        con.execute("CREATE TABLE metrics_raw(name VARCHAR, type VARCHAR, time_ns BIGINT, attributes VARCHAR, "
                    "value DOUBLE, count BIGINT, sum DOUBLE)")
        if self._metrics:
            con.executemany("INSERT INTO metrics_raw VALUES (?, ?, ?, ?, ?, ?, ?)", [
                (m.name, m.type, m.time_ns, json.dumps(m.attributes), m.value, m.count, m.sum) for m in self._metrics])
        con.execute("CREATE VIEW metrics AS SELECT name, type, time_ns, CAST(attributes::JSON AS MAP(VARCHAR, VARCHAR)) "
                    "AS attributes, value, count, sum FROM metrics_raw")
        con.execute("CREATE TABLE logs_raw(time_ns BIGINT, severity VARCHAR, body VARCHAR, attributes VARCHAR, "
                    "trace_id VARCHAR, span_id VARCHAR)")
        if self._logs:
            con.executemany("INSERT INTO logs_raw VALUES (?, ?, ?, ?, ?, ?)", [
                (l.time_ns, l.severity, l.body, json.dumps(l.attributes), l.trace_id, l.span_id) for l in self._logs])
        con.execute("CREATE VIEW logs AS SELECT time_ns, severity, body, CAST(attributes::JSON AS MAP(VARCHAR, VARCHAR)) "
                    "AS attributes, trace_id, span_id FROM logs_raw")
        ext = self.extent()
        con.execute("CREATE TABLE eval_window(start_ns BIGINT, end_ns BIGINT)")
        con.execute("INSERT INTO eval_window VALUES (?, ?)", [ext.start_ns, ext.end_ns])

    # ------------------------------------------------------------ the protocol
    def extent(self) -> Window:
        times = [s.start_ns for s in self._spans] + [m.time_ns for m in self._metrics] + [l.time_ns for l in self._logs]
        ends = [s.end_ns for s in self._spans]
        if not times:
            return Window(None, None)
        return Window(min(times), max(ends + times) + 1)

    def set_window(self, window: Window) -> None:
        """Re-point the `eval_window` helper table (queries may join it)."""
        self.con.execute("DELETE FROM eval_window")
        self.con.execute("INSERT INTO eval_window VALUES (?, ?)", [window.start_ns, window.end_ns])

    def query(self, dialect: str, text: str, window: Window) -> QueryResult:
        if dialect not in self.dialects:
            raise UnsupportedDialect(dialect)
        self.set_window(window)
        try:
            cur = self.con.execute(text)
            rows = cur.fetchall()
            cols = tuple(d[0] for d in (cur.description or ()))
        except duckdb.Error as e:
            raise QueryError(str(e).splitlines()[0]) from None
        return QueryResult(columns=cols, rows=tuple(tuple(r) for r in rows))

    def _in_window(self, ts: int, window: Window) -> bool:
        return window.contains(ts)

    def list_spans(self, flow_id: str, window: Window, flow_version: str | None = None) -> Sequence[SpanRow]:
        return [s for s in self._spans
                if s.attributes.get("flow.id") == flow_id
                and (flow_version is None or s.attributes.get("flow.version") == flow_version)
                and self._in_window(s.start_ns, window)]

    def list_metrics(self, flow_id: str, window: Window, flow_version: str | None = None) -> Sequence[MetricRow]:
        return [m for m in self._metrics
                if m.attributes.get("flow.id") == flow_id
                and (flow_version is None or m.attributes.get("flow.version") == flow_version)
                and self._in_window(m.time_ns, window)]

    def list_logs(self, flow_id: str, window: Window, flow_version: str | None = None) -> Sequence[LogRow]:
        return [l for l in self._logs
                if l.attributes.get("flow.id") == flow_id
                and (flow_version is None or l.attributes.get("flow.version") == flow_version)
                and self._in_window(l.time_ns, window)]

    # --------------------------------------------------------------- utilities
    def all_spans(self) -> Sequence[SpanRow]:
        return list(self._spans)

    def counts(self) -> dict[str, int]:
        return {"spans": len(self._spans), "metrics": len(self._metrics), "logs": len(self._logs),
                "traces": len({s.trace_id for s in self._spans})}

    def close(self) -> None:
        self.con.close()
