"""Adapter protocol — the seam between the coverage engine and a telemetry backend.

The engine (coverage.py, answerability.py, conformance.py) never talks to a
backend directly. It asks an adapter for three things:

  1. the spans / metrics / logs of a flow over a window, as plain rows
     (list_spans, list_metrics, list_logs) — the engine computes completeness,
     cost attribution, execution evidence and conformance in Python over them;
  2. execution of a verification query in a dialect the adapter declares
     (query) — the engine checks the result against the declared
     expected_shape (FTC §4.4, "portability by contract");
  3. the extent of the data it holds (extent), used as the default window.

An adapter is conformant iff (spec/coverage-engine.md §5): it lists the
dialects it executes in `dialects`; `query` returns a QueryResult whose
`columns` are the result's column names and whose `rows` are tuples in that
order; it raises UnsupportedDialect for any dialect not in `dialects` (the
engine then reports the scenario as `not_evaluated`, never as answerable);
and `list_spans` rows carry the attribute names of the canonical namespace
(FTC §4.7), with the deprecated aliases already mapped (and a warning
recorded in `ingest_warnings`).

Adding a backend (Tempo/TraceQL, PromQL, Datadog, ...) means implementing
this protocol in a new module under flowtrace/adapters/ and nothing else.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence, runtime_checkable


# The canonical flow-attribute namespace (FTC §4.7, the shared-canon table)
# with each attribute's class (FTC §4.4; revision 2026-10-11): `identifier`
# names a thing, `digest` commits to a value without disclosing it. Every
# attribute here belongs on the assurance stream. The three `dec.*` digests of
# an effect step's evidence (added 2026-10-11) are what make the step's span
# joinable to the authorization and completion evidence issued around it and
# to the human approval the authorization cites. The deprecated aliases
# (`flow.segment.id` -> flow.step, `flow.priority` -> flow.criticality) are
# mapped on ingest by the adapters and never emitted (canon resolution C).
CANONICAL_ATTRIBUTES: dict[str, str] = {
    "flow.id": "identifier",                   # declared flow id (entry component, at the trigger)
    "flow.version": "identifier",              # flow semver at execution time
    "flow.step": "identifier",                 # current declared step id, on the hosting component's boundary span
    "flow.criticality": "identifier",          # P0..P3 (was flow.priority)
    "flow.step.criticality": "identifier",     # per-step override
    "flow.step.nd_class": "identifier",        # ND0..ND3 as declared
    "flow.run_id": "identifier",               # only when an explicit run id differs from the trace id
    "dec.step_cert_digest": "digest",          # sha256 digest of the DEC step certificate for this span's step
    "dec.run_cert_digest": "digest",           # digest of the run certificate (entry component, at run end)
    "dec.authz_cert_digest": "digest",         # digest of the authorization evidence (policy-decision record) for this span's effect step
    "dec.completion_cert_digest": "digest",    # digest of the completion evidence for this span's effect step
    "dec.approval_digest": "digest",           # digest of the human_approval attestation referenced by the authorization evidence
}
EFFECT_STEP_ATTRIBUTES = ("dec.authz_cert_digest", "dec.completion_cert_digest", "dec.approval_digest")


class UnsupportedDialect(Exception):
    """Raised by Adapter.query for a dialect the adapter does not execute."""


class QueryError(Exception):
    """Raised by Adapter.query when the backend rejects the query text."""


@dataclass(frozen=True)
class Window:
    """Half-open [start_ns, end_ns); None = unbounded on that side."""
    start_ns: int | None = None
    end_ns: int | None = None

    def contains(self, ts_ns: int) -> bool:
        return (self.start_ns is None or ts_ns >= self.start_ns) and (self.end_ns is None or ts_ns < self.end_ns)

    def as_dict(self) -> dict:
        return {"start_ns": self.start_ns, "end_ns": self.end_ns}


@dataclass(frozen=True)
class SpanRow:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    kind: str                      # SERVER | CLIENT | INTERNAL | PRODUCER | CONSUMER | UNSPECIFIED
    start_ns: int
    end_ns: int
    status: str                    # OK | ERROR | UNSET
    attributes: dict[str, str]     # span attributes, values rendered as strings
    resource: dict[str, str] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        return (self.end_ns - self.start_ns) / 1e6

    def attr(self, key: str) -> str | None:
        return self.attributes.get(key)


@dataclass(frozen=True)
class MetricRow:
    name: str
    type: str                      # gauge | sum | histogram | summary | exponential_histogram
    time_ns: int
    attributes: dict[str, str]
    value: float | None = None     # gauge/sum point value
    count: int | None = None       # histogram/summary count
    sum: float | None = None       # histogram/summary sum


@dataclass(frozen=True)
class LogRow:
    time_ns: int
    severity: str                  # severityText (upper-cased) or derived from severityNumber
    body: str
    attributes: dict[str, str]
    trace_id: str | None = None
    span_id: str | None = None


@dataclass(frozen=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]

    @property
    def row_count(self) -> int:
        return len(self.rows)


@runtime_checkable
class Adapter(Protocol):
    """See the module docstring for the conformance rule."""
    name: str
    dialects: frozenset[str]
    ingest_warnings: list[str]

    def extent(self) -> Window: ...
    def query(self, dialect: str, text: str, window: Window) -> QueryResult: ...
    def list_spans(self, flow_id: str, window: Window, flow_version: str | None = None) -> Sequence[SpanRow]: ...
    def list_metrics(self, flow_id: str, window: Window, flow_version: str | None = None) -> Sequence[MetricRow]: ...
    def list_logs(self, flow_id: str, window: Window, flow_version: str | None = None) -> Sequence[LogRow]: ...
