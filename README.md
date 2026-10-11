# flowtrace — Flow-Based Telemetry Coverage, reference implementation

*Software 0.1.0 · implements FTC v1.1 · consumes `flow.spec/v0.2` and DEC v0.2.*

[![gate](https://github.com/azimuth-ink/flowtrace/actions/workflows/gate.yml/badge.svg?branch=main)](https://github.com/azimuth-ink/flowtrace/actions/workflows/gate.yml)
[![code: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue.svg)](https://github.com/azimuth-ink/flowtrace/blob/main/LICENSE)
[![paper: CC0](https://img.shields.io/badge/paper-CC0_1.0-lightgrey.svg)](https://doi.org/10.5281/zenodo.21415947)

flowtrace is the coverage engine disclosed in *Flow-Based Telemetry Coverage:
A Method for Measuring and Governing Observability by Business-Flow
Consequence* (Gray 2026, defensive publication, concept DOI
[10.5281/zenodo.21415947](https://doi.org/10.5281/zenodo.21415947); v1.1 is
in [`paper/`](paper/flow-based-telemetry-coverage.md)). It answers the
question per-component instrumentation cannot: **when a business-critical
flow degrades, can we detect it, locate the cause and resolve it with the
telemetry we have?** — and blocks, in CI, the change that makes the answer
"no".

What it does, section by section of the paper:

- **Tiering (§4.2)** — a flow's criticality `P0..P3` (declared, or derived
  from weighted business-impact dimensions) selects its policy: coverage
  threshold, sampling floor, alert-latency bound, incident-response SLA.
- **SLA → SLO decomposition (§4.3)** — the flow-level latency, availability
  and error budgets are allocated across the steps of its DAG: serial sum /
  parallel max, criticality factor, **nondeterminism factor** (ND0..ND3),
  safety margin, proportional scaling, p95↔p99 approximation, and the
  **cold-start** allocation when no history exists. Pure functions,
  property-tested.
- **Answerability (§4.4)** — each step's debug scenarios are tested by
  executing their verification queries through a backend adapter and
  checking the result against a declared **shape contract**
  `{dialect, text, expected_shape{min_rows, required_columns[]}}`.
- **Coverage score (§4.5)** — telemetry completeness, debug answerability,
  SLO-breach detectability, cost attribution and, optionally,
  **execution-evidence coverage** (binding B7: the fraction of ND0/ND1 step
  executions whose span carries a `dec.step_cert_digest` that verifies
  against the issuer's trust bundle — verified by agent-dec's verifier, never
  reimplemented).
- **Conformance (§4.8)** — convergent / absent / divergent over the window,
  and per run the declared flow read as the **authorized plan**: off-plan
  steps, order violations, loop-bound exceedance per `on_exceed`; the run
  certificate's manifest is the realized DAG when the run carries one (B6).
- **The gate (§4.6)** — `flowtrace gate` writes a schema-validated
  `coverage-report.json`, exits non-zero when a flow falls below its tier's
  threshold (or trips a fail-class finding), and prints per-component deltas
  against a baseline report for review comments.

The normative contract of the engine is
[`spec/coverage-engine.md`](spec/coverage-engine.md); the report format is
[`spec/schemas/coverage-report.schema.json`](spec/schemas/coverage-report.schema.json).

## Three repositories, one system

flowtrace defines no flow descriptor and no certificate. It consumes both:

| Repository | What flowtrace takes from it | Pin (0.1.0) |
|---|---|---|
| [azimuth-ink/polydiagram](https://github.com/azimuth-ink/polydiagram) | `flow.spec/v0.2` (one schema, one owner), the validator R1–R11, the canonical `quote-issue` descriptor | `azimuth-ink/polydiagram@9345577` — v0.2-canon, software 0.3.0 |
| [azimuth-ink/agent-dec](https://github.com/azimuth-ink/agent-dec) | the DEC verifier (`verify_dec`, called as a library), the signed flow-bound `quote-issue` run, trust bundles | `azimuth-ink/agent-dec@e8075f9` — v0.2-canon, software 0.2.0 |

`examples/flows/quote-issue.flow.yaml` is byte-identical to the descriptor in
the three companion papers, in polydiagram (`examples/retail-quote.flow.yaml`)
and in agent-dec (`examples/flow-bound/flows/`); CI checks it with `cmp`. The
`three-repo` CI job validates the flows with polydiagram, verifies
agent-dec's flow-bound run with flowtrace's flows as the registry, and runs
the gate with execution evidence — the test that the three artifacts are one
system.

## Install

```bash
pip install flowtrace                     # engine only (pyyaml, jsonschema, duckdb, rfc8785)
pip install "flowtrace[companions]"       # + polydiagram and agent-dec at the pinned git refs
```

The pinned refs above live on branches that are **not yet pushed**. Until
they are, install the companions from sibling checkouts (this is what the CI
comment says to do, and what `make dev` does):

```bash
git clone https://github.com/azimuth-ink/polydiagram ../polydiagram   # at 9345577
git clone https://github.com/azimuth-ink/agent-dec   ../agent-dec     # at e8075f9
make dev            # pip install -r requirements-dev.txt; pip install ../polydiagram ../agent-dec; pip install -e .
make check          # pytest + polydiagram validation + agent-dec verification + the three gate runs + expected reports
```

Python ≥ 3.10. Without polydiagram installed the engine still runs (the
descriptor is loaded with a warning instead of being validated); without
agent-dec, execution evidence cannot be enabled.

## Quickstart — the three windows

`examples/telemetry/` holds three synthetic evaluation windows for
`quote-issue` (32 runs each; generated, seeded, by
`tools/make_synthetic_telemetry.py` from the signed DEC example so the
digests on the spans are real):

```bash
ARGS="--flows examples/flows --config flowtrace.yaml --alerts examples/alerts.yaml \
      --queries examples/queries/quote-issue.queries.yaml \
      --trust-bundle examples/dec/trust-bundle.json --dec-dir examples/dec/flow-bound \
      --execution-evidence --reproducible"

# 1. every step observable, every scenario answerable, every breach detectable, every ND0 execution evidenced
flowtrace gate $ARGS --telemetry examples/telemetry/quote-issue.full.otlp.jsonl --out full.json
#   GATE quote-issue@2.0.0 [P0]: score 1.0000 >= threshold 1.00 — PASS           (exit 0)

# 2. step s5 (docs.render) emits nothing: a named blind spot, completeness 0, cost attribution 5/6
flowtrace gate $ARGS --telemetry examples/telemetry/quote-issue.s5-silent.otlp.jsonl --baseline full.json --out s5.json
#   GATE quote-issue@2.0.0 [P0]: score 0.6333 < threshold 1.00 — FAIL (…; blind-spot)   (exit 1)
#   conformance  window absent absent=['s5']; runs {'convergent': 1, 'absent': 31, …}

# 3. step s4's span lacks risk.decision: completeness 0 and the stale-reference-data scenario unanswerable
flowtrace gate $ARGS --telemetry examples/telemetry/quote-issue.s4-missing-attr.otlp.jsonl --baseline full.json --out s4.json
#   GATE quote-issue@2.0.0 [P0]: score 0.4000 < threshold 1.00 — FAIL (…)        (exit 1)
```

The reports the gate must reproduce byte for byte are in
`examples/expected/` (that is what `--reproducible` is for: no timestamp, no
commit, basenames). Other commands:

```bash
flowtrace decompose --flows examples/flows            # derived per-step SLOs (cold start without --history)
flowtrace tier --dimension revenue_impact=critical    # criticality score -> tier -> policy
flowtrace conformance --flows examples/flows --telemetry examples/telemetry/quote-issue.s5-silent.otlp.jsonl --dec-dir examples/dec/flow-bound
flowtrace validate-report examples/expected/quote-issue.full.json
```

### What the example inputs are

- `flowtrace.yaml` — every constant the paper calls illustrative, as a
  default with a comment citing its section (tier table, factors, weights
  0.40/0.30/0.20/0.10 and 0.35/0.25/0.20/0.10/0.10 with execution evidence;
  shared-canon resolution E). Pass your own file to `--config`; it is merged
  over the defaults.
- `examples/alerts.yaml` — the alert configuration breach detectability
  needs: per target (flow-level SLO key, or step + SLO key) a threshold,
  evaluation window and notification latency. Format `flowtrace.alerts/v0.1`.
- `examples/queries/quote-issue.queries.yaml` — a **query binding**. The
  canonical descriptor's s4 verification query is a natural-language
  placeholder (`<query returning decisions grouped by reference-data version
  …>`) and the descriptor is byte-identical across the papers, so the
  executable `otel-sql` form and its expected shape are bound to the scenario
  from outside. A descriptor may instead carry `dialect` and
  `expected_shape` itself (flow.spec/v0.2 fields).
- `examples/dec/` — agent-dec's signed flow-bound run copied verbatim
  (`SOURCE` records the pin) and a `dec-trust/0.2` bundle built from its
  issuer key (agent-dec ships the key as a bare PEM).

### Execution evidence in the examples

Every synthetic run carries, on each step's boundary span, the real
`dec.step_cert_digest` of the one signed `quote-issue` run agent-dec ships
(signed artifacts are never minted by hand — canon invariant 3). Binding B7
is therefore satisfied for all 32 runs (the certificate is found, its
signature verifies, `subject.flow` matches the span) and the component scores
1.0 for s4. The certificate's `subject.run_id`, however, is the trace id of
only the first run; for the other 31 the engine reports a **run-binding
mismatch**. The default `scoring.execution_evidence.run_binding: warn` counts
B7 and reports the mismatch; `strict` (recommended in production, where every
run has its own certificates) would score 1/32 here. The first run's trace id
*is* the certified one, so its conformance reading takes the run
certificate's manifest as the realized DAG (B6) — in the s5-silent window that
run reads *convergent* from the manifest while the 31 span-sourced runs read
*absent*: the certificate says s5 ran; the telemetry cannot see it.

## Adding a backend — the dialect contract

A verification query is portable by contract, not by dialect (FTC §4.4). The
engine never interprets query text; it hands `(dialect, text, window)` to an
adapter and checks the rows it gets back against `expected_shape`. An adapter
is a module implementing `flowtrace.adapters.base.Adapter`:

```python
class Adapter(Protocol):
    name: str
    dialects: frozenset[str]              # the dialects it executes, e.g. {"traceql"}
    ingest_warnings: list[str]
    def extent(self) -> Window: ...
    def query(self, dialect, text, window) -> QueryResult: ...   # columns + rows; UnsupportedDialect otherwise
    def list_spans(self, flow_id, window, flow_version=None) -> Sequence[SpanRow]: ...
    def list_metrics(self, flow_id, window, flow_version=None) -> Sequence[MetricRow]: ...
    def list_logs(self, flow_id, window, flow_version=None) -> Sequence[LogRow]: ...
```

Rows carry the canonical attribute names (`flow.id`, `flow.version`,
`flow.step`, …; FTC §4.7) with the deprecated `flow.segment.id` /
`flow.priority` mapped on ingest with a warning and never emitted. Register
the module in `flowtrace.adapters.REGISTRY`; nothing in the engine changes.
A scenario whose dialect no adapter executes is reported `not_evaluated`,
never answerable. The full rule is spec §5.4.

The shipped adapter, `otlp_duckdb`, reads OTLP/JSON export files — one
`ExportTraceServiceRequest` / `ExportMetricsServiceRequest` /
`ExportLogsServiceRequest` per line, the shape the OpenTelemetry Collector's
`file` exporter writes, so a production export replays through the gate
unchanged — into DuckDB and executes dialect **`otel-sql`**: a SELECT over
`spans(trace_id, span_id, parent_span_id, name, service_name, kind, start_ns,
end_ns, duration_ms, status, attributes MAP, resource MAP)`, `metrics`,
`logs` and `eval_window`. `attributes['flow.step']` is the value or NULL;
cast numbers with `::DOUBLE`. Spec §5.5 has the schema.

## Repository layout

```
paper/                 FTC v1.1 (CC0 1.0) — the disclosure this software implements
spec/coverage-engine.md               normative: tiering, decomposition, answerability contract, scoring, gate, conformance
spec/schemas/          coverage-report.schema.json (flowtrace.report/v0.1), verification-query.schema.json (flowtrace.queries/v0.1)
flowtrace.yaml         the shipped defaults, every constant with its FTC section
src/flowtrace/         tiering, decompose, answerability, coverage, conformance, gate, cli, report, config, flows
src/flowtrace/adapters/   base.py (the protocol), otlp_duckdb.py (the reference adapter)
examples/flows/        quote-issue.flow.yaml — the canonical descriptor, byte-identical to the papers and both companions
examples/telemetry/    three synthetic OTLP/JSON windows (full, s5-silent, s4-missing-attr)
examples/expected/     the three reports the gate reproduces byte for byte
examples/dec/          agent-dec's signed flow-bound run (verbatim) + trust-bundle.json + SOURCE
examples/alerts.yaml   examples/queries/   the detectability and answerability inputs
tools/make_synthetic_telemetry.py     seeded generator (real certificate digests, cross-checked against the manifest)
tests/                 pytest + hypothesis: one module per engine module, byte-identity of the canon, expected reports, CLI
.github/workflows/gate.yml            the three-repo job (3.10 / 3.12) and the weekly latest-companions variant
Makefile               make dev / test / validate-flows / verify-dec / gate / expected / check
```

## Versioning

Three tracks, stated once. **Paper** versions (FTC v1.x) describe the
method. **Specification** versions are what artifacts declare and are owned
elsewhere: `flow.spec/v0.x` (polydiagram) for descriptors, `dec_version` /
`dec-trust/0.x` (agent-dec) for certificates and bundles; flowtrace owns only
the formats it introduces — `flowtrace.report/v0.x`, `flowtrace.config/v0.x`,
`flowtrace.alerts/v0.x`, `flowtrace.queries/v0.x` — versioned in
`spec/coverage-engine.md` and the schemas. **Software** releases
(`pyproject.toml`, `CITATION.cff`, `.zenodo.json`, git tags) follow semantic
versioning and declare which paper and which companion versions they
implement: 0.1.0 implements FTC v1.1 on `flow.spec/v0.2` (polydiagram 0.3.0
at `9345577`) and DEC v0.2 (agent-dec 0.2.0 at `e8075f9`). Deprecated
attribute aliases are accepted on ingest with a warning through every
`flow.spec/v0.x` version and never emitted. See `CHANGELOG.md`.

## Status and scope

0.1.0: the engine, one adapter, the shared running example end to end, the
three-repo CI. Deliberately out of scope (contracts defined, tooling
invited): a canvas, a trace-topology discovery miner, more than one backend
adapter. Limits the paper states apply: conformance is evaluated after the
fact; execution evidence is as strong as the issuer's trust bundle; the
engine cannot measure effective sampling from an export alone.

### What a real deployment must add

- **Adapters** for the telemetry backend in use (Tempo/TraceQL, PromQL +
  trace store, Datadog, ClickHouse, …) implementing the protocol above; the
  DuckDB adapter is for exports, fixtures and CI.
- **Alert-config import**: a tool that writes `alerts.yaml` from the alerting
  system's rules (Alertmanager, Datadog monitors, …) so detectability tracks
  what is actually configured.
- **Query bindings per dialect** for scenarios whose descriptors carry
  placeholders, kept beside the flows and reviewed with them.
- **Retention and windows**: scheduled gate runs over rolling windows with
  the report history kept (trends across the cold-start transition, PD §5's
  "what did we know and when"), and a certificate store the gate can resolve
  digests against (`--dec-dir` is a directory stand-in).
- **Sampling-rate input** from the collector's sampler configuration
  (`--sampling-rate`) and `run_binding: strict` once every run carries its
  own certificates.

## License

Code, schemas, configuration, examples and tests: Apache-2.0 (see
`LICENSE`, including its patent grant). The paper under `paper/` is a
defensive publication under CC0 1.0 (public domain dedication); the notes at
the end of `LICENSE` say so. Signed artifacts under `examples/dec/` are
copied verbatim from agent-dec (Apache-2.0).

## Citing

See `CITATION.cff`. Cite the method by its concept DOI
(10.5281/zenodo.21415947); a software DOI is minted per tagged release.

*Drafting and specification development were assisted by Claude (Anthropic);
all design decisions, claims, and errors are the author's.*
