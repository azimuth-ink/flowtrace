# flowtrace — Flow-Based Telemetry Coverage, reference implementation

*Software 0.1.0 · implements FTC v1.1 (revision of 2026-10-11: control-plane mechanics) · consumes `flow.spec/v0.2` and DEC v0.2.*

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
  reimplemented) extended to **authorization coverage** for effect steps
  (B7 extended: a `dec.authz_cert_digest` that resolves to a policy-decision
  record signed by a policy authority, bound to the span, accepted by the
  verifier's step 1d, and an `allow`). Computed over the **assurance
  stream** (§4.4): required attributes carry a class (`identifier | digest |
  content`); `content` is never on the assurance stream and is evaluated on
  the sampled stream.
- **Two-sided indicators (§4.5)** — the **degradation rate** (runs that took
  a declared `on_fail` edge) and the **veto rate** (runs whose outcome is
  `block`), each against a declared band; out of band in either direction is
  a finding. Exact from run-certificate manifests, approximate from spans.
- **Conformance (§4.8)** — convergent / absent / divergent over the window,
  and per run the declared flow read as the **authorized plan**: off-plan
  steps, order violations, loop-bound exceedance per `on_exceed`; the run
  certificate's manifest is the realized DAG when the run carries one (B6);
  declared degradation paths and latches, outcomes and termination (B9);
  attempts of an effect step collapsed into the declared step with
  reconciliation before retry (B17); effect steps without authorization
  evidence (B10); cancellation propagation across parent and child runs
  (B14). Everything that needs a certificate chain is taken from agent-dec's
  verifier called as a library on the run's directory.
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
| [azimuth-ink/polydiagram](https://github.com/azimuth-ink/polydiagram) | `flow.spec/v0.2` (one schema, one owner), the validator R1–R15, the canonical `quote-issue` descriptor | `azimuth-ink/polydiagram@e768f1c` — revision 2026-10-11 (outcomes, `on_fail`, `effect` / `attempts`, attribute classes, `assurance_sampling_floor`; R12–R15, DG13), software 0.3.0 |
| [azimuth-ink/agent-dec](https://github.com/azimuth-ink/agent-dec) | the DEC verifier (`verify_dec`, called as a library: signatures, the conformance reading, the step-1d readings), the signed flow-bound `quote-issue` run with its evidence artifacts, the variants and negatives, the `dec-trust/0.2` bundle | `azimuth-ink/agent-dec@89fdc36` — revision 2026-10-11 (authorization / completion evidence, `human_approval`, steps 1c/1d, `policy_authorities[]` / `approvers[]`), software 0.2.0 |

`examples/flows/quote-issue.flow.yaml` (2.1.0, sha256 `bcbf4315…`) is
byte-identical to the descriptor in the three companion papers, in
polydiagram (`examples/retail-quote.flow.yaml`) and in agent-dec
(`examples/flow-bound/flows/`); CI checks it with `cmp`, and every artifact
under `examples/dec/` against the agent-dec checkout. The `three-repo` CI job
validates the flows with polydiagram, verifies agent-dec's flow-bound run
(and the vendored copy, variants and cancelled pair) with flowtrace's flows
as the registry and the `dec-trust/0.2` bundle, and runs the gate with
execution evidence over the seven windows — the test that the three
artifacts are one system.

## Install

```bash
pip install flowtrace                     # engine only (pyyaml, jsonschema, duckdb, rfc8785)
pip install "flowtrace[companions]"       # + polydiagram and agent-dec at the pinned git refs
```

The pinned refs above live on branches that are **not yet pushed**. Until
they are, install the companions from sibling checkouts (this is what the CI
comment says to do, and what `make dev` does):

```bash
git clone https://github.com/azimuth-ink/polydiagram ../polydiagram   # at e768f1c
git clone https://github.com/azimuth-ink/agent-dec   ../agent-dec     # at 89fdc36
make dev            # pip install -r requirements-dev.txt; pip install ../polydiagram ../agent-dec (as wheels); pip install -e .
make check          # pytest + polydiagram validation + agent-dec verification + the seven gate runs + expected reports
```

Install the companions as wheels (what `make dev` does), never with
`pip install -e`: an editable agent-dec resolves its default methods
directory against the checkout and hides the installed-package behaviour the
gate relies on (`--methods`). A stale earlier install is skipped by pip as
"already satisfied" — `pip install --force-reinstall --no-deps` the two
checkouts when the sibling commits move.

Python ≥ 3.10. Without polydiagram installed the engine still runs (the
descriptor is loaded with a warning instead of being validated); without
agent-dec, execution evidence cannot be enabled.

## Quickstart — the seven windows

`examples/telemetry/` holds seven synthetic evaluation windows for
`quote-issue` 2.1.0 (32 runs each; generated, seeded, by
`tools/make_synthetic_telemetry.py` from the signed DEC examples so the
digests on the spans are real — step certificates, run certificates and, on
the effect step `s6`, the authorization and completion evidence):

```bash
ARGS="--flows examples/flows --config flowtrace.yaml --alerts examples/alerts.yaml \
      --queries examples/queries/quote-issue.queries.yaml \
      --trust-bundle examples/dec/trust-bundle.json --dec-dir examples/dec/flow-bound \
      --execution-evidence --reproducible"
TEL=examples/telemetry

# 1. every step observable, every scenario answerable, every breach detectable, s4 certificates and s6 authorizations verified
flowtrace gate $ARGS --telemetry $TEL/quote-issue.full.otlp.jsonl --out full.json
#   GATE quote-issue@2.1.0 [P0]: score 1.0000 >= threshold 1.00 — PASS           (exit 0)
#   execution_evidence  1.0000  … s4 32/32, s6 authz 32/32  (certificates 1.0, authorization 1.0000)
#   degradation_rate    0.0000  band [0.0, 0.25]  0/32 runs  source mixed (approximate)

# 2. s5 fails and the run delivers without the document — s5's declared on_fail edge to s6: convergent by declaration
flowtrace gate $ARGS --telemetry $TEL/quote-issue.s5-degraded.otlp.jsonl --baseline full.json --out degraded.json
#   PASS; degradation_rate 0.0312 (1/32: the certified run's manifest says `via: on_fail`; from spans alone s5 → s6 is
#   also the primary edge, so the other 31 runs cannot be counted — the shared-target note says so)

# 3. s6's first attempt completes `unknown`, a `reconciled` completion follows, no retry: convergent
flowtrace gate $ARGS --telemetry $TEL/quote-issue.s6-unknown-reconciled.otlp.jsonl --baseline full.json --out reconciled.json

# 4. step s5 (docs.render) emits nothing: a named blind spot, completeness 0, cost attribution 5/6
flowtrace gate $ARGS --telemetry $TEL/quote-issue.s5-silent.otlp.jsonl --baseline full.json --out s5.json
#   GATE quote-issue@2.1.0 [P0]: score 0.6333 < threshold 1.00 — FAIL (…; blind-spot)   (exit 1)

# 5. step s4's span lacks risk.decision: completeness 0 and the stale-reference-data scenario unanswerable
flowtrace gate $ARGS --telemetry $TEL/quote-issue.s4-missing-attr.otlp.jsonl --baseline full.json --out s4.json
#   GATE quote-issue@2.1.0 [P0]: score 0.4000 < threshold 1.00 — FAIL (…)        (exit 1)

# 6. s6 retried after an `unknown` completion with no reconciliation (binding B17): divergent, from agent-dec's step 1d
flowtrace gate $ARGS --telemetry $TEL/quote-issue.s6-retry-unreconciled.otlp.jsonl --baseline full.json --out retry.json
#   FAIL (non-convergent-runs; retry-without-reconciliation); realized s1 s2 s3 s4 s5 s6×2

# 7. a cancelled parent whose child completed 120 s after the cancellation (binding B14): divergent
flowtrace gate $ARGS --runs-dir examples/dec/flow-bound/negative/cancellation-not-propagated \
          --telemetry $TEL/quote-issue.cancelled-child-late.otlp.jsonl --baseline full.json --out cancelled.json
#   FAIL (…; cancellation-not-propagated): child run fcc6c3a3… closed (completed) at 07:19:28Z, after 07:17:28Z + 30 s
```

The reports the gate must reproduce byte for byte are in
`examples/expected/` (that is what `--reproducible` is for: no timestamp, no
commit, basenames). Flags added on 2026-10-15: `--assurance-telemetry FILE`
(the assurance stream as a second export; `--telemetry` is then the sampled
stream) and `--assurance-sampling-rate`; `--methods DIR` (agent-dec's ND0
replay artifacts when its verifier runs on a run directory; default
`methods/` in or beside a `--dec-dir`); `--approvals DIR` (`human_approval`
attestations, default `approvals/` beside each chain); `--runs-dir DIR` (run
certificates outside the window, for the children of cancelled parents).
Other commands:

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
  shared-canon resolution E; the `slis.*` bands — `flow.spec/v0.2` carries no
  band field, so the running example's bands live here under
  `flows.quote-issue`; `attribute_classes`, `telemetry.assumed_assurance_sampling_rate`,
  `conformance.cancel_propagation_s`). Pass your own file to `--config`; it
  is merged over the defaults.
- `examples/alerts.yaml` — the alert configuration breach detectability
  needs: per target (flow-level SLO key, or step + SLO key) a threshold,
  evaluation window and notification latency; and, with `slo:
  degradation_rate | veto_rate` and `bound: max | min`, a watch on one bound
  of an indicator's band. Format `flowtrace.alerts/v0.1`.
- `examples/queries/quote-issue.queries.yaml` — a **query binding**. The
  canonical descriptor's s4 verification query is a natural-language
  placeholder (`<query returning decisions grouped by reference-data version
  …>`) and the descriptor is byte-identical across the papers, so the
  executable `otel-sql` form and its expected shape are bound to the scenario
  from outside. A descriptor may instead carry `dialect` and
  `expected_shape` itself (flow.spec/v0.2 fields).
- `examples/dec/` — agent-dec's signed example set copied verbatim
  (`SOURCE` records the pin): the `dec-trust/0.2` bundle with its three key
  classes (`keys[]`, `policy_authorities[]`, `approvers[]`), the method
  artifacts, the flow-bound run (s1..s5, the s6 authorization, s6, the s6
  completion), the variants `s5-degraded` / `s6-reconciled` / `s6-approval`,
  the cancelled parent and child, the negatives and the hosted ND1 run.

### Execution evidence in the examples

Every synthetic run carries, on each step's boundary span, the real
`dec.step_cert_digest` of one signed `quote-issue` run agent-dec ships, and
on `s6` the real `dec.authz_cert_digest` and `dec.completion_cert_digest` of
its evidence (signed artifacts are never minted by hand — canon invariant 3).
Binding B7, and B7 extended to authorization records, is therefore satisfied
for all 32 runs (the artifact is found, its signature verifies in its
trust-bundle class, `subject.flow` matches the span, the verifier's step 1d
accepts it) and the component scores 1.0 for s4 and s6. The artifacts'
`subject.run_id`, however, is the trace id of only the first run; for the
other 31 the engine reports a **run-binding mismatch**. The default
`scoring.execution_evidence.run_binding: warn` counts B7 and reports the
mismatch; `strict` (recommended in production, where every run has its own
certificates) would score 1/32 here. The first run's trace id *is* the
certified one, and its trigger span names the run certificate by
`dec.run_cert_digest` (several of the vendored negatives claim the same run
id; the digest settles it), so its conformance reading takes the run
certificate's manifest as the realized DAG (B6) — in the s5-silent window
that run reads *convergent* from the manifest while the 31 span-sourced runs
read *absent* (the certificate says s5 ran; the telemetry cannot see it); in
the s5-degraded window it is the one run the degradation rate can count
exactly; in the s6-retry-unreconciled and cancelled-child-late windows it is
the one run the verifier's step 1d and the cross-run reading can judge. What
the span-sourced runs cannot support is listed under
`conformance.summary.unchecked` in every report (B10 and B17 for 31 runs),
so a green gate is never mistaken for a checked rule.

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
src/flowtrace/evidence.py   the bridge to agent-dec's verifier (step-1d findings parsed from its line contract)
examples/flows/        quote-issue.flow.yaml — the canonical 2.1.0 descriptor, byte-identical to the papers and both companions
examples/telemetry/    seven synthetic OTLP/JSON windows (full, s5-degraded, s6-unknown-reconciled, s5-silent, s4-missing-attr, s6-retry-unreconciled, cancelled-child-late)
examples/expected/     the seven reports the gate reproduces byte for byte
examples/dec/          agent-dec's signed example set (verbatim: flow-bound run + evidence, variants, cancelled pair, negatives, hosted) + trust-bundle.json + methods + SOURCE
examples/alerts.yaml   examples/queries/   the detectability and answerability inputs (incl. the two band alerts and the binding's stream)
tools/make_synthetic_telemetry.py     seeded generator (real certificate and evidence digests, cross-checked against the manifests)
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
implement: 0.1.0 implements FTC v1.1 — with its revision of 2026-10-11 — on
`flow.spec/v0.2` (polydiagram 0.3.0 at `azimuth-ink/polydiagram@e768f1c`) and
DEC v0.2 (agent-dec 0.2.0 at `azimuth-ink/agent-dec@89fdc36`). Deprecated
attribute aliases are accepted on ingest with a warning through every
`flow.spec/v0.x` version and never emitted. See `CHANGELOG.md`.

## Status and scope

0.1.0: the engine, one adapter, the shared running example end to end, the
three-repo CI; since 2026-10-15 the control-plane mechanics of the paper's
revision of 2026-10-11 (see `CHANGELOG.md`). Deliberately out of scope
(contracts defined, tooling invited): a canvas, a trace-topology discovery
miner, more than one backend adapter. Limits the paper states apply:
conformance is evaluated after the fact (an effect step without
authorization evidence is recorded, never prevented); execution evidence is
as strong as the issuer's trust bundle; the engine cannot measure effective
sampling from an export alone, for either stream; compensation is not
declarable; whether a child's grant was within its parent's scope is the
grant issuer's check, not conformance's.

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
  (`--sampling-rate`, and `--assurance-sampling-rate` when the assurance
  stream is exported apart) and `run_binding: strict` once every run carries
  its own certificates.
- **The assurance stream as a pipeline** — a second exporter or sampler for
  the boundary spans with the `flow.*` / `dec.*` attributes and the
  `identifier` / `digest` attributes at `assurance_sampling_floor`; the
  engine only reads what the export holds and reports a `content` attribute
  found there.
- **Approvals and child runs reachable by digest and run id** (`--approvals`,
  `--runs-dir` are directory stand-ins, like `--dec-dir`).

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
