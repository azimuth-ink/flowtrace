# Changelog

All notable changes to this repository are documented here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the software
follows [Semantic Versioning](https://semver.org/). The paper version (FTC
v1.x), the specification versions this software consumes (`flow.spec/v0.x`
from polydiagram, `dec_version` from agent-dec) and the formats this
software owns (`flowtrace.report/v0.x`, `flowtrace.config/v0.x`,
`flowtrace.alerts/v0.x`, `flowtrace.queries/v0.x`) are tracked in the entries
that change them — see the README's "Versioning" section.

## [Unreleased]

## [0.1.0] — 2026-10-10

First release: the coverage engine the FTC paper discloses, implementing
FTC v1.1 §4.2–§4.8 on top of `flow.spec/v0.2` (polydiagram 0.3.0,
`azimuth-ink/polydiagram@9345577`) and DEC v0.2 (agent-dec 0.2.0,
`azimuth-ink/agent-dec@e8075f9`). Accompanies paper v1.1 (`paper/`, CC0).

### Added
- `spec/coverage-engine.md` (normative): tier policy table as defaults, the decomposition algorithm restated over steps with the nondeterminism factor and the cold-start embodiment, the verification-query contract `{dialect, text, expected_shape{min_rows, required_columns[]}}`, scoring components / default weights / tier thresholds (shared-canon resolution E), the report format, gate semantics and the conformance reading.
- `spec/schemas/coverage-report.schema.json` (`flowtrace.report/v0.1`) and `spec/schemas/verification-query.schema.json` (`flowtrace.queries/v0.1`).
- `flowtrace.yaml`: every constant the paper calls illustrative, as a shipped default with a comment citing its FTC section.
- `flowtrace.tiering` (§4.2), `flowtrace.decompose` (§4.3; pure, property-tested with hypothesis), `flowtrace.answerability` (§4.4), `flowtrace.coverage` (§4.5 — completeness, answerability, breach detectability, cost attribution, execution-evidence coverage per binding B7 using agent-dec's verifier as a library), `flowtrace.conformance` (§4.8 — window and per-run readings, run-certificate manifest as the realized DAG per binding B6, loop bounds per `on_exceed`), `flowtrace.gate` (§4.6) and the `flowtrace` CLI (`gate`, `decompose`, `tier`, `conformance`, `validate-report`).
- Adapter protocol (`flowtrace.adapters.base`) and the reference adapter `otlp_duckdb`: OTLP/JSON export files (the Collector `file` exporter shape) into DuckDB; dialect `otel-sql` over `spans` / `metrics` / `logs` views with attributes as `MAP(VARCHAR, VARCHAR)`; deprecated `flow.segment.id` / `flow.priority` mapped on ingest with a warning (resolution C).
- Inputs the paper leaves to the deployment, given minimal formats: `alerts.yaml` (`flowtrace.alerts/v0.1`) for breach detectability; query bindings (`flowtrace.queries/v0.1`) so a descriptor whose `verification_query` is a placeholder — the canonical `quote-issue` descriptor is one — can be evaluated without editing it.
- `examples/flows/quote-issue.flow.yaml`: the canonical descriptor, byte-identical to canon §3, the paper, polydiagram and agent-dec; `examples/dec/`: agent-dec's signed flow-bound run copied verbatim plus a `dec-trust/0.2` bundle built from its issuer key; `examples/telemetry/`: three seeded synthetic windows (full, s5-silent, s4-missing-attr) from `tools/make_synthetic_telemetry.py`, carrying the real step-certificate digests; `examples/expected/`: the reports the gate must reproduce byte for byte.
- `.github/workflows/gate.yml`: pytest on Python 3.10 / 3.12, polydiagram validation of the flows, agent-dec verification of the flow-bound example against flowtrace's flows as registry, the gate over the three windows with execution evidence enabled and the expected reports asserted (the `three-repo` job); a weekly scheduled variant.
- `Makefile` (`make dev` installs the companions from sibling checkouts until the pinned refs are pushed; `make check` runs what CI runs).

### Decisions recorded
- Execution evidence is off by default (`scoring.execution_evidence.enabled: false`; the paper calls the component optional) and on with `--execution-evidence`; when on, `--trust-bundle` and `--dec-dir` are required.
- `scoring.execution_evidence.run_binding: warn` by default: B7 (trust-bundle verification + `subject.flow` match) decides the score; a certificate that does not bind to the span's run (`subject.run_id != trace id`) is reported, and `strict` makes it fail. The shipped example reuses the one signed run across synthetic runs, so `strict` would score 1/32 there.
- A not-evaluated scenario (placeholder with no binding, or a dialect the adapter does not execute) scores zero, like an unanswerable one, so a P0 flow cannot pass with unevaluable scenarios.
- Components that are not applicable to a flow are dropped and the remaining weights renormalized; a component the tier requires (answerability for P0) is always applicable.
- Segment (edge) terms are not modeled separately in 0.1.0: each hop's latency is counted inside the receiving step (one of the two treatments FTC §4.3 discloses).
