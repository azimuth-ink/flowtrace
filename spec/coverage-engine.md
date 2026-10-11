# The flowtrace coverage engine — normative specification

*Specification v0.1 — implemented by software 0.1.0 (2026-10-10). Implements
Flow-Based Telemetry Coverage v1.1 (`paper/flow-based-telemetry-coverage.md`,
"FTC"), §4.2–§4.8.*

This document is normative for the engine: where the paper says *may* and
*for example*, this document says what the shipped engine does, with the
constants it ships as defaults. The paper is the disclosure; this document is
the contract an implementation of the engine (or a replacement adapter) must
honor. Where the two differ in wording, the paper governs the method and
this document governs the engine. The key words MUST, SHOULD and MAY are to
be read as in RFC 2119.

The engine is built **on** the companion specifications and redefines none of
them:

| Artifact | Owner | Pin consumed by 0.1.0 |
|---|---|---|
| Flow descriptor (`flow.spec/v0.2`), rules R1–R11, the `quote-issue` canon | azimuth-ink/polydiagram | `9345577` (software 0.3.0) |
| Step / run certificates (`dec_version` 0.2), trust bundles (`dec-trust/0.2`), the verifier | azimuth-ink/agent-dec | `e8075f9` (software 0.2.0) |
| Terminology, attribute namespace, bindings B1–B7 | the shared canon, reproduced in FTC v1.1 "Terminology" and §4.7 | — |

Terms (*flow, step, segment, run, trigger, criticality, SLO, required
telemetry, debug scenario, answerability, coverage, conformance, authorized
plan, nondeterminism class, method, certificate, attestation, run
certificate*) carry the canonical meanings of the FTC Terminology section.

---

## 1. Inputs

| Input | Format | Required | Role |
|---|---|---|---|
| Flow descriptors | `*.flow.yaml`, `flow.spec/v0.2` | yes | the declared flows; validated with polydiagram's validator (R1–R11) when it is installed, loaded with a warning otherwise |
| Telemetry | adapter-specific; 0.1.0: OTLP/JSON export files (§5.3) | yes | the evaluation window |
| Configuration | `flowtrace.yaml` (`flowtrace.config/v0.1`) | no | every tunable constant; the shipped file is the default and a user file is merged over it |
| Alerts | `alerts.yaml` (`flowtrace.alerts/v0.1`, §6.3) | no | breach detectability; without it every target is undetectable |
| Query bindings | `flowtrace.queries/v0.1` (`spec/schemas/verification-query.schema.json`) | no | executable verification queries for scenarios whose descriptor carries a placeholder or a dialect the adapter does not execute |
| Certificates + trust bundle | `*.dec.json` under one or more directories; `dec-trust/0.x` | when execution evidence is enabled | binding B7 (§6.5) and the manifest input to conformance (B6, §7) |
| Baseline | a previous `coverage-report.json` | no | deltas for review comments (§9) |

A **window** is the half-open interval `[start_ns, end_ns)` the adapter
reports as the extent of the telemetry it holds. A **run** is the set of
spans sharing a trace id (canon B3: `run_id` = trace id of the trigger span
unless `flow.run_id` is set). A step's **boundary span** in a run is a span
carrying `flow.step = <id>` whose parent is absent or carries a different
`flow.step`; interior spans inherit `flow.step` and are not boundaries. A
step executed more than once in a run (a `loop` iteration, a retry) has one
boundary span per execution.

## 2. Tiering (FTC §4.2)

2.1 **Tier.** A flow's tier is `metadata.criticality` (`P0..P3`). The
deprecated values `tier-1 | tier-2 | tier-3` map to `P0 | P1 | P2` and the
FTC v1.0 words `critical | high | medium | low` map to `P0 | P1 | P2 | P3`;
both are accepted with a warning through every `flow.spec/v0.x` version and
never emitted (canon resolution C). A step's own `criticality` overrides the
flow's for decomposition and for per-step policy; a step without one inherits
the flow's.

2.2 **Derivation.** When a tier is derived rather than declared (`flowtrace
tier`), the criticality score is the weighted sum of bounded business-impact
dimensions (`criticality_score.dimensions`, weights summing to 1; values are
scale words `critical | high | medium | low` → 10 | 7 | 4 | 1, or numbers on
0..10); any dimension at its maximum forces P0; otherwise the tier is the
highest whose `score_min` the score reaches. A declared
`metadata.criticality` always wins over a derived one.

2.3 **Policy table (defaults; `tiers` in flowtrace.yaml).**

| Tier | score_min | Coverage threshold | Sampling floor | Alert latency | IR SLA | Requires convergence | Requires answerability block |
|---|---:|---:|---:|---:|---:|---|---|
| P0 | 7.0 | 1.00 | 1.00 (always) | 60 s | 15 min | yes | yes |
| P1 | 5.0 | 0.90 | 0.80 | 5 min | 1 h | no | no |
| P2 | 3.0 | 0.75 | 0.50 | 15 min | 4 h | no | no |
| P3 | 0.0 | 0.50 | 0.10 | 1 h | next business day (`null`) | no | no |

The effective sampling floor of a flow is the larger of the tier's floor and
the descriptor's `spec.telemetry.sampling_floor`. The engine cannot measure
the effective sampling rate from an export alone; it takes
`telemetry.assumed_sampling_rate` (default 1.0, an export is assumed
complete) or `--sampling-rate`, and a rate below the floor is a fail-class
finding (`sampling-below-floor`).

## 3. Decomposition (FTC §4.3, restated over steps)

3.1 **Groups.** Steps are partitioned into a serial group and a parallel
group; the successors of a `fanout` step form the parallel group. The
**synchronous frontier** is the document-order prefix of steps up to the
first `kind: async` step; the **asynchronous tail** is the rest. The flow's
`latency_p95_ms` (trigger → synchronous frontier) is decomposed across the
frontier at p95; `async_completion_p99_s` (trigger → last step) is decomposed
across the tail at p99 after reserving the frontier's p99 contribution
(observed when history exists, else the sum of the frontier's derived p99
allocations).

3.2 **Latency algorithm** (`decompose.allocate_latency`; constants from
`decomposition`):

1. serial: `flow_target ≥ Σ step`; parallel: `flow_target ≥ max step`.
2. `available = target − max(history over the parallel group)`.
3. serial `base_i = available × hist_i / Σ hist_serial`; a parallel step's base is its own history.
4. `× criticality_factor(crit_i)` — defaults P0 0.8, P1 0.9, P2 1.0, P3 1.2, using the step's own criticality where declared, the flow's otherwise.
4b. `× nd_factor(nd_class_i)` — defaults ND0 0.9, ND1 1.0, ND2 1.1, ND3 1.25, undeclared 1.0.
5. `× safety_margin` — default 0.9.
6. error budget: `flow_error_budget × error_factor(crit_i) / n` over the steps of the group — defaults P0 0.5, P1 0.75, P2 1.0, P3 1.5.
7. if `Σ serial + max parallel > target`, every allocation is scaled by `target / (Σ serial + max parallel)`; the factor is recorded as `scale`.
8. the other percentile is approximated: `p95 ≈ 0.7 × p99` (`p95_from_p99`), and the inverse.

An **asserted** per-step SLO (`steps[].slo`) takes precedence over the derived
value; the difference remains headroom. The report records base, each factor,
the pre-scale and allocated values, the asserted value and the effective one.

3.3 **Availability.** Over n serial steps, `base = A^(1/n)`; a step's
requirement is `100 − (100 − base) × min(1, criticality_factor)` (higher
criticality tightens; a factor above 1 is clamped so the product constraint
always holds), capped at `availability_ceiling` (99.99) unless the base
itself exceeds the ceiling, in which case the base stands. The product of
per-step availabilities is therefore never below the flow target.

3.4 **History and cold start.** The engine's history is the window itself:
the observed p95 / p99 of each step's boundary-span durations. When a step
has no observation, or the window holds fewer than
`decomposition.cold_start.min_sample_runs` runs (default 30), the cold-start
embodiment applies and the mode is recorded on the result
(`cold-start:equal_split` — the default strategy; `criticality_weighted`,
share ∝ criticality factor; `declared_prior`, asserted shares passed to the
allocator). The parallel group, whose history is then unknown, takes one
slot beside the serial steps so that `Σ serial + max parallel` fills the
target exactly before factors. The transition from cold start to history is
visible in the report (`mode`, `sample_runs`, `min_sample_runs`) so that
trends are not misread across it.

3.5 **Segments.** 0.1.0 does not model a separate segment (edge) term: each
hop's latency is counted inside the step that receives it — one of the two
treatments FTC §4.3 discloses. A later version MAY add optional segment terms
without changing the step allocation above.

## 4. Completeness (FTC §4.5, first component; the minimal completeness check)

A step is **observable in a run** iff:

- (B2, the minimal completeness check) it has a boundary span whose
  `flow.id`, `flow.version` and `flow.step` are present, with `flow.version`
  equal to the declared version; and
- for every `required_telemetry.traces[]` entry, a span of the run carrying
  `flow.step = <id>` has that `span_name` and every `required_attributes[]`
  key present and non-empty (any span of the step may satisfy an attribute);
  and
- for every `required_telemetry.metrics[]` entry, a metric data point of that
  name exists in the window with `flow.id` and `flow.step` labels for the
  step (metrics are aggregated, so this is a window-level check applied to
  every run); and
- for every `required_telemetry.logs[]` entry, a log record exists in the
  window with `flow.id` / `flow.step` attributes for the step and the
  declared `level`.

A run is **complete** iff every declared step is observable in it. The
component's score is `complete runs / sampled runs` (0 with no runs). The
report carries per step the number of runs in which it was present and
complete, the fraction, and every missing item with its count. A step present
in no run is a **named blind spot** (`blind-spot`, fail class).

## 5. Answerability (FTC §4.4) — the verification-query contract

5.1 **Resolved query.** For each `debug_scenarios[]` entry of each step the
engine resolves one query object `{dialect, text, expected_shape}`:

1. a query **binding** (`--queries`, `flowtrace.queries/v0.1`) whose
   `(flow, step, scenario | index)` matches, if any; else
2. the descriptor's `verification_query` as `text`, its `dialect` (default
   `otel-sql`), its `expected_shape` (default `{min_rows: 1}`).

A `text` of the form `<…>` is a **placeholder** (natural-language intent, as
in the canonical descriptor) and is never executed.

5.2 **Expected shape.** `{min_rows: integer ≥ 0 (default 1),
required_columns: [name…]}`. The check passes iff the result has at least
`min_rows` rows and every required column name is among the result's
columns. Nothing else about the result is interpreted.

5.3 **Statuses.** `answerable` (executed, shape satisfied); `unanswerable`
(executed, shape not satisfied, or the backend rejected the query);
`not_evaluated` (an unbound placeholder, or a dialect the adapter does not
execute). The score is `answerable / declared`; `not_evaluated` counts in the
denominator and contributes zero (FTC §4.4: never reported as answerable).
A flow with no scenarios scores 0 if its tier requires the answerability
block (P0 by default, with the fail-class finding
`answerability-block-missing`) and is otherwise *not applicable* (§6.2).

5.4 **Adapter conformance.** An adapter (a module implementing
`flowtrace.adapters.base.Adapter`) is conformant iff it: declares the
dialects it executes (`dialects`); for a dialect it declares, executes
`query(dialect, text, window)` and returns the result's column names and
rows; raises `UnsupportedDialect` for any other dialect; serves
`list_spans`, `list_metrics` and `list_logs` for a flow over a window with
the canonical attribute names, mapping the deprecated aliases
`flow.segment.id → flow.step` and `flow.priority → flow.criticality` on
ingest with a warning; and reports its extent. Adding a backend (Tempo /
TraceQL, PromQL, Datadog, …) is implementing this protocol; the engine does
not change.

5.5 **The `otel-sql` dialect (reference adapter `otlp_duckdb`).** Input: a
`.jsonl` file of OTLP/JSON export requests, one per line
(`ExportTraceServiceRequest` / `ExportMetricsServiceRequest` /
`ExportLogsServiceRequest`, the shape the Collector `file` exporter writes;
lowerCamelCase field names; enums as integers or proto names). A query is a
single SELECT over:

```
spans(trace_id, span_id, parent_span_id, name, service_name, kind, start_ns, end_ns,
      duration_ms, status, attributes MAP(VARCHAR, VARCHAR), resource MAP(VARCHAR, VARCHAR))
metrics(name, type, time_ns, attributes MAP(VARCHAR, VARCHAR), value, count, sum)
logs(time_ns, severity, body, attributes MAP(VARCHAR, VARCHAR), trace_id, span_id)
eval_window(start_ns, end_ns)                       -- one row: the window
```

Attribute values are strings (`attributes['cost.usd']::DOUBLE` to cast);
`attributes['k']` is NULL when the key is absent; `kind` is
`SERVER | CLIENT | INTERNAL | PRODUCER | CONSUMER | UNSPECIFIED`; `status` is
`OK | ERROR | UNSET`.

## 6. Scoring (FTC §4.5)

6.1 **Components and default weights** (`scoring` in flowtrace.yaml; the
paper calls them illustrative, canon resolution E makes them the engine's
defaults):

| Component | Definition | Weight | Weight with execution evidence |
|---|---|---:|---:|
| completeness | §4 | 0.40 | 0.35 |
| answerability | §5 | 0.30 | 0.25 |
| detectability | §6.3 | 0.20 | 0.20 |
| cost_attribution | §6.4 | 0.10 | 0.10 |
| execution_evidence | §6.5 (optional; `scoring.execution_evidence.enabled` or `--execution-evidence`) | — | 0.10 |

6.2 **Applicability.** Every component reports `applicable`. A component that
is not applicable to a flow (no SLO targets at all for detectability; no
`debug_scenarios` for answerability on a tier that does not require them; no
ND0/ND1 steps for execution evidence) is dropped and the remaining weights
are renormalized to sum to 1; the effective weights are recorded in the
report. A component the tier requires is always applicable and scores 0 when
its inputs are missing. The flow's score is the weighted sum, rounded to six
decimals, compared with the tier's coverage threshold (§2.3).

6.3 **Breach detectability.** The **targets** are the flow-level SLO keys
present in `spec.slos` (`latency_p95_ms`, `async_completion_p99_s`,
`availability`) and every asserted per-step key in `latency_p95_ms,
latency_p99_ms, error_rate_percent, availability`. Derived SLOs (§3) are
reported, not gated. For each target the engine computes the observed value
over the window (frontier latency from the trigger span's start to the last
frontier boundary span's end; async completion to the last boundary span's
end; availability as the fraction of runs with no `ERROR` boundary span;
per-step percentiles of boundary-span durations; per-step error rate) and
whether it is **breached** (observed above a latency / error target, below an
availability target). An alert entry of `alerts.yaml`

```yaml
apiVersion: flowtrace.alerts/v0.1
alerts:
  - id: <string>          # optional
    flow: <flow id>
    scope: flow | step    # default: step if `step` is given, else flow
    step: <step id>       # scope step
    slo: <SLO key>
    threshold: <number>   # same unit as the SLO key
    evaluation_window_s: <seconds>
    notification_latency_s: <seconds>
```

**covers** a target when `flow`, `scope`/`step` and `slo` match. A target is
**detectable** iff an alert covers it, the alert's threshold is at least as
tight as the target (≤ for latency and error rate, ≥ for availability),
`evaluation_window_s + notification_latency_s` is within the tier's alert
latency bound, and — when the window holds a breach — the alert would have
fired on the observed value. The score is `detectable / targets`; with no
alert configuration every target is undetectable.

6.4 **Cost attribution.** A step is **attributable** iff at least one of its
boundary spans in the window carries one of `cost.attributes` (defaults
`cost.usd, cost.tokens, llm.usage.total_tokens, gen_ai.usage.total_tokens`).
The score is `attributable steps / steps`; the flow is attributable iff every
step is. The report lists the attributes seen per step and, where `cost.usd`
is present, its sum.

6.5 **Execution-evidence coverage (binding B7).** The population is the
steps declared `nd_class: ND0 | ND1`. For each such step and each sampled
run, the boundary span's `dec.step_cert_digest` **verifies** iff: a step
certificate with that digest (agent-dec's `cert_digest`: sha256 over the RFC
8785 canonical bytes of the signed certificate) is found under `--dec-dir`;
its signature verifies against the issuer's trust bundle (agent-dec's
resolver and `verify_signature`, called as a library — the engine does not
reimplement verification; key status and validity window apply); its
`subject.flow = {id, version, step}` equals the span's `flow.id`,
`flow.version`, `flow.step` and `subject.step_id` equals the step (B7, FTC
§4.7); and its class is ND0 or ND1 (an attestation is not execution
evidence). The score is `verified / (runs × |population|)`. Statuses are
reported per step (`verified, missing-span, missing-digest,
certificate-not-found, signature-invalid, flow-mismatch, class-mismatch,
run-binding-mismatch, unverifiable`).

**Run binding.** A verified certificate whose `subject.run_id` is neither the
span's trace id nor its `flow.run_id` (B3/B4) is `run-binding-mismatch`.
Under `scoring.execution_evidence.run_binding: warn` (default) it still
counts as evidence — B7 as the paper states it is satisfied — and the
mismatch is reported (`evidence-run-binding`, warn class); under `strict` it
does not count. `strict` is RECOMMENDED for production; the default is
`warn` because the shipped example reuses the one signed run of agent-dec's
example across synthetic runs (signed artifacts are never minted by hand).

## 7. Conformance (FTC §4.8, PD §5; bindings B6, B7)

7.1 **Window reading.** The declared step set versus the set of steps
observed in the window (boundary spans grouped by `flow.id` / `flow.step`):
**absent** = declared, unobserved (a completeness failure by another name);
**divergent** = observed, undeclared (off-plan); **convergent** otherwise. A
window with no runs reads absent.

7.2 **Run reading (the authorized plan).** Per run, the realized step DAG is
compared with the declared graph (`next`, with the sequential default;
`choice` branches; `loop` back-edges and bounds). The input is, per B6, the
run certificate's `manifest.steps[]` when the run carries one — found through
`dec.run_cert_digest` on the trigger span or `subject.run_id` equal to the
trace id (or `flow.run_id`); a referenced certificate that binds a different
run, a run id claimed by several distinct certificates with none named on the
trigger span, or a run certificate whose signature does not verify against
the trust bundle is rejected and noted (`conformance.summary.notes`) — and
the run's boundary spans in start order otherwise. The rules are agent-dec's reading of a manifest (its
`conformance_reading`, used when installed; `flowtrace.conformance._reading`
implements the same rules and the test suite asserts agreement): an entry
naming no declared step (or unbound) is **off-plan**; a step repeated without
a `loop` step on its cycle, or a declared order violated, is **divergent**; a
`loop` step iterated more than `bound.max` is **divergent** under
`on_exceed: flag` and a **failed-run** under `on_exceed: fail`; a declared
step on the taken path with no entry is **absent**; **convergent** otherwise.

7.3 **Gate consequences.** Off-plan steps in the window and runs reading
divergent or failed are fail-class findings for a tier with
`require_convergent` (P0 by default) and warnings otherwise. Absent findings
are not gated here — they are already completeness failures.

## 8. Report format (`flowtrace.report/v0.1`)

`coverage-report.json` MUST validate against
`spec/schemas/coverage-report.schema.json`. Top level: the engine version and
report schema; `generated_at`; `inputs` (paths, the sha256 of every telemetry
file, the adapter and its dialects, and `flows_commit`, the git HEAD of the
flow set when it lives in a repository — PD §5's "what did we know and
when"); the `window` with its counts; ingest warnings; one entry per flow;
the overall verdict and exit code. Per flow: id, version, criticality, the
descriptor's file name and sha256, the tier policy applied, runs and spans
sampled, the effective sampling rate, score, threshold, verdict and reasons,
the effective weights, every component with its per-step detail (named blind
spots; failing scenarios with reasons; targets with observed values and
alerts; attributable steps; evidence statuses), the decomposition (§3), the
conformance readings (§7), the observed SLO values, the findings
(`{code, severity: fail | warn, message, step?}`), and the delta block when a
baseline was given. Keys are sorted and the file ends with a newline, so two
runs over the same inputs produce identical bytes; `--reproducible`
additionally nulls `generated_at` and `flows_commit` and stores input paths
as basenames, which is how `examples/expected/` is produced.

## 9. Gate semantics (FTC §4.6)

`flowtrace gate` evaluates every flow in `--flows` over the window and exits
**0** iff every flow passes, **1** iff any flow fails, **2** on a usage or
load error (a descriptor that fails polydiagram's validation; execution
evidence enabled without `--trust-bundle` and `--dec-dir`; a missing input).
A flow **fails** iff its score is below its tier's coverage threshold or any
fail-class finding is present: `blind-spot`, `sampling-below-floor`,
`answerability-block-missing` (tier requires it), `off-plan-steps` and
`non-convergent-runs` (tier requires convergence), and, with a baseline,
`tier-threshold-regression` (the baseline was at or above the threshold and
this report is below it). With `--baseline` the gate prints and records the
score delta and per-component deltas; a decrease that stays above the
threshold is the warning `score-decreased`. Warnings never change the exit
code.

## 10. Configuration (`flowtrace.config/v0.1`)

The shipped `flowtrace.yaml` is the complete default; a user file is merged
over it key by key (`apiVersion` must match). Every constant cites the FTC
section it comes from in a comment. Weights MUST sum to 1 in both sets;
every tier MUST be present; the engine refuses a configuration that violates
either.

## 11. Relationship to the paper and the canon

- FTC §4.5 states the components and weights as illustrative; §6.1 ships
  them as defaults (canon resolution E).
- FTC §4.3's worked example is reproduced by `decompose.allocate_latency`
  (tests/test_decompose.py) to the millisecond; the engine's history is the
  window rather than a separate store (§3.4), a choice of input, not of
  algorithm.
- FTC §4.4's structured form `expects: {rows: ">= 1", columns: […]}` is the
  paper's illustration; the engine's contract is `expected_shape:
  {min_rows, required_columns[]}`, the field names `flow.spec/v0.2` carries
  (`dialect`, `expected_shape`). The binding file (§5.1) exists because the
  canonical descriptor's query is a placeholder and the descriptor is
  byte-identical across the three repositories.
- FTC §4.8 lists absent, divergent and the loop bounds; the engine adds the
  reporting detail of §7 and reads the manifest as the realized DAG per B6.
- Canon §2.1's deprecated aliases are accepted on ingest (§5.4) and never
  emitted; the report and the adapters emit only canonical names.
