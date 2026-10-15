# The flowtrace coverage engine — normative specification

*Specification v0.1 — implemented by software 0.1.0 (2026-10-10). Implements
Flow-Based Telemetry Coverage v1.1 (`paper/flow-based-telemetry-coverage.md`,
"FTC"), §4.2–§4.8.*

*Revision 2026-10-11 (control-plane mechanics; no version bump, the software
stays 0.1.0 until tagged): the paragraphs tagged **[D11]**, **[H1]**, **[H3]**,
**[H4]**, **[D13]**, **[D14]** and **[D15]** below are the normative engine
rules for the FTC additions of the same date (the assurance stream and
attribute classes, the two-sided indicators, authorization coverage for
effect steps, hosted set-bounded methods, and the conformance readings for
degradation, attempts, authorization and cancellation). Each tag names the
unit the paragraph belongs to, so that a unit can be removed with its
paragraphs; untagged text is the 0.1.0 contract, unchanged. Where a tagged
paragraph names a field, finding or option the 0.1.0 software does not yet
have, the paragraph is the contract the next release implements.*

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

*2026-10-11:* the revision of the same date depends on the companion
revisions that add, in polydiagram, the optional descriptor fields
`outcomes`, `on_fail`, `effect`, `attempts`, `cancel_propagation_s`,
`max_decision_age_s`, attribute `class` and `assurance_sampling_floor` with
rules R12–R15, and, in agent-dec, the artifact kinds `authorization` and
`completion`, the `human_approval` attestation, the manifest fields
`outcome`, `termination`, `children[]` and `steps[].via`, verifier steps 1c
and 1d, and the trust-bundle classes `approvers[]` and
`policy_authorities[]`; the pins above are updated after those commits land
(pinned order: polydiagram → agent-dec → flowtrace). Bindings B14 and B17
are read by this engine as FTC §4.8 states.

Terms (*flow, step, segment, run, trigger, criticality, SLO, required
telemetry, debug scenario, answerability, coverage, conformance, authorized
plan, nondeterminism class, method, certificate, attestation, run
certificate*) carry the canonical meanings of the FTC Terminology section;
so do the terms added on 2026-10-11 (*outcome, degradation path, latch,
termination, gate, effect step, attempt, authorization evidence, completion
evidence, task grant, assurance stream*).

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
| **[D15]** Assurance-stream telemetry | adapter-specific; 0.1.0 adapters: a second OTLP/JSON export (`--assurance-telemetry`) | no | the assurance stream when it is exported separately from the sampled stream (§4.1); when absent, the one `--telemetry` export is both streams |
| **[D15] [H1] [H4]** Evidence artifacts | `kind: authorization` and `kind: completion` artifacts and `human_approval` attestations, `*.dec.json` under the same `--dec-dir` directories | when execution evidence is enabled and the flow declares effect steps | authorization coverage (§6.6) and the effect-step conformance readings (§7.5, §7.6) |
| **[H3]** Other runs' certificates | `--runs-dir <dir>` (one or more), run certificates of runs outside the window, found by `subject.run_id` | no | cancellation propagation across parent and child runs (§7.7); without it the rule is reported unchecked |

A **window** is the half-open interval `[start_ns, end_ns)` the adapter
reports as the extent of the telemetry it holds. A **run** is the set of
spans sharing a trace id (canon B3: `run_id` = trace id of the trigger span
unless `flow.run_id` is set). A step's **boundary span** in a run is a span
carrying `flow.step = <id>` whose parent is absent or carries a different
`flow.step`; interior spans inherit `flow.step` and are not boundaries. A
step executed more than once in a run (a `loop` iteration, a retry) has one
boundary span per execution.

**[H4]** For a step declared `effect: true`, the repeated boundary spans of
one run are its **attempts** and are read by §7.5, not as iterations and not
as a repeated step. **[D15]** The **assurance stream** of a flow is, in this
engine's model, the boundary spans of its declared steps with the `flow.*`
and `dec.*` attributes and the required attributes of class `identifier` or
`digest`, plus the required metrics; the **sampled stream** is everything the
`--telemetry` export holds. §4.1 states which stream each check reads.

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

2.4 **[D15] Assurance floor.** When the descriptor declares
`spec.telemetry.assurance_sampling_floor`, the tier's sampling floor is
satisfied by the assurance stream (FTC §4.4): the **effective assurance
floor** is the larger of the tier's floor and `assurance_sampling_floor`,
and the effective sampling floor of the sampled stream is the descriptor's
`sampling_floor` alone. The engine takes
`telemetry.assumed_assurance_sampling_rate` (default: the assumed sampling
rate) or `--assurance-sampling-rate`; a rate below the effective assurance
floor is the fail-class finding `assurance-sampling-below-floor`. A
descriptor whose `assurance_sampling_floor` is lower than its
`sampling_floor` is the fail-class finding
`assurance-floor-below-sampling-floor` (the assurance stream is drawn from
the sampled stream and cannot be retained more sparsely than it); the
companion validator's R15 rejects such a descriptor first
(`assurance_sampling_floor ∈ [sampling_floor, 1.0]`), so the engine's
finding is reached only by a descriptor loaded without validation. When the
descriptor declares no `assurance_sampling_floor`, 2.3 applies unchanged and
the two streams are one.

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

4.1 **[D15] Attribute classes and streams.** A `required_attributes[]` entry
is a name (as in `flow.spec/v0.2` before 2026-10-11 and in the v2.0.0 canon)
or an object `{name, class}` with `class ∈ {identifier, digest, content}`
(FTC §4.4). The class is declared, never inferred: on a flow that declares
`assurance_sampling_floor`, the companion validator's **R15** requires every
entry to be in object form with an explicit `class` (a name-only entry is a
validator finding there) and requires `assurance_sampling_floor ∈
[sampling_floor, 1.0]`; R15 does **not** forbid `content` attributes on any
flow. The engine resolves every entry to a class: a declared class as
declared; a name-only entry — which, after R15, occurs only on a flow that
declares no assurance stream (where stream placement is moot) or in a
descriptor that reached the engine without validation (§1: loaded with a
warning) — as `identifier`, recorded in the report as `class_assumed: true`
with the warn-class finding `attribute-class-assumed` once per flow
(`attribute_classes.warn_on_assumed`, default true); the `flow.*`
attributes as `identifier` and the `dec.*` attributes as `digest` whether or
not they are listed. The rule the engine enforces is FTC §4.4's: attributes
on the assurance stream are `identifier` or `digest`, never `content`.
Consequences:

- Every check of §4 except the `content` items reads the **assurance
  stream** (the `--assurance-telemetry` export when given, else the
  `--telemetry` export); a required attribute of class `content`, and every
  verification query of a scenario whose `required_data` names such an
  attribute (§5), reads the **sampled stream** (`--telemetry`). The report
  records per attribute its class, whether it was assumed, and the stream it
  was read from; the per-run completeness of a `content` attribute is
  computed over the sampled runs and joined to the assurance stream's runs by
  trace id, with a run absent from the sampled stream counted as *not
  evaluated* for that attribute rather than as missing.
- A `content`-class attribute found on a boundary span of the assurance
  stream export (when the two exports are distinct) is the warn-class
  finding `content-on-assurance-stream`, naming the attribute and the step:
  the pipeline carried content where the flow declared it would not. The
  engine does not inspect values; it matches declared names.
- `assurance_sampling_floor: 1.0` with any `content`-class required
  attribute is a valid flow (R15 permits `content` on every flow) and is
  accepted by this engine: the attribute is simply read from the sampled
  stream. What R15 does reject on such a flow — a name-only entry, or an
  assurance floor outside `[sampling_floor, 1.0]` — is a load error (§9)
  here as for every other validator rule.

With a single export and no declared `assurance_sampling_floor`, 4.1 changes
nothing but the class bookkeeping in the report.

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
ND0/ND1 steps for execution evidence — **[D15]** and, after 2026-10-11, no
steps declared `effect: true` either) is dropped and the remaining weights
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

**[D13] Hosted set-bounded methods.** A certificate whose `method.kind` is
`hosted` (ND1; `method.digest` is the configuration-record digest;
`evidence.type: configuration_record`, `replay: none`) is in the ND0/ND1
population and verifies on the same conditions as any other certificate;
the engine never attempts replay for any certificate and so needs no special
case beyond accepting the evidence type, and it reports the status
`verified` with `evidence_type: configuration_record` so the report shows
which evidence is attested by configuration provenance rather than
replayable.

6.6 **[D15] Authorization coverage for effect steps (binding B7, extended;
FTC §4.5).** When the flow declares steps with `effect: true`, the
execution-evidence component gains a second population: the effect steps.
For each effect step and each sampled run, the boundary span's
`dec.authz_cert_digest` **verifies** iff: an artifact with that digest and
`kind: authorization` is found under `--dec-dir`; agent-dec's verifier,
called as a library, accepts it — signature against a `policy_authorities[]`
key of the `dec-trust/0.2` bundle, its step-1d checks (issued before the
step's certificate in chain order, within the decision's validity window and
the flow's `max_decision_age_s`, and, where it cites a `human_approval`, that
attestation's checks) with no finding; its subject binds to the span's
`flow.id`, `flow.version`, `flow.step` and run (B3/B4, with the same
`run_binding` setting as 6.5); and its `decision` is `allow`. Statuses per
step: `verified, missing-span, missing-digest, artifact-not-found,
signature-invalid, flow-mismatch, run-binding-mismatch, authority-not-trusted,
denied, authorization-expired, authorization-stale, approval-invalid,
unverifiable`. `denied` (a verifying record with `decision: deny`, including
`reason: policy-unavailable`) counts as not covered and raises the
conformance finding of §7.6. The pooled score is
`(verified certificate instances + verified authorization instances) /
(runs × (|ND0/ND1 steps| + |effect steps|))`, a step in both populations
counting in both; the report carries the two populations' scores separately
as `certificate_coverage` and `authorization_coverage` beside the pooled
`execution_evidence`. The completion digest (`dec.completion_cert_digest`)
and the approval digest (`dec.approval_digest`) are resolved and reported
per step when present (`completion_status`, `approval_present`) and do not
enter the score in this revision; `scoring.execution_evidence.count_completion`
(default false) adds a third population, the effect steps' completion
evidence with `status ∈ {completed, reconciled}`, for operators who want it.

6.7 **[D11] Two-sided indicators: degradation rate and veto rate (FTC
§4.5).** For every flow that declares `outcomes` or any `on_fail`, the engine
reports two indicators over the window's runs, each with its band:

- `degradation_rate` = runs that took at least one declared `on_fail` edge /
  runs;
- `veto_rate` = runs whose outcome is `block` / runs.

The source per run is the run certificate's manifest when the run carries one
(§7.2: `steps[].via == on_fail` for the degradation rate; `manifest.outcome ==
block` for the veto rate; `source: manifest`); otherwise the boundary-span
sequence of the assurance stream (`source: spans`, reported as
`approximate: true`): a transition from step X to step Y counts as degraded
iff Y is X's `on_fail.to` and Y is not in X's `next`; a run whose last
boundary span is a step with `on_fail.outcome` and that has no successor span
counts as degraded, and as vetoed iff that outcome is `block`. Where
`on_fail.to` is also in `next` (the canon's `s5`), spans cannot distinguish
the paths and the run counts as not degraded with the note
`shared-target: <step>` in the indicator's detail; the manifest is the only
exact source. A band is `{min, max}` on `[0, 1]`, read from
`slis.<indicator>.band` in `flowtrace.yaml` with a per-flow override under
`slis.<indicator>.flows.<flow id>` (§10), or from the descriptor if a later
`flow.spec` version carries one (a descriptor band wins). A rate outside its
band is the finding `sli-out-of-band` (`{indicator, rate, band, direction:
above | below}`), warn class by default and fail class when the band
declares `gate: true`. The indicators are reported beside the score and do
not enter it; an alert in `alerts.yaml` with `slo: degradation_rate` or
`slo: veto_rate` makes the band's bounds detectability targets under §6.3
(`threshold` compared as ≤ `max` and ≥ `min`).

**[D14]** Because the companion validator's R14 (binding B12) admits only
ND0/ND1 steps as sources of an `on_fail` edge to `block`, the veto rate of a
valid flow measures deterministic gates only; the engine does not re-check
R14 and does not treat a generative step's `on_fail` to `review` or
`clarify` as a veto.

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
are not gated here — they are already completeness failures. *(2026-10-11:
the readings of 7.4–7.7 are divergent readings of a run and are gated by
the same rule, under the finding codes they name.)*

7.4 **[D11] Convergent degradation, latch, outcome and termination (binding
B9 as read here; FTC §4.8).** The run reading of 7.2 admits declared
`on_fail` edges: an entry reached from step X via X's `on_fail.to` is
**convergent** (the manifest says `via: on_fail`; from spans, the transition
is X's `on_fail.to` and the engine records `via: on_fail` itself); an entry
that follows an `on_fail` edge of a step is read against that target's
`next` from there on. **Divergent** readings added: `latched-reentry` — after
an `on_fail` edge with `latch: true`, any later entry for the source step or
for a step on the primary path between the source and the target;
`undeclared-outcome` — a manifest `outcome` not in the flow's `outcomes`
(the default list when the flow declares none); `undeclared-edge` — an
`on_fail` taken whose target is not the step's declared `on_fail` (from a
manifest `via: on_fail` entry whose predecessor declares a different target,
or none). A manifest `termination` of `cancelled` or `expired` reads
**convergent** when it is recorded (the steps after the last entry are
neither absent nor divergent: the run was stopped), subject to 7.6 for a
parent with children; `failed` reads as 7.2's failed run; a run whose
manifest has no `termination` is read as before 2026-10-11. A `loop` step's
`bound.on_exceed` in the `{to | outcome}` form is read as a degradation path
taken at iteration `max + 1`, with `fail` ≡ `outcome: error` and `flag` ≡
the 0.1.0 divergent reading. From spans alone, an `on_fail.outcome` edge
is read as the run ending at the source step (its declared successors are
not absent); the engine cannot see the outcome and records `outcome:
unknown`. The engine's reading and agent-dec's `conformance_reading` must
agree on these rules as on 7.2's; the test suite asserts it.

7.5 **[H4] Attempts of an effect step and reconciliation before retry
(binding B17 as read here; FTC §4.8).** For a step declared `effect: true`,
repeated entries of the step in one run — manifest entries sharing
`subject.idempotency_key_commitment` with `attempt_id` 1, 2, …, or, from
spans, repeated boundary spans of the step — are **attempts** and collapse
into the one declared step for every reading of 7.2 and 7.4: the step is
present once, its order is that of its first attempt, and the repeat is not
a divergent repetition. More attempts than `attempts.max` is read as the
step's `on_exceed` taken (7.4) at attempt `max + 1`, or, when the
`attempts` block declares no `on_exceed`, as the divergent finding
`attempts-over-bound` (`{step, attempts_seen, max}`); a flow that declares
`effect: true` without `attempts` has no bound and the collapse still
applies. With certificates, the engine reads agent-dec's step-1d result for
B17: an attempt with `attempt_id > 1` whose previous attempt's completion
evidence is absent or has `status: unknown` is the divergent finding
`retry-without-reconciliation` (`{step, attempt_id}`); the engine never
re-derives the chain itself. From spans alone the attempts collapse and the
finding is reported `unchecked`. Per effect step the report carries
`attempts: {runs_with_retries, max_attempts_seen, over_bound, unreconciled}`.
Different runs' attempts are never pooled: an idempotency key is scoped to
the run that committed to it.

7.6 **[H1] Effect steps without authorization evidence (binding B10 as read
here; FTC §4.8).** With certificates, an effect step whose step certificate
is not preceded in the chain by a `kind: authorization` artifact for the
same `idempotency_key_commitment` and `attempt_id`, or whose authorization
evidence has `decision: deny`, is the divergent finding
`effect-without-authorization` (`{step, attempt_id, reason: missing |
denied}`), taken from agent-dec's step-1d result. From spans alone a
boundary span without `dec.authz_cert_digest` is the §6.6 status
`missing-digest` and the finding is reported `unchecked`. The engine records
the finding; it has no path by which to prevent the step, and this
specification describes none.

7.7 **[H3] Cancellation propagation across runs (binding B14; FTC §4.8).**
For a run whose manifest has `termination: cancelled` and a non-empty
`children[]`, the engine resolves every child's run certificate — in
`--dec-dir`, then in each `--runs-dir`, by `subject.run_id` — and the run is
**convergent** iff every child's manifest has `termination ∈ {cancelled,
completed}` and `issued_at ≤ parent.cancelled_at + cancel_propagation_s`
(the parent's cancellation instant is its manifest's `terminated_at`, or
its run certificate's `issued_at` when absent — `terminated_at` being the
companion run manifest's optional instant at which the run's `termination`
state was reached; the flow's `cancel_propagation_s`, or
`conformance.cancel_propagation_s` from §10 when the flow declares none). Otherwise the divergent finding
`cancellation-not-propagated` (`{parent_run_id, child_run_id, reason:
not-terminated | late | certificate-not-found}`) is attributed to the parent
run; `certificate-not-found` is reported `unchecked` rather than divergent
when no `--runs-dir` was given. A child with `termination: expired` or
`failed` is `not-terminated` for this rule (B14 names `cancelled` and
`completed` only). The rule is checked one level deep per run and applied to
every run in the window, so a grandchild is checked when its parent is in
the window or in `--runs-dir`. The engine compares termination and timing
only; it never reads a grant's contents (it sees `task_grant_commitment`,
a digest) and makes no statement about scope.

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

*2026-10-11 additions to the per-flow entry (the report schema gains them as
optional keys under the same `flowtrace.report/v0.1`; a report without them
still validates):* **[D15]** `streams` (`{assurance: {source, assumed_rate,
effective_floor}, sampled: {source, assumed_rate, effective_floor}}`) and,
per required attribute, `{class, class_assumed, stream}`; under the
execution-evidence component, `certificate_coverage`,
`authorization_coverage` and the per-effect-step authorization statuses of
§6.6 with `completion_status` and `approval_present`; **[D13]**
`evidence_type` per certificate status; **[D11]** `slis` (`{degradation_rate,
veto_rate}`, each `{rate, band, source, approximate, runs, degraded_runs |
vetoed_runs, notes[]}`); **[D11] [H4] [H1] [H3]** under the conformance
readings, per run `via` per entry, `outcome`, `termination`, the
`attempts` block of §7.5 per effect step, and the cross-run block of §7.7
(`{children_checked, children_unresolved}`); and the new finding codes of
§9. The sorted-keys and trailing-newline rules are unchanged, so
`examples/expected/` is regenerated once (the three new synthetic windows
`quote-issue.s5-degraded`, `quote-issue.s6-unknown-reconciled` and
`quote-issue.s6-retry-unreconciled` are added at the same time).

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

*2026-10-11 finding codes.* Fail class: **[D15]**
`assurance-sampling-below-floor`, `assurance-floor-below-sampling-floor`;
**[D11]** `sli-out-of-band` when the band declares `gate: true` (warn class
otherwise). Divergent run readings, which fail a tier that requires
convergence and warn otherwise, exactly as `non-convergent-runs`: **[D11]**
`latched-reentry`, `undeclared-outcome`, `undeclared-edge`; **[H4]**
`retry-without-reconciliation`, `attempts-over-bound` (when `on_exceed` names
no step or outcome that absorbs it); **[H1]** `effect-without-authorization`;
**[H3]** `cancellation-not-propagated`. Warn class only: **[D15]**
`attribute-class-assumed`, `content-on-assurance-stream`. A reading reported
`unchecked` (§7.5–§7.7 without the evidence they need) is neither a finding
nor a pass; it is listed under `conformance.summary.unchecked` so that a
green gate cannot be mistaken for a checked rule. Load errors (exit 2) gain:
**[H3]** a `--runs-dir` that does not exist; **[D15]** an
`--assurance-telemetry` export whose window does not overlap `--telemetry`'s.

## 10. Configuration (`flowtrace.config/v0.1`)

The shipped `flowtrace.yaml` is the complete default; a user file is merged
over it key by key (`apiVersion` must match). Every constant cites the FTC
section it comes from in a comment. Weights MUST sum to 1 in both sets;
every tier MUST be present; the engine refuses a configuration that violates
either.

*2026-10-11 keys (all optional; the shipped file carries the defaults
shown):* **[D15]** `telemetry.assumed_assurance_sampling_rate` (default:
`assumed_sampling_rate`); `attribute_classes.warn_on_assumed` (default
`true`); `attribute_classes.namespace_defaults` (default `{flow.*:
identifier, dec.*: digest}`); `scoring.execution_evidence.count_completion`
(default `false`). **[D11]** `slis.degradation_rate.band` and
`slis.veto_rate.band` (default `{min: 0.0, max: 1.0, gate: false}`, the
whole range, so that nothing fires until an operator declares a band), each
with `flows.<flow id>.band` overrides. **[H3]**
`conformance.cancel_propagation_s` (default `30`, used only when the flow
declares none). The weights of §6.1 are unchanged; authorization coverage
is pooled into `execution_evidence` and adds no weight.

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
- **[D15]** FTC §4.4 discloses attribute classes and the assurance stream;
  on a flow that declares one the class is always explicit (validator R15),
  and FTC says a realization reports an assumed class where a name-only
  entry can still occur (no assurance stream declared; unvalidated
  descriptor); §4.1 makes the assumption explicit (`identifier`) and the
  report mandatory. FTC §4.4's statement that the tier's sampling parameter
  is satisfied by the assurance stream is §2.4.
- **[D11]** FTC §4.5 says the band is declared "in the flow specification
  where the schema carries it, or in the coverage engine's configuration";
  `flow.spec/v0.2` carries no band as of 2026-10-11, so §6.7 reads it from
  `flowtrace.yaml` and defines precedence for a future descriptor field.
- **[D15] [H1] [H3] [H4]** FTC §4.5 and §4.8 describe what a realization
  reads "from spans alone" and what it reports as unchecked; §6.6 and
  §7.5–§7.7 fix the statuses. Everything that needs a certificate chain is
  taken from agent-dec's verifier called as a library (step 1d results);
  this engine never re-implements chain, signature or evidence-order
  checks.
- **[D14]** FTC §4.5 cites gate authority (binding B12) as a validator rule
  of the companion schema; this engine relies on it (§6.7) and does not
  enforce it.
