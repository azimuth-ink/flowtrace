# Flow-Based Telemetry Coverage: A Method for Measuring and Governing Observability by Business-Flow Consequence

**Jeff Gray** — Affiliation: Independent. ORCID: `0009-0005-6796-6576`. Correspondence: `jeff@azimuth.ink`.

*Defensive Publication · Version 1.1 · October 10, 2026*

> **Purpose of this document.** This is a *defensive publication*. It discloses the methods below in sufficient detail to enable a person of ordinary skill in observability and site-reliability engineering to implement them, for the explicit purpose of placing this subject matter in the public domain as prior art. It is deliberately broad: it enumerates not only a preferred embodiment but a wide range of variations, so that the disclosed concepts and their obvious variants cannot subsequently be patented by any party. Version 1.1 adds disclosed subject matter (§§ listed in Revision history); it does not withdraw any disclosure made in version 1.0.
>
> **License.** This disclosure is released under Creative Commons CC0 1.0 (public domain dedication) for the purpose of establishing prior art. Any accompanying reference implementation is licensed Apache-2.0, including its patent grant. No patent rights are asserted or reserved over the methods disclosed herein.

Concept DOI `10.5281/zenodo.21415947` (resolves to the latest version). Version 1.0 (2026-07-17): `10.5281/zenodo.21415948`. Version 1.1: `[version DOI assigned on deposit]`.

## Abstract

A method, system, and data format are disclosed for measuring and governing software observability in terms of end-to-end *business flows* rather than per-service instrumentation. Critical flows spanning multiple services are declared as first-class entities; each flow is scored by business consequence to derive a priority tier; flow-level service-level agreements (SLAs) are algorithmically decomposed into per-segment service-level objectives (SLOs); the telemetry required to detect, debug, and resolve issues in each segment is specified; and a multi-dimensional *coverage score* is computed that measures not merely whether instrumentation exists, but whether the available telemetry can actually *answer* the diagnostic questions that arise when a flow degrades. Coverage is enforced in continuous integration so that changes reducing the observability of high-consequence flows are blocked. The disclosed methods are realized on top of distributed-tracing standards (for example, OpenTelemetry) using a declared `flow.*` attribute namespace. Version 1.1 additionally discloses step-primary flow modeling with derived segments, a nondeterminism factor in budget allocation, execution-evidence coverage, dialect-contract verification queries, bounded iteration, and conformance of observed executions against the declared flow read as an authorized plan; no disclosure made in version 1.0 is withdrawn.

**Relationship to companion work.** This disclosure is one of three companion publications. *The Polymorphic Diagram* (Gray 2026b, DOI 10.5281/zenodo.21524592) embeds declared flows in a governed architecture-as-code substrate with bidirectional conformance and a live diagram surface, and owns the `flow.spec` descriptor schema. *Deterministic Execution Certificates* (Gray 2026c, DOI 10.5281/zenodo.21525232) provides signed, hash-chained, per-step execution evidence for the steps of a run, graded by nondeterminism class. This paper owns consequence-based tiering, SLA-to-SLO decomposition, required-telemetry and answerability specification, and the multi-dimensional coverage score. The three share the terminology and identity bindings reproduced in the Terminology section.

## 1 Field

The disclosure relates to software observability, distributed tracing, site-reliability engineering, and the governance of telemetry quality in distributed and service-oriented systems, including systems that incorporate machine-learning or large-language-model components.

## Terminology

The following terms are used in this disclosure and in the two companion publications with the meanings given here. The table is reproduced from the terminology shared by the three publications; the third column records how each term reconciles their vocabularies (FTC: this disclosure; PD: *The Polymorphic Diagram*; DEC: *Deterministic Execution Certificates*) and is included as an aid to readers of all three. Where version 1.0 of this disclosure used a different term, the version 1.0 term is retained as an alias at its first use in the body text.

In version 1.0 of this disclosure the primary unit was the segment (a transition between a source and target service). Version 1.1 adopts the step (a component performing an operation) as the primary unit and retains the segment as the derived edge between consecutive steps. Both modelings are disclosed; see §5. The canonical definition's "never the primary unit" is a vocabulary rule for artifacts written against the shared terminology; it does not withdraw the version 1.0 segment-primary modeling, which remains disclosed (§5; §6, aspect 9).

| Canonical term | Definition | Replaces / reconciles |
|---|---|---|
| **flow** | A declared, versioned, owner-attributed, business-meaningful path through the typed component graph, carrying criticality and SLOs. | Same in all three. |
| **step** | The unit of a flow: one component performing one operation. A node. Identified by `step.id` within a flow. Steps may form a DAG via `next`. | PD "step" (keep). FTC "segment" (see below). DEC "step" (keep). |
| **segment** | The transition between two consecutive steps. An edge. Derived from the step DAG; used for latency-budget decomposition of inter-component hops and for network/authn/authz layer annotations. Never the primary unit. | FTC v1.0 used "segment" as the primary unit (source_service → target_service). In FTC v1.1, "segment" is retained with this narrowed-and-aliased meaning, and the primary unit becomes "step." Both are disclosed. |
| **run** | One execution instance of a flow. `run_id` is the OpenTelemetry trace id of the flow's trigger span unless an explicit `run_id` is declared and bound to it. | DEC `subject.run_id` (keep, add binding). PD had no execution-instance term. |
| **trigger** | The event that starts a run and at which the entry component resolves `flow.id`. | PD (keep). FTC: add. |
| **criticality** | A flow's consequence tier: `P0 \| P1 \| P2 \| P3`, P0 highest. Optionally derived from a numeric `criticality_score` per FTC §4.2. Per-step criticality is optional and defaults to the flow's. | FTC P0–P3 (keep). PD `tier-1 \| tier-2 \| tier-3` → map tier-1→P0, tier-2→P1, tier-3→P2; keep the old values as deprecated aliases in the v0.2 schema enum for one version. |
| **SLO** | A reliability objective. Flow-level SLOs are required (end-to-end, with the synchronous frontier distinguished). Per-step SLOs are optional and may be asserted or derived by FTC §4.3 decomposition. Per-segment SLOs are optional. | PD flow-level only → add optional per-step. FTC per-segment → per-step primary, per-segment optional. |
| **SLA** | The flow-level commitment from which SLOs are decomposed. | FTC (keep). PD: mention once. |
| **required telemetry** | Per step: the spans, attributes, metrics and logs that must exist for the step to be observable. | FTC `required_telemetry` (keep). PD: add as optional per-step block. |
| **debug scenario** | A named diagnostic situation a step must be able to answer, with `required_data` and a `verification_query` that returns data iff the telemetry suffices. | FTC (keep). PD: add. DEC: cross-reference only. |
| **answerability** | The property that a step's declared debug scenarios return sufficient data when their verification queries run. The second component of coverage. | FTC (keep, promote to a defined term). PD: add. |
| **coverage** | FTC's multi-dimensional score: completeness, answerability, breach detectability, cost attribution (and, in v1.1, execution-evidence coverage). The binary "every declared step has attributable telemetry" check is the **minimal completeness check**, not "coverage." | PD §4.2 called the binary check the "minimal instance" of the constraint; rename it "minimal completeness check" and cite FTC for coverage. |
| **conformance** | The reflexion triad over declared flows vs. observed trace topology: **convergent**, **absent** (declared, unobserved), **divergent** (observed, undeclared). | PD §5 (keep). FTC: add as a disclosed variant. DEC: cross-reference. |
| **authorized plan** | A declared flow read as the set of steps a run is permitted to take. A divergent finding on an agentic flow is an off-plan execution. | New in all three; see §4.8 of this disclosure. |
| **nondeterminism class** (`nd_class`) | `ND0 \| ND1 \| ND2 \| ND3` per DEC §1.2. Optional per step in flow.spec v0.2; required in every DEC step certificate. | DEC (keep). PD/FTC: add. |
| **method** | A content-addressed reference `{ref, version, digest}` to the reviewed, versioned executable artifact a step runs. Required for any step claiming ND0 or ND1; optional otherwise. | DEC (keep). PD step `op` is the human-readable verb label and stays; `method` is added beside it. FTC `operation` (e.g. `POST /api/v1/resource`) becomes `op`. |

## 2 Background and Problem

Conventional approaches to observability "coverage" measure instrumentation at the level of individual components: whether a given endpoint emits a span, whether a service exports metrics, what fraction of code paths are traced. These measures answer "is this thing instrumented?" but not the operationally decisive question: **when a business-critical, multi-service flow degrades, can we detect it, locate the cause, and resolve it with the telemetry we have?**

Per-component coverage has several well-known deficiencies. A system can show high per-service instrumentation yet be unable to diagnose an end-to-end latency regression because the *connective* telemetry across service boundaries is missing, or because emitted spans lack the attributes needed to answer specific diagnostic questions. Component-level coverage also treats all instrumentation as equally valuable, providing no principled way to invest telemetry effort where business consequence is greatest. Finally, conventional coverage is disconnected from SLAs: it cannot tell an engineer whether a given segment's performance budget is being met, or which segment is consuming a flow's latency budget.

What is needed is an observability-coverage method oriented around end-to-end flows, prioritized by consequence, tied to SLA decomposition, and measured by diagnostic *answerability*.

## 3 Summary of the Disclosed Method

The disclosed method comprises the following elements, which may be used together or independently.

1. **Flow declaration.** Critical end-to-end business flows are declared as first-class, versioned specifications, each composed of ordered, concurrent, or bounded-iterative *steps* (a component performing an operation), with *segments* (transitions between consecutive steps; in version 1.0, transitions between services) derivable from the step graph; the v1.0 segment-primary modeling remains disclosed.
2. **Consequence-based prioritization.** Each flow is scored along business-impact dimensions (for example, revenue impact, user impact, frequency, data sensitivity, operational complexity, compliance requirement) to produce a criticality score and a discrete priority tier, which in turn sets a required coverage target and operational parameters (sampling rate, alert latency, incident-response SLA).
3. **SLA-to-SLO decomposition.** A flow-level SLA (latency percentiles, availability, error budget) is algorithmically decomposed into per-segment SLOs, accounting for serial versus parallel composition, historical performance, segment criticality and, where steps carry a declared nondeterminism class, a nondeterminism factor, safety margins, and error-budget allocation.
4. **Required-telemetry specification.** For each segment, the spans, attributes, metrics, and logs required to meet observability requirements are declared, along with the diagnostic ("debug") scenarios that must be answerable and the verification queries that test answerability.
5. **Multi-dimensional coverage scoring.** A coverage score is computed per flow from weighted components: telemetry completeness, debug-scenario answerability, SLO-breach detectability, and cost attribution and, optionally, execution-evidence coverage.
6. **CI/CD enforcement.** Coverage is computed in continuous integration; deployments that reduce a flow's coverage below its tier's threshold are blocked, and coverage deltas are surfaced in code review.
7. **Standards realization.** The above is realized over distributed-tracing standards via a declared flow-attribute namespace and overlaid on a service-topology visualization.
8. **Conformance.** Observed trace topology is compared against declared flows in both directions (declared-but-unobserved; observed-but-undeclared), and for flows executed by autonomous agents the declared flow is read as the authorized plan, so an observed-but-undeclared step is an off-plan execution finding.
9. **Execution-evidence binding.** Where steps are executed under signed per-step execution certificates (companion work), the certificate digest is carried on the step's span, the run's realized step graph is compared with the declared flow, and the coverage score may include an execution-evidence component.

## 4 Detailed Description (Enabling Embodiment)

### 4.1 Flow Definition Data Model

A flow is declared in a versioned, machine-readable specification. A representative schema (illustrated in YAML; equivalently expressible in JSON or any structured format):

#### Representative schema (version 1.0, segment-primary)

This is the schema as disclosed in version 1.0, reproduced unchanged:

```yaml
flow_spec_version: "1.0"
flow:
  id: "user_message_generation"
  name: "User Message Generation"
  description: "End-to-end flow from request submission to response delivery"

  business_impact:
    revenue_impact: "critical"      # critical | high | medium | low
    user_impact: "critical"
    frequency: "high"
    compliance_requirement: true    # e.g., regulatory / audit relevance

  sla:                              # flow-level targets
    availability: 99.9
    p50_latency_ms: 800
    p95_latency_ms: 1500
    p99_latency_ms: 2000
    max_latency_ms: 5000
    error_budget: 0.1               # percent

  stakeholders:
    product_owner: "<role or address>"
    tech_lead: "<role or address>"
    on_call_team: "<team>"
    escalation_policy: "<policy reference>"

  segments:
    - id: "api_gateway_routing"
      name: "API Gateway Request Routing"
      source_service: "api_gateway"
      target_service: "request_handler"
      operation: "POST /api/v1/resource"
      concurrency: "serial"          # serial | parallel | optional
      criticality: "medium"          # critical | high | medium | low
      slo:                           # derived (see 4.3) or asserted
        p99_latency_ms: 50
        p95_latency_ms: 30
        error_rate_percent: 0.01
      required_telemetry:
        traces:
          - span_name: "http.server.request"
            required_attributes:
              - http.method
              - http.route
              - http.status_code
              - request.id
              - flow.id
              - flow.segment.id
            sampling_strategy: "always"
        metrics:
          - metric_name: "segment_request_duration_seconds"
            type: "histogram"
        logs:
          - level: "INFO"
      debug_scenarios:
        - scenario: "Downstream unavailability"
          required_data:
            - "Error rate by target service"
            - "Request distribution across backends"
          verification_query: "<query returning the data iff telemetry suffices>"
```

A segment represents a transition between a source and target service. Segments declare their concurrency relationship (serial, parallel, or optional), a criticality classification, an SLO (asserted or derived), the telemetry required to observe them, and one or more diagnostic scenarios with verification queries.

#### Representative schema (version 1.1, step-primary; identical to `flow.spec/v0.2`)

Version 1.1 additionally discloses the step-primary modeling, in which the unit of a flow is a *step* (previously *segment*): one component performing one operation. The representative schema is the `quote-issue` retail quote flow, which is the running example shared with the companion publications and is reproduced here exactly as it appears in them:

```yaml
apiVersion: flow.spec/v0.2
kind: Flow
metadata:
  id: quote-issue
  name: "Retail quote issuance"
  version: 2.0.0
  owner: { business: retail-products, technical: team-quotes }
  criticality: P0
  description: >
    Customer-initiated quote request through pricing, limits check, and
    asynchronous document delivery. Shared running example across FTC, PD and DEC.
spec:
  trigger: { type: user_interaction, description: "Customer submits quote request" }
  steps:
    - id: s1
      component: edge.api-gateway
      op: receive
      kind: sync
      next: [s2]
    - id: s2
      component: identity.session
      op: authorize
      kind: sync
      next: [s3]
    - id: s3
      component: payments.quote-engine
      op: price
      kind: sync
      next: [s4]
    - id: s4
      component: risk.limits-check
      op: evaluate
      kind: sync
      nd_class: ND0
      method: { ref: methods/limits-check, version: 3.1.0, digest: "sha256:fad9362bcab1866e2e08bfb0f98c5a199b01b231ad13b855dcee86444e43d6b6" }
      slo: { latency_p99_ms: 120, error_rate_percent: 0.01 }
      required_telemetry:
        traces:
          - span_name: risk.limits-check/evaluate
            required_attributes: [flow.id, flow.step, risk.limit_id, risk.decision]
        metrics:
          - { name: step_duration_seconds, type: histogram }
      debug_scenarios:
        - scenario: "Limit evaluated against stale reference data"
          required_data: ["reference-data version per evaluation", "decision by version"]
          verification_query: "<query returning decisions grouped by reference-data version for flow.step=s4 over the window>"
      next: [s5]
    - id: s5
      component: docs.render
      op: generate
      kind: async
      nd_class: ND2
      next: [s6]
    - id: s6
      component: notify.customer
      op: deliver
      kind: async
  slos:
    availability: 99.9
    latency_p95_ms: 1800          # trigger → s4 (synchronous frontier)
    async_completion_p99_s: 120   # trigger → s6
  telemetry:
    required_signals: [trace, metric]
    attribute_namespace: flow
    sampling_floor: 0.10
```

A step is one component performing one operation, identified by `id` within the flow; steps form a directed acyclic graph through `next`, and a step's `kind` is one of `sync`, `async`, `fanout`, `choice` or `loop`. A `loop` step declares `bound: {max: N, on_exceed: fail | flag}` with N ≥ 1 (§4.8). The flow's criticality, owners, trigger, end-to-end SLOs (with the synchronous frontier distinguished from asynchronous completion) and telemetry requirements are declared once on the flow; the per-step blocks `criticality`, `slo`, `required_telemetry`, `debug_scenarios`, `nd_class` and `method` are optional, so that a flow may be declared with no more than its path and then enriched. In the example, step `s4` carries the full answerability block and a content-addressed `method`; steps `s4` and `s5` carry a nondeterminism class, and the remaining steps are undeclared (an undeclared step carries no declaration-side constraint and is classified at issuance by the runtime). The segment, the primary unit of version 1.0, is in this modeling the edge between two consecutive steps, derived from `next`: it carries no identifier of its own, takes its endpoints' components as its source and target, and may optionally carry an SLO of its own (the latency of the hop) and network, authentication and authorization annotations. The two schemas map as follows:

| Version 1.0 (segment-primary) | Version 1.1 (step-primary) |
|---|---|
| a `segments[]` entry | the edge between two consecutive steps; the entry's per-segment fields attach to the later (target) step |
| `id` (segment identifier) | the ordered pair (earlier `step.id`, later `step.id`); where an explicit segment identifier is wanted, `flow.segment.id` remains accepted as an alias (§4.7) |
| `source_service` | the earlier step's `component` |
| `target_service` | the later step's `component` |
| `operation` | the later step's `op` (the version 1.0 example `POST /api/v1/resource` becomes the step's verb label; a content-addressed `method` may be added beside it) |
| `concurrency: serial` | the earlier step's `next` names exactly the later step; `kind: sync` |
| `concurrency: parallel` | the earlier step's `next` names several steps, or `kind: fanout` |
| `concurrency: optional` | a `kind: choice` branch (one of several `next` branches is taken), or a `kind: async` step off the synchronous frontier |
| — (no version 1.0 equivalent) | `kind: loop` with `bound: {max, on_exceed}` (§4.8) |
| `criticality` | per-step `criticality`: the version 1.0 vocabulary `critical \| high \| medium \| low` maps to `P0 \| P1 \| P2 \| P3`; a step without one defaults to the flow's (§4.2) |
| `slo` (asserted or derived) | per-step `slo` (asserted or derived, §4.3); optionally also a per-segment `slo` on the edge |
| `required_telemetry` | the same block, per step |
| `debug_scenarios` | the same block, per step |
| `flow.segment.id` (required attribute) | `flow.step` (§4.7) |
| — (no version 1.0 equivalent) | `nd_class`, `method` (per step) |
| `flow.business_impact` | `metadata.criticality` (derived per §4.2, or asserted) |
| `flow.sla` | `spec.slos` |
| `flow.stakeholders` | `metadata.owner` |

Either modeling may be used: a specification may declare steps, segments, or both, with either as the primary unit (§5). Where both are declared, the segment set must be consistent with the step graph (every declared segment is an edge of `next`, and every edge of `next` is at most one segment).

### 4.2 Consequence-Based Prioritization

Each flow receives a criticality score computed from weighted business-impact dimensions. In one embodiment, dimensions include revenue impact, user impact, frequency, data sensitivity, and operational complexity, each on a bounded scale, combined by a weighted sum to yield a criticality score. The score (or any single dimension reaching its maximum) maps to a discrete priority tier:

| Tier | Criteria (example) | Coverage | Sampling | Alert latency | Incident-response SLA |
|---|---|---|---|---|---|
| P0 | criticality ≥ 7.0, or any impact dimension maximal | 100% | always | ≤ 1 min | ≤ 15 min |
| P1 | 5.0 ≤ criticality < 7.0 | 90% | ≥ 80% | ≤ 5 min | ≤ 1 hr |
| P2 | 3.0 ≤ criticality < 5.0 | 75% | ~50% | ≤ 15 min | ≤ 4 hr |
| P3 | criticality < 3.0 | 50% | ~10% | ≤ 1 hr | next business day |

The specific weights, scales, thresholds, and operational parameters are tunable; the disclosed concept is the *derivation of a coverage requirement and operational policy from a consequence-based flow score*.

The tier vocabulary is `P0..P3`. Companion artifacts that used `tier-1..tier-3` map tier-1→P0, tier-2→P1, tier-3→P2. Criticality may also be declared per step: a step's declared criticality, where present, overrides the flow's criticality for decomposition purposes (§4.3) and for the per-step operational parameters derived from the tier, and a step without a declared criticality inherits the flow's. The version 1.0 per-segment criticality vocabulary (`critical | high | medium | low`) remains disclosed and maps to `P0 | P1 | P2 | P3` respectively.

### 4.3 SLA-to-SLO Decomposition Algorithm

A flow-level SLA is decomposed into per-step SLOs (in version 1.0, per-segment SLOs). Version 1.1 states the algorithm over steps. A segment — the transition between two consecutive steps — may be modeled as part of the downstream step's budget (the hop's latency is counted inside the step that receives it) or as a separate, optional segment term with its own allocation; both treatments are disclosed. The version 1.0 statement, which is recovered by reading "segment" for "step" throughout and omitting step 4b, remains disclosed. In the preferred embodiment for latency:

1. Partition steps (and any separately modeled segments) into serial and parallel groups. For serial steps the flow latency lower-bounds the sum of step latencies (`flow_p99 >= sum(step_p99)`, plus `sum(segment_p99)` over any separately modeled segments); for parallel steps it lower-bounds the maximum (`flow_p99 >= max(step_p99)`).
2. Compute available budget as the flow target minus the parallel group's maximum historical contribution.
3. For each serial step, allocate a base contribution proportional to its historical p99 share of the available budget.
4. Apply a *criticality factor* that tightens budgets for more-critical steps and loosens them for less-critical ones (illustrative factors: critical/P0 0.8, high/P1 0.9, medium/P2 1.0, low/P3 1.2), using the step's own criticality where declared and the flow's otherwise (§4.2).
   - **4b.** Apply a *nondeterminism factor* derived from the step's declared class (illustrative: ND0 0.9, ND1 1.0, ND2 1.1, ND3 1.25), tightening budgets for deterministic steps and loosening them for generative ones; for quality and cost budgets (see §5) the factor direction may invert, and the disclosed concept is the use of the nondeterminism class as an allocation input. A step with no declared class takes a factor of 1.0.
5. Apply a safety margin (for example, multiply by 0.9).
6. Allocate the flow error budget across steps by a criticality-weighted factor divided by step count (illustrative error factors: critical/P0 0.5, high/P1 0.75, medium/P2 1.0, low/P3 1.5).
7. If the sum of allocated serial budgets plus the parallel maximum exceeds the flow target, scale all allocations down proportionally so the constraint holds.
8. Approximate other percentiles from the allocated value where direct data is unavailable (for example, p95 ≈ 0.7 × p99).

For availability, serial composition multiplies: a flow availability target *A* over *n* serial steps yields a base per-step requirement equal to the *n*-th root of *A*, increased for higher-criticality steps and capped at a ceiling (for example, 99.99%).

The algorithm applies to any percentile target (the flow target may be stated at p95, p99, or another percentile, with historical shares taken at the same percentile), and step 8 approximates the remaining percentiles.

**Cold-start embodiment.** When no historical p99 (or other percentile) exists for a step — a new flow, a new step, or a step whose component has been replaced — the historical share used in step 3 is unavailable. The following allocations are disclosed for this case: an *equal split* of the available budget across the serial steps; a *declared prior*, an asserted share or absolute budget per step recorded in the flow specification; or a *criticality-weighted split*, in which each step's share is proportional to its criticality factor so that more-critical steps receive tighter budgets from the outset. Whichever is used, the flow specification declares a minimum sample size (a count of observed runs, or a window length), and once that sample is reached the allocation is recomputed from the observed shares by steps 1–8; the transition is itself recorded so that coverage trends (§4.6) are not misread across it. Version 1.0 §5 lists equal split among the budget-allocation strategies; this paragraph makes its cold-start application explicit.

The disclosed concept is the *algorithmic, criticality- and composition-aware allocation of a flow-level reliability budget to constituent steps (in version 1.0, segments)*, not any single set of constants.

#### Worked decomposition: `quote-issue`

The following applies the algorithm to the version 1.1 representative schema (§4.1). All historical shares and factors are illustrative. Steps `s1`–`s4` are serial and synchronous (the synchronous frontier); `s5`–`s6` are asynchronous. The flow is P0 and no step declares its own criticality, so every step takes the P0 criticality factor 0.8; the nondeterminism factors are 1.0 for `s1`, `s2` and `s3` (no declared class), 0.9 for `s4` (ND0), 1.1 for `s5` (ND2) and 1.0 for `s6` (no declared class); the safety margin is 0.9. No segment term is modeled separately; each hop's latency is counted inside the step that receives it.

*Synchronous frontier, latency.* The flow target is `latency_p95_ms: 1800` (trigger → `s4`). There is no parallel group, so the available budget (step 2) is the full 1,800 ms. With illustrative historical p95 shares of 5%, 10%, 65% and 20%:

| Step | Hist. share | Base (ms) | × criticality | × nondeterminism | × safety | Allocated p95 (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `s1` | 5% | 90 | 0.8 → 72.0 | 1.0 → 72.0 | 0.9 → 64.8 | 65 |
| `s2` | 10% | 180 | 0.8 → 144.0 | 1.0 → 144.0 | 0.9 → 129.6 | 130 |
| `s3` | 65% | 1,170 | 0.8 → 936.0 | 1.0 → 936.0 | 0.9 → 842.4 | 842 |
| `s4` | 20% | 360 | 0.8 → 288.0 | 0.9 → 259.2 | 0.9 → 233.3 | 233 |
| Sum | 100% | 1,800 | | | | 1,270 |

The sum of the serial allocations, 1,270 ms, does not exceed the 1,800 ms target, so step 7 applies no scaling and the remaining 530 ms is headroom. By step 8, `s4`'s p99 is approximated as 233 / 0.7 ≈ 333 ms; the descriptor asserts a tighter `latency_p99_ms: 120` for `s4`, and an asserted step SLO takes precedence over the derived one, the difference remaining headroom. Had the sum exceeded the target (for example, with nondeterminism factors above 1.0 on several steps), every allocation would have been scaled by the ratio of the target to the sum.

*Error budget and availability.* The flow's `availability: 99.9` implies a 0.1% error budget. Step 6 allocates it across the four synchronous steps with the P0 error factor 0.5: 0.1% × 0.5 / 4 = 0.0125% per step. The descriptor asserts `error_rate_percent: 0.01` for `s4`, which is tighter and prevails. For availability, the base per-step requirement is 0.999^(1/4) ≈ 99.975%, raised toward the 99.99% ceiling for the P0 steps.

*Asynchronous completion.* The flow target is `async_completion_p99_s: 120` (trigger → `s6`). Because the target is measured from the trigger, the synchronous frontier's p99 contribution is reserved first (illustratively 2.0 s), leaving 118.0 s for `s5` and `s6`. With illustrative historical p99 shares of 80% and 20%: base 94.4 s and 23.6 s; after the criticality factor (0.8) 75.52 s and 18.88 s; after the nondeterminism factor (1.1 for `s5`, ND2; 1.0 for `s6`) 83.07 s and 18.88 s; after the safety margin (0.9) 74.8 s and 17.0 s. The sum, 91.8 s plus the 2.0 s reservation, is 93.8 s, within the 120 s target; step 7 applies no scaling. The generative step `s5` receives a looser budget than its historical share alone would give it, which is the intended effect of the nondeterminism factor on a latency budget.

### 4.4 Required-Telemetry Specification and Answerability

Each step (in version 1.0, each segment) declares the telemetry required to observe it and, crucially, the **diagnostic scenarios** that must be answerable when the step misbehaves. Each scenario specifies the data required to resolve it and a **verification query** that returns that data if and only if the telemetry is sufficient. **Answerability** is the property that a step's declared debug scenarios return sufficient data when their verification queries run; it is the second component of coverage (§4.5). Answerability is tested by executing the verification queries against representative trace, metric, and log stores and checking that they return sufficient, populated results. This converts "is it instrumented?" into "can it be debugged?"

**Portability by contract.** Verification queries are portable by contract, not by dialect. A query is declared with a *dialect* (for example `otel-sql`, `promql`, `traceql`, `datadog`, or a vendor dialect) and an *expected result shape* (for example: at least one row; a named set of columns; a non-empty series for each observed value of a grouping key; a count within a declared range). An evaluator for a given telemetry backend is conformant if it executes the query in a dialect it supports and checks the returned result against the declared shape. The flow specification therefore need not be rewritten per backend, a scenario may carry the same query in more than one dialect, and an evaluator that cannot execute any of a scenario's dialects reports the scenario as not evaluated rather than as answerable. One structured form, disclosed as an optional alternative to the plain string carried in the version 1.1 schema (§4.1):

```yaml
verification_query:
  dialect: otel-sql
  text: "<query returning decisions grouped by reference-data version for flow.step=s4 over the window>"
  expects: { rows: ">= 1", columns: [reference_data_version, decision, count] }
```

**Worked example: `quote-issue` step `s4`.** The version 1.1 representative schema (§4.1) declares for step `s4` (component `risk.limits-check`, operation `evaluate`, class ND0) the required span `risk.limits-check/evaluate` with the attributes `flow.id`, `flow.step`, `risk.limit_id` and `risk.decision`, a `step_duration_seconds` histogram, and one debug scenario:

```yaml
      debug_scenarios:
        - scenario: "Limit evaluated against stale reference data"
          required_data: ["reference-data version per evaluation", "decision by version"]
          verification_query: "<query returning decisions grouped by reference-data version for flow.step=s4 over the window>"
```

The scenario is answerable if and only if the query, run over spans with `flow.id = quote-issue` and `flow.step = s4` in the evaluation window, returns at least one row per reference-data version observed, each with its decision counts. The required-attribute list for the span does not itself include a reference-data version attribute; answerability of this scenario therefore depends on the version being obtainable — as an additional span attribute, or by joining `risk.limit_id` to a reference-data ledger — and executing the verification query is what reveals whether it is. An empty result, or a result lacking the version key, marks the scenario unanswerable and contributes zero for this step to the answerability component of §4.5. This is the distinction between completeness (the declared attributes are present) and answerability (the declared question can be answered), and it is the kind of gap that per-component coverage does not notice.

### 4.5 Multi-Dimensional Coverage Scoring

A per-flow coverage score is computed as a weighted combination of components. In one embodiment:

- **Telemetry completeness (weight 0.40):** fraction of sampled traces in which all required spans and required attributes are present and all required metrics and logs exist.
- **Debug answerability (weight 0.30):** fraction of declared diagnostic scenarios whose verification queries return sufficient data.
- **SLO-breach detectability (weight 0.20):** whether breaches of segment SLOs would be detected by configured alerts within the tier's alert-latency bound.
- **Cost attribution (weight 0.10):** whether per-segment (and per-flow) cost can be attributed from available telemetry.
- **Execution-evidence coverage (optional; illustrative weight 0.10 when enabled):** for steps declared ND0 or ND1, the fraction of sampled runs in which the step's span carries a `dec.step_cert_digest` that verifies against the issuer's trust bundle — that is, the digest of a signed per-step execution certificate issued for that step of that run (binding B7, §4.7). When this component is enabled, an illustrative redistribution of the weights is 0.35 / 0.25 / 0.20 / 0.10 / 0.10 (completeness / answerability / detectability / cost attribution / execution evidence).

In the components above, "segment" is the version 1.0 term and, under version 1.1 terminology, reads "step (and, where modeled, segment)".

The overall score is compared against the flow's tier threshold (for example, P0 requires the maximum; P1 a high threshold) to determine pass or fail. Weights, components, and thresholds are tunable; the disclosed concept is the *composition of completeness with answerability, detectability, and attribution into a single governed coverage metric keyed to flow consequence*. The weights stated in this section are illustrative in this disclosure; a coverage engine may ship them as configurable defaults.

**Minimal completeness check.** The binary check that every declared step has attributable telemetry — spans grouped by (`flow.id`, `flow.step`) over the window, compared against the declared step set — is the **minimal completeness check**. It is what the coverage constraint of the companion Polymorphic Diagram paper (§4.2 of that paper) evaluates; it is a necessary condition for, and a degenerate case of, the telemetry-completeness component above; and the full multi-dimensional score is this section. In this disclosure "coverage" means the full score.

### 4.6 CI/CD Enforcement and Visualization

Coverage is computed automatically in continuous integration. A change that reduces a flow's coverage below its tier threshold is blocked; coverage deltas are reported in code review; coverage trends are tracked over time. A topology visualization overlays flow paths on the service graph, coloring segments by SLO status and enabling drill-down into segment performance and missing telemetry. The topology overlay described here is realized in the companion work as the flow lens of a polymorphic diagram; coverage and answerability shading are rendered on the declared topology.

### 4.7 Standards Realization

The method is realized over a distributed-tracing standard (for example, OpenTelemetry) by introducing a small flow-attribute namespace carried on spans — for example `flow.id`, `flow.segment.id`, and optionally `flow.priority` and `flow.segment.criticality` — enabling flow-aware aggregation, coverage measurement, and visualization atop existing tracing infrastructure without proprietary agents. The attributes `flow.segment.id` and `flow.priority` were renamed in v1.1 to `flow.step` and `flow.criticality`; the v1.0 names remain disclosed and are accepted as aliases.

Correspondingly, the v1.0 attribute `flow.segment.criticality` becomes `flow.step.criticality` and receives the same treatment. Deprecated aliases are accepted on ingest, with a warning, through all `flow.spec/v0.x` versions and are removed at `flow.spec/v1.0`; they are never emitted.

The attribute namespace, expressed as an OpenTelemetry semantic-convention extension, is shared with the companion publications:

| Attribute | Type | Required | Set by | Meaning |
|---|---|---|---|---|
| `flow.id` | string | yes | entry component at trigger | declared flow id |
| `flow.version` | string | yes | entry component | flow semver at execution time |
| `flow.step` | string | yes | hosting component, on its boundary span | current declared step id |
| `flow.criticality` | string | optional | entry component | `P0..P3` (was `flow.priority` in FTC) |
| `flow.step.criticality` | string | optional | hosting component | per-step override |
| `flow.step.nd_class` | string | optional | hosting component | `ND0..ND3` as declared |
| `flow.run_id` | string | optional | entry component | only when an explicit run id differs from the trace id |
| `dec.step_cert_digest` | string | optional | hosting component, after issuance | sha256 digest of the DEC step certificate for this span's step |
| `dec.run_cert_digest` | string | optional | entry component, at run end | digest of the run certificate |
| ~~`flow.segment.id`~~ | string | deprecated | — | FTC v1.0 name for the step identifier. Accept on ingest as an alias of `flow.step` for one major version; never emit. |
| ~~`flow.priority`~~ | string | deprecated | — | FTC v1.0 name for `flow.criticality`. Same treatment. |

Propagation: `flow.id`, `flow.version`, `flow.step` travel as baggage and are recorded on every span; interior spans inherit; only declared step boundaries update `flow.step`. Metrics carry the same keys as exemplar labels; cost/usage ledger records carry them as columns.

**Identity bindings.** The following bindings are normative for any realization of this method that interoperates with the companion publications (the binding numbers are those used across the three companion publications):

- **B2 (flow ↔ telemetry).** Every span of a run MUST carry `flow.id`, `flow.version` and `flow.step` as set out in the table above.
- **B3 (run ↔ trace).** `run_id` MUST equal the trace id of the trigger span unless `flow.run_id` is set, in which case both MUST be recorded on the trigger span.
- **B7 (coverage ↔ evidence).** Coverage MAY include execution-evidence coverage: the fraction of ND0/ND1 steps in a window whose spans carry a verifiable `dec.step_cert_digest` (§4.5). A realization that reports this component MUST compute it from digests that verify against the issuer's trust bundle and whose certificate's `subject.flow = {id, version, step}` matches the span's `flow.id`, `flow.version` and `flow.step`.

### 4.8 Conformance and the Authorized Plan

Observed trace topology is compared against the declared flows in both directions. Following the software reflexion models of Murphy, Notkin and Sullivan (2001), as applied to live trace topology in the companion Polymorphic Diagram paper (§5 of that paper), each declared or observed path is classified as **convergent** (observed traffic matches a declared flow's steps in order), **absent** (declared, unobserved: a flow or step with no attributable traffic over its evaluation window — a dead flow, broken instrumentation, or a genuinely dormant path), or **divergent** (observed, undeclared: recurring paths matching no declared flow, routed to *declare*, *exempt* or *investigate*). Conformance is disclosed here as a variant of the coverage method: an absent step is a completeness failure by another name, and a divergent path is telemetry that the declared flow set cannot attribute.

**The authorized-plan reading.** For flows executed by autonomous agents, whose step sequence is chosen at runtime, the declared flow is read as the **authorized plan**: the set of steps, with their `next` relations and bounds, that a run is permitted to take. The comparison is then made per run rather than per window. The run's realized step DAG — as observed from its spans grouped by `flow.step`, or, where the run carries a run certificate, as recorded in that certificate's `manifest.steps[]` — is compared with the declared step graph. Binding B6 of the companion publications is normative here: where a run certificate exists, its `manifest.steps[]` is the realized step DAG and MUST be the input to the per-run comparison; a run whose realized DAG matches the declared flow is convergent, and extra steps are divergent (off-plan). A run whose realized DAG is a path through the declared graph is **convergent**. A step in the realized DAG that is not in the declared graph, or a transition not permitted by `next`, is an **off-plan execution**: a divergent finding attributed to the run, routed to *declare* (the plan was incomplete), *exempt* (an instrumentation or infrastructure step), or *investigate* (the agent took a step it was not authorized to take). A declared step that the plan required and the realized DAG lacks is an **absent** finding for that run.

**Bounded iteration.** A step declared with `kind: loop` carries `bound: {max: N, on_exceed: fail | flag}` with N ≥ 1. A run that iterates the step more than N times is handled per the declared `on_exceed`. With `fail` (the *hard cap*) the run is terminated at iteration N+1 and recorded as failed, so that the bound is enforced by the executing system and is an invariant of the system's behavior. With `flag` (the *soft cap*) the run is permitted to continue and the exceedance is recorded as a divergent finding against the run, so that the bound is enforced by governance and produces evidence without interrupting a run in flight. Both variants are disclosed; the flow author chooses per step.

**Evaluation.** Conformance is evaluated after the fact: continuously over windows for the topology reading, and per run for the authorized-plan reading. Pre-execution plan verification is outside this disclosure. Findings are recorded with the version of the flow set they were evaluated against. Conformance findings may feed back into coverage: a flow with unresolved divergent findings may be scored as if its completeness were reduced, and a tier threshold may require zero unresolved off-plan findings for P0 flows.

## 5 Alternative Embodiments and Variations

The following variations are expressly disclosed so that they, too, constitute prior art.

- Expressing flow specifications in any structured format (YAML, JSON, TOML, protobuf, a database schema, or a domain-specific language).
- Any number and choice of business-impact dimensions and any aggregation function (weighted sum, weighted product, maximum, learned model) for the criticality score; any number of priority tiers.
- Decomposition objectives beyond latency and availability, including throughput, saturation, freshness, accuracy, token cost, or model-quality budgets for machine-learning and large-language-model segments.
- Budget-allocation strategies including equal split, proportional-to-historical, critical-path-weighted, optimization-based (for example, minimizing total budget subject to the flow constraint), or reinforcement/feedback-tuned allocation.
- Answerability testing by static analysis of instrumentation, by executing verification queries against live or synthetic data, by replaying recorded traces, or by fault injection and chaos experiments that confirm a scenario becomes detectable.
- Coverage components beyond the four named, with arbitrary weights, including security/audit-event coverage, privacy/PII-handling coverage, and lineage/provenance coverage.
- Enforcement at any stage: pre-commit, pull-request gating, pre-deploy, or continuous runtime monitoring with alerting on coverage regression.
- Realization over any tracing or telemetry standard or vendor backend; carriage of flow identifiers via span attributes, baggage/context propagation, resource attributes, or log and metric labels.
- Application to machine-learning and large-language-model flows, where segments may represent retrieval, routing, inference, tool calls, or consolidation steps, and where cost and quality budgets are decomposed alongside latency.
- Multi-flow optimization that allocates a finite telemetry or cost budget across competing flows by consequence.
- Modeling flows as steps (nodes), as segments (edges), or both, with either as primary.
- Nondeterminism class as an input to budget allocation, coverage weighting, sampling policy, or alert routing.
- Execution-evidence coverage computed from signed per-step certificates, from unsigned provenance records, or from replay success rates.
- Verification queries expressed in any query dialect with a declared result-shape contract; evaluators that execute queries against live stores, recorded traces, synthetic data, or by replay.
- Conformance evaluated against declared flows read as authorized plans, with hard or soft bounds on iterative steps, applied to autonomous-agent executions.
- Bounded iteration (`loop`) and choice steps declared with explicit bounds and branch sets.

## 6 Enumerated Disclosed Aspects

For clarity of the disclosed scope (these are *not* patent claims; they are an enumeration of subject matter placed in the public domain):

1. A method comprising declaring a multi-service business flow as a versioned specification of ordered or concurrent segments and computing an observability coverage measure for the flow.
2. The method of (1), further comprising scoring the flow by business consequence to derive a priority tier and a corresponding required coverage target and operational policy.
3. The method of (1), further comprising decomposing a flow-level reliability budget into per-segment objectives in a manner that accounts for serial/parallel composition, historical performance, and segment criticality.
4. The method of (1), wherein the coverage measure includes a component testing whether available telemetry can answer declared diagnostic scenarios via verification queries.
5. The method of (1), wherein the coverage measure is a weighted combination of telemetry completeness, diagnostic answerability, SLO-breach detectability, and cost attribution.
6. The method of (1), further comprising blocking, in an automated build/deploy pipeline, changes that reduce a flow's coverage below its required target, and reporting coverage deltas in review.
7. The method of (1), realized over a distributed-tracing standard by carrying flow and segment identifiers as telemetry attributes, and overlaying flow status on a service-topology visualization.
8. The methods of (1)–(7) applied to flows containing machine-learning or large-language-model segments, including decomposition of cost and quality budgets across such segments.
9. The method of (1), wherein the flow is declared as steps (each a component performing an operation) forming a directed graph, as segments (transitions between consecutive steps), or both, with either as the primary unit, and wherein steps may be ordered, concurrent, conditional (choice), or bounded-iterative (loop) with an explicit bound and branch set.
10. The method of (1), wherein steps carry a declared nondeterminism class, and the class is used as an input to reliability-budget allocation (including a nondeterminism factor applied in the decomposition of (3)), to coverage weighting, to sampling policy, or to alert routing.
11. The method of (1), wherein the coverage measure includes an execution-evidence component computed from signed per-step execution certificates, from unsigned provenance records, or from replay success rates, the evidence being bound to a step by a certificate digest carried as a telemetry attribute on the step's span.
12. The method of (4), wherein each verification query is declared with a query dialect and an expected result-shape contract, and answerability is evaluated by any evaluator that executes the query against live stores, recorded traces, or synthetic data, or by replay, and checks the result against the declared shape.
13. The method of (1), further comprising comparing observed trace topology, or a run's realized step graph as recorded in a signed run certificate, against the declared flow in both directions (declared-but-unobserved; observed-but-undeclared), reading the declared flow as the authorized plan for executions by autonomous agents, and treating an observed-but-undeclared step, or an iterative step exceeding its declared bound, as an off-plan finding routed to declare, exempt, or investigate, or as a failed run, according to a hard or soft bound declared per step.

## 7 Industrial Applicability

The disclosed methods apply to any distributed or service-oriented software system where end-to-end reliability and diagnosability matter, including consumer and enterprise web services, financial and regulated systems requiring auditability, AI/LLM application platforms whose flows span retrieval, routing, inference, and tool execution, and autonomous and agentic software systems whose execution paths are determined at runtime.

## 8 Revision history

- **v1.0 (2026-07-17):** initial disclosure.
- **v1.1 (2026-10-10):** terminology reconciled with companion publications (Terminology section); step-primary modeling disclosed (§3 item 1, §4.1); nondeterminism factor (§4.3 step 4b); cold-start allocation made explicit (§4.3); execution-evidence coverage (§4.5, §4.7 binding B7); conformance and authorized-plan reading (§3 items 8–9, §4.8); dialect-contract verification queries (§4.4); bounded iteration (§4.1, §4.8); attribute namespace renamed with aliases and identity bindings B2, B3, B6 and B7 (§4.7, §4.8); `quote-issue` worked example (§4.1, §4.3, §4.4); alternative embodiments appended (§5); aspects 9–13 added (§6); agentic systems added to industrial applicability (§7); references added. No disclosure withdrawn.

## Acknowledgment

Drafting and specification development were assisted by Claude (Anthropic); all design decisions, claims, and errors are the author's.

## References

- Gray, J. (2026a). Flow-Based Telemetry Coverage: A Method for Measuring and Governing Observability by Business-Flow Consequence. Version 1.0. Zenodo. Concept DOI https://doi.org/10.5281/zenodo.21415947; version DOI https://doi.org/10.5281/zenodo.21415948.
- Gray, J. (2026b). The Polymorphic Diagram: Binding Declared Business Flows to Runtime Telemetry in Governed Architecture-as-Code. Preprint, v1.1. Zenodo. Concept DOI https://doi.org/10.5281/zenodo.21524592; version DOI https://doi.org/10.5281/zenodo.21524593. Specification and reference tooling: https://github.com/azimuth-ink/polydiagram (concept DOI https://doi.org/10.5281/zenodo.21524083).
- Gray, J. (2026c). Deterministic Execution Certificates: Verifiable Evidence for Hybrid LLM-Agent Workflows. Preprint, v0.1, deposited as a defensive publication. Zenodo. DOI https://doi.org/10.5281/zenodo.21525232. Specification and reference verifier: https://github.com/azimuth-ink/agent-dec (concept DOI https://doi.org/10.5281/zenodo.21524087).
- Murphy, G. C., Notkin, D., Sullivan, K. J. (2001). Software Reflexion Models: Bridging the Gap Between Design and Implementation. *IEEE Transactions on Software Engineering*, 27(4).
- OpenTelemetry Authors. *OpenTelemetry Specification and Semantic Conventions.* opentelemetry.io.

---

*This document is a defensive publication intended to establish prior art and to keep the disclosed methods freely available. It may be redistributed in full. Released under CC0 1.0.*
