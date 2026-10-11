"""flowtrace — reference implementation of Flow-Based Telemetry Coverage (FTC v1.1).

The coverage engine the FTC paper discloses (paper/flow-based-telemetry-coverage.md),
built *on* the companion repositories and never redefining their artifacts:

* flow descriptors are ``flow.spec/v0.2`` documents owned by
  azimuth-ink/polydiagram (one schema, one owner); flowtrace consumes them;
* execution evidence is verified by azimuth-ink/agent-dec's verifier, called as
  a library (binding B7); flowtrace never reimplements certificate verification.

Modules (FTC section each implements):

  tiering        §4.2  criticality score -> P0..P3 -> tier policy (defaults in flowtrace.yaml)
  decompose      §4.3  SLA -> per-step SLOs: serial sum / parallel max, criticality and
                       nondeterminism factors, safety margin, error budget, scaling, cold start
  answerability  §4.4  verification queries by dialect contract {dialect, text, expected_shape}
  coverage       §4.5  completeness, answerability, breach detectability, cost attribution,
                       execution-evidence coverage (B7)
  conformance    §4.8  convergent / absent / divergent over spans, the authorized-plan reading
                       per run (manifest input per B6), loop-bound exceedance
  gate           §4.6  tier-threshold gate, baseline deltas, coverage-report.json
  adapters       the backend protocol and the reference OTLP-JSON -> DuckDB adapter (``otel-sql``)
  cli            ``flowtrace gate | decompose | tier | conformance``

Normative text: spec/coverage-engine.md. Report format: spec/schemas/coverage-report.schema.json.
"""

__version__ = "0.1.0"
REPORT_SCHEMA_VERSION = "flowtrace.report/v0.1"
CONFIG_API_VERSION = "flowtrace.config/v0.1"
ALERTS_API_VERSION = "flowtrace.alerts/v0.1"
QUERIES_API_VERSION = "flowtrace.queries/v0.1"
