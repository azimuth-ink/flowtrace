"""Shared fixtures: repository paths, the shipped config, the canonical flow,
adapters over the three synthetic windows, and the sibling checkouts (when
present beside this repository, as in `make dev` and the three-repo CI job)."""
from __future__ import annotations

import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"
EXAMPLES = REPO / "examples"
FLOWS = EXAMPLES / "flows"
TELEMETRY = EXAMPLES / "telemetry"
EXPECTED = EXAMPLES / "expected"
DEC = EXAMPLES / "dec"
FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"
CANON = FLOWS / "quote-issue.flow.yaml"
CONFIG = REPO / "flowtrace.yaml"
ALERTS = EXAMPLES / "alerts.yaml"
QUERIES = EXAMPLES / "queries" / "quote-issue.queries.yaml"
TRUST_BUNDLE = DEC / "trust-bundle.json"
DEC_DIR = DEC / "flow-bound"
WINDOWS = ("full", "s5-silent", "s4-missing-attr")

# sha256 of the canonical quote-issue v0.2 descriptor (canon §3; same constant as polydiagram's test)
CANON_SHA256 = "adff7b89ab89311ef0e6f110a7125ec4d9317cdd296a928fea04aaef7d71fe91"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def sibling(name: str) -> pathlib.Path | None:
    """A sibling checkout: $FLOWTRACE_SIBLINGS/<name>, ../<name>, or siblings/<name>."""
    cands = []
    if os.environ.get("FLOWTRACE_SIBLINGS"):
        cands.append(pathlib.Path(os.environ["FLOWTRACE_SIBLINGS"]) / name)
    cands += [REPO.parent / name, REPO / "siblings" / name]
    for c in cands:
        if (c / "pyproject.toml").exists():
            return c
    return None


def telemetry(window: str) -> pathlib.Path:
    return TELEMETRY / f"quote-issue.{window}.otlp.jsonl"


@pytest.fixture(scope="session")
def cfg():
    from flowtrace.config import load_config
    return load_config(CONFIG)


@pytest.fixture(scope="session")
def canon_flow():
    from flowtrace.flows import load_flows
    (flow,) = load_flows(FLOWS)
    return flow


# A test double of the quote-issue flow with the control-plane declarations of
# the revision of 2026-10-11 (outcomes, on_fail / latch, effect / attempts,
# cancel_propagation_s, max_decision_age_s, attribute classes, the assurance
# floor): the same declarations as canon §7.1, used by the unit tests so that
# the rules can be exercised whatever version examples/flows/ carries.
DEGRADING_FLOW = """
apiVersion: flow.spec/v0.2
kind: Flow
metadata:
  id: quote-issue
  name: "Retail quote issuance"
  version: 2.1.0
  owner: { business: retail-products, technical: team-quotes }
  criticality: P0
spec:
  trigger: { type: user_interaction }
  outcomes: [allow, block, clarify, review, error]
  steps:
    - { id: s1, component: edge.api-gateway, op: receive, kind: sync, next: [s2] }
    - { id: s2, component: identity.session, op: authorize, kind: sync, next: [s3] }
    - { id: s3, component: payments.quote-engine, op: price, kind: sync, on_fail: { outcome: review }, next: [s4] }
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
            required_attributes:
              - { name: flow.id, class: identifier }
              - { name: flow.step, class: identifier }
              - { name: risk.limit_id, class: identifier }
              - { name: risk.decision, class: identifier }
        metrics:
          - { name: step_duration_seconds, type: histogram }
      debug_scenarios:
        - scenario: "Limit evaluated against stale reference data"
          required_data: ["reference-data version per evaluation", "decision by version"]
          verification_query: "<query returning decisions grouped by reference-data version for flow.step=s4 over the window>"
      on_fail: { outcome: block }
      next: [s5]
    - { id: s5, component: docs.render, op: generate, kind: async, nd_class: ND2, on_fail: { to: s6, latch: true }, next: [s6] }
    - { id: s6, component: notify.customer, op: deliver, kind: async, effect: true, attempts: { max: 3, on_exceed: { outcome: error } } }
  slos: { availability: 99.9, latency_p95_ms: 1800, async_completion_p99_s: 120 }
  cancel_propagation_s: 30
  max_decision_age_s: 300
  telemetry: { required_signals: [trace, metric], attribute_namespace: flow, sampling_floor: 0.10, assurance_sampling_floor: 1.0 }
"""


@pytest.fixture(scope="session")
def degrading_flow():
    import yaml
    from flowtrace.flows import Flow
    return Flow(FLOWS / "quote-issue.flow.yaml", yaml.safe_load(DEGRADING_FLOW), "0" * 64)


@pytest.fixture(scope="session")
def adapters():
    from flowtrace.adapters.otlp_duckdb import OtlpDuckDBAdapter
    return {w: OtlpDuckDBAdapter([telemetry(w)]) for w in WINDOWS}


@pytest.fixture
def gate_inputs(tmp_path):
    """GateInputs for a window with every input the three-repo job passes."""
    from flowtrace.gate import GateInputs

    def make(window: str, **over):
        base = dict(flows=str(FLOWS), telemetry=[str(telemetry(window))], config=str(CONFIG), alerts=str(ALERTS),
                    trust_bundle=str(TRUST_BUNDLE), dec_dirs=[str(DEC_DIR)], queries=[str(QUERIES)],
                    execution_evidence=True, reproducible=True, out=str(tmp_path / f"{window}.json"))
        base.update(over)
        return GateInputs(**base)
    return make
