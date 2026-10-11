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
