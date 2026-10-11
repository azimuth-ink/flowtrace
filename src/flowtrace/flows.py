"""Flow descriptors (flow.spec/v0.2) — loaded, never redefined.

The schema and the rules R1–R11 belong to azimuth-ink/polydiagram. When that
package is installed, every descriptor is validated with its validator before
the engine touches it; when it is not, the engine loads the YAML with a
warning that the descriptor was not validated (the gate still runs — the
three-repo CI job is where validation is mandatory).
"""
from __future__ import annotations

import hashlib
import pathlib
import subprocess
from dataclasses import dataclass, field
from typing import Any, Mapping

import yaml

from .config import REPLAYABLE_ND_CLASSES
from .tiering import normalize_criticality


class FlowError(ValueError):
    pass


@dataclass
class Flow:
    path: pathlib.Path
    doc: dict
    sha256: str
    warnings: list[str] = field(default_factory=list)

    @property
    def id(self) -> str:
        return str(self.doc["metadata"]["id"])

    @property
    def version(self) -> str:
        return str(self.doc["metadata"]["version"])

    @property
    def criticality(self) -> str:
        return normalize_criticality(self.doc["metadata"].get("criticality"), None) or "P2"

    @property
    def steps(self) -> list[dict]:
        return [s for s in (self.doc.get("spec") or {}).get("steps") or [] if isinstance(s, dict)]

    @property
    def step_ids(self) -> list[str]:
        return [s["id"] for s in self.steps]

    def step(self, sid: str) -> dict | None:
        for s in self.steps:
            if s.get("id") == sid:
                return s
        return None

    @property
    def replayable_steps(self) -> list[str]:
        """Steps declared ND0/ND1 — the execution-evidence population (B7)."""
        return [s["id"] for s in self.steps if s.get("nd_class") in REPLAYABLE_ND_CLASSES]

    @property
    def has_answerability_block(self) -> bool:
        return any(k in s for s in self.steps for k in ("slo", "required_telemetry", "debug_scenarios"))

    @property
    def sampling_floor(self) -> float | None:
        v = ((self.doc.get("spec") or {}).get("telemetry") or {}).get("sampling_floor")
        return None if v is None else float(v)

    @property
    def required_signals(self) -> list[str]:
        return list(((self.doc.get("spec") or {}).get("telemetry") or {}).get("required_signals") or [])


def _polydiagram_validator():
    try:
        from polydiagram import validate_flows as vf  # type: ignore
    except ImportError:
        return None
    return vf


def load_flows(directory: str | pathlib.Path, registry: str | None = None, strict: bool = False) -> list[Flow]:
    """Every *.flow.yaml under `directory`, validated with polydiagram when
    installed. Raises FlowError on any validator finding (or, with strict,
    on any R-DEPRECATED warning)."""
    root = pathlib.Path(directory)
    paths = sorted(root.rglob("*.flow.yaml")) if root.is_dir() else [root]
    if not paths:
        raise FlowError(f"no *.flow.yaml under {root}")
    vf = _polydiagram_validator()
    validators = vf.load_validators() if vf else None
    reg = vf.load_registry(registry) if (vf and registry) else None
    flows, findings, seen = [], [], {}
    for p in paths:
        raw = p.read_bytes()
        doc = yaml.safe_load(raw.decode("utf-8"))
        if not isinstance(doc, dict) or doc.get("kind") != "Flow":
            raise FlowError(f"{p}: not a Flow document")
        warns: list[str] = []
        if vf:
            vf.check_flow(doc, p, validators, reg, findings, warns)
        else:
            warns.append(f"{p.name}: polydiagram is not installed; descriptor loaded without R1–R11 validation")
        fid = (doc.get("metadata") or {}).get("id")
        if fid in seen:
            findings.append(f"{p}: R4: flow id '{fid}' already declared in {seen[fid]}")
        seen[fid] = p
        flows.append(Flow(path=p, doc=doc, sha256=hashlib.sha256(raw).hexdigest(), warnings=warns))
    if strict:
        findings += [w for f in flows for w in f.warnings if "R-DEPRECATED" in w]
    if findings:
        raise FlowError("flow validation failed:\n  " + "\n  ".join(findings))
    return flows


def git_commit(path: str | pathlib.Path) -> str | None:
    """HEAD commit of the repository containing `path`, or None (PD §5: the
    report records which version of the declared flow set it evaluated)."""
    try:
        out = subprocess.run(["git", "-C", str(pathlib.Path(path).resolve()), "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else None


def required_trace_specs(step: Mapping[str, Any]) -> list[dict]:
    return list(((step.get("required_telemetry") or {}).get("traces")) or [])


def required_metric_specs(step: Mapping[str, Any]) -> list[dict]:
    return list(((step.get("required_telemetry") or {}).get("metrics")) or [])


def required_log_specs(step: Mapping[str, Any]) -> list[dict]:
    return list(((step.get("required_telemetry") or {}).get("logs")) or [])
