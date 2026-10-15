"""The bridge to agent-dec's verifier for the step-1d readings (revision 2026-10-11).

Everything that needs a certificate chain — effect-evidence order (B10),
approval checks (B11, B15), freshness (B16), reconciliation before retry
(B17) — is taken from agent-dec's verifier, called as a library on the run
directory that holds the run certificate; this engine never re-implements
chain, signature or evidence-order checks (spec §7.5–§7.7, §11). The
verifier reports its step-1d results as lines of a fixed form (its
documented contract):

    FINDING   <name> <file>: <reason>      a step-1c/1d finding (exit 3 when the evidence is otherwise verified)
    NOTE      <kind> <file>: <text>        informational (completion-missing, explicit-run-id, …)
    FAILED    <verdict> <file>: <reason>   an evidence failure (exit 1)
    <part> (step 1x): …UNCHECKED…           a summary line naming a check it could not perform

`VerifierRun` is one run directory's parsed result, cached per directory.
"""
from __future__ import annotations

import contextlib
import io
import pathlib
import re
from dataclasses import dataclass, field

FINDING_RE = re.compile(r"^\s*FINDING\s+(\S+)\s+(\S+): (.*)$")
NOTE_RE = re.compile(r"^\s*NOTE\s+(\S+)\s+(\S+): (.*)$")
FAILED_RE = re.compile(r"^\s*FAILED\s+(\S+)\s+(\S+): (.*)$")
SUMMARY_RE = re.compile(r"^(flow binding|claims|effect evidence|grants and children) \((step .*?)\): (.*)$")
VERDICT_RE = re.compile(r"^RUN VERDICT: (\S+)")

# The step-1d findings this engine reads (spec §7.5–§7.7, §6.6), and which of
# them make the run's reading divergent (spec §9). The approval findings and
# the authorization window/freshness findings are statuses of authorization
# coverage (§6.6) and are passed through as findings on the run; they do not
# change its reading.
DIVERGENT_FINDINGS = ("retry-without-reconciliation", "effect-without-authorization", "cancellation-not-propagated")
PASS_THROUGH_FINDINGS = ("authorization-expired", "authorization-stale", "sod-violation", "approval-payload-mismatch")


@dataclass
class VerifierRun:
    directory: pathlib.Path
    exit_code: int | None = None
    verdict: str = "error"                       # verified | not-clean | failed | error
    findings: list[tuple[str, str, str]] = field(default_factory=list)     # (name, file, reason)
    notes: list[tuple[str, str, str]] = field(default_factory=list)        # (kind, file, text)
    failed: list[tuple[str, str, str]] = field(default_factory=list)       # (verdict, file, reason)
    unchecked: list[str] = field(default_factory=list)                     # summary parts reported UNCHECKED
    summaries: dict[str, str] = field(default_factory=dict)                # step -> summary text
    error: str | None = None
    argv: list[str] = field(default_factory=list)

    def findings_for(self, file_name: str) -> list[tuple[str, str]]:
        """[(name, reason)] of the findings the verifier attributed to one chain member."""
        return [(n, r) for n, f, r in self.findings if f == file_name]

    def failed_for(self, file_name: str) -> list[tuple[str, str]]:
        return [(v, r) for v, f, r in self.failed if f == file_name]

    def notes_for(self, file_name: str) -> list[tuple[str, str]]:
        return [(k, t) for k, f, t in self.notes if f == file_name]

    @property
    def ok(self) -> bool:
        return self.verdict in ("verified", "not-clean")


def verifier_argv(run_dir: pathlib.Path, *, trust_bundle: pathlib.Path | None, flows_dir: pathlib.Path | None,
                  methods: pathlib.Path | None, approvals: pathlib.Path | None, runs_dirs: list[pathlib.Path]) -> list[str]:
    argv = ["--dir", str(run_dir)]
    if trust_bundle:
        argv += ["--trust-bundle", str(trust_bundle)]
    if flows_dir:
        argv += ["--flow-registry", str(flows_dir)]
    if methods:
        argv += ["--methods", str(methods)]
    if approvals:
        argv += ["--approvals", str(approvals)]
    for d in runs_dirs:
        argv += ["--runs-dir", str(d)]
    return argv


def run_verifier(run_dir: pathlib.Path, argv: list[str]) -> VerifierRun:
    """Call agent-dec's verifier on one run directory and parse its report."""
    result = VerifierRun(directory=run_dir, argv=list(argv))
    try:
        from agent_dec import verify_dec as vd  # type: ignore
    except ImportError:
        result.error = "agent-dec is not installed"
        return result
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out):
            rc = vd.main(argv)
    except SystemExit as e:                      # the verifier's own usage / load errors
        result.error = f"verifier exited: {e.code}"
        rc = None
    except Exception as e:                       # noqa: BLE001 — a verifier crash is a report, not a gate crash
        result.error = f"verifier raised {type(e).__name__}: {str(e)[:120]}"
        rc = None
    result.exit_code = rc
    for line in out.getvalue().splitlines():
        m = FINDING_RE.match(line)
        if m:
            result.findings.append((m.group(1), m.group(2), m.group(3)))
            continue
        m = NOTE_RE.match(line)
        if m:
            result.notes.append((m.group(1), m.group(2), m.group(3)))
            continue
        m = FAILED_RE.match(line)
        if m:
            result.failed.append((m.group(1), m.group(2), m.group(3)))
            continue
        m = SUMMARY_RE.match(line)
        if m:
            result.summaries[m.group(2)] = m.group(3)
            for part in m.group(3).split("; "):
                # a part the verifier could not check (a zero count of unchecked claims is not one)
                if "UNCHECKED" in part and not re.search(r"\b0 UNCHECKED", part):
                    result.unchecked.append(f"{m.group(2)}: {part.strip()}")
            continue
        m = VERDICT_RE.match(line)
        if m:
            word = m.group(1)
            result.verdict = {"verified": "verified", "NOT": "not-clean", "FAILED": "failed"}.get(word, "error")
    return result
