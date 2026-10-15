"""Byte identity of the shared artifacts: the canonical quote-issue descriptor
(one source, copied verbatim) and the signed DEC example (never hand-edited)."""
import hashlib
import json
import re

import pytest

from conftest import CANON, CANON_SHA256, CERTIFIED_RUN, DEC, DEC_DIR, FIXTURES, REPO, TRUST_BUNDLE, sibling


def test_canon_descriptor_is_byte_identical_to_fixture():
    example = CANON.read_bytes()
    assert example == (FIXTURES / "quote-issue.canon.yaml").read_bytes()
    assert hashlib.sha256(example).hexdigest() == CANON_SHA256


def test_canon_descriptor_matches_block_in_paper():
    paper = (REPO / "paper" / "flow-based-telemetry-coverage.md").read_text(encoding="utf-8")
    blocks = re.findall(r"```yaml\n(.*?)```\n", paper, re.S)
    assert CANON.read_text(encoding="utf-8") in blocks


@pytest.mark.skipif(sibling("polydiagram") is None, reason="polydiagram checkout not beside this repo")
def test_canon_descriptor_identical_to_polydiagram_example():
    assert CANON.read_bytes() == (sibling("polydiagram") / "examples" / "retail-quote.flow.yaml").read_bytes()


@pytest.mark.skipif(sibling("agent-dec") is None, reason="agent-dec checkout not beside this repo")
def test_dec_example_identical_to_agent_dec():
    """Every vendored artifact under examples/dec/ is byte-identical to the
    agent-dec checkout's (flow-bound run with its evidence members, the
    variants, the cancelled pair, the negatives, the hosted run, methods,
    the issuer key and the trust bundle)."""
    src = sibling("agent-dec") / "examples"
    names = sorted(p.name for p in DEC_DIR.glob("*.dec.json"))
    assert names == ["authorization-s6.dec.json", "completion-s6.dec.json", "run.dec.json"] + [f"step-s{i}.dec.json" for i in range(1, 7)]
    vendored = sorted(p for p in DEC.rglob("*") if p.is_file() and p.name != "SOURCE")
    assert len(vendored) > 250
    for p in vendored:
        rel = p.relative_to(DEC)
        assert p.read_bytes() == (src / rel).read_bytes(), str(rel)
    # agent-dec's flow registry carries the same canonical descriptor (not vendored: examples/flows is the registry)
    assert CANON.read_bytes() == (src / "flow-bound" / "flows" / "quote-issue.flow.yaml").read_bytes()
    assert not (DEC_DIR / "flows").exists()


def test_trust_bundle_is_agent_decs_with_the_three_classes():
    bundle = json.loads(TRUST_BUNDLE.read_text())
    assert bundle["format"] == "dec-trust/0.2"
    assert bundle["issuer"]["id"] == "operator.example"
    (key,) = bundle["keys"]
    assert key["key_id"] == "k-2026-10" and key["status"] == "active"
    assert key["public_key_pem"] == (DEC / "issuer-pubkey.pem").read_text()
    (pa,) = bundle["policy_authorities"]
    (ap,) = bundle["approvers"]
    assert (pa["id"], pa["key_id"]) == ("policy.operator.example", "p-2026-10") and (ap["id"], ap["key_id"]) == ("approver:a.example", "a-2026-10")
    assert len({key["key_id"], pa["key_id"], ap["key_id"]}) == 3                   # the three classes are disjoint by key id
    assert "flow_registries" not in bundle                                         # the registry is passed explicitly (--flow-registry)
    assert hashlib.sha256(TRUST_BUNDLE.read_bytes()).hexdigest() == "c8d2d734cf2c15168be841424edeff9e15828760daaf2cf3c8ef5d65a7403fe9"


def test_step_certificate_digests_match_manifest():
    """The digests the synthetic spans carry are agent-dec's cert_digest of the
    signed step certificates — recomputed here with RFC 8785."""
    import rfc8785
    run = json.loads((DEC_DIR / "run.dec.json").read_text())
    manifest = {m["flow_step"]: m["cert_digest"] for m in run["manifest"]["steps"]}
    for p in DEC_DIR.glob("step-*.dec.json"):
        c = json.loads(p.read_text())
        d = "sha256:" + hashlib.sha256(rfc8785.dumps(c)).hexdigest()
        assert manifest[c["subject"]["flow"]["step"]] == d
    assert run["subject"]["run_id"] == run["subject"]["trace_id"] == CERTIFIED_RUN
