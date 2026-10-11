"""Byte identity of the shared artifacts: the canonical quote-issue descriptor
(one source, copied verbatim) and the signed DEC example (never hand-edited)."""
import hashlib
import json
import re

import pytest

from conftest import CANON, CANON_SHA256, DEC, DEC_DIR, FIXTURES, REPO, TRUST_BUNDLE, sibling


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
    src = sibling("agent-dec") / "examples" / "flow-bound"
    names = sorted(p.name for p in DEC_DIR.glob("*.dec.json"))
    assert names == ["run.dec.json"] + [f"step-s{i}.dec.json" for i in range(1, 7)]
    for n in names:
        assert (DEC_DIR / n).read_bytes() == (src / n).read_bytes(), n
    assert (DEC / "issuer-pubkey.pem").read_bytes() == (sibling("agent-dec") / "examples" / "issuer-pubkey.pem").read_bytes()
    # agent-dec's flow registry carries the same canonical descriptor
    assert CANON.read_bytes() == (src / "flows" / "quote-issue.flow.yaml").read_bytes()


def test_trust_bundle_is_built_from_the_example_issuer_key():
    bundle = json.loads(TRUST_BUNDLE.read_text())
    assert bundle["format"] == "dec-trust/0.2"
    assert bundle["issuer"]["id"] == "operator.example"
    (key,) = bundle["keys"]
    assert key["key_id"] == "k-2026-10" and key["status"] == "active"
    assert key["public_key_pem"] == (DEC / "issuer-pubkey.pem").read_text()
    assert bundle["flow_registries"][0]["ref"] == "../flows/"


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
    assert run["subject"]["run_id"] == run["subject"]["trace_id"] == "b8e06f909fc7110707032a18b942e128"
