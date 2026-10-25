"""Versions agree within the repo; the package ships its schemas and defaults;
the pins to the companion repositories are recorded consistently."""
import json
import re

import yaml

from conftest import REPO
import flowtrace

VERSION = "0.1.0"
PINS = {"polydiagram": "e768f1c", "agent-dec": "89fdc36"}


def test_versions_agree():
    assert flowtrace.__version__ == VERSION
    assert re.search(r'^version = "(.+)"$', (REPO / "pyproject.toml").read_text(), re.M).group(1) == VERSION
    cff = yaml.safe_load((REPO / "CITATION.cff").read_text())
    assert cff["version"] == VERSION and str(cff["date-released"]) == "2026-10-10" and "doi" not in cff
    zen = json.loads((REPO / ".zenodo.json").read_text())
    assert zen["version"] == VERSION and zen["publication_date"] == "2026-10-10" and "doi" not in zen
    changelog = (REPO / "CHANGELOG.md").read_text()
    assert f"## [{VERSION}] — 2026-10-10" in changelog and "### 2026-10-15 — control-plane mechanics" in changelog
    spec = (REPO / "spec" / "coverage-engine.md").read_text()
    assert f"software {VERSION}" in spec


def test_pins_recorded_consistently():
    py = (REPO / "pyproject.toml").read_text()
    readme = (REPO / "README.md").read_text()
    wf = (REPO / ".github" / "workflows" / "gate.yml").read_text()
    for repo, sha in PINS.items():
        ref = f"azimuth-ink/{repo}@{sha}"
        assert f"git+https://github.com/{ref}" in py, ref
        assert ref in readme, ref
        assert sha in wf, ref
    assert "azimuth-ink/agent-dec\n#   pin:        89fdc36" in (REPO / "examples" / "dec" / "SOURCE").read_text()
    mk = (REPO / "Makefile").read_text()
    cff = (REPO / "CITATION.cff").read_text()
    for repo, sha in PINS.items():
        assert f"azimuth-ink/{repo}@{sha}" in mk and f"azimuth-ink/{repo}@{sha}" in cff, (repo, sha)


def test_installed_package_finds_schemas_and_defaults():
    from flowtrace.config import default_config_path
    from flowtrace.report import schema_path
    assert default_config_path().name == "flowtrace.yaml"
    assert schema_path("coverage-report.schema.json").exists()
    assert schema_path("verification-query.schema.json").exists()
    py = (REPO / "pyproject.toml").read_text()
    for f in ("spec/schemas/coverage-report.schema.json", "spec/schemas/verification-query.schema.json", "flowtrace.yaml"):
        assert f'"{f}"' in py


def test_verification_query_schema_accepts_the_shipped_binding():
    from jsonschema import Draft202012Validator
    schema = json.loads((REPO / "spec" / "schemas" / "verification-query.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    v = Draft202012Validator(schema)
    doc = yaml.safe_load((REPO / "examples" / "queries" / "quote-issue.queries.yaml").read_text())
    assert list(v.iter_errors(doc)) == []
    assert list(v.iter_errors({"dialect": "otel-sql", "text": "SELECT 1", "expected_shape": {"min_rows": 1}})) == []
    assert list(v.iter_errors({"dialect": "otel-sql"})) != []


def test_no_ds_store_and_required_files():
    assert not list(REPO.rglob(".DS_Store"))
    for f in ("README.md", "LICENSE", "CITATION.cff", ".zenodo.json", "CHANGELOG.md", "requirements-dev.txt",
              "flowtrace.yaml", "spec/coverage-engine.md", ".github/workflows/gate.yml", "paper/flow-based-telemetry-coverage.md"):
        assert (REPO / f).exists(), f
    assert "CC0" in (REPO / "LICENSE").read_text() and "Apache License" in (REPO / "LICENSE").read_text()
