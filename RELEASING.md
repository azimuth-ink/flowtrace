# Releasing

## Versioning
- Repo releases are semver git tags (`vX.Y.Z`); `pyproject.toml`, `CITATION.cff`,
  `.zenodo.json` and the `CHANGELOG.md` heading must agree (`tests/test_packaging.py`
  enforces it). The software version, the paper version (FTC v1.x) and the
  companion pins (`.github/workflows/gate.yml`, `pyproject.toml`) evolve independently.

## Procedure
1. Ensure `main` is green (the `gate` workflow) and the companion pins point at
   commits that exist on GitHub (`make dev-pinned` resolves).
2. Tag and push:
   ```bash
   git tag -a v0.1.0 -m "v0.1.0"
   git push origin v0.1.0
   ```
3. The `release` workflow re-runs the gate with the pinned companions, builds the
   source zip and the paper PDF (`paper/flow-based-telemetry-coverage.tex` via
   latexmk), and publishes a GitHub Release with those assets.
4. If the Zenodo–GitHub integration is enabled for this repository, Zenodo
   archives the release and mints a **software** version DOI under the software
   concept record, from `.zenodo.json`. Enable it once, on Zenodo's GitHub page,
   after the repository exists.

## The paper's own record is separate
The method's Zenodo record (concept DOI 10.5281/zenodo.21415947, a CC0 defensive
publication) is a preprint deposit, not the software archive. A new paper version
is uploaded there by hand: take the PDF the release built, create a new version of
the preprint record, and then paste the version DOI Zenodo assigns into the
paper's DOI line (`paper/flow-based-telemetry-coverage.md` and `.tex`) in a
follow-up `docs:` commit — the PDF cannot carry its own version DOI, and the
concept DOI in the text already resolves to the latest version.
