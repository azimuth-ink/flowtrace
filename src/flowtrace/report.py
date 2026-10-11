"""coverage-report.json: schema validation and deterministic serialization."""
from __future__ import annotations

import json
import pathlib

from jsonschema import Draft202012Validator

_HERE = pathlib.Path(__file__).resolve().parent


def schema_path(name: str) -> pathlib.Path:
    """Installed package (schemas/ beside this module) or repo checkout (spec/schemas/)."""
    for cand in (_HERE / "schemas" / name, _HERE.parent.parent / "spec" / "schemas" / name):
        if cand.exists():
            return cand
    raise FileNotFoundError(f"schema not found: {name}")


def load_schema(name: str = "coverage-report.schema.json") -> dict:
    schema = json.loads(schema_path(name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return schema


def validate_report(report: dict) -> None:
    v = Draft202012Validator(load_schema())
    errs = sorted(v.iter_errors(report), key=lambda e: e.json_path)
    if errs:
        raise ValueError("coverage report does not match its schema:\n  " +
                         "\n  ".join(f"{e.json_path}: {e.message}" for e in errs[:10]))


def dumps(report: dict) -> str:
    """Stable bytes: sorted keys, 2-space indent, trailing newline, no NaN."""
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"


def write_report(report: dict, path: str | pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(dumps(report), encoding="utf-8")
    return p
