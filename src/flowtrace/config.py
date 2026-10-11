"""Configuration: the shipped defaults (flowtrace.yaml) merged under a user file.

The defaults file is the single source of every tunable constant; this module
only loads, merges and lightly validates it. See flowtrace.yaml for the FTC
section each constant comes from.
"""
from __future__ import annotations

import copy
import pathlib
from typing import Any, Mapping

import yaml

from . import CONFIG_API_VERSION

_HERE = pathlib.Path(__file__).resolve().parent

TIERS = ("P0", "P1", "P2", "P3")
ND_CLASSES = ("ND0", "ND1", "ND2", "ND3")
REPLAYABLE_ND_CLASSES = ("ND0", "ND1")
COMPONENTS = ("completeness", "answerability", "detectability", "cost_attribution", "execution_evidence")


class ConfigError(ValueError):
    pass


def default_config_path() -> pathlib.Path:
    """flowtrace.yaml in the installed package (force-included) or the repo root."""
    for cand in (_HERE / "flowtrace.yaml", _HERE.parent.parent / "flowtrace.yaml"):
        if cand.exists():
            return cand
    raise ConfigError("default flowtrace.yaml not found (package and repo layouts)")


def _deep_merge(base: dict, over: Mapping) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_config(path: str | pathlib.Path | None = None) -> dict:
    """Defaults merged under `path` (if given). Raises ConfigError on a
    document that is not a mapping or declares a different apiVersion."""
    base = yaml.safe_load(default_config_path().read_text(encoding="utf-8"))
    if path is None:
        cfg = base
    else:
        user = yaml.safe_load(pathlib.Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(user, Mapping):
            raise ConfigError(f"{path}: configuration is not a mapping")
        api = user.get("apiVersion", CONFIG_API_VERSION)
        if api != CONFIG_API_VERSION:
            raise ConfigError(f"{path}: apiVersion {api!r} is not {CONFIG_API_VERSION}")
        cfg = _deep_merge(base, user)
    validate_config(cfg)
    return cfg


def validate_config(cfg: Mapping[str, Any]) -> None:
    tiers = cfg.get("tiers") or {}
    for t in TIERS:
        if t not in tiers:
            raise ConfigError(f"tiers.{t} missing")
        thr = tiers[t].get("coverage_threshold")
        if not isinstance(thr, (int, float)) or not 0 <= thr <= 1:
            raise ConfigError(f"tiers.{t}.coverage_threshold must be in [0, 1]")
    sc = cfg.get("scoring") or {}
    for key, names in (("weights", COMPONENTS[:4]), ("weights_with_execution_evidence", COMPONENTS)):
        w = sc.get(key) or {}
        missing = [n for n in names if n not in w]
        if missing:
            raise ConfigError(f"scoring.{key} missing {missing}")
        total = sum(float(w[n]) for n in names)
        if abs(total - 1.0) > 1e-9:
            raise ConfigError(f"scoring.{key} weights sum to {total}, not 1.0")
    dec = cfg.get("decomposition") or {}
    for key in ("criticality_factor", "error_factor"):
        for t in TIERS:
            if t not in (dec.get(key) or {}):
                raise ConfigError(f"decomposition.{key}.{t} missing")
    for c in ND_CLASSES + ("none",):
        if c not in (dec.get("nd_factor") or {}):
            raise ConfigError(f"decomposition.nd_factor.{c} missing")


def weights_for(cfg: Mapping[str, Any], execution_evidence: bool) -> dict[str, float]:
    sc = cfg["scoring"]
    key = "weights_with_execution_evidence" if execution_evidence else "weights"
    return {k: float(v) for k, v in sc[key].items()}
