"""FTC §4.2: score -> tier -> policy; alias handling."""
import pytest

from flowtrace.tiering import (normalize_criticality, policy, score_from_dimensions, step_criticality,
                               tier_from_dimensions, tier_from_score)


@pytest.mark.parametrize("score,tier", [(7.0, "P0"), (9.9, "P0"), (6.99, "P1"), (5.0, "P1"), (4.99, "P2"), (3.0, "P2"), (2.99, "P3"), (0, "P3")])
def test_tier_thresholds_from_the_policy_table(cfg, score, tier):
    assert tier_from_score(score, cfg) == tier


def test_any_maximal_dimension_forces_p0(cfg):
    tier, score = tier_from_dimensions({"revenue_impact": "low", "user_impact": "low", "frequency": "critical"}, cfg)
    assert score < 7.0 and tier == "P0"
    assert tier_from_score(1.0, cfg, any_maximal=True) == "P0"


def test_weighted_sum_over_scale_words_and_numbers(cfg):
    score, maximal = score_from_dimensions({"revenue_impact": "high", "user_impact": 7, "frequency": "medium",
                                            "data_sensitivity": "low", "operational_complexity": "low"}, cfg)
    assert score == pytest.approx(0.3 * 7 + 0.3 * 7 + 0.15 * 4 + 0.15 * 1 + 0.10 * 1)
    assert maximal is False
    with pytest.raises(ValueError):
        score_from_dimensions({"revenue_impact": "enormous"}, cfg)
    with pytest.raises(ValueError):
        score_from_dimensions({"revenue_impact": 11}, cfg)


def test_policy_table_defaults(cfg):
    p0, p3 = policy(cfg, "P0"), policy(cfg, "P3")
    assert (p0.coverage_threshold, p0.sampling_floor, p0.alert_latency_s, p0.ir_sla_s) == (1.0, 1.0, 60, 900)
    assert p0.require_convergent and p0.answerability_required
    assert (p3.coverage_threshold, p3.sampling_floor, p3.alert_latency_s, p3.ir_sla_s) == (0.5, 0.1, 3600, None)
    assert not p3.require_convergent and not p3.answerability_required
    assert p0.as_dict()["tier"] == "P0"


def test_deprecated_aliases_map_with_a_warning():
    warnings = []
    assert normalize_criticality("tier-1", warnings, "metadata") == "P0"
    assert normalize_criticality("tier-3", warnings) == "P2"
    assert normalize_criticality("critical", warnings) == "P0"
    assert normalize_criticality("low", warnings) == "P3"
    assert normalize_criticality("P1", warnings) == "P1"
    assert normalize_criticality(None, warnings) is None
    assert len(warnings) == 4 and all("R-DEPRECATED" in w for w in warnings)
    with pytest.raises(ValueError):
        normalize_criticality("P9")


def test_step_criticality_defaults_to_flow():
    assert step_criticality({"id": "s1"}, "P0") == "P0"
    assert step_criticality({"id": "s1", "criticality": "P2"}, "P0") == "P2"
    w = []
    assert step_criticality({"id": "s1", "criticality": "tier-2"}, "P0", w) == "P1" and w
