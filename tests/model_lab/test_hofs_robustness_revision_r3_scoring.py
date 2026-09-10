from __future__ import annotations

from copy import deepcopy

from research.model_zoo.hofs_robustness_revision_r3.scoring import (
    apply_predeclared_selection,
)


def _eligible(candidate_id: str, weight: float, lower: float, pooled: float) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "global_weight": weight,
        "mae_gain_vs_v04": pooled,
        "rmse_gain_vs_v04": 0.01,
        "seed_dgp_wins": 35,
        "seed_dgp_total": 50,
        "dgp_mean_wins": 7,
        "dgp_total": 10,
        "worst_dgp_mean_harm": 0.02,
        "worst_seed_dgp_harm": 0.04,
        "pooled_p95_non_worse": True,
        "extreme_frequency_non_worse": True,
        "bootstrap_mae_gain_lower_5pct": lower,
    }


def test_predeclared_selection_uses_lower_then_pooled_then_larger_weight() -> None:
    rows = [
        _eligible("hofs_r3_global_log_shrink_w0125", 0.125, 0.01, 0.03),
        _eligible("hofs_r3_global_log_shrink_w0250", 0.25, 0.02, 0.02),
        _eligible("hofs_r3_global_log_shrink_w0500", 0.50, 0.02, 0.04),
        _eligible("hofs_r3_global_log_shrink_w0750", 0.75, 0.02, 0.04),
        _eligible("hofs_r3_global_log_shrink_w1000_r2_control", 1.0, 0.015, 0.08),
    ]
    expanded, decision = apply_predeclared_selection(rows)
    assert decision["selected_candidate_id"] == "hofs_r3_global_log_shrink_w0750"
    assert decision["robust_r3_deserves_final_research_freeze"] is True
    selected = next(row for row in expanded if row["selected_by_predeclared_rule"])
    assert selected["selection_rank"] == 1


def test_no_candidate_passes_means_stop_without_sweep() -> None:
    rows = [
        _eligible("hofs_r3_global_log_shrink_w0125", 0.125, 0.01, 0.03),
        _eligible("hofs_r3_global_log_shrink_w0250", 0.25, 0.01, 0.03),
        _eligible("hofs_r3_global_log_shrink_w0500", 0.50, 0.01, 0.03),
        _eligible("hofs_r3_global_log_shrink_w0750", 0.75, 0.01, 0.03),
        _eligible("hofs_r3_global_log_shrink_w1000_r2_control", 1.0, 0.01, 0.03),
    ]
    failed = []
    for row in rows:
        item = deepcopy(row)
        item["worst_dgp_mean_harm"] = 0.031
        failed.append(item)
    expanded, decision = apply_predeclared_selection(failed)
    assert not any(row["selection_eligible"] for row in expanded)
    assert decision["status"] == "NO_ELIGIBLE_CANDIDATE_STOP_NO_NEW_SWEEP"
    assert decision["selected_candidate_id"] is None
    assert decision["no_additional_sweep_authorized"] is True
