from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pe_c4_r2_numerical_robustness_v1.contracts import (
    FINAL_VARIANT_ID,
    NUMERIC_FAILURE_MESSAGES,
    VARIANTS,
    C4R2ContractError,
    SolverVariant,
    semantic_sha256,
    variant,
)
from research.model_zoo.pe_c4_r2_numerical_robustness_v1.runner import (
    _is_numeric_solver_failure,
)
from scripts.model_lab.pe_c4_r2_numerical_research_v1 import _stress_canonical


def test_variant_universe_and_final_fallback_are_frozen() -> None:
    assert len(VARIANTS) == 5
    assert len({item.variant_id for item in VARIANTS}) == 5
    final = variant(FINAL_VARIANT_ID)
    assert final.irls_max_iterations == 80
    assert final.irls_tolerance == 1e-8
    assert final.block_v04_fallback is True
    assert final.same_huber_objective is True
    assert final.same_box_constraints is True


def test_variant_rejects_objective_or_tolerance_drift() -> None:
    with pytest.raises(C4R2ContractError):
        SolverVariant("c4_r2_bad", 80, 1e-7, True)
    with pytest.raises(C4R2ContractError):
        SolverVariant(
            "c4_r2_bad",
            80,
            1e-8,
            True,
            same_huber_objective=False,
        )


def test_only_exact_numeric_failures_are_fallback_eligible() -> None:
    error_type = type("HierarchicalStateV7ContractError", (RuntimeError,), {})
    for message in NUMERIC_FAILURE_MESSAGES:
        assert _is_numeric_solver_failure(error_type(message)) is True
    assert _is_numeric_solver_failure(error_type("input schema drifted")) is False
    assert _is_numeric_solver_failure(RuntimeError(NUMERIC_FAILURE_MESSAGES[0])) is False


def test_semantic_hash_is_order_stable() -> None:
    assert semantic_sha256({"a": 1, "b": 2}) == semantic_sha256({"b": 2, "a": 1})


@pytest.mark.parametrize(
    "case", ("extreme_valuation", "many_active_constraints", "extreme_residuals")
)
def test_observed_pe_stress_preserves_causal_missing_mask(case: str) -> None:
    observed = np.linspace(10.0, 30.0, 600)
    observed[[0, 7, 80, 173, 599]] = np.nan
    frame = pd.DataFrame({"observed_pe": observed})

    stressed = _stress_canonical(frame, case)
    stressed_values = stressed["observed_pe"].to_numpy(dtype=np.float64)

    assert np.array_equal(np.isnan(stressed_values), np.isnan(observed))
    assert np.all(stressed_values[np.isfinite(stressed_values)] > 0.0)
