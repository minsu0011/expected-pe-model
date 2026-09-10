from __future__ import annotations

import numpy as np
import pytest

from research.model_zoo.hofs_robustness_revision_r3.contracts import (
    CANDIDATES,
    FORMULA,
    SELECTION_ORDER,
    SPENT_PROXY_GATES,
    HofsRobustnessContractError,
    selection_lock_payload,
    validate_contract,
)
from research.model_zoo.hofs_robustness_revision_r3.prediction import derive_blend_matrix


def test_pre_score_lock_has_exact_candidate_surface_and_selection() -> None:
    validate_contract()
    payload = selection_lock_payload()
    assert FORMULA == "pred_log = v04_log + w*(hofs_r2_log-v04_log)"
    assert [item.weight for item in CANDIDATES] == [0.125, 0.25, 0.50, 0.75, 1.0]
    assert payload["additional_weights_allowed"] is False
    assert payload["refit_allowed"] is False
    assert payload["seed_dgp_truth_state_or_observable_routing_allowed"] is False
    assert tuple(payload["selection_order"]) == SELECTION_ORDER
    assert SPENT_PROXY_GATES["bootstrap_mae_gain_lower_5pct_strictly_greater_than"] == 0.0


def test_blend_matrix_uses_only_global_formula_and_exact_r2_control() -> None:
    v04 = np.array([2.0, 3.0, 4.0])
    hofs = np.array([4.0, 2.0, 3.0])
    actual = derive_blend_matrix(v04, hofs)
    expected = np.column_stack(
        [v04 + item.weight * (hofs - v04) for item in CANDIDATES]
    )
    np.testing.assert_allclose(actual, expected, rtol=0.0, atol=0.0)
    np.testing.assert_array_equal(actual[:, -1], hofs)


@pytest.mark.parametrize(
    ("v04", "hofs"),
    [
        (np.array([[1.0]]), np.array([1.0])),
        (np.array([1.0]), np.array([1.0, 2.0])),
        (np.array([]), np.array([])),
        (np.array([np.nan]), np.array([1.0])),
        (np.array([1.0]), np.array([np.inf])),
    ],
)
def test_blend_matrix_rejects_invalid_operands(v04: np.ndarray, hofs: np.ndarray) -> None:
    with pytest.raises(HofsRobustnessContractError):
        derive_blend_matrix(v04, hofs)
