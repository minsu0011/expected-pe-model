from __future__ import annotations

import hashlib
import inspect
from pathlib import Path

from research.model_zoo.prospective_fresh_ensemble_v1.authorization import blocked_status
from research.model_zoo.prospective_fresh_ensemble_v1.contracts import (
    CANDIDATE_DIGEST_SHA256,
    CANDIDATE_FAMILY,
    CANDIDATE_ID,
    CANDIDATE_MEMBERS,
    CHEAP_EXPECTED_ROWS,
    CHEAP_FOLD_IDS,
    FULL_EXPECTED_FOLDS,
    FULL_EXPECTED_ROWS,
    QUALIFICATION_GATES,
    S4_FEATURE_COLUMNS,
    S4_PARAMETERS,
    candidate_payload,
    canonical_json_bytes,
)
from research.model_zoo.prospective_fresh_ensemble_v1.evaluation import EvaluationTask
from research.model_zoo.prospective_fresh_ensemble_v1.prediction import PredictionTask
from research.model_zoo.prospective_fresh_ensemble_v1.seed_ledger import (
    heldout_commitment,
    next_prime_seeds,
    read_registry,
)
from research.model_zoo.structural_v7 import contracts as v7_contracts
from research.model_zoo.structural_v7 import folds as v7_folds
from research.model_zoo.structural_v7 import models as v7_models


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_candidate_is_the_one_precommitted_level_median() -> None:
    preimage = CANDIDATE_FAMILY + "|" + "|".join(sorted(CANDIDATE_MEMBERS))
    assert hashlib.sha256(preimage.encode()).hexdigest() == CANDIDATE_DIGEST_SHA256
    assert CANDIDATE_ID == "pointwise_level_median3__5c65a5a85e727116ebe8"
    assert candidate_payload()["search_space_size"] == 1
    assert candidate_payload()["runner_up_allowed"] is False
    assert CANDIDATE_MEMBERS == (
        "s4_decomposition_ridge_ar1_with_regime_v7",
        "v04_expected_pe",
        "v04_ml_expected_pe_no_regime",
    )


def test_exact_s4_contract_and_frozen_v7_sources() -> None:
    assert len(S4_FEATURE_COLUMNS) == 36
    assert S4_FEATURE_COLUMNS == v7_contracts.REGIME_RESIDUAL_FEATURES
    assert S4_PARAMETERS["ridge_alpha"] == 10.0
    assert S4_PARAMETERS["ridge_solver"] == "svd"
    assert S4_PARAMETERS["within_test_update"] is False
    source = inspect.getsource(v7_models.fit_decomposition_ar)
    assert 'Ridge(alpha=10.0, solver="svd", fit_intercept=True)' in source
    assert "_fit_ar1(np.log(target) - structural)" in source
    assert _sha(Path(v7_models.__file__)) == "20f3a862603017691b25b241c561d6403efc36b21fdd50a55a0b10ba8c657787"
    assert _sha(Path(v7_folds.__file__)) == "45dcb158e714074eb1434dd96bc20d68f3cfb301bb90e3a7e68804266aaad354"
    assert _sha(Path(v7_contracts.__file__)) == "98602980edfbb6b7258b19c49e0b9f6e5c12e81a689e31a543aad16719e08f46"


def test_full_primary_and_fixed_cheap_secondary_surfaces() -> None:
    import pandas as pd

    folds = v7_folds.build_outer_folds(pd.bdate_range("2013-01-02", periods=1800))
    assert len(folds) == FULL_EXPECTED_FOLDS == 62
    assert sum(fold.test_rows for fold in folds) == FULL_EXPECTED_ROWS == 1296
    cheap = [fold for fold in folds if fold.fold_id in CHEAP_FOLD_IDS]
    assert tuple(fold.fold_id for fold in cheap) == CHEAP_FOLD_IDS
    assert sum(fold.test_rows for fold in cheap) == CHEAP_EXPECTED_ROWS == 246


def test_prediction_and_evaluation_addresses_are_type_separated() -> None:
    prediction_fields = set(PredictionTask.__dataclass_fields__)
    evaluation_fields = set(EvaluationTask.__dataclass_fields__)
    assert not any(token in field for field in prediction_fields for token in ("truth", "fair", "evaluation"))
    assert "synthetic_truth_csv" in evaluation_fields
    assert "synthetic_truth_csv" not in prediction_fields


def test_qualification_gates_are_exact_and_terminal() -> None:
    assert QUALIFICATION_GATES["pooled_fair_log_mae_relative_gain_strictly_greater_than"] == 0.0
    assert QUALIFICATION_GATES[
        "pooled_fair_log_rmse_relative_gain_greater_than_or_equal_to"
    ] == 0.0
    assert QUALIFICATION_GATES["minimum_seed_mae_wins"] == 3
    assert QUALIFICATION_GATES["maximum_worst_seed_mae_relative_harm"] == 0.03
    assert QUALIFICATION_GATES["full_coverage_required"] is True
    assert QUALIFICATION_GATES["deterministic_replay_required"] is True
    assert QUALIFICATION_GATES["pit_train_prefix_only_required"] is True
    assert QUALIFICATION_GATES["failure_action"] == "STOP_ALL_MARK_QUALIFICATION_SPENT_NO_RUNNER_UP"


def test_seed_derivation_is_deterministic_and_registry_is_valid() -> None:
    planned = next_prime_seeds(7207, 10)
    assert planned == (7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297)
    assert heldout_commitment(planned[5:]) == hashlib.sha256(
        canonical_json_bytes({"locked_seeds": list(planned[5:])})
    ).hexdigest()
    registry = read_registry(PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json")
    assert registry["registry_id"] == "v04-prospective-spent-seeds-v1"


def test_prelaunch_is_fail_closed_without_two_approvals(tmp_path: Path) -> None:
    status = blocked_status(tmp_path)
    assert status == {
        "qualification_audit_present": False,
        "qualification_root_approval_present": False,
        "qualification_launch_authorized": False,
        "heldout_unlock_present": False,
        "heldout_launch_authorized": False,
    }
