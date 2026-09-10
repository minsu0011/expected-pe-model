from __future__ import annotations

import json
import os
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.observable_fair_value_state_v1_ablation.contracts import (
    AblationContractError,
    DECISION_GATES,
    ELIGIBLE_ABLATIONS,
    EXPECTED_FOLD_COUNT,
    EXPECTED_SCORE_ROWS_PER_SEED,
    FOLD_SPEC,
    HISTGB_PARAMETERS,
    LGBM_PARAMETERS,
    MODEL_IDS,
    SOURCE_LANES,
    STATE_CONTRACT_SHA256,
    V04_BASELINE_FEATURES,
    assert_runtime_path_allowed,
    design_payload,
    feature_sets,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.custody import (
    project_root,
    run_source_scan,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.deterministic import (
    CORRELATION_ALGORITHM_ID,
    fixed_order_correlation,
)
from research.model_zoo.observable_fair_value_state_v1_ablation.evaluation import (
    _decision_rows,
)


def test_design_is_fixed_matched_and_score_blind() -> None:
    payload = design_payload()
    assert payload["score_blind_design"] is True
    assert payload["promotion_authority"] is False
    assert payload["observable_state_contract_sha256"] == STATE_CONTRACT_SHA256
    assert len(V04_BASELINE_FEATURES) == 36
    assert len(ELIGIBLE_ABLATIONS) == 4
    assert len(MODEL_IDS) == 7
    assert set(feature_sets()) == set(MODEL_IDS)
    assert LGBM_PARAMETERS["n_jobs"] == 1
    assert LGBM_PARAMETERS["deterministic"] is True
    assert HISTGB_PARAMETERS["loss"] == "absolute_error"
    assert payload["models"]["no_hyperparameter_sweep"] is True
    assert (
        payload["regime_probability_provenance"]["full_sequence_smoothed_probability_input_allowed"]
        is False
    )


def test_fold_surface_is_exact_prefix_schedule() -> None:
    starts = FOLD_SPEC.starts()
    assert len(starts) == EXPECTED_FOLD_COUNT == 62
    assert starts[0] == 504
    assert starts[-1] == 1785
    assert FOLD_SPEC.first_fold_number == 12
    emitted = sum(min(1800, start + 21) - start for start in starts)
    assert emitted == EXPECTED_SCORE_ROWS_PER_SEED == 1296
    assert FOLD_SPEC.training_window == "expanding_prefix"
    assert FOLD_SPEC.within_fold_refit is False
    assert FOLD_SPEC.same_row_observed_pe_feature_allowed is False


def test_runtime_path_guard_accepts_only_exact_spent_qualification_paths() -> None:
    root = project_root()
    lane = SOURCE_LANES[0]
    seed = lane.seeds[0]
    accepted = (
        root
        / lane.root_relative
        / "runtime"
        / "qualification"
        / "canonical"
        / f"seed_{seed}"
        / "canonical.csv"
    )
    assert assert_runtime_path_allowed(accepted, root, purpose="canonical") == accepted.resolve()
    attacked = root / "outputs" / ("held" + "out") / "canonical" / f"seed_{seed}" / "canonical.csv"
    with pytest.raises(AblationContractError, match="forbidden"):
        assert_runtime_path_allowed(attacked, root, purpose="canonical")
    wrong_stage = (
        root
        / lane.root_relative
        / "runtime"
        / "qualification_extra"
        / "canonical"
        / f"seed_{seed}"
        / "canonical.csv"
    )
    with pytest.raises(AblationContractError, match="allowlist"):
        assert_runtime_path_allowed(wrong_stage, root, purpose="canonical")


def test_operational_source_scan_and_prediction_truth_separation() -> None:
    root = project_root()
    receipt = run_source_scan(root)
    assert receipt["passed"]
    assert receipt["sealed_surface_reference_count"] == 0
    prediction_source = (
        root
        / "research"
        / "model_zoo"
        / "observable_fair_value_state_v1_ablation"
        / "prediction.py"
    ).read_text(encoding="utf-8")
    assert "evaluation_truth_path" not in prediction_source
    assert "truth_vault" not in prediction_source


def _metric_frame(model_values: dict[str, tuple[float, float, float]]) -> pd.DataFrame:
    records = []
    for model_id, (mae, rmse, p95) in model_values.items():
        records.append(
            {
                "model_id": model_id,
                "rows": 12960,
                "mae": mae,
                "rmse": rmse,
                "p95_abs_error": p95,
                "p99_abs_error": p95 * 1.2,
                "max_abs_error": p95 * 1.5,
            }
        )
    return pd.DataFrame(records)


def test_decision_gate_thresholds_are_frozen_and_separate_by_estimator() -> None:
    assert DECISION_GATES["strong_survivor"]["pooled_mae_relative_gain_min"] == 0.005
    values: dict[str, tuple[float, float, float]] = {}
    for model_id in MODEL_IDS:
        if model_id.endswith("v04_exact_baseline"):
            values[model_id] = (0.0400, 0.0500, 0.0800)
        else:
            values[model_id] = (0.0390, 0.0490, 0.0790)
    pooled = _metric_frame(values)
    per_seed_records = []
    for seed in range(10):
        for model_id, (mae, rmse, p95) in values.items():
            per_seed_records.append(
                {
                    "seed": seed,
                    "model_id": model_id,
                    "mae": mae,
                    "rmse": rmse,
                    "p95_abs_error": p95,
                }
            )
    decisions = _decision_rows(pooled, pd.DataFrame(per_seed_records))
    assert len(decisions) == 5
    assert {row["decision"] for row in decisions} == {"STRONG_SURVIVOR"}


def test_fixed_order_correlation_is_hashseed_byte_stable() -> None:
    left = np.array([0.1, -0.2, 0.3, 0.4, -0.05], dtype=np.float64)
    right = np.array([-0.3, 0.2, 0.15, 0.7, -0.1], dtype=np.float64)
    value = fixed_order_correlation(left, right)
    assert np.isfinite(value)
    assert CORRELATION_ALGORITHM_ID == "FIXED_ORDER_MATH_FSUM_CENTERED_FLOAT64_V1"
    code = (
        "import json,numpy as np;"
        "from research.model_zoo.observable_fair_value_state_v1_ablation.deterministic "
        "import fixed_order_correlation;"
        "x=np.array([0.1,-0.2,0.3,0.4,-0.05],dtype=np.float64);"
        "y=np.array([-0.3,0.2,0.15,0.7,-0.1],dtype=np.float64);"
        "print(json.dumps({'correlation':fixed_order_correlation(x,y)},sort_keys=True,separators=(',',':')))"
    )
    outputs = []
    root = project_root()
    for hash_seed in ("1", "777"):
        environment = os.environ.copy()
        environment["PYTHONHASHSEED"] = hash_seed
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(root / "src"), str(root), environment.get("PYTHONPATH", "")]
        )
        completed = subprocess.run(
            [sys.executable, "-c", code],
            cwd=root,
            env=environment,
            check=True,
            capture_output=True,
        )
        outputs.append(completed.stdout)
    assert outputs[0] == outputs[1]
    assert json.loads(outputs[0])["correlation"] == value
