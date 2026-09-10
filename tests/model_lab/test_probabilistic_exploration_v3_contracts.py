from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.probabilistic_exploration_v2.contracts import (
    ExplorationContractError,
)
from research.model_zoo.probabilistic_exploration_v3.closure import (
    file_record,
    verify_records,
    verify_runtime_closure,
)
from research.model_zoo.probabilistic_exploration_v3.adapters import make_adapter
from research.model_zoo.probabilistic_exploration_v3.design import (
    CATBOOST_GPU_INDEPENDENT_CANDIDATE_ID,
    CANDIDATE_BACKEND,
    CHEAP_FOLD_IDS,
    CHEAP_FOLD_ROW_COUNTS,
    EXPECTED_ALL_CANDIDATE_ROWS,
    EXPECTED_REDUCED_ROWS_PER_MODEL,
    EXPECTED_REDUCED_ROWS_PER_SEED,
    GPU_CANDIDATE_IDS,
    GPU_NUMERICAL_CONTRACT,
    LOCKED_CANDIDATES,
    FEATURE_COLUMNS,
    EXPECTED_DROPPED_FEATURES_BY_FOLD,
    SPENT_SEEDS,
    design_payload,
    verify_design_file,
)
from research.model_zoo.probabilistic_exploration_v3.governance import (
    load_v3_inventory,
)
from research.model_zoo.probabilistic_exploration_v3.inputs import (
    load_full_and_reduced_identity,
    load_prediction_inputs,
)
from research.model_zoo.probabilistic_exploration_v3.runner import (
    select_fold_feature_subset,
)


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"


def test_terminal_fold_geometry_is_exactly_refrozen() -> None:
    _, _, v2_inventory = load_v3_inventory(ROOT, BASE / "INPUT_INVENTORY.json")
    _, reduced = load_full_and_reduced_identity(ROOT, v2_inventory)
    assert CHEAP_FOLD_ROW_COUNTS["fold_073"] == 15
    assert EXPECTED_REDUCED_ROWS_PER_SEED == 246
    assert EXPECTED_REDUCED_ROWS_PER_MODEL == 1230
    assert EXPECTED_ALL_CANDIDATE_ROWS == 4920
    for seed, frame in reduced.groupby("seed", sort=True):
        assert len(frame) == 246, seed
        assert frame.groupby("fold_id", sort=False).size().to_dict() == CHEAP_FOLD_ROW_COUNTS


def test_design_lock_is_exact_source_mirror() -> None:
    assert verify_design_file(BASE / "DESIGN_LOCK.json") == design_payload()


def test_full_load_candidate_backends_are_explicit() -> None:
    for model_id, candidate in LOCKED_CANDIDATES.items():
        parameters = candidate["parameters"]
        if model_id in GPU_CANDIDATE_IDS:
            backend = parameters.get("device_type", parameters.get("task_type"))
            assert str(backend).casefold() == "gpu"
        else:
            assert model_id == "histgb_quantile_with_regime_exploration_v1"
            assert "device_type" not in parameters and "task_type" not in parameters
    assert GPU_NUMERICAL_CONTRACT["lightgbm"]["backend"] == "WINDOWS_OPENCL_GPU"
    assert GPU_NUMERICAL_CONTRACT["lightgbm"]["bit_exact_repeat_required"] is False
    assert (
        GPU_NUMERICAL_CONTRACT["catboost"]["same_seed_bit_exact_repeat_required"]
        is False
    )
    assert CANDIDATE_BACKEND == {
        "lightgbm_quantile_with_regime_exploration_v1": (
            "WINDOWS_OPENCL_GPU_DEVICE_0"
        ),
        "catboost_gpu_independent_quantiles_v1": (
            "CATBOOST_GPU_DEVICE_0"
        ),
        "histgb_quantile_with_regime_exploration_v1": "CPU_ONLY",
        "conformal_lgbm_residual_with_regime_exploration_v1": (
            "WINDOWS_OPENCL_GPU_DEVICE_0"
        ),
    }
    preflight = design_payload()["gpu_backend_preflight"]
    assert preflight["required_before_heavy_prediction_approval"] is True
    assert preflight["truth_opened"] is False
    assert preflight["score_or_evaluator_computed"] is False
    assert preflight["bit_exact_repeat_required"] is False


def test_v3_2_replaces_broken_catboost_without_changing_other_configs() -> None:
    failed_v3_1 = json.loads(
        (
            ROOT
            / "outputs"
            / "model_zoo_probabilistic_exploration_v3_1_design_20260820"
            / "DESIGN_LOCK.json"
        ).read_text(encoding="utf-8")
    )
    unchanged_ids = (
        "lightgbm_quantile_with_regime_exploration_v1",
        "histgb_quantile_with_regime_exploration_v1",
        "conformal_lgbm_residual_with_regime_exploration_v1",
    )
    for model_id in unchanged_ids:
        assert LOCKED_CANDIDATES[model_id] == failed_v3_1["candidates"][model_id]
    assert "catboost_multiquantile_with_regime_exploration_v1" not in LOCKED_CANDIDATES
    candidate = LOCKED_CANDIDATES[CATBOOST_GPU_INDEPENDENT_CANDIDATE_ID]
    assert candidate["family"] == "catboost_gpu_independent_quantiles"
    assert candidate["fit_sequence"] == "ascending_alpha_serial"
    assert candidate["parameters"]["loss_function_family"] == "Quantile"
    assert candidate["parameters"]["quantiles"] == [0.1, 0.25, 0.5, 0.75, 0.9]


def test_catboost_gpu_independent_adapter_fits_five_alphas_and_rearranges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import catboost

    fitted: list[dict[str, object]] = []

    class FakeCatBoostRegressor:
        def __init__(self, **parameters: object) -> None:
            self.parameters = parameters
            fitted.append(parameters)

        def fit(self, x: pd.DataFrame, y: np.ndarray) -> None:
            assert len(x) == len(y) == 3

        def predict(self, x: pd.DataFrame) -> np.ndarray:
            alpha = float(str(self.parameters["loss_function"]).split("=")[1])
            return np.full(len(x), 1.0 - alpha)

    monkeypatch.setattr(catboost, "CatBoostRegressor", FakeCatBoostRegressor)
    active = tuple(column for column in FEATURE_COLUMNS if column != "eps_disagreement")
    train = pd.DataFrame(np.ones((3, len(active))), columns=active)
    test = pd.DataFrame(np.ones((2, len(active))), columns=active)
    adapter = make_adapter(CATBOOST_GPU_INDEPENDENT_CANDIDATE_ID)
    adapter.fit(train, pd.Series([10.0, 11.0, 12.0]), seed=6301, fold_id="fold_012")
    prediction = adapter.predict(test, seed=6301, fold_id="fold_012")
    assert [item["loss_function"] for item in fitted] == [
        "Quantile:alpha=0.1",
        "Quantile:alpha=0.25",
        "Quantile:alpha=0.5",
        "Quantile:alpha=0.75",
        "Quantile:alpha=0.9",
    ]
    assert len({item["random_seed"] for item in fitted}) == 5
    quantiles = prediction.filter(like="predicted_pe_p").to_numpy()
    assert (np.diff(quantiles, axis=1) >= 0.0).all()
    assert adapter.crossing_diagnostics is not None
    assert adapter.crossing_diagnostics["raw_crossing_rows"] == 2


def test_source_drift_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    record = file_record(source, root=tmp_path)
    verify_records(tmp_path, [record])
    source.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(ExplorationContractError, match="drift"):
        verify_records(tmp_path, [record])


def test_feature_drop_uses_train_missingness_not_test_values() -> None:
    train = pd.DataFrame(np.ones((3, len(FEATURE_COLUMNS))), columns=FEATURE_COLUMNS)
    test_a = pd.DataFrame(np.zeros((2, len(FEATURE_COLUMNS))), columns=FEATURE_COLUMNS)
    test_b = pd.DataFrame(np.full((2, len(FEATURE_COLUMNS)), 999.0), columns=FEATURE_COLUMNS)
    train["eps_disagreement"] = np.nan
    train["forecast_p_bear"] = np.nan
    left_train, left_test, left_active, left_dropped = select_fold_feature_subset(
        train, test_a
    )
    right_train, right_test, right_active, right_dropped = select_fold_feature_subset(
        train, test_b
    )
    assert left_active == right_active
    assert left_dropped == right_dropped == ("eps_disagreement", "forecast_p_bear")
    assert tuple(left_train.columns) == tuple(right_train.columns) == left_active
    assert tuple(left_test.columns) == tuple(right_test.columns) == left_active
    assert not left_test.equals(right_test)


def test_locked_inputs_match_feature_availability_refreeze() -> None:
    _, _, v2_inventory = load_v3_inventory(ROOT, BASE / "INPUT_INVENTORY.json")
    features, labels, identity = load_prediction_inputs(ROOT, v2_inventory)
    for seed in SPENT_SEEDS:
        seed_features = features.loc[features["seed"] == seed].set_index(
            "ordered_position", drop=False
        )
        seed_labels = labels.loc[labels["seed"] == seed]
        seed_identity = identity.loc[identity["seed"] == seed]
        for fold_id in CHEAP_FOLD_IDS:
            test_identity = seed_identity.loc[seed_identity["fold_id"] == fold_id]
            test_start_position = int(test_identity["ordered_position"].min())
            test_start_date = pd.to_datetime(test_identity["date"], utc=True).min()
            training = seed_labels.loc[
                seed_labels["ordered_position"] < test_start_position
            ]
            target = pd.to_numeric(training["observed_pe"], errors="coerce")
            available = pd.to_datetime(
                training["label_available_at"], errors="coerce", utc=True
            )
            training = training.loc[
                target.notna()
                & (target > 0.0)
                & available.notna()
                & (available < test_start_date)
            ]
            train_x = seed_features.loc[
                training["ordered_position"], list(FEATURE_COLUMNS)
            ].reset_index(drop=True)
            test_x = seed_features.loc[
                test_identity["ordered_position"], list(FEATURE_COLUMNS)
            ].reset_index(drop=True)
            _, _, _, dropped = select_fold_feature_subset(train_x, test_x)
            assert dropped == EXPECTED_DROPPED_FEATURES_BY_FOLD[fold_id]


def test_runtime_closure_replays_under_locked_resources() -> None:
    closure_path = BASE / "RUNTIME_CLOSURE.json"
    digest = closure_path.with_suffix(".sha256").read_text(encoding="utf-8").split()[0]
    receipt = verify_runtime_closure(
        repo_root=ROOT,
        closure_path=closure_path,
        expected_raw_sha256=digest,
    )
    assert receipt["status"] == "PASS"
    resource = receipt["resource_policy"]
    assert resource["common_full_load_receipt"]["affinity_mask_hex"] == "0xFFFFFFFF"
    assert resource["gpu_selected_by_candidate"] is False


def test_approval_templates_are_explicitly_unsealed() -> None:
    for name in (
        "HEAVY_FIT_APPROVAL_TEMPLATE.json",
        "FUTURE_SCORE_APPROVAL_TEMPLATE.json",
        "CENTRAL_SURVIVOR_TOURNAMENT_APPROVAL_TEMPLATE.json",
    ):
        payload = json.loads((BASE / name).read_text(encoding="utf-8"))
        assert payload["approved"] is False
        assert payload["seal_sha256"] is None
