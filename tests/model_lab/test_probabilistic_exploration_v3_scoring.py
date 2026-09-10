from __future__ import annotations

from pathlib import Path

import math
import pandas as pd
import pytest

from research.model_zoo.probabilistic_exploration_v2.contracts import (
    ExplorationContractError,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.probabilistic_exploration_v2.scoring import (
    PREDICTION_COLUMNS,
)
from research.model_zoo.probabilistic_exploration_v3.central import (
    preflight_immutable_survivor_bridge,
)
from research.model_zoo.probabilistic_exploration_v3.governance import (
    load_v3_inventory,
)
from research.model_zoo.probabilistic_exploration_v3.design import (
    CANDIDATE_BACKEND,
    CANDIDATE_IDS,
    CANDIDATE_CONFIG_SHA256,
    EXPECTED_DROPPED_FEATURES_BY_FOLD,
    FEATURE_COLUMNS,
    GPU_NUMERICAL_CONTRACT,
)
from research.model_zoo.probabilistic_exploration_v3.inputs import (
    load_full_and_reduced_identity,
)
from research.model_zoo.probabilistic_exploration_v3.scoring import (
    preflight_future_prediction_publication,
    validate_future_prediction_frames,
)
from research.model_zoo.probabilistic_exploration_v3.runner import PREDICTION_SCHEMA
from research.model_zoo.probabilistic_exploration_v3.surfaces import (
    central_point_surface,
)


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"


def _synthetic_publication_frames() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    _, _, v2_inventory = load_v3_inventory(ROOT, BASE / "INPUT_INVENTORY.json")
    _, reduced = load_full_and_reduced_identity(ROOT, v2_inventory)
    parts = []
    for model_id in CANDIDATE_IDS:
        frame = reduced.copy()
        frame["model_id"] = model_id
        frame["predicted_pe_p10"] = 10.0
        frame["predicted_pe_p25"] = 11.0
        frame["predicted_pe_p50"] = 12.0
        frame["predicted_pe_p75"] = 13.0
        frame["predicted_pe_p90"] = 14.0
        frame["expected_pe"] = 12.0
        frame["uncertainty_log_iqr"] = math.log(13.0) - math.log(11.0)
        frame["uncertainty_log_idr"] = math.log(14.0) - math.log(10.0)
        frame["uncertainty_robust_sigma"] = (
            frame["uncertainty_log_iqr"] / 1.3489795003921634
        )
        frame["uncertainty_p90_p10_ratio"] = 1.4
        parts.append(frame.loc[:, list(PREDICTION_COLUMNS)])
    predictions = pd.concat(parts, ignore_index=True)
    return predictions, central_point_surface(predictions), reduced


def test_detached_future_frame_accepts_exact_variable_geometry() -> None:
    predictions, bridge, reduced = _synthetic_publication_frames()
    validate_future_prediction_frames(predictions, bridge, reduced)
    terminal = predictions.loc[predictions["fold_id"] == "fold_073"]
    assert len(terminal) == len(CANDIDATE_IDS) * 5 * 15


def test_detached_future_frame_rejects_bridge_drift_before_truth() -> None:
    predictions, bridge, reduced = _synthetic_publication_frames()
    bridge.loc[0, "prediction"] += 0.01
    with pytest.raises(ExplorationContractError, match="bridge"):
        validate_future_prediction_frames(predictions, bridge, reduced)


def test_detached_future_frame_rejects_terminal_row_loss() -> None:
    predictions, bridge, reduced = _synthetic_publication_frames()
    predictions = predictions.drop(index=predictions.index[-1]).reset_index(drop=True)
    with pytest.raises(ExplorationContractError, match="rows"):
        validate_future_prediction_frames(predictions, bridge, reduced)


def test_immutable_survivor_bridge_preflight_is_truth_free_and_exact() -> None:
    _, v3_inventory, v2_inventory = load_v3_inventory(ROOT, BASE / "INPUT_INVENTORY.json")
    bridge, receipt = preflight_immutable_survivor_bridge(
        repo_root=ROOT,
        v3_inventory=v3_inventory,
        v2_inventory=v2_inventory,
    )
    assert len(bridge) == 12_960
    assert receipt["rows_per_model"] == 6480
    assert receipt["truth_opened"] is False
    assert receipt["score_computed"] is False


def test_frozen_future_publication_drift_fails_before_truth(tmp_path: Path) -> None:
    predictions, bridge, _ = _synthetic_publication_frames()
    design_digest = sha256_bytes((BASE / "DESIGN_LOCK.json").read_bytes())
    inventory_digest = sha256_bytes((BASE / "INPUT_INVENTORY.json").read_bytes())
    closure_digest = (BASE / "RUNTIME_CLOSURE.sha256").read_text(
        encoding="utf-8"
    ).split()[0]
    backend_receipts = {
        f"{model_id}|{seed}": {
            "candidate_backend": CANDIDATE_BACKEND[model_id],
            "gpu_selected_by_candidate": (
                model_id != "histgb_quantile_with_regime_exploration_v1"
            ),
        }
        for model_id in CANDIDATE_IDS
        for seed in (6301, 6421, 6521, 6607, 6701)
    }
    feature_receipts = [
        {
            "seed": seed,
            "fold_id": fold_id,
            "model_id": model_id,
            "selection_source": "ELIGIBLE_TRAINING_X_ONLY",
            "test_values_inspected_for_selection": False,
            "target_values_inspected_for_selection": False,
            "imputation_applied": False,
            "active_features": [column for column in FEATURE_COLUMNS if column not in dropped],
            "dropped_all_missing_features": list(dropped),
        }
        for model_id in CANDIDATE_IDS
        for seed in (6301, 6421, 6521, 6607, 6701)
        for fold_id, dropped in EXPECTED_DROPPED_FEATURES_BY_FOLD.items()
    ]
    receipt = {
        "schema_version": PREDICTION_SCHEMA,
        "lane_labels": ["EXPLORATION_ONLY", "NOT_PROMOTION_EVIDENCE"],
        "parent_design_lock_raw_sha256": (
            "e7e6ec4b8f0bc6398913e7bb78b9eb3828b20e1de8914104619e1ceb84e8e71e"
        ),
        "common_full_load_lock_raw_sha256": (
            "621ff4b9bcbdb535723a1df9f6ec7edf8de286225e6b75bc9c593e4bd187fe95"
        ),
        "probabilistic_v3_2_design_lock_raw_sha256": design_digest,
        "v3_2_input_inventory_raw_sha256": inventory_digest,
        "runtime_closure_raw_sha256": closure_digest,
        "candidate_ids": list(CANDIDATE_IDS),
        "candidate_config_sha256": dict(CANDIDATE_CONFIG_SHA256),
        "gpu_numerical_contract": GPU_NUMERICAL_CONTRACT,
        "fold_row_counts_per_seed": {
            "fold_012": 21,
            "fold_017": 21,
            "fold_022": 21,
            "fold_027": 21,
            "fold_032": 21,
            "fold_037": 21,
            "fold_042": 21,
            "fold_047": 21,
            "fold_052": 21,
            "fold_059": 21,
            "fold_066": 21,
            "fold_073": 15,
        },
        "reduced_identity_logical_sha256": (
            "c049f5d291a2124021839f7448a1d50f64fbc9269dce70652298bb80073f976c"
        ),
        "rows_per_model": 1230,
        "rows": 4920,
        "worker_backend_receipts": backend_receipts,
        "worker_candidate_config_sha256": {
            f"{model_id}|{seed}": CANDIDATE_CONFIG_SHA256[model_id]
            for model_id in CANDIDATE_IDS
            for seed in (6301, 6421, 6521, 6607, 6701)
        },
        "fold_feature_receipts": feature_receipts,
        "truth_opened": False,
        "score_computed": False,
        "fresh_or_heldout_opened": False,
        "registry_mutated": False,
        "production_promotion_authority": False,
    }
    payloads = {
        "PREDICTIONS.csv": predictions.to_csv(
            index=False, lineterminator="\n", float_format="%.17g"
        ).encode(),
        "CENTRAL_P50_BRIDGE.csv": bridge.to_csv(
            index=False, lineterminator="\n", float_format="%.17g"
        ).encode(),
        "EXECUTION_RECEIPT.json": canonical_json_bytes(receipt) + b"\n",
    }
    for name, raw in payloads.items():
        (tmp_path / name).write_bytes(raw)
    manifest = {
        "schema_version": (
            "expected_pe_model_lab.probabilistic_exploration_v3_2.prediction_publication.v1"
        ),
        "lane_labels": ["EXPLORATION_ONLY", "NOT_PROMOTION_EVIDENCE"],
        "files": {
            name: {"bytes": len(raw), "sha256": sha256_bytes(raw)}
            for name, raw in sorted(payloads.items())
        },
        "truth_opened": False,
        "score_computed": False,
        "fresh_or_heldout_opened": False,
        "registry_mutated": False,
        "production_promotion_authority": False,
    }
    manifest_raw = canonical_json_bytes(manifest) + b"\n"
    (tmp_path / "MANIFEST.json").write_bytes(manifest_raw)
    _, _, v2_inventory = load_v3_inventory(ROOT, BASE / "INPUT_INVENTORY.json")
    preflight_future_prediction_publication(
        repo_root=ROOT,
        v2_inventory=v2_inventory,
        prediction_directory=tmp_path,
        prediction_manifest_raw_sha256=sha256_bytes(manifest_raw),
        design_raw_sha256=design_digest,
        inventory_raw_sha256=inventory_digest,
        runtime_closure_raw_sha256=closure_digest,
    )
    with (tmp_path / "PREDICTIONS.csv").open("ab") as stream:
        stream.write(b"DRIFT")
    with pytest.raises(ExplorationContractError, match="drift"):
        preflight_future_prediction_publication(
            repo_root=ROOT,
            v2_inventory=v2_inventory,
            prediction_directory=tmp_path,
            prediction_manifest_raw_sha256=sha256_bytes(manifest_raw),
            design_raw_sha256=design_digest,
            inventory_raw_sha256=inventory_digest,
            runtime_closure_raw_sha256=closure_digest,
        )
