"""Freeze V4 exact-base replay bindings without mutable DGP state."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Iterable


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON object required: {path}")
    return value


def main() -> int:
    root = _root()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.structural.contracts import (
        STRUCTURAL_DESIGN_SHA256,
        canonical_json_bytes,
        seal_payload,
        sha256_bytes,
        sha256_file,
    )

    output = root / ("outputs/model_zoo_structural_wave_screen_20260819/BASE_BINDING_LOCK_V4.json")
    if output.exists():
        raise FileExistsError(f"refusing to overwrite base-binding lock: {output}")

    def record(path: Path) -> dict[str, Any]:
        path = path.resolve(strict=True)
        return {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }

    def inventory(paths: Iterable[Path]) -> list[dict[str, Any]]:
        return [record(path) for path in sorted(paths, key=lambda item: item.as_posix())]

    wave1 = root / "outputs/model_zoo_wave1_screen_20260819"
    execution_binding_path = wave1 / "EXECUTION_BINDING.json"
    predict_inputs_path = wave1 / "PREDICT_INPUTS.json"
    registry_path = wave1 / (
        "execution_snapshots/"
        "040f0f1394875aefab1cdff0bb10c8ae80973cc296de4729b481eb35ce32d1c0.snapshot"
    )
    feature_registry_path = wave1 / (
        "execution_snapshots/"
        "2ea4c225ed3bcd94d4bb13536a6f00735cdfadf32d1534d4b671ea75e6524d7d.snapshot"
    )
    environment_path = wave1 / (
        "execution_snapshots/"
        "7b86220669a4e4c013f59b36f990cae09a0f1710909de78132a4adb2621601ab.snapshot"
    )
    expected_files = {
        execution_binding_path: "f40b71c5eaa4ac1ad52a4999cd02af13b62695677fab2597252745e6af89782c",
        predict_inputs_path: "f8f30ab74d812909b644984ba9ee3c4a8f509dfabb2ab566c7048313245d500c",
        registry_path: "040f0f1394875aefab1cdff0bb10c8ae80973cc296de4729b481eb35ce32d1c0",
        feature_registry_path: "2ea4c225ed3bcd94d4bb13536a6f00735cdfadf32d1534d4b671ea75e6524d7d",
        environment_path: "7b86220669a4e4c013f59b36f990cae09a0f1710909de78132a4adb2621601ab",
    }
    for path, expected in expected_files.items():
        if sha256_file(path) != expected:
            raise RuntimeError(f"frozen Wave1 dependency changed: {path}")

    registry = _read(registry_path)
    records = {
        str(row["model_id"]): row
        for row in registry["records"]
        if row["model_id"] in {"xgboost_cpu_common", "spline_ridge_common"}
    }
    if set(records) != {"xgboost_cpu_common", "spline_ridge_common"}:
        raise RuntimeError("selected pair records are missing")

    v04_source_paths = {
        root / "src/pe_regime_v04/__init__.py",
        root / "src/pe_regime_v04/ablation.py",
        root / "src/pe_regime_v04/config.py",
        root / "src/pe_regime_v04/expected_pe.py",
        root / "src/pe_regime_v04/fundamental_vintage.py",
        root / "src/pe_regime_v04/labels.py",
        root / "src/pe_regime_v04/lagged_market_conditioned.py",
        root / "src/pe_regime_v04/market_conditioned.py",
        root / "src/pe_regime_v04/matured_proxy_gate.py",
        root / "src/pe_regime_v04/metrics.py",
        root / "src/pe_regime_v04/ml_incumbent_smoothing.py",
        root / "src/pe_regime_v04/pipeline.py",
        root / "src/pe_regime_v04/regime_stacker.py",
        root / "src/pe_regime_v04/utility_gate.py",
        root / "src/pe_regime_v04/utils.py",
        root / "src/pe_regime_v04/valuation.py",
    }
    v04_inventory = inventory(v04_source_paths)
    v04_source_sha = sha256_bytes(canonical_json_bytes(v04_inventory))
    config_record = record(root / "config/v04_bottleneck.yaml")
    design_record = record(root / "config/v04_matured_proxy_regularized_gate_design_lock.json")
    candidate_record = record(root / "config/v04_matured_proxy_regularized_gate_candidate.json")
    if config_record["sha256"] != (
        "1e52f6ed5f5abb3c2b720c58f39360f33506307a0f16571dba85157e534fb84e"
    ):
        raise RuntimeError("frozen v04 config changed")

    pair_source_paths = {
        root / "src/pe_regime_v04/model_lab/__init__.py",
        root / "src/pe_regime_v04/model_lab/contracts.py",
        root / "src/pe_regime_v04/model_lab/folds.py",
        root / "src/pe_regime_v04/model_lab/models/__init__.py",
        root / "src/pe_regime_v04/model_lab/models/wave1/__init__.py",
        root / "src/pe_regime_v04/model_lab/models/wave1/adapters.py",
        root / "src/pe_regime_v04/model_lab/models/wave1/artifacts.py",
        root / "src/pe_regime_v04/model_lab/models/wave1/spec.py",
    }
    pair_inventory = inventory(pair_source_paths)
    pair_source_sha = sha256_bytes(canonical_json_bytes(pair_inventory))
    environment_record = record(environment_path)
    feature_registry_record = record(feature_registry_path)

    pair_replay_contract = {
        "adapter": "pe_regime_v04.model_lab.models.wave1.adapters.build_wave1_model",
        "source_inventory": pair_inventory,
        "source_inventory_sha256": pair_source_sha,
        "input_loader": "load_wave1_seed_frames",
        "folds": {
            "min_train_sessions": 252,
            "max_train_sessions": 1008,
            "test_sessions": 21,
            "step_sessions": 21,
            "embargo_sessions": 0,
            "allow_partial_final_test": False,
        },
        "within_test_target_updates": False,
        "caller_prediction_input": False,
    }

    def pair_binding(model_id: str) -> dict[str, Any]:
        row = records[model_id]
        if row["track"] != "C" or row["feature_set"] != "common":
            raise RuntimeError(f"selected pair semantic binding changed: {model_id}")
        replay = {**pair_replay_contract, "model_record": row}
        return {
            "model_id": model_id,
            "family": str(row["family"]),
            "track": "C",
            "decision_cutoff": "EOD_AFTER_ALL_SAME_SESSION_SOURCES",
            "source_sha256": pair_source_sha,
            "config_sha256": str(row["parameters_sha256"]),
            "environment_sha256": environment_record["sha256"],
            "feature_registry_sha256": feature_registry_record["sha256"],
            "feature_ids": list(row["feature_ids"]),
            "replay_contract_sha256": sha256_bytes(canonical_json_bytes(replay)),
        }

    predict_inputs = _read(predict_inputs_path)
    if predict_inputs.get("manifest_sha256") != (
        "b08dd0a63c9b02ef14f06b3fd48764ac44c954100be5f360d03df7390aa494e8"
    ):
        raise RuntimeError("predict-input logical seal changed")
    spent_surfaces: list[dict[str, Any]] = []
    expected_seeds = (6301, 6421, 6521, 6607, 6701)
    if tuple(int(row["seed"]) for row in predict_inputs["seeds"]) != expected_seeds:
        raise RuntimeError("spent input universe changed")
    for row in predict_inputs["seeds"]:
        # Custody records only: no CSV target or prediction column is read here.
        spent_surfaces.append(
            {
                "seed": int(row["seed"]),
                "canonical_csv": dict(row["canonical_csv"]),
                "output_csv": dict(row["output_csv"]),
                "expected_rows": int(row["expected_rows"]),
                "identity_logical_sha256": str(row["identity_logical_sha256"]),
            }
        )

    residual_replay = {
        "adapter": "pe_regime_v04.pipeline.apply_v04_layers",
        "source_inventory": v04_inventory,
        "source_inventory_sha256": v04_source_sha,
        "config": config_record,
        "design_lock": design_record,
        "candidate_overrides": candidate_record,
        "raw_output_column": "v04_expected_pe",
        "alignment": "prediction_at_t_equals_raw_overlay_output_at_t_minus_1",
        "model_seed_by_spent_seed": {str(seed): 500000 + seed for seed in expected_seeds},
        "recompute_then_require_exact_frozen_output254_match": True,
        "rowwise_training_end": "immediately_previous_complete_session",
        "caller_prediction_input": False,
        "truth_access": False,
    }
    residual_replay_sha = sha256_bytes(canonical_json_bytes(residual_replay))
    residual = {
        "model_id": "v04_expected_pe",
        "family": "frozen_v04_overlay",
        "track": "A",
        "decision_cutoff": "PIT_FUNDAMENTAL_1230_UTC",
        "source_sha256": v04_source_sha,
        "config_sha256": config_record["sha256"],
        "environment_sha256": environment_record["sha256"],
        "feature_registry_sha256": feature_registry_record["sha256"],
        "feature_ids": [],
        "replay_contract_sha256": residual_replay_sha,
    }
    pair = [pair_binding("xgboost_cpu_common"), pair_binding("spline_ridge_common")]
    payload = seal_payload(
        {
            "format_version": 4,
            "mode": "structural_exact_base_execution_binding_lock",
            "design_sha256": STRUCTURAL_DESIGN_SHA256,
            "trigger_decision_sha256": (
                "45b6dee894ed72809c49902f4f78ff058a465db6ebfe8903a21c659883504765"
            ),
            "residual_base": residual,
            "ensemble_pair": pair,
            "binding_evidence": {
                "predict_inputs": record(predict_inputs_path),
                "wave1_execution_binding": record(execution_binding_path),
                "model_registry_snapshot": record(registry_path),
                "feature_registry_snapshot": feature_registry_record,
                "environment_snapshot": environment_record,
                "residual_v04_replay": residual_replay,
                "wave1_pair_replay": pair_replay_contract,
                "spent_surfaces": spent_surfaces,
            },
            "unrelated_dgp_contract_consumed": False,
            "generic_or_substituted_base_allowed": False,
            "caller_prediction_or_fold_artifact_allowed": False,
            "pair_order_is_semantic": True,
            "huber_execution_allowed": False,
            "project_prediction_executed_while_freezing": False,
        }
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_json_bytes(payload) + b"\n")
    print(
        json.dumps(
            {
                "path": output.relative_to(root).as_posix(),
                "manifest_sha256": payload["manifest_sha256"],
                "file_sha256": sha256_file(output),
                "v04_source_inventory_count": len(v04_inventory),
                "wave1_pair_source_inventory_count": len(pair_inventory),
                "spent_surfaces_bound_without_csv_read": len(spent_surfaces),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
