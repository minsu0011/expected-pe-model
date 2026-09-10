"""Freeze the score-free, explicitly outcome-aware Iteration 2 design."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


SOURCE_FILES = (
    "research/model_zoo/dgp_exploration_iteration2/__init__.py",
    "research/model_zoo/dgp_exploration_iteration2/artifacts.py",
    "research/model_zoo/dgp_exploration_iteration2/contracts.py",
    "research/model_zoo/dgp_exploration_iteration2/ensemble.py",
    "research/model_zoo/dgp_exploration_iteration2/precommit.py",
    "research/model_zoo/dgp_exploration_iteration2/resources.py",
    "research/model_zoo/dgp_exploration_iteration2/runner.py",
    "scripts/model_lab/dgp_exploration_iteration2/freeze_design.py",
    "scripts/model_lab/dgp_exploration_iteration2/run_iteration2.py",
    "scripts/model_lab/dgp_exploration_iteration2/verify_precommit.py",
    "tests/model_lab/test_dgp_exploration_iteration2.py",
)
INPUT_FILES = (
    "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json",
    "outputs/model_zoo_aggressive_full_load_20260820/DESIGN_LOCK.json",
    "outputs/model_zoo_dgp_exploration_v3_design_20260820/DESIGN_LOCK.json",
    "outputs/model_zoo_dgp_exploration_v3_predictions_20260820/CHECKSUMS.sha256",
    "outputs/model_zoo_dgp_exploration_v3_predictions_20260820/COMMON_IDENTITIES.csv",
    "outputs/model_zoo_dgp_exploration_v3_predictions_20260820/FOLD_DIAGNOSTICS.csv",
    "outputs/model_zoo_dgp_exploration_v3_predictions_20260820/PREDICTION_RECEIPT.json",
    "outputs/model_zoo_dgp_exploration_v3_predictions_20260820/PREDICTIONS_FROZEN.csv",
    "outputs/model_zoo_dgp_exploration_v3_predictions_audit_20260820/AUDIT.json",
    "outputs/model_zoo_dgp_exploration_v3_predictions_audit_20260820/CHECKSUMS.sha256",
    "outputs/model_zoo_dgp_exploration_v3_predictions_audit_20260820/verify_addendum.py",
    "outputs/model_zoo_dgp_exploration_v3_scores_20260820/CHECKSUMS.sha256",
    "outputs/model_zoo_dgp_exploration_v3_scores_20260820/RUN_MANIFEST.json",
    "outputs/model_zoo_dgp_exploration_v3_scores_20260820/ROW_ERRORS_TRUTH_DERIVED.csv",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_json_bytes(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{hashlib.sha256(raw).hexdigest()}.tmp")
    if temporary.exists():
        temporary.unlink()
    with temporary.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    if path.read_bytes() != raw:
        raise RuntimeError("Iteration 2 design artifact changed after atomic write")


def main() -> int:
    from research.model_zoo.dgp_exploration_iteration2 import (
        EVIDENCE_CLASS,
        PRODUCTION_AUTHORITY,
        PROMOTION_AUTHORITY,
    )
    from research.model_zoo.dgp_exploration_iteration2.contracts import (
        CANDIDATE_IDS,
        DGPS,
        FULL_IDENTITY_COLUMNS,
        IDENTITY_COLUMNS,
        POOL_MODELS,
        candidate_design,
        resource_design,
    )
    from research.model_zoo.dgp_exploration_iteration2.precommit import repository_root

    root = repository_root()
    source_sha256 = {name: sha256_file(root / name) for name in SOURCE_FILES}
    input_sha256 = {name: sha256_file(root / name) for name in INPUT_FILES}
    candidates = candidate_design()
    candidate_payload_sha256 = hashlib.sha256(canonical_json_bytes(candidates)).hexdigest()
    input_payload_sha256 = hashlib.sha256(canonical_json_bytes(input_sha256)).hexdigest()
    payload = {
        "schema_version": "expected_pe_dgp_exploration_iteration2.design_lock.v1",
        "lane_id": "expected_pe_dgp_exploration_iteration2_20260820",
        "evidence_class": EVIDENCE_CLASS,
        "promotion_authority": PROMOTION_AUTHORITY,
        "production_authority": PRODUCTION_AUTHORITY,
        "outcome_aware": True,
        "outcome_awareness_reason": (
            "Iteration 2 was specified after observing Iteration 1 ExtraTrees weakness "
            "on DGP-B/H; none of its scores are promotion evidence"
        ),
        "selection_frozen_before_iteration2_score": True,
        "candidate_ids": list(CANDIDATE_IDS),
        "candidate_design": candidates,
        "candidate_payload_sha256": candidate_payload_sha256,
        "logo_design": {
            "pool_model_ids_in_matrix_order": list(POOL_MODELS),
            "heldout_unit": "DGP",
            "heldout_dgps": list(DGPS),
            "training_dgp_count": 9,
            "heldout_dgp_count": 1,
            "objective": "mean squared log-P/E error",
            "constraints": "weight_j>=0 and sum(weight_j)=1",
            "solver": "enumerate all nonempty active sets; equality KKT via numpy.linalg.lstsq",
            "tie_break": "loss tolerance 1e-18 then lexicographically first active index tuple",
            "negative_feasibility_tolerance": 1e-10,
            "sum_one_assertion_tolerance": 1e-12,
            "same_dgp_training_truth_rows": 0,
        },
        "same_dgp_training_truth_for_logo": False,
        "identity_design": {
            "central_evaluator_identity": list(IDENTITY_COLUMNS),
            "full_prediction_identity": list(FULL_IDENTITY_COLUMNS),
            "common_identity_rows": 18_900,
            "input_prediction_rows": 170_100,
            "seeds": [2026082001, 2026082003, 2026082007, 2026082011, 2026082017],
            "dgps": list(DGPS),
            "rows_per_seed_dgp": 378,
            "fold_custody": "reuse frozen cheap fold_id; no refit or fold reselection",
        },
        "truth_design": {
            "source": "immutable V3 predictions plus immutable V3 truth-derived row errors",
            "reconstruction": "log_truth = log(prediction) - fair_log_error",
            "cross_model_consistency_tolerance": 1e-12,
            "truth_publication": False,
            "physical_production_truth_custody_claimed": False,
        },
        "evaluation_design": {
            "target": "same-row evaluator-only true fair P/E in log space",
            "incumbent": "v04_expected_pe",
            "metrics": [
                "global MAE/RMSE",
                "per-DGP mean/median MAE/RMSE",
                "global and per-DGP seed wins",
                "global and per-DGP worst relative harm",
                "signed and absolute error correlation",
                "oracle complementarity",
                "DGP win count and worst-DGP identity",
            ],
            "central_threshold_source": (
                "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json"
            ),
        },
        "resource_design": resource_design(),
        "input_sha256": input_sha256,
        "input_payload_sha256": input_payload_sha256,
        "source_sha256": source_sha256,
        "source_count": len(source_sha256),
        "input_count": len(input_sha256),
        "forbidden": {
            "production_registry_write": True,
            "production_champion_write": True,
            "fresh_or_heldout_claim": True,
            "same_dgp_truth_for_logo_weight_fit": True,
            "post_score_candidate_or_parameter_change": True,
        },
        "execution_status": "DESIGN_LOCKED_SCORE_NOT_YET_COMPUTED",
    }
    destination = root / "outputs/model_zoo_dgp_exploration_iteration2_design_20260820"
    if destination.exists() and any(destination.iterdir()):
        raise RuntimeError("Iteration 2 design output must be absent or empty")
    raw = canonical_json_bytes(payload)
    atomic_write(destination / "DESIGN_LOCK.json", raw)
    design_hash = hashlib.sha256(raw).hexdigest()
    checksum_raw = f"{design_hash}  DESIGN_LOCK.json\n".encode("ascii")
    atomic_write(destination / "CHECKSUMS.sha256", checksum_raw)
    print(
        json.dumps(
            {
                "status": "PASS_SCORE_FREE_OUTCOME_AWARE_DESIGN_FREEZE",
                "design_lock_raw_sha256": design_hash,
                "checksums_raw_sha256": hashlib.sha256(checksum_raw).hexdigest(),
                "candidate_payload_sha256": candidate_payload_sha256,
                "source_count": len(source_sha256),
                "input_count": len(input_sha256),
                "score_computed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

