"""Exact implementation and artifact inventory for the five candidate slots."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .contracts import (
    BCE_CHECKSUMS_SHA256,
    BCE_MANIFEST_SHA256,
    BCE_PREDICTION_ROOT,
    BCE_PREDICTIONS_SHA256,
    DETAILED_EVIDENCE_CLASS,
    FIVE_CANDIDATE_SLOTS,
    PUBLIC_CHECKSUMS_SHA256,
    PUBLIC_FREEZE_SHA256,
    PUBLIC_ROOT,
    RESEARCH_EVIDENCE_CLASS,
    TRUTH_CHECKSUMS_SHA256,
    TRUTH_RECEIPT_SHA256,
    TRUTH_ROOT,
    ResearchTournamentContractError,
)


HOFS_V11_DESIGN_CHECKSUMS = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v11_"
    "dgp_r4_design_preflight_20260821/CHECKSUMS.sha256"
)
HOFS_V11_DESIGN_CHECKSUMS_SHA256 = (
    "31f91129a6d925ee0d043f212725816d04e7a168ef002fdc52a371af2a70c31e"
)
HOFS_V11_AUDIT_CHECKSUMS = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v11_"
    "independent_prelaunch_audit_20260821/CHECKSUMS.sha256"
)
HOFS_V11_AUDIT_CHECKSUMS_SHA256 = (
    "461b3b33bcad374defa81f7acbb1379d9b9fb02d09653096b9be5806b5ccfc10"
)
TCN_V7_DESIGN_CHECKSUMS = (
    "outputs/model_zoo_causal_valuation_tcn_v7_score_free_design_environment_"
    "preflight_20260821/bundle/CHECKSUMS.sha256"
)
TCN_V7_DESIGN_CHECKSUMS_SHA256 = (
    "ece6e1cb0404a14c182387043f50914d83377568fbaf0e23043aa719508a0b80"
)
TCN_V7_AUDIT = (
    "outputs/model_zoo_causal_valuation_tcn_v7_independent_score_free_"
    "prelaunch_audit_r1_20260821/AUDIT.json"
)
TCN_V7_AUDIT_SHA256 = (
    "3b9db12fd1a850af8e7b8fb02212de6b206ebe2f0b5262fe650cd44ac7836e24"
)
TCN_V7_AUDIT_CHECKSUMS = (
    "outputs/model_zoo_causal_valuation_tcn_v7_independent_score_free_"
    "prelaunch_audit_r1_20260821/CHECKSUMS.sha256"
)
TCN_V7_AUDIT_CHECKSUMS_SHA256 = (
    "8fba2d7ffba4f25cc540c472b57b707d060c3ea2af717ad2830d9367e4db1bce"
)


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def _strict_json(content: bytes, *, label: str) -> dict[str, Any]:
    def pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in rows:
            if key in output:
                raise ResearchTournamentContractError(f"duplicate JSON key in {label}: {key}")
            output[key] = value
        return output

    try:
        result = json.loads(content.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ResearchTournamentContractError(f"invalid JSON: {label}") from exc
    if type(result) is not dict:
        raise ResearchTournamentContractError(f"JSON root must be an object: {label}")
    return result


def _require_file(project_root: Path, relative: str, expected_sha256: str) -> Path:
    root = Path(project_root).resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ResearchTournamentContractError(f"inventory path escaped project: {relative}") from exc
    if not path.is_file() or path.is_symlink():
        raise ResearchTournamentContractError(f"inventory artifact is not an ordinary file: {relative}")
    actual = sha256_file(path)
    if actual != expected_sha256:
        raise ResearchTournamentContractError(
            f"inventory artifact hash drifted: {relative}: {actual}"
        )
    return path


def build_inventory(project_root: Path) -> dict[str, Any]:
    """Verify only pinned metadata/source artifacts; never open truth payloads."""

    project = Path(project_root).resolve()
    public_freeze = _require_file(
        project, f"{PUBLIC_ROOT}/FREEZE_RECEIPT.json", PUBLIC_FREEZE_SHA256
    )
    public_checksums = _require_file(
        project, f"{PUBLIC_ROOT}/CHECKSUMS.sha256", PUBLIC_CHECKSUMS_SHA256
    )
    truth_receipt = _require_file(
        project, f"{TRUTH_ROOT}/VAULT_RECEIPT.json", TRUTH_RECEIPT_SHA256
    )
    truth_checksums = _require_file(
        project, f"{TRUTH_ROOT}/CHECKSUMS.sha256", TRUTH_CHECKSUMS_SHA256
    )
    prediction = _require_file(
        project, f"{BCE_PREDICTION_ROOT}/PREDICTIONS.csv", BCE_PREDICTIONS_SHA256
    )
    prediction_manifest_path = _require_file(
        project, f"{BCE_PREDICTION_ROOT}/PREDICTION_MANIFEST.json", BCE_MANIFEST_SHA256
    )
    prediction_checksums = _require_file(
        project, f"{BCE_PREDICTION_ROOT}/CHECKSUMS.sha256", BCE_CHECKSUMS_SHA256
    )
    prediction_manifest = _strict_json(
        prediction_manifest_path.read_bytes(), label="BCE prediction manifest"
    )
    if (
        prediction_manifest.get("status")
        != "PREDICTIONS_FROZEN_EVALUATOR_CUSTODY_UNOPENED"
        or prediction_manifest.get("identity_rows") != 64_800
        or prediction_manifest.get("task_count") != 50
        or prediction_manifest.get("fold_blocks") != 3_100
        or prediction_manifest.get("prediction_raw_sha256") != BCE_PREDICTIONS_SHA256
    ):
        raise ResearchTournamentContractError("BCE prediction manifest closure drifted")

    hofs_design = _require_file(
        project, HOFS_V11_DESIGN_CHECKSUMS, HOFS_V11_DESIGN_CHECKSUMS_SHA256
    )
    hofs_audit = _require_file(
        project, HOFS_V11_AUDIT_CHECKSUMS, HOFS_V11_AUDIT_CHECKSUMS_SHA256
    )
    tcn_design = _require_file(
        project, TCN_V7_DESIGN_CHECKSUMS, TCN_V7_DESIGN_CHECKSUMS_SHA256
    )
    tcn_audit = _require_file(project, TCN_V7_AUDIT, TCN_V7_AUDIT_SHA256)
    tcn_audit_checksums = _require_file(
        project, TCN_V7_AUDIT_CHECKSUMS, TCN_V7_AUDIT_CHECKSUMS_SHA256
    )

    return {
        "schema_version": "expected_pe.pre_cert_research.inventory.v1",
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
        "status": "PASS_EXACT_SPENT_INPUTS_BCE_3_OF_5_SCOREABLE",
        "input_artifacts": {
            "public_freeze": {
                "relative_path": public_freeze.relative_to(project).as_posix(),
                "raw_sha256": PUBLIC_FREEZE_SHA256,
            },
            "public_checksums": {
                "relative_path": public_checksums.relative_to(project).as_posix(),
                "raw_sha256": PUBLIC_CHECKSUMS_SHA256,
            },
            "truth_receipt": {
                "relative_path": truth_receipt.relative_to(project).as_posix(),
                "raw_sha256": TRUTH_RECEIPT_SHA256,
                "payload_opened_by_inventory": False,
            },
            "truth_checksums": {
                "relative_path": truth_checksums.relative_to(project).as_posix(),
                "raw_sha256": TRUTH_CHECKSUMS_SHA256,
            },
            "bce_predictions": {
                "relative_path": prediction.relative_to(project).as_posix(),
                "raw_sha256": BCE_PREDICTIONS_SHA256,
                "rows": 64_800,
                "model_columns": 4,
            },
            "bce_prediction_manifest": {
                "relative_path": prediction_manifest_path.relative_to(project).as_posix(),
                "raw_sha256": BCE_MANIFEST_SHA256,
            },
            "bce_prediction_checksums": {
                "relative_path": prediction_checksums.relative_to(project).as_posix(),
                "raw_sha256": BCE_CHECKSUMS_SHA256,
            },
        },
        "candidate_slots": [
            {
                **slot.__dict__,
                "evidence_class": RESEARCH_EVIDENCE_CLASS,
                "certified": False,
                "promotion_eligible": False,
            }
            for slot in FIVE_CANDIDATE_SLOTS
        ],
        "hofs_blocker": {
            "status": "BLOCKED_IMPLEMENTATION",
            "design_checksums": {
                "relative_path": hofs_design.relative_to(project).as_posix(),
                "raw_sha256": HOFS_V11_DESIGN_CHECKSUMS_SHA256,
            },
            "audit_checksums": {
                "relative_path": hofs_audit.relative_to(project).as_posix(),
                "raw_sha256": HOFS_V11_AUDIT_CHECKSUMS_SHA256,
                "design_findings": "P0_P1_P2_0_0_0",
            },
            "reason": "V11_PRIVATE_EXECUTION_IDENTITY_LOST_NO_PREDICTIONS",
            "must_not_do": "DO_NOT_LAUNCH_OR_IMPERSONATE_V11",
            "required_adapter": {
                "adapter_id": "hofs_spent_r4_prediction_adapter_v1",
                "new_identity_required": True,
                "numeric_entrypoints": [
                    "adapt_r4_canonical_source_v7",
                    "build_hierarchical_state_features_v7",
                    "build_r4_fold_plan_v7",
                    "fit_chronological_prefix_v7",
                    "run_frozen_decision_block_v7",
                ],
                "source_lineage": (
                    "scripts/model_lab/hierarchical_observable_fair_value_state_v9/"
                    "prediction_launcher.py:execute_task"
                ),
                "required_geometry": {
                    "tasks": 50,
                    "fits": 3_100,
                    "prediction_rows": 64_800,
                    "outer_workers": 32,
                    "inner_threads": 1,
                    "gpu": False,
                },
                "normalized_prediction_fields": [
                    "seed_alias",
                    "dgp_id",
                    "session_position",
                    "date",
                    "ticker",
                    "fold_id",
                    "expected_pe",
                    "expected_log_pe",
                    "uncertainty",
                    "confidence",
                    "source_model_version",
                    "prediction_valid",
                    "pit_valid",
                    "evidence_class",
                ],
            },
        },
        "tcn_blocker": {
            "status": "BLOCKED_IMPLEMENTATION",
            "design_checksums": {
                "relative_path": tcn_design.relative_to(project).as_posix(),
                "raw_sha256": TCN_V7_DESIGN_CHECKSUMS_SHA256,
            },
            "audit": {
                "relative_path": tcn_audit.relative_to(project).as_posix(),
                "raw_sha256": TCN_V7_AUDIT_SHA256,
                "verdict": "NO_GO_P0_P1_P2_0_1_0",
            },
            "audit_checksums": {
                "relative_path": tcn_audit_checksums.relative_to(project).as_posix(),
                "raw_sha256": TCN_V7_AUDIT_CHECKSUMS_SHA256,
            },
            "reason": "NO_PRIVATE_PROCESS_FULL_R4_RUNNER_OR_PREDICTION_ARTIFACT",
            "must_not_do": "DO_NOT_RUN_V7_AS_V8_OR_ADD_ANOTHER_IN_PROCESS_HOOK_PATCH",
            "required_adapter": {
                "adapter_id": "causal_tcn_spent_r4_panel_adapter_v1",
                "new_identity_required": True,
                "private_worker_owns": [
                    "module",
                    "encoder",
                    "training_center",
                    "optimizer",
                    "model_state",
                ],
                "public_inputs": [
                    "42 Observable-State V1 feature columns",
                    "v04_expected_pe",
                    "seed-DGP entity identity",
                    "canonical date",
                    "training-only DGP nuisance group",
                ],
                "training_contract": {
                    "sequence_length": 128,
                    "purge_sessions": 127,
                    "embargo_sessions": 5,
                    "minimum_training_rows": 756,
                    "primary_variant": "private-process successor of cvtcn_v7_tcn_residual",
                    "diagnostic_variants": ["GRU-D residual", "same-row static MLP"],
                },
                "required_output_rows": 64_800,
            },
        },
        "access": {
            "truth_payload_files_opened": 0,
            "latent_payload_files_opened": 0,
            "fresh_payload_files_opened": 0,
            "heldout_payload_files_opened": 0,
            "model_fits": 0,
            "predictions_created": 0,
        },
    }


__all__ = [
    "build_inventory",
    "sha256_bytes",
    "sha256_file",
]
