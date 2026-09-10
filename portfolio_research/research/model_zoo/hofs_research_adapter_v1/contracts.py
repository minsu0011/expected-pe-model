"""Immutable contracts for the isolated H-OFS spent-public research adapter."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Final


class HofsResearchAdapterError(RuntimeError):
    """Raised when the research adapter's fixed boundary drifts."""


FORMAT_VERSION: Final = 1
ADAPTER_ID: Final = "hofs_research_adapter_v1"
FULL_EXECUTION_ID: Final = "hofs_research_adapter_v1_full_r2"
MODEL_ID: Final = "hofs_research_adapter_v1_r2__audited_v7_numeric_lineage"
EVIDENCE_CLASS: Final = "RESEARCH_ONLY"
DETAILED_EVIDENCE_CLASS: Final = (
    "RESEARCH_ONLY_SPENT_PUBLIC_INPUT_PREDICTION_NOT_CERTIFICATION_OR_PROMOTION_EVIDENCE"
)

PUBLIC_INPUT_ROOT: Final = "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
PUBLIC_INPUT_PASS: Final = "replays/pass_1"
PUBLIC_FREEZE_RAW_SHA256: Final = (
    "f5125088b258925dec7854a29ab9da9f09698d3bbf79afa6b0896e7da959fe14"
)
PUBLIC_CHECKSUMS_RAW_SHA256: Final = (
    "fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7"
)
CANONICAL_INPUT_LEDGER_SHA256: Final = (
    "b768136055291bfbfa329959d8d1cbd572cf95fde27761e33d41de8da7b19a45"
)

SEEDS: Final = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
DGPS: Final = tuple("ABCDEFGHIJ")
ROWS_PER_TASK: Final = 1_800
SCORE_START: Final = 504
SCORE_END: Final = 1_800
BLOCK_ROWS: Final = 21
FOLDS_PER_TASK: Final = 62
TASK_COUNT: Final = 50
FIT_COUNT: Final = 3_100
PREDICTION_ROW_COUNT: Final = 64_800

FULL_OUTER_WORKERS: Final = 16
INNER_THREADS: Final = 1
BENCHMARK_WORKERS: Final = (4, 8, 12, 16)
BENCHMARK_TASK_COUNT: Final = 16
BENCHMARK_FOLD_INDICES: Final = (0, 20, 40, 61)
PROCESS_START_METHOD: Final = "spawn"
NONINFORMATIVE_GROUP_LABEL: Final = "PUBLIC_TASK_SINGLE_GROUP"
THREAD_ENVIRONMENT: Final = (
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("NUMEXPR_NUM_THREADS", "1"),
    ("CUDA_VISIBLE_DEVICES", "-1"),
)

V7_CONTRACT_SHA256: Final = "c4def6f1568df18f78d4329f75083640d118b45c7621c51b621ee0fb34682637"
V7_FIT_CONFIG_SHA256: Final = (
    "8cec07ee549e8183a221f396796d013923eb0f7f23532fb3a51fc004f30ff3a3"
)
V7_NUMERIC_SOURCE_SHA256: Final = {
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/__init__.py": (
        "339dde7e0a1b3a1fe96c7d55800c3898cc044b06989372d31a24b7c1f70dfd3e"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/adapter.py": (
        "7dc93b7e079e6ae5fcb910111f837d6167ab6b545cbf36610d238d8d24b8f694"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/artifacts.py": (
        "5acb9e0cca3e364a1be0108f6648d1b66cbb233dd4dbe396546607727bf9a89b"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/contracts.py": (
        "5b1001acf1a03ec36c68ddfcb372b965b9249b385de76cbfcaff72895707f4a9"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/custody.py": (
        "24b78bc46b08db6cf9570413f2f89ea00032e921b53c67dd1a5d3c814f4e9161"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/dgp_r4.py": (
        "dc680ffc87472745786411b39d981d613cf2cf378c077ccad1d90374394c725d"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/estimator.py": (
        "65992a8d1056b3c388efaf78de9c04adbd9520ef7532a5e4d715f943944d172c"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/features.py": (
        "8b4e05d64254ac68ec8ee05df5b92deafe16eed3fe82158662b8da7f6d76d475"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/runner.py": (
        "539a7ef948fc8475ec69f19440e1ce3618d21fa18dde2a1f5c19858238cef5ff"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/runtime.py": (
        "7109669c36cad34288bd275b7ab131331f4b0c7e22376651dfd03e19f8d92077"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/source_audit.py": (
        "9edbfe42b0c3d8e5cd462429955c74e5ade2f4e59d564694837a4a9005d3d4fc"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/validation.py": (
        "b61514f430011e95144734db7bb5f7367a02b9e9b7c40c7a0376a3630c80d096"
    ),
}

PREDICTION_COLUMNS: Final = (
    "task_ordinal",
    "task_seed",
    "task_dgp",
    "fold_index",
    "source_row_position",
    "entity_id",
    "decision_date",
    "hofs_v7_expected_pe",
    "hofs_v7_pe_p10",
    "hofs_v7_pe_p90",
    "hofs_v7_log_scale",
    "hofs_v7_tail_guard_weight",
    "parameter_sha256",
    "decision_block_ordered_membership_sha256",
    "decision_block_set_membership_sha256",
    "decision_source_positions_sha256",
    "output_manifest_sha256",
    "within_block_parameter_update_count",
)

SMOKE_OUTPUT_ROOT: Final = "outputs/model_zoo_hofs_research_adapter_v1_smoke_r1_20260822"
BENCHMARK_OUTPUT_ROOT: Final = (
    "outputs/model_zoo_hofs_research_adapter_v1_worker_benchmark_r1_20260822"
)
FAILED_R1_OUTPUT_ROOT: Final = "outputs/model_zoo_hofs_research_adapter_v1_full_r1_20260822"
FAILURE_RECEIPT_ROOT: Final = (
    "outputs/model_zoo_hofs_research_adapter_v1_full_r1_failure_receipt_20260822"
)
R2_PREFLIGHT_ROOT: Final = (
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_preflight_20260822"
)
FULL_OUTPUT_ROOT: Final = "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822"


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def semantic_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def design_payload() -> dict[str, Any]:
    """Return the complete score-free adapter design declaration."""

    return {
        "format_version": FORMAT_VERSION,
        "adapter_id": ADAPTER_ID,
        "full_execution_id": FULL_EXECUTION_ID,
        "model_id": MODEL_ID,
        "evidence_class": EVIDENCE_CLASS,
        "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
        "purpose": "PE-C4_SPENT_PUBLIC_R4_PREDICTION_ADAPTER",
        "authority": {
            "formal_model_identity": False,
            "service_identity": False,
            "certification": False,
            "qualification": False,
            "promotion": False,
            "registry_or_champion_mutation": False,
            "score": False,
            "prediction_research_only": True,
        },
        "numeric_lineage": {
            "policy": "CALL_EXACT_AUDITED_V7_FUNCTIONS_WITHOUT_PATCH_OR_LAUNCHER_REUSE",
            "v7_contract_sha256": V7_CONTRACT_SHA256,
            "v7_fit_config_sha256": V7_FIT_CONFIG_SHA256,
            "source_sha256": dict(V7_NUMERIC_SOURCE_SHA256),
            "called_functions": [
                "adapt_r4_canonical_source_v7",
                "build_hierarchical_state_features_v7",
                "build_r4_fold_plan_v7",
                "fit_chronological_prefix_v7",
                "run_frozen_decision_block_v7",
            ],
            "legacy_launcher_or_service_called": False,
            "seed_or_dgp_numeric_input": False,
            "nuisance_membership_policy": (
                "ONE_CONSTANT_NONINFORMATIVE_LABEL_FOR_EVERY_TASK; "
                "SEED_AND_DGP_USED_ONLY_FOR_PATH_FOLD_CUSTODY_AND_OUTPUT_IDENTITY"
            ),
        },
        "inputs": {
            "root": PUBLIC_INPUT_ROOT,
            "pass": PUBLIC_INPUT_PASS,
            "allowed_payload": "canonical150.csv_ONLY",
            "canonical_file_count": TASK_COUNT,
            "freeze_raw_sha256": PUBLIC_FREEZE_RAW_SHA256,
            "checksums_raw_sha256": PUBLIC_CHECKSUMS_RAW_SHA256,
            "canonical_ledger_sha256": CANONICAL_INPUT_LEDGER_SHA256,
            "external_path_arguments": False,
        },
        "geometry": {
            "seeds": list(SEEDS),
            "dgps": list(DGPS),
            "tasks": TASK_COUNT,
            "rows_per_task": ROWS_PER_TASK,
            "score_start_inclusive": SCORE_START,
            "score_end_exclusive": SCORE_END,
            "folds_per_task": FOLDS_PER_TASK,
            "fits": FIT_COUNT,
            "prediction_rows": PREDICTION_ROW_COUNT,
            "within_block_updates": 0,
        },
        "missing_and_fallback": {
            "champion_overlay_opened": False,
            "champion_prediction_fallback": "FORBIDDEN",
            "missing_prediction_policy": "FAIL_TASK_AND_ABORT_ATOMIC_PUBLICATION",
            "nonfinite_prediction_policy": "FAIL_TASK_AND_ABORT_ATOMIC_PUBLICATION",
            "zero_fill": False,
            "partial_publish": False,
        },
        "resources": {
            "full_outer_workers": FULL_OUTER_WORKERS,
            "inner_threads": INNER_THREADS,
            "process_start_method": PROCESS_START_METHOD,
            "thread_environment": dict(THREAD_ENVIRONMENT),
            "gpu_used": False,
            "benchmark_workers": list(BENCHMARK_WORKERS),
            "benchmark_tasks": BENCHMARK_TASK_COUNT,
            "benchmark_fold_indices": list(BENCHMARK_FOLD_INDICES),
        },
        "publication": {
            "same_parent_staging": True,
            "exclusive_destination": True,
            "atomic_directory_replace": True,
            "checksums": True,
            "overwrite": False,
        },
        "standardized_adapter": {
            "module": "research.model_zoo.pre_certification_research_tournament_v1.adapters",
            "function": "normalize_hofs_rows",
            "expected_source_columns": list(PREDICTION_COLUMNS),
            "model_id": MODEL_ID,
        },
    }


def design_sha256() -> str:
    return semantic_sha256(design_payload())


__all__ = [
    "ADAPTER_ID",
    "BENCHMARK_FOLD_INDICES",
    "BENCHMARK_OUTPUT_ROOT",
    "BENCHMARK_TASK_COUNT",
    "BENCHMARK_WORKERS",
    "BLOCK_ROWS",
    "CANONICAL_INPUT_LEDGER_SHA256",
    "DETAILED_EVIDENCE_CLASS",
    "DGPS",
    "EVIDENCE_CLASS",
    "FIT_COUNT",
    "FOLDS_PER_TASK",
    "FULL_OUTER_WORKERS",
    "FULL_EXECUTION_ID",
    "FULL_OUTPUT_ROOT",
    "FAILED_R1_OUTPUT_ROOT",
    "FAILURE_RECEIPT_ROOT",
    "HofsResearchAdapterError",
    "INNER_THREADS",
    "MODEL_ID",
    "NONINFORMATIVE_GROUP_LABEL",
    "PREDICTION_COLUMNS",
    "PREDICTION_ROW_COUNT",
    "PROCESS_START_METHOD",
    "PUBLIC_CHECKSUMS_RAW_SHA256",
    "PUBLIC_FREEZE_RAW_SHA256",
    "PUBLIC_INPUT_PASS",
    "PUBLIC_INPUT_ROOT",
    "R2_PREFLIGHT_ROOT",
    "ROWS_PER_TASK",
    "SCORE_END",
    "SCORE_START",
    "SEEDS",
    "SMOKE_OUTPUT_ROOT",
    "TASK_COUNT",
    "THREAD_ENVIRONMENT",
    "V7_CONTRACT_SHA256",
    "V7_FIT_CONFIG_SHA256",
    "V7_NUMERIC_SOURCE_SHA256",
    "canonical_json_bytes",
    "design_payload",
    "design_sha256",
    "semantic_sha256",
]
