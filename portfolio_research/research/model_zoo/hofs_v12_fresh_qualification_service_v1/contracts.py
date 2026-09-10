"""Truth-free contracts for the blocked PE-C4 H-OFS V12 qualification service."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
from typing import Any, Final, Mapping

from research.model_zoo.hofs_research_adapter_v1.contracts import (
    NONINFORMATIVE_GROUP_LABEL,
    THREAD_ENVIRONMENT,
    V7_CONTRACT_SHA256,
    V7_FIT_CONFIG_SHA256,
    V7_NUMERIC_SOURCE_SHA256,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    C4_ID,
    HOFS_TASK_SURFACE_COLUMNS,
    IDENTITY_COLUMNS,
)


class HofsV12QualificationServiceError(RuntimeError):
    """Raised before a qualification surface can escape a frozen boundary."""


SERVICE_ID: Final = "hofs_v12_fresh_qualification_service_v1"
SERVICE_SCHEMA_VERSION: Final = "expected_pe.hofs_v12.qualification_service.v1"
TASK_MANIFEST_SCHEMA_VERSION: Final = "expected_pe.hofs_v12.external_task_binding.v1"
TASK_MANIFEST_STATUS: Final = "PASS_EXTERNAL_PRETRUTH_COMMON_TASK_BINDING"
EVIDENCE_CLASS: Final = "QUALIFICATION_PRETRUTH_PREDICTION_SERVICE"
CANDIDATE_ID: Final = C4_ID

QUALIFICATION_SEEDS: Final = (7573, 7577, 7583, 7589, 7591)
SEED_ALIASES: Final = tuple(
    f"qualification_seed_{ordinal:02d}" for ordinal in range(1, len(QUALIFICATION_SEEDS) + 1)
)
SEED_ALIAS_TO_QUALIFICATION_SEED: Final = dict(
    zip(SEED_ALIASES, QUALIFICATION_SEEDS, strict=True)
)
QUALIFICATION_SEED_TO_ALIAS: Final = {
    seed: alias for alias, seed in SEED_ALIAS_TO_QUALIFICATION_SEED.items()
}
DGP_IDS: Final = tuple("ABCDEFGHIJ")
TASK_COUNT: Final = len(SEED_ALIASES) * len(DGP_IDS)
SYMBOL: Final = "DGP_ISSUER"

SOURCE_ROWS_PER_TASK: Final = 1_800
FIRST_PREDICTION_POSITION: Final = 504
SCORE_END_EXCLUSIVE: Final = 1_800
REGULAR_BLOCK_ROWS: Final = 21
FOLDS_PER_TASK: Final = 62
PREDICTION_ROWS_PER_TASK: Final = SCORE_END_EXCLUSIVE - FIRST_PREDICTION_POSITION
FIRST_FOLD_NUMBER: Final = 12
FINAL_FOLD_NUMBER: Final = 73
WITHIN_BLOCK_PARAMETER_UPDATE_COUNT: Final = 0

CANONICAL_COLUMN_COUNT: Final = 150
CANONICAL_HEADER_SHA256: Final = (
    "384058edbe1f7a84994374953f53a2782ab364e772b97219fbe3e5d81c6ad68e"
)
CANONICAL_COLUMNS: Final = (
    "date",
    "open",
    "high",
    "low",
    "close",
    "volume",
    "stock_split",
    "symbol",
    "available_at",
    "eps_ttm_raw",
    "filed_at",
    "period_end",
    "eps_method",
    "eps_primary_method",
    "eps_definition",
    "eps_disagreement",
    "eps_confidence",
    "timestamp_exact",
    "eps_method_count",
    "eps_method_values",
    "eps_approximation_flag",
    "eps_reconstruction_approximate",
    "eps_quarter_sources",
    "accession",
    "fiscal_period",
    "source_tag",
    "eps_source_tag",
    "shares_source_tag",
    "event_source",
    "effective_date",
    "eps_split_factor",
    "eps_ttm",
    "negative_earnings_flag",
    "observed_pe",
    "earnings_yield",
    "eps_staleness_days",
    "eps_period_age_days",
    "price_basis",
    "stock_return_5",
    "pe_change_5",
    "pe_log_change_5",
    "stock_return_20",
    "pe_change_20",
    "pe_log_change_20",
    "stock_return_63",
    "pe_change_63",
    "pe_log_change_63",
    "stock_return_126",
    "pe_change_126",
    "pe_log_change_126",
    "stock_return_252",
    "pe_change_252",
    "pe_log_change_252",
    "eps_ttm_growth_252",
    "eps_ttm_growth_126",
    "pe_lag_21",
    "log_pe_lag_21",
    "pe_median_252_lag",
    "pe_median_756_lag",
    "benchmark_close",
    "benchmark_return_1",
    "benchmark_return_5",
    "benchmark_return_21",
    "benchmark_return_63",
    "benchmark_return_126",
    "benchmark_return_252",
    "benchmark_realized_vol_10",
    "benchmark_realized_vol_20",
    "benchmark_realized_vol_63",
    "benchmark_sma_20",
    "benchmark_sma_50",
    "benchmark_sma_200",
    "benchmark_price_vs_sma_50",
    "benchmark_price_vs_sma_200",
    "benchmark_sma_50_vs_200",
    "benchmark_sma_200_slope_20",
    "benchmark_drawdown_252",
    "benchmark_trend_efficiency_63",
    "benchmark_volume_log_z_63",
    "p_bear",
    "p_sideways",
    "p_bull",
    "regime_entropy",
    "regime_agreement",
    "ensemble_dynamic_active",
    "regime_active_model_count",
    "regime_effective_model_count",
    "regime_diversity_factor",
    "weight_rule",
    "loss_rule",
    "weight_sjm3",
    "loss_sjm3",
    "weight_sjm2_gate",
    "loss_sjm2_gate",
    "weight_hmm3",
    "loss_hmm3",
    "market_regime",
    "regime_confidence",
    "forecast_p_bear",
    "forecast_p_sideways",
    "forecast_p_bull",
    "rule_p_bear",
    "rule_p_sideways",
    "rule_p_bull",
    "sjm3_p_bear",
    "sjm3_p_sideways",
    "sjm3_p_bull",
    "sjm2_gate_p_bear",
    "sjm2_gate_p_sideways",
    "sjm2_gate_p_bull",
    "sjm2_p_bear",
    "sjm2_p_sideways",
    "sjm2_p_bull",
    "hmm3_p_bear",
    "hmm3_p_sideways",
    "hmm3_p_bull",
    "pe_bear_median",
    "pe_bear_log_mean",
    "pe_bear_log_std",
    "pe_bear_percentile",
    "pe_bear_log_z",
    "pe_bear_effective_history",
    "pe_sideways_median",
    "pe_sideways_log_mean",
    "pe_sideways_log_std",
    "pe_sideways_percentile",
    "pe_sideways_log_z",
    "pe_sideways_effective_history",
    "pe_bull_median",
    "pe_bull_log_mean",
    "pe_bull_log_std",
    "pe_bull_percentile",
    "pe_bull_log_z",
    "pe_bull_effective_history",
    "pe_history_count",
    "statistical_expected_pe",
    "regime_conditional_pe_percentile",
    "regime_conditional_pe_log_z",
    "regime_adjusted_valuation_score",
    "ml_expected_pe",
    "expected_pe",
    "expected_pe_weight_stat",
    "expected_pe_weight_ml",
    "expected_pe_stat_oos_log_mae",
    "expected_pe_ml_oos_log_mae",
    "expected_pe_blend_dynamic",
    "pe_gap_log",
    "pe_gap_percent",
    "valuation_state",
    "valuation_confidence",
)
R4_NUMERIC_COLUMN_COUNT: Final = 22
UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE: Final = (
    "regime_adjusted_valuation_score"
)

OUTER_WORKERS: Final = 16
LOGICAL_CPUS_PER_WORKER: Final = 32
INNER_THREADS: Final = 1
PROCESS_START_METHOD: Final = "spawn"
EXPECTED_CPU_IDS: Final = tuple(range(32))
WORKER_AFFINITY_MASK: Final = 0xFFFFFFFF
WORKER_AFFINITY_POLICY: Final = "EVERY_WORKER_SEES_THE_SAME_FULL_MACHINE_MASK"
GPU_OFF_ENVIRONMENT: Final = dict(THREAD_ENVIRONMENT)

RESOURCE_RESOLUTION_LOCK_RELATIVE: Final = (
    "research/model_zoo/portfolio_governance_v1/"
    "HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json"
)
RESOURCE_RESOLUTION_LOCK_RAW_SHA256: Final = (
    "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c"
)
RESOURCE_RESOLUTION_LOCK_STATUS: Final = "DESIGN_LOCK_NO_EXECUTION_AUTHORITY"
NUMERIC_RESOURCE_GATE_STATUS: Final = "PASS_EXACT_LIVE_FULL_AFFINITY_ENVIRONMENT"

RUNTIME_PREBINDING_SCHEMA_VERSION: Final = "expected_pe.hofs_v12.runtime_prebinding.v1"
RUNTIME_PREBINDING_STATUS: Final = (
    "PRE_BINDING_EXTERNAL_WRAPPER_MEASUREMENT_AND_FILE_ID_REQUIRED"
)
RUNTIME_LANE_ID: Final = "isolated_c4"
RUNTIME_PREBINDING_FIELDS: Final = (
    "schema_version",
    "status",
    "candidate_ids",
    "ended_perf_counter_ns",
    "gpu_process_observation_count",
    "lane_id",
    "peak_process_tree_rss_bytes",
    "peak_vram_bytes",
    "process_exit_records",
    "sample_count",
    "sample_interval_max_ms",
    "started_perf_counter_ns",
    "wall_time_ns",
)
PROCESS_EXIT_FIELDS: Final = ("process_role", "worker_ordinal", "exit_code")

ACTUAL_COMMON_PATH_BINDING_STATUS: Final = (
    "PENDING_PRETRUTH_ACTUAL_COMMON_PATH_BINDING"
)
SOURCE_MODEL_VERSION_BINDING_STATUS: Final = "PENDING_FINAL_V12_SOURCE_CLOSURE_SHA256"
PRODUCTION_NUMERIC_AUTHORITY_STATUS: Final = (
    "DENIED_PENDING_EXTERNAL_BINDING_SOURCE_FREEZE_AND_ROOT_AUTHORITY"
)
SOURCE_MODEL_VERSION_PREFIX: Final = SERVICE_ID
SPENT_RESEARCH_ONLY_SCHEMA_VERSION: Final = (
    "expected_pe.hofs_v12.spent_research_only_fixed_input.v1"
)
SPENT_RESEARCH_ONLY_STATUS: Final = (
    "SPENT_RESEARCH_ONLY_FIXED_PUBLIC_INPUT_NO_QUALIFICATION_AUTHORITY"
)
SPENT_RESEARCH_ONLY_SEED_ALIAS: Final = "spent_research_seed_2026082001"
SPENT_RESEARCH_ONLY_SEED: Final = 2_026_082_001
SPENT_RESEARCH_ONLY_DGP_ID: Final = "A"
SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256: Final = (
    "aa6bb2f3e63b4423c79a578c3ed2fb8353050dd5ed7dc2d117931abfde1bb384"
)
SPENT_RESEARCH_ONLY_ACCESS_COUNTER_FIELDS: Final = (
    "qualification_access_count",
    "fresh_access_count",
    "truth_access_count",
    "heldout_access_count",
    "score_access_count",
)
SPENT_EVIDENCE_OUTPUT_ROOT: Final = (
    "outputs/model_zoo_hofs_v12_resource_resolution_spent_evidence_v1_20260822"
)
SPENT_EVIDENCE_STAGING_ROOT: Final = (
    "outputs/.model_zoo_hofs_v12_resource_resolution_spent_evidence_v1_20260822.staging"
)

V7_RUNTIME_ENVELOPE_CONFLICT_ID: Final = "P0_V7_32CPU_VS_V12_2CPU_AFFINITY_CONFLICT"
V7_RUNTIME_ENVELOPE_CONFLICT_STATUS: Final = (
    "RESOLVED_BY_FULL_MACHINE_AFFINITY_WITH_EXACT_LIVE_GATE"
)
V7_REQUIRED_AFFINITY_MASK: Final = 0xFFFFFFFF
V7_REQUIRED_LOGICAL_CPU_COUNT: Final = 32
V7_REQUIRED_OUTER_WORKERS: Final = 32

_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")

_CANONICAL_HEADER_OBSERVED_SHA256 = hashlib.sha256(
    json.dumps(
        list(CANONICAL_COLUMNS), separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
).hexdigest()
if (
    len(CANONICAL_COLUMNS) != CANONICAL_COLUMN_COUNT
    or len(set(CANONICAL_COLUMNS)) != CANONICAL_COLUMN_COUNT
    or _CANONICAL_HEADER_OBSERVED_SHA256 != CANONICAL_HEADER_SHA256
):
    raise HofsV12QualificationServiceError("embedded canonical150 header drifted")

TASK_MANIFEST_FIELDS: Final = (
    "schema_version",
    "status",
    "task_ordinal",
    "qualification_seed",
    "seed_alias",
    "dgp_id",
    "canonical_raw_sha256",
    "canonical_semantic_sha256",
    "canonical_header_sha256",
    "canonical_rows",
    "canonical_columns",
    "common_task_manifest_raw_sha256",
    "common_task_manifest_semantic_sha256",
    "common_task_manifest_volume_serial_number",
    "common_task_manifest_file_id_128",
    "actual_common_path_binding_status",
)


def _require_hex64(value: object, *, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise HofsV12QualificationServiceError(f"{label} must be 64 lowercase hex digits")
    return value


def _require_exact_int(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise HofsV12QualificationServiceError(f"{label} must be an exact integer >= {minimum}")
    return value


def validate_exact_json_primitives(value: object, *, path: str = "$") -> None:
    """Reject numpy/pandas scalars, tuples, nonfinite floats, and non-string keys."""

    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise HofsV12QualificationServiceError(f"nonfinite JSON float at {path}")
        return
    if type(value) is list:
        for ordinal, item in enumerate(value):
            validate_exact_json_primitives(item, path=f"{path}[{ordinal}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise HofsV12QualificationServiceError(f"non-string JSON key at {path}")
            validate_exact_json_primitives(item, path=f"{path}.{key}")
        return
    raise HofsV12QualificationServiceError(
        f"non-native JSON value at {path}: {type(value).__name__}"
    )


def canonical_json_bytes(payload: object) -> bytes:
    """Return V2 canonical pretty JSON bytes, including one terminal LF."""

    validate_exact_json_primitives(payload)
    return (
        json.dumps(
            payload,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def semantic_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class QualificationFoldSpec:
    """One direct, seed-free strict-prefix fold in the frozen 504:1800:21 geometry."""

    fold_ordinal: int
    fold_id: str
    fit_prefix_end_exclusive: int
    decision_block_start_inclusive: int
    decision_block_end_exclusive: int
    decision_row_count: int
    within_block_parameter_update_count: int = WITHIN_BLOCK_PARAMETER_UPDATE_COUNT

    def __post_init__(self) -> None:
        ordinal = _require_exact_int(self.fold_ordinal, label="fold ordinal")
        if ordinal >= FOLDS_PER_TASK:
            raise HofsV12QualificationServiceError("fold ordinal escaped the frozen geometry")
        expected_start = FIRST_PREDICTION_POSITION + ordinal * REGULAR_BLOCK_ROWS
        expected_end = min(expected_start + REGULAR_BLOCK_ROWS, SCORE_END_EXCLUSIVE)
        expected_fold_id = f"fold_{FIRST_FOLD_NUMBER + ordinal:03d}"
        if (
            self.fold_id != expected_fold_id
            or self.fit_prefix_end_exclusive != expected_start
            or self.decision_block_start_inclusive != expected_start
            or self.decision_block_end_exclusive != expected_end
            or self.decision_row_count != expected_end - expected_start
            or self.within_block_parameter_update_count != 0
        ):
            raise HofsV12QualificationServiceError("fold geometry or causal policy drifted")

    def payload(self) -> dict[str, Any]:
        return asdict(self)


def build_qualification_fold_plan() -> tuple[QualificationFoldSpec, ...]:
    """Build the qualification schedule directly, without a spent-seed plan."""

    plan = tuple(
        QualificationFoldSpec(
            fold_ordinal=ordinal,
            fold_id=f"fold_{FIRST_FOLD_NUMBER + ordinal:03d}",
            fit_prefix_end_exclusive=FIRST_PREDICTION_POSITION
            + ordinal * REGULAR_BLOCK_ROWS,
            decision_block_start_inclusive=FIRST_PREDICTION_POSITION
            + ordinal * REGULAR_BLOCK_ROWS,
            decision_block_end_exclusive=min(
                FIRST_PREDICTION_POSITION + (ordinal + 1) * REGULAR_BLOCK_ROWS,
                SCORE_END_EXCLUSIVE,
            ),
            decision_row_count=min(
                FIRST_PREDICTION_POSITION + (ordinal + 1) * REGULAR_BLOCK_ROWS,
                SCORE_END_EXCLUSIVE,
            )
            - (FIRST_PREDICTION_POSITION + ordinal * REGULAR_BLOCK_ROWS),
        )
        for ordinal in range(FOLDS_PER_TASK)
    )
    sizes = tuple(item.decision_row_count for item in plan)
    if sizes != (21,) * 61 + (15,) or sum(sizes) != PREDICTION_ROWS_PER_TASK:
        raise HofsV12QualificationServiceError("aggregate fold geometry drifted")
    return plan


@dataclass(frozen=True)
class ExternalTaskBinding:
    """Path-free binding supplied by the separately authenticated common manifest."""

    schema_version: str
    status: str
    task_ordinal: int
    qualification_seed: int
    seed_alias: str
    dgp_id: str
    canonical_raw_sha256: str
    canonical_semantic_sha256: str
    canonical_header_sha256: str
    canonical_rows: int
    canonical_columns: int
    common_task_manifest_raw_sha256: str
    common_task_manifest_semantic_sha256: str
    common_task_manifest_volume_serial_number: int
    common_task_manifest_file_id_128: str
    actual_common_path_binding_status: str

    def __post_init__(self) -> None:
        if self.schema_version != TASK_MANIFEST_SCHEMA_VERSION or self.status != TASK_MANIFEST_STATUS:
            raise HofsV12QualificationServiceError("external task binding identity drifted")
        ordinal = _require_exact_int(self.task_ordinal, label="task ordinal")
        if ordinal >= TASK_COUNT:
            raise HofsV12QualificationServiceError("task ordinal escaped the 50-task universe")
        if type(self.qualification_seed) is not int:
            raise HofsV12QualificationServiceError("qualification seed must be an exact integer")
        if self.seed_alias not in SEED_ALIASES or self.dgp_id not in DGP_IDS:
            raise HofsV12QualificationServiceError("task alias or DGP escaped the frozen universe")
        if SEED_ALIAS_TO_QUALIFICATION_SEED[self.seed_alias] != self.qualification_seed:
            raise HofsV12QualificationServiceError("qualification seed-to-alias binding drifted")
        expected_ordinal = SEED_ALIASES.index(self.seed_alias) * len(DGP_IDS) + DGP_IDS.index(
            self.dgp_id
        )
        if ordinal != expected_ordinal:
            raise HofsV12QualificationServiceError("task order is not alias-major, DGP-minor")
        for label, value in (
            ("canonical raw SHA-256", self.canonical_raw_sha256),
            ("canonical semantic SHA-256", self.canonical_semantic_sha256),
            ("common task manifest raw SHA-256", self.common_task_manifest_raw_sha256),
            (
                "common task manifest semantic SHA-256",
                self.common_task_manifest_semantic_sha256,
            ),
        ):
            _require_hex64(value, label=label)
        if self.canonical_header_sha256 != CANONICAL_HEADER_SHA256:
            raise HofsV12QualificationServiceError("canonical header binding drifted")
        if (
            self.canonical_rows != SOURCE_ROWS_PER_TASK
            or self.canonical_columns != CANONICAL_COLUMN_COUNT
        ):
            raise HofsV12QualificationServiceError("canonical geometry binding drifted")
        _require_exact_int(
            self.common_task_manifest_volume_serial_number,
            label="common task manifest volume serial number",
        )
        if (
            type(self.common_task_manifest_file_id_128) is not str
            or _HEX32.fullmatch(self.common_task_manifest_file_id_128) is None
        ):
            raise HofsV12QualificationServiceError(
                "common task manifest FileId must be 32 lowercase hex digits"
            )
        if self.actual_common_path_binding_status != ACTUAL_COMMON_PATH_BINDING_STATUS:
            raise HofsV12QualificationServiceError(
                "actual common path binding must remain explicitly pending"
            )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> ExternalTaskBinding:
        if type(value) is not dict or set(value) != set(TASK_MANIFEST_FIELDS):
            raise HofsV12QualificationServiceError("external task binding field universe drifted")
        return cls(**{field: value[field] for field in TASK_MANIFEST_FIELDS})  # type: ignore[arg-type]

    def payload(self) -> dict[str, Any]:
        return asdict(self)


def build_source_model_version(source_closure_sha256: str) -> str:
    """Build the final C4 version string once an external freeze binds service bytes."""

    closure = _require_hex64(source_closure_sha256, label="V12 source closure SHA-256")
    return (
        f"{SOURCE_MODEL_VERSION_PREFIX}__source_closure_sha256_{closure}"
        "__frozen_v7_r2_numeric_lineage"
    )


def task_identity_from_ordinal(task_ordinal: int) -> tuple[str, str]:
    ordinal = _require_exact_int(task_ordinal, label="task ordinal")
    if ordinal >= TASK_COUNT:
        raise HofsV12QualificationServiceError("task ordinal escaped the 50-task universe")
    seed_index, dgp_index = divmod(ordinal, len(DGP_IDS))
    return SEED_ALIASES[seed_index], DGP_IDS[dgp_index]


def contract_payload() -> dict[str, Any]:
    """Return a deterministic declaration with no execution or filesystem authority."""

    return {
        "schema_version": SERVICE_SCHEMA_VERSION,
        "service_id": SERVICE_ID,
        "candidate_id": CANDIDATE_ID,
        "evidence_class": EVIDENCE_CLASS,
        "authority": {
            "actual_numeric_launch": False,
            "fresh_or_heldout_discovery": False,
            "path_input": False,
            "publication": False,
            "score_or_truth_input": False,
            "spent_public_equivalence_smoke": True,
        },
        "task_contract": {
            "qualification_seed_to_alias": dict(QUALIFICATION_SEED_TO_ALIAS),
            "dgp_ids": list(DGP_IDS),
            "task_count": TASK_COUNT,
            "task_order": "seed_alias_major_then_dgp_id_minor",
            "seed_numeric_input_to_estimator_or_router": False,
            "dgp_numeric_input_to_estimator_or_router": False,
            "actual_common_path_binding_status": ACTUAL_COMMON_PATH_BINDING_STATUS,
            "production_numeric_authority_status": PRODUCTION_NUMERIC_AUTHORITY_STATUS,
            "spent_research_only_identity": {
                "schema_version": SPENT_RESEARCH_ONLY_SCHEMA_VERSION,
                "status": SPENT_RESEARCH_ONLY_STATUS,
                "seed_alias": SPENT_RESEARCH_ONLY_SEED_ALIAS,
                "spent_seed": SPENT_RESEARCH_ONLY_SEED,
                "dgp_id": SPENT_RESEARCH_ONLY_DGP_ID,
                "canonical_raw_sha256": SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256,
                "qualification_path_callable": False,
                "access_counts": {
                    field: 0 for field in SPENT_RESEARCH_ONLY_ACCESS_COUNTER_FIELDS
                },
            },
        },
        "input_contract": {
            "injected_types": ["bytes", "pandas.DataFrame"],
            "public_numeric_entry_type": "bytes",
            "csv_parser": "FROZEN_R2_PANDAS_READ_CSV_DEFAULT",
            "canonical_header_sha256": CANONICAL_HEADER_SHA256,
            "canonical_columns": CANONICAL_COLUMN_COUNT,
            "rows": SOURCE_ROWS_PER_TASK,
            "numeric_column_count": R4_NUMERIC_COLUMN_COUNT,
            "score_named_upstream_column_excluded": (
                UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE
            ),
            "path_arguments": False,
        },
        "geometry": {
            "first_prediction_position": FIRST_PREDICTION_POSITION,
            "score_end_exclusive": SCORE_END_EXCLUSIVE,
            "block_rows": REGULAR_BLOCK_ROWS,
            "folds": FOLDS_PER_TASK,
            "prediction_rows": PREDICTION_ROWS_PER_TASK,
            "within_block_parameter_updates": 0,
        },
        "output_columns": list(HOFS_TASK_SURFACE_COLUMNS),
        "numeric_lineage": {
            "v7_contract_sha256": V7_CONTRACT_SHA256,
            "v7_fit_config_sha256": V7_FIT_CONFIG_SHA256,
            "v7_source_sha256": dict(V7_NUMERIC_SOURCE_SHA256),
            "noninformative_group_label": NONINFORMATIVE_GROUP_LABEL,
            "expected_log_pe_formula": "log(v7_expected_pe)",
            "tail_guard_and_log_scale": "identity",
        },
        "resources": {
            "outer_workers": OUTER_WORKERS,
            "logical_cpus_per_worker": LOGICAL_CPUS_PER_WORKER,
            "worker_affinity_policy": WORKER_AFFINITY_POLICY,
            "worker_affinity_mask_hex": f"0x{WORKER_AFFINITY_MASK:08X}",
            "worker_cpu_ids": list(EXPECTED_CPU_IDS),
            "inner_threads": INNER_THREADS,
            "process_start_method": PROCESS_START_METHOD,
            "gpu_off_environment": dict(GPU_OFF_ENVIRONMENT),
            "v7_resource_receipt_outer_workers_field": V7_REQUIRED_OUTER_WORKERS,
            "v7_outer_workers_semantics": (
                "FROZEN_V7_RUNTIME_DECLARATION_NOT_C4_CONTROLLER_POOL_SIZE"
            ),
        },
        "runtime_conflict": {
            "id": V7_RUNTIME_ENVELOPE_CONFLICT_ID,
            "status": V7_RUNTIME_ENVELOPE_CONFLICT_STATUS,
            "v7_required_affinity_mask": f"0x{V7_REQUIRED_AFFINITY_MASK:08X}",
            "v7_required_logical_cpu_count": V7_REQUIRED_LOGICAL_CPU_COUNT,
            "v7_required_outer_workers": V7_REQUIRED_OUTER_WORKERS,
            "numeric_entry_gate_status": NUMERIC_RESOURCE_GATE_STATUS,
            "resource_resolution_lock_relative": RESOURCE_RESOLUTION_LOCK_RELATIVE,
            "resource_resolution_lock_raw_sha256": (
                RESOURCE_RESOLUTION_LOCK_RAW_SHA256
            ),
        },
        "runtime_receipt_boundary": {
            "service_artifact": RUNTIME_PREBINDING_STATUS,
            "evaluator_final_receipt_claimed_by_service": False,
            "external_wrapper_process_tree_sampling_required": True,
            "external_wrapper_file_id_and_raw_hash_binding_required": True,
            "sample_interval_max_ms": 100.0,
            "required_lane_id": RUNTIME_LANE_ID,
            "required_candidate_ids": [CANDIDATE_ID],
        },
        "source_model_version_binding_status": SOURCE_MODEL_VERSION_BINDING_STATUS,
    }


__all__ = [
    "ACTUAL_COMMON_PATH_BINDING_STATUS",
    "CANONICAL_COLUMN_COUNT",
    "CANONICAL_COLUMNS",
    "CANONICAL_HEADER_SHA256",
    "CANDIDATE_ID",
    "DGP_IDS",
    "EXPECTED_CPU_IDS",
    "ExternalTaskBinding",
    "FIRST_PREDICTION_POSITION",
    "FOLDS_PER_TASK",
    "GPU_OFF_ENVIRONMENT",
    "HOFS_TASK_SURFACE_COLUMNS",
    "HofsV12QualificationServiceError",
    "IDENTITY_COLUMNS",
    "INNER_THREADS",
    "LOGICAL_CPUS_PER_WORKER",
    "NUMERIC_RESOURCE_GATE_STATUS",
    "OUTER_WORKERS",
    "PREDICTION_ROWS_PER_TASK",
    "PROCESS_EXIT_FIELDS",
    "PROCESS_START_METHOD",
    "PRODUCTION_NUMERIC_AUTHORITY_STATUS",
    "QualificationFoldSpec",
    "QUALIFICATION_SEEDS",
    "QUALIFICATION_SEED_TO_ALIAS",
    "REGULAR_BLOCK_ROWS",
    "RESOURCE_RESOLUTION_LOCK_RAW_SHA256",
    "RESOURCE_RESOLUTION_LOCK_RELATIVE",
    "RESOURCE_RESOLUTION_LOCK_STATUS",
    "RUNTIME_PREBINDING_FIELDS",
    "RUNTIME_LANE_ID",
    "RUNTIME_PREBINDING_SCHEMA_VERSION",
    "RUNTIME_PREBINDING_STATUS",
    "SCORE_END_EXCLUSIVE",
    "SEED_ALIASES",
    "SEED_ALIAS_TO_QUALIFICATION_SEED",
    "SERVICE_ID",
    "SOURCE_MODEL_VERSION_BINDING_STATUS",
    "SPENT_RESEARCH_ONLY_ACCESS_COUNTER_FIELDS",
    "SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256",
    "SPENT_RESEARCH_ONLY_DGP_ID",
    "SPENT_RESEARCH_ONLY_SCHEMA_VERSION",
    "SPENT_RESEARCH_ONLY_SEED",
    "SPENT_RESEARCH_ONLY_SEED_ALIAS",
    "SPENT_RESEARCH_ONLY_STATUS",
    "SPENT_EVIDENCE_OUTPUT_ROOT",
    "SPENT_EVIDENCE_STAGING_ROOT",
    "SOURCE_ROWS_PER_TASK",
    "SYMBOL",
    "TASK_COUNT",
    "TASK_MANIFEST_FIELDS",
    "TASK_MANIFEST_SCHEMA_VERSION",
    "TASK_MANIFEST_STATUS",
    "UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE",
    "V7_CONTRACT_SHA256",
    "V7_FIT_CONFIG_SHA256",
    "V7_NUMERIC_SOURCE_SHA256",
    "V7_RUNTIME_ENVELOPE_CONFLICT_ID",
    "V7_RUNTIME_ENVELOPE_CONFLICT_STATUS",
    "WORKER_AFFINITY_MASK",
    "WORKER_AFFINITY_POLICY",
    "build_qualification_fold_plan",
    "build_source_model_version",
    "canonical_json_bytes",
    "contract_payload",
    "semantic_sha256",
    "task_identity_from_ordinal",
    "validate_exact_json_primitives",
]
