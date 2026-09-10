"""Exact no-run contract for the H-OFS V4 / public R4 integration draft.

This namespace deliberately has no model execution capability.  It documents
and proves the two requested surfaces cannot be combined without a maintenance
revision of the model contract.  The public input geometry is still fully
enumerated so a later V5 design can reuse an exact, score-blind custody plan.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Final, Mapping


class IntegrationContractError(RuntimeError):
    """Raised when input, design, or no-run custody differs from this contract."""


LAB_ID: Final = "hofs_v4_dgp_r4_prediction_lane_v1"
SCHEMA_VERSION: Final = "expected_pe.hofs_v4_dgp_r4_prediction_lane.v1"
STATUS: Final = "DRAFT_NO_GO_EXACT_V4_INTEGRATION_BLOCKED"
EVIDENCE_CLASS: Final = "SCORE_BLIND_PUBLIC_INPUT_DESIGN_PREFLIGHT_ONLY"

PUBLIC_INPUT_ROOT: Final = (
    "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
)
PUBLIC_INPUT_FREEZE_RAW_SHA256: Final = (
    "f5125088b258925dec7854a29ab9da9f09698d3bbf79afa6b0896e7da959fe14"
)
PUBLIC_INPUT_CHECKSUMS_RAW_SHA256: Final = (
    "fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7"
)
PUBLIC_CANONICAL_HEADER_SHA256: Final = (
    "384058edbe1f7a84994374953f53a2782ab364e772b97219fbe3e5d81c6ad68e"
)
PUBLIC_OBSERVABLE_STATE_CONTRACT_SHA256: Final = (
    "e2a03bd42de59df3d537e170dcba1713be545814b2054135475dedc54c0cde10"
)
PUBLIC_PASS_ID: Final = "pass_1"
SEEDS: Final = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
DGP_IDS: Final = tuple("ABCDEFGHIJ")

V4_DESIGN_ROOT: Final = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v4_"
    "design_preflight_20260821"
)
V4_DESIGN_CHECKSUMS_RAW_SHA256: Final = (
    "830ece4ee0db38359490e2f73a9d7dfeaf98271b58efa6dbca4b070216efe16a"
)
V4_DESIGN_LOCK_RAW_SHA256: Final = (
    "9c78db23623774f64147a331ffc8e08716fc0be2f77627cbdfd27ca4403c0406"
)
V4_DESIGN_CONTRACT_SHA256: Final = (
    "5af5003e853ee125d971d9283d15b7b952ad99423645a3c0437fb666f7a31c56"
)
V4_SOURCE_CLOSURE_RAW_SHA256: Final = (
    "6c60da692267ff2e3a97f245425c3128a67a5c3120215838ab9e0aefe67d65aa"
)
V4_SOURCE_CLOSURE_SEMANTIC_SHA256: Final = (
    "afc6aaf80748ecc4f382a807837c4bd7101fd0a6bcc7f78c0a7495ab510caf4a"
)
V4_AUDIT_ROOT: Final = (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v4_"
    "independent_audit_20260821"
)
V4_AUDIT_RAW_SHA256: Final = (
    "7c3de60249e4945a24226b9f2467b5bb7389cd875bb18f52d11746e5eca5b324"
)
V4_AUDIT_SEMANTIC_SHA256: Final = (
    "b157609efa9838e3ded33a6df73e767b365d8d863dc418df41bc9df167598650"
)
V4_AUDIT_SEAL_RAW_SHA256: Final = (
    "e77b797d4d366b77385ad80ae9284e74670148ffda14f13440462890fc54f58d"
)
V4_AUDIT_SEAL_SEMANTIC_SHA256: Final = (
    "e05322847af0f3845a2e50bd5a95c2bbb8cda0534917b32cf0ac4117c5469775"
)
V4_AUDIT_CHECKSUMS_RAW_SHA256: Final = (
    "cb0f16a42fec9ced397bb33b7ff5087266ce045e638d4c9d81c7c15dac114bec"
)
V4_AUDIT_VERDICT: Final = (
    "GO_FUTURE_SCORE_BLIND_PREDICTION_LANE_EXACT_FROZEN_V4_ONLY"
)

PINNED_PYTHON_VERSION: Final = "3.10.19"
PINNED_PYTHON_EXECUTABLE: Final = (
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
PINNED_PYTHON_EXECUTABLE_SHA256: Final = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)

MODEL_SOURCE_COLUMNS: Final = (
    "symbol",
    "date",
    "observed_pe",
    "eps_ttm",
    "eps_ttm_growth_126",
    "eps_ttm_growth_252",
    "eps_staleness_days",
    "eps_period_age_days",
    "eps_confidence",
    "eps_disagreement",
    "eps_approximation_flag",
    "benchmark_return_21",
    "benchmark_return_63",
    "benchmark_return_252",
    "benchmark_realized_vol_20",
    "benchmark_realized_vol_63",
    "benchmark_drawdown_252",
    "benchmark_sma_50_vs_200",
    "benchmark_trend_efficiency_63",
    "p_bear",
    "p_sideways",
    "p_bull",
)
MODEL_TARGET_COLUMN: Final = "observed_pe"
MODEL_ENTITY_COLUMN: Final = "symbol"
MODEL_DATE_COLUMN: Final = "date"
TRAINING_PROXY: Final = (
    "log(observed_pe_t)-prior_log_pe_t_on_strictly_earlier_fit_prefix"
)
OVERLAY_POLICY: Final = (
    "custody_only_assert_exact_canonical150_prefix_and_selected_public_columns;"
    "no_v04_extension_column_enters_model"
)
FORBIDDEN_MODEL_COLUMNS: Final = frozenset(
    {
        "true_fair_pe",
        "true_regime",
        "true_observed_pe",
        "latent",
        "score",
        "heldout",
        "vault",
        "evaluator",
        "registry",
        "expected_pe",
        "ml_expected_pe",
        "v04_expected_pe",
        "bce_prediction",
        "seed",
        "dgp_id",
        "research_dgp_id",
    }
)


@dataclass(frozen=True)
class FoldGeometry:
    rows_per_task: int = 1800
    first_test_position: int = 504
    end_exclusive: int = 1800
    regular_block_rows: int = 21
    terminal_block_rows: int = 15
    first_fold_number: int = 12
    task_count: int = 50

    @property
    def test_starts(self) -> tuple[int, ...]:
        return tuple(
            range(self.first_test_position, self.end_exclusive, self.regular_block_rows)
        )

    @property
    def fold_count_per_task(self) -> int:
        return len(self.test_starts)

    @property
    def decision_rows_per_task(self) -> int:
        return self.end_exclusive - self.first_test_position

    @property
    def total_fold_count(self) -> int:
        return self.task_count * self.fold_count_per_task

    @property
    def total_decision_count(self) -> int:
        return self.task_count * self.decision_rows_per_task

    @property
    def requested_fit_count(self) -> int:
        return self.total_fold_count

    @property
    def exact_v4_native_decision_capacity(self) -> int:
        return self.total_fold_count

    @property
    def exact_v4_uncovered_decision_count(self) -> int:
        return self.total_decision_count - self.exact_v4_native_decision_capacity

    def fold_id(self, test_start: int) -> str:
        if type(test_start) is not int or test_start not in self.test_starts:
            raise IntegrationContractError("test start is outside the exact R4 fold grid")
        offset = (test_start - self.first_test_position) // self.regular_block_rows
        return f"fold_{self.first_fold_number + offset:03d}"

    def test_end_exclusive(self, test_start: int) -> int:
        if test_start not in self.test_starts:
            raise IntegrationContractError("test start is outside the exact R4 fold grid")
        return min(self.end_exclusive, test_start + self.regular_block_rows)

    def __post_init__(self) -> None:
        values = tuple(asdict(self).values())
        if any(type(value) is not int for value in values):
            raise IntegrationContractError("fold geometry requires exact integers")
        sizes = [self.test_end_exclusive(start) - start for start in self.test_starts]
        if (
            self.fold_count_per_task != 62
            or sizes[:-1] != [21] * 61
            or sizes[-1] != self.terminal_block_rows
            or sum(sizes) != 1296
            or self.total_fold_count != 3100
            or self.total_decision_count != 64800
            or self.exact_v4_uncovered_decision_count != 61700
        ):
            raise IntegrationContractError("R4 fold/identity geometry drifted")


GEOMETRY: Final = FoldGeometry()

REQUESTED_RESOURCE_POLICY: Final = {
    "cpu_ids": list(range(32)),
    "affinity_mask_hex": "0xFFFFFFFF",
    "outer_workers": 32,
    "inner_threads": 1,
    "gpu_enabled": False,
    "gpu_disabled_environment": {"CUDA_VISIBLE_DEVICES": "-1"},
}
EXACT_V4_RESOURCE_POLICY: Final = {
    "cpu_ids": list(range(32)),
    "affinity_mask_hex": "0xFFFFFFFF",
    "max_outer_workers": 10,
    "inner_threads": 1,
    "gpu_usage": False,
    "gpu_disabled_environment": {"CUDA_VISIBLE_DEVICES": "-1"},
}

V4_RUNTIME_SOURCE_SHA256: Final = {
    "research/model_zoo/hierarchical_observable_fair_value_state_v4/adapter.py": (
        "927d76aaaaade29507b60725d15cfca31562940f47e4b1f3ce63134ec6ba7bd0"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v4/contracts.py": (
        "15e6f15da5707e77e561e393fa3656dd9f3feca1d077765f16e63877517a1af7"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v4/estimator.py": (
        "efe59fabb1e8a01311b0d719efb045a8b157fc2c71f2e9959cafd74527a21302"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v4/features.py": (
        "62e497602ec0c89ba8f7e00238dbd35a948347f1bb71ec9be0b951cd4d80713e"
    ),
    "research/model_zoo/hierarchical_observable_fair_value_state_v4/runner.py": (
        "27eccddeff03a8730a37b864e28713322037b63d10c4e117cd7110623b47ed2b"
    ),
}

BLOCKING_FINDINGS: Final = (
    {
        "finding_id": "P0-001_SINGLE_DECISION_DATE_BINDING_CONFLICTS_WITH_21_ROW_BLOCKS",
        "severity": "P0",
        "status": "OPEN_LAUNCH_BLOCKER",
        "requested": {
            "fits": 3100,
            "decision_identities": 64800,
            "fold_blocks": 3100,
        },
        "exact_v4": {
            "decision_dates_per_parameter_bundle": 1,
            "entities_per_public_task": 1,
            "native_decisions_from_requested_fits": 3100,
            "uncovered_decisions": 61700,
        },
        "evidence": (
            "DecisionBatchV4 requires one shared decision date and exact V4 inference "
            "requires that date to equal parameters.frozen_for_decision_date."
        ),
        "prohibited_workarounds": [
            "mutate_or_clone_parameter_decision_date_without_refit",
            "bypass_apply_frozen_parameters_v4",
            "increase_to_64800_fits",
            "discard_61700_decision_identities",
        ],
    },
    {
        "finding_id": "P0-002_OUTER32_CONFLICTS_WITH_EXACT_V4_MAX_OUTER10",
        "severity": "P0",
        "status": "OPEN_LAUNCH_BLOCKER",
        "requested_outer_workers": 32,
        "exact_v4_max_outer_workers": 10,
        "matching_resource_fields": [
            "cpu_ids_0_through_31",
            "affinity_mask_0xFFFFFFFF",
            "inner_threads_1",
            "gpu_off",
            "pinned_python_3_10_19",
        ],
        "prohibited_workarounds": [
            "reinterpret_outer32_as_nonbinding",
            "override_exact_v4_runtime_plan",
            "claim_clean_v4_audit_applies_to_a_different_resource_contract",
        ],
    },
    {
        "finding_id": "P0-003_FIRST_FOLD_HAS_ONLY_503_WARM_FIT_ROWS",
        "severity": "P0",
        "status": "OPEN_LAUNCH_BLOCKER",
        "first_test_position": 504,
        "strict_prefix_rows": 504,
        "causal_nonwarm_rows_for_single_entity_start": 1,
        "maximum_warm_fit_rows": 503,
        "exact_v4_minimum_warm_fit_rows": 504,
        "evidence": (
            "Observable State emits no prior offset for an entity's first row; exact V4 "
            "drops non-finite offsets before enforcing MIN_TRAIN_ROWS."
        ),
        "prohibited_workarounds": [
            "drop_first_evaluation_identity",
            "move_first_fold_start",
            "lower_MIN_TRAIN_ROWS_without_a_new_contract",
            "use_same_row_observed_pe_to_warm_the_prior",
        ],
    },
    {
        "finding_id": "P0-004_HISTORICAL_REGIME_FALLBACK_GATE_EXCEEDED",
        "severity": "P0",
        "status": "OPEN_LAUNCH_BLOCKER",
        "public_initial_malformed_regime_rows_per_task": 199,
        "first_prefix_fit_row_fallback_count": 198,
        "exact_v4_fallback_max_count": 8,
        "exact_v4_fallback_max_fraction": 0.02,
        "decision_window_malformed_regime_rows": 0,
        "evidence": (
            "The public regime warmup is valid public missingness, but exact V4 applies "
            "its count/fraction fallback gate to all selected historical fit rows."
        ),
        "prohibited_workarounds": [
            "drop_historical_prefix_rows_without_a_new_fit_contract",
            "silently_impute_before_the_exact_v4_state_adapter",
            "exclude_fallback_rows_from_receipts",
            "relax_count_or_fraction_without_a_maintenance_revision",
        ],
    },
)

V5_MAINTENANCE_RECOMMENDATION: Final = {
    "namespace": "hierarchical_observable_fair_value_state_v5",
    "parameter_block_binding": (
        "fit_end < block_start <= every_decision_date <= block_end"
    ),
    "same_parameters_for_entire_block": True,
    "within_block_update_count": 0,
    "required_cross_bindings": [
        "exact_fold_identity_set_sha256",
        "exact_ordered_decision_date_sha256",
        "fold_plan_sha256",
        "parameter_bundle_sha256",
    ],
    "warm_row_contract": {
        "preserve_first_test_position": 504,
        "requested_prefix_rows_min": 504,
        "expected_causal_nonwarm_drop": (
            "exactly_one_per_entity_start_pattern_and_bound_in_receipt"
        ),
        "warm_fit_rows_min": 503,
        "multi_entity_relation": (
            "warm_fit_rows=requested_prefix_rows-entity_first_prior_missing_count-"
            "other_explicitly_hashed_invalid_rows"
        ),
    },
    "regime_warmup_contract": {
        "separate_expected_warmup_from_unexpected_malformed": True,
        "expected_warmup_definition": (
            "per_entity_exact_contiguous_leading_rows_with_all_three_probabilities_missing"
        ),
        "expected_warmup_source_rows_max": 199,
        "expected_warmup_requires_public_canonical_receipt_and_hash": True,
        "expected_warmup_fallback": "uniform_causal_with_separate_count_and_hash_receipt",
        "valid_then_missing_classification": "unexpected_malformed",
        "unexpected_malformed_gate": {"max_count": 8, "max_fraction": 0.02},
        "expected_warmup_allowed_in_decision_blocks": False,
        "silent_drop_or_general_gate_relaxation": False,
    },
    "resource_contract": "new_explicit_outer32_contract_separate_from_v4",
}

NO_RUN_FLAGS: Final = {
    "launch_allowed": False,
    "model_fit_executed": False,
    "model_prediction_executed": False,
    "truth_payload_opened": False,
    "vault_payload_opened": False,
    "latent_payload_opened": False,
    "score_computed": False,
    "heldout_payload_opened": False,
    "evaluator_payload_opened": False,
    "registry_payload_opened_by_clean_lane": False,
    "registry_mutated": False,
    "promotion_authority": False,
}


def canonical_json_bytes(payload: Any) -> bytes:
    """Return the single ASCII JSON encoding used by integration seals."""

    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def semantic_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def sealed_payload(
    payload: Mapping[str, Any], *, field: str = "manifest_sha256"
) -> dict[str, Any]:
    output = dict(payload)
    output.pop(field, None)
    output[field] = semantic_sha256(output)
    return output


def design_payload(
    *,
    input_closure_raw_sha256: str,
    input_closure_semantic_sha256: str,
    decision_identities_raw_sha256: str,
    fold_plan_raw_sha256: str,
    source_closure_raw_sha256: str,
    source_closure_semantic_sha256: str,
) -> dict[str, Any]:
    """Build the exact non-authoritative, no-run design declaration."""

    payload = {
        "schema_version": f"{SCHEMA_VERSION}.design_lock.v1",
        "lab_id": LAB_ID,
        "status": STATUS,
        "evidence_class": EVIDENCE_CLASS,
        "authoritative_freeze": False,
        "superseded_draft": True,
        "public_input_binding": {
            "relative_root": PUBLIC_INPUT_ROOT,
            "freeze_receipt_raw_sha256": PUBLIC_INPUT_FREEZE_RAW_SHA256,
            "checksums_raw_sha256": PUBLIC_INPUT_CHECKSUMS_RAW_SHA256,
            "pass_id": PUBLIC_PASS_ID,
        },
        "hofs_v4_binding": {
            "relative_root": V4_DESIGN_ROOT,
            "design_lock_raw_sha256": V4_DESIGN_LOCK_RAW_SHA256,
            "checksums_raw_sha256": V4_DESIGN_CHECKSUMS_RAW_SHA256,
            "design_contract_sha256": V4_DESIGN_CONTRACT_SHA256,
            "source_closure_raw_sha256": V4_SOURCE_CLOSURE_RAW_SHA256,
            "source_closure_semantic_sha256": V4_SOURCE_CLOSURE_SEMANTIC_SHA256,
        },
        "hofs_v4_clean_audit_binding": {
            "relative_root": V4_AUDIT_ROOT,
            "audit_raw_sha256": V4_AUDIT_RAW_SHA256,
            "audit_semantic_sha256": V4_AUDIT_SEMANTIC_SHA256,
            "seal_receipt_raw_sha256": V4_AUDIT_SEAL_RAW_SHA256,
            "seal_receipt_semantic_sha256": V4_AUDIT_SEAL_SEMANTIC_SHA256,
            "checksums_raw_sha256": V4_AUDIT_CHECKSUMS_RAW_SHA256,
            "verdict": V4_AUDIT_VERDICT,
            "scope_not_extended_by_this_draft": True,
        },
        "input_surface": {
            "canonical_width": 150,
            "overlay_width": 254,
            "model_source_columns": list(MODEL_SOURCE_COLUMNS),
            "target_column": MODEL_TARGET_COLUMN,
            "target_usage": "strict_train_prefix_only",
            "training_proxy": TRAINING_PROXY,
            "entity_column": MODEL_ENTITY_COLUMN,
            "date_column": MODEL_DATE_COLUMN,
            "overlay_policy": OVERLAY_POLICY,
            "forbidden_model_columns": sorted(FORBIDDEN_MODEL_COLUMNS),
            "same_or_future_row_target_available_to_fit": False,
        },
        "geometry": {
            **asdict(GEOMETRY),
            "fold_count_per_task": GEOMETRY.fold_count_per_task,
            "total_fold_count": GEOMETRY.total_fold_count,
            "requested_fit_count": GEOMETRY.requested_fit_count,
            "decision_rows_per_task": GEOMETRY.decision_rows_per_task,
            "total_decision_count": GEOMETRY.total_decision_count,
            "exact_v4_native_decision_capacity": (
                GEOMETRY.exact_v4_native_decision_capacity
            ),
            "exact_v4_uncovered_decision_count": (
                GEOMETRY.exact_v4_uncovered_decision_count
            ),
        },
        "fold_policy": {
            "train_prefix": "positions_0_through_test_start_minus_1",
            "test_blocks": "61_blocks_of_21_then_1_block_of_15",
            "dgp_nuisance_usage": "training_only_exact_entity_date_membership_join",
            "dgp_nuisance_deploy_usage": "marginalized_to_zero",
            "seed_or_dgp_feature_usage": False,
            "within_block_update_count_requested": 0,
        },
        "requested_resource_policy": dict(REQUESTED_RESOURCE_POLICY),
        "exact_v4_resource_policy": dict(EXACT_V4_RESOURCE_POLICY),
        "runtime": {
            "python_version": PINNED_PYTHON_VERSION,
            "python_executable": PINNED_PYTHON_EXECUTABLE,
            "python_executable_raw_sha256": PINNED_PYTHON_EXECUTABLE_SHA256,
        },
        "artifact_bindings": {
            "input_closure_raw_sha256": input_closure_raw_sha256,
            "input_closure_semantic_sha256": input_closure_semantic_sha256,
            "decision_identities_raw_sha256": decision_identities_raw_sha256,
            "fold_plan_raw_sha256": fold_plan_raw_sha256,
            "source_closure_raw_sha256": source_closure_raw_sha256,
            "source_closure_semantic_sha256": source_closure_semantic_sha256,
        },
        "blocking_findings": [dict(item) for item in BLOCKING_FINDINGS],
        "severity_counts": {"P0": 4, "P1": 0, "P2": 0},
        "recommended_followup": dict(V5_MAINTENANCE_RECOMMENDATION),
        "authority": dict(NO_RUN_FLAGS),
    }
    return sealed_payload(payload)


__all__ = [
    "BLOCKING_FINDINGS",
    "DGP_IDS",
    "EVIDENCE_CLASS",
    "EXACT_V4_RESOURCE_POLICY",
    "FORBIDDEN_MODEL_COLUMNS",
    "GEOMETRY",
    "IntegrationContractError",
    "LAB_ID",
    "MODEL_DATE_COLUMN",
    "MODEL_ENTITY_COLUMN",
    "MODEL_SOURCE_COLUMNS",
    "MODEL_TARGET_COLUMN",
    "NO_RUN_FLAGS",
    "OVERLAY_POLICY",
    "PINNED_PYTHON_EXECUTABLE",
    "PINNED_PYTHON_EXECUTABLE_SHA256",
    "PINNED_PYTHON_VERSION",
    "PUBLIC_CANONICAL_HEADER_SHA256",
    "PUBLIC_INPUT_CHECKSUMS_RAW_SHA256",
    "PUBLIC_INPUT_FREEZE_RAW_SHA256",
    "PUBLIC_INPUT_ROOT",
    "PUBLIC_OBSERVABLE_STATE_CONTRACT_SHA256",
    "PUBLIC_PASS_ID",
    "REQUESTED_RESOURCE_POLICY",
    "SCHEMA_VERSION",
    "SEEDS",
    "STATUS",
    "TRAINING_PROXY",
    "V4_AUDIT_CHECKSUMS_RAW_SHA256",
    "V4_AUDIT_RAW_SHA256",
    "V4_AUDIT_ROOT",
    "V4_AUDIT_SEAL_RAW_SHA256",
    "V4_AUDIT_SEAL_SEMANTIC_SHA256",
    "V4_AUDIT_SEMANTIC_SHA256",
    "V4_AUDIT_VERDICT",
    "V4_DESIGN_CHECKSUMS_RAW_SHA256",
    "V4_DESIGN_CONTRACT_SHA256",
    "V4_DESIGN_LOCK_RAW_SHA256",
    "V4_DESIGN_ROOT",
    "V4_RUNTIME_SOURCE_SHA256",
    "V4_SOURCE_CLOSURE_RAW_SHA256",
    "V4_SOURCE_CLOSURE_SEMANTIC_SHA256",
    "V5_MAINTENANCE_RECOMMENDATION",
    "canonical_json_bytes",
    "design_payload",
    "sealed_payload",
    "semantic_sha256",
]
