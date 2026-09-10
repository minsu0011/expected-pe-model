"""Frozen score-blind DGP-R4 causal-prefix repair contract for H-OFS V7.

V7 preserves the frozen V6 estimator, execution geometry, runtime, regime
warmup semantics, order custody, and numerical certificates.  Its only
estimator-contract change is the public-R4 causal prefix: every entity has
exact invalid positions ``(0, 1, 2)`` and therefore 501 warm rows in the first
504-row prefix.  The exact future prediction launcher/publisher is part of the
frozen source closure.  This preflight grants no real-run, score, registry, or
promotion authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping

# Importing any parent submodule executes its package initializer.  Verify the
# complete four-file runtime closure with stdlib only *before* that import.
PARENT_RUNTIME_SOURCE_SHA256 = {
    "research/model_zoo/observable_fair_value_state_v1/__init__.py": (
        "4593a813178dceaab705e9d9863a0140d8b5020aea53081feaaa866adfd70eaa"
    ),
    "research/model_zoo/observable_fair_value_state_v1/audit.py": (
        "5f5d60f6e485d7638f7989a73a135a76ad51a44f2b70310ee35d10cbb12612ad"
    ),
    "research/model_zoo/observable_fair_value_state_v1/contracts.py": (
        "cded6a396238c27909e62c724c6a32c7eedd6818f78362694f4d1ae13ad72217"
    ),
    "research/model_zoo/observable_fair_value_state_v1/features.py": (
        "cf5ebfed19eef892cdc07c145d53736902809c2bccf4781be924c215c16a4a18"
    ),
}


def _verify_parent_runtime_closure_preimport() -> None:
    project_root = Path(__file__).resolve().parents[3]
    for relative_path, expected_sha256 in PARENT_RUNTIME_SOURCE_SHA256.items():
        path = project_root / relative_path
        if not path.is_file():
            raise RuntimeError(f"parent runtime source is missing: {relative_path}")
        actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual_sha256 != expected_sha256:
            raise RuntimeError(f"parent runtime source drifted: {relative_path}")


_verify_parent_runtime_closure_preimport()

from research.model_zoo.observable_fair_value_state_v1.contracts import (  # noqa: E402
    FEATURE_OUTPUT_COLUMNS as PARENT_FEATURE_OUTPUT_COLUMNS,
    contract_sha256 as parent_feature_contract_sha256,
)


class HierarchicalStateV7ContractError(ValueError):
    """Raised when an H-OFS V7 contract or custody boundary is violated."""


FORMAT_VERSION = 6
LAB_ID = "hierarchical_observable_fair_value_state_v7"
CANDIDATE_ID = "hofs_v7_huber_soft_pool_state_dgp_r4_blocked"
STATUS = "SCORE_BLIND_V7_DGP_R4_CAUSAL_PREFIX_REPAIR_PREFLIGHT_ONLY"
EVIDENCE_CLASS = "DESIGN_INPUT_AND_SCHEMA_PREFLIGHT_ONLY_NO_EMPIRICAL_OR_SCORE_EVIDENCE"
PARENT_FEATURE_LAB_ID = "observable_fair_value_state_v1"
PARENT_FEATURE_CONTRACT_SHA256 = "e2a03bd42de59df3d537e170dcba1713be545814b2054135475dedc54c0cde10"
if parent_feature_contract_sha256() != PARENT_FEATURE_CONTRACT_SHA256:
    raise HierarchicalStateV7ContractError("parent Observable State V1 contract drifted")
if len(PARENT_FEATURE_OUTPUT_COLUMNS) != 42:
    raise HierarchicalStateV7ContractError("parent Observable State V1 feature universe drifted")

V4_INDEPENDENT_AUDIT_BINDING = {
    "path": (
        "outputs/model_zoo_hierarchical_observable_fair_value_state_v4_"
        "independent_audit_20260821/AUDIT.json"
    ),
    "raw_sha256": "7c3de60249e4945a24226b9f2467b5bb7389cd875bb18f52d11746e5eca5b324",
    "semantic_sha256": "b157609efa9838e3ded33a6df73e767b365d8d863dc418df41bc9df167598650",
    "manifest_raw_sha256": ("951a459523b4b2e8af3f72f8ca94f8217cf8d9f646de9c114601e0dba6cc4371"),
    "seal_raw_sha256": "e77b797d4d366b77385ad80ae9284e74670148ffda14f13440462890fc54f58d",
    "checksums_raw_sha256": ("cb0f16a42fec9ced397bb33b7ff5087266ce045e638d4c9d81c7c15dac114bec"),
    "verdict": "GO_FUTURE_SCORE_BLIND_PREDICTION_LANE_EXACT_FROZEN_V4_ONLY",
    "severity_counts": {"P0": 0, "P1": 0, "P2": 0},
    "finding_count": 0,
}

V4_DESIGN_FREEZE_BINDING = {
    "path": "outputs/model_zoo_hierarchical_observable_fair_value_state_v4_design_preflight_20260821",
    "design_contract_sha256": ("5af5003e853ee125d971d9283d15b7b952ad99423645a3c0437fb666f7a31c56"),
    "checksums_raw_sha256": ("830ece4ee0db38359490e2f73a9d7dfeaf98271b58efa6dbca4b070216efe16a"),
    "design_lock_raw_sha256": ("9c78db23623774f64147a331ffc8e08716fc0be2f77627cbdfd27ca4403c0406"),
    "manifest_raw_sha256": ("c69ab68d6f5d8052d97cad08a5584cbe0cc3c4b2b4917d63d9176ffa1a5453ba"),
    "seal_raw_sha256": "eb2ec383ad678b345c4a4aa7e1b92872c3770850647bac6a9419e922d7018545",
    "source_closure_raw_sha256": (
        "6c60da692267ff2e3a97f245425c3128a67a5c3120215838ab9e0aefe67d65aa"
    ),
}

V5_DESIGN_FREEZE_BINDING = {
    "path": (
        "outputs/model_zoo_hierarchical_observable_fair_value_state_v5_"
        "dgp_r4_design_preflight_20260821"
    ),
    "design_contract_sha256": ("743135705872605890c36593b12c91cf245db765e738fdf0a9eede81482f96b4"),
    "checksums_raw_sha256": ("f7d5ed4b2db435069409f6cb474fc2d86e322ca40aa403eabbd05ab86d84acec"),
    "design_lock_raw_sha256": ("c641b3937d7c7b580d80bc7943d5d31f77fe394fb807d726b0f2b3d9fc637058"),
    "manifest_raw_sha256": ("1690e132ed6a1eb04e28e28859e216a882fcb1ab07ad0910e17fec99284c4ec4"),
    "seal_raw_sha256": "fa877cfb5ba857f1452a2e58e52208a77bb1f92619cc660a5e3107e4ac85c5b7",
    "source_closure_raw_sha256": (
        "44fc0a8a6b0e84dec4b4a5aac75fa21f468dae6d8d4e19b77ad3a78f08e3c0bc"
    ),
}

V5_INDEPENDENT_AUDIT_BINDING = {
    "path": (
        "outputs/model_zoo_hierarchical_observable_fair_value_state_v5_"
        "independent_prelaunch_audit_20260821/AUDIT.json"
    ),
    "raw_sha256": "09d46eafa83ef5ecaa8b39b5bfc511521b587ab111be49370d00c7e31d2a7d73",
    "semantic_sha256": "0e8a5247452e641ff9b1ea24db0d982be116f4182abc1d2825d5e9da3542866e",
    "manifest_raw_sha256": ("83abcff360f4c6f5fd157abb868dbc462a0f5dfb4eabef2d51d45a0cb9d35e13"),
    "seal_raw_sha256": "d62b151b3d14ecb07413807e064c21c1c4cf5c143093236d57cbd7f1d31ac9df",
    "checksums_raw_sha256": ("3f5e1e622a2e72e593fec9f4b0c8ac78a84d6e26a1c5db0e50536958849c962a"),
    "verdict": "NO_GO_PREDICTION_ONLY_LAUNCH_P1_ORDER_CUSTODY",
    "severity_counts": {"P0": 0, "P1": 1, "P2": 0},
    "finding_count": 1,
    "failed_check": "noncanonical_requested_block_order_rejected",
    "required_repair_scope": "P1_ORDER_CUSTODY_ONLY",
}

V6_DESIGN_FREEZE_BINDING = {
    "path": (
        "outputs/model_zoo_hierarchical_observable_fair_value_state_v6_"
        "dgp_r4_design_preflight_20260821"
    ),
    "design_contract_sha256": "ec0850a0cefc628b89e9f15e341ced58ec1abbcfc4b620d07f7772fbadcb0000",
    "checksums_raw_sha256": "855ebe2240a1d02c1f761ab839bb04a7372b5c7317e907e7136ce53a24996615",
    "design_lock_raw_sha256": "7ba0d71f3207ed4a226fef97a7ffcae793a3537a8ef4459290fbb5b6b0efbf91",
    "manifest_raw_sha256": "6cb74c34a22718fedb3fa5dd21e92f6b1a47fa03d17bbd0ef1c981acf1c57086",
    "seal_raw_sha256": "f000bcc85d0a1615fcf126ace44984dd3c67c4823ceabe1d791d3b510b954e02",
    "source_closure_raw_sha256": (
        "84509197d46bdfc895719095c3e4162def74840ddd857c5f118b029da9575bc0"
    ),
}

V6_INDEPENDENT_AUDIT_BINDING = {
    "path": (
        "outputs/model_zoo_hierarchical_observable_fair_value_state_v6_"
        "independent_prelaunch_audit_20260821/AUDIT.json"
    ),
    "raw_sha256": "7296d5b8f031e3f4646cd11b87a517ee8b420eab4dd0a21d4bd43ee2c53caa7e",
    "semantic_sha256": "439be93b6c26720d6f42546bd8c0bd235fc1c23ac41acc9e32a519cfc5929cc4",
    "manifest_raw_sha256": "33746cdaa25ac5d81e3c2c2b64b793e61a0749d9cca95dfd4995d2dee655519b",
    "seal_raw_sha256": "fec22f9ea1cf36fc259a483df42808dba2e3cfa570fd934989beaf72a272288a",
    "checksums_raw_sha256": "d85e3e1ccf2733975827019eb86fc48712ea3c352bcef94dbbb40256b28a0a98",
    "verdict": "GO_SCORE_BLIND_PREDICTION_ONLY_LAUNCH_EXACT_FROZEN_V6_ONLY",
    "severity_counts": {"P0": 0, "P1": 0, "P2": 0},
    "finding_count": 0,
}

V6_ZERO_FIT_FAILURE_EVIDENCE = {
    "event": "FROZEN_V6_PUBLIC_R4_PREDICTION_LAUNCH_FAILED_CLOSED_BEFORE_SOLVER",
    "error_type": "HierarchicalStateV6ContractError",
    "error_message": "per-entity prefix violates requested/causal-first-row nonwarm policy",
    "completed_fit_count": 0,
    "completed_prediction_row_count": 0,
    "published_output_root": False,
    "task_count": 50,
    "first_prefix_requested_rows_per_task": 504,
    "causal_invalid_positions_per_task": [0, 1, 2],
    "observed_pe_nonfinite_positions_per_task": [0, 1],
    "causal_offset_nonfinite_positions_per_task": [0, 1, 2],
    "first_prefix_nonwarm_rows_per_task": 3,
    "first_prefix_warm_rows_per_task": 501,
    "reviewed_temporary_launcher_sha256": (
        "21b067165ea2d616d418b4c0441eaa571ab8402ee2d6170072a0e47f3b3ff32d"
    ),
    "v6_frozen_snapshot_sha256_after_failure": (
        "63f90c5da80bc456e73bbf3f08c3e92ddb59bb6e9fbb4b5b316cda71b70c895b"
    ),
    "public_r4_bound_files_sha256_after_failure": (
        "117fe4c189517a84b12acb07d498b96f1d76cd47b238afacb451ea899c7b979f"
    ),
}

R4_INPUT_BINDING = {
    "path": "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821",
    "downstream_input_pass": "replays/pass_1",
    "freeze_receipt_raw_sha256": (
        "f5125088b258925dec7854a29ab9da9f09698d3bbf79afa6b0896e7da959fe14"
    ),
    "checksums_raw_sha256": ("fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7"),
    "public_hash_ledger_raw_sha256": (
        "7d817b623ab025a32489ca0f811ed36a90d48521fae2ecb7f86feca68ec4b97b"
    ),
    "task_diagnostics_raw_sha256": (
        "5cc694f85fbada9a1364808d4e741bc7c1ebc678c0240af28e441cc6a3373903"
    ),
    "source_manifest_raw_sha256": (
        "ed4703f09e0bd22961cbd2cc4eed12024abef6a8d19a38a25ddda46f406fd310"
    ),
    "bound_public_file_count": 150,
    "bound_public_files_sha256": (
        "117fe4c189517a84b12acb07d498b96f1d76cd47b238afacb451ea899c7b979f"
    ),
}

R4_SEEDS = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
R4_DGPS = tuple("ABCDEFGHIJ")
R4_TASK_COUNT = 50
R4_ROWS_PER_TASK = 1800
R4_SCORE_START_INCLUSIVE = 504
R4_SCORE_END_EXCLUSIVE = 1800
R4_TEST_BLOCK_ROWS = 21
R4_FOLDS_PER_TASK = 62
R4_TOTAL_FIT_COUNT = 3100
R4_DECISION_ROWS_PER_TASK = 1296
R4_TOTAL_DECISION_ROWS = 64800

TRAINING_PROXY = "log(observed_pe_t)-prior_log_pe_t_on_strictly_earlier_block_prefix"
FIT_POLICY = (
    "one_chronological_prefix_fit_per_exact_multi_date_decision_block_"
    "canonical_ordered_and_set_membership_source_position_custody_"
    "zero_within_block_updates"
)
LOSS = "huber_delta_1p345_with_mad_scale_and_projected_ridge_irls"

# Fixed architecture constants.  There are no sweep slots in this revision.
HUBER_DELTA = 1.345
GLOBAL_RIDGE = 2.0
CONTEXT_RIDGE = 8.0
REGIME_DEVIATION_RIDGE = 32.0
DGP_NUISANCE_RIDGE = 128.0
IRLS_MAX_ITERATIONS = 50
IRLS_TOLERANCE = 1e-8
QP_MAX_SWEEPS = 20_000
QP_KKT_TOLERANCE = 1e-10
MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY = 504
MIN_WARM_PREFIX_ROWS_PER_ENTITY = 501
ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY = (0, 1, 2)
MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY = len(ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY)
ROBUST_STANDARDIZATION_SCALE_FLOOR = 1e-6
ROBUST_SCALE_FLOOR = 0.01
ROBUST_SCALE_CEILING = 0.50
REGIME_SCALE_PSEUDO_COUNT = 64.0
DGP_SCALE_PSEUDO_COUNT = 256.0
PERSISTENCE_BOUNDS = (-0.25, 0.95)
INNOVATION_BOUNDS = (-0.25, 0.75)
TAIL_SOFT_LIMIT_SIGMAS = 3.0
TAIL_SOFT_LIMIT_MIN_LOG = 0.03
TAIL_SOFT_LIMIT_MAX_LOG = math.log(1.50)
INTERVAL_LOWER_PROBABILITY = 0.10
INTERVAL_UPPER_PROBABILITY = 0.90
INTERVAL_NORMAL_QUANTILE = 1.2815515655446004
LOG_PE_BOUNDS = (math.log(1.0), math.log(200.0))
REGIME_FALLBACK_POLICY = "uniform_with_receipt_below_fixed_limit_else_fail_closed"
REGIME_FALLBACK_MAX_COUNT = 8
REGIME_FALLBACK_MAX_FRACTION = 0.02
REGIME_RENORMALIZATION_ABS_TOLERANCE = 1e-12
EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY = 199
EXPECTED_REGIME_WARMUP_POLICY = (
    "exact_contiguous_leading_all_three_missing_per_entity_uniform_causal_fallback"
)

# The future fit and inference lane is deliberately restricted to one exact
# Windows/Python/BLAS resource surface.  V7 tests and preflight use this same
# interpreter; no fallback runtime is authorized.
PINNED_PYTHON_VERSION = "3.10.19"
PINNED_PYTHON_EXECUTABLE = (
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
PINNED_PYTHON_EXECUTABLE_SHA256 = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_NUMPY_VERSION = "1.26.4"
PINNED_PANDAS_VERSION = "2.2.3"
PINNED_AFFINITY_MASK = 0xFFFFFFFF
PINNED_CPU_IDS = tuple(range(32))
PINNED_THREAD_ENVIRONMENT = (
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("NUMEXPR_NUM_THREADS", "1"),
)
PINNED_THREADPOOL_BACKENDS = (("blas", "openblas", "0.3.23.dev", "pthreads", 1),)
GPU_DISABLED_ENVIRONMENT = (("CUDA_VISIBLE_DEVICES", "-1"),)

PARENT_TO_MODEL_FEATURE = {
    "ofs_v1_state_prior_log_pe": "hofs_v7_offset_prior_log_pe",
    "ofs_v1_val_distance_median_252_lag1": "hofs_v7_state_displacement_lag1",
    "ofs_v1_state_innovation_lag1": "hofs_v7_innovation_lag1",
    "ofs_v1_state_prior_slope": "hofs_v7_prior_slope",
    "ofs_v1_eps_growth_curve": "hofs_v7_eps_growth_curve",
    "ofs_v1_eps_staleness_log1p": "hofs_v7_eps_staleness_log1p",
    "ofs_v1_eps_confidence_01": "hofs_v7_eps_confidence_01",
    "ofs_v1_eps_disagreement_log1p": "hofs_v7_eps_disagreement_log1p",
    "ofs_v1_eps_approximation_flag": "hofs_v7_eps_approximation_flag",
    "ofs_v1_market_return_63": "hofs_v7_market_return_63",
    "ofs_v1_market_volatility_63": "hofs_v7_market_volatility_63",
    "ofs_v1_market_drawdown_252": "hofs_v7_market_drawdown_252",
    "ofs_v1_market_trend_efficiency_63": "hofs_v7_market_trend_efficiency_63",
    "ofs_v1_regime_entropy": "hofs_v7_regime_entropy",
    "ofs_v1_regime_p_bear": "hofs_v7_regime_p_bear",
    "ofs_v1_regime_p_sideways": "hofs_v7_regime_p_sideways",
    "ofs_v1_regime_p_bull": "hofs_v7_regime_p_bull",
}
MODEL_FEATURE_COLUMNS = tuple(PARENT_TO_MODEL_FEATURE.values())
OFFSET_COLUMN = "hofs_v7_offset_prior_log_pe"
STATE_DISPLACEMENT_COLUMN = "hofs_v7_state_displacement_lag1"
INNOVATION_COLUMN = "hofs_v7_innovation_lag1"
REGIME_COLUMNS = (
    "hofs_v7_regime_p_bear",
    "hofs_v7_regime_p_sideways",
    "hofs_v7_regime_p_bull",
)
CONTEXT_COLUMNS = (
    "hofs_v7_prior_slope",
    "hofs_v7_eps_growth_curve",
    "hofs_v7_eps_staleness_log1p",
    "hofs_v7_eps_confidence_01",
    "hofs_v7_eps_disagreement_log1p",
    "hofs_v7_eps_approximation_flag",
    "hofs_v7_market_return_63",
    "hofs_v7_market_volatility_63",
    "hofs_v7_market_drawdown_252",
    "hofs_v7_market_trend_efficiency_63",
    "hofs_v7_regime_entropy",
)
STANDARDIZED_COLUMNS = (
    STATE_DISPLACEMENT_COLUMN,
    INNOVATION_COLUMN,
    *CONTEXT_COLUMNS,
)
IDENTITY_COLUMNS = ("hofs_v7_entity_id", "hofs_v7_decision_date")
DGP_MEMBERSHIP_COLUMN = "hofs_v7_research_dgp_id"
DGP_MEMBERSHIP_COLUMNS = (*IDENTITY_COLUMNS, DGP_MEMBERSHIP_COLUMN)
OUTPUT_COLUMNS = (
    "hofs_v7_expected_pe",
    "hofs_v7_pe_p10",
    "hofs_v7_pe_p90",
    "hofs_v7_log_scale",
    "hofs_v7_tail_guard_weight",
)
PREDICTION_OUTPUT_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "BLOCK_RECEIPTS.jsonl",
    "CHECKSUMS.sha256",
    "EXECUTION_RECEIPT.json",
    "IMMUTABILITY_RECEIPT.json",
    "INPUT_RECEIPT.json",
    "LAUNCH_CONTRACT.json",
    "MANIFEST.json",
    "PREDICTIONS.csv",
    "REPORT.md",
    "RUNTIME_RECEIPT.json",
    "SEAL_RECEIPT.json",
    "TASK_RECEIPTS.jsonl",
    "prediction_launcher.py",
)

FORBIDDEN_INFERENCE_COLUMNS = frozenset(
    {
        "dgp_id",
        "research_dgp_id",
        "seed",
        "true_fair_pe",
        "true_regime",
        "expected_pe",
        "ml_expected_pe",
        "v04_expected_pe",
        "bce_prediction",
        "hofs_v4_expected_pe",
    }
)
RESEARCH_DGP_POLICY = {
    "feature_group_usage": "FORBIDDEN_FIXED_ENTITY_ONLY",
    "mean_fit_usage": "training_only_intercept_persistence_innovation_nuisance",
    "scale_fit_usage": "training_only_robust_log_scale_nuisance",
    "shrinkage_ridge": DGP_NUISANCE_RIDGE,
    "scale_pseudo_count": DGP_SCALE_PSEUDO_COUNT,
    "centering": "row_weighted_zero_sum_by_membership_digest_order",
    "deploy_usage": "FORBIDDEN_ALL_EFFECTS_MARGINALIZED_TO_ZERO",
}


@dataclass(frozen=True)
class CandidateSpec:
    candidate_id: str
    family: str
    architecture: str
    fit_policy: str
    loss: str
    deployable_input: str
    uncertainty_output: str

    def __post_init__(self) -> None:
        values = (
            self.candidate_id,
            self.family,
            self.architecture,
            self.fit_policy,
            self.loss,
            self.deployable_input,
            self.uncertainty_output,
        )
        if any(type(value) is not str or not value for value in values):
            raise HierarchicalStateV7ContractError(
                "candidate specification requires exact nonempty strings"
            )
        if self.candidate_id != CANDIDATE_ID:
            raise HierarchicalStateV7ContractError("candidate specification ID drifted")
        expected = {
            "family": "HIERARCHICAL_ROBUST_OBSERVABLE_STATE_DYNAMICS_V7_DGP_R4_BLOCKED",
            "architecture": (
                "prior state offset; projected Huber IRLS innovation equation; strongly-shrunk "
                "soft-regime sum-to-zero deviations; train-only strongly-shrunk DGP mean and "
                "scale nuisance; DGP effects marginalized at deployment"
            ),
            "fit_policy": FIT_POLICY,
            "loss": LOSS,
            "deployable_input": (
                "17 production-observable H-OFS V7 features plus exact ordered/set/source-position decision custody"
            ),
            "uncertainty_output": (
                "fixed p10/p90 Normal quantiles with scale-adaptive tanh tail guard"
            ),
        }
        actual = {
            "family": self.family,
            "architecture": self.architecture,
            "fit_policy": self.fit_policy,
            "loss": self.loss,
            "deployable_input": self.deployable_input,
            "uncertainty_output": self.uncertainty_output,
        }
        if actual != expected:
            raise HierarchicalStateV7ContractError("candidate specification policy drifted")


CANDIDATE = CandidateSpec(
    candidate_id=CANDIDATE_ID,
    family="HIERARCHICAL_ROBUST_OBSERVABLE_STATE_DYNAMICS_V7_DGP_R4_BLOCKED",
    architecture=(
        "prior state offset; projected Huber IRLS innovation equation; strongly-shrunk "
        "soft-regime sum-to-zero deviations; train-only strongly-shrunk DGP mean and scale "
        "nuisance; DGP effects marginalized at deployment"
    ),
    fit_policy=FIT_POLICY,
    loss=LOSS,
    deployable_input=(
        "17 production-observable H-OFS V7 features plus exact "
        "ordered/set/source-position decision custody"
    ),
    uncertainty_output="fixed p10/p90 Normal quantiles with scale-adaptive tanh tail guard",
)

RUNTIME_PLAN = {
    "hardware_profile": "AMD_7950X3D_32_LOGICAL_CPU_RTX5080_96GB_RAM",
    "estimator_device": "CPU_ONLY_DETERMINISTIC_PROJECTED_IRLS",
    "gpu_usage": False,
    "gpu_disabled_environment": dict(GPU_DISABLED_ENVIRONMENT),
    "python_version": PINNED_PYTHON_VERSION,
    "python_executable": PINNED_PYTHON_EXECUTABLE,
    "python_executable_sha256": PINNED_PYTHON_EXECUTABLE_SHA256,
    "numpy_version": PINNED_NUMPY_VERSION,
    "pandas_version": PINNED_PANDAS_VERSION,
    "affinity_mask_hex": f"0x{PINNED_AFFINITY_MASK:08X}",
    "cpu_ids": list(PINNED_CPU_IDS),
    "threadpool_backends": [list(item) for item in PINNED_THREADPOOL_BACKENDS],
    "max_outer_workers": 32,
    "inner_threads": 1,
    "ram_soft_budget_gib": 80,
    "ram_min_free_gib": 12,
    "fixed_row_order": "decision_date_then_entity_id_stable_mergesort",
    "incoming_order_policy": "REJECT_NONCANONICAL_WITHOUT_SILENT_SORT",
    "decision_custody": ("DOMAIN_SEPARATED_ORDERED_SET_ENDPOINT_AND_SOURCE_POSITION_SHA256"),
    "normal_equation_accumulation": "sequential_row_outer_product",
    "blas_environment": dict(PINNED_THREAD_ENVIRONMENT),
    "fit_and_inference_runtime_gate": "MANDATORY_EXACT_NO_FALLBACK",
    "inference_output_resource_binding": "FULL_RECEIPT_AND_SHA256",
}

FAILURE_BOUNDARIES = (
    "any parent contract or complete runtime source-closure drift",
    "any research DGP or seed field influencing feature lag/history or deployable parameters",
    "any missing, duplicate, positional-only, or non one-to-one entity/date identity",
    "any non-string entity or DGP label, coercion collision, or position-only DGP membership",
    "any fit row not strictly earlier than the first date of its exact decision block",
    "any incoming decision identities not already in exact decision-date/entity stable mergesort order",
    "any decision ordered membership, set membership, canonical endpoint row, or source-position hash drift",
    "any parameter update, refit, target observation, or parameter hash drift within a block",
    "any causal invalid positions other than exact leading (0,1,2) for every entity",
    "any requested/nonwarm/warm prefix count other than exact 504=3+501 at first fold",
    "any expected regime warmup row that is not an exact contiguous leading all-three-missing prefix",
    "any expected regime warmup row in a decision block",
    "any unexpected malformed regime count or fraction beyond the exact selected rows",
    "any non-converged IRLS result or non-finite/unbounded deployable parameter",
    "any final-weight KKT violation above the fixed threshold",
    "any missing fit-input, objective, convergence, resource, or artifact provenance hash",
    "any JSON field whose exact bool, int, float, string, sequence, enum, or counter domain drifts",
    "any post-construction feature, identity, fallback-mask, renormalization-mask, count, or order mutation",
    "any fit or inference runtime outside exact Python, affinity, thread, dependency, or GPU-off pins",
    "any directory, symlink, special file, or undeclared child in a parameter bundle",
    "any Windows reparse-point root or child in a parameter or design bundle",
    "any duplicate, omitted, extra, reordered, or unpinned checksum-ledger path",
    "any MANIFEST, SEAL, DESIGN, contract, audit, resource, authority, or universe cross-binding drift",
    "any real prediction, truth, vault, score, registry, champion, or promotion action under preflight",
)


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize a seal payload with one deterministic byte representation."""

    return json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def contract_payload() -> dict[str, Any]:
    """Return the complete fixed H-OFS V7 design declaration."""

    return {
        "format_version": FORMAT_VERSION,
        "lab_id": LAB_ID,
        "candidate": asdict(CANDIDATE),
        "status": STATUS,
        "evidence_class": EVIDENCE_CLASS,
        "authority": {
            "real_model_fit": False,
            "research_or_production_prediction": False,
            "truth_or_score_access": False,
            "fresh_or_heldout_access": False,
            "vault_access": False,
            "registry_or_champion_mutation": False,
            "promotion": False,
            "synthetic_preflight_fit": True,
        },
        "v6_independent_go_audit_binding": dict(V6_INDEPENDENT_AUDIT_BINDING),
        "v6_design_freeze_binding": dict(V6_DESIGN_FREEZE_BINDING),
        "v6_zero_fit_failure_evidence": dict(V6_ZERO_FIT_FAILURE_EVIDENCE),
        "inherited_v5_independent_no_go_audit_binding": dict(V5_INDEPENDENT_AUDIT_BINDING),
        "inherited_v5_design_freeze_binding": dict(V5_DESIGN_FREEZE_BINDING),
        "inherited_v4_independent_audit_binding": dict(V4_INDEPENDENT_AUDIT_BINDING),
        "inherited_v4_design_freeze_binding": dict(V4_DESIGN_FREEZE_BINDING),
        "r4_public_input_binding": dict(R4_INPUT_BINDING),
        "parent_feature_contract": {
            "lab_id": PARENT_FEATURE_LAB_ID,
            "sha256": PARENT_FEATURE_CONTRACT_SHA256,
            "feature_count": len(PARENT_FEATURE_OUTPUT_COLUMNS),
            "complete_runtime_source_sha256": dict(PARENT_RUNTIME_SOURCE_SHA256),
        },
        "training_proxy": TRAINING_PROXY,
        "fit_policy": FIT_POLICY,
        "loss": LOSS,
        "fixed_hyperparameters": {
            "huber_delta": HUBER_DELTA,
            "global_ridge": GLOBAL_RIDGE,
            "context_ridge": CONTEXT_RIDGE,
            "regime_deviation_ridge": REGIME_DEVIATION_RIDGE,
            "dgp_nuisance_ridge": DGP_NUISANCE_RIDGE,
            "irls_max_iterations": IRLS_MAX_ITERATIONS,
            "irls_tolerance": IRLS_TOLERANCE,
            "box_qp_max_coordinate_sweeps": QP_MAX_SWEEPS,
            "box_qp_kkt_tolerance": QP_KKT_TOLERANCE,
            "minimum_requested_prefix_rows_per_entity": MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY,
            "minimum_warm_prefix_rows_per_entity": MIN_WARM_PREFIX_ROWS_PER_ENTITY,
            "allowed_causal_invalid_positions_per_entity": list(
                ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY
            ),
            "maximum_causal_prefix_nonwarm_per_entity": (
                MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY
            ),
            "first_fold_estimator_sufficiency": {
                "requested_rows_per_entity": MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY,
                "causal_invalid_rows_per_entity": MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY,
                "warm_rows_per_entity": MIN_WARM_PREFIX_ROWS_PER_ENTITY,
                "minimum_warm_rows_required": MIN_WARM_PREFIX_ROWS_PER_ENTITY,
                "passed": True,
            },
            "robust_standardization_scale_floor": ROBUST_STANDARDIZATION_SCALE_FLOOR,
            "robust_scale_bounds": [ROBUST_SCALE_FLOOR, ROBUST_SCALE_CEILING],
            "regime_scale_pseudo_count": REGIME_SCALE_PSEUDO_COUNT,
            "dgp_scale_pseudo_count": DGP_SCALE_PSEUDO_COUNT,
            "persistence_bounds": list(PERSISTENCE_BOUNDS),
            "innovation_bounds": list(INNOVATION_BOUNDS),
            "tail_soft_limit_sigmas": TAIL_SOFT_LIMIT_SIGMAS,
            "tail_soft_limit_log_bounds": [
                TAIL_SOFT_LIMIT_MIN_LOG,
                TAIL_SOFT_LIMIT_MAX_LOG,
            ],
            "interval_probabilities": [
                INTERVAL_LOWER_PROBABILITY,
                INTERVAL_UPPER_PROBABILITY,
            ],
            "interval_normal_quantile": INTERVAL_NORMAL_QUANTILE,
            "log_pe_bounds": list(LOG_PE_BOUNDS),
            "regime_fallback_policy": REGIME_FALLBACK_POLICY,
            "regime_fallback_max_count": REGIME_FALLBACK_MAX_COUNT,
            "regime_fallback_max_fraction": REGIME_FALLBACK_MAX_FRACTION,
            "regime_renormalization_abs_tolerance": REGIME_RENORMALIZATION_ABS_TOLERANCE,
            "expected_regime_warmup_prefix_max_per_entity": (
                EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY
            ),
            "expected_regime_warmup_policy": EXPECTED_REGIME_WARMUP_POLICY,
            "feature_center": "finite_prefix_median",
            "feature_scale": "1p4826_mad_then_iqr_over_1p349_then_population_std_then_1",
            "residual_scale": "1p4826_centered_mad_then_centered_rms_then_fixed_floor",
            "objective": "row_sum_huber_plus_one_half_quadratic_penalty",
            "irls_start": "all_zero_coefficients_and_unit_weights",
            "irls_final_certificate": "recomputed_final_weights_with_exact_kkt_gate",
            "deploy_scale_residual": "DGP_MEAN_NUISANCE_MARGINALIZED_TO_ZERO",
        },
        "feature_adapter": {
            "parent_to_model": dict(PARENT_TO_MODEL_FEATURE),
            "model_feature_columns": list(MODEL_FEATURE_COLUMNS),
            "identity_columns": list(IDENTITY_COLUMNS),
            "entity_type": "EXACT_PYTHON_STR_NO_COERCION",
            "fixed_history_group": "entity_id_else_symbol_only",
            "research_group_arguments": "NOT_ACCEPTED",
            "forbidden_inference_columns": sorted(FORBIDDEN_INFERENCE_COLUMNS),
        },
        "research_dgp_policy": dict(RESEARCH_DGP_POLICY),
        "research_dgp_membership_columns": list(DGP_MEMBERSHIP_COLUMNS),
        "output_columns": list(OUTPUT_COLUMNS),
        "output_scale_semantics": {"hofs_v7_log_scale": "natural_log_of_final_uncertainty_scale"},
        "runtime_plan": dict(RUNTIME_PLAN),
        "decision_block_order_custody": {
            "canonical_order": "decision_date_then_entity_id_stable_mergesort",
            "incoming_order_policy": "REJECT_WITHOUT_SILENT_SORT",
            "ordered_membership_hash_domain": ("H_OFS_V7_DECISION_BLOCK_ORDERED_MEMBERSHIP"),
            "set_membership_hash_domain": "H_OFS_V7_DECISION_BLOCK_SET_MEMBERSHIP",
            "source_positions_hash_domain": "H_OFS_V7_DECISION_SOURCE_POSITIONS",
            "canonical_endpoints": "EXACT_FIRST_AND_LAST_ORDERED_IDENTITY_ROWS",
            "source_positions": "UNIQUE_IN_RANGE_STRICTLY_INCREASING_AND_ORDER_BOUND",
            "output_manifest_cross_seal": True,
        },
        "dgp_r4_execution_geometry": {
            "seeds": list(R4_SEEDS),
            "dgps": list(R4_DGPS),
            "task_count": R4_TASK_COUNT,
            "rows_per_task": R4_ROWS_PER_TASK,
            "score_start_inclusive": R4_SCORE_START_INCLUSIVE,
            "score_end_exclusive": R4_SCORE_END_EXCLUSIVE,
            "test_block_rows": R4_TEST_BLOCK_ROWS,
            "folds_per_task": R4_FOLDS_PER_TASK,
            "fit_count": R4_TOTAL_FIT_COUNT,
            "decision_rows_per_task": R4_DECISION_ROWS_PER_TASK,
            "decision_row_count": R4_TOTAL_DECISION_ROWS,
            "fit_reuse": "one_frozen_parameter_hash_for_every_row_in_exact_block",
            "within_block_parameter_update_count": 0,
        },
        "prediction_execution_launcher": {
            "source_path": (
                "scripts/model_lab/hierarchical_observable_fair_value_state_v7/"
                "prediction_launcher.py"
            ),
            "frozen_design_filename": "PREDICTION_LAUNCHER.py",
            "modes": ["check", "run"],
            "check_mode_real_fit_count": 0,
            "check_mode_real_prediction_count": 0,
            "run_requires_external_independent_audit_pins": [
                "audit_checksums_raw_sha256",
                "audit_raw_sha256",
                "audit_semantic_sha256",
            ],
            "run_requires_audit_verdict": (
                "GO_SCORE_BLIND_PREDICTION_ONLY_LAUNCH_EXACT_FROZEN_V7_ONLY"
            ),
            "run_requires_audit_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
            "process_start_method": "spawn",
            "task_parallelism": "50_fixed_tasks_max_32_workers",
            "fold_execution": "62_sequential_chronological_fits_per_task",
            "input_order_policy": "REJECT_WITHOUT_SILENT_SORT",
            "prediction_output_file_universe": list(PREDICTION_OUTPUT_FILE_UNIVERSE),
            "publication": (
                "unique_same_parent_staging_exclusive_fsynced_preverified_os_replace_"
                "postverified"
            ),
            "forbidden_output_columns": sorted(FORBIDDEN_INFERENCE_COLUMNS),
            "prediction_gate": "all_expected_pe_and_intervals_finite_and_positive",
            "score_registry_promotion_authority": False,
        },
        "failure_boundaries": list(FAILURE_BOUNDARIES),
        "selection_policy": {
            "candidate_count": 1,
            "hyperparameter_sweep": False,
            "ranking": "single_candidate_no_adaptive_selection",
        },
    }


def contract_sha256() -> str:
    return hashlib.sha256(canonical_json_bytes(contract_payload())).hexdigest()


def sealed_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    output = dict(payload)
    output.pop("manifest_sha256", None)
    output["manifest_sha256"] = hashlib.sha256(canonical_json_bytes(output)).hexdigest()
    return output


__all__ = [
    "CANDIDATE",
    "CANDIDATE_ID",
    "CONTEXT_COLUMNS",
    "DGP_MEMBERSHIP_COLUMN",
    "DGP_MEMBERSHIP_COLUMNS",
    "DGP_NUISANCE_RIDGE",
    "EVIDENCE_CLASS",
    "EXPECTED_REGIME_WARMUP_POLICY",
    "EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY",
    "FAILURE_BOUNDARIES",
    "FORBIDDEN_INFERENCE_COLUMNS",
    "GLOBAL_RIDGE",
    "GPU_DISABLED_ENVIRONMENT",
    "HUBER_DELTA",
    "HierarchicalStateV7ContractError",
    "IDENTITY_COLUMNS",
    "INNOVATION_BOUNDS",
    "INNOVATION_COLUMN",
    "INTERVAL_NORMAL_QUANTILE",
    "IRLS_MAX_ITERATIONS",
    "IRLS_TOLERANCE",
    "LAB_ID",
    "LOG_PE_BOUNDS",
    "ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY",
    "MAX_CAUSAL_PREFIX_NONWARM_PER_ENTITY",
    "MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY",
    "MIN_WARM_PREFIX_ROWS_PER_ENTITY",
    "MODEL_FEATURE_COLUMNS",
    "OFFSET_COLUMN",
    "OUTPUT_COLUMNS",
    "PREDICTION_OUTPUT_FILE_UNIVERSE",
    "PARENT_FEATURE_CONTRACT_SHA256",
    "PARENT_RUNTIME_SOURCE_SHA256",
    "PARENT_TO_MODEL_FEATURE",
    "PERSISTENCE_BOUNDS",
    "PINNED_AFFINITY_MASK",
    "PINNED_CPU_IDS",
    "PINNED_NUMPY_VERSION",
    "PINNED_PANDAS_VERSION",
    "PINNED_PYTHON_EXECUTABLE",
    "PINNED_PYTHON_EXECUTABLE_SHA256",
    "PINNED_PYTHON_VERSION",
    "PINNED_THREAD_ENVIRONMENT",
    "PINNED_THREADPOOL_BACKENDS",
    "QP_KKT_TOLERANCE",
    "QP_MAX_SWEEPS",
    "REGIME_COLUMNS",
    "REGIME_DEVIATION_RIDGE",
    "REGIME_FALLBACK_MAX_COUNT",
    "REGIME_FALLBACK_MAX_FRACTION",
    "REGIME_RENORMALIZATION_ABS_TOLERANCE",
    "ROBUST_SCALE_CEILING",
    "ROBUST_SCALE_FLOOR",
    "ROBUST_STANDARDIZATION_SCALE_FLOOR",
    "RUNTIME_PLAN",
    "R4_DECISION_ROWS_PER_TASK",
    "R4_DGPS",
    "R4_FOLDS_PER_TASK",
    "R4_INPUT_BINDING",
    "R4_ROWS_PER_TASK",
    "R4_SCORE_END_EXCLUSIVE",
    "R4_SCORE_START_INCLUSIVE",
    "R4_SEEDS",
    "R4_TASK_COUNT",
    "R4_TEST_BLOCK_ROWS",
    "R4_TOTAL_DECISION_ROWS",
    "R4_TOTAL_FIT_COUNT",
    "STANDARDIZED_COLUMNS",
    "STATE_DISPLACEMENT_COLUMN",
    "STATUS",
    "TAIL_SOFT_LIMIT_MAX_LOG",
    "TAIL_SOFT_LIMIT_MIN_LOG",
    "TAIL_SOFT_LIMIT_SIGMAS",
    "V4_DESIGN_FREEZE_BINDING",
    "V4_INDEPENDENT_AUDIT_BINDING",
    "V5_DESIGN_FREEZE_BINDING",
    "V5_INDEPENDENT_AUDIT_BINDING",
    "V6_DESIGN_FREEZE_BINDING",
    "V6_INDEPENDENT_AUDIT_BINDING",
    "V6_ZERO_FIT_FAILURE_EVIDENCE",
    "canonical_json_bytes",
    "contract_payload",
    "contract_sha256",
    "sealed_payload",
]
