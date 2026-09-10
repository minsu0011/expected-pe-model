"""Frozen contracts for the spent-only five-slot research tournament."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from typing import Any, Final


class ResearchTournamentContractError(RuntimeError):
    """Raised when the spent research tournament boundary drifts."""


FORMAT_VERSION: Final = 1
TOURNAMENT_ID: Final = "pre_certification_research_tournament_v1"
EXPERIMENT_ID: Final = "exp_pre_cert_research_spent_r4_bce_20260822"
RESEARCH_EVIDENCE_CLASS: Final = "RESEARCH_ONLY"
DETAILED_EVIDENCE_CLASS: Final = (
    "RESEARCH_ONLY_SPENT_OUTCOME_EXPOSED_NOT_CERTIFICATION_OR_PROMOTION_EVIDENCE"
)

FRESH_AUTHORITY: Final = False
HELDOUT_AUTHORITY: Final = False
CERTIFICATION_AUTHORITY: Final = False
PROMOTION_AUTHORITY: Final = False
PORTFOLIO_ADMISSION_AUTHORITY: Final = False
REGISTRY_MUTATION_AUTHORITY: Final = False

PUBLIC_ROOT: Final = "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
PUBLIC_FREEZE_SHA256: Final = (
    "f5125088b258925dec7854a29ab9da9f09698d3bbf79afa6b0896e7da959fe14"
)
PUBLIC_CHECKSUMS_SHA256: Final = (
    "fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7"
)
TRUTH_ROOT: Final = "outputs/model_zoo_dgp_state_tournament_v1_truth_vault_r2_20260821"
TRUTH_RECEIPT_SHA256: Final = (
    "93c414a8d15d1a2cce0d0c173cb1ccd2d79001d003a8962d12b331ce98a3888b"
)
TRUTH_CHECKSUMS_SHA256: Final = (
    "9139db5aff9ec248da01185d3778a172fe8f04445a3ebc21db8f7473c38562f2"
)
BCE_PREDICTION_ROOT: Final = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v1_predictions_r1_20260821"
)
BCE_PREDICTIONS_SHA256: Final = (
    "f2d38f9de31aa89d502050babb5df185fd35a30851701eb3a90e8c50fe64064b"
)
BCE_MANIFEST_SHA256: Final = (
    "c78c942df28809696435fd90b5a3220fa3f3298a7db57d33a13f95f5cd7aab2d"
)
BCE_CHECKSUMS_SHA256: Final = (
    "af2d910510ff31b988776ddcd5842628f6a4c991f4f19ee487bcc1b5a66ca624"
)

OUTPUT_ROOT: Final = (
    "outputs/model_zoo_pre_certification_research_tournament_v1_bce_spent_r4_20260822"
)

SEEDS: Final = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
SEED_ALIASES: Final = tuple(f"research_seed_{index:02d}" for index in range(1, 6))
SEED_ALIAS_TO_VALUE: Final = dict(zip(SEED_ALIASES, SEEDS, strict=True))
DGP_IDS: Final = tuple("ABCDEFGHIJ")
ROWS_PER_TASK: Final = 1_800
SCORE_START: Final = 504
SCORE_END: Final = 1_800
SCORE_ROWS_PER_TASK: Final = SCORE_END - SCORE_START
TASK_COUNT: Final = len(SEEDS) * len(DGP_IDS)
COMMON_IDENTITIES: Final = TASK_COUNT * SCORE_ROWS_PER_TASK
FOLDS_PER_TASK: Final = 62
FOLD_BLOCKS: Final = TASK_COUNT * FOLDS_PER_TASK

TRUTH_COLUMNS: Final = (
    "date",
    "true_fair_pe",
    "true_log_fair_pe",
    "true_economic_eps_contemporaneous",
    "true_pit_eps",
    "true_observed_pe",
    "true_expected_pe_eligible",
)
PREDICTION_COLUMNS: Final = (
    "seed_alias",
    "dgp_id",
    "date",
    "symbol",
    "session_position",
    "fold_id",
    "train_end_position",
    "test_start_position",
    "incumbent__v04_expected_pe",
    "challenger__lgbm_full_state",
    "challenger__histgb_full_state",
    "bce_v1_observable_state_confidence",
    "candidate__bce_b",
    "alpha__bce_b",
    "candidate__bce_d",
    "alpha__bce_d",
    "candidate__fixed_alpha_040",
    "alpha__fixed_alpha_040",
    "directional_agreement",
    "raw_log_consensus_correction",
)

CHAMPION_ID: Final = "v04_expected_pe"
BCE_B_ID: Final = "bce_v1_b_causal_rolling_dispersion_budget"
BCE_D_ID: Final = "bce_v1_d_observable_state_confidence_shrinkage"
FIXED_040_ID: Final = "bce_tournament_v1_fixed_alpha_040_directional_consensus"

MODEL_COLUMNS: Final = {
    CHAMPION_ID: "incumbent__v04_expected_pe",
    BCE_B_ID: "candidate__bce_b",
    BCE_D_ID: "candidate__bce_d",
    FIXED_040_ID: "candidate__fixed_alpha_040",
}
SCORED_CANDIDATE_IDS: Final = (BCE_B_ID, BCE_D_ID, FIXED_040_ID)
SCORED_MODEL_IDS: Final = (CHAMPION_ID, *SCORED_CANDIDATE_IDS)

EXTREME_ABS_LOG_ERROR_THRESHOLD: Final = math.log(1.10)
DISAGREEMENT_THRESHOLDS: Final = (0.02, 0.05, 0.10)
TAIL_QUANTILES: Final = (0.95, 0.99)
BOOTSTRAP_REPLICATES: Final = 2_000
BOOTSTRAP_RNG_SEED: Final = 2026082201


@dataclass(frozen=True)
class CandidateSlot:
    slot_id: str
    display_name: str
    family: str
    current_version: str
    research_readiness: str
    scored_model_id: str | None
    implementation_status: str
    required_next_adapter: str | None


FIVE_CANDIDATE_SLOTS: Final = (
    CandidateSlot(
        "PE-C1",
        "BCE-B",
        "bounded_consensus",
        "bce_v1_b",
        "PASS_SPENT_PREDICTIONS_SCOREABLE",
        BCE_B_ID,
        "COMPLETE_RESEARCH_ONLY",
        None,
    ),
    CandidateSlot(
        "PE-C2",
        "BCE-D",
        "observable_state_bounded_consensus",
        "bce_v1_d",
        "PASS_SPENT_PREDICTIONS_SCOREABLE",
        BCE_D_ID,
        "COMPLETE_RESEARCH_ONLY",
        None,
    ),
    CandidateSlot(
        "PE-C3",
        "Fixed Directional Consensus alpha=0.40",
        "deterministic_bounded_consensus_control",
        "fixed_alpha_040_v1",
        "PASS_SPENT_PREDICTIONS_SCOREABLE",
        FIXED_040_ID,
        "COMPLETE_RESEARCH_ONLY",
        None,
    ),
    CandidateSlot(
        "PE-C4",
        "H-OFS",
        "hierarchical_observable_fair_value_state",
        "v11_estimator_requires_new_research_runner_and_v12_formal_binding",
        "BLOCKED_IMPLEMENTATION",
        None,
        "NO_USABLE_PREDICTION_ARTIFACT",
        "hofs_spent_r4_prediction_adapter_v1",
    ),
    CandidateSlot(
        "PE-C5",
        "Causal TCN",
        "causal_sequence_residual",
        "v7_hypothesis_requires_private_process_v8",
        "BLOCKED_IMPLEMENTATION",
        None,
        "NO_FULL_SPENT_R4_RUNNER_OR_PREDICTION_ARTIFACT",
        "causal_tcn_spent_r4_panel_adapter_v1",
    ),
)


def canonical_json_bytes(payload: Any) -> bytes:
    """Serialize JSON without NaN or noncanonical whitespace."""

    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def semantic_sha256(payload: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def fold_id_for_position(position: int) -> str:
    if type(position) is not int or not SCORE_START <= position < SCORE_END:
        raise ResearchTournamentContractError("score position is outside spent R4 geometry")
    number = 12 + (position - SCORE_START) // 21
    return f"fold_{min(number, 73):03d}"


def design_lock_payload() -> dict[str, Any]:
    """Return the complete research-only design declaration."""

    payload: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "tournament_id": TOURNAMENT_ID,
        "experiment_id": EXPERIMENT_ID,
        "evidence_class": RESEARCH_EVIDENCE_CLASS,
        "detailed_evidence_class": DETAILED_EVIDENCE_CLASS,
        "authority": {
            "fresh": FRESH_AUTHORITY,
            "heldout": HELDOUT_AUTHORITY,
            "certification": CERTIFICATION_AUTHORITY,
            "promotion": PROMOTION_AUTHORITY,
            "portfolio_admission": PORTFOLIO_ADMISSION_AUTHORITY,
            "registry_mutation": REGISTRY_MUTATION_AUTHORITY,
        },
        "inputs": {
            "public_root": PUBLIC_ROOT,
            "public_freeze_raw_sha256": PUBLIC_FREEZE_SHA256,
            "public_checksums_raw_sha256": PUBLIC_CHECKSUMS_SHA256,
            "spent_truth_root": TRUTH_ROOT,
            "spent_truth_receipt_raw_sha256": TRUTH_RECEIPT_SHA256,
            "spent_truth_checksums_raw_sha256": TRUTH_CHECKSUMS_SHA256,
            "bce_prediction_root": BCE_PREDICTION_ROOT,
            "bce_predictions_raw_sha256": BCE_PREDICTIONS_SHA256,
            "bce_manifest_raw_sha256": BCE_MANIFEST_SHA256,
            "bce_checksums_raw_sha256": BCE_CHECKSUMS_SHA256,
            "latent_inputs_allowed": False,
            "path_arguments_allowed": False,
        },
        "geometry": {
            "seeds": list(SEEDS),
            "seed_aliases": list(SEED_ALIASES),
            "dgps": list(DGP_IDS),
            "tasks": TASK_COUNT,
            "rows_per_task": ROWS_PER_TASK,
            "score_start_inclusive": SCORE_START,
            "score_end_exclusive": SCORE_END,
            "score_rows_per_task": SCORE_ROWS_PER_TASK,
            "common_identities": COMMON_IDENTITIES,
            "folds_per_task": FOLDS_PER_TASK,
            "fold_blocks": FOLD_BLOCKS,
        },
        "five_candidate_slots": [asdict(slot) for slot in FIVE_CANDIDATE_SLOTS],
        "scored_now": {
            "champion_id": CHAMPION_ID,
            "candidate_ids": list(SCORED_CANDIDATE_IDS),
            "model_columns": dict(MODEL_COLUMNS),
        },
        "metrics": {
            "primary_space": "natural_log_expected_pe",
            "signed_error": "log_prediction_minus_true_log_fair_pe",
            "mae": True,
            "rmse": True,
            "seed_slices": True,
            "dgp_slices": True,
            "seed_dgp_slices": True,
            "chronological_fold_slices": True,
            "tail_quantiles": list(TAIL_QUANTILES),
            "extreme_abs_log_error_threshold": EXTREME_ABS_LOG_ERROR_THRESHOLD,
            "systematic_dgp_joint_tail_failure_definition": (
                "candidate_p95_gt_champion_p95_and_candidate_extreme_frequency_gt_champion_"
                "and_candidate_only_q95_count_gt_champion_only_q95_count"
            ),
            "complementarity": [
                "signed_error_pearson",
                "absolute_error_pearson",
                "log_prediction_pearson",
                "prediction_disagreement_frequency_2_5_10pct",
                "oracle_pair_mae",
                "oracle_pair_rmse",
            ],
            "oracle_is_achievable_model_score": False,
            "bootstrap": {
                "purpose": "RESEARCH_STABILITY_DIAGNOSTIC_ONLY",
                "replicates": BOOTSTRAP_REPLICATES,
                "rng_seed": BOOTSTRAP_RNG_SEED,
                "hierarchy": "seed_then_dgp_then_chronological_fold",
                "formal_gate": False,
            },
        },
        "selection": {
            "parameter_or_alpha_sweep": False,
            "candidate_selection_authority": False,
            "score_may_mutate_model": False,
            "score_may_support_certification_or_promotion": False,
        },
        "status": "FROZEN_RESEARCH_ONLY_BCE_3_OF_5_SCOREABLE",
    }
    payload["design_semantic_sha256"] = semantic_sha256(payload)
    return payload


__all__ = [name for name in globals() if name.isupper()] + [
    "CandidateSlot",
    "ResearchTournamentContractError",
    "canonical_json_bytes",
    "design_lock_payload",
    "fold_id_for_position",
    "semantic_sha256",
]
