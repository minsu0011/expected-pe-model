"""Injected, truth-free contract for the five-line qualification evaluator.

The module deliberately contains no repository paths and performs no filesystem I/O.  A
one-shot custody layer must supply the frozen policy bytes and the final pre-truth binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
from typing import Any, Final, Iterable, Mapping, Sequence


class QualificationEvaluatorError(RuntimeError):
    """Raised when an injected contract, artifact, or score input drifts."""


SCHEMA_VERSION: Final = (
    "expected_pe.portfolio_governance.qualification_certification_design_lock.v2"
)
LOCK_STATUS: Final = "FROZEN_PRE_TRUTH_SUPERSEDING_POLICY_ONLY"
EVIDENCE_CLASS: Final = "FROZEN_PRE_TRUTH_POLICY_ONLY"
CHAMPION_ID: Final = "v04_expected_pe"
C1_ID: Final = "bce_v1_b_causal_rolling_dispersion_budget"
C2_ID: Final = "bce_v1_d_observable_state_confidence_shrinkage"
C3_ID: Final = "bce_tournament_v1_fixed_alpha_040_directional_consensus"
C4_ID: Final = "hofs_v4_expected_pe"
C5_ID: Final = "cvtcn_v8_private_process_tcn_residual"
CANDIDATE_IDS: Final = (C1_ID, C2_ID, C3_ID, C4_ID)
MODEL_IDS: Final = (CHAMPION_ID, *CANDIDATE_IDS)
DGP_IDS: Final = tuple("ABCDEFGHIJ")
SEED_ALIAS_TO_VALUE: Final = {
    "qualification_seed_01": 7573,
    "qualification_seed_02": 7577,
    "qualification_seed_03": 7583,
    "qualification_seed_04": 7589,
    "qualification_seed_05": 7591,
}
SEED_ALIASES: Final = tuple(SEED_ALIAS_TO_VALUE)

ROWS_PER_TASK: Final = 1_296
TASK_COUNT: Final = 50
IDENTITY_COUNT: Final = 64_800
MODEL_ROW_COUNT: Final = 324_000
FIRST_POSITION: Final = 504
FINAL_POSITION: Final = 1_799
EXTREME_THRESHOLD: Final = 0.09531017980432493
DISAGREEMENT_THRESHOLDS: Final = (
    0.019802627296179712,
    0.04879016416943201,
    0.09531017980432493,
)
DISAGREEMENT_QUANTILES: Final = (0.5, 0.9, 0.95)

IDENTITY_COLUMNS: Final = (
    "seed_alias",
    "dgp_id",
    "session_position",
    "date",
    "symbol",
    "fold_id",
    "train_end_position",
    "test_start_position",
)
PREDICTION_COLUMNS: Final = (
    *IDENTITY_COLUMNS,
    "pe_model_id",
    "model_ordinal",
    "expected_pe",
    "expected_log_pe",
    "uncertainty",
    "confidence",
    "regime_state",
    "specialist_tags",
    "prediction_valid",
    "pit_valid",
    "source_model_version",
    "valuation_state_confidence",
    "out_of_distribution_score",
    "model_disagreement",
    "state_uncertainty",
    "applied_alpha",
    "raw_log_correction",
)
TRUTH_COLUMNS: Final = (
    "date",
    "true_fair_pe",
    "true_log_fair_pe",
    "true_economic_eps_contemporaneous",
    "true_pit_eps",
    "true_observed_pe",
    "true_expected_pe_eligible",
)
TRUTH_EVALUATOR_COLUMNS: Final = (
    *IDENTITY_COLUMNS,
    "true_fair_pe",
    "true_log_fair_pe",
    "true_economic_eps_contemporaneous",
    "true_pit_eps",
    "true_observed_pe",
    "true_expected_pe_eligible",
)

RANKING_RULE: Final = (
    "worst_dgp_mean_harm_ascending",
    "dgp_mean_wins_descending",
    "pooled_mae_relative_gain_descending",
    "candidate_id_ascending",
)
CLASSIFICATION_PRECEDENCE: Final = (
    "CERTIFIED_SURVIVOR",
    "PORTFOLIO_SPECIALIST_CANDIDATE",
    "DIVERSITY_CANDIDATE",
    "REJECTED",
    "RESEARCH_ONLY",
)
RUNTIME_FIELDS: Final = (
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
RUNTIME_BINDING_FIELDS: Final = ("raw_sha256", "file_id", "receipt")
FILE_ID_FIELDS: Final = ("volume_serial_number", "file_id_128")
RUNTIME_SCHEMA_VERSION: Final = "expected_pe.qualification.prediction_runtime.v1"
RUNTIME_STATUS: Final = "PASS_FROZEN_PRETRUTH_RUNTIME"
RUNTIME_LANES: Final = ("shared_c1_c3", "isolated_c4")
RESEARCH_DIAGNOSTIC_FIELDS: Final = (
    "candidate_id",
    "research_candidate_id",
    "candidate_summary_raw_sha256",
    "checksums_raw_sha256",
    "pooled_mae_relative_gain",
)
FINAL_BINDING_FIELDS: Final = (
    "schema_version",
    "qualification_lock_raw_sha256",
    "prediction_artifact_raw_sha256",
    "prediction_artifact_semantic_sha256",
    "post_prediction_audit_raw_sha256",
    "post_prediction_audit_semantic_sha256",
    "common_full_identities_semantic_sha256",
    "prediction_columns",
    "source_model_versions",
)
ONE_SHOT_CUSTODY_VERIFICATION_FIELDS: Final = (
    "schema_version",
    "qualification_lock_raw_sha256",
    "prediction_artifact_raw_sha256",
    "prediction_artifact_semantic_sha256",
    "post_prediction_audit_raw_sha256",
    "post_prediction_audit_semantic_sha256",
    "common_full_identities_semantic_sha256",
    "prediction_rows_stream_from_verified_held_artifact",
    "post_prediction_audit_links_prediction_artifact",
    "verification_completed_before_truth_open",
)
IDENTITY_SEMANTIC_SHA256_RULE: Final = (
    "SHA-256 over the byte concatenation, in fixed task/row order, of canonical JSON "
    "lines for each logical eight-field identity encoded as a JSON array in "
    "identity_columns_in_order; each line uses UTF-8, sort_keys=true, "
    "separators=(',',':'), ensure_ascii=false, allow_nan=false, and one terminal LF."
)
SCORECARD_COLUMNS: Final = (
    "line_id",
    "candidate_id",
    "family",
    "version",
    "research_readiness",
    "fresh_qualification_status",
    "mae",
    "rmse",
    "gain_vs_v04_mae",
    "gain_vs_v04_rmse",
    "seed_wins",
    "seed_total",
    "dgp_wins",
    "dgp_total",
    "direct_dgp_wins",
    "worst_seed_harm",
    "worst_dgp_harm",
    "worst_seed_dgp_harm",
    "p95",
    "p99",
    "extreme_count",
    "systematic_joint_tail_failures",
    "error_corr_v04",
    "abs_error_corr_v04",
    "prediction_corr_v04",
    "oracle_pair_mae",
    "oracle_pair_rmse",
    "oracle_marginal_mae_gain",
    "deployable",
    "pit_safe",
    "causal_safe",
    "portfolio_role",
    "certification_status",
)

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")


def sha256_bytes(raw: bytes) -> str:
    """Return the lowercase SHA-256 of *raw*."""

    return hashlib.sha256(raw).hexdigest()


def canonical_json_bytes(payload: object) -> bytes:
    """Serialize an artifact by the V2 sorted, indented, terminal-LF contract."""

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


def canonical_json_line_bytes(payload: object) -> bytes:
    """Serialize one compact UTF-8 JSON line for the V2 identity digest."""

    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def identity_semantic_sha256(identities: Iterable[Sequence[object]]) -> str:
    """Hash fixed-order eight-field identities by the exact V2 JSONL algorithm."""

    digest = hashlib.sha256()
    for ordinal, identity in enumerate(identities):
        if type(identity) not in (list, tuple) or len(identity) != len(IDENTITY_COLUMNS):
            raise QualificationEvaluatorError(
                f"identity semantic input differs at ordinal {ordinal}"
            )
        try:
            digest.update(canonical_json_line_bytes(list(identity)))
        except (TypeError, ValueError) as exc:
            raise QualificationEvaluatorError(
                f"identity semantic input is not canonical JSON at ordinal {ordinal}"
            ) from exc
    return digest.hexdigest()


def _reject_constant(value: str) -> None:
    raise QualificationEvaluatorError(f"nonfinite JSON constant is forbidden: {value}")


def strict_json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    """Parse a UTF-8 JSON object while rejecting duplicates and nonfinite constants."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise QualificationEvaluatorError(f"duplicate JSON key in {label}: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise QualificationEvaluatorError(f"invalid UTF-8 JSON: {label}") from exc
    if type(payload) is not dict:
        raise QualificationEvaluatorError(f"JSON root is not an object: {label}")
    return payload


def _mapping(value: object, *, label: str) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise QualificationEvaluatorError(f"{label} must be an exact JSON object")
    return value


def _sequence(value: object, *, label: str) -> Sequence[Any]:
    if type(value) is not list:
        raise QualificationEvaluatorError(f"{label} must be an exact JSON list")
    return value


def _exact_keys(value: Mapping[str, Any], expected: Sequence[str], *, label: str) -> None:
    if len(value) != len(expected) or set(value) != set(expected):
        raise QualificationEvaluatorError(f"{label} key universe differs from the frozen schema")


def _hex64(value: object, *, label: str) -> str:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise QualificationEvaluatorError(f"{label} must be a lowercase SHA-256")
    return value


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise QualificationEvaluatorError(f"{label} must be an integer >= {minimum}")
    return value


def _finite(value: object, *, label: str) -> float:
    if type(value) not in (int, float):
        raise QualificationEvaluatorError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number):
        raise QualificationEvaluatorError(f"{label} must be finite")
    return number


def _require_equal(actual: object, expected: object, *, label: str) -> None:
    if actual != expected:
        raise QualificationEvaluatorError(f"{label} differs from the V2 policy")


@dataclass(frozen=True)
class QualificationContract:
    """Validated semantic projection of an injected superseding V2 lock."""

    raw_sha256: str
    lock_id: str
    payload: Mapping[str, Any]
    research_baselines: Mapping[str, Mapping[str, Any]]

    @classmethod
    def from_json_bytes(
        cls,
        raw: bytes,
        *,
        expected_raw_sha256: str,
    ) -> "QualificationContract":
        observed = sha256_bytes(raw)
        if observed != _hex64(expected_raw_sha256, label="expected qualification lock hash"):
            raise QualificationEvaluatorError("qualification lock raw SHA-256 differs")
        payload = strict_json_object(raw, label="qualification V2 lock")
        cls._validate_payload(payload)
        diagnostics = _mapping(payload["diagnostic_contract"], label="diagnostic_contract")
        gap = _mapping(
            diagnostics["research_vs_qualification_gap"],
            label="research_vs_qualification_gap",
        )
        baselines = _mapping(gap["spent_research_bindings"], label="spent research bindings")
        return cls(
            raw_sha256=observed,
            lock_id=str(payload["lock_id"]),
            payload=payload,
            research_baselines=baselines,
        )

    @staticmethod
    def _validate_payload(payload: Mapping[str, Any]) -> None:
        _require_equal(payload.get("schema_version"), SCHEMA_VERSION, label="schema_version")
        _require_equal(payload.get("status"), LOCK_STATUS, label="lock status")
        _require_equal(payload.get("evidence_class"), EVIDENCE_CLASS, label="evidence class")
        _require_equal(
            payload.get("serialization_contract"),
            "UTF-8 JSON, recursively sorted keys, indent=2, LF line endings, terminal LF, allow_nan=false",
            label="serialization contract",
        )
        if not isinstance(payload.get("lock_id"), str) or not payload["lock_id"]:
            raise QualificationEvaluatorError("lock_id is missing")

        authority = _mapping(payload.get("authority"), label="authority")
        if not authority or any(type(value) is not bool or value for value in authority.values()):
            raise QualificationEvaluatorError("policy lock unexpectedly grants execution authority")

        candidates = tuple(payload.get("scoreable_candidate_ids_in_order", ()))
        _require_equal(candidates, CANDIDATE_IDS, label="scoreable candidate order")
        geometry = _mapping(
            payload.get("prediction_and_truth_geometry"),
            label="prediction_and_truth_geometry",
        )
        _require_equal(
            tuple(geometry.get("candidate_prediction_ids_in_order", ())),
            MODEL_IDS,
            label="prediction model order",
        )
        _require_equal(
            tuple(geometry.get("identity_columns_in_order", ())),
            IDENTITY_COLUMNS,
            label="identity columns",
        )
        _require_equal(
            tuple(geometry.get("truth_columns_in_order", ())),
            TRUTH_COLUMNS,
            label="truth columns",
        )
        _require_equal(
            geometry.get("identity_semantic_sha256"),
            IDENTITY_SEMANTIC_SHA256_RULE,
            label="identity semantic SHA-256 algorithm",
        )
        _require_equal(
            geometry.get("seed_alias_to_qualification_seed"),
            SEED_ALIAS_TO_VALUE,
            label="seed alias mapping",
        )
        _require_equal(geometry.get("symbol"), "DGP_ISSUER", label="symbol")
        _require_equal(geometry.get("scoreable_identity_count"), IDENTITY_COUNT, label="identity count")
        _require_equal(geometry.get("long_prediction_rows"), MODEL_ROW_COUNT, label="model rows")
        required_mask = (
            "true_expected_pe_eligible AND v04 prediction_valid AND v04 pit_valid AND "
            "prediction_valid AND pit_valid for every one of PE-C1 through PE-C4"
        )
        _require_equal(geometry.get("common_mask"), required_mask, label="common mask")

        generation = _mapping(
            payload.get("common_generation_contract"), label="common_generation_contract"
        )
        _require_equal(
            tuple(generation.get("qualification_seeds_in_order", ())),
            tuple(SEED_ALIAS_TO_VALUE.values()),
            label="qualification seeds",
        )
        _require_equal(
            tuple(generation.get("dgp_ids_in_order", ())), DGP_IDS, label="DGP order"
        )
        _require_equal(generation.get("logical_task_count"), TASK_COUNT, label="task count")
        _require_equal(
            generation.get("model_prediction_rows_per_task"),
            ROWS_PER_TASK,
            label="rows per task",
        )

        screen = _mapping(
            payload.get("qualification_performance_screen"),
            label="qualification_performance_screen",
        )
        expected_screen = {
            "all_gates_conjunctive": True,
            "dgp_mean_wins_min": 6,
            "dgp_total": 10,
            "pooled_extreme_error_frequency_non_worse": True,
            "pooled_mae_relative_gain_min": 0.005,
            "pooled_p95_abs_log_error_non_worse": True,
            "pooled_rmse_relative_gain_min": 0.0,
            "seed_dgp_total": 50,
            "seed_dgp_wins_min": 30,
            "worst_dgp_mean_harm_max": 0.03,
            "worst_seed_dgp_harm_max": 0.05,
        }
        _require_equal(dict(screen), expected_screen, label="qualification performance gate")

        ranking = _mapping(payload.get("ranking_contract"), label="ranking_contract")
        _require_equal(
            tuple(ranking.get("formal_survivor_rank_tuple", ())),
            RANKING_RULE,
            label="ranking rule",
        )
        _require_equal(
            ranking.get("formal_survivor_rank_universe"),
            "CERTIFIED_SURVIVOR candidates only",
            label="formal rank universe",
        )
        _require_equal(ranking.get("non_survivor_formal_rank"), None, label="non-survivor rank")
        _require_equal(ranking.get("rounding_before_rank"), False, label="ranking rounding")

        classification = _mapping(
            payload.get("classification_contract"), label="classification_contract"
        )
        _require_equal(
            tuple(classification.get("classification_precedence", ())),
            CLASSIFICATION_PRECEDENCE,
            label="classification precedence",
        )

        math_contract = _mapping(payload.get("metric_math_contract"), label="metric math")
        _require_equal(
            math_contract.get("extreme_abs_log_error_threshold"),
            EXTREME_THRESHOLD,
            label="extreme threshold",
        )
        _require_equal(
            math_contract.get("extreme_abs_log_error_comparison"),
            "greater_than_or_equal",
            label="extreme comparison",
        )
        expected_slice_math = {
            "seed_gain": "(v04_seed_mae-candidate_seed_mae)/v04_seed_mae",
            "seed_win": "seed_gain strictly greater than 0; ties are losses",
            "worst_seed_harm": "max(0,-min(the five seed_gains))",
            "direct_dgp_win": (
                "The per-DGP pooled MAE relative gain computed by gain is strictly "
                "greater than 0; ties are losses."
            ),
        }
        for key, expected in expected_slice_math.items():
            _require_equal(
                math_contract.get(key), expected, label=f"metric math/{key}"
            )

        diagnostics = _mapping(payload.get("diagnostic_contract"), label="diagnostic_contract")
        oracle_pair = _mapping(diagnostics.get("oracle_pair"), label="oracle_pair")
        _require_equal(
            oracle_pair.get("marginal_mae_zero_denominator_rule"),
            (
                "If min(candidate_mae,v04_mae) is exactly 0.0, serialize "
                "marginal_mae_gain_vs_better_standalone as JSON null, serialize status "
                "ZERO_BETTER_STANDALONE_MAE, and set the diversity oracle-gain conjunct "
                "to false."
            ),
            label="oracle marginal-MAE zero denominator rule",
        )
        disagreement = _mapping(diagnostics.get("disagreement"), label="disagreement")
        _require_equal(
            tuple(disagreement.get("thresholds_natural_log", ())),
            DISAGREEMENT_THRESHOLDS,
            label="disagreement thresholds",
        )
        _require_equal(
            tuple(disagreement.get("type7_quantiles", ())),
            DISAGREEMENT_QUANTILES,
            label="disagreement quantiles",
        )
        _require_equal(
            disagreement.get("comparison"),
            "strict_greater_than",
            label="disagreement comparator",
        )
        overfit = _mapping(diagnostics.get("overfit_detector"), label="overfit detector")
        expected_overfit = {
            "dgp_mean_gain_population_variance": (
                "Let mean=math.fsum(the ten dgp_mean_gains)/10; "
                "variance=math.fsum((gain-mean)*(gain-mean) in frozen DGP order)/10."
            ),
            "fold_mae_gain_population_variance": (
                "Let mean=math.fsum(all nonempty fixed-order fold MAE relative gains)/"
                "fold_count; variance=math.fsum((gain-mean)*(gain-mean) in fixed fold "
                "order)/fold_count."
            ),
            "parameter_sensitivity": (
                "Do not estimate parameter sensitivity on fresh qualification. Serialize "
                "value as JSON null and status NOT_REESTIMATED_ON_FRESH; only separately "
                "hash-bound spent-research sensitivity may be reported outside the fresh score."
            ),
            "prediction_instability": (
                "Do not rerun or perturb a frozen candidate after qualification results. "
                "Serialize numeric value as JSON null and status NOT_REMEASURED_ON_FRESH, "
                "while separately reporting the pretruth deterministic source-recomputation "
                "audit binding."
            ),
            "seed_mae_gain_population_variance": (
                "Let mean=math.fsum(the five seed MAE relative gains)/5; "
                "variance=math.fsum((gain-mean)*(gain-mean) in frozen seed order)/5."
            ),
            "tail_deterioration": (
                "p95_relative_deterioration=(candidate_p95-v04_p95)/v04_p95 with a "
                "strictly positive v04 p95 denominator; "
                "extreme_frequency_deterioration=candidate_extreme_frequency-"
                "v04_extreme_frequency."
            ),
        }
        _require_equal(dict(overfit), expected_overfit, label="overfit detector")
        runtime = _mapping(diagnostics.get("runtime_receipt"), label="runtime_receipt")
        _require_equal(
            tuple(runtime.get("required_fields", ())), RUNTIME_FIELDS, label="runtime fields"
        )
        _require_equal(
            runtime.get("schema_version"), RUNTIME_SCHEMA_VERSION, label="runtime schema"
        )
        _require_equal(runtime.get("status"), RUNTIME_STATUS, label="runtime status")
        _require_equal(
            runtime.get("lane_contract"),
            (
                "The first receipt is lane_id shared_c1_c3 for PE-C1 through PE-C3 in "
                "scoreable order; the second is lane_id isolated_c4 for PE-C4 only."
            ),
            label="runtime lane contract",
        )

        baselines = _mapping(
            _mapping(
                diagnostics.get("research_vs_qualification_gap"),
                label="research gap contract",
            ).get("spent_research_bindings"),
            label="spent research bindings",
        )
        _require_equal(tuple(sorted(baselines)), tuple(sorted(CANDIDATE_IDS)), label="baseline IDs")
        for candidate_id, record_value in baselines.items():
            record = _mapping(record_value, label=f"research baseline/{candidate_id}")
            _hex64(
                record.get("candidate_summary_raw_sha256"),
                label=f"research baseline summary/{candidate_id}",
            )
            _hex64(
                record.get("checksums_raw_sha256"),
                label=f"research baseline checksums/{candidate_id}",
            )
            _finite(
                record.get("pooled_mae_relative_gain"),
                label=f"research baseline gain/{candidate_id}",
            )
            if not isinstance(record.get("research_candidate_id"), str):
                raise QualificationEvaluatorError("research candidate identity is missing")

        terminal = _mapping(payload.get("c5_terminal_resolution"), label="C5 terminal resolution")
        expected_terminal = {
            "candidate_id": C5_ID,
            "portfolio_scorecard_record": "NOT_RUN_TERMINAL_CUSTODY_NO_GO",
            "status": "RESEARCH_ONLY_SATURATED",
            "current_identity_retry_allowed": False,
            "fresh_surface_consumed": False,
            "heldout_surface_consumed": False,
            "performance_claim_allowed": False,
            "replacement_or_substitution_allowed": False,
        }
        for key, expected in expected_terminal.items():
            _require_equal(terminal.get(key), expected, label=f"C5 terminal/{key}")
        _hex64(
            terminal.get("terminal_forensic_audit_raw_sha256"), label="C5 forensic audit"
        )
        _hex64(
            terminal.get("terminal_forensic_checksums_raw_sha256"),
            label="C5 forensic checksums",
        )

        scorecard = _mapping(payload.get("scorecard_contract"), label="scorecard contract")
        _require_equal(
            tuple(scorecard.get("columns_in_order", ())),
            SCORECARD_COLUMNS,
            label="scorecard columns",
        )
        _require_equal(
            scorecard.get("dgp_wins_definition"),
            (
                "Count of the ten dgp_mean_gains strictly greater than zero; "
                "direct_dgp_wins separately counts per-DGP pooled MAE gains strictly "
                "greater than zero."
            ),
            label="scorecard DGP win definition",
        )
        _require_equal(
            scorecard.get("qualification_deployable"),
            False,
            label="scorecard deployability",
        )
        _require_equal(
            scorecard.get("c5_metric_policy"),
            (
                "PE-C5 uses the identical column universe, null for every unavailable "
                "numeric or safety metric, deployable=false, and "
                "NOT_RUN_TERMINAL_CUSTODY_NO_GO status without a performance claim."
            ),
            label="scorecard C5 policy",
        )
        _require_equal(
            scorecard.get("scoreable_safety_rule"),
            (
                "pit_safe and causal_safe are true only because the final pretruth "
                "prediction/source audit binding is a truth-open prerequisite; deployable "
                "remains false until separate heldout and release gates."
            ),
            label="scorecard safety rule",
        )


@dataclass(frozen=True)
class FinalPretruthBinding:
    """Hashes and versions that a later final freeze must inject into the evaluator."""

    payload: Mapping[str, Any]
    source_model_versions: Mapping[str, str]

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        contract: QualificationContract,
    ) -> "FinalPretruthBinding":
        mapping = _mapping(value, label="final pretruth binding")
        _exact_keys(mapping, FINAL_BINDING_FIELDS, label="final pretruth binding")
        _require_equal(
            mapping["schema_version"],
            "expected_pe.qualification.final_pretruth_binding.v1",
            label="final binding schema",
        )
        _require_equal(
            mapping["qualification_lock_raw_sha256"],
            contract.raw_sha256,
            label="final binding policy hash",
        )
        for field in (
            "prediction_artifact_raw_sha256",
            "prediction_artifact_semantic_sha256",
            "post_prediction_audit_raw_sha256",
            "post_prediction_audit_semantic_sha256",
            "common_full_identities_semantic_sha256",
        ):
            _hex64(mapping[field], label=f"final binding/{field}")
        _require_equal(
            tuple(mapping["prediction_columns"]),
            PREDICTION_COLUMNS,
            label="final binding prediction columns",
        )
        versions = _mapping(mapping["source_model_versions"], label="source model versions")
        if len(versions) != len(MODEL_IDS) or set(versions) != set(MODEL_IDS):
            raise QualificationEvaluatorError("source model version universe differs")
        normalized: dict[str, str] = {}
        for model_id in MODEL_IDS:
            version = versions[model_id]
            if type(version) is not str or not version.strip() or "pending" in version.casefold():
                raise QualificationEvaluatorError(
                    f"source_model_version is not final for {model_id}"
                )
            normalized[model_id] = version
        return cls(payload=dict(mapping), source_model_versions=normalized)


@dataclass(frozen=True)
class OneShotCustodyVerification:
    """Wrapper assertion that row streams and post-audit hashes share one binding.

    The detached arithmetic core cannot authenticate file handles or control truth-open
    timing.  A one-shot custody wrapper must create this record only after verifying the
    held prediction artifact, its exact row stream, and its post-prediction audit against
    ``FinalPretruthBinding`` and before opening truth.  The evaluator rechecks every linked
    value and rejects a false prerequisite; this record is not a substitute for wrapper I/O
    custody evidence.
    """

    payload: Mapping[str, Any]

    @classmethod
    def from_mapping(
        cls,
        value: Mapping[str, Any],
        *,
        contract: QualificationContract,
        final_binding: FinalPretruthBinding,
    ) -> "OneShotCustodyVerification":
        record = _mapping(value, label="one-shot custody verification")
        _exact_keys(
            record,
            ONE_SHOT_CUSTODY_VERIFICATION_FIELDS,
            label="one-shot custody verification",
        )
        _require_equal(
            record["schema_version"],
            "expected_pe.qualification.one_shot_custody_verification.v1",
            label="one-shot custody schema",
        )
        _require_equal(
            record["qualification_lock_raw_sha256"],
            contract.raw_sha256,
            label="one-shot custody lock hash",
        )
        for field in (
            "prediction_artifact_raw_sha256",
            "prediction_artifact_semantic_sha256",
            "post_prediction_audit_raw_sha256",
            "post_prediction_audit_semantic_sha256",
            "common_full_identities_semantic_sha256",
        ):
            _require_equal(
                record[field],
                final_binding.payload[field],
                label=f"one-shot custody/{field}",
            )
        for field in (
            "prediction_rows_stream_from_verified_held_artifact",
            "post_prediction_audit_links_prediction_artifact",
            "verification_completed_before_truth_open",
        ):
            if type(record[field]) is not bool or not record[field]:
                raise QualificationEvaluatorError(
                    f"one-shot custody prerequisite is not true: {field}"
                )
        return cls(payload=dict(record))


def validate_research_diagnostics(
    records: Sequence[Mapping[str, Any]],
    *,
    contract: QualificationContract,
) -> dict[str, dict[str, Any]]:
    """Validate pretruth-bound spent-research diagnostic inputs without opening artifacts."""

    if type(records) not in (list, tuple) or len(records) != len(CANDIDATE_IDS):
        raise QualificationEvaluatorError("research diagnostics must contain exactly four records")
    output: dict[str, dict[str, Any]] = {}
    for value in records:
        record = _mapping(value, label="research diagnostic")
        _exact_keys(record, RESEARCH_DIAGNOSTIC_FIELDS, label="research diagnostic")
        candidate_id = record["candidate_id"]
        if candidate_id not in CANDIDATE_IDS or candidate_id in output:
            raise QualificationEvaluatorError("research diagnostic candidate universe differs")
        baseline = _mapping(
            contract.research_baselines[candidate_id],
            label=f"research baseline/{candidate_id}",
        )
        for field in RESEARCH_DIAGNOSTIC_FIELDS[1:]:
            _require_equal(
                record[field], baseline[field], label=f"research diagnostic/{candidate_id}/{field}"
            )
        output[candidate_id] = dict(record)
    _require_equal(tuple(output), CANDIDATE_IDS, label="research diagnostic order")
    return output


def _validate_file_id(value: object, *, label: str) -> dict[str, Any]:
    record = _mapping(value, label=label)
    _exact_keys(record, FILE_ID_FIELDS, label=label)
    volume = _integer(record["volume_serial_number"], label=f"{label}/volume")
    file_id = record["file_id_128"]
    if type(file_id) is not str or _HEX32.fullmatch(file_id) is None:
        raise QualificationEvaluatorError(f"{label}/file_id_128 must be 32 lowercase hex digits")
    return {"volume_serial_number": volume, "file_id_128": file_id}


def validate_runtime_bindings(
    bindings: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Validate two externally hash/FileId-bound, pretruth runtime receipts."""

    if type(bindings) not in (list, tuple) or len(bindings) != 2:
        raise QualificationEvaluatorError("runtime bindings must contain shared C1-C3 and C4")
    expected_candidate_sets = (CANDIDATE_IDS[:3], (C4_ID,))
    output: list[dict[str, Any]] = []
    seen_lanes: set[str] = set()
    for ordinal, value in enumerate(bindings):
        binding = _mapping(value, label="runtime binding")
        _exact_keys(binding, RUNTIME_BINDING_FIELDS, label="runtime binding")
        raw_hash = _hex64(binding["raw_sha256"], label="runtime receipt hash")
        file_id = _validate_file_id(binding["file_id"], label="runtime receipt FileId")
        receipt = _mapping(binding["receipt"], label="runtime receipt")
        _exact_keys(receipt, RUNTIME_FIELDS, label="runtime receipt")
        try:
            observed_hash = sha256_bytes(canonical_json_bytes(receipt))
        except (TypeError, ValueError) as exc:
            raise QualificationEvaluatorError(
                "runtime receipt is not canonical-JSON serializable"
            ) from exc
        if observed_hash != raw_hash:
            raise QualificationEvaluatorError(
                "runtime receipt canonical SHA-256 differs from its external binding"
            )
        candidate_ids = tuple(receipt["candidate_ids"])
        _require_equal(
            candidate_ids,
            expected_candidate_sets[ordinal],
            label="runtime candidate attribution",
        )
        lane_id = receipt["lane_id"]
        if lane_id != RUNTIME_LANES[ordinal] or lane_id in seen_lanes:
            raise QualificationEvaluatorError("runtime lane_id differs or is duplicated")
        seen_lanes.add(lane_id)
        _require_equal(
            receipt["schema_version"], RUNTIME_SCHEMA_VERSION, label="runtime schema_version"
        )
        _require_equal(receipt["status"], RUNTIME_STATUS, label="runtime status")
        started = _integer(receipt["started_perf_counter_ns"], label="runtime start")
        ended = _integer(receipt["ended_perf_counter_ns"], label="runtime end")
        wall = _integer(receipt["wall_time_ns"], label="runtime wall time")
        if ended < started or wall != ended - started:
            raise QualificationEvaluatorError("runtime monotonic interval differs")
        interval = _finite(receipt["sample_interval_max_ms"], label="runtime sample interval")
        if interval <= 0.0 or interval > 100.0:
            raise QualificationEvaluatorError("runtime sample interval exceeds 100 ms")
        _integer(receipt["sample_count"], label="runtime sample count", minimum=1)
        _integer(receipt["peak_process_tree_rss_bytes"], label="runtime peak RSS")
        if _integer(receipt["peak_vram_bytes"], label="runtime peak VRAM") != 0:
            raise QualificationEvaluatorError("runtime receipt reports GPU VRAM")
        if (
            _integer(
                receipt["gpu_process_observation_count"],
                label="runtime GPU observations",
            )
            != 0
        ):
            raise QualificationEvaluatorError("runtime receipt reports a GPU process")
        exits = _sequence(receipt["process_exit_records"], label="process exit records")
        if not exits:
            raise QualificationEvaluatorError("process exit records are empty")
        normalized_exits: list[tuple[str, int]] = []
        for exit_value in exits:
            exit_record = _mapping(exit_value, label="process exit record")
            _exact_keys(
                exit_record,
                ("process_role", "worker_ordinal", "exit_code"),
                label="process exit record",
            )
            role = exit_record["process_role"]
            if type(role) is not str or not role:
                raise QualificationEvaluatorError("process role is missing")
            worker = _integer(exit_record["worker_ordinal"], label="worker ordinal")
            if type(exit_record["exit_code"]) is not int or exit_record["exit_code"] != 0:
                raise QualificationEvaluatorError("runtime process exit is nonzero")
            normalized_exits.append((role, worker))
        if normalized_exits != sorted(normalized_exits) or len(normalized_exits) != len(
            set(normalized_exits)
        ):
            raise QualificationEvaluatorError("process exit records are unsorted or duplicated")
        output.append(
            {
                "raw_sha256": raw_hash,
                "file_id": file_id,
                "receipt": dict(receipt),
            }
        )
    return tuple(output)


__all__ = [
    "C1_ID",
    "C2_ID",
    "C3_ID",
    "C4_ID",
    "C5_ID",
    "CANDIDATE_IDS",
    "CHAMPION_ID",
    "CLASSIFICATION_PRECEDENCE",
    "DGP_IDS",
    "DISAGREEMENT_QUANTILES",
    "DISAGREEMENT_THRESHOLDS",
    "EXTREME_THRESHOLD",
    "FINAL_POSITION",
    "FIRST_POSITION",
    "FinalPretruthBinding",
    "IDENTITY_COLUMNS",
    "IDENTITY_COUNT",
    "MODEL_IDS",
    "MODEL_ROW_COUNT",
    "OneShotCustodyVerification",
    "PREDICTION_COLUMNS",
    "QualificationContract",
    "QualificationEvaluatorError",
    "RANKING_RULE",
    "ROWS_PER_TASK",
    "SCORECARD_COLUMNS",
    "SEED_ALIASES",
    "SEED_ALIAS_TO_VALUE",
    "TASK_COUNT",
    "TRUTH_COLUMNS",
    "TRUTH_EVALUATOR_COLUMNS",
    "canonical_json_bytes",
    "canonical_json_line_bytes",
    "identity_semantic_sha256",
    "sha256_bytes",
    "strict_json_object",
    "validate_research_diagnostics",
    "validate_runtime_bindings",
]
