"""Pure-Python scoring core for one injected PE qualification evaluation.

The functions accept already-custodied row iterables.  They do not discover paths, open files,
import prediction code, mutate registries, or create scoring authority.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from operator import mul
from typing import Any, Iterable, Mapping, Sequence

from .contract import (
    C1_ID,
    C2_ID,
    C3_ID,
    C4_ID,
    C5_ID,
    CANDIDATE_IDS,
    CHAMPION_ID,
    DGP_IDS,
    DISAGREEMENT_QUANTILES,
    DISAGREEMENT_THRESHOLDS,
    EXTREME_THRESHOLD,
    FINAL_POSITION,
    FIRST_POSITION,
    IDENTITY_COUNT,
    MODEL_IDS,
    PREDICTION_COLUMNS,
    RANKING_RULE,
    ROWS_PER_TASK,
    SCORECARD_COLUMNS,
    SEED_ALIASES,
    TRUTH_EVALUATOR_COLUMNS,
    FinalPretruthBinding,
    OneShotCustodyVerification,
    QualificationContract,
    QualificationEvaluatorError,
    identity_semantic_sha256,
    validate_research_diagnostics,
    validate_runtime_bindings,
)


Identity = tuple[str, str, int, str, str, str, int, int]

FAMILY_BY_CANDIDATE = {
    C1_ID: "bounded_consensus",
    C2_ID: "observable_state_bounded_consensus",
    C3_ID: "fixed_directional_consensus",
    C4_ID: "hierarchical_observable_fair_value_state",
    C5_ID: "causal_temporal_convolution_private_process",
}


@dataclass(frozen=True)
class DecodedPredictions:
    identities: tuple[Identity, ...]
    expected_log_pe: Mapping[str, tuple[float, ...]]
    common_identity_semantic_sha256: str


@dataclass(frozen=True)
class DecodedTruth:
    true_log_fair_pe: tuple[float, ...]
    eligible: tuple[bool, ...]


@dataclass(frozen=True)
class EvaluationResult:
    pooled_metrics: tuple[dict[str, Any], ...]
    seed_metrics: tuple[dict[str, Any], ...]
    dgp_metrics: tuple[dict[str, Any], ...]
    seed_dgp_metrics: tuple[dict[str, Any], ...]
    dgp_mean_metrics: tuple[dict[str, Any], ...]
    fold_metrics: tuple[dict[str, Any], ...]
    tail_metrics: tuple[dict[str, Any], ...]
    complementarity_metrics: tuple[dict[str, Any], ...]
    decisions: tuple[dict[str, Any], ...]
    diagnostic_ranking: tuple[dict[str, Any], ...]
    formal_survivor_ranking: tuple[dict[str, Any], ...]
    candidate_scorecard: tuple[dict[str, Any], ...]
    terminal_c5_record: Mapping[str, Any]
    bound_diagnostics: Mapping[str, Any]
    geometry: Mapping[str, Any]

    def as_payload(self) -> dict[str, Any]:
        """Return a JSON-safe result payload without changing metric precision."""

        return {
            "pooled_metrics": list(self.pooled_metrics),
            "seed_metrics": list(self.seed_metrics),
            "dgp_metrics": list(self.dgp_metrics),
            "seed_dgp_metrics": list(self.seed_dgp_metrics),
            "dgp_mean_metrics": list(self.dgp_mean_metrics),
            "fold_metrics": list(self.fold_metrics),
            "tail_metrics": list(self.tail_metrics),
            "complementarity_metrics": list(self.complementarity_metrics),
            "decisions": list(self.decisions),
            "diagnostic_ranking": list(self.diagnostic_ranking),
            "formal_survivor_ranking": list(self.formal_survivor_ranking),
            "candidate_scorecard": list(self.candidate_scorecard),
            "terminal_c5_record": dict(self.terminal_c5_record),
            "bound_diagnostics": dict(self.bound_diagnostics),
            "geometry": dict(self.geometry),
        }


def _exact_row_keys(
    row: Mapping[str, object],
    expected: Sequence[str],
    *,
    label: str,
) -> None:
    if not isinstance(row, Mapping) or tuple(row) != tuple(expected):
        raise QualificationEvaluatorError(f"{label} columns/order differ")


def _string(value: object, *, label: str) -> str:
    if type(value) is not str or not value:
        raise QualificationEvaluatorError(f"{label} must be a nonempty string")
    return value


def _integer(value: object, *, label: str) -> int:
    if type(value) is int:
        return value
    if type(value) is str:
        try:
            number = int(value)
        except ValueError as exc:
            raise QualificationEvaluatorError(f"{label} is not an integer") from exc
        if str(number) == value:
            return number
    raise QualificationEvaluatorError(f"{label} is not canonically serialized")


def _float(value: object, *, label: str) -> float:
    if type(value) not in (str, int, float):
        raise QualificationEvaluatorError(f"{label} is not numeric")
    try:
        number = float(value)
    except ValueError as exc:
        raise QualificationEvaluatorError(f"{label} is not numeric") from exc
    if not math.isfinite(number):
        raise QualificationEvaluatorError(f"{label} must be finite")
    return number


def _boolean(value: object, *, label: str) -> bool:
    if type(value) is bool:
        return value
    if value in ("True", "true"):
        return True
    if value in ("False", "false"):
        return False
    raise QualificationEvaluatorError(f"{label} is not a canonical boolean")


def _fold_for_position(position: int) -> tuple[str, int, int]:
    if position < FIRST_POSITION or position > FINAL_POSITION:
        raise QualificationEvaluatorError("session_position escaped 504..1799")
    fold_number = 12 + (position - FIRST_POSITION) // 21
    test_start = FIRST_POSITION + (fold_number - 12) * 21
    return f"fold_{fold_number:03d}", test_start - 1, test_start


def _identity_from_row(row: Mapping[str, object], *, label: str) -> Identity:
    seed_alias = _string(row["seed_alias"], label=f"{label}/seed_alias")
    dgp_id = _string(row["dgp_id"], label=f"{label}/dgp_id")
    position = _integer(row["session_position"], label=f"{label}/session_position")
    date = _string(row["date"], label=f"{label}/date")
    symbol = _string(row["symbol"], label=f"{label}/symbol")
    fold_id = _string(row["fold_id"], label=f"{label}/fold_id")
    train_end = _integer(row["train_end_position"], label=f"{label}/train_end")
    test_start = _integer(row["test_start_position"], label=f"{label}/test_start")
    return (seed_alias, dgp_id, position, date, symbol, fold_id, train_end, test_start)


def _validate_identity_geometry(identity: Identity, identity_ordinal: int) -> None:
    seed_index, remainder = divmod(identity_ordinal, len(DGP_IDS) * ROWS_PER_TASK)
    dgp_index, row_index = divmod(remainder, ROWS_PER_TASK)
    expected_position = FIRST_POSITION + row_index
    expected_fold, expected_train, expected_start = _fold_for_position(expected_position)
    expected = (
        SEED_ALIASES[seed_index],
        DGP_IDS[dgp_index],
        expected_position,
        identity[3],
        "DGP_ISSUER",
        expected_fold,
        expected_train,
        expected_start,
    )
    if identity != expected:
        raise QualificationEvaluatorError(
            f"prediction identity geometry differs at ordinal {identity_ordinal}"
        )


def decode_prediction_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    binding: FinalPretruthBinding,
) -> DecodedPredictions:
    """Consume exactly 324,000 long rows as adjacent five-model identity blocks."""

    iterator = iter(rows)
    identities: list[Identity] = []
    logs: dict[str, list[float]] = {model_id: [] for model_id in MODEL_IDS}
    last_dates: dict[tuple[str, str], str] = {}
    for identity_ordinal in range(IDENTITY_COUNT):
        block_identity: Identity | None = None
        for model_ordinal, model_id in enumerate(MODEL_IDS):
            try:
                row = next(iterator)
            except StopIteration as exc:
                raise QualificationEvaluatorError("prediction artifact ended before 324,000 rows") from exc
            _exact_row_keys(row, PREDICTION_COLUMNS, label="prediction row")
            identity = _identity_from_row(row, label="prediction row")
            if block_identity is None:
                block_identity = identity
                _validate_identity_geometry(identity, identity_ordinal)
            elif identity != block_identity:
                raise QualificationEvaluatorError("identity fields differ inside a five-model block")
            if row["pe_model_id"] != model_id:
                raise QualificationEvaluatorError("five-model block order differs")
            if _integer(row["model_ordinal"], label="model_ordinal") != model_ordinal:
                raise QualificationEvaluatorError("model_ordinal differs")
            if not _boolean(row["prediction_valid"], label="prediction_valid") or not _boolean(
                row["pit_valid"], label="pit_valid"
            ):
                raise QualificationEvaluatorError(
                    "all prediction_valid and pit_valid flags must be true before truth"
                )
            version = _string(row["source_model_version"], label="source_model_version")
            if version != binding.source_model_versions[model_id]:
                raise QualificationEvaluatorError("source_model_version differs from final binding")
            expected_pe = _float(row["expected_pe"], label="expected_pe")
            expected_log = _float(row["expected_log_pe"], label="expected_log_pe")
            if expected_pe <= 0.0 or not math.isclose(
                math.log(expected_pe), expected_log, rel_tol=0.0, abs_tol=1.0e-14
            ):
                raise QualificationEvaluatorError("expected_pe/expected_log_pe identity differs")
            logs[model_id].append(expected_log)
        if block_identity is None:  # pragma: no cover - MODEL_IDS is nonempty
            raise QualificationEvaluatorError("empty prediction model block")
        task_key = (block_identity[0], block_identity[1])
        previous_date = last_dates.get(task_key)
        if previous_date is not None and block_identity[3] <= previous_date:
            raise QualificationEvaluatorError("task dates are duplicate or nonmonotonic")
        last_dates[task_key] = block_identity[3]
        identities.append(block_identity)
    try:
        next(iterator)
    except StopIteration:
        pass
    else:
        raise QualificationEvaluatorError("prediction artifact contains rows after 324,000")
    semantic = identity_semantic_sha256(identities)
    expected_semantic = binding.payload["common_full_identities_semantic_sha256"]
    if semantic != expected_semantic:
        raise QualificationEvaluatorError("common FULL_IDENTITIES semantic SHA-256 differs")
    return DecodedPredictions(
        identities=tuple(identities),
        expected_log_pe={key: tuple(value) for key, value in logs.items()},
        common_identity_semantic_sha256=semantic,
    )


def decode_truth_rows(
    rows: Iterable[Mapping[str, object]],
    *,
    identities: Sequence[Identity],
) -> DecodedTruth:
    """Validate 64,800 already-authenticated logical truth rows in fixed order."""

    iterator = iter(rows)
    truth_log: list[float] = []
    eligible: list[bool] = []
    for ordinal, expected_identity in enumerate(identities):
        try:
            row = next(iterator)
        except StopIteration as exc:
            raise QualificationEvaluatorError("truth projection ended before 64,800 rows") from exc
        _exact_row_keys(row, TRUTH_EVALUATOR_COLUMNS, label="truth evaluator row")
        identity = _identity_from_row(row, label="truth evaluator row")
        if identity != expected_identity:
            raise QualificationEvaluatorError(f"truth identity/order differs at ordinal {ordinal}")
        fair = _float(row["true_fair_pe"], label="true_fair_pe")
        log_fair = _float(row["true_log_fair_pe"], label="true_log_fair_pe")
        if fair <= 0.0 or not math.isclose(
            math.log(fair), log_fair, rel_tol=0.0, abs_tol=2.0e-12
        ):
            raise QualificationEvaluatorError("truth fair/log-fair identity differs")
        for column in (
            "true_economic_eps_contemporaneous",
            "true_pit_eps",
            "true_observed_pe",
        ):
            _float(row[column], label=column)
        truth_log.append(log_fair)
        eligible.append(
            _boolean(row["true_expected_pe_eligible"], label="true_expected_pe_eligible")
        )
    try:
        next(iterator)
    except StopIteration:
        pass
    else:
        raise QualificationEvaluatorError("truth projection contains rows after 64,800")
    return DecodedTruth(true_log_fair_pe=tuple(truth_log), eligible=tuple(eligible))


def type7_quantile(values: Sequence[float], probability: float) -> float:
    """Return the explicit sorted-linear Type-7 quantile frozen by V2."""

    if not values:
        raise QualificationEvaluatorError("quantile group is empty")
    if not 0.0 <= probability <= 1.0:
        raise QualificationEvaluatorError("quantile probability escaped [0,1]")
    ordered = sorted(values)
    location = (len(ordered) - 1) * probability
    lower = math.floor(location)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = location - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def _summary(errors: Sequence[float], indexes: Sequence[int] | None = None) -> dict[str, Any]:
    values = list(errors) if indexes is None else [errors[index] for index in indexes]
    if not values or not all(math.isfinite(value) for value in values):
        raise QualificationEvaluatorError("metric group is empty or nonfinite")
    absolute = [abs(value) for value in values]
    count = len(values)
    extreme_count = sum(value >= EXTREME_THRESHOLD for value in absolute)
    return {
        "rows": count,
        "mae": math.fsum(absolute) / count,
        "rmse": math.sqrt(math.fsum(map(mul, values, values)) / count),
        "mean_signed_error": math.fsum(values) / count,
        "p95_absolute_error": type7_quantile(absolute, 0.95),
        "p99_absolute_error": type7_quantile(absolute, 0.99),
        "max_absolute_error": max(absolute),
        "extreme_error_count": extreme_count,
        "extreme_error_frequency": extreme_count / count,
    }


def _gain(candidate: float, champion: float, *, label: str) -> float:
    if not math.isfinite(candidate) or not math.isfinite(champion) or champion <= 0.0:
        raise QualificationEvaluatorError(f"relative metric denominator is invalid: {label}")
    return (champion - candidate) / champion


def _population_variance(values: Sequence[float], *, label: str) -> float:
    if not values or not all(math.isfinite(value) for value in values):
        raise QualificationEvaluatorError(f"population variance input is invalid: {label}")
    mean = math.fsum(values) / len(values)
    centered = [value - mean for value in values]
    return math.fsum(map(mul, centered, centered)) / len(values)


def _relative_deterioration(candidate: float, champion: float, *, label: str) -> float:
    if not math.isfinite(candidate) or not math.isfinite(champion) or champion <= 0.0:
        raise QualificationEvaluatorError(
            f"relative deterioration denominator is invalid: {label}"
        )
    return (candidate - champion) / champion


def _metric_record(
    candidate_id: str,
    candidate: Mapping[str, Any],
    champion: Mapping[str, Any],
    **identity: object,
) -> dict[str, Any]:
    mae_gain = _gain(float(candidate["mae"]), float(champion["mae"]), label="MAE")
    rmse_gain = _gain(float(candidate["rmse"]), float(champion["rmse"]), label="RMSE")
    return {
        **identity,
        "candidate_id": candidate_id,
        "rows": candidate["rows"],
        **{f"candidate_{key}": value for key, value in candidate.items() if key != "rows"},
        **{f"champion_{key}": value for key, value in champion.items() if key != "rows"},
        "mae_relative_gain_vs_v04": mae_gain,
        "rmse_relative_gain_vs_v04": rmse_gain,
        "mae_relative_harm_vs_v04": max(0.0, -mae_gain),
        "p95_non_worse": float(candidate["p95_absolute_error"])
        <= float(champion["p95_absolute_error"]),
        "extreme_frequency_non_worse": float(candidate["extreme_error_frequency"])
        <= float(champion["extreme_error_frequency"]),
    }


def fixed_order_correlation(left: Sequence[float], right: Sequence[float]) -> dict[str, Any]:
    """Compute V2 Pearson correlation with explicit null/status semantics."""

    if len(left) != len(right):
        raise QualificationEvaluatorError("correlation vector lengths differ")
    if len(left) < 2:
        return {"value": None, "status": "INSUFFICIENT_ROWS"}
    if not all(math.isfinite(value) for value in left) or not all(
        math.isfinite(value) for value in right
    ):
        raise QualificationEvaluatorError("correlation input is nonfinite")
    count = len(left)
    left_mean = math.fsum(left) / count
    right_mean = math.fsum(right) / count
    left_centered = [value - left_mean for value in left]
    right_centered = [value - right_mean for value in right]
    left_ss = math.fsum(map(mul, left_centered, left_centered))
    right_ss = math.fsum(map(mul, right_centered, right_centered))
    if left_ss == 0.0 or right_ss == 0.0:
        return {"value": None, "status": "ZERO_VARIANCE"}
    covariance = math.fsum(map(mul, left_centered, right_centered))
    value = covariance / (math.sqrt(left_ss) * math.sqrt(right_ss))
    return {"value": max(-1.0, min(1.0, value)), "status": "OK"}


def _group_indexes(
    identities: Sequence[Identity],
    selected: Sequence[int],
) -> tuple[
    dict[str, list[int]],
    dict[str, list[int]],
    dict[tuple[str, str], list[int]],
    dict[tuple[str, str, str], list[int]],
]:
    seeds = {seed: [] for seed in SEED_ALIASES}
    dgps = {dgp: [] for dgp in DGP_IDS}
    cells = {(seed, dgp): [] for seed in SEED_ALIASES for dgp in DGP_IDS}
    folds: dict[tuple[str, str, str], list[int]] = {}
    expected_fold_keys: set[tuple[str, str, str]] = set()
    for identity in identities:
        expected_fold_keys.add((identity[0], identity[1], identity[5]))
    for compact_index, source_index in enumerate(selected):
        identity = identities[source_index]
        seeds[identity[0]].append(compact_index)
        dgps[identity[1]].append(compact_index)
        cells[(identity[0], identity[1])].append(compact_index)
        folds.setdefault((identity[0], identity[1], identity[5]), []).append(compact_index)
    if any(not indexes for indexes in seeds.values()):
        raise QualificationEvaluatorError("a seed is empty on the common mask")
    if any(not indexes for indexes in dgps.values()):
        raise QualificationEvaluatorError("a DGP is empty on the common mask")
    if any(not indexes for indexes in cells.values()):
        raise QualificationEvaluatorError("a seed-DGP cell is empty on the common mask")
    if set(folds) != expected_fold_keys or any(not indexes for indexes in folds.values()):
        raise QualificationEvaluatorError("a required fold is empty on the common mask")
    return seeds, dgps, cells, folds


def _summaries_by_group(
    errors: Sequence[float], groups: Mapping[object, Sequence[int]]
) -> dict[object, dict[str, Any]]:
    return {key: _summary(errors, indexes) for key, indexes in groups.items()}


def _systematic_tail(
    candidate_id: str,
    candidate_errors: Sequence[float],
    champion_errors: Sequence[float],
    dgp_groups: Mapping[str, Sequence[int]],
    candidate_pooled: Mapping[str, Any],
    champion_pooled: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_abs = [abs(value) for value in candidate_errors]
    champion_abs = [abs(value) for value in champion_errors]
    candidate_threshold = float(candidate_pooled["p95_absolute_error"])
    champion_threshold = float(champion_pooled["p95_absolute_error"])
    diagnostics: list[dict[str, Any]] = []
    failures = 0
    for dgp_id, indexes in dgp_groups.items():
        candidate_dgp = _summary(candidate_errors, indexes)
        champion_dgp = _summary(champion_errors, indexes)
        candidate_only = sum(
            candidate_abs[index] >= candidate_threshold
            and champion_abs[index] < champion_threshold
            for index in indexes
        )
        champion_only = sum(
            champion_abs[index] >= champion_threshold
            and candidate_abs[index] < candidate_threshold
            for index in indexes
        )
        joint = sum(
            candidate_abs[index] >= candidate_threshold
            and champion_abs[index] >= champion_threshold
            for index in indexes
        )
        failure = (
            float(candidate_dgp["p95_absolute_error"])
            > float(champion_dgp["p95_absolute_error"])
            and float(candidate_dgp["extreme_error_frequency"])
            > float(champion_dgp["extreme_error_frequency"])
            and candidate_only > champion_only
        )
        failures += int(failure)
        diagnostics.append(
            {
                "dgp_id": dgp_id,
                "joint_q95_count": joint,
                "candidate_only_q95_count": candidate_only,
                "champion_only_q95_count": champion_only,
                "candidate_dgp_p95": candidate_dgp["p95_absolute_error"],
                "champion_dgp_p95": champion_dgp["p95_absolute_error"],
                "candidate_dgp_extreme_frequency": candidate_dgp["extreme_error_frequency"],
                "champion_dgp_extreme_frequency": champion_dgp["extreme_error_frequency"],
                "systematic_joint_tail_failure": failure,
            }
        )
    return {
        "candidate_id": candidate_id,
        "rows": candidate_pooled["rows"],
        "candidate_p95_absolute_error": candidate_pooled["p95_absolute_error"],
        "champion_p95_absolute_error": champion_pooled["p95_absolute_error"],
        "candidate_p99_absolute_error": candidate_pooled["p99_absolute_error"],
        "champion_p99_absolute_error": champion_pooled["p99_absolute_error"],
        "candidate_extreme_error_count": candidate_pooled["extreme_error_count"],
        "champion_extreme_error_count": champion_pooled["extreme_error_count"],
        "candidate_extreme_error_frequency": candidate_pooled["extreme_error_frequency"],
        "champion_extreme_error_frequency": champion_pooled["extreme_error_frequency"],
        "pooled_p95_non_worse": float(candidate_pooled["p95_absolute_error"])
        <= float(champion_pooled["p95_absolute_error"]),
        "pooled_p99_non_worse": float(candidate_pooled["p99_absolute_error"])
        <= float(champion_pooled["p99_absolute_error"]),
        "pooled_extreme_frequency_non_worse": float(
            candidate_pooled["extreme_error_frequency"]
        )
        <= float(champion_pooled["extreme_error_frequency"]),
        "systematic_dgp_joint_tail_failure_count": failures,
        "dgp_diagnostics": diagnostics,
        "formal_qualification_gate_component": False,
    }


def _complementarity(
    candidate_id: str,
    candidate_log: Sequence[float],
    champion_log: Sequence[float],
    candidate_errors: Sequence[float],
    champion_errors: Sequence[float],
    candidate_pooled: Mapping[str, Any],
    champion_pooled: Mapping[str, Any],
) -> dict[str, Any]:
    candidate_abs = [abs(value) for value in candidate_errors]
    champion_abs = [abs(value) for value in champion_errors]
    oracle_abs = [
        champion if champion <= candidate else candidate
        for candidate, champion in zip(candidate_abs, champion_abs, strict=True)
    ]
    count = len(oracle_abs)
    oracle_mae = math.fsum(oracle_abs) / count
    oracle_rmse = math.sqrt(math.fsum(map(mul, oracle_abs, oracle_abs)) / count)
    better_mae = min(float(candidate_pooled["mae"]), float(champion_pooled["mae"]))
    if better_mae == 0.0:
        marginal_gain: float | None = None
        oracle_status = "ZERO_BETTER_STANDALONE_MAE"
    else:
        marginal_gain = (better_mae - oracle_mae) / better_mae
        oracle_status = "OK"
    disagreement = [
        abs(candidate - champion)
        for candidate, champion in zip(candidate_log, champion_log, strict=True)
    ]
    signed_corr = fixed_order_correlation(candidate_errors, champion_errors)
    absolute_corr = fixed_order_correlation(candidate_abs, champion_abs)
    prediction_corr = fixed_order_correlation(candidate_log, champion_log)
    frequencies = {
        f"frequency_gt_{int(round(math.expm1(threshold) * 100))}pct": (
            sum(value > threshold for value in disagreement) / count
        )
        for threshold in DISAGREEMENT_THRESHOLDS
    }
    return {
        "candidate_id": candidate_id,
        "rows": count,
        "signed_error_correlation_vs_v04": signed_corr["value"],
        "signed_error_correlation_status": signed_corr["status"],
        "absolute_error_correlation_vs_v04": absolute_corr["value"],
        "absolute_error_correlation_status": absolute_corr["status"],
        "log_prediction_correlation_vs_v04": prediction_corr["value"],
        "log_prediction_correlation_status": prediction_corr["status"],
        "median_absolute_log_prediction_disagreement": type7_quantile(
            disagreement, DISAGREEMENT_QUANTILES[0]
        ),
        "q90_absolute_log_prediction_disagreement": type7_quantile(
            disagreement, DISAGREEMENT_QUANTILES[1]
        ),
        "q95_absolute_log_prediction_disagreement": type7_quantile(
            disagreement, DISAGREEMENT_QUANTILES[2]
        ),
        **frequencies,
        "oracle_pair_mae": oracle_mae,
        "oracle_pair_rmse": oracle_rmse,
        "oracle_marginal_mae_gain_vs_better_standalone": marginal_gain,
        "oracle_marginal_gain_status": oracle_status,
        "oracle_is_achievable_model_or_gate": False,
    }


def _rank_key(row: Mapping[str, Any]) -> tuple[float, int, float, str]:
    return (
        float(row["worst_dgp_mean_harm"]),
        -int(row["dgp_mean_wins"]),
        -float(row["pooled_mae_relative_gain"]),
        str(row["candidate_id"]),
    )


def evaluate_qualification(
    *,
    contract: QualificationContract,
    final_binding: FinalPretruthBinding,
    custody_verification: OneShotCustodyVerification,
    prediction_rows: Iterable[Mapping[str, object]],
    truth_rows: Iterable[Mapping[str, object]],
    research_diagnostics: Sequence[Mapping[str, Any]],
    runtime_bindings: Sequence[Mapping[str, Any]],
) -> EvaluationResult:
    """Evaluate four scoreable candidates and emit the terminal C5 record.

    The caller is responsible for one-shot activation and secure file handles.  Before truth
    opens it must verify that ``prediction_rows`` comes from the exact held artifact pinned by
    ``final_binding`` and that the bound post-prediction audit links that artifact.  The required
    ``custody_verification`` makes this wrapper boundary explicit; this function performs no I/O
    and grants no authority.
    """

    QualificationContract._validate_payload(contract.payload)
    frozen_research = contract.payload["diagnostic_contract"][
        "research_vs_qualification_gap"
    ]["spent_research_bindings"]
    if contract.lock_id != contract.payload["lock_id"] or dict(
        contract.research_baselines
    ) != dict(frozen_research):
        raise QualificationEvaluatorError("qualification contract projection differs")
    final_binding = FinalPretruthBinding.from_mapping(
        final_binding.payload,
        contract=contract,
    )
    if final_binding.payload["qualification_lock_raw_sha256"] != contract.raw_sha256:
        raise QualificationEvaluatorError("final binding targets a different policy lock")
    verified_custody = OneShotCustodyVerification.from_mapping(
        custody_verification.payload,
        contract=contract,
        final_binding=final_binding,
    )
    research = validate_research_diagnostics(research_diagnostics, contract=contract)
    runtimes = validate_runtime_bindings(runtime_bindings)
    decoded = decode_prediction_rows(prediction_rows, binding=final_binding)
    truth = decode_truth_rows(truth_rows, identities=decoded.identities)
    selected = [index for index, eligible in enumerate(truth.eligible) if eligible]
    if not selected:
        raise QualificationEvaluatorError("common mask is empty")
    seed_groups, dgp_groups, cell_groups, fold_groups = _group_indexes(
        decoded.identities, selected
    )
    truth_log = [truth.true_log_fair_pe[index] for index in selected]
    compact_logs = {
        model_id: [decoded.expected_log_pe[model_id][index] for index in selected]
        for model_id in MODEL_IDS
    }
    errors = {
        model_id: [
            prediction - target
            for prediction, target in zip(compact_logs[model_id], truth_log, strict=True)
        ]
        for model_id in MODEL_IDS
    }

    champion_errors = errors[CHAMPION_ID]
    champion_pooled = _summary(champion_errors)
    champion_seed = _summaries_by_group(champion_errors, seed_groups)
    champion_dgp = _summaries_by_group(champion_errors, dgp_groups)
    champion_cell = _summaries_by_group(champion_errors, cell_groups)
    champion_fold = _summaries_by_group(champion_errors, fold_groups)

    pooled_rows: list[dict[str, Any]] = []
    seed_rows: list[dict[str, Any]] = []
    dgp_rows: list[dict[str, Any]] = []
    cell_rows: list[dict[str, Any]] = []
    dgp_mean_rows: list[dict[str, Any]] = []
    fold_rows: list[dict[str, Any]] = []
    tail_rows: list[dict[str, Any]] = []
    complementarity_rows: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    runtime_by_candidate: dict[str, Mapping[str, Any]] = {}
    for binding in runtimes:
        for candidate_id in binding["receipt"]["candidate_ids"]:
            runtime_by_candidate[candidate_id] = binding

    role = contract.payload["role_review_contract"]
    diversity_gate = role["diversity_review_all_conjunctive"]
    specialist_gate = role["specialist_review_all_conjunctive"]
    performance_gate = contract.payload["qualification_performance_screen"]

    for candidate_id in CANDIDATE_IDS:
        candidate_errors = errors[candidate_id]
        candidate_pooled = _summary(candidate_errors)
        pooled = _metric_record(candidate_id, candidate_pooled, champion_pooled)
        pooled_rows.append(pooled)
        candidate_seed = _summaries_by_group(candidate_errors, seed_groups)
        candidate_dgp = _summaries_by_group(candidate_errors, dgp_groups)
        candidate_cell = _summaries_by_group(candidate_errors, cell_groups)
        candidate_fold = _summaries_by_group(candidate_errors, fold_groups)

        candidate_seed_records: list[dict[str, Any]] = []
        for seed_alias in SEED_ALIASES:
            record = _metric_record(
                candidate_id,
                candidate_seed[seed_alias],
                champion_seed[seed_alias],
                seed_alias=seed_alias,
            )
            candidate_seed_records.append(record)
            seed_rows.append(record)
        candidate_dgp_records: list[dict[str, Any]] = []
        for dgp_id in DGP_IDS:
            record = _metric_record(
                candidate_id,
                candidate_dgp[dgp_id],
                champion_dgp[dgp_id],
                dgp_id=dgp_id,
            )
            candidate_dgp_records.append(record)
            dgp_rows.append(record)
        candidate_cell_records: list[dict[str, Any]] = []
        for seed_alias in SEED_ALIASES:
            for dgp_id in DGP_IDS:
                key = (seed_alias, dgp_id)
                record = _metric_record(
                    candidate_id,
                    candidate_cell[key],
                    champion_cell[key],
                    seed_alias=seed_alias,
                    dgp_id=dgp_id,
                )
                candidate_cell_records.append(record)
                cell_rows.append(record)
        candidate_fold_records: list[dict[str, Any]] = []
        for key in fold_groups:
            record = _metric_record(
                candidate_id,
                candidate_fold[key],
                champion_fold[key],
                seed_alias=key[0],
                dgp_id=key[1],
                fold_id=key[2],
            )
            candidate_fold_records.append(record)
            fold_rows.append(record)

        candidate_dgp_means: list[dict[str, Any]] = []
        for dgp_id in DGP_IDS:
            gains = [
                float(record["mae_relative_gain_vs_v04"])
                for record in candidate_cell_records
                if record["dgp_id"] == dgp_id
            ]
            if len(gains) != len(SEED_ALIASES):
                raise QualificationEvaluatorError("DGP mean lacks five seed-DGP gains")
            mean_gain = math.fsum(gains) / len(gains)
            record = {
                "candidate_id": candidate_id,
                "dgp_id": dgp_id,
                "seed_dgp_count": len(gains),
                "dgp_mean_gain": mean_gain,
                "dgp_mean_harm": max(0.0, -mean_gain),
                "dgp_mean_win": mean_gain > 0.0,
                "specialist_slice": mean_gain >= 0.02,
            }
            candidate_dgp_means.append(record)
            dgp_mean_rows.append(record)

        seed_gains = [
            float(row["mae_relative_gain_vs_v04"]) for row in candidate_seed_records
        ]
        direct_dgp_gains = [
            float(row["mae_relative_gain_vs_v04"]) for row in candidate_dgp_records
        ]
        cell_gains = [float(row["mae_relative_gain_vs_v04"]) for row in candidate_cell_records]
        dgp_mean_gains = [float(row["dgp_mean_gain"]) for row in candidate_dgp_means]
        fold_gains = [
            float(row["mae_relative_gain_vs_v04"]) for row in candidate_fold_records
        ]
        seed_wins = sum(gain > 0.0 for gain in seed_gains)
        direct_dgp_wins = sum(gain > 0.0 for gain in direct_dgp_gains)
        seed_dgp_wins = sum(gain > 0.0 for gain in cell_gains)
        dgp_mean_wins = sum(gain > 0.0 for gain in dgp_mean_gains)
        worst_seed_harm = max(0.0, -min(seed_gains))
        worst_direct_dgp_harm = max(0.0, -min(direct_dgp_gains))
        worst_cell_harm = max(0.0, -min(cell_gains))
        worst_dgp_mean_harm = max(0.0, -min(dgp_mean_gains))
        seed_gain_variance = _population_variance(seed_gains, label="seed MAE gains")
        dgp_mean_gain_variance = _population_variance(
            dgp_mean_gains, label="DGP mean gains"
        )
        fold_gain_variance = _population_variance(fold_gains, label="fold MAE gains")
        specialist_dgp_count = sum(
            bool(row["specialist_slice"]) for row in candidate_dgp_means
        )

        tail = _systematic_tail(
            candidate_id,
            candidate_errors,
            champion_errors,
            dgp_groups,
            candidate_pooled,
            champion_pooled,
        )
        tail_rows.append(tail)
        p95_relative_deterioration = _relative_deterioration(
            float(candidate_pooled["p95_absolute_error"]),
            float(champion_pooled["p95_absolute_error"]),
            label="pooled p95 absolute error",
        )
        extreme_frequency_deterioration = float(
            candidate_pooled["extreme_error_frequency"]
        ) - float(champion_pooled["extreme_error_frequency"])
        complementarity = _complementarity(
            candidate_id,
            compact_logs[candidate_id],
            compact_logs[CHAMPION_ID],
            candidate_errors,
            champion_errors,
            candidate_pooled,
            champion_pooled,
        )
        complementarity_rows.append(complementarity)

        gate_checks = {
            "gate_pooled_mae": float(pooled["mae_relative_gain_vs_v04"])
            >= float(performance_gate["pooled_mae_relative_gain_min"]),
            "gate_pooled_rmse": float(pooled["rmse_relative_gain_vs_v04"])
            >= float(performance_gate["pooled_rmse_relative_gain_min"]),
            "gate_seed_dgp_wins": seed_dgp_wins
            >= int(performance_gate["seed_dgp_wins_min"]),
            "gate_dgp_mean_wins": dgp_mean_wins
            >= int(performance_gate["dgp_mean_wins_min"]),
            "gate_worst_dgp_mean_harm": worst_dgp_mean_harm
            <= float(performance_gate["worst_dgp_mean_harm_max"]),
            "gate_worst_seed_dgp_harm": worst_cell_harm
            <= float(performance_gate["worst_seed_dgp_harm_max"]),
            "gate_pooled_p95": bool(tail["pooled_p95_non_worse"]),
            "gate_extreme_frequency": bool(tail["pooled_extreme_frequency_non_worse"]),
        }
        gate_pass = all(gate_checks.values())

        correlations = (
            complementarity["signed_error_correlation_vs_v04"],
            complementarity["absolute_error_correlation_vs_v04"],
        )
        diversity_checks = {
            "diversity_positive_pooled_mae_gain": float(pooled["mae_relative_gain_vs_v04"])
            > float(diversity_gate["pooled_mae_relative_gain_strict_min"]),
            "diversity_p95_non_worse": bool(tail["pooled_p95_non_worse"]),
            "diversity_extreme_non_worse": bool(tail["pooled_extreme_frequency_non_worse"]),
            "diversity_joint_tail": int(tail["systematic_dgp_joint_tail_failure_count"])
            <= int(diversity_gate["systematic_dgp_joint_tail_failure_count_max"]),
            "diversity_oracle_gain": complementarity[
                "oracle_marginal_mae_gain_vs_better_standalone"
            ]
            is not None
            and float(complementarity["oracle_marginal_mae_gain_vs_better_standalone"])
            >= float(diversity_gate["marginal_oracle_mae_gain_vs_better_standalone_min"]),
            "diversity_error_correlation": any(
                value is not None
                and float(value)
                <= float(
                    diversity_gate[
                        "signed_or_absolute_error_correlation_vs_v04_max_at_least_one"
                    ]
                )
                for value in correlations
            ),
        }
        specialist_checks = {
            "specialist_positive_pooled_mae_gain": float(pooled["mae_relative_gain_vs_v04"])
            > float(specialist_gate["pooled_mae_relative_gain_strict_min"]),
            "specialist_p95_non_worse": bool(tail["pooled_p95_non_worse"]),
            "specialist_extreme_non_worse": bool(tail["pooled_extreme_frequency_non_worse"]),
            "specialist_seed_dgp_wins": seed_dgp_wins
            >= int(specialist_gate["seed_dgp_wins_min"]),
            "specialist_dgp_count": specialist_dgp_count
            >= int(specialist_gate["specialist_dgp_count_min"]),
            "specialist_joint_tail": int(tail["systematic_dgp_joint_tail_failure_count"])
            <= int(specialist_gate["systematic_dgp_joint_tail_failure_count_max"]),
            "specialist_worst_dgp": worst_dgp_mean_harm
            <= float(specialist_gate["worst_dgp_mean_harm_max"]),
            "specialist_worst_cell": worst_cell_harm
            <= float(specialist_gate["worst_seed_dgp_harm_max"]),
        }
        specialist_pass = not gate_pass and all(specialist_checks.values())
        diversity_pass = (
            not gate_pass and not specialist_pass and all(diversity_checks.values())
        )
        pooled_mae_gain = float(pooled["mae_relative_gain_vs_v04"])
        if gate_pass:
            classification = "CERTIFIED_SURVIVOR"
        elif specialist_pass:
            classification = "PORTFOLIO_SPECIALIST_CANDIDATE"
        elif diversity_pass:
            classification = "DIVERSITY_CANDIDATE"
        elif pooled_mae_gain <= 0.0:
            classification = "REJECTED"
        else:
            classification = "RESEARCH_ONLY"

        baseline_gain = float(research[candidate_id]["pooled_mae_relative_gain"])
        decision = {
            "candidate_id": candidate_id,
            "pooled_mae_relative_gain": pooled_mae_gain,
            "pooled_rmse_relative_gain": pooled["rmse_relative_gain_vs_v04"],
            "seed_wins": seed_wins,
            "seed_total": len(seed_gains),
            "direct_dgp_wins": direct_dgp_wins,
            "direct_dgp_total": len(direct_dgp_gains),
            "seed_dgp_wins": seed_dgp_wins,
            "seed_dgp_total": len(cell_gains),
            "dgp_mean_wins": dgp_mean_wins,
            "dgp_total": len(dgp_mean_gains),
            "worst_seed_harm": worst_seed_harm,
            "worst_direct_dgp_harm": worst_direct_dgp_harm,
            "worst_dgp_mean_harm": worst_dgp_mean_harm,
            "worst_seed_dgp_harm": worst_cell_harm,
            "seed_mae_gain_population_variance": seed_gain_variance,
            "dgp_mean_gain_population_variance": dgp_mean_gain_variance,
            "fold_mae_gain_population_variance": fold_gain_variance,
            "p95_relative_deterioration": p95_relative_deterioration,
            "extreme_frequency_deterioration": extreme_frequency_deterioration,
            "parameter_sensitivity": None,
            "parameter_sensitivity_status": "NOT_REESTIMATED_ON_FRESH",
            "prediction_instability": None,
            "prediction_instability_status": "NOT_REMEASURED_ON_FRESH",
            "pretruth_source_recomputation_audit_raw_sha256": final_binding.payload[
                "post_prediction_audit_raw_sha256"
            ],
            "pretruth_source_recomputation_audit_semantic_sha256": final_binding.payload[
                "post_prediction_audit_semantic_sha256"
            ],
            "specialist_dgp_count": specialist_dgp_count,
            "systematic_dgp_joint_tail_failure_count": tail[
                "systematic_dgp_joint_tail_failure_count"
            ],
            "research_pooled_mae_relative_gain": baseline_gain,
            "research_vs_qualification_gap": pooled_mae_gain - baseline_gain,
            **gate_checks,
            "all_eight_performance_gates_pass": gate_pass,
            **specialist_checks,
            "specialist_review_pass": specialist_pass,
            **diversity_checks,
            "diversity_review_pass": diversity_pass,
            "classification": classification,
            "performance_pass": gate_pass,
            "role_review_is_performance_pass": False,
            "portfolio_admission": False,
            "runtime_receipt_raw_sha256": runtime_by_candidate[candidate_id]["raw_sha256"],
            "runtime_receipt_file_id": runtime_by_candidate[candidate_id]["file_id"],
            "runtime_attribution": (
                "SHARED_NOT_SEPARATELY_ATTRIBUTABLE"
                if candidate_id in (C1_ID, C2_ID, C3_ID)
                else "ISOLATED"
            ),
        }
        decisions.append(decision)

    ranked = sorted(decisions, key=_rank_key)
    diagnostic_ranking = tuple(
        {
            "diagnostic_rank": rank,
            "candidate_id": row["candidate_id"],
            "classification": row["classification"],
            "gate_pass": row["all_eight_performance_gates_pass"],
            "worst_dgp_mean_harm": row["worst_dgp_mean_harm"],
            "dgp_mean_wins": row["dgp_mean_wins"],
            "pooled_mae_relative_gain": row["pooled_mae_relative_gain"],
            "ranking_rule": list(RANKING_RULE),
            "diagnostic_only": True,
        }
        for rank, row in enumerate(ranked, start=1)
    )
    survivors = [row for row in ranked if row["classification"] == "CERTIFIED_SURVIVOR"]
    formal_ranking = tuple(
        {
            "formal_survivor_rank": rank,
            "candidate_id": row["candidate_id"],
            "worst_dgp_mean_harm": row["worst_dgp_mean_harm"],
            "dgp_mean_wins": row["dgp_mean_wins"],
            "pooled_mae_relative_gain": row["pooled_mae_relative_gain"],
            "ranking_rule": list(RANKING_RULE),
            "rank_universe": "CERTIFIED_SURVIVOR_ONLY",
        }
        for rank, row in enumerate(survivors, start=1)
    )

    decision_by_candidate = {row["candidate_id"]: row for row in decisions}
    pooled_by_candidate = {row["candidate_id"]: row for row in pooled_rows}
    tail_by_candidate = {row["candidate_id"]: row for row in tail_rows}
    complementarity_by_candidate = {
        row["candidate_id"]: row for row in complementarity_rows
    }
    scoreable_scorecard: list[dict[str, Any]] = []
    for index, candidate_id in enumerate(CANDIDATE_IDS, start=1):
        decision = decision_by_candidate[candidate_id]
        pooled = pooled_by_candidate[candidate_id]
        tail = tail_by_candidate[candidate_id]
        complementarity = complementarity_by_candidate[candidate_id]
        certified = bool(decision["all_eight_performance_gates_pass"])
        scoreable_scorecard.append(
            {
                "line_id": f"PE-C{index}",
                "candidate_id": candidate_id,
                "family": FAMILY_BY_CANDIDATE[candidate_id],
                "version": final_binding.source_model_versions[candidate_id],
                "research_readiness": "FROZEN_SPENT_RESEARCH_BINDING",
                "fresh_qualification_status": "SCORED_EXACT_QUALIFICATION",
                "mae": pooled["candidate_mae"],
                "rmse": pooled["candidate_rmse"],
                "gain_vs_v04_mae": pooled["mae_relative_gain_vs_v04"],
                "gain_vs_v04_rmse": pooled["rmse_relative_gain_vs_v04"],
                "seed_wins": decision["seed_wins"],
                "seed_total": decision["seed_total"],
                "dgp_wins": decision["dgp_mean_wins"],
                "dgp_total": decision["dgp_total"],
                "direct_dgp_wins": decision["direct_dgp_wins"],
                "worst_seed_harm": decision["worst_seed_harm"],
                "worst_dgp_harm": decision["worst_dgp_mean_harm"],
                "worst_seed_dgp_harm": decision["worst_seed_dgp_harm"],
                "p95": tail["candidate_p95_absolute_error"],
                "p99": tail["candidate_p99_absolute_error"],
                "extreme_count": tail["candidate_extreme_error_count"],
                "systematic_joint_tail_failures": tail[
                    "systematic_dgp_joint_tail_failure_count"
                ],
                "error_corr_v04": complementarity[
                    "signed_error_correlation_vs_v04"
                ],
                "abs_error_corr_v04": complementarity[
                    "absolute_error_correlation_vs_v04"
                ],
                "prediction_corr_v04": complementarity[
                    "log_prediction_correlation_vs_v04"
                ],
                "oracle_pair_mae": complementarity["oracle_pair_mae"],
                "oracle_pair_rmse": complementarity["oracle_pair_rmse"],
                "oracle_marginal_mae_gain": complementarity[
                    "oracle_marginal_mae_gain_vs_better_standalone"
                ],
                "deployable": False,
                "pit_safe": True,
                "causal_safe": True,
                "portfolio_role": decision["classification"],
                "certification_status": (
                    "CERTIFIED_SURVIVOR"
                    if certified
                    else "NOT_CERTIFIED_PERFORMANCE_SCREEN"
                ),
            }
        )

    terminal = contract.payload["c5_terminal_resolution"]
    c5_scorecard_record = {
        "line_id": "PE-C5",
        "candidate_id": C5_ID,
        "family": FAMILY_BY_CANDIDATE[C5_ID],
        "version": "V8_TERMINAL_CUSTODY_NO_GO",
        "research_readiness": "RESEARCH_ONLY_SATURATED",
        "fresh_qualification_status": "NOT_RUN_TERMINAL_CUSTODY_NO_GO",
        "mae": None,
        "rmse": None,
        "gain_vs_v04_mae": None,
        "gain_vs_v04_rmse": None,
        "seed_wins": None,
        "seed_total": None,
        "dgp_wins": None,
        "dgp_total": None,
        "direct_dgp_wins": None,
        "worst_seed_harm": None,
        "worst_dgp_harm": None,
        "worst_seed_dgp_harm": None,
        "p95": None,
        "p99": None,
        "extreme_count": None,
        "systematic_joint_tail_failures": None,
        "error_corr_v04": None,
        "abs_error_corr_v04": None,
        "prediction_corr_v04": None,
        "oracle_pair_mae": None,
        "oracle_pair_rmse": None,
        "oracle_marginal_mae_gain": None,
        "deployable": False,
        "pit_safe": None,
        "causal_safe": None,
        "portfolio_role": "RESEARCH_ONLY",
        "certification_status": "NOT_RUN_TERMINAL_CUSTODY_NO_GO",
    }
    if tuple(c5_scorecard_record) != SCORECARD_COLUMNS or any(
        tuple(row) != SCORECARD_COLUMNS for row in scoreable_scorecard
    ):
        raise QualificationEvaluatorError("scorecard columns/order differ from V2")
    scorecard = (*scoreable_scorecard, c5_scorecard_record)
    c5_record = {
        **c5_scorecard_record,
        "scoreable": False,
        "classification": "RESEARCH_ONLY",
        "current_portfolio_wave_rejected": True,
        "performance_claim_allowed": False,
        "retry_allowed": False,
        "fresh_surface_consumed": False,
        "heldout_surface_consumed": False,
        "terminal_forensic_audit_raw_sha256": terminal[
            "terminal_forensic_audit_raw_sha256"
        ],
        "terminal_forensic_checksums_raw_sha256": terminal[
            "terminal_forensic_checksums_raw_sha256"
        ],
    }

    return EvaluationResult(
        pooled_metrics=tuple(pooled_rows),
        seed_metrics=tuple(seed_rows),
        dgp_metrics=tuple(dgp_rows),
        seed_dgp_metrics=tuple(cell_rows),
        dgp_mean_metrics=tuple(dgp_mean_rows),
        fold_metrics=tuple(fold_rows),
        tail_metrics=tuple(tail_rows),
        complementarity_metrics=tuple(complementarity_rows),
        decisions=tuple(decisions),
        diagnostic_ranking=diagnostic_ranking,
        formal_survivor_ranking=formal_ranking,
        candidate_scorecard=scorecard,
        terminal_c5_record=c5_record,
        bound_diagnostics={
            "qualification_lock_raw_sha256": contract.raw_sha256,
            "final_pretruth_binding": dict(final_binding.payload),
            "one_shot_custody_verification": dict(verified_custody.payload),
            "research_diagnostics": [research[candidate_id] for candidate_id in CANDIDATE_IDS],
            "runtime_bindings": list(runtimes),
            "diagnostics_are_pretruth_bound_inputs": True,
            "runtime_measured_by_evaluator": False,
            "oracle_is_achievable_model_or_gate": False,
        },
        geometry={
            "prediction_long_rows": IDENTITY_COUNT * len(MODEL_IDS),
            "identity_rows": IDENTITY_COUNT,
            "common_mask_rows": len(selected),
            "seed_count": len(seed_groups),
            "dgp_count": len(dgp_groups),
            "seed_dgp_cells": len(cell_groups),
            "fold_blocks": len(fold_groups),
            "candidate_count": len(CANDIDATE_IDS),
            "common_full_identities_semantic_sha256": decoded.common_identity_semantic_sha256,
            "model_specific_row_drops": 0,
            "sort_pivot_imputation_or_partial_join": False,
        },
    )


__all__ = [
    "DecodedPredictions",
    "DecodedTruth",
    "EvaluationResult",
    "decode_prediction_rows",
    "decode_truth_rows",
    "evaluate_qualification",
    "fixed_order_correlation",
    "type7_quantile",
]
