"""Injected-input PE-C4 service with an exact live full-affinity numeric gate."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import math
from typing import Any, Callable, Mapping, Sequence

import numpy as np
import pandas as pd

from research.model_zoo.hierarchical_observable_fair_value_state_v7.dgp_r4 import (
    R4_CANONICAL_COLUMNS,
)
from research.model_zoo.hofs_research_adapter_v1.contracts import (
    NONINFORMATIVE_GROUP_LABEL,
    V7_CONTRACT_SHA256,
    V7_FIT_CONFIG_SHA256,
)
from research.model_zoo.hofs_research_adapter_v1.inputs import (
    verify_numeric_source_closure,
)

from .contracts import (
    ACTUAL_COMMON_PATH_BINDING_STATUS,
    CANONICAL_COLUMN_COUNT,
    CANONICAL_COLUMNS,
    CANONICAL_HEADER_SHA256,
    DGP_IDS,
    FOLDS_PER_TASK,
    HOFS_TASK_SURFACE_COLUMNS,
    IDENTITY_COLUMNS,
    OUTER_WORKERS,
    PREDICTION_ROWS_PER_TASK,
    PRODUCTION_NUMERIC_AUTHORITY_STATUS,
    R4_NUMERIC_COLUMN_COUNT,
    SCORE_END_EXCLUSIVE,
    SEED_ALIASES,
    SOURCE_MODEL_VERSION_BINDING_STATUS,
    SOURCE_ROWS_PER_TASK,
    SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256,
    SPENT_RESEARCH_ONLY_DGP_ID,
    SPENT_RESEARCH_ONLY_SCHEMA_VERSION,
    SPENT_RESEARCH_ONLY_SEED,
    SPENT_RESEARCH_ONLY_SEED_ALIAS,
    SPENT_RESEARCH_ONLY_STATUS,
    SYMBOL,
    TASK_COUNT,
    UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE,
    ExternalTaskBinding,
    HofsV12QualificationServiceError,
    QualificationFoldSpec,
    build_qualification_fold_plan,
)
from .runtime import assert_actual_numeric_launch_allowed


@dataclass(frozen=True)
class InputValidationReceipt:
    """Hash and identity receipt for one injected, path-free canonical task."""

    task_ordinal: int
    seed_alias: str
    dgp_id: str
    source_kind: str
    canonical_raw_sha256: str
    raw_bytes_reverified: bool
    canonical_semantic_sha256: str
    canonical_header_sha256: str
    canonical_rows: int
    canonical_columns: int
    numeric_columns: int
    upstream_score_named_column_excluded: bool
    external_manifest_file_id_held_by_wrapper: bool
    actual_common_path_binding_status: str
    qualification_access_count: int
    fresh_access_count: int
    truth_access_count: int
    heldout_access_count: int
    score_access_count: int
    status: str = "PASS_TRUTH_FREE_INJECTED_CANONICAL_PREFLIGHT"


@dataclass(frozen=True)
class _SpentResearchOnlyBinding:
    """Unforgeable-by-parameter fixed identity for the one spent-public smoke task."""

    canonical_semantic_sha256: str
    canonical_raw_sha256: str
    schema_version: str = SPENT_RESEARCH_ONLY_SCHEMA_VERSION
    status: str = SPENT_RESEARCH_ONLY_STATUS
    task_ordinal: int = 0
    spent_seed: int = SPENT_RESEARCH_ONLY_SEED
    seed_alias: str = SPENT_RESEARCH_ONLY_SEED_ALIAS
    dgp_id: str = SPENT_RESEARCH_ONLY_DGP_ID
    qualification_access_count: int = 0
    fresh_access_count: int = 0
    truth_access_count: int = 0
    heldout_access_count: int = 0
    score_access_count: int = 0
    actual_common_path_binding_status: str = (
        "NOT_APPLICABLE_SPENT_RESEARCH_ONLY_FIXED_INPUT"
    )

    def __post_init__(self) -> None:
        if (
            self.schema_version != SPENT_RESEARCH_ONLY_SCHEMA_VERSION
            or self.status != SPENT_RESEARCH_ONLY_STATUS
            or self.task_ordinal != 0
            or self.spent_seed != SPENT_RESEARCH_ONLY_SEED
            or self.seed_alias != SPENT_RESEARCH_ONLY_SEED_ALIAS
            or self.dgp_id != SPENT_RESEARCH_ONLY_DGP_ID
            or self.canonical_raw_sha256 != SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256
            or type(self.canonical_semantic_sha256) is not str
            or len(self.canonical_semantic_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.canonical_semantic_sha256
            )
            or any(
                type(value) is not int or value != 0
                for value in (
                    self.qualification_access_count,
                    self.fresh_access_count,
                    self.truth_access_count,
                    self.heldout_access_count,
                    self.score_access_count,
                )
            )
            or self.actual_common_path_binding_status
            != "NOT_APPLICABLE_SPENT_RESEARCH_ONLY_FIXED_INPUT"
        ):
            raise HofsV12QualificationServiceError(
                "spent-research-only fixed identity or zero-access boundary drifted"
            )


@dataclass(frozen=True)
class ValidatedTaskInput:
    """Canonical frame plus custody identity; never pass this object to the estimator."""

    canonical: pd.DataFrame
    canonical_dates: tuple[str, ...]
    binding: ExternalTaskBinding | _SpentResearchOnlyBinding
    receipt: InputValidationReceipt


@dataclass(frozen=True)
class V7DecisionBlockResult:
    """Minimal audited V7 values and custody fields needed by the 11-column surface."""

    fold_ordinal: int
    source_row_positions: tuple[int, ...]
    entity_ids: tuple[str, ...]
    decision_dates: tuple[str, ...]
    expected_pe: tuple[float, ...]
    pe_p10: tuple[float, ...]
    pe_p90: tuple[float, ...]
    log_scale: tuple[float, ...]
    tail_guard_weight: tuple[float, ...]
    fit_prefix_end_exclusive: int
    within_block_parameter_update_count: int
    parameter_sha256: str
    fit_receipt_sha256: str
    decision_block_ordered_membership_sha256: str
    decision_block_set_membership_sha256: str
    decision_source_positions_sha256: str
    output_manifest_sha256: str

    def __post_init__(self) -> None:
        plan = build_qualification_fold_plan()
        if type(self.fold_ordinal) is not int or not 0 <= self.fold_ordinal < len(plan):
            raise HofsV12QualificationServiceError("V7 block fold ordinal drifted")
        spec = plan[self.fold_ordinal]
        expected_positions = tuple(
            range(spec.decision_block_start_inclusive, spec.decision_block_end_exclusive)
        )
        if (
            self.source_row_positions != expected_positions
            or self.fit_prefix_end_exclusive != spec.fit_prefix_end_exclusive
            or self.within_block_parameter_update_count != 0
        ):
            raise HofsV12QualificationServiceError("V7 block strict-prefix custody drifted")
        sequences: tuple[Sequence[object], ...] = (
            self.entity_ids,
            self.decision_dates,
            self.expected_pe,
            self.pe_p10,
            self.pe_p90,
            self.log_scale,
            self.tail_guard_weight,
        )
        if any(len(values) != spec.decision_row_count for values in sequences):
            raise HofsV12QualificationServiceError("V7 block row geometry drifted")
        if any(entity != SYMBOL for entity in self.entity_ids):
            raise HofsV12QualificationServiceError("V7 block entity identity drifted")
        if any(type(value) is not str or not value for value in self.decision_dates):
            raise HofsV12QualificationServiceError("V7 block date identity drifted")
        for value in self.expected_pe:
            if type(value) is not float or not math.isfinite(value) or value <= 0.0:
                raise HofsV12QualificationServiceError("V7 expected P/E is invalid")
        if any(
            type(lower) is not float
            or type(upper) is not float
            or not math.isfinite(lower)
            or not math.isfinite(upper)
            or lower <= 0.0
            or upper <= 0.0
            or lower > expected
            or expected > upper
            for lower, expected, upper in zip(
                self.pe_p10, self.expected_pe, self.pe_p90, strict=True
            )
        ):
            raise HofsV12QualificationServiceError("V7 interval values are invalid")
        for value in self.log_scale:
            if type(value) is not float or not math.isfinite(value):
                raise HofsV12QualificationServiceError("V7 log scale is invalid")
        for value in self.tail_guard_weight:
            if type(value) is not float or not math.isfinite(value) or not 0.0 <= value <= 1.0:
                raise HofsV12QualificationServiceError("V7 tail guard is outside [0,1]")
        for label, value in (
            ("V7 parameter SHA-256", self.parameter_sha256),
            ("V7 fit receipt SHA-256", self.fit_receipt_sha256),
            (
                "V7 ordered membership SHA-256",
                self.decision_block_ordered_membership_sha256,
            ),
            ("V7 set membership SHA-256", self.decision_block_set_membership_sha256),
            ("V7 source positions SHA-256", self.decision_source_positions_sha256),
            ("V7 output manifest SHA-256", self.output_manifest_sha256),
        ):
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise HofsV12QualificationServiceError(f"{label} is invalid")


@dataclass(frozen=True)
class ComputedTaskArtifact:
    """One complete task surface plus the exact numeric/resource audit material."""

    surface: pd.DataFrame
    blocks: tuple[V7DecisionBlockResult, ...]
    input_receipt: InputValidationReceipt
    resource_envelope: dict[str, Any]


NumericBackend = Callable[
    [pd.DataFrame, tuple[QualificationFoldSpec, ...]],
    tuple[V7DecisionBlockResult, ...],
]

_AUDITED_NUMERIC_CAPABILITY = object()


def _canonical_header_sha256(columns: Sequence[str]) -> str:
    raw = json.dumps(list(columns), separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _parse_exact_canonical_csv(raw: bytes) -> pd.DataFrame:
    """Parse bytes with the exact pandas CSV path used by frozen H-OFS r2."""

    try:
        # The frozen adapter used plain ``pd.read_csv``. The round-trip option
        # changes input float bits and therefore cannot establish r2 parity.
        frame = pd.read_csv(io.BytesIO(raw))
    except (UnicodeDecodeError, pd.errors.EmptyDataError, pd.errors.ParserError, ValueError) as exc:
        raise HofsV12QualificationServiceError("injected canonical bytes cannot be parsed") from exc
    if frame.columns.has_duplicates or tuple(map(str, frame.columns)) != CANONICAL_COLUMNS:
        raise HofsV12QualificationServiceError(
            "injected canonical bytes are not exact sealed canonical150"
        )
    return frame


def _logical_frame_sha256(frame: pd.DataFrame) -> str:
    rendered = frame.to_csv(
        index=False,
        lineterminator="\n",
        float_format="%.17g",
        na_rep="",
    ).encode("utf-8")
    return hashlib.sha256(rendered).hexdigest()


def _normalize_binding(
    value: ExternalTaskBinding | Mapping[str, object],
) -> ExternalTaskBinding:
    if type(value) is ExternalTaskBinding:
        return value
    return ExternalTaskBinding.from_mapping(value)


def _canonical_dates(frame: pd.DataFrame) -> tuple[str, ...]:
    if "date" not in frame.columns:
        raise HofsV12QualificationServiceError("canonical date column is missing")
    raw = frame["date"].astype(str)
    parsed = pd.to_datetime(raw, format="%Y-%m-%d", errors="coerce")
    if (
        parsed.isna().any()
        or parsed.duplicated().any()
        or not parsed.is_monotonic_increasing
        or not np.array_equal(raw.to_numpy(dtype=object), parsed.dt.strftime("%Y-%m-%d"))
    ):
        raise HofsV12QualificationServiceError(
            "canonical dates must be exact unique increasing YYYY-MM-DD strings"
        )
    return tuple(raw)


def _validate_exact_canonical_frame(frame: pd.DataFrame) -> tuple[str, ...]:
    if type(frame) is not pd.DataFrame or frame.columns.has_duplicates:
        raise HofsV12QualificationServiceError("canonical input must be an exact DataFrame")
    if not frame.index.equals(pd.RangeIndex(SOURCE_ROWS_PER_TASK)):
        raise HofsV12QualificationServiceError("canonical input index or row count drifted")
    header = CANONICAL_COLUMNS
    if (
        len(header) != CANONICAL_COLUMN_COUNT
        or tuple(map(str, frame.columns)) != header
        or _canonical_header_sha256(header) != CANONICAL_HEADER_SHA256
    ):
        raise HofsV12QualificationServiceError("canonical input is not exact sealed canonical150")
    if (
        UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE not in header
        or len(R4_CANONICAL_COLUMNS) != R4_NUMERIC_COLUMN_COUNT
        or not set(R4_CANONICAL_COLUMNS).issubset(header)
        or UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE in R4_CANONICAL_COLUMNS
    ):
        raise HofsV12QualificationServiceError("canonical-to-V7 numeric allowlist drifted")
    if (
        frame["symbol"].isna().any()
        or not frame["symbol"].map(lambda value: type(value) is str and value == SYMBOL).all()
    ):
        raise HofsV12QualificationServiceError("canonical symbol must be constant DGP_ISSUER")
    return _canonical_dates(frame)


def validate_injected_task(
    canonical_input: bytes | pd.DataFrame,
    *,
    external_binding: ExternalTaskBinding | Mapping[str, object],
) -> ValidatedTaskInput:
    """Validate injected bytes/DataFrame and its external hash/FileId identity binding."""

    binding = _normalize_binding(external_binding)
    raw_reverified = False
    if type(canonical_input) is bytes:
        if not canonical_input:
            raise HofsV12QualificationServiceError("injected canonical bytes are empty")
        raw_sha256 = hashlib.sha256(canonical_input).hexdigest()
        if raw_sha256 != binding.canonical_raw_sha256:
            raise HofsV12QualificationServiceError("injected canonical raw hash drifted")
        try:
            frame = _parse_exact_canonical_csv(canonical_input)
        except HofsV12QualificationServiceError as exc:
            raise HofsV12QualificationServiceError(
                "injected canonical bytes failed the sealed parser"
            ) from exc
        raw_reverified = True
        source_kind = "INJECTED_CANONICAL_BYTES"
    elif type(canonical_input) is pd.DataFrame:
        frame = canonical_input.copy(deep=True)
        raw_sha256 = binding.canonical_raw_sha256
        source_kind = "INJECTED_DATAFRAME_EXTERNAL_RAW_BINDING_ONLY"
    else:
        raise HofsV12QualificationServiceError(
            "canonical input must be exact bytes or pandas.DataFrame"
        )
    dates = _validate_exact_canonical_frame(frame)
    try:
        semantic = _logical_frame_sha256(frame)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HofsV12QualificationServiceError("canonical semantic hash failed") from exc
    if semantic != binding.canonical_semantic_sha256:
        raise HofsV12QualificationServiceError("canonical semantic hash drifted")
    receipt = InputValidationReceipt(
        task_ordinal=binding.task_ordinal,
        seed_alias=binding.seed_alias,
        dgp_id=binding.dgp_id,
        source_kind=source_kind,
        canonical_raw_sha256=raw_sha256,
        raw_bytes_reverified=raw_reverified,
        canonical_semantic_sha256=semantic,
        canonical_header_sha256=CANONICAL_HEADER_SHA256,
        canonical_rows=len(frame),
        canonical_columns=len(frame.columns),
        numeric_columns=len(R4_CANONICAL_COLUMNS),
        upstream_score_named_column_excluded=True,
        # The current binding carries caller-projected FileId fields but remains
        # explicitly pending.  Only a future held-handle wrapper may attest true.
        external_manifest_file_id_held_by_wrapper=False,
        actual_common_path_binding_status=binding.actual_common_path_binding_status,
        qualification_access_count=0,
        fresh_access_count=0,
        truth_access_count=0,
        heldout_access_count=0,
        score_access_count=0,
    )
    return ValidatedTaskInput(
        canonical=frame,
        canonical_dates=dates,
        binding=binding,
        receipt=receipt,
    )


def _validate_spent_research_only_input(canonical_input: bytes) -> ValidatedTaskInput:
    """Validate the sole fixed spent input without projecting qualification custody."""

    if type(canonical_input) is not bytes or not canonical_input:
        raise HofsV12QualificationServiceError(
            "spent-research-only input must be exact nonempty canonical bytes"
        )
    raw_sha256 = hashlib.sha256(canonical_input).hexdigest()
    if raw_sha256 != SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256:
        raise HofsV12QualificationServiceError(
            "spent-research-only canonical raw pin drifted"
        )
    frame = _parse_exact_canonical_csv(canonical_input)
    dates = _validate_exact_canonical_frame(frame)
    try:
        semantic = _logical_frame_sha256(frame)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HofsV12QualificationServiceError(
            "spent-research-only canonical semantic hash failed"
        ) from exc
    binding = _SpentResearchOnlyBinding(
        canonical_semantic_sha256=semantic,
        canonical_raw_sha256=raw_sha256,
    )
    receipt = InputValidationReceipt(
        task_ordinal=binding.task_ordinal,
        seed_alias=binding.seed_alias,
        dgp_id=binding.dgp_id,
        source_kind="SPENT_RESEARCH_ONLY_FIXED_CANONICAL_BYTES",
        canonical_raw_sha256=raw_sha256,
        raw_bytes_reverified=True,
        canonical_semantic_sha256=semantic,
        canonical_header_sha256=CANONICAL_HEADER_SHA256,
        canonical_rows=len(frame),
        canonical_columns=len(frame.columns),
        numeric_columns=len(R4_CANONICAL_COLUMNS),
        upstream_score_named_column_excluded=True,
        external_manifest_file_id_held_by_wrapper=False,
        actual_common_path_binding_status=binding.actual_common_path_binding_status,
        qualification_access_count=binding.qualification_access_count,
        fresh_access_count=binding.fresh_access_count,
        truth_access_count=binding.truth_access_count,
        heldout_access_count=binding.heldout_access_count,
        score_access_count=binding.score_access_count,
        status="PASS_SPENT_RESEARCH_ONLY_FIXED_CANONICAL_PREFLIGHT",
    )
    return ValidatedTaskInput(
        canonical=frame,
        canonical_dates=dates,
        binding=binding,
        receipt=receipt,
    )


def _select_v7_numeric_source(canonical: pd.DataFrame) -> pd.DataFrame:
    """Apply the exact 22-column boundary before any numeric backend call."""

    if tuple(R4_CANONICAL_COLUMNS) != tuple(dict.fromkeys(R4_CANONICAL_COLUMNS)):
        raise HofsV12QualificationServiceError("V7 numeric allowlist is duplicated")
    if UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE in R4_CANONICAL_COLUMNS:
        raise HofsV12QualificationServiceError("upstream score-named column entered V7 input")
    output = canonical.loc[:, list(R4_CANONICAL_COLUMNS)].copy(deep=True)
    if tuple(output.columns) != R4_CANONICAL_COLUMNS or len(output.columns) != 22:
        raise HofsV12QualificationServiceError("V7 numeric input schema drifted")
    return output


def _identity_rows(frame: pd.DataFrame, columns: tuple[str, str]) -> list[list[str]]:
    return [
        [str(entity), pd.Timestamp(date).strftime("%Y-%m-%d")]
        for entity, date in frame.loc[:, list(columns)].itertuples(index=False, name=None)
    ]


def _execute_audited_v7_numeric_lineage(
    numeric_source: pd.DataFrame,
    plan: tuple[QualificationFoldSpec, ...],
    *,
    capability: object,
) -> tuple[V7DecisionBlockResult, ...]:
    """Call unchanged audited V7 functions; reachable only after the public P0 gate."""

    if capability is not _AUDITED_NUMERIC_CAPABILITY:
        raise HofsV12QualificationServiceError("audited V7 numeric capability is private")
    if tuple(numeric_source.columns) != R4_CANONICAL_COLUMNS:
        raise HofsV12QualificationServiceError("audited V7 input escaped the 22-column allowlist")
    verify_numeric_source_closure()
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: PLC0415
        adapt_r4_canonical_source_v7,
        build_hierarchical_state_features_v7,
        contract_sha256,
        fit_chronological_prefix_v7,
        fit_config_sha256,
        run_frozen_decision_block_v7,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v7.contracts import (  # noqa: PLC0415
        IDENTITY_COLUMNS as V7_IDENTITY_COLUMNS,
        OUTPUT_COLUMNS,
    )

    if contract_sha256() != V7_CONTRACT_SHA256 or fit_config_sha256() != V7_FIT_CONFIG_SHA256:
        raise HofsV12QualificationServiceError("live V7 semantic contract drifted")
    source = adapt_r4_canonical_source_v7(numeric_source)
    if (
        tuple(source.columns) != R4_CANONICAL_COLUMNS
        or len(source) != SOURCE_ROWS_PER_TASK
        or not source.index.equals(pd.RangeIndex(SOURCE_ROWS_PER_TASK))
    ):
        raise HofsV12QualificationServiceError("audited V7 adapted source drifted")
    actual_identity = [
        [str(symbol), pd.Timestamp(date).strftime("%Y-%m-%d")]
        for symbol, date in source.loc[:, ["symbol", "date"]].itertuples(
            index=False, name=None
        )
    ]
    if actual_identity != sorted(actual_identity, key=lambda row: (row[1], row[0])):
        raise HofsV12QualificationServiceError("audited V7 source order drifted")
    full_state = build_hierarchical_state_features_v7(source)
    full_state.assert_live_integrity()
    if _identity_rows(full_state.identities, V7_IDENTITY_COLUMNS) != actual_identity:
        raise HofsV12QualificationServiceError("audited V7 state identity drifted")
    observed = source["observed_pe"].copy()
    research_groups = pd.Series(
        [NONINFORMATIVE_GROUP_LABEL] * SOURCE_ROWS_PER_TASK,
        index=source.index,
        dtype="object",
    )

    blocks: list[V7DecisionBlockResult] = []

    def validate_v7_resource_receipt(receipt: object, *, purpose: str) -> None:
        if (
            getattr(receipt, "purpose", None) != purpose
            or getattr(receipt, "logical_cpu_count", None) != 32
            or getattr(receipt, "affinity_mask_hex", None) != "0xFFFFFFFF"
            or getattr(receipt, "cpu_ids", None) != tuple(range(32))
            or getattr(receipt, "outer_workers", None) != 32
            or getattr(receipt, "inner_threads", None) != 1
            or getattr(receipt, "gpu_used", None) is not False
        ):
            raise HofsV12QualificationServiceError(
                f"unchanged V7 {purpose} resource receipt drifted"
            )

    for spec in plan:
        start = spec.decision_block_start_inclusive
        end = spec.decision_block_end_exclusive
        requested = full_state.identities.iloc[start:end].copy()
        if requested.index.tolist() != list(range(start, end)):
            raise HofsV12QualificationServiceError("V7 requested source positions drifted")
        requested_rows = _identity_rows(requested, V7_IDENTITY_COLUMNS)
        capability_result = fit_chronological_prefix_v7(
            source,
            decision_block_identities=requested,
            observed_pe=observed,
            research_dgp_groups=research_groups,
        )
        fit = capability_result.fit
        parameters = fit.parameters
        fit_receipt = fit.fit_receipt
        output = run_frozen_decision_block_v7(
            source,
            requested_identities=requested,
            parameters=parameters,
        )
        validate_v7_resource_receipt(fit.resource_receipt, purpose="FIT")
        validate_v7_resource_receipt(
            output.inference_resource_receipt, purpose="INFERENCE"
        )
        expected_positions = tuple(range(start, end))
        if (
            parameters.decision_source_positions != expected_positions
            or fit_receipt.decision_source_positions != expected_positions
            or output.input_rows != spec.decision_row_count
            or len(output.values) != spec.decision_row_count
            or tuple(output.values.columns) != OUTPUT_COLUMNS
            or parameters.within_block_parameter_update_count != 0
            or fit_receipt.within_block_parameter_update_count != 0
            or output.within_block_parameter_update_count != 0
        ):
            raise HofsV12QualificationServiceError("V7 fit/output causal custody drifted")
        parameter_sha256 = parameters.sha256()
        if (
            output.parameter_sha256 != parameter_sha256
            or parameters.convergence_receipt_sha256 != fit_receipt.sha256()
            or parameters.decision_block_ordered_membership_sha256
            != output.decision_block_ordered_membership_sha256
            or parameters.decision_block_set_membership_sha256
            != output.decision_block_set_membership_sha256
            or parameters.decision_source_positions_sha256
            != output.decision_source_positions_sha256
        ):
            raise HofsV12QualificationServiceError("V7 parameter/output binding drifted")
        if (
            fit_receipt.prefix_entity_row_counts != ((SYMBOL, start, 3, start - 3),)
            or fit_receipt.prefix_entity_causal_invalid_positions != ((SYMBOL, (0, 1, 2)),)
            or fit_receipt.fit_row_count != start - 3
            or fit_receipt.causal_prefix_nonwarm_row_count != 3
            or fit_receipt.source_regime_fallback_count != 0
            or output.regime_fallback_count != 0
        ):
            raise HofsV12QualificationServiceError("V7 strict-prefix receipt drifted")
        output_identities = _identity_rows(output.identities, V7_IDENTITY_COLUMNS)
        if output_identities != requested_rows:
            raise HofsV12QualificationServiceError("V7 output identity order drifted")
        numeric = output.values.to_numpy(dtype=np.float64)
        if (
            not np.isfinite(numeric).all()
            or not (numeric[:, :3] > 0.0).all()
            or not (numeric[:, 1] <= numeric[:, 0]).all()
            or not (numeric[:, 0] <= numeric[:, 2]).all()
            or not ((numeric[:, 4] >= 0.0) & (numeric[:, 4] <= 1.0)).all()
        ):
            raise HofsV12QualificationServiceError("V7 output numeric domain drifted")
        blocks.append(
            V7DecisionBlockResult(
                fold_ordinal=spec.fold_ordinal,
                source_row_positions=expected_positions,
                entity_ids=tuple(row[0] for row in output_identities),
                decision_dates=tuple(row[1] for row in output_identities),
                expected_pe=tuple(float(value) for value in numeric[:, 0]),
                pe_p10=tuple(float(value) for value in numeric[:, 1]),
                pe_p90=tuple(float(value) for value in numeric[:, 2]),
                log_scale=tuple(float(value) for value in numeric[:, 3]),
                tail_guard_weight=tuple(float(value) for value in numeric[:, 4]),
                fit_prefix_end_exclusive=spec.fit_prefix_end_exclusive,
                within_block_parameter_update_count=(
                    output.within_block_parameter_update_count
                ),
                parameter_sha256=parameter_sha256,
                fit_receipt_sha256=fit_receipt.sha256(),
                decision_block_ordered_membership_sha256=(
                    output.decision_block_ordered_membership_sha256
                ),
                decision_block_set_membership_sha256=(
                    output.decision_block_set_membership_sha256
                ),
                decision_source_positions_sha256=output.decision_source_positions_sha256,
                output_manifest_sha256=output.output_manifest_sha256,
            )
        )
    return tuple(blocks)


def _validate_block_universe(
    blocks: tuple[V7DecisionBlockResult, ...],
    plan: tuple[QualificationFoldSpec, ...],
) -> None:
    if type(blocks) is not tuple or len(blocks) != FOLDS_PER_TASK:
        raise HofsV12QualificationServiceError("V7 block universe is partial")
    if tuple(block.fold_ordinal for block in blocks) != tuple(range(FOLDS_PER_TASK)):
        raise HofsV12QualificationServiceError("V7 blocks are duplicated or reordered")
    if sum(len(block.expected_pe) for block in blocks) != PREDICTION_ROWS_PER_TASK:
        raise HofsV12QualificationServiceError("V7 block aggregate row count drifted")
    if any(block.fit_prefix_end_exclusive != spec.fit_prefix_end_exclusive for block, spec in zip(blocks, plan, strict=True)):
        raise HofsV12QualificationServiceError("V7 block/plan prefix binding drifted")


def _assemble_task_surface(
    validated: ValidatedTaskInput,
    blocks: tuple[V7DecisionBlockResult, ...],
) -> pd.DataFrame:
    plan = build_qualification_fold_plan()
    _validate_block_universe(blocks, plan)
    rows: list[dict[str, Any]] = []
    for spec, block in zip(plan, blocks, strict=True):
        for local_ordinal, source_position in enumerate(block.source_row_positions):
            canonical_date = validated.canonical_dates[source_position]
            if (
                block.entity_ids[local_ordinal] != SYMBOL
                or block.decision_dates[local_ordinal] != canonical_date
            ):
                raise HofsV12QualificationServiceError("V7/canonical output identity drifted")
            row = {
                "seed_alias": validated.binding.seed_alias,
                "dgp_id": validated.binding.dgp_id,
                "session_position": source_position,
                "date": canonical_date,
                "symbol": SYMBOL,
                "fold_id": spec.fold_id,
                "train_end_position": spec.fit_prefix_end_exclusive - 1,
                "test_start_position": spec.decision_block_start_inclusive,
                "hofs_r2_expected_log_pe": math.log(block.expected_pe[local_ordinal]),
                "hofs_v7_tail_guard_weight": block.tail_guard_weight[local_ordinal],
                "hofs_v7_log_scale": block.log_scale[local_ordinal],
            }
            if tuple(row) != HOFS_TASK_SURFACE_COLUMNS:
                raise HofsV12QualificationServiceError("H-OFS task surface schema drifted")
            rows.append(row)
    surface = pd.DataFrame.from_records(rows, columns=HOFS_TASK_SURFACE_COLUMNS)
    if type(validated.binding) is ExternalTaskBinding:
        validate_task_surface(surface)
    elif type(validated.binding) is _SpentResearchOnlyBinding:
        _validate_task_surface_exact(
            surface,
            allowed_seed_aliases=(SPENT_RESEARCH_ONLY_SEED_ALIAS,),
            allowed_dgp_ids=(SPENT_RESEARCH_ONLY_DGP_ID,),
        )
    else:  # pragma: no cover - the frozen dataclass union is exhaustive.
        raise HofsV12QualificationServiceError("task surface binding class drifted")
    return surface


def _validate_task_surface_exact(
    frame: pd.DataFrame,
    *,
    allowed_seed_aliases: tuple[str, ...],
    allowed_dgp_ids: tuple[str, ...],
) -> None:
    """Validate exact dtypes, output order, identity geometry, and domains."""

    if (
        type(frame) is not pd.DataFrame
        or frame.columns.has_duplicates
        or tuple(map(str, frame.columns)) != HOFS_TASK_SURFACE_COLUMNS
        or len(frame) != PREDICTION_ROWS_PER_TASK
        or not frame.index.equals(pd.RangeIndex(PREDICTION_ROWS_PER_TASK))
    ):
        raise HofsV12QualificationServiceError("H-OFS task surface shape or schema drifted")
    exact_dtypes = {
        "seed_alias": np.dtype("O"),
        "dgp_id": np.dtype("O"),
        "session_position": np.dtype("int64"),
        "date": np.dtype("O"),
        "symbol": np.dtype("O"),
        "fold_id": np.dtype("O"),
        "train_end_position": np.dtype("int64"),
        "test_start_position": np.dtype("int64"),
        "hofs_r2_expected_log_pe": np.dtype("float64"),
        "hofs_v7_tail_guard_weight": np.dtype("float64"),
        "hofs_v7_log_scale": np.dtype("float64"),
    }
    if any(frame[column].dtype != dtype for column, dtype in exact_dtypes.items()):
        raise HofsV12QualificationServiceError("H-OFS task surface exact dtype drifted")
    if frame.loc[:, list(IDENTITY_COLUMNS)].duplicated().any():
        raise HofsV12QualificationServiceError("H-OFS task surface identity is duplicated")
    if (
        frame["seed_alias"].nunique(dropna=False) != 1
        or frame["seed_alias"].iloc[0] not in allowed_seed_aliases
        or frame["dgp_id"].nunique(dropna=False) != 1
        or frame["dgp_id"].iloc[0] not in allowed_dgp_ids
        or not frame["symbol"].map(lambda value: type(value) is str and value == SYMBOL).all()
    ):
        raise HofsV12QualificationServiceError("H-OFS task output identity escaped universe")
    positions = frame["session_position"].to_numpy(copy=False)
    if not np.array_equal(positions, np.arange(504, SCORE_END_EXCLUSIVE, dtype=np.int64)):
        raise HofsV12QualificationServiceError("H-OFS task positions are not exact 504..1799")
    plan = build_qualification_fold_plan()
    expected_starts = np.concatenate(
        [np.full(spec.decision_row_count, spec.decision_block_start_inclusive) for spec in plan]
    )
    expected_train_ends = expected_starts - 1
    expected_folds = np.concatenate(
        [np.full(spec.decision_row_count, spec.fold_id, dtype=object) for spec in plan]
    )
    if (
        not np.array_equal(frame["test_start_position"].to_numpy(copy=False), expected_starts)
        or not np.array_equal(frame["train_end_position"].to_numpy(copy=False), expected_train_ends)
        or not np.array_equal(frame["fold_id"].to_numpy(dtype=object), expected_folds)
    ):
        raise HofsV12QualificationServiceError("H-OFS task fold identity drifted")
    if not frame["date"].map(lambda value: type(value) is str).all():
        raise HofsV12QualificationServiceError("H-OFS task date dtype or value drifted")
    dates = pd.to_datetime(frame["date"], format="%Y-%m-%d", errors="coerce")
    if (
        dates.isna().any()
        or dates.duplicated().any()
        or not dates.is_monotonic_increasing
        or not np.array_equal(
            frame["date"].to_numpy(copy=False), dates.dt.strftime("%Y-%m-%d")
        )
    ):
        raise HofsV12QualificationServiceError("H-OFS task dates drifted")
    expected_log = frame["hofs_r2_expected_log_pe"].to_numpy(copy=False)
    tail = frame["hofs_v7_tail_guard_weight"].to_numpy(copy=False)
    log_scale = frame["hofs_v7_log_scale"].to_numpy(copy=False)
    if (
        not np.isfinite(expected_log).all()
        or not np.isfinite(tail).all()
        or not ((tail >= 0.0) & (tail <= 1.0)).all()
        or not np.isfinite(log_scale).all()
    ):
        raise HofsV12QualificationServiceError("H-OFS task numeric values drifted")


def validate_task_surface(frame: pd.DataFrame) -> None:
    """Validate the exact qualification-only 11-column surface contract."""

    _validate_task_surface_exact(
        frame,
        allowed_seed_aliases=SEED_ALIASES,
        allowed_dgp_ids=DGP_IDS,
    )


def _compute_surface_with_backend_for_test(
    validated: ValidatedTaskInput,
    backend: NumericBackend,
) -> pd.DataFrame:
    """Synthetic-test seam; not exported and never grants the audited capability."""

    if type(validated) is not ValidatedTaskInput or not callable(backend):
        raise HofsV12QualificationServiceError("synthetic surface seam inputs drifted")
    numeric_source = _select_v7_numeric_source(validated.canonical)
    blocks = backend(numeric_source, build_qualification_fold_plan())
    return _assemble_task_surface(validated, blocks)


def _compute_validated_task_artifact(validated: ValidatedTaskInput) -> ComputedTaskArtifact:
    """Shared private numeric core reached only by an authorized or fixed spent entry."""

    verify_numeric_source_closure()
    resource_envelope = assert_actual_numeric_launch_allowed(
        validated.binding.task_ordinal % OUTER_WORKERS
    )
    numeric_source = _select_v7_numeric_source(validated.canonical)
    blocks = _execute_audited_v7_numeric_lineage(
        numeric_source,
        build_qualification_fold_plan(),
        capability=_AUDITED_NUMERIC_CAPABILITY,
    )
    surface = _assemble_task_surface(validated, blocks)
    return ComputedTaskArtifact(
        surface=surface,
        blocks=blocks,
        input_receipt=validated.receipt,
        resource_envelope=resource_envelope,
    )


def compute_task_artifact(
    canonical_input: bytes | pd.DataFrame,
    *,
    external_binding: ExternalTaskBinding | Mapping[str, object],
) -> ComputedTaskArtifact:
    """Fail closed until a new revision binds production inputs and authority."""

    binding = _normalize_binding(external_binding)
    if (
        binding.actual_common_path_binding_status == ACTUAL_COMMON_PATH_BINDING_STATUS
        or SOURCE_MODEL_VERSION_BINDING_STATUS.startswith("PENDING_")
        or PRODUCTION_NUMERIC_AUTHORITY_STATUS
        != "GRANTED_FINAL_EXTERNAL_BINDING_SOURCE_FREEZE_AND_ROOT_AUTHORITY"
    ):
        raise HofsV12QualificationServiceError(
            "production numeric entry is denied while external binding, source freeze, "
            "or root authority remains pending"
        )
    validated = validate_injected_task(canonical_input, external_binding=binding)
    if not validated.receipt.raw_bytes_reverified:
        raise HofsV12QualificationServiceError(
            "public numeric entry requires hash-verified canonical bytes parsed by the "
            "frozen V7 CSV path"
        )
    return _compute_validated_task_artifact(validated)


def compute_spent_research_only_task_artifact(
    canonical_input: bytes,
) -> ComputedTaskArtifact:
    """Run only the exact pinned spent-public task; grant no qualification authority."""

    validated = _validate_spent_research_only_input(canonical_input)
    return _compute_validated_task_artifact(validated)


def compute_task_surface(
    canonical_input: bytes | pd.DataFrame,
    *,
    external_binding: ExternalTaskBinding | Mapping[str, object],
) -> pd.DataFrame:
    """Return the exact 11-column surface from a fully audited task artifact."""

    return compute_task_artifact(
        canonical_input, external_binding=external_binding
    ).surface


def validate_exact_task_universe(
    bindings: Sequence[ExternalTaskBinding | Mapping[str, object]],
) -> tuple[ExternalTaskBinding, ...]:
    """Validate the complete 50-task order before a batch can start."""

    if type(bindings) not in (list, tuple) or len(bindings) != TASK_COUNT:
        raise HofsV12QualificationServiceError("task binding universe must contain exactly 50")
    normalized = tuple(_normalize_binding(value) for value in bindings)
    if tuple(item.task_ordinal for item in normalized) != tuple(range(TASK_COUNT)):
        raise HofsV12QualificationServiceError("task binding universe is reordered")
    if len({item.canonical_raw_sha256 for item in normalized}) != TASK_COUNT:
        raise HofsV12QualificationServiceError("task canonical raw bindings are duplicated")
    if len({item.canonical_semantic_sha256 for item in normalized}) != TASK_COUNT:
        raise HofsV12QualificationServiceError("task canonical semantic bindings are duplicated")
    return normalized


__all__ = [
    "ComputedTaskArtifact",
    "InputValidationReceipt",
    "ValidatedTaskInput",
    "V7DecisionBlockResult",
    "compute_task_artifact",
    "compute_spent_research_only_task_artifact",
    "compute_task_surface",
    "validate_exact_task_universe",
    "validate_injected_task",
    "validate_task_surface",
]
