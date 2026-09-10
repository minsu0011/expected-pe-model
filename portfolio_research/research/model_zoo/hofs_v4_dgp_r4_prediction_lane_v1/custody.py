"""Public-only R4 input custody and deterministic no-run fold enumeration."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from typing import Any, Iterable, Mapping

import numpy as np
import pandas as pd
from pandas.testing import assert_frame_equal

from .contracts import (
    DGP_IDS,
    FORBIDDEN_MODEL_COLUMNS,
    GEOMETRY,
    MODEL_SOURCE_COLUMNS,
    MODEL_TARGET_COLUMN,
    PUBLIC_CANONICAL_HEADER_SHA256,
    PUBLIC_INPUT_CHECKSUMS_RAW_SHA256,
    PUBLIC_INPUT_FREEZE_RAW_SHA256,
    PUBLIC_INPUT_ROOT,
    PUBLIC_OBSERVABLE_STATE_CONTRACT_SHA256,
    PUBLIC_PASS_ID,
    SCHEMA_VERSION,
    SEEDS,
    IntegrationContractError,
    canonical_json_bytes,
    sealed_payload,
    semantic_sha256,
)


IDENTITY_FIELDNAMES = (
    "task_ordinal",
    "task_id",
    "seed_alias",
    "dgp_id",
    "session_position",
    "fold_ordinal",
    "fold_id",
    "fold_test_offset",
    "symbol",
    "canonical_date",
    "hofs_v4_entity_id",
    "hofs_v4_decision_date",
)

FOLD_FIELDNAMES = (
    "task_ordinal",
    "task_id",
    "seed_alias",
    "dgp_id",
    "fold_ordinal",
    "fold_id",
    "train_start_position",
    "train_end_exclusive",
    "train_row_count",
    "warm_fit_row_count",
    "fit_regime_fallback_count",
    "fit_regime_fallback_fraction",
    "fit_expected_warmup_regime_fallback_count",
    "fit_unexpected_malformed_regime_count",
    "exact_v4_fit_fallback_gate_pass",
    "fit_end_date",
    "test_start_position",
    "test_end_exclusive",
    "test_row_count",
    "block_start_date",
    "block_end_date",
    "hofs_v4_entity_id",
    "membership_join_columns",
    "research_dgp_membership_value",
    "training_target_column",
    "same_or_future_target_rows_available_to_fit",
    "within_block_update_count",
    "v4_single_session_legal_position_if_fit_existed",
)


@dataclass(frozen=True)
class InputClosureResult:
    payload: dict[str, Any]
    decision_identities_csv: bytes
    fold_plan_csv: bytes

    def __post_init__(self) -> None:
        if type(self.payload) is not dict:
            raise IntegrationContractError("input closure payload requires exact dict")
        if type(self.decision_identities_csv) is not bytes or not self.decision_identities_csv:
            raise IntegrationContractError("decision identity artifact requires nonempty bytes")
        if type(self.fold_plan_csv) is not bytes or not self.fold_plan_csv:
            raise IntegrationContractError("fold plan artifact requires nonempty bytes")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _has_reparse_attribute(path: Path) -> bool:
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & flag)


def _require_safe_directory(path: Path, *, label: str) -> None:
    try:
        is_directory = path.is_dir()
        is_symlink = path.is_symlink()
        is_reparse = _has_reparse_attribute(path)
    except OSError as exc:
        raise IntegrationContractError(f"{label} cannot be inspected") from exc
    if not is_directory or is_symlink or is_reparse:
        raise IntegrationContractError(f"{label} must be an ordinary non-reparse directory")


def _require_safe_file(path: Path, *, label: str) -> None:
    try:
        is_file = path.is_file()
        is_symlink = path.is_symlink()
        is_reparse = _has_reparse_attribute(path)
    except OSError as exc:
        raise IntegrationContractError(f"{label} cannot be inspected") from exc
    if not is_file or is_symlink or is_reparse:
        raise IntegrationContractError(f"{label} must be an ordinary non-reparse file")


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise IntegrationContractError(f"duplicate JSON key rejected: {key}")
        output[key] = value
    return output


def load_json_object(path: Path) -> dict[str, Any]:
    _require_safe_file(path, label=path.name)
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                IntegrationContractError(f"non-finite JSON constant rejected: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrationContractError(f"{path.name} is not valid UTF-8 JSON") from exc
    if type(payload) is not dict:
        raise IntegrationContractError(f"{path.name} JSON root requires exact object")
    return payload


def verify_self_seal(payload: Mapping[str, Any], expected: str) -> None:
    unsigned = dict(payload)
    claimed = unsigned.pop("manifest_sha256", None)
    if type(claimed) is not str or claimed != expected or semantic_sha256(unsigned) != claimed:
        raise IntegrationContractError("semantic self-seal differs")


def _csv_header(path: Path) -> tuple[str, ...]:
    _require_safe_file(path, label=path.name)
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            header = next(csv.reader(stream))
    except (UnicodeError, csv.Error, StopIteration) as exc:
        raise IntegrationContractError(f"{path.name} has no valid CSV header") from exc
    if any(type(value) is not str or not value for value in header):
        raise IntegrationContractError(f"{path.name} header contains an invalid name")
    if len(set(header)) != len(header):
        raise IntegrationContractError(f"{path.name} header contains duplicates")
    return tuple(header)


def _csv_bytes(fieldnames: tuple[str, ...], rows: Iterable[Mapping[str, Any]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(
        stream,
        fieldnames=fieldnames,
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(dict(row))
    return stream.getvalue().encode("utf-8")


def _iso_date(value: object) -> str:
    timestamp = pd.to_datetime(value, errors="coerce")
    if pd.isna(timestamp) or pd.Timestamp(timestamp).tzinfo is not None:
        raise IntegrationContractError("public decision date is invalid")
    return pd.Timestamp(timestamp).isoformat()


def _task_id(seed: int, dgp_id: str) -> str:
    return f"seed_{seed}__dgp_{dgp_id}"


def _validate_root_receipt(root: Path) -> dict[str, Any]:
    receipt_path = root / "FREEZE_RECEIPT.json"
    checksums_path = root / "CHECKSUMS.sha256"
    _require_safe_file(receipt_path, label="public input freeze receipt")
    _require_safe_file(checksums_path, label="public input checksum ledger")
    if sha256_file(receipt_path) != PUBLIC_INPUT_FREEZE_RAW_SHA256:
        raise IntegrationContractError("public input freeze receipt hash differs")
    if sha256_file(checksums_path) != PUBLIC_INPUT_CHECKSUMS_RAW_SHA256:
        raise IntegrationContractError("public input checksum ledger hash differs")
    receipt = load_json_object(receipt_path)
    expected = {
        "task_count": 50,
        "rows_per_task": 1800,
        "full_identity_rows": 90000,
        "score_start_inclusive": 504,
        "score_end_exclusive": 1800,
        "canonical_header_sha256": PUBLIC_CANONICAL_HEADER_SHA256,
        "observable_state_contract_sha256": PUBLIC_OBSERVABLE_STATE_CONTRACT_SHA256,
        "score_computed": False,
        "survivor_selected_or_fit": False,
        "truth_file_read": False,
        "truth_value_selected": False,
    }
    for field, expected_value in expected.items():
        if receipt.get(field) != expected_value:
            raise IntegrationContractError(f"public freeze receipt field differs: {field}")
    if receipt.get("seeds") != list(SEEDS) or receipt.get("dgps") != list(DGP_IDS):
        raise IntegrationContractError("public seed/DGP task universe differs")
    return receipt


def _read_selected_frame(path: Path) -> pd.DataFrame:
    try:
        frame = pd.read_csv(path, usecols=list(MODEL_SOURCE_COLUMNS), low_memory=False)
    except (OSError, ValueError) as exc:
        raise IntegrationContractError(f"could not read selected public columns: {path.name}") from exc
    frame = frame.loc[:, list(MODEL_SOURCE_COLUMNS)]
    if tuple(frame.columns) != MODEL_SOURCE_COLUMNS or frame.columns.has_duplicates:
        raise IntegrationContractError("selected public model schema differs")
    if len(frame) != GEOMETRY.rows_per_task or not frame.index.equals(
        pd.RangeIndex(GEOMETRY.rows_per_task)
    ):
        raise IntegrationContractError("public task row/index geometry differs")
    return frame


def _validate_task(
    task_dir: Path,
    *,
    task_ordinal: int,
    seed: int,
    dgp_id: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    _require_safe_directory(task_dir, label="public task directory")
    canonical_path = task_dir / "canonical150.csv"
    overlay_path = task_dir / "v04_overlay.csv"
    geometry_path = task_dir / "GEOMETRY.json"
    receipt_path = task_dir / "TASK_RECEIPT.json"
    for path in (canonical_path, overlay_path, geometry_path, receipt_path):
        _require_safe_file(path, label=path.name)

    receipt = load_json_object(receipt_path)
    if (
        receipt.get("seed") != seed
        or receipt.get("dgp") != dgp_id
        or receipt.get("pass_id") != PUBLIC_PASS_ID
        or receipt.get("candidate_or_survivor_fit_executed") is not False
        or receipt.get("score_computed") is not False
        or receipt.get("truth_namespace_accessed") is not False
    ):
        raise IntegrationContractError("public task receipt authority/identity differs")

    canonical_raw_sha256 = sha256_file(canonical_path)
    overlay_raw_sha256 = sha256_file(overlay_path)
    geometry_raw_sha256 = sha256_file(geometry_path)
    if canonical_raw_sha256 != receipt.get("canonical150_raw_sha256"):
        raise IntegrationContractError("canonical150 task hash differs")
    if overlay_raw_sha256 != receipt.get("v04_overlay_raw_sha256"):
        raise IntegrationContractError("overlay254 task hash differs")
    if geometry_raw_sha256 != receipt.get("geometry_raw_sha256"):
        raise IntegrationContractError("public geometry task hash differs")

    canonical_header = _csv_header(canonical_path)
    overlay_header = _csv_header(overlay_path)
    if len(canonical_header) != 150 or len(overlay_header) != 254:
        raise IntegrationContractError("canonical/overlay public width differs")
    if overlay_header[:150] != canonical_header:
        raise IntegrationContractError("overlay does not preserve exact canonical150 prefix")
    if semantic_sha256(list(canonical_header)) != PUBLIC_CANONICAL_HEADER_SHA256:
        raise IntegrationContractError("canonical150 header semantic hash differs")
    if not set(MODEL_SOURCE_COLUMNS).issubset(canonical_header):
        raise IntegrationContractError("required public H-OFS source column is absent")
    if set(MODEL_SOURCE_COLUMNS).intersection(FORBIDDEN_MODEL_COLUMNS):
        raise IntegrationContractError("forbidden field entered the model allowlist")

    canonical = _read_selected_frame(canonical_path)
    overlay = _read_selected_frame(overlay_path)
    try:
        assert_frame_equal(canonical, overlay, check_dtype=True, check_exact=True)
    except AssertionError as exc:
        raise IntegrationContractError("selected canonical/overlay public values differ") from exc

    if canonical["symbol"].isna().any() or any(
        type(value) is not str or not value for value in canonical["symbol"].tolist()
    ):
        raise IntegrationContractError("public entity values require exact nonempty strings")
    if canonical["symbol"].nunique(dropna=False) != 1:
        raise IntegrationContractError("each public R4 task must contain exactly one entity")
    dates = pd.to_datetime(canonical["date"], errors="coerce")
    if dates.isna().any() or not dates.is_monotonic_increasing or dates.duplicated().any():
        raise IntegrationContractError("public task dates must be unique and increasing")
    if pd.MultiIndex.from_arrays([canonical["symbol"], dates]).has_duplicates:
        raise IntegrationContractError("public entity/date join is not one-to-one")

    observed = pd.to_numeric(canonical[MODEL_TARGET_COLUMN], errors="coerce").to_numpy(
        dtype=np.float64
    )
    target_window = observed[GEOMETRY.first_test_position : GEOMETRY.end_exclusive]
    if not np.isfinite(target_window).all() or not (target_window > 0.0).all():
        raise IntegrationContractError("public observed_pe proxy target window differs")
    regime = canonical.loc[:, ["p_bear", "p_sideways", "p_bull"]].apply(
        pd.to_numeric, errors="coerce"
    ).to_numpy(dtype=np.float64)
    totals = regime.sum(axis=1)
    valid_regime = (
        np.isfinite(regime).all(axis=1)
        & (regime >= 0.0).all(axis=1)
        & np.isfinite(totals)
        & (totals > 0.0)
    )
    invalid_positions = np.flatnonzero(~valid_regime)
    all_three_missing = np.isnan(regime).all(axis=1)
    if (
        not np.array_equal(invalid_positions, np.arange(199, dtype=np.int64))
        or not all_three_missing[:199].all()
        or all_three_missing[199:].any()
    ):
        raise IntegrationContractError(
            "public regime warmup is not the exact contiguous all-missing prefix"
        )
    expected_regime_warmup = np.zeros(len(regime), dtype=bool)
    expected_regime_warmup[:199] = True
    unexpected_malformed_regime = (~valid_regime) & (~expected_regime_warmup)
    positive_proxy = np.isfinite(observed) & (observed > 0.0)
    causal_prior_warm = np.zeros(len(observed), dtype=bool)
    initialized = False
    for position, is_positive in enumerate(positive_proxy):
        causal_prior_warm[position] = initialized
        if is_positive:
            initialized = True
    fit_eligible = positive_proxy & causal_prior_warm

    geometry = load_json_object(geometry_path)
    expected_geometry = {
        "seed": seed,
        "dgp": dgp_id,
        "rows": 1800,
        "canonical_columns": 150,
        "overlay_columns": 254,
        "score_start_inclusive": 504,
        "score_end_exclusive": 1800,
        "target_interval_rows": 1296,
        "canonical_header_sha256": PUBLIC_CANONICAL_HEADER_SHA256,
        "observable_state_contract_sha256": PUBLIC_OBSERVABLE_STATE_CONTRACT_SHA256,
        "observable_state_missing_columns": [],
        "evaluator_mapping_accessed": False,
    }
    for field, expected_value in expected_geometry.items():
        if geometry.get(field) != expected_value:
            raise IntegrationContractError(f"public task geometry field differs: {field}")
    if geometry.get("observable_state_required_columns") != list(MODEL_SOURCE_COLUMNS[1:]):
        raise IntegrationContractError("public Observable State required schema differs")

    symbol = canonical["symbol"].iloc[0]
    task_id = _task_id(seed, dgp_id)
    seed_alias = f"seed_{seed}"
    identity_rows: list[dict[str, Any]] = []
    fold_rows: list[dict[str, Any]] = []
    for fold_ordinal, test_start in enumerate(GEOMETRY.test_starts):
        test_end = GEOMETRY.test_end_exclusive(test_start)
        fold_id = GEOMETRY.fold_id(test_start)
        fit_end_date = _iso_date(canonical["date"].iloc[test_start - 1])
        block_start_date = _iso_date(canonical["date"].iloc[test_start])
        block_end_date = _iso_date(canonical["date"].iloc[test_end - 1])
        prefix_fit_eligible = fit_eligible[:test_start]
        warm_fit_row_count = int(prefix_fit_eligible.sum())
        fit_regime_fallback_count = int(
            ((~valid_regime[:test_start]) & prefix_fit_eligible).sum()
        )
        fit_expected_warmup_count = int(
            (expected_regime_warmup[:test_start] & prefix_fit_eligible).sum()
        )
        fit_unexpected_malformed_count = int(
            (unexpected_malformed_regime[:test_start] & prefix_fit_eligible).sum()
        )
        fit_regime_fallback_fraction = (
            fit_regime_fallback_count / warm_fit_row_count
            if warm_fit_row_count
            else float("inf")
        )
        fallback_gate_pass = (
            fit_regime_fallback_count <= 8
            and fit_regime_fallback_fraction <= 0.02
        )
        fold_rows.append(
            {
                "task_ordinal": task_ordinal,
                "task_id": task_id,
                "seed_alias": seed_alias,
                "dgp_id": dgp_id,
                "fold_ordinal": fold_ordinal,
                "fold_id": fold_id,
                "train_start_position": 0,
                "train_end_exclusive": test_start,
                "train_row_count": test_start,
                "warm_fit_row_count": warm_fit_row_count,
                "fit_regime_fallback_count": fit_regime_fallback_count,
                "fit_regime_fallback_fraction": float.hex(
                    fit_regime_fallback_fraction
                ),
                "fit_expected_warmup_regime_fallback_count": (
                    fit_expected_warmup_count
                ),
                "fit_unexpected_malformed_regime_count": (
                    fit_unexpected_malformed_count
                ),
                "exact_v4_fit_fallback_gate_pass": str(
                    fallback_gate_pass
                ).lower(),
                "fit_end_date": fit_end_date,
                "test_start_position": test_start,
                "test_end_exclusive": test_end,
                "test_row_count": test_end - test_start,
                "block_start_date": block_start_date,
                "block_end_date": block_end_date,
                "hofs_v4_entity_id": symbol,
                "membership_join_columns": (
                    "hofs_v4_entity_id+hofs_v4_decision_date"
                ),
                "research_dgp_membership_value": dgp_id,
                "training_target_column": MODEL_TARGET_COLUMN,
                "same_or_future_target_rows_available_to_fit": "false",
                "within_block_update_count": 0,
                "v4_single_session_legal_position_if_fit_existed": test_start,
            }
        )
        for session_position in range(test_start, test_end):
            decision_date = _iso_date(canonical["date"].iloc[session_position])
            identity_rows.append(
                {
                    "task_ordinal": task_ordinal,
                    "task_id": task_id,
                    "seed_alias": seed_alias,
                    "dgp_id": dgp_id,
                    "session_position": session_position,
                    "fold_ordinal": fold_ordinal,
                    "fold_id": fold_id,
                    "fold_test_offset": session_position - test_start,
                    "symbol": symbol,
                    "canonical_date": str(canonical["date"].iloc[session_position]),
                    "hofs_v4_entity_id": symbol,
                    "hofs_v4_decision_date": decision_date,
                }
            )

    if len(identity_rows) != 1296 or len(fold_rows) != 62:
        raise IntegrationContractError("task fold/identity enumeration differs")
    task_record = {
        "task_ordinal": task_ordinal,
        "task_id": task_id,
        "seed": seed,
        "seed_alias": seed_alias,
        "dgp_id": dgp_id,
        "pass_id": PUBLIC_PASS_ID,
        "relative_task_root": task_dir.as_posix().split(f"{PUBLIC_INPUT_ROOT}/", 1)[-1],
        "canonical150_raw_sha256": canonical_raw_sha256,
        "overlay254_raw_sha256": overlay_raw_sha256,
        "geometry_raw_sha256": geometry_raw_sha256,
        "task_receipt_raw_sha256": sha256_file(receipt_path),
        "canonical_header_sha256": semantic_sha256(list(canonical_header)),
        "overlay_header_sha256": semantic_sha256(list(overlay_header)),
        "row_count": len(canonical),
        "entity_count": int(canonical["symbol"].nunique()),
        "entity_id": symbol,
        "first_date": _iso_date(canonical["date"].iloc[0]),
        "last_date": _iso_date(canonical["date"].iloc[-1]),
        "public_geometry_identity_sha256": geometry.get("identity_sha256"),
        "model_source_allowlist_sha256": semantic_sha256(list(MODEL_SOURCE_COLUMNS)),
        "selected_canonical_overlay_exact": True,
        "valid_regime_row_count": int(valid_regime.sum()),
        "invalid_regime_row_count": int((~valid_regime).sum()),
        "expected_regime_warmup_source_row_count": int(
            expected_regime_warmup.sum()
        ),
        "expected_regime_warmup_identity_sha256": semantic_sha256(
            [
                {
                    "entity_id": symbol,
                    "position": int(position),
                    "decision_date": _iso_date(canonical["date"].iloc[position]),
                }
                for position in np.flatnonzero(expected_regime_warmup)
            ]
        ),
        "unexpected_malformed_regime_row_count": int(
            unexpected_malformed_regime.sum()
        ),
        "decision_window_invalid_regime_row_count": int(
            (~valid_regime[GEOMETRY.first_test_position : GEOMETRY.end_exclusive]).sum()
        ),
        "first_fold_warm_fit_row_count": int(fold_rows[0]["warm_fit_row_count"]),
        "first_fold_fit_regime_fallback_count": int(
            fold_rows[0]["fit_regime_fallback_count"]
        ),
        "folds_passing_exact_v4_fit_fallback_gate": sum(
            row["exact_v4_fit_fallback_gate_pass"] == "true" for row in fold_rows
        ),
        "positive_finite_proxy_target_window_rows": int(
            (np.isfinite(target_window) & (target_window > 0.0)).sum()
        ),
        "fold_count": len(fold_rows),
        "decision_identity_count": len(identity_rows),
        "training_dgp_membership": dgp_id,
        "training_dgp_membership_join": [
            "hofs_v4_entity_id",
            "hofs_v4_decision_date",
        ],
        "seed_or_dgp_passed_as_model_feature": False,
        "overlay_extension_passed_as_model_feature": False,
    }
    return task_record, identity_rows, fold_rows


def build_public_input_closure(project_root: Path) -> InputClosureResult:
    """Verify and enumerate only the named public R4 canonical/overlay surfaces."""

    project = project_root.resolve(strict=True)
    input_root = project / PUBLIC_INPUT_ROOT
    _require_safe_directory(input_root, label="public input root")
    receipt = _validate_root_receipt(input_root)
    pass_root = input_root / "replays" / PUBLIC_PASS_ID
    _require_safe_directory(input_root / "replays", label="public replay root")
    _require_safe_directory(pass_root, label="public pass_1 root")

    task_records: list[dict[str, Any]] = []
    identity_rows: list[dict[str, Any]] = []
    fold_rows: list[dict[str, Any]] = []
    task_ordinal = 0
    for seed in SEEDS:
        seed_root = pass_root / f"seed_{seed}"
        _require_safe_directory(seed_root, label="public seed root")
        for dgp_id in DGP_IDS:
            task_dir = seed_root / f"dgp_{dgp_id}"
            record, task_identities, task_folds = _validate_task(
                task_dir,
                task_ordinal=task_ordinal,
                seed=seed,
                dgp_id=dgp_id,
            )
            task_records.append(record)
            identity_rows.extend(task_identities)
            fold_rows.extend(task_folds)
            task_ordinal += 1

    if (
        len(task_records) != GEOMETRY.task_count
        or len(identity_rows) != GEOMETRY.total_decision_count
        or len(fold_rows) != GEOMETRY.total_fold_count
    ):
        raise IntegrationContractError("global public task/fold/identity geometry differs")
    identity_keys = {
        (row["task_id"], row["hofs_v4_entity_id"], row["hofs_v4_decision_date"])
        for row in identity_rows
    }
    if len(identity_keys) != GEOMETRY.total_decision_count:
        raise IntegrationContractError("global task/entity/date decision custody is not unique")
    if sum(record["fold_count"] for record in task_records) != 3100:
        raise IntegrationContractError("global per-fold training prefix closure differs")
    if any(
        record["decision_window_invalid_regime_row_count"] != 0
        or record["invalid_regime_row_count"] != 199
        or record["expected_regime_warmup_source_row_count"] != 199
        or record["unexpected_malformed_regime_row_count"] != 0
        or record["first_fold_fit_regime_fallback_count"] != 198
        or record["folds_passing_exact_v4_fit_fallback_gate"] != 0
        for record in task_records
    ):
        raise IntegrationContractError("public regime fallback geometry differs from preflight")

    identity_bytes = _csv_bytes(IDENTITY_FIELDNAMES, identity_rows)
    fold_bytes = _csv_bytes(FOLD_FIELDNAMES, fold_rows)
    identity_raw_sha256 = hashlib.sha256(identity_bytes).hexdigest()
    fold_raw_sha256 = hashlib.sha256(fold_bytes).hexdigest()
    payload = sealed_payload(
        {
            "schema_version": f"{SCHEMA_VERSION}.input_closure.v1",
            "status": "PASS_EXACT_PUBLIC_R4_INPUT_CLOSURE_NO_MODEL_RUN",
            "public_input_root": PUBLIC_INPUT_ROOT,
            "public_input_freeze_receipt_raw_sha256": (
                PUBLIC_INPUT_FREEZE_RAW_SHA256
            ),
            "public_input_checksums_raw_sha256": (
                PUBLIC_INPUT_CHECKSUMS_RAW_SHA256
            ),
            "public_input_status": receipt.get("status"),
            "pass_id": PUBLIC_PASS_ID,
            "canonical_header_sha256": PUBLIC_CANONICAL_HEADER_SHA256,
            "observable_state_contract_sha256": (
                PUBLIC_OBSERVABLE_STATE_CONTRACT_SHA256
            ),
            "model_source_columns": list(MODEL_SOURCE_COLUMNS),
            "model_source_allowlist_sha256": semantic_sha256(
                list(MODEL_SOURCE_COLUMNS)
            ),
            "target_column": MODEL_TARGET_COLUMN,
            "target_usage": "strict_train_prefix_only",
            "canonical_is_sole_model_value_source": True,
            "overlay_is_custody_only": True,
            "task_count": len(task_records),
            "fold_count": len(fold_rows),
            "decision_identity_count": len(identity_rows),
            "decision_identities_raw_sha256": identity_raw_sha256,
            "fold_plan_raw_sha256": fold_raw_sha256,
            "task_records": task_records,
            "forbidden_namespace_files_opened": [],
            "comparator_diagnostics_opened": False,
            "public_subdirectory_payload_opened": False,
            "truth_or_vault_payload_opened": False,
            "evaluator_or_score_payload_opened": False,
            "heldout_or_registry_payload_opened": False,
            "model_fit_executed": False,
            "model_prediction_executed": False,
        }
    )
    return InputClosureResult(
        payload=payload,
        decision_identities_csv=identity_bytes,
        fold_plan_csv=fold_bytes,
    )


__all__ = [
    "FOLD_FIELDNAMES",
    "IDENTITY_FIELDNAMES",
    "InputClosureResult",
    "build_public_input_closure",
    "load_json_object",
    "sha256_file",
    "verify_self_seal",
]
