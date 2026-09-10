"""Score-blind DGP-R4 public-input closure and exact block plan for H-OFS V7.

Only fixed ``pass_1`` canonical, overlay, and comparator-diagnostics paths are
opened.  This module has no fit, prediction, evaluator, score, or registry API.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .contracts import (
    ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY,
    EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY,
    MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY,
    MIN_WARM_PREFIX_ROWS_PER_ENTITY,
    OFFSET_COLUMN,
    R4_DECISION_ROWS_PER_TASK,
    R4_DGPS,
    R4_FOLDS_PER_TASK,
    R4_INPUT_BINDING,
    R4_ROWS_PER_TASK,
    R4_SCORE_END_EXCLUSIVE,
    R4_SCORE_START_INCLUSIVE,
    R4_SEEDS,
    R4_TASK_COUNT,
    R4_TEST_BLOCK_ROWS,
    R4_TOTAL_DECISION_ROWS,
    R4_TOTAL_FIT_COUNT,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
)
from .estimator import causal_training_valid_mask_v7
from .features import build_hierarchical_state_features_v7
from .validation import require_exact_int, require_exact_str


R4_CANONICAL_COLUMNS = (
    "date",
    "symbol",
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
R4_PUBLIC_FILENAMES = (
    "canonical150.csv",
    "v04_overlay.csv",
    "comparator_diagnostics.csv",
)
R4_RAW_HEADER_SHA256 = {
    "canonical150.csv": "5686048e635944fa53b29bc278a8eb7f97a2396fa827fb222bb96be47551e84d",
    "v04_overlay.csv": "03712a448c15353378651e7043f2473c2ba439441b865c6532cbb2f77255a774",
    "comparator_diagnostics.csv": (
        "64c8d57cf8515615616741a66631bc14555f903d8ba690389f11e410a787036d"
    ),
}
R4_COLUMN_COUNTS = {
    "canonical150.csv": 150,
    "v04_overlay.csv": 254,
    "comparator_diagnostics.csv": 6,
}


@dataclass(frozen=True)
class R4FoldSpecV7:
    seed: int
    dgp: str
    fold_index: int
    fit_prefix_end_exclusive: int
    decision_block_start_inclusive: int
    decision_block_end_exclusive: int
    decision_row_count: int
    within_block_parameter_update_count: int = 0

    def __post_init__(self) -> None:
        require_exact_int(self.seed, label="R4 fold seed", minimum=0)
        require_exact_str(self.dgp, label="R4 fold DGP")
        for label, value in (
            ("fold index", self.fold_index),
            ("fit prefix end", self.fit_prefix_end_exclusive),
            ("block start", self.decision_block_start_inclusive),
            ("block end", self.decision_block_end_exclusive),
            ("decision rows", self.decision_row_count),
            ("within-block updates", self.within_block_parameter_update_count),
        ):
            require_exact_int(value, label=f"R4 {label}", minimum=0)
        if self.seed not in R4_SEEDS or self.dgp not in R4_DGPS:
            raise HierarchicalStateV7ContractError("R4 fold task identity drifted")
        if not 0 <= self.fold_index < R4_FOLDS_PER_TASK:
            raise HierarchicalStateV7ContractError("R4 fold index drifted")
        expected_start = R4_SCORE_START_INCLUSIVE + self.fold_index * R4_TEST_BLOCK_ROWS
        expected_end = min(expected_start + R4_TEST_BLOCK_ROWS, R4_SCORE_END_EXCLUSIVE)
        if (
            self.fit_prefix_end_exclusive != expected_start
            or self.decision_block_start_inclusive != expected_start
            or self.decision_block_end_exclusive != expected_end
            or self.decision_row_count != expected_end - expected_start
            or self.within_block_parameter_update_count != 0
        ):
            raise HierarchicalStateV7ContractError("R4 fold geometry drifted")

    def payload(self) -> dict[str, Any]:
        return asdict(self)


def build_r4_fold_plan_v7() -> tuple[R4FoldSpecV7, ...]:
    plan = tuple(
        R4FoldSpecV7(
            seed=seed,
            dgp=dgp,
            fold_index=fold_index,
            fit_prefix_end_exclusive=(R4_SCORE_START_INCLUSIVE + fold_index * R4_TEST_BLOCK_ROWS),
            decision_block_start_inclusive=(
                R4_SCORE_START_INCLUSIVE + fold_index * R4_TEST_BLOCK_ROWS
            ),
            decision_block_end_exclusive=min(
                R4_SCORE_START_INCLUSIVE + (fold_index + 1) * R4_TEST_BLOCK_ROWS,
                R4_SCORE_END_EXCLUSIVE,
            ),
            decision_row_count=(
                min(
                    R4_SCORE_START_INCLUSIVE + (fold_index + 1) * R4_TEST_BLOCK_ROWS,
                    R4_SCORE_END_EXCLUSIVE,
                )
                - (R4_SCORE_START_INCLUSIVE + fold_index * R4_TEST_BLOCK_ROWS)
            ),
        )
        for seed in R4_SEEDS
        for dgp in R4_DGPS
        for fold_index in range(R4_FOLDS_PER_TASK)
    )
    if (
        len(plan) != R4_TOTAL_FIT_COUNT
        or sum(item.decision_row_count for item in plan) != R4_TOTAL_DECISION_ROWS
    ):
        raise HierarchicalStateV7ContractError("R4 aggregate fold geometry drifted")
    return plan


def adapt_r4_canonical_source_v7(canonical: pd.DataFrame) -> pd.DataFrame:
    """Return the exact production-observable columns accepted by H-OFS V7."""

    if type(canonical) is not pd.DataFrame or canonical.empty:
        raise HierarchicalStateV7ContractError("R4 canonical input must be non-empty")
    if canonical.columns.has_duplicates or not canonical.index.is_unique:
        raise HierarchicalStateV7ContractError("R4 canonical schema/index must be unique")
    missing = [name for name in R4_CANONICAL_COLUMNS if name not in canonical.columns]
    if missing:
        raise HierarchicalStateV7ContractError(f"R4 canonical columns are missing: {missing}")
    output = canonical.loc[:, list(R4_CANONICAL_COLUMNS)].copy()
    dates = pd.to_datetime(output["date"], errors="coerce")
    if dates.isna().any() or getattr(dates.dt, "tz", None) is not None:
        raise HierarchicalStateV7ContractError("R4 canonical dates are invalid")
    if any(type(value) is not str or not value for value in output["symbol"].to_numpy(object)):
        raise HierarchicalStateV7ContractError("R4 canonical symbols require exact strings")
    if output.assign(date=dates).duplicated(["symbol", "date"]).any():
        raise HierarchicalStateV7ContractError("R4 canonical entity/date identity is duplicated")
    output["date"] = dates.to_numpy(dtype="datetime64[ns]")
    return output


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _parse_json_exact(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in output:
                raise HierarchicalStateV7ContractError(
                    f"duplicate or invalid R4 JSON key: {label}:{key}"
                )
            output[key] = value
        return output

    payload = json.loads(
        content.decode("ascii"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda value: (_ for _ in ()).throw(
            HierarchicalStateV7ContractError(f"non-finite R4 JSON value: {label}:{value}")
        ),
    )
    if type(payload) is not dict:
        raise HierarchicalStateV7ContractError(f"R4 JSON root is not an object: {label}")
    return payload


def _require_regular_file(path: Path, *, root: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.resolve().parent != path.parent.resolve():
        raise HierarchicalStateV7ContractError(f"R4 public path is not a regular child: {path}")
    if root not in path.resolve().parents:
        raise HierarchicalStateV7ContractError("R4 public path escaped the pinned input root")
    return path.read_bytes()


def _expected_warmup_receipt(frame: pd.DataFrame) -> dict[str, Any]:
    source = adapt_r4_canonical_source_v7(frame)
    ordered = source.sort_values(["symbol", "date"], kind="mergesort")
    expected_membership: list[list[str]] = []
    counts: list[list[Any]] = []
    unexpected_count = 0
    decision_expected_count = 0
    for symbol, group in ordered.groupby("symbol", sort=False):
        raw_regime = group.loc[:, ["p_bear", "p_sideways", "p_bull"]]
        all_missing = raw_regime.isna().all(axis=1).to_numpy(dtype=bool)
        prefix_count = 0
        while prefix_count < len(all_missing) and bool(all_missing[prefix_count]):
            prefix_count += 1
        if prefix_count > EXPECTED_REGIME_WARMUP_PREFIX_MAX_PER_ENTITY:
            raise HierarchicalStateV7ContractError(
                "R4 expected regime warmup exceeds the sealed public maximum"
            )
        numeric = raw_regime.apply(pd.to_numeric, errors="coerce").to_numpy(np.float64)
        valid = (
            np.isfinite(numeric).all(axis=1)
            & (numeric >= 0.0).all(axis=1)
            & (numeric.sum(axis=1) > 0.0)
        )
        expected = np.zeros(len(group), dtype=bool)
        expected[:prefix_count] = True
        unexpected_count += int((~valid & ~expected).sum())
        group_positions = group.index.to_numpy()
        decision_expected_count += int(
            expected[np.flatnonzero(group_positions >= R4_SCORE_START_INCLUSIVE)].sum()
        )
        counts.append([symbol, prefix_count])
        for date in group.loc[expected, "date"]:
            expected_membership.append([symbol, pd.Timestamp(date).isoformat()])
    receipt = {
        "per_entity_counts": counts,
        "expected_row_count": len(expected_membership),
        "expected_membership_sha256": hashlib.sha256(
            canonical_json_bytes(expected_membership)
        ).hexdigest(),
        "unexpected_malformed_row_count": unexpected_count,
        "decision_expected_warmup_row_count": decision_expected_count,
        "uniform_causal_fallback": True,
    }
    return receipt


def _causal_invalid_prefix_receipt(frame: pd.DataFrame) -> dict[str, Any]:
    """Prove the exact public causal-prefix geometry without fitting or predicting."""

    source = adapt_r4_canonical_source_v7(frame)
    state = build_hierarchical_state_features_v7(source)
    proxy = pd.to_numeric(source["observed_pe"], errors="coerce").to_numpy(np.float64)
    offset = pd.to_numeric(state.features[OFFSET_COLUMN], errors="coerce").to_numpy(
        np.float64
    )
    valid = causal_training_valid_mask_v7(proxy, offset)
    ordered = state.identities.loc[:, ["hofs_v7_entity_id", "hofs_v7_decision_date"]].copy()
    ordered["_source_position"] = np.arange(len(ordered), dtype=np.int64)
    ordered = ordered.sort_values(
        ["hofs_v7_entity_id", "hofs_v7_decision_date"], kind="mergesort"
    )
    per_entity: list[dict[str, Any]] = []
    for entity, group in ordered.groupby("hofs_v7_entity_id", sort=False):
        source_positions = group["_source_position"].to_numpy(dtype=np.int64)
        entity_valid = valid[source_positions]
        entity_proxy = proxy[source_positions]
        entity_offset = offset[source_positions]
        requested = MIN_REQUESTED_PREFIX_ROWS_PER_ENTITY
        if len(source_positions) < R4_SCORE_END_EXCLUSIVE:
            raise HierarchicalStateV7ContractError("R4 causal receipt entity geometry drifted")
        invalid_positions = tuple(int(value) for value in np.flatnonzero(~entity_valid))
        first_invalid = tuple(value for value in invalid_positions if value < requested)
        later_invalid = tuple(value for value in invalid_positions if value >= requested)
        observed_nonfinite = tuple(
            int(value) for value in np.flatnonzero(~np.isfinite(entity_proxy))
        )
        offset_nonfinite = tuple(
            int(value) for value in np.flatnonzero(~np.isfinite(entity_offset))
        )
        decision_invalid = tuple(
            value
            for value in invalid_positions
            if R4_SCORE_START_INCLUSIVE <= value < R4_SCORE_END_EXCLUSIVE
        )
        warm = int(entity_valid[:requested].sum())
        if (
            first_invalid != ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY
            or later_invalid
            or observed_nonfinite != (0, 1)
            or offset_nonfinite != ALLOWED_CAUSAL_INVALID_POSITIONS_PER_ENTITY
            or warm != MIN_WARM_PREFIX_ROWS_PER_ENTITY
            or decision_invalid
        ):
            raise HierarchicalStateV7ContractError(
                "R4 public causal invalid-prefix evidence drifted"
            )
        invalid_identities = [
            [
                str(group.iloc[position]["hofs_v7_entity_id"]),
                pd.Timestamp(group.iloc[position]["hofs_v7_decision_date"]).isoformat(),
            ]
            for position in first_invalid
        ]
        per_entity.append(
            {
                "entity_id": str(entity),
                "first_prefix_requested_row_count": requested,
                "causal_invalid_positions": list(first_invalid),
                "causal_invalid_identity_membership_sha256": hashlib.sha256(
                    canonical_json_bytes(invalid_identities)
                ).hexdigest(),
                "observed_pe_nonfinite_positions": list(observed_nonfinite),
                "causal_offset_nonfinite_positions": list(offset_nonfinite),
                "first_prefix_nonwarm_row_count": len(first_invalid),
                "first_prefix_warm_row_count": warm,
                "later_unexpected_invalid_row_count": len(later_invalid),
                "decision_invalid_row_count": len(decision_invalid),
                "estimator_sufficiency_minimum_warm_rows": MIN_WARM_PREFIX_ROWS_PER_ENTITY,
                "estimator_sufficiency_passed": warm >= MIN_WARM_PREFIX_ROWS_PER_ENTITY,
            }
        )
    if len(per_entity) != 1:
        raise HierarchicalStateV7ContractError("R4 task must contain exactly one entity")
    return {
        "per_entity": per_entity,
        "per_entity_sha256": hashlib.sha256(canonical_json_bytes(per_entity)).hexdigest(),
        "validity_predicate": "finite_positive_observed_pe_and_finite_causal_offset",
    }


def build_r4_input_closure_v7(project_root: str | Path) -> dict[str, Any]:
    """Validate and receipt only the 150 fixed public R4 input files."""

    project = Path(project_root).resolve()
    root = (project / str(R4_INPUT_BINDING["path"])).resolve()
    if root.is_symlink() or not root.is_dir() or root.parent != (project / "outputs").resolve():
        raise HierarchicalStateV7ContractError("R4 input root custody drifted")

    pinned_root_files = {
        "FREEZE_RECEIPT.json": "freeze_receipt_raw_sha256",
        "CHECKSUMS.sha256": "checksums_raw_sha256",
        "PUBLIC_HASH_LEDGER.json": "public_hash_ledger_raw_sha256",
        "TASK_DIAGNOSTICS.csv": "task_diagnostics_raw_sha256",
        "SOURCE_MANIFEST.csv": "source_manifest_raw_sha256",
    }
    root_contents: dict[str, bytes] = {}
    for name, pin in pinned_root_files.items():
        content = _require_regular_file(root / name, root=root)
        if _sha256(content) != R4_INPUT_BINDING[pin]:
            raise HierarchicalStateV7ContractError(f"R4 pinned root artifact drifted: {name}")
        root_contents[name] = content
    freeze = _parse_json_exact(root_contents["FREEZE_RECEIPT.json"], label="FREEZE_RECEIPT")
    expected_freeze = {
        "status": "PASS_PUBLIC_CANONICAL_OVERLAY_INPUTS_FROZEN_READY_FOR_ONE_SURVIVOR",
        "task_count": R4_TASK_COUNT,
        "rows_per_task": R4_ROWS_PER_TASK,
        "score_start_inclusive": R4_SCORE_START_INCLUSIVE,
        "score_end_exclusive": R4_SCORE_END_EXCLUSIVE,
        "downstream_input_pass": R4_INPUT_BINDING["downstream_input_pass"],
        "score_computed": False,
        "survivor_selected_or_fit": False,
        "truth_file_read": False,
    }
    actual_freeze = {
        **{key: freeze.get(key) for key in expected_freeze if key != "downstream_input_pass"},
        "downstream_input_pass": freeze.get("immutable_publish", {}).get("downstream_input_pass"),
    }
    if actual_freeze != expected_freeze:
        raise HierarchicalStateV7ContractError("R4 public freeze semantics drifted")

    checksum_map: dict[str, str] = {}
    for line in root_contents["CHECKSUMS.sha256"].decode("ascii").splitlines():
        parts = line.split("  ", maxsplit=1)
        if len(parts) == 2:
            checksum_map[parts[1].replace("\\", "/")] = parts[0]

    public_files: list[list[Any]] = []
    task_receipts: list[dict[str, Any]] = []
    task_causal_receipts: list[dict[str, Any]] = []
    for seed in R4_SEEDS:
        for dgp in R4_DGPS:
            task_relative = f"replays/pass_1/seed_{seed}/dgp_{dgp}"
            task = root / Path(task_relative)
            raw_by_name: dict[str, bytes] = {}
            for name in R4_PUBLIC_FILENAMES:
                relative = f"{task_relative}/{name}"
                content = _require_regular_file(task / name, root=root)
                digest = _sha256(content)
                if checksum_map.get(relative) != digest:
                    raise HierarchicalStateV7ContractError(
                        f"R4 public checksum binding drifted: {relative}"
                    )
                header = content.splitlines()[0]
                if _sha256(header) != R4_RAW_HEADER_SHA256[name]:
                    raise HierarchicalStateV7ContractError(f"R4 public header drifted: {relative}")
                raw_by_name[name] = content
                public_files.append([relative, digest, len(content)])

            canonical_path = task / "canonical150.csv"
            canonical = pd.read_csv(canonical_path)
            overlay_dates = pd.read_csv(task / "v04_overlay.csv", usecols=["date"])
            diagnostic_dates = pd.read_csv(
                task / "comparator_diagnostics.csv",
                usecols=["row_position", "date"],
            )
            if (
                len(canonical) != R4_ROWS_PER_TASK
                or len(overlay_dates) != R4_ROWS_PER_TASK
                or len(diagnostic_dates) != R4_ROWS_PER_TASK
                or len(canonical.columns) != R4_COLUMN_COUNTS["canonical150.csv"]
                or len(raw_by_name["v04_overlay.csv"].splitlines()[0].split(b","))
                != R4_COLUMN_COUNTS["v04_overlay.csv"]
                or len(raw_by_name["comparator_diagnostics.csv"].splitlines()[0].split(b","))
                != R4_COLUMN_COUNTS["comparator_diagnostics.csv"]
            ):
                raise HierarchicalStateV7ContractError("R4 public row/schema geometry drifted")
            canonical_dates = canonical["date"].astype(str)
            if (
                overlay_dates["date"].astype(str).tolist() != canonical_dates.tolist()
                or diagnostic_dates["row_position"].tolist() != list(range(R4_ROWS_PER_TASK))
                or diagnostic_dates["date"].astype(str).tolist() != canonical_dates.tolist()
            ):
                raise HierarchicalStateV7ContractError("R4 public identity parity drifted")
            warmup = _expected_warmup_receipt(canonical)
            task_receipts.append({"seed": seed, "dgp": dgp, **warmup})
            causal = _causal_invalid_prefix_receipt(canonical)
            task_causal_receipts.append({"seed": seed, "dgp": dgp, **causal})

    public_files_sha256 = hashlib.sha256(canonical_json_bytes(public_files)).hexdigest()
    if (
        len(public_files) != R4_INPUT_BINDING["bound_public_file_count"]
        or public_files_sha256 != R4_INPUT_BINDING["bound_public_files_sha256"]
    ):
        raise HierarchicalStateV7ContractError("R4 public file ledger closure drifted")
    if (
        len(task_receipts) != R4_TASK_COUNT
        or any(item["expected_row_count"] != 199 for item in task_receipts)
        or any(item["unexpected_malformed_row_count"] != 0 for item in task_receipts)
        or any(item["decision_expected_warmup_row_count"] != 0 for item in task_receipts)
    ):
        raise HierarchicalStateV7ContractError("R4 expected/unexpected regime split drifted")
    if len(task_causal_receipts) != R4_TASK_COUNT:
        raise HierarchicalStateV7ContractError("R4 causal prefix task count drifted")
    for receipt in task_causal_receipts:
        row = receipt["per_entity"][0]
        if (
            row["causal_invalid_positions"] != [0, 1, 2]
            or row["observed_pe_nonfinite_positions"] != [0, 1]
            or row["causal_offset_nonfinite_positions"] != [0, 1, 2]
            or row["first_prefix_requested_row_count"] != 504
            or row["first_prefix_nonwarm_row_count"] != 3
            or row["first_prefix_warm_row_count"] != 501
            or row["later_unexpected_invalid_row_count"] != 0
            or row["decision_invalid_row_count"] != 0
            or row["estimator_sufficiency_passed"] is not True
        ):
            raise HierarchicalStateV7ContractError("R4 causal prefix receipt drifted")
    plan = build_r4_fold_plan_v7()
    return {
        "schema_version": "expected_pe.hofs_v7.dgp_r4_public_input_closure.v1",
        "status": "PASS_EXACT_PUBLIC_R4_CANONICAL_OVERLAY_DIAGNOSTICS_PREFLIGHT",
        "input_binding": dict(R4_INPUT_BINDING),
        "public_files": public_files,
        "public_files_sha256": public_files_sha256,
        "task_regime_receipts": task_receipts,
        "task_regime_receipts_sha256": hashlib.sha256(
            canonical_json_bytes(task_receipts)
        ).hexdigest(),
        "task_causal_prefix_receipts": task_causal_receipts,
        "task_causal_prefix_receipts_sha256": hashlib.sha256(
            canonical_json_bytes(task_causal_receipts)
        ).hexdigest(),
        "geometry": {
            "task_count": R4_TASK_COUNT,
            "folds_per_task": R4_FOLDS_PER_TASK,
            "fit_count": len(plan),
            "decision_rows_per_task": R4_DECISION_ROWS_PER_TASK,
            "decision_row_count": sum(item.decision_row_count for item in plan),
            "test_block_rows": R4_TEST_BLOCK_ROWS,
            "within_block_parameter_update_count": 0,
        },
        "access": {
            "canonical_file_open_count": R4_TASK_COUNT,
            "overlay_file_open_count": R4_TASK_COUNT,
            "diagnostics_file_open_count": R4_TASK_COUNT,
            "other_data_payload_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "score_call_count": 0,
            "model_registry_file_read_count": 0,
            "evaluator_or_protected_artifact_open_count": 0,
        },
    }


__all__ = [
    "R4FoldSpecV7",
    "R4_CANONICAL_COLUMNS",
    "adapt_r4_canonical_source_v7",
    "build_r4_fold_plan_v7",
    "build_r4_input_closure_v7",
    "_causal_invalid_prefix_receipt",
]
