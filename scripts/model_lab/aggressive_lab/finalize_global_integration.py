"""Root-token-gated publication of the frozen global integration replay.

This finalizer is intentionally separate from the score-neutral integration package.
It only replays already-frozen predictions and metrics in memory.  It grants no model
fit, prediction mutation, fresh/held-out evaluation, registry, production, or promotion
authority.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Mapping

import pandas as pd

from research.model_zoo.aggressive_lab.global_integration.builder import (
    InMemoryTables,
    build_ensemble_rows,
    build_status_evidence_rows,
    build_wave1_global_rows,
    combine_in_memory_tables,
    inspect_integration_plan,
    load_bound_dgp_tables,
    load_bound_lane_payloads,
)
from research.model_zoo.aggressive_lab.global_integration.catalog import (
    default_catalog,
    sha256_file,
    terminal_late_bindings,
    verify_status_evidence,
)
from research.model_zoo.aggressive_lab.global_integration.schema import (
    ENSEMBLE_LEADERBOARD_FILENAME,
    GLOBAL_LEADERBOARD_FILENAME,
    MULTI_DGP_LEADERBOARD_FILENAME,
    OUTPUT_FILENAMES,
    SCHEMA_VERSION,
    validate_exact_schema,
)


FINALIZATION_TOKEN = "FINALIZE_EXPECTED_PE_GLOBAL_LEADERBOARDS_EXPLORATION_ONLY_20260820"
DEFAULT_OUTPUT_DIRECTORY = (
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820"
)
FROZEN_SOURCE_TREE_SHA256 = "4407e490e8a77d87c62c51ddbfc223354f7f8c2622f658136b77b2b50f1fb8ae"

# This exact 13-record tree is the root-audited integration implementation.  The
# finalizer is deliberately outside it and cannot silently redefine its contents.
FROZEN_SOURCE_RECORDS: Mapping[str, tuple[str, int]] = {
    "research/model_zoo/aggressive_lab/global_integration/__init__.py": (
        "673ed1c252bb5423d8a54a26b7b7ae33d956e754fffccdeefe48998da456a87f",
        335,
    ),
    "research/model_zoo/aggressive_lab/global_integration/builder.py": (
        "13744dcef1dae9c545d19766e341475d91e541c1467b1954de6eb8bbbd2d47b0",
        44_151,
    ),
    "research/model_zoo/aggressive_lab/global_integration/catalog.py": (
        "2ea1c45acdf30e0d81c747e71c8899b4c280cce9a7a9009e4022145c1f9cda43",
        28_376,
    ),
    "research/model_zoo/aggressive_lab/global_integration/CONTRACT.json": (
        "37991a312560e6f40090480738f5bf4207c41b94dc059ad9ad31b4d6b99316bb",
        2_025,
    ),
    "research/model_zoo/aggressive_lab/global_integration/contract.py": (
        "439378e9d825f8175ed794da75f5e5285fd779f3942d51991eafaa5edb1e708f",
        1_976,
    ),
    "research/model_zoo/aggressive_lab/global_integration/dgp_adapter.py": (
        "345cf02e24a6926c6aacf9433b5656975056c841f882bda4c1a824f669ab26ba",
        6_242,
    ),
    "research/model_zoo/aggressive_lab/global_integration/ensembles.py": (
        "9a8dfff97cab907ed55f97681111175e653167ec69725e7929278bdc8f3dda67",
        13_406,
    ),
    "research/model_zoo/aggressive_lab/global_integration/metrics.py": (
        "4bf172220eb5d457a740c9530c20fb548580f62b4e56e28160a67d64249d4299",
        5_642,
    ),
    "research/model_zoo/aggressive_lab/global_integration/normalization.py": (
        "15bf7e77f9ed930f4eb4e67a5e10ca38a1f28023e621872fd9f7b68bd4a0bcef",
        8_766,
    ),
    "research/model_zoo/aggressive_lab/global_integration/schema.py": (
        "ee017fd1bfaf0e91572d3a7227555186272ecd23c02421be9cac1db0eeb853ce",
        5_876,
    ),
    "research/model_zoo/aggressive_lab/global_integration/thresholds.py": (
        "09536072b3ca2fd523ba858fa47e5722236d3f4d649db4df8108090b686b776d",
        2_787,
    ),
    "scripts/model_lab/aggressive_lab/inspect_global_integration.py": (
        "80515970338bf5c2bab9df6dc251302cdc83e5d054ee99c216aa54ecbca96ae4",
        693,
    ),
    "tests/model_lab/test_global_integration.py": (
        "141add03c95265aa891d9b9624442f697997b83b708ece505c3a320272e96dc9",
        17_677,
    ),
}

# Independent primary-receipt pins supplement the hashes embedded in the frozen
# catalog.  resolve_binding also verifies every summary/comparison/manifest auxiliary
# pin, so a primary match alone is never treated as sufficient.
EXPECTED_TERMINAL_PRIMARY: Mapping[str, tuple[str, str, int]] = {
    "wave1_stage1": (
        "3e62d655aac81f7e295ba559325858ca0e5e75fb285f9a108fef32e30819fc88",
        "a134da37f73107087755cf0724d216c776331fe28944a1635018b0f85f88c0f3",
        6,
    ),
    "classical_v1": (
        "7667870271238527ecdfa5c5808a4ecd39857da0990eb77e2a3f1a5535d6d21c",
        "96dac2dea7a8f61bec562aa5cc18c036af5fafb829eab90e244e5ed92ad0ad2d",
        4,
    ),
    "state_space_v1": (
        "ac3b4a44423f36cd083f0d3b9b3acf57f50fdbea0d22e9a2e121c1c5f8b011a5",
        "5d2956da499c12e1a4330b3d9c357d1081d472a198db826ba401c356f6b19470",
        4,
    ),
    "structural_v7": (
        "239abcffb266725b76a56cf57cca623f79a96611c312e6c81b7ddd6851916cb0",
        "8b6d527ae0a16a7da710e50bfb105a83e484ecd383d79b115a4dee86a8d4bf17",
        6,
    ),
    "simulator_specialist_v1": (
        "8d1d9a075910580f13cc41d81b8450edb7181db21688fe5651e12fd2e1514dc7",
        "9d3ec44705c56bde31b0980380da3010d2dd672d48c0a05478a76341fa7ad31e",
        5,
    ),
    "probabilistic_v2": (
        "2092bce5a1f1cbe91274b2f9bd8ab2ce1f5a49d635876f889f93945b9600d69f",
        "784f3ad84a5d61c141b2a97e816d643babb541d9a11032f1210d6cec454b37f3",
        5,
    ),
    "dgp_v3": (
        "9d1752a847a4d0b0053feef83d222b1ce25ac42f0528e685f7f9849b8c873762",
        "8d79768bd4e5ca1e9977af0b8dea41edf2d20a8cae1ce5824cd5edf5f368237a",
        5,
    ),
    "dgp_iteration2": (
        "85f8d757a9ffe5464d2bfdf03fab885c05df8b5ebe3d5c9a7d6ced729d0f8d44",
        "a057a2283411424c45f7595550617ce8c5df563c4a477ff46b643f1aee830793",
        5,
    ),
    "structural_v8": (
        "d999379486057f3039fec6535267cfa8989dad05d936cef2d01fd7b14ea69c34",
        "4f4035b3e6af49e2c6aee8f158a19efe0ef2be1aa7ff7b5b50bdf94632dd1a8c",
        6,
    ),
    "probabilistic_v3_2": (
        "581c4a68e2686d3b2ed75767992ca3e5f44f1c87ed7103d83edd102cfead4c57",
        "bcce84401bacf172dd2bbaf7723df040a3a1e8cdfe9238dab8671fcee1ef0b36",
        4,
    ),
}

PROTECTED_CONTROL_PATHS = (
    "research/model_zoo/model_registry.json",
    "research/model_zoo/model_registry.csv",
    "research/model_zoo/feature_registry.json",
    "research/model_zoo/feature_registry.csv",
    "outputs/v04_spent_seed_registry.json",
)

EXPECTED_OUTPUT_FILES = frozenset(
    (*OUTPUT_FILENAMES, "MANIFEST.json", "REPORT.md", "CHECKSUMS.sha256")
)


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _relative_file(root: Path, relative: str) -> Path:
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"path escaped repository root: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def assert_token(token: str) -> str:
    """Fail before replay or writes unless the exact root authorization is supplied."""

    if token != FINALIZATION_TOKEN:
        raise PermissionError("exact global leaderboard finalization token is required")
    return _sha256_bytes(token.encode("utf-8"))


def verify_frozen_source_tree(root: Path) -> dict[str, Any]:
    """Verify the exact root-audited 13-record integration tree and aggregate."""

    root = root.resolve()
    records: list[dict[str, Any]] = []
    aggregate_lines: list[str] = []
    # The root audit was produced by PowerShell on Windows, whose pathname sort is
    # case-insensitive (notably CONTRACT.json versus __init__.py).
    for relative in sorted(FROZEN_SOURCE_RECORDS, key=str.casefold):
        expected_sha256, expected_bytes = FROZEN_SOURCE_RECORDS[relative]
        path = _relative_file(root, relative)
        payload = path.read_bytes()
        actual_sha256 = _sha256_bytes(payload)
        if len(payload) != expected_bytes or actual_sha256 != expected_sha256:
            raise ValueError(f"frozen integration source differs: {relative}")
        records.append(
            {
                "path": relative,
                "bytes": len(payload),
                "raw_sha256": actual_sha256,
            }
        )
        aggregate_lines.append(f"{actual_sha256}  {relative}\n")
    aggregate = _sha256_bytes("".join(aggregate_lines).encode("utf-8"))
    if aggregate != FROZEN_SOURCE_TREE_SHA256:
        raise ValueError("frozen integration source-tree aggregate differs")
    return {
        "algorithm": "sha256(casefold-sorted '<raw_sha256>  <relative_path>\\n')",
        "record_count": len(records),
        "aggregate_sha256": aggregate,
        "records": records,
    }


def _terminal_artifact_receipts(root: Path) -> list[dict[str, Any]]:
    """Return a complete second-pass receipt for catalog and late-bound artifacts."""

    root = root.resolve()
    late = terminal_late_bindings(root)
    records: list[dict[str, Any]] = []
    for spec in default_catalog():
        supplied = late.get(spec.lane_id)
        pins: list[tuple[Path, str]] = []
        if supplied is None:
            pins.extend((root / relative, expected) for relative, expected in spec.fixed_artifacts)
        else:
            pins.extend(
                (
                    (supplied.evaluation_manifest, supplied.evaluation_manifest_raw_sha256),
                    (supplied.summary_artifact, supplied.summary_raw_sha256),
                    (supplied.prediction_artifact, supplied.prediction_raw_sha256),
                )
            )
            if supplied.comparison_artifact is not None:
                if supplied.comparison_raw_sha256 is None:
                    raise ValueError("late-bound comparison hash is absent")
                pins.append((supplied.comparison_artifact, supplied.comparison_raw_sha256))
            if supplied.prediction_manifest is not None:
                if supplied.prediction_manifest_raw_sha256 is None:
                    raise ValueError("late-bound prediction-manifest hash is absent")
                pins.append((supplied.prediction_manifest, supplied.prediction_manifest_raw_sha256))
            pins.extend(supplied.auxiliary_artifacts)
        for path, expected in pins:
            resolved = path.resolve()
            try:
                relative = resolved.relative_to(root).as_posix()
            except ValueError as exc:
                raise ValueError("terminal artifact escaped repository root") from exc
            if not resolved.is_file() or sha256_file(resolved) != expected:
                raise ValueError(f"terminal artifact differs: {relative}")
            records.append(
                {
                    "lane_id": spec.lane_id,
                    "path": relative,
                    "raw_sha256": expected,
                }
            )
    return records


def verify_terminal_bindings(root: Path) -> dict[str, Any]:
    """Re-resolve all terminal sources and enforce independent primary pins."""

    root = root.resolve()
    plan = inspect_integration_plan(root, late_bindings=terminal_late_bindings(root))
    if not plan.all_sources_bound or plan.pending_lane_ids:
        raise ValueError("global integration terminal sources are not all bound")
    if plan.finalization_authorized:
        raise ValueError("integration package unexpectedly grants finalization authority")
    if tuple(plan.output_filenames) != OUTPUT_FILENAMES:
        raise ValueError("integration output filenames differ")
    if plan.status_evidence_count != 11:
        raise ValueError("status-only evidence inventory differs")
    receipts = {receipt.lane_id: receipt for receipt in plan.receipts}
    if set(receipts) != set(EXPECTED_TERMINAL_PRIMARY):
        raise ValueError("terminal lane inventory differs")
    for lane_id, (
        manifest_hash,
        prediction_hash,
        artifact_count,
    ) in EXPECTED_TERMINAL_PRIMARY.items():
        receipt = receipts[lane_id]
        actual = (
            receipt.manifest_raw_sha256,
            receipt.prediction_raw_sha256,
            receipt.verified_artifact_count,
        )
        if receipt.status != "BOUND" or actual != (
            manifest_hash,
            prediction_hash,
            artifact_count,
        ):
            raise ValueError(f"terminal primary receipt differs: {lane_id}")
    artifact_receipts = _terminal_artifact_receipts(root)
    return {
        "all_sources_bound": True,
        "pending_lane_ids": [],
        "receipt_count": len(receipts),
        "verified_artifact_count": len(artifact_receipts),
        "source_receipts": [asdict(receipts[lane_id]) for lane_id in receipts],
        "artifact_receipts": artifact_receipts,
    }


def snapshot_protected_controls(root: Path) -> dict[str, dict[str, Any]]:
    """Hash registries/control surfaces so the replay can prove non-mutation."""

    root = root.resolve()
    result: dict[str, dict[str, Any]] = {}
    for relative in PROTECTED_CONTROL_PATHS:
        unresolved = root / relative
        resolved = unresolved.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"protected control escaped repository root: {relative}") from exc
        exists = resolved.is_file()
        result[relative] = {
            "exists": exists,
            "raw_sha256": sha256_file(resolved) if exists else None,
        }
    return result


def replay_in_memory(root: Path) -> InMemoryTables:
    """Replay the frozen predictions through the frozen evaluator; never fit a model."""

    root = root.resolve()
    bindings = terminal_late_bindings(root)
    payloads = load_bound_lane_payloads(root, late_bindings=bindings)
    global_base, base_surface, metadata = build_wave1_global_rows(payloads)
    ensemble = build_ensemble_rows(base_surface, metadata)
    dgp_tables = load_bound_dgp_tables(root)
    status = build_status_evidence_rows(verify_status_evidence(root))
    return combine_in_memory_tables(
        global_base,
        dgp_tables,
        ensemble,
        status_evidence=status,
    )


def _require_all(series: pd.Series, *, message: str) -> None:
    if not series.fillna(False).astype(bool).all():
        raise ValueError(message)


def validate_tables(tables: InMemoryTables) -> dict[str, Any]:
    """Apply exact publication invariants to the three in-memory tables."""

    frames = tables.as_mapping()
    if tuple(frames) != OUTPUT_FILENAMES:
        raise ValueError("in-memory output filenames/order differ")
    expected_rows = {
        GLOBAL_LEADERBOARD_FILENAME: 82,
        MULTI_DGP_LEADERBOARD_FILENAME: 13,
        ENSEMBLE_LEADERBOARD_FILENAME: 22_100,
    }
    for filename, frame in frames.items():
        validate_exact_schema(frame, filename)
        if len(frame) != expected_rows[filename]:
            raise ValueError(f"unexpected row count: {filename}")

    global_rows = tables.global_leaderboard
    dgp_rows = tables.multi_dgp_leaderboard
    ensemble_rows = tables.ensemble_leaderboard

    eligible = global_rows.loc[
        global_rows["cheap_apples_to_apples"].eq(True)  # noqa: E712
        & global_rows["directly_deployable"].eq(True)  # noqa: E712
        & global_rows["simulator_specialist"].eq(False)  # noqa: E712
    ]
    if len(eligible) != 51 or eligible["model_id"].nunique() != 51:
        raise ValueError("exact common-cheap eligible model inventory differs")
    if not eligible["cheap_evaluated_rows"].eq(1_230).all():
        raise ValueError("eligible models do not all cover the exact cheap mask")
    if eligible["cheap_identity_sha256"].nunique(dropna=False) != 1:
        raise ValueError("eligible models do not share one exact cheap identity")

    incomplete = global_rows.loc[
        global_rows["candidate_kind"].eq("BASE_INCOMPLETE_COVERAGE")
    ].set_index("model_id")
    expected_incomplete = {
        "huber_with_regime": 936,
        "state_space_local_linear_trend_target_history_only": 1_146,
    }
    if incomplete["projection_valid_positive_rows"].to_dict() != expected_incomplete:
        raise ValueError("incomplete Wave1 coverage receipt differs")
    if not incomplete["projection_mask_rows"].eq(1_230).all():
        raise ValueError("incomplete Wave1 projection mask differs")
    withheld_cheap = [
        "cheap_identity_sha256",
        "cheap_evaluated_rows",
        "cheap_coverage",
        "cheap_fair_log_mae",
        "cheap_fair_log_rmse",
        "cheap_mae_relative_gain_vs_v04",
        "cheap_rmse_relative_gain_vs_v04",
        "cheap_tournament_gate_pass",
        "cheap_research_continue",
        "cheap_rank_within_partition",
    ]
    if incomplete.loc[:, withheld_cheap].notna().any().any():
        raise ValueError("incomplete Wave1 candidate received pseudo-common cheap evidence")

    simulator = global_rows.loc[global_rows["simulator_specialist"].eq(True)]  # noqa: E712
    if len(simulator) != 5 or simulator["directly_deployable"].fillna(True).astype(bool).any():
        raise ValueError("simulator specialist partition/deployability differs")
    simulator_ids = set(simulator["model_id"].astype(str))
    ensemble_member_ids = {
        member for joined in ensemble_rows["member_ids"].astype(str) for member in joined.split("|")
    }
    if simulator_ids & ensemble_member_ids:
        raise ValueError("simulator specialist leaked into deployable ensemble search")
    if ensemble_rows["contains_simulator_specialist"].fillna(True).astype(bool).any():
        raise ValueError("ensemble simulator-exclusion label differs")

    if not dgp_rows["model_id"].is_unique or not dgp_rows["common_identity_rows"].eq(18_900).all():
        raise ValueError("multi-DGP identity/inventory differs")
    robust_gate_passes = int(dgp_rows["robust_gate_pass"].eq(True).sum())  # noqa: E712
    if robust_gate_passes != 0:
        raise ValueError("multi-DGP robust gate pass count differs")

    status_only = global_rows.loc[global_rows["numeric_metrics_available"].eq(False)]  # noqa: E712
    if len(status_only) != 11:
        raise ValueError("status-only evidence count differs")
    status_numeric = [
        column
        for column in global_rows.columns
        if column.startswith(("projection_", "cheap_", "full_", "dgp_"))
        and column
        not in {
            "projection_exclusion_reason",
            "cheap_apples_to_apples",
            "cheap_mask_id",
            "cheap_identity_sha256",
            "full_mask_id",
            "full_identity_sha256",
            "full_metrics_cross_lane_comparable",
            "dgp_mask_id",
            "dgp_worst_mae_id",
            "dgp_worst_rmse_id",
        }
    ]
    if status_only.loc[:, status_numeric].notna().any().any():
        raise ValueError("status-only evidence contains numeric metrics")

    family_counts = ensemble_rows["ensemble_family"].value_counts().to_dict()
    expected_family_counts = {
        "equal_geometric_pair": 1_275,
        "pointwise_level_median3": 20_825,
    }
    if family_counts != expected_family_counts:
        raise ValueError("ensemble family search counts differ")
    for family, count in expected_family_counts.items():
        family_rows = ensemble_rows.loc[ensemble_rows["ensemble_family"].eq(family)]
        if not family_rows["family_search_space_size"].eq(count).all():
            raise ValueError(f"ensemble family search-space label differs: {family}")
    checks = (
        (
            ensemble_rows["eligible_base_model_count"].eq(51),
            "ensemble eligible model count differs",
        ),
        (
            ensemble_rows["total_search_space_size"].eq(22_100),
            "ensemble total search-space label differs",
        ),
        (
            ensemble_rows["fresh_validation_required"],
            "ensemble fresh-validation requirement differs",
        ),
        (
            ensemble_rows["evidence_class"].eq("POST_RESULT_EXHAUSTIVE_SEARCH"),
            "ensemble evidence-class label differs",
        ),
        (
            ensemble_rows["promotion_authority"].eq("NOT_PROMOTION_EVIDENCE"),
            "ensemble promotion-authority label differs",
        ),
        (
            ensemble_rows["status"].eq("POST_RESULT_EXHAUSTIVE_SEARCH_NOT_PROMOTION_EVIDENCE"),
            "ensemble status label differs",
        ),
        (
            ensemble_rows["selection_bias_caveat"]
            .astype(str)
            .str.contains("MULTIPLE_COMPARISON_BIAS", regex=False),
            "ensemble multiple-comparison caveat differs",
        ),
    )
    for series, message in checks:
        _require_all(series, message=message)
    if ensemble_rows["outcome_selected"].fillna(True).astype(bool).any():
        raise ValueError("ensemble search was mislabeled outcome-selected")
    if not global_rows["promotion_authority"].eq("NOT_PROMOTION_EVIDENCE").all():
        raise ValueError("global rows unexpectedly carry promotion authority")
    if not dgp_rows["promotion_authority"].eq("NOT_PROMOTION_EVIDENCE").all():
        raise ValueError("multi-DGP rows unexpectedly carry promotion authority")

    return {
        "row_counts": expected_rows,
        "eligible_base_model_count": 51,
        "cheap_mask_rows": 1_230,
        "cheap_identity_sha256": str(eligible["cheap_identity_sha256"].iloc[0]),
        "incomplete_positive_rows": expected_incomplete,
        "simulator_specialist_count": 5,
        "simulator_ensemble_member_count": 0,
        "multi_dgp_common_identity_rows": 18_900,
        "multi_dgp_robust_gate_pass_count": robust_gate_passes,
        "status_only_row_count": 11,
        "status_only_numeric_nonnull_count": 0,
        "ensemble_family_counts": expected_family_counts,
        "ensemble_total_search_space_size": 22_100,
        "ensemble_evidence_class": "POST_RESULT_EXHAUSTIVE_SEARCH",
        "ensemble_promotion_authority": "NOT_PROMOTION_EVIDENCE",
    }


def _validate_output_directory(root: Path, output_dir: Path) -> tuple[Path, Path]:
    root = root.resolve()
    outputs = (root / "outputs").resolve()
    if not outputs.is_dir():
        raise FileNotFoundError(outputs)
    candidate = output_dir if output_dir.is_absolute() else root / output_dir
    candidate = candidate.resolve()
    if candidate.parent != outputs:
        raise ValueError("publication directory must be a direct child of repository outputs")
    if candidate.exists():
        raise FileExistsError(f"refusing to overwrite publication directory: {candidate}")
    if not candidate.name or candidate.name.startswith("."):
        raise ValueError("publication directory name is invalid")
    return outputs, candidate


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    if temporary.exists() or path.exists():
        raise FileExistsError(path)
    with temporary.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _atomic_write_csv(path: Path, frame: pd.DataFrame) -> None:
    temporary = path.parent / f".{path.name}.tmp"
    if temporary.exists() or path.exists():
        raise FileExistsError(path)
    with temporary.open("x", encoding="utf-8", newline="") as handle:
        frame.to_csv(
            handle,
            index=False,
            lineterminator="\n",
            float_format="%.17g",
        )
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")


def _report_bytes(validation: Mapping[str, Any], source_tree_hash: str) -> bytes:
    rows = validation["row_counts"]
    families = validation["ensemble_family_counts"]
    report = f"""# Expected P/E Global Leaderboards — Exploration-only publication

Status: `EXPLORATION_ONLY / NOT_PROMOTION_EVIDENCE`

This publication is a deterministic replay of immutable prediction/evaluation artifacts. It
does not fit a model, mutate predictions, access fresh or held-out data, update a registry,
or grant production/promotion authority.

## Published tables

- `{GLOBAL_LEADERBOARD_FILENAME}`: {rows[GLOBAL_LEADERBOARD_FILENAME]} rows
- `{MULTI_DGP_LEADERBOARD_FILENAME}`: {rows[MULTI_DGP_LEADERBOARD_FILENAME]} rows
- `{ENSEMBLE_LEADERBOARD_FILENAME}`: {rows[ENSEMBLE_LEADERBOARD_FILENAME]} rows

## Audit invariants

- Frozen 13-record integration tree: `{source_tree_hash}`
- Exact common-cheap eligible base models: 51 on 1,230 identities
- Incomplete Wave1 coverage: `huber_with_regime` 936/1,230;
  `state_space_local_linear_trend_target_history_only` 1,146/1,230
- Simulator specialists: 5, all non-deployable and excluded from ensembles
- Multi-DGP rows: 13 on 18,900 identities; robust-gate passes: 0
- Status-only rows: 11, with no numeric metrics
- Ensemble search: {families["equal_geometric_pair"]} equal-geometric pairs and
  {families["pointwise_level_median3"]} pointwise median-of-three members

Every ensemble is labeled `POST_RESULT_EXHAUSTIVE_SEARCH` and requires genuinely fresh
validation. A diagnostic gate value in these spent-data tables is not a tournament pass.
"""
    return report.encode("utf-8")


def _verify_staged_publication(
    staging: Path,
    tables: InMemoryTables,
    expected_hashes: Mapping[str, str],
) -> None:
    actual_names = {path.name for path in staging.iterdir() if path.is_file()}
    if actual_names != EXPECTED_OUTPUT_FILES or any(path.is_dir() for path in staging.iterdir()):
        raise ValueError("staged publication file set differs")
    for filename, expected in expected_hashes.items():
        if sha256_file(staging / filename) != expected:
            raise ValueError(f"staged publication hash differs: {filename}")
    for filename, original in tables.as_mapping().items():
        replayed = pd.read_csv(staging / filename)
        validate_exact_schema(replayed, filename)
        if len(replayed) != len(original):
            raise ValueError(f"serialized publication row count differs: {filename}")


def _safe_cleanup_staging(staging: Path, outputs: Path, final_name: str) -> None:
    resolved = staging.resolve()
    if resolved.parent != outputs.resolve() or not resolved.name.startswith(
        f".{final_name}.staging-"
    ):
        raise RuntimeError("refusing unsafe staging cleanup")
    if resolved.exists():
        shutil.rmtree(resolved)


def finalize(root: Path, output_dir: Path, token: str) -> dict[str, Any]:
    """Replay, validate, and atomically publish exactly six exploration artifacts."""

    token_sha256 = assert_token(token)
    root = root.resolve()
    outputs, final_dir = _validate_output_directory(root, output_dir)
    source_before = verify_frozen_source_tree(root)
    terminal_before = verify_terminal_bindings(root)
    controls_before = snapshot_protected_controls(root)

    tables = replay_in_memory(root)
    validation = validate_tables(tables)

    source_after_replay = verify_frozen_source_tree(root)
    terminal_after_replay = verify_terminal_bindings(root)
    controls_after_replay = snapshot_protected_controls(root)
    if source_after_replay != source_before or terminal_after_replay != terminal_before:
        raise RuntimeError("frozen inputs changed during in-memory replay")
    if controls_after_replay != controls_before:
        raise RuntimeError("protected registry/control surface changed during replay")

    staging = Path(tempfile.mkdtemp(prefix=f".{final_dir.name}.staging-", dir=outputs))
    published = False
    try:
        csv_receipts: dict[str, dict[str, Any]] = {}
        for filename, frame in tables.as_mapping().items():
            path = staging / filename
            _atomic_write_csv(path, frame)
            csv_receipts[filename] = {
                "bytes": path.stat().st_size,
                "raw_sha256": sha256_file(path),
                "rows": len(frame),
                "columns": [str(column) for column in frame.columns],
            }

        report_payload = _report_bytes(validation, source_before["aggregate_sha256"])
        _atomic_write_bytes(staging / "REPORT.md", report_payload)
        report_hash = _sha256_bytes(report_payload)
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "status": "FINALIZED_EXPLORATION_ONLY",
            "evidence_class": "EXPLORATION_ONLY",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
            "authorization": {
                "exact_root_token_verified": True,
                "token_sha256": token_sha256,
            },
            "authority": {
                "production": False,
                "registry": False,
                "promotion": False,
                "fresh_data": False,
                "heldout_data": False,
                "model_fit": False,
                "prediction_mutation": False,
            },
            "publication": {
                "atomic_directory_rename": True,
                "output_directory": final_dir.relative_to(root).as_posix(),
                "exact_file_count": len(EXPECTED_OUTPUT_FILES),
                "exact_filenames": sorted(EXPECTED_OUTPUT_FILES),
            },
            "frozen_source_tree": source_before,
            "terminal_bindings": terminal_before,
            "integrity_reverification": {
                "before_replay": True,
                "after_replay": True,
                "immediately_before_atomic_publish": True,
                "protected_control_snapshot": controls_before,
            },
            "validation": validation,
            "artifacts": {
                **csv_receipts,
                "REPORT.md": {
                    "bytes": len(report_payload),
                    "raw_sha256": report_hash,
                },
            },
            "finalizer_raw_sha256": sha256_file(Path(__file__).resolve()),
            "caveat": (
                "Spent-data exploration only. Ensemble rows are post-result exhaustive "
                "search diagnostics and require genuinely fresh validation."
            ),
        }
        manifest_payload = _json_bytes(manifest)
        _atomic_write_bytes(staging / "MANIFEST.json", manifest_payload)

        checksum_targets = {
            **{name: receipt["raw_sha256"] for name, receipt in csv_receipts.items()},
            "MANIFEST.json": _sha256_bytes(manifest_payload),
            "REPORT.md": report_hash,
        }
        checksum_payload = "".join(
            f"{checksum_targets[name]}  {name}\n" for name in sorted(checksum_targets)
        ).encode("utf-8")
        _atomic_write_bytes(staging / "CHECKSUMS.sha256", checksum_payload)
        _verify_staged_publication(staging, tables, checksum_targets)

        # Last fail-closed gate: no mutable source/control byte may change between the
        # validated replay and the single atomic directory publication boundary.
        if verify_frozen_source_tree(root) != source_before:
            raise RuntimeError("frozen source tree changed before atomic publication")
        if verify_terminal_bindings(root) != terminal_before:
            raise RuntimeError("terminal artifacts changed before atomic publication")
        if snapshot_protected_controls(root) != controls_before:
            raise RuntimeError("protected control surface changed before atomic publication")
        if final_dir.exists():
            raise FileExistsError(f"publication directory appeared during replay: {final_dir}")
        os.replace(staging, final_dir)
        published = True
        if {path.name for path in final_dir.iterdir()} != EXPECTED_OUTPUT_FILES:
            raise RuntimeError("published file set differs after atomic rename")
        return {
            "status": "FINALIZED_EXPLORATION_ONLY",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
            "output_directory": final_dir.relative_to(root).as_posix(),
            "manifest_raw_sha256": checksum_targets["MANIFEST.json"],
            "checksums_raw_sha256": sha256_file(final_dir / "CHECKSUMS.sha256"),
            "row_counts": validation["row_counts"],
        }
    finally:
        if not published and staging.exists():
            _safe_cleanup_staging(staging, outputs, final_dir.name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Root-token-gated exploration-only global leaderboard finalizer."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=Path(DEFAULT_OUTPUT_DIRECTORY))
    parser.add_argument("--token", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = finalize(args.root, args.output_dir, args.token)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
