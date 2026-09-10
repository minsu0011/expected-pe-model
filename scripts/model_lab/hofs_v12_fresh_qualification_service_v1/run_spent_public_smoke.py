"""Fixed-path, no-publish H-OFS V12 resource and spent-equivalence smoke."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import time
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

RESOURCE_LOCK = (
    PROJECT_ROOT
    / "research/model_zoo/portfolio_governance_v1/"
    "HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json"
)
SPENT_INPUT_ROOT = (
    PROJECT_ROOT / "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
)
SPENT_CANONICAL = (
    SPENT_INPUT_ROOT
    / "replays/pass_1/seed_2026082001/dgp_A/canonical150.csv"
)
PREDECESSOR_ROOT = (
    PROJECT_ROOT / "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822"
)

FIXED_FILE_PINS = {
    RESOURCE_LOCK: "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c",
    SPENT_INPUT_ROOT / "CHECKSUMS.sha256": (
        "fa7f031f8d8a5f7eb3883618ba1d0715affebad19b2c9c3ee85b34d3c0656ff7"
    ),
    SPENT_INPUT_ROOT / "FREEZE_RECEIPT.json": (
        "f5125088b258925dec7854a29ab9da9f09698d3bbf79afa6b0896e7da959fe14"
    ),
    SPENT_CANONICAL: "aa6bb2f3e63b4423c79a578c3ed2fb8353050dd5ed7dc2d117931abfde1bb384",
    PREDECESSOR_ROOT / "CHECKSUMS.sha256": (
        "4453e6ac01c0479cee794a4ef825fba392fde5ed22fe1dbbbb6729961b072b80"
    ),
    PREDECESSOR_ROOT / "PREDICTIONS.csv": (
        "bb19a0a15ab20bda7d384a87df5ab0c26ef2b1db1db35a0c7f9b9c77d0542fcd"
    ),
    PREDECESSOR_ROOT / "TASK_RECEIPTS.jsonl": (
        "3e93b16c29ebfb10068f0feaa82a40c90f1958bf5405c3c219c15b01551df76b"
    ),
    PREDECESSOR_ROOT / "FOLD_RECEIPTS.jsonl": (
        "a4ba4822e8a792cec66b81850e301f1c1103c7a64e51779dee95d998612f34ee"
    ),
}
EXPECTED_PREDECESSOR_TASK_ROWS_SHA256 = (
    "b9ddd3fc9b397a825da4ae3a5abb35370df19f3db64b5a89c61b4e0f40edb58e"
)
SPENT_SEED = 2026082001
SPENT_DGP = "A"


class SpentSmokeError(RuntimeError):
    """Raised on any fixed-input or bitwise-equivalence drift."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_fixed_files() -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for path, expected in FIXED_FILE_PINS.items():
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.is_symlink():
            raise SpentSmokeError(f"fixed file identity is invalid: {path}")
        observed = _sha256_file(resolved)
        if observed != expected:
            raise SpentSmokeError(f"fixed file hash drifted: {path}")
        stat = resolved.stat()
        records[resolved.relative_to(PROJECT_ROOT).as_posix()] = {
            "raw_sha256": observed,
            "size_bytes": stat.st_size,
            "volume_serial_number": int(stat.st_dev),
            "file_id_128": f"{int(stat.st_ino) & ((1 << 128) - 1):032x}",
        }
    return records


def _float_bits(value: object) -> bytes:
    return struct.pack(">d", float(value))


def _current_prediction_rows(blocks: tuple[object, ...]) -> list[dict[str, Any]]:
    from research.model_zoo.hofs_research_adapter_v1.contracts import (  # noqa: PLC0415
        PREDICTION_COLUMNS,
    )

    rows: list[dict[str, Any]] = []
    for block in blocks:
        for local, position in enumerate(block.source_row_positions):
            row = {
                "task_ordinal": 0,
                "task_seed": SPENT_SEED,
                "task_dgp": SPENT_DGP,
                "fold_index": block.fold_ordinal,
                "source_row_position": position,
                "entity_id": block.entity_ids[local],
                "decision_date": f"{block.decision_dates[local]}T00:00:00",
                "hofs_v7_expected_pe": block.expected_pe[local],
                "hofs_v7_pe_p10": block.pe_p10[local],
                "hofs_v7_pe_p90": block.pe_p90[local],
                "hofs_v7_log_scale": block.log_scale[local],
                "hofs_v7_tail_guard_weight": block.tail_guard_weight[local],
                "parameter_sha256": block.parameter_sha256,
                "decision_block_ordered_membership_sha256": (
                    block.decision_block_ordered_membership_sha256
                ),
                "decision_block_set_membership_sha256": (
                    block.decision_block_set_membership_sha256
                ),
                "decision_source_positions_sha256": (
                    block.decision_source_positions_sha256
                ),
                "output_manifest_sha256": block.output_manifest_sha256,
                "within_block_parameter_update_count": 0,
            }
            if tuple(row) != PREDICTION_COLUMNS:
                raise SpentSmokeError("reconstructed predecessor row schema drifted")
            rows.append(row)
    return rows


def run_spent_equivalence_no_publish() -> dict[str, Any]:
    """Run one spent-public task and compare every V7 numeric bit to frozen r2."""

    import pandas as pd  # noqa: PLC0415

    from research.model_zoo.hofs_research_adapter_v1.contracts import (  # noqa: PLC0415
        canonical_json_bytes as r2_canonical_json_bytes,
    )
    from research.model_zoo.hofs_v12_fresh_qualification_service_v1 import (  # noqa: PLC0415
        SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256,
        SPENT_RESEARCH_ONLY_DGP_ID,
        SPENT_RESEARCH_ONLY_SEED_ALIAS,
        compute_spent_research_only_task_artifact,
        current_windows_process_memory,
    )
    from research.model_zoo.hofs_v12_fresh_qualification_service_v1.contracts import (  # noqa: PLC0415
        canonical_json_bytes as service_canonical_json_bytes,
        validate_exact_json_primitives,
    )

    started = time.perf_counter_ns()
    files = _verify_fixed_files()
    canonical_raw = SPENT_CANONICAL.read_bytes()
    artifact = compute_spent_research_only_task_artifact(canonical_raw)
    input_receipt = artifact.input_receipt
    if (
        input_receipt.seed_alias != SPENT_RESEARCH_ONLY_SEED_ALIAS
        or input_receipt.dgp_id != SPENT_RESEARCH_ONLY_DGP_ID
        or input_receipt.canonical_raw_sha256
        != SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256
        or input_receipt.external_manifest_file_id_held_by_wrapper is not False
        or any(
            type(value) is not int or value != 0
            for value in (
                input_receipt.qualification_access_count,
                input_receipt.fresh_access_count,
                input_receipt.truth_access_count,
                input_receipt.heldout_access_count,
                input_receipt.score_access_count,
            )
        )
    ):
        raise SpentSmokeError("spent-research-only identity or zero-access receipt drifted")
    current_rows = _current_prediction_rows(artifact.blocks)
    current_rows_sha256 = hashlib.sha256(r2_canonical_json_bytes(current_rows)).hexdigest()

    predecessor = pd.read_csv(
        PREDECESSOR_ROOT / "PREDICTIONS.csv", float_precision="round_trip"
    )
    predecessor = predecessor.loc[
        (predecessor["task_seed"] == SPENT_SEED)
        & (predecessor["task_dgp"] == SPENT_DGP)
    ].reset_index(drop=True)
    if len(predecessor) != 1_296:
        raise SpentSmokeError("frozen predecessor task row universe drifted")
    numeric_columns = (
        "hofs_v7_expected_pe",
        "hofs_v7_pe_p10",
        "hofs_v7_pe_p90",
        "hofs_v7_log_scale",
        "hofs_v7_tail_guard_weight",
    )
    numeric_mismatches = 0
    identity_or_hash_mismatches = 0
    mismatch_examples: list[dict[str, Any]] = []
    for ordinal, current in enumerate(current_rows):
        prior = predecessor.iloc[ordinal]
        for column in numeric_columns:
            differs = _float_bits(current[column]) != _float_bits(prior[column])
            numeric_mismatches += int(bool(differs))
            if differs and len(mismatch_examples) < 5:
                mismatch_examples.append(
                    {
                        "row": ordinal,
                        "column": column,
                        "current": current[column],
                        "prior": float(prior[column]),
                        "current_bits": _float_bits(current[column]).hex(),
                        "prior_bits": _float_bits(prior[column]).hex(),
                    }
                )
        for column in (
            "task_ordinal",
            "task_seed",
            "task_dgp",
            "fold_index",
            "source_row_position",
            "entity_id",
            "decision_date",
            "parameter_sha256",
            "decision_block_ordered_membership_sha256",
            "decision_block_set_membership_sha256",
            "decision_source_positions_sha256",
            "output_manifest_sha256",
            "within_block_parameter_update_count",
        ):
            differs = current[column] != prior[column]
            identity_or_hash_mismatches += int(bool(differs))
            if differs and len(mismatch_examples) < 5:
                mismatch_examples.append(
                    {
                        "row": ordinal,
                        "column": column,
                        "current": current[column],
                        "prior": prior[column].item()
                        if hasattr(prior[column], "item")
                        else prior[column],
                    }
                )
    expected_log = tuple(math.log(float(value)) for value in predecessor["hofs_v7_expected_pe"])
    surface_log = tuple(float(value) for value in artifact.surface["hofs_r2_expected_log_pe"])
    surface_log_mismatches = sum(
        _float_bits(actual) != _float_bits(expected)
        for actual, expected in zip(surface_log, expected_log, strict=True)
    )
    if (
        current_rows_sha256 != EXPECTED_PREDECESSOR_TASK_ROWS_SHA256
        or numeric_mismatches
        or identity_or_hash_mismatches
        or surface_log_mismatches
    ):
        raise SpentSmokeError(
            "spent bitwise comparison failed: "
            f"current_digest={current_rows_sha256}, "
            f"expected_digest={EXPECTED_PREDECESSOR_TASK_ROWS_SHA256}, "
            f"numeric={numeric_mismatches}, identity={identity_or_hash_mismatches}, "
            f"log={surface_log_mismatches}, examples={mismatch_examples!r}"
        )
    ended = time.perf_counter_ns()
    memory = current_windows_process_memory()
    receipt = {
        "schema_version": "expected_pe.hofs_v12.spent_public_equivalence_smoke.v1",
        "status": "PASS_SPENT_PUBLIC_ONE_TASK_62_FOLD_BITWISE_EQUIVALENCE",
        "resource_resolution_lock_raw_sha256": FIXED_FILE_PINS[RESOURCE_LOCK],
        "spent_seed": SPENT_SEED,
        "spent_dgp": SPENT_DGP,
        "fold_count": len(artifact.blocks),
        "prediction_row_count": len(current_rows),
        "bitwise_numeric_comparison_count": len(current_rows) * len(numeric_columns),
        "bitwise_numeric_mismatch_count": numeric_mismatches,
        "identity_or_hash_mismatch_count": identity_or_hash_mismatches,
        "surface_log_bitwise_mismatch_count": surface_log_mismatches,
        "current_prediction_rows_sha256": current_rows_sha256,
        "frozen_r2_prediction_rows_sha256": EXPECTED_PREDECESSOR_TASK_ROWS_SHA256,
        "resource_envelope": artifact.resource_envelope,
        "fixed_file_records": files,
        "elapsed_ns": ended - started,
        "peak_process_rss_bytes": memory["peak_rss_bytes"],
        "publication_count": 0,
        "qualification_access_count": 0,
        "fresh_access_count": 0,
        "truth_artifact_access_count": 0,
        "heldout_access_count": 0,
        "score_artifact_access_count": 0,
        "upstream_score_named_numeric_use_count": 0,
    }
    validate_exact_json_primitives(receipt)
    raw = service_canonical_json_bytes(receipt)
    return {**receipt, "receipt_raw_sha256": hashlib.sha256(raw).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=("resource-preflight", "spent-equivalence-no-publish"),
    )
    arguments = parser.parse_args()
    if arguments.mode == "resource-preflight":
        from research.model_zoo.hofs_v12_fresh_qualification_service_v1 import (  # noqa: PLC0415
            run_native_16_worker_resource_preflight,
        )

        receipt = run_native_16_worker_resource_preflight()
    else:
        receipt = run_spent_equivalence_no_publish()
    from research.model_zoo.hofs_v12_fresh_qualification_service_v1.contracts import (  # noqa: PLC0415
        validate_exact_json_primitives,
    )

    validate_exact_json_primitives(receipt)
    raw = (
        json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
