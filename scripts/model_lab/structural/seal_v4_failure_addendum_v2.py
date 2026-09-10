"""Supersede the V4 failure receipt's overly broad affected-fold statement."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.models.wave1.artifacts import (  # noqa: E402
    load_predict_inputs,
    load_wave1_seed_frames,
)
from pe_regime_v04.model_lab.folds import generate_pit_folds  # noqa: E402
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_file,
    verify_payload_seal,
)
from pe_regime_v04.model_lab.structural.nested import (  # noqa: E402
    FORMAL_OUTER_FOLD_SPEC,
)


OLD = ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json"
OUTPUT = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/"
    "V4_FAILED_ATTEMPT_ADDENDUM_V2.json"
)
OLD_RAW = "d8b6723854ce03a897bbef6febcc8e5bae0654896c3f73a1bcaddeabe4544cb8"
OLD_LOGICAL = "453e3f4939c15a38dedccc603b839fc57b34eaf43401ffbb6f032e6697e9b8bd"


def main() -> int:
    old = json.loads(OLD.read_text(encoding="utf-8"))
    verify_payload_seal(old)
    if sha256_file(OLD) != OLD_RAW or old["manifest_sha256"] != OLD_LOGICAL:
        raise RuntimeError("old V4 failure receipt changed")
    manifest = load_predict_inputs(
        ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
    )
    rows = []
    for seed_row in manifest["seeds"]:
        frame, _ = load_wave1_seed_frames(seed_row)
        folds = generate_pit_folds(
            frame.loc[:, ["date"]],
            FORMAL_OUTER_FOLD_SPEC,
            date_column="date",
        )[12:]
        invalid = {0, 1}
        affected = [fold.fold_id for fold in folds if invalid.issubset(set(fold.train_positions))]
        rows.append(
            {
                "seed": int(seed_row["seed"]),
                "invalid_target_positions": [0, 1],
                "affected_fold_ids": affected,
                "first_unaffected_fold_id": next(
                    fold.fold_id for fold in folds if invalid.isdisjoint(set(fold.train_positions))
                ),
            }
        )
    expected = [f"fold_{index:03d}" for index in range(12, 37)]
    if any(row["affected_fold_ids"] != expected for row in rows):
        raise RuntimeError("corrected affected-fold audit changed")
    payload = seal_payload(
        {
            "format_version": 2,
            "mode": "structural_v4_terminal_failure_receipt_addendum",
            "supersedes_fold_scope_only": {
                "path": OLD.relative_to(ROOT).as_posix(),
                "raw_sha256": OLD_RAW,
                "logical_sha256": OLD_LOGICAL,
            },
            "correction": {
                "old_statement": "all 62 required folds affected",
                "correct_statement": (
                    "rolling max_train_size=1008 retains positions 0/1 only in folds 012..036; "
                    "fold 037 starts training at position 21"
                ),
                "per_seed": rows,
                "affected_fold_count_per_seed": 25,
                "unaffected_fold_count_per_seed": 37,
                "v4_payload_effect": (
                    "each decomposition candidate-by-seed payload began at fold_012 and failed "
                    "there, so the entire payload published no rows"
                ),
            },
            "unchanged_findings": {
                "status": "TERMINAL_FAILED_NO_PREDICTION_ARTIFACT",
                "evaluation_truth_opened": False,
                "scores_computed": False,
                "relaunch_authorized": False,
            },
        }
    )
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
