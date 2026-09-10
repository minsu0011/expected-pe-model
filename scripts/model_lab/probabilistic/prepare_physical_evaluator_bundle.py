from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal V4 physical evaluator bundle spec")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--candidate-surface", type=Path, action="append", required=True)
    parser.add_argument("--reference-surface", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.contracts import verify_payload_seal
    from pe_regime_v04.model_lab.probabilistic.physical_evaluator import (
        HANDOFF_SPEC_SCHEMA,
    )
    from pe_regime_v04.model_lab.probabilistic.references import REFERENCE_IDS
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS

    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
    verify_payload_seal(pointer)
    candidates: dict[str, object] = {}
    for surface_arg in args.candidate_surface:
        path = surface_arg if surface_arg.is_absolute() else root / surface_arg
        surface = json.loads(path.read_text(encoding="utf-8"))
        verify_payload_seal(surface)
        candidates.update(surface["records"])
    if set(candidates) != set(CANDIDATE_IDS):
        raise RuntimeError("candidate surfaces do not cover exactly three candidates")
    reference_path = (
        args.reference_surface
        if args.reference_surface.is_absolute()
        else root / args.reference_surface
    )
    reference_surface = json.loads(reference_path.read_text(encoding="utf-8"))
    verify_payload_seal(reference_surface)
    if set(reference_surface["records"]) != set(REFERENCE_IDS):
        raise RuntimeError("reference surface does not cover exactly two references")
    payload = {
        "schema_version": HANDOFF_SPEC_SCHEMA,
        "authorization_pointer_path": pointer_path.relative_to(root).as_posix(),
        "common_mask_path": pointer["common_mask_path"],
        "candidates": {
            model_id: {
                "prediction_path": candidates[model_id]["prediction_path"],
                "receipt_path": candidates[model_id]["receipt_path"],
                "runtime_receipt_path": candidates[model_id]["runtime_receipt_path"],
            }
            for model_id in CANDIDATE_IDS
        },
        "references": {
            reference_id: {
                "prediction_path": reference_surface["records"][reference_id]["prediction_path"],
                "receipt_path": reference_surface["records"][reference_id]["receipt_path"],
                "execution_receipt_path": reference_surface["records"][reference_id][
                    "execution_receipt_path"
                ],
            }
            for reference_id in REFERENCE_IDS
        },
        "comparators": {
            "v04_expected_pe": {
                "prediction_path": pointer["v04_comparator_path"],
                "receipt_path": pointer["v04_comparator_receipt_path"],
            },
            "ml_expected_pe": {
                "prediction_path": pointer["ml_comparator_path"],
                "receipt_path": pointer["ml_comparator_receipt_path"],
            },
        },
        "truth_path": pointer["truth_path"],
        "synthetic_only": True,
        "formal_execution_authorized": False,
    }
    output = args.output if args.output.is_absolute() else root / args.output
    immutable_write_json(output, payload)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
