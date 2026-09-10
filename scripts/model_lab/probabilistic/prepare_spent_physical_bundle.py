from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seal the exact formal physical-evaluator bundle without opening truth"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--pointer", type=Path, required=True)
    parser.add_argument("--execution-request", type=Path, required=True)
    parser.add_argument("--expected-execution-request-sha256", required=True)
    parser.add_argument("--independent-go", type=Path, required=True)
    parser.add_argument("--expected-independent-go-sha256", required=True)
    parser.add_argument("--candidate-surface", type=Path, action="append", required=True)
    parser.add_argument("--reference-surface", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import FORMAL_SCOPE
    from pe_regime_v04.model_lab.probabilistic.contracts import verify_payload_seal
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        load_formal_launch_authority,
        verify_externally_pinned_pointer,
    )
    from pe_regime_v04.model_lab.probabilistic.physical_evaluator import HANDOFF_SPEC_SCHEMA
    from pe_regime_v04.model_lab.probabilistic.references import REFERENCE_IDS
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS
    from pe_regime_v04.model_lab.probabilistic.spent import UPSTREAM_INPUTS

    pointer_path = args.pointer if args.pointer.is_absolute() else root / args.pointer
    execution_request_path = (
        args.execution_request
        if args.execution_request.is_absolute()
        else root / args.execution_request
    )
    independent_go_path = (
        args.independent_go if args.independent_go.is_absolute() else root / args.independent_go
    )
    launch_authority = load_formal_launch_authority(
        execution_request_path=execution_request_path,
        expected_execution_request_sha256=args.expected_execution_request_sha256,
        independent_go_path=independent_go_path,
        expected_independent_go_sha256=args.expected_independent_go_sha256,
        repo_root=root,
    )
    pointer = verify_externally_pinned_pointer(
        pointer_path,
        request=launch_authority.request,
    )
    if (
        pointer.get("authorization_scope") != FORMAL_SCOPE
        or pointer.get("truth_path_present") is not False
    ):
        raise RuntimeError("formal prediction pointer is invalid or exposes truth")
    candidates = {}
    for value in args.candidate_surface:
        path = value if value.is_absolute() else root / value
        surface = json.loads(path.read_bytes())
        verify_payload_seal(surface)
        model_id = surface.get("model_id")
        if (
            model_id in candidates
            or surface.get("status") != "PASS_FULL_MASK_FORMAL_PREDICTION_CUSTODY"
            or surface.get("authorization_raw_sha256") != pointer["authorization_raw_sha256"]
            or surface.get("activation_raw_sha256") != pointer["formal_activation_raw_sha256"]
            or surface.get("external_execution_request_raw_sha256")
            != launch_authority.request.raw_sha256
            or surface.get("independent_go_raw_sha256")
            != launch_authority.independent_go.raw_sha256
            or surface.get("truth_bytes_read") is not False
        ):
            raise RuntimeError("candidate surface differs from formal custody")
        candidates[model_id] = surface
    if set(candidates) != set(CANDIDATE_IDS):
        raise RuntimeError("physical bundle requires exactly all three candidates")
    reference_path = (
        args.reference_surface
        if args.reference_surface.is_absolute()
        else root / args.reference_surface
    )
    references = json.loads(reference_path.read_bytes())
    verify_payload_seal(references)
    if (
        references.get("status") != "PASS_FULL_MASK_CAUSAL_REFERENCE_CUSTODY"
        or set(references.get("records", {})) != set(REFERENCE_IDS)
        or references.get("authorization_raw_sha256") != pointer["authorization_raw_sha256"]
        or references.get("activation_raw_sha256") != pointer["formal_activation_raw_sha256"]
        or references.get("external_execution_request_raw_sha256")
        != launch_authority.request.raw_sha256
        or references.get("independent_go_raw_sha256") != launch_authority.independent_go.raw_sha256
        or references.get("truth_bytes_read") is not False
    ):
        raise RuntimeError("reference surface differs from formal custody")
    payload = {
        "schema_version": HANDOFF_SPEC_SCHEMA,
        "authorization_pointer_path": pointer_path.relative_to(root).as_posix(),
        "external_execution_request_path": execution_request_path.relative_to(root).as_posix(),
        "external_execution_request_raw_sha256": launch_authority.request.raw_sha256,
        "independent_go_path": independent_go_path.relative_to(root).as_posix(),
        "independent_go_raw_sha256": launch_authority.independent_go.raw_sha256,
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
                "prediction_path": references["records"][reference_id]["prediction_path"],
                "receipt_path": references["records"][reference_id]["receipt_path"],
                "execution_receipt_path": references["records"][reference_id][
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
        
        "truth_path": UPSTREAM_INPUTS["evaluate"]["path"],
        "truth_manifest_expected_raw_sha256": UPSTREAM_INPUTS["evaluate"]["raw_sha256"],
        "truth_parent_read": False,
        "synthetic_only": False,
        "formal_execution_authorized": True,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
    }
    output = args.output if args.output.is_absolute() else root / args.output
    immutable_write_json(output, payload)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
