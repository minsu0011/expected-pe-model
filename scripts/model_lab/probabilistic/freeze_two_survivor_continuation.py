from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Freeze the score-free V3 two-survivor continuation audit candidate"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--activation-directory", type=Path, default=Path("outputs/p5s/v3/a")
    )
    parser.add_argument(
        "--audit-directory",
        type=Path,
        default=Path(
            "outputs/model_zoo_probabilistic_wave_two_survivor_continuation_v2_20260819"
        ),
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))

    from pe_regime_v04.model_lab.probabilistic.artifacts import (
        checksum_manifest,
        immutable_write_json,
        immutable_write_text,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
        seal_payload,
        sha256_bytes,
    )
    from pe_regime_v04.model_lab.probabilistic.custody import (
        write_content_addressed_json,
    )
    from pe_regime_v04.model_lab.probabilistic.source_closure import (
        build_source_closure_payload,
    )
    from pe_regime_v04.model_lab.probabilistic.two_survivor_continuation import (
        BROKEN_CANDIDATE_ID,
        CONTINUATION_GO_SCHEMA,
        CONTINUATION_POINTER_SCHEMA,
        SURVIVOR_IDS,
        V2_ROOTS,
        REGISTRY_TERMINAL_STATE,
        build_continuation_activation_payload,
        build_continuation_request_payload,
        continuation_policy,
        frozen_comparator_custody,
        frozen_registry_terminal_state,
        frozen_survivor_custody,
        frozen_v2_roots,
        load_continuation_activation,
        load_continuation_request,
        load_verified_terminal_custody,
    )

    activation_directory = args.activation_directory
    if not activation_directory.is_absolute():
        activation_directory = root / activation_directory
    audit_directory = args.audit_directory
    if not audit_directory.is_absolute():
        audit_directory = root / audit_directory

    forbidden_outputs = tuple(
        root / relative
        for relative in (
            "outputs/p5s/c/2",
            "outputs/p5s/r",
            "outputs/p5s/e",
            "outputs/p5s/h",
            "outputs/p5s/v3/r",
            "outputs/p5s/v3/b",
            "outputs/p5s/v3/e",
            "outputs/p5s/v3/h",
        )
    )
    if any(path.exists() for path in forbidden_outputs):
        raise RuntimeError(
            "continuation freeze requires NGBoost/reference/truth/evaluator custody to remain absent"
        )

    load_verified_terminal_custody(root)
    source_path = write_content_addressed_json(
        activation_directory,
        "TWO_SURVIVOR_SOURCE_SNAPSHOT",
        build_source_closure_payload(root),
    )
    source_raw_sha256 = sha256_bytes(source_path.read_bytes())
    source_relative = source_path.relative_to(root).as_posix()
    activation_payload = build_continuation_activation_payload(
        source_snapshot_path=source_relative,
        source_snapshot_raw_sha256=source_raw_sha256,
    )
    activation_path = write_content_addressed_json(
        activation_directory,
        "TWO_SURVIVOR_CONTINUATION_ACTIVATION",
        activation_payload,
    )
    activation_raw_sha256 = sha256_bytes(activation_path.read_bytes())
    activation_relative = activation_path.relative_to(root).as_posix()
    activation = load_continuation_activation(
        activation_path,
        expected_raw_sha256=activation_raw_sha256,
        repo_root=root,
    )

    request_payload = build_continuation_request_payload(
        activation_path=activation_relative,
        activation_raw_sha256=activation_raw_sha256,
        source_snapshot_path=source_relative,
        source_snapshot_raw_sha256=source_raw_sha256,
    )
    request_path = write_content_addressed_json(
        activation_directory,
        "TWO_SURVIVOR_EXTERNAL_REQUEST",
        request_payload,
    )
    request_raw_sha256 = sha256_bytes(request_path.read_bytes())
    request_relative = request_path.relative_to(root).as_posix()
    load_continuation_request(
        request_path,
        expected_raw_sha256=request_raw_sha256,
        activation=activation,
    )

    pointer_payload = seal_payload(
        {
            "schema_version": CONTINUATION_POINTER_SCHEMA,
            "status": "INACTIVE_PENDING_INDEPENDENT_GO",
            "formal": False,
            "activation": {
                "path": activation_relative,
                "raw_sha256": activation_raw_sha256,
            },
            "external_request": {
                "path": request_relative,
                "raw_sha256": request_raw_sha256,
            },
            "source_snapshot": {
                "path": source_relative,
                "raw_sha256": source_raw_sha256,
            },
            "survivor_ids": list(SURVIVOR_IDS),
            "broken_candidate_id": BROKEN_CANDIDATE_ID,
            "v2_roots": frozen_v2_roots(),
            "survivor_custody": frozen_survivor_custody(),
            "comparator_custody": frozen_comparator_custody(),
            "terminal_registry_state": frozen_registry_terminal_state(),
            "truth_path_present": False,
            "reference_path_present": False,
            "bundle_path_present": False,
            "evaluator_path_present": False,
            "heavy_compute_authorized": False,
            "score_computation_authorized": False,
            "fresh_seed_reserved_or_opened": False,
            "heldout_opened": False,
        }
    )
    pointer_path = write_content_addressed_json(
        activation_directory,
        "TWO_SURVIVOR_CONTINUATION_POINTER",
        pointer_payload,
    )
    pointer_raw_sha256 = sha256_bytes(pointer_path.read_bytes())

    expected_go_bindings = {
        "activation_raw_sha256": activation_raw_sha256,
        "request_raw_sha256": request_raw_sha256,
        "source_snapshot_raw_sha256": source_raw_sha256,
        "v2_go_raw_sha256": V2_ROOTS["v2_independent_go"]["raw_sha256"],
        "terminal_failure_receipt_raw_sha256": V2_ROOTS[
            "terminal_failure_receipt"
        ]["raw_sha256"],
        "terminal_failure_audit_raw_sha256": V2_ROOTS["terminal_failure_audit"][
            "raw_sha256"
        ],
        "terminal_failure_audit_logical_sha256": V2_ROOTS[
            "terminal_failure_audit"
        ]["logical_sha256"],
        "terminal_registry_append_raw_sha256": REGISTRY_TERMINAL_STATE[
            "append_receipt"
        ]["raw_sha256"],
        "model_registry_csv_raw_sha256": REGISTRY_TERMINAL_STATE[
            "model_registry_csv"
        ]["raw_sha256"],
        "model_registry_json_raw_sha256": REGISTRY_TERMINAL_STATE[
            "model_registry_json"
        ]["raw_sha256"],
        "model_registry_logical_sha256": REGISTRY_TERMINAL_STATE[
            "model_registry_json"
        ]["logical_sha256"],
    }
    audit_request = seal_payload(
        {
            "schema_version": (
                "expected_pe_model_zoo.probabilistic_two_survivor_audit_request.v1"
            ),
            "status": "INDEPENDENT_AUDIT_REQUIRED",
            "design_sha256": PROBABILISTIC_DESIGN_SHA256,
            "activation_path": activation_relative,
            "activation_raw_sha256": activation_raw_sha256,
            "external_request_path": request_relative,
            "external_request_raw_sha256": request_raw_sha256,
            "pointer_path": pointer_path.relative_to(root).as_posix(),
            "pointer_raw_sha256": pointer_raw_sha256,
            "source_snapshot_path": source_relative,
            "source_snapshot_raw_sha256": source_raw_sha256,
            "required_independent_go_contract": {
                "schema_version": CONTINUATION_GO_SCHEMA,
                "status": "FINAL_GO",
                "bindings": expected_go_bindings,
                "survivor_ids": list(SURVIVOR_IDS),
                "broken_candidate_id": BROKEN_CANDIDATE_ID,
                "decision": {
                    "two_survivor_continuation": "GO",
                    "p0_count": 0,
                    "p1_count": 0,
                    "candidate_refit_or_retry_authorized": False,
                    "reference_generation_authorized": True,
                    "separate_truth_child_authorized_after_complete_bundle": True,
                    "score_before_complete_bundle_authorized": False,
                },
                "fresh_seed_reserved_or_opened": False,
                "heldout_opened": False,
                "manifest_sha256": "COMPUTE_AFTER_INDEPENDENT_AUTHORING",
            },
            "formal": False,
            "reference_truth_or_score_generated": False,
            "heavy_compute_performed": False,
            "registry_modified": False,
        }
    )
    audit_request_path = audit_directory / "AUDIT_REQUEST.json"
    publication_path = audit_directory / "PUBLICATION.json"
    report_path = audit_directory / "REPORT.md"
    checksums_path = audit_directory / "CHECKSUMS.sha256"
    immutable_write_json(audit_request_path, audit_request, sealed=False)
    publication = seal_payload(
        {
            "schema_version": (
                "expected_pe_model_zoo.probabilistic_two_survivor_publication.v1"
            ),
            "status": "SCORE_FREE_AUDIT_CANDIDATE_NOT_FORMAL_GO",
            "formal": False,
            "activation": {
                "path": activation_relative,
                "raw_sha256": activation_raw_sha256,
            },
            "external_request": {
                "path": request_relative,
                "raw_sha256": request_raw_sha256,
            },
            "pointer": {
                "path": pointer_path.relative_to(root).as_posix(),
                "raw_sha256": pointer_raw_sha256,
            },
            "source_snapshot": {
                "path": source_relative,
                "raw_sha256": source_raw_sha256,
            },
            "v2_go_raw_sha256": V2_ROOTS["v2_independent_go"]["raw_sha256"],
            "failure_receipt_raw_sha256": V2_ROOTS["terminal_failure_receipt"][
                "raw_sha256"
            ],
            "terminal_audit_raw_sha256": V2_ROOTS["terminal_failure_audit"][
                "raw_sha256"
            ],
            "terminal_audit_logical_sha256": V2_ROOTS["terminal_failure_audit"][
                "logical_sha256"
            ],
            "terminal_registry_state": frozen_registry_terminal_state(),
            "survivor_ids": list(SURVIVOR_IDS),
            "broken_candidate": BROKEN_CANDIDATE_ID,
            "policy": continuation_policy(),
            "independent_go_required": True,
            "reference_truth_or_score_generated": False,
            "heavy_compute_performed": False,
            "registry_modified": False,
        }
    )
    immutable_write_json(publication_path, publication, sealed=False)
    immutable_write_text(
        report_path,
        "# Probabilistic V3 two-survivor continuation\n\n"
        "Status: `SCORE_FREE_AUDIT_CANDIDATE_NOT_FORMAL_GO`.\n\n"
        "The exact V2 qlinear and qhist prediction, prediction-receipt, and runtime "
        "bytes are imported without refit. NGBoost is permanently excluded as BROKEN. "
        "The historical V2 launch authority is centrally revoked. New reference, bundle, "
        "and evaluator gates require exact 2 candidate receipts, 2 reference participants, "
        "2 comparator receipts, 2 candidate runtime receipts, and 1 global runtime receipt. "
        "No reference, truth, score, fresh seed, heldout, registry write, or heavy compute "
        "occurred while freezing this candidate.\n",
    )
    checksum_inputs = (
        source_path,
        activation_path,
        request_path,
        pointer_path,
        audit_request_path,
        publication_path,
        report_path,
    )
    immutable_write_text(
        checksums_path,
        checksum_manifest(checksum_inputs, root=root),
    )
    result = {
        "status": "SCORE_FREE_AUDIT_CANDIDATE_NOT_FORMAL_GO",
        "formal": False,
        "activation_path": activation_relative,
        "activation_raw_sha256": activation_raw_sha256,
        "external_request_path": request_relative,
        "external_request_raw_sha256": request_raw_sha256,
        "pointer_path": pointer_path.relative_to(root).as_posix(),
        "pointer_raw_sha256": pointer_raw_sha256,
        "source_snapshot_path": source_relative,
        "source_snapshot_raw_sha256": source_raw_sha256,
        "audit_request_path": audit_request_path.relative_to(root).as_posix(),
        "audit_request_raw_sha256": sha256_bytes(audit_request_path.read_bytes()),
        "publication_path": publication_path.relative_to(root).as_posix(),
        "publication_raw_sha256": sha256_bytes(publication_path.read_bytes()),
        "checksums_raw_sha256": sha256_bytes(checksums_path.read_bytes()),
        "reference_truth_or_score_generated": False,
        "heavy_compute_performed": False,
    }
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
