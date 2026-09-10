from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Atomically pin the exact V5 five-seed formal spent-screen policy"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--input-manifest",
        type=Path,
        default=Path("outputs/p5s/i/SPENT_PREDICT_INPUTS_MANIFEST.json"),
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("outputs/p5s/a2"),
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    input_manifest_path = args.input_manifest
    if not input_manifest_path.is_absolute():
        input_manifest_path = root / input_manifest_path
    output = args.output_directory
    if not output.is_absolute():
        output = root / output
    spent_root = root / "outputs/p5s"
    custody_directories = (spent_root / "c", spent_root / "r")
    if any(path.exists() and any(path.rglob("*")) for path in custody_directories):
        raise RuntimeError("formal activation must be published before any prediction custody")

    from pe_regime_v04.model_lab.probabilistic.adapters import (
        adapter_binding_sha256_by_id,
        candidate_environment_sha256_by_id,
    )
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import (
        FORMAL_SCOPE,
        build_execution_authorization_payload,
        load_execution_authorization,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
        seal_payload,
        sha256_bytes,
        sha256_file,
        verify_payload_seal,
    )
    from pe_regime_v04.model_lab.probabilistic.custody import (
        load_verified_pit_features,
        load_verified_point_comparator,
        load_verified_training_labels,
        seal_point_comparator_custody_receipt,
        write_content_addressed_json,
    )
    from pe_regime_v04.model_lab.probabilistic.formal_pins import (
        EXECUTION_REQUEST_SCHEMA,
        PRIOR_EXTERNAL_ROOTS,
        PRIOR_NO_GO,
    )
    from pe_regime_v04.model_lab.probabilistic.references import (
        load_verified_point_prediction_history,
        reference_binding_sha256_by_id,
    )
    from pe_regime_v04.model_lab.probabilistic.source_closure import (
        build_source_closure_payload,
    )
    from pe_regime_v04.model_lab.probabilistic.spent import (
        FORMAL_ACTIVATION_SCHEMA,
        INDEPENDENT_GO,
        UPSTREAM_INPUTS,
        V5_ROOTS,
        exact_policy,
        verify_fixed_external_authorities,
    )

    verify_fixed_external_authorities(root, include_evaluation_input=True)
    try:
        input_manifest_raw = input_manifest_path.read_bytes()
        input_manifest = json.loads(input_manifest_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("spent prediction input manifest is unavailable") from exc
    verify_payload_seal(input_manifest)
    if (
        input_manifest.get("status") != "SEALED_TRUTH_BLIND_INPUT_CUSTODY"
        or input_manifest.get("evaluation_manifest_read") is not False
        or input_manifest.get("truth_bytes_read") is not False
    ):
        raise RuntimeError("spent prediction input custody is not truth-blind")
    artifact_records = input_manifest.get("artifacts")
    required_artifacts = {
        "feature",
        "label",
        "identity",
        "point_history",
        "v04_comparator",
        "ml_comparator",
        "role",
        "common_mask",
        "feature_provenance",
    }
    if not isinstance(artifact_records, dict) or set(artifact_records) != required_artifacts:
        raise RuntimeError("spent prediction input artifact set differs")

    paths: dict[str, Path] = {}
    for name, record in artifact_records.items():
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            raise RuntimeError(f"spent artifact record differs: {name}")
        path = (root / record["path"]).resolve()
        raw = path.read_bytes()
        if len(raw) != record["bytes"] or sha256_bytes(raw) != record["sha256"]:
            raise RuntimeError(f"spent artifact bytes differ: {name}")
        paths[name] = path

    source_path = write_content_addressed_json(
        output, "SPENT_FORMAL_SOURCE_SNAPSHOT", build_source_closure_payload(root)
    )
    bindings = {
        "adapter_binding_sha256_by_id": adapter_binding_sha256_by_id(),
        "candidate_source_snapshot_sha256": sha256_file(source_path),
        "comparator_prediction_sha256_by_id": {
            "point_history": sha256_file(paths["point_history"]),
            "v04_expected_pe": sha256_file(paths["v04_comparator"]),
            "ml_expected_pe": sha256_file(paths["ml_comparator"]),
        },
        # The evaluator manifest binds the five source truth payloads.  Its path
        # is deliberately absent from the truth-blind prediction pointer.
        "detached_truth_manifest_sha256": UPSTREAM_INPUTS["evaluate"]["raw_sha256"],
        "environment_manifest_sha256_by_id": candidate_environment_sha256_by_id(),
        "feature_artifact_raw_sha256": sha256_file(paths["feature"]),
        "feature_provenance_sha256": sha256_file(paths["feature_provenance"]),
        "probabilistic_reference_sha256_by_id": reference_binding_sha256_by_id(),
        "spent_role_authorization_sha256": sha256_file(paths["role"]),
        "training_label_artifact_raw_sha256": sha256_file(paths["label"]),
    }
    authorization_payload = build_execution_authorization_payload(
        identity_raw=paths["identity"].read_bytes(),
        bindings=bindings,
        authorization_scope=FORMAL_SCOPE,
        formal_execution_authorized=True,
        synthetic_evaluation_authorized=False,
    )
    authorization_path = write_content_addressed_json(
        output, "SPENT_FORMAL_EXECUTION_AUTHORIZATION", authorization_payload
    )
    authorization_sha256 = sha256_file(authorization_path)
    required_bindings = authorization_payload["required_bindings"]
    activation_payload = seal_payload(
        {
            "schema_version": FORMAL_ACTIVATION_SCHEMA,
            "design_sha256": PROBABILISTIC_DESIGN_SHA256,
            "status": "ACTIVE_BEFORE_ANY_PROBABILISTIC_PREDICTION",
            "independent_go": INDEPENDENT_GO,
            "v5_roots": V5_ROOTS,
            "upstream_inputs": UPSTREAM_INPUTS,
            "policy": exact_policy(),
            "formal_authorization_raw_sha256": authorization_sha256,
            "formal_source_snapshot_raw_sha256": sha256_file(source_path),
            "formal_identity_raw_sha256": sha256_file(paths["identity"]),
            "formal_required_bindings": required_bindings,
            "predecessor_external_roots": PRIOR_EXTERNAL_ROOTS,
            "prior_no_go": PRIOR_NO_GO,
            "predict_input_manifest_raw_sha256": sha256_bytes(input_manifest_raw),
            "probabilistic_predictions_existed_before_activation": False,
            "published_before_prediction": True,
        }
    )
    activation_path = write_content_addressed_json(
        output, "FORMAL_ACTIVATION_POLICY_PIN", activation_payload
    )
    activation_sha256 = sha256_file(activation_path)
    authorization = load_execution_authorization(
        authorization_path,
        paths["identity"],
        source_path,
        expected_precommit_sha256=authorization_sha256,
        require_formal=True,
        formal_activation_path=activation_path,
        expected_formal_activation_sha256=activation_sha256,
    )
    load_verified_pit_features(
        paths["feature"], paths["feature_provenance"], authorization=authorization
    )
    load_verified_training_labels(paths["label"], authorization=authorization)
    load_verified_point_prediction_history(
        paths["point_history"], authorization=authorization, comparator_id="point_history"
    )
    comparator_receipts: dict[str, Path] = {}
    for comparator_id, key in (
        ("v04_expected_pe", "v04_comparator"),
        ("ml_expected_pe", "ml_comparator"),
    ):
        artifact = load_verified_point_comparator(
            paths[key], comparator_id=comparator_id, authorization=authorization
        )
        comparator_receipts[comparator_id] = seal_point_comparator_custody_receipt(
            artifact, output, authorization=authorization
        )

    pointer_payload = seal_payload(
        {
            "schema_version": "expected_pe_model_zoo.probabilistic_formal_pointer.v1",
            "authorization_scope": FORMAL_SCOPE,
            "authorization_path": authorization_path.relative_to(root).as_posix(),
            "authorization_raw_sha256": authorization_sha256,
            "formal_activation_path": activation_path.relative_to(root).as_posix(),
            "formal_activation_raw_sha256": activation_sha256,
            "source_snapshot_path": source_path.relative_to(root).as_posix(),
            "source_snapshot_raw_sha256": sha256_file(source_path),
            "identity_path": paths["identity"].relative_to(root).as_posix(),
            "identity_raw_sha256": sha256_file(paths["identity"]),
            "common_mask_path": paths["common_mask"].relative_to(root).as_posix(),
            "common_mask_raw_sha256": sha256_file(paths["common_mask"]),
            "feature_path": paths["feature"].relative_to(root).as_posix(),
            "feature_raw_sha256": sha256_file(paths["feature"]),
            "feature_provenance_path": paths["feature_provenance"].relative_to(root).as_posix(),
            "feature_provenance_raw_sha256": sha256_file(paths["feature_provenance"]),
            "training_label_path": paths["label"].relative_to(root).as_posix(),
            "training_label_raw_sha256": sha256_file(paths["label"]),
            "point_history_path": paths["point_history"].relative_to(root).as_posix(),
            "point_history_raw_sha256": sha256_file(paths["point_history"]),
            "v04_comparator_path": paths["v04_comparator"].relative_to(root).as_posix(),
            "v04_comparator_raw_sha256": sha256_file(paths["v04_comparator"]),
            "v04_comparator_receipt_path": comparator_receipts["v04_expected_pe"]
            .relative_to(root)
            .as_posix(),
            "v04_comparator_receipt_raw_sha256": sha256_file(
                comparator_receipts["v04_expected_pe"]
            ),
            "ml_comparator_path": paths["ml_comparator"].relative_to(root).as_posix(),
            "ml_comparator_raw_sha256": sha256_file(paths["ml_comparator"]),
            "ml_comparator_receipt_path": comparator_receipts["ml_expected_pe"]
            .relative_to(root)
            .as_posix(),
            "ml_comparator_receipt_raw_sha256": sha256_file(comparator_receipts["ml_expected_pe"]),
            "role_path": paths["role"].relative_to(root).as_posix(),
            "role_raw_sha256": sha256_file(paths["role"]),
            "predecessor_external_roots": PRIOR_EXTERNAL_ROOTS,
            "prior_no_go": PRIOR_NO_GO,
            "truth_path_present": False,
            "prediction_execution_authorized": True,
            "score_computation_authorized": False,
            "fresh_seed_reserved_or_opened": False,
            "heldout_opened": False,
        }
    )
    pointer_path = write_content_addressed_json(
        output, "SPENT_FORMAL_AUTHORIZATION_POINTER", pointer_payload
    )
    superseding_roots = {
        "pointer_raw_sha256": sha256_file(pointer_path),
        "activation_raw_sha256": activation_sha256,
        "authorization_raw_sha256": authorization_sha256,
        "source_snapshot_raw_sha256": sha256_file(source_path),
        "predict_input_manifest_raw_sha256": sha256_bytes(input_manifest_raw),
    }
    execution_request_payload = seal_payload(
        {
            "schema_version": EXECUTION_REQUEST_SCHEMA,
            "design_sha256": PROBABILISTIC_DESIGN_SHA256,
            "status": "SUPERSEDING_CHAIN_AUDIT_CANDIDATE",
            "predecessor_external_roots": PRIOR_EXTERNAL_ROOTS,
            "prior_no_go": PRIOR_NO_GO,
            "superseding_roots": superseding_roots,
            "same_pin_required_by_candidate_reference_bundle_parent_child": True,
            "independent_go_required_before_compute": True,
            "heavy_compute_authorized_by_request_alone": False,
            "fresh_seed_reserved_or_opened": False,
            "heldout_opened": False,
        }
    )
    execution_request_path = write_content_addressed_json(
        output,
        "FORMAL_EXTERNAL_EXECUTION_REQUEST",
        execution_request_payload,
    )
    publication = {
        "schema_version": "expected_pe_model_zoo.probabilistic_activation_publication.v2",
        "status": "SUPERSEDING_FORMAL_SPENT_SCREEN_AUDIT_CANDIDATE",
        "activation_path": activation_path.relative_to(root).as_posix(),
        "activation_raw_sha256": activation_sha256,
        "authorization_path": authorization_path.relative_to(root).as_posix(),
        "authorization_raw_sha256": authorization_sha256,
        "pointer_path": pointer_path.relative_to(root).as_posix(),
        "pointer_raw_sha256": sha256_file(pointer_path),
        "source_snapshot_raw_sha256": sha256_file(source_path),
        "execution_request_path": execution_request_path.relative_to(root).as_posix(),
        "execution_request_raw_sha256": sha256_file(execution_request_path),
        "predecessor_external_roots": PRIOR_EXTERNAL_ROOTS,
        "prior_no_go": PRIOR_NO_GO,
        "independent_go_required_before_compute": True,
        "heavy_compute_authorized": False,
        "prediction_custody_absent_at_publication": True,
        "policy": exact_policy(),
    }
    publication_path = (
        root / "outputs/model_zoo_probabilistic_wave_spent_screen_20260819/"
        "FORMAL_ACTIVATION_PUBLICATION_V2.json"
    )
    immutable_write_json(publication_path, publication)
    print(
        json.dumps(
            {
                "status": "SUPERSEDING_FORMAL_SPENT_SCREEN_AUDIT_CANDIDATE",
                "publication": publication_path.relative_to(root).as_posix(),
                "pointer": pointer_path.relative_to(root).as_posix(),
                "pointer_raw_sha256": sha256_file(pointer_path),
                "execution_request": execution_request_path.relative_to(root).as_posix(),
                "execution_request_raw_sha256": sha256_file(execution_request_path),
                "heavy_compute_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
