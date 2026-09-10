from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import research.model_zoo.hofs_v12_fresh_qualification_service_v2 as package
from research.model_zoo.hofs_v12_fresh_qualification_service_v1.contracts import (
    ACTUAL_COMMON_PATH_BINDING_STATUS,
    GPU_OFF_ENVIRONMENT,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v2 import binding, service
from research.model_zoo.hofs_v12_fresh_qualification_service_v2.binding import (
    BoundTaskInput,
    HeldFileRecord,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v2.contracts import (
    COMMON_ROOT_BINDING_SCHEMA_VERSION,
    COMMON_ROOT_BINDING_STATUS,
    HOFS_TASK_SURFACE_COLUMNS,
    OUTER_WORKERS,
    OUTPUT_FILE_UNIVERSE,
    POSTGEN_AUDIT_SCHEMA_VERSION,
    POSTGEN_AUDIT_SEAL_SCHEMA_VERSION,
    POSTGEN_AUDIT_STATUS,
    POSTGEN_AUDIT_VERDICT,
    POSTGEN_TARGET_ROOT_FILE_COUNT,
    PROCESS_START_METHOD,
    PROJECT_ROOT,
    SOURCE_TREE_RELATIVES,
    PUBLICATION_CONTRACT_REVISION,
    TASK_COUNT,
    ZERO_SEVERITY_COUNTS,
    HofsV12QualificationBindingError,
    capture_source_closure,
    canonical_json_bytes,
)


def _record(relative: str, raw: bytes, *, inode: int) -> HeldFileRecord:
    return HeldFileRecord(
        relative=relative,
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        size_bytes=len(raw),
        volume_serial_number=17,
        file_id_128=f"{inode:032x}",
    )


def _task() -> BoundTaskInput:
    raw = b"fixed-spent-only-placeholder\n"
    receipt_raw = b'{"fixed":"spent"}\n'
    return BoundTaskInput(
        task_ordinal=0,
        qualification_seed=7573,
        seed_alias="qualification_seed_01",
        dgp_id="A",
        canonical_raw=raw,
        canonical_record=_record(
            "replays/pass_1/seed_7573/dgp_A/canonical150.csv", raw, inode=1
        ),
        canonical_semantic_sha256="1" * 64,
        pass_2_canonical_record=_record(
            "replays/pass_2/seed_7573/dgp_A/canonical150.csv", raw, inode=2
        ),
        task_receipt_record=_record(
            "replays/pass_1/seed_7573/dgp_A/TASK_RECEIPT.json",
            receipt_raw,
            inode=3,
        ),
        task_receipt_semantic_sha256="2" * 64,
    )


def test_public_api_exposes_only_target_bound_actual_entry() -> None:
    assert package.OUTER_WORKERS == 16
    assert package.TASK_COUNT == 50
    assert PROCESS_START_METHOD == "spawn"
    assert tuple(HOFS_TASK_SURFACE_COLUMNS) == (
        "seed_alias",
        "dgp_id",
        "session_position",
        "date",
        "symbol",
        "fold_id",
        "train_end_position",
        "test_start_position",
        "hofs_r2_expected_log_pe",
        "hofs_v7_tail_guard_weight",
        "hofs_v7_log_scale",
    )
    assert "compute_task_artifact" not in package.__all__
    assert "_numeric_task" not in package.__all__
    assert package.__all__ == sorted(package.__all__) or len(set(package.__all__)) == len(
        package.__all__
    )


def test_v2_projects_held_task_without_changing_v1_estimator_contract() -> None:
    task = _task()
    projected = service._v1_external_binding(task)
    assert projected.actual_common_path_binding_status == ACTUAL_COMMON_PATH_BINDING_STATUS
    assert projected.canonical_raw_sha256 == task.canonical_record.raw_sha256
    assert projected.canonical_semantic_sha256 == task.canonical_semantic_sha256
    assert projected.common_task_manifest_file_id_128 == task.task_receipt_record.file_id_128
    assert projected.task_ordinal == 0
    assert projected.qualification_seed == 7573
    with pytest.raises(HofsV12QualificationBindingError, match="order or identity"):
        BoundTaskInput(
            **{
                **task.__dict__,
                "dgp_id": "B",
            }
        )


def test_postgen_gate_is_exact_target_bound_and_zero_access() -> None:
    assert POSTGEN_AUDIT_SCHEMA_VERSION == "expected_pe.r8.r14.post_generation_audit.v1"
    assert (
        POSTGEN_AUDIT_SEAL_SCHEMA_VERSION
        == "expected_pe.r8.r14.post_generation_audit_seal.v1"
    )
    root = Path("C:/bound/common")
    root_record = _record(".", b"common", inode=10)
    manifest = _record("MANIFEST.json", b"manifest", inode=11)
    checksums = _record("CHECKSUMS.sha256", b"checksums", inode=12)
    tree = "3" * 64
    root_identity = {
        "identity_source": "GetFileInformationByHandleEx.FileIdInfo",
        "volume_serial_number": f"{root_record.volume_serial_number:016x}",
        "file_id_128": root_record.file_id_128,
    }
    target_binding = {
        "public_root_name": root.name,
        "manifest_raw_sha256": manifest.raw_sha256,
        "checksums_raw_sha256": checksums.raw_sha256,
        "expected_tree_semantic_sha256": tree,
        "observed_tree_semantic_sha256": tree,
        "target_root_file_count": POSTGEN_TARGET_ROOT_FILE_COUNT,
        "root_identity": root_identity,
    }
    target_binding_raw = json.dumps(
        target_binding,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    payload = {
        "schema_version": POSTGEN_AUDIT_SCHEMA_VERSION,
        "status": POSTGEN_AUDIT_STATUS,
        "verdict": POSTGEN_AUDIT_VERDICT,
        "severity_counts": dict(ZERO_SEVERITY_COUNTS),
        "audited_public_root_name": root.name,
        "public_manifest_raw_sha256": manifest.raw_sha256,
        "public_checksums_raw_sha256": checksums.raw_sha256,
        "expected_public_tree_semantic_sha256": tree,
        "public_tree_semantic_sha256": tree,
        "public_root_volume_serial_number": root_identity["volume_serial_number"],
        "public_root_file_id_128": root_record.file_id_128,
        "target_root_file_count": POSTGEN_TARGET_ROOT_FILE_COUNT,
        "access": {
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
            "protected_namespace_open_count": 0,
            "public_protected_metadata_receipt_open_count": 1,
        },
        "target_binding": target_binding,
        "target_binding_sha256": hashlib.sha256(target_binding_raw).hexdigest(),
    }
    binding._validate_postgen_audit(
        payload,
        common_root=root,
        root_identity=root_identity,
        manifest_record=manifest,
        checksums_record=checksums,
    )
    for field, attacked in (
        ("status", "GO"),
        ("audited_public_root_name", "different"),
        ("public_manifest_raw_sha256", "0" * 64),
        (
            "access",
            {
                **payload["access"],
                "truth_open_count": 1,
            },
        ),
        ("severity_counts", {"P0": 0, "P1": 1, "P2": 0}),
    ):
        mutated = dict(payload)
        mutated[field] = attacked
        with pytest.raises(HofsV12QualificationBindingError):
            binding._validate_postgen_audit(
                mutated,
                common_root=root,
                root_identity=root_identity,
                manifest_record=manifest,
                checksums_record=checksums,
            )


def test_external_json_contract_is_compact_ascii_lf_not_c4_pretty_json() -> None:
    payload = {"z": 2, "a": "ascii"}
    external_raw = b'{"a":"ascii","z":2}\n'
    assert binding._load_canonical_json(external_raw, label="external") == payload
    with pytest.raises(HofsV12QualificationBindingError, match="canonical exact"):
        binding._load_canonical_json(canonical_json_bytes(payload), label="external")


def test_source_closure_is_exact_stable_and_excludes_live_r8r13_tree() -> None:
    first = capture_source_closure()
    second = capture_source_closure()
    assert first == second
    assert first.source_model_version == f"sha256:{first.semantic_sha256}"
    relatives = tuple(row["relative"] for row in first.records)
    assert len(relatives) == len(set(relatives))
    assert relatives == tuple(sorted(relatives))
    assert all(row["size_bytes"] > 0 for row in first.records)
    assert all(len(row["raw_sha256"]) == 64 for row in first.records)
    assert all("r8_r13" not in relative.casefold() for relative in relatives)
    for tree in SOURCE_TREE_RELATIVES:
        assert any(relative.startswith(f"{tree}/") for relative in relatives)


def test_batch_contract_is_16_spawn_gpu_off_and_has_no_tuning_surface() -> None:
    assert OUTER_WORKERS == 16
    assert PROCESS_START_METHOD == "spawn"
    assert GPU_OFF_ENVIRONMENT["CUDA_VISIBLE_DEVICES"] == "-1"
    assert all(value == "1" for key, value in GPU_OFF_ENVIRONMENT.items() if "THREAD" in key)
    source = (PROJECT_ROOT / "research/model_zoo/hofs_v12_fresh_qualification_service_v2/service.py").read_text(
        encoding="utf-8"
    )
    assert "ProcessPoolExecutor(" in source
    assert "max_workers=OUTER_WORKERS" in source
    assert "mp.get_context(PROCESS_START_METHOD)" in source
    assert "_compute_validated_task_artifact(validated)" in source
    assert "hyperparameter" not in source.casefold()
    assert "optuna" not in source.casefold()
    assert "gridsearch" not in source.casefold()


def test_common_root_receipt_identity_is_final_not_pending() -> None:
    assert COMMON_ROOT_BINDING_SCHEMA_VERSION.endswith(".v2")
    assert COMMON_ROOT_BINDING_STATUS.startswith("PASS_TARGET_BOUND")
    assert TASK_COUNT == 50


def test_output_file_universe_matches_publisher_canonical_order() -> None:
    assert PUBLICATION_CONTRACT_REVISION.endswith("ORDER_R1")
    assert len(OUTPUT_FILE_UNIVERSE) == len(set(OUTPUT_FILE_UNIVERSE)) == 7
    assert OUTPUT_FILE_UNIVERSE == tuple(sorted(OUTPUT_FILE_UNIVERSE))
    assert OUTPUT_FILE_UNIVERSE == (
        "C4_TASK_RECEIPTS.json",
        "C4_TASK_SURFACES.csv",
        "CHECKSUMS.sha256",
        "COMMON_ROOT_BINDING.json",
        "MANIFEST.json",
        "RUNTIME_RECEIPT.json",
        "SOURCE_MANIFEST.json",
    )
