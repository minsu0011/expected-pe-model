"""Publish non-certifying terminal evidence for the interrupted R2 prediction freeze.

This tool never completes, rewrites, deletes, activates, or scores the partial
prediction bundle.  Dry-run is read-only.  Apply may atomically create only one
new terminal evidence root whose single leaf records why the four-leaf prefix
cannot be promoted into a sealed prediction bundle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)

RUN_ID = "r2_20260824T000005"
PREDICTION_ROOT_RELATIVE = (
    "outputs/model_zoo_pe_four_model_heldout_predictions_r2_20260824T000005"
)
WORK_ROOT_RELATIVE = (
    "build/pe_four_model_heldout_prediction_work_r2_20260824T000005"
)
TERMINAL_ROOT_NAME = (
    "model_zoo_pe_four_model_heldout_prediction_terminal_failure_"
    "r2_20260824T000005"
)
TERMINAL_LEAF = "TERMINAL_FAILURE.json"
AUTHORITY_RELATIVE = (
    "build/pe_four_model_heldout_execution_authority_r2_20260824T000005.json"
)
AUTHORITY_RAW_SHA256 = (
    "024872276d57d5a01c9ec049c31b9180bea684c4b8d53c03221b820cb616d8bc"
)
PROTOCOL_RELATIVE = (
    "outputs/model_zoo_pe_four_model_heldout_r2_reservation_"
    "r2_20260824T000005/promotion_policy.lock.json"
)
PROTOCOL_RAW_SHA256 = (
    "5d480fc9161fe65c1d8aacd4c10e138ec5839c7b3048e5f22c14b303ca56d193"
)
POSTGEN_GO_RELATIVE = (
    "build/pe_four_model_heldout_r2_post_generation_audit_"
    "r2a_20260824T000005/R2_POST_GENERATION_AUDIT.json"
)
POSTGEN_GO_RAW_SHA256 = (
    "78418e706336468fbadd6b26e90d85c7245f86309cf361e54fa693e388c921cc"
)
POSTGEN_GO_SEMANTIC_SHA256 = (
    "2adc1096436acb8a69861e5f68f7613cc77210e2758120547ab22297f75bc6e2"
)
EXECUTION_AUTHORITY_SEMANTIC_SHA256 = (
    "f1afcbf889deeb7859be7338a91540056a36b81a4bce53a6135cfa67313b7920"
)
PROTOCOL_BINDING_SEMANTIC_SHA256 = (
    "f82126d1f1b1aff53453e174771e6f7e35044484c5ca0e94bc145f2c0314a2f1"
)

PARTIAL_LEAVES = (
    "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
    "PREDICTION_MANIFEST.json",
    "PREDICTIONS.csv",
    "SOURCE_MANIFEST.json",
)
EXPECTED_PREFIX_ROOT_IDENTITY = {
    "volume_serial_number": "b8ec13dfec13972a",
    "file_id_128": "fc262100000055000000000000000000",
}
EXPECTED_PREFIX_REFS: dict[str, dict[str, object]] = {
    "HELDOUT_PREDICTION_FREEZE_RECEIPT.json": {
        "relative_path": f"{PREDICTION_ROOT_RELATIVE}/HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
        "raw_sha256": "99fb02f1ca995b10efec7bc403088bb4fddb7e02a505e33f104b39bdb969b728",
        "size_bytes": 4_120,
        "volume_serial_number": 13_325_047_249_941_796_650,
        "file_id_128": "1527210000005c000000000000000000",
    },
    "PREDICTION_MANIFEST.json": {
        "relative_path": f"{PREDICTION_ROOT_RELATIVE}/PREDICTION_MANIFEST.json",
        "raw_sha256": "17f0856f006cb7bdf1f25cf85dcb2206b313d4dbddd69a27403eeb0ca472687b",
        "size_bytes": 4_386,
        "volume_serial_number": 13_325_047_249_941_796_650,
        "file_id_128": "11272100000060000000000000000000",
    },
    "PREDICTIONS.csv": {
        "relative_path": f"{PREDICTION_ROOT_RELATIVE}/PREDICTIONS.csv",
        "raw_sha256": "2ab25a4c07fdf92e37949f0968207008233a3678b7c8b807d26d20675b24cfdb",
        "size_bytes": 96_190_998,
        "volume_serial_number": 13_325_047_249_941_796_650,
        "file_id_128": "09272100000054000000000000000000",
    },
    "SOURCE_MANIFEST.json": {
        "relative_path": f"{PREDICTION_ROOT_RELATIVE}/SOURCE_MANIFEST.json",
        "raw_sha256": "b954a358d5a2bb995dee0e920c578324e96152129ac42d2b32a2fa0894897fef",
        "size_bytes": 32_158,
        "volume_serial_number": 13_325_047_249_941_796_650,
        "file_id_128": "0a27210000005e000000000000000000",
    },
}

EXPECTED_WORK_ROOT_IDENTITY = {
    "volume_serial_number": "b8ec13dfec13972a",
    "file_id_128": "55232100000078000000000000000000",
}
EXPECTED_WORK_PREDICTION_RAW_SHA256 = (
    "2ab25a4c07fdf92e37949f0968207008233a3678b7c8b807d26d20675b24cfdb"
)
EXPECTED_EXECUTION_RECEIPT_RAW_SHA256 = (
    "f9491b5c582075a94271c7746e7da8bfc56818b0004ec3ee0e9ce800ed5e9723"
)
EXPECTED_BCE_RECEIPT_RECORDS_SEMANTIC_SHA256 = (
    "5726522dac582b3a60a3e83e41bb3c61ba3d7619435c034b59faf9ee5f1ac825"
)
EXPECTED_C4_RECEIPT_RECORDS_SEMANTIC_SHA256 = (
    "87ed91ec67772fdd59e9d70790f16f0d41a4b00e5da0f70b11d5cdb8800c601a"
)
EXPECTED_RECEIPT_HASHES_SEMANTIC_SHA256 = (
    "2b6449b00baec9e5b540a726b053b42084417a56a16ee1f451eaa10cf26684cc"
)

BASE_NUMERIC_ENVIRONMENT = {
    "CUDA_VISIBLE_DEVICES": "-1",
    "MKL_NUM_THREADS": "1",
    "NVIDIA_VISIBLE_DEVICES": "void",
    "NUMEXPR_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
}
BCE_NUMERIC_ENVIRONMENT = {
    **BASE_NUMERIC_ENVIRONMENT,
    "HIP_VISIBLE_DEVICES": "-1",
    "ROCR_VISIBLE_DEVICES": "-1",
}

DIAGNOSTIC_SOURCE_SHA256 = {
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/publisher.py": (
        "54fbc0acfbb6ace1da346d5f6dc0a0958fb6c541544bcdca70c6d93efb608c10"
    ),
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/independent_audit.py": (
        "33be202a6d638c1fe6c91cd5a305a2e60a1e314483a2dc90719f82432c21d2da"
    ),
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/prediction_execution.py": (
        "4f6783cd09d9fdb7be4ccfa1086248460d1380e8924e85c64410d4c971c80f11"
    ),
    "research/model_zoo/pe_five_model_qualification_prediction_auditor_v1/secure_publication.py": (
        "9e09edad569b3569850acf6d0184fee89ff657e5875d68c2b48d3f2e8d047cb1"
    ),
    "scripts/model_lab/pe_four_model_fresh_heldout_authority_v1/heldout_prediction_auditor.py": (
        "3d2b3138a379c42d4de802bc1c942e21c3da59b63c8c12e35d9f5de3a5c097ac"
    ),
    "research/model_zoo/pe_c1_c3_fresh_qualification_service_v1/contracts.py": (
        "f8dcbdd2adb8cd7dfd295639f55633f824b599617ad4f55ea07e9f17310dbf82"
    ),
}

FAILURE_CODES = (
    "R2_PREDICTION_PUBLICATION_FILESHARE_SEQUENCE_DENIAL",
    "R2_PREDICTION_AUDITOR_BCE_RESOURCE_ENVIRONMENT_MISMATCH",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TerminalEvidenceError(RuntimeError):
    """The exact terminal-evidence precondition differs."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise TerminalEvidenceError("terminal publisher requires -I -B")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise TerminalEvidenceError("terminal publisher forbids Python environment controls")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        value = str(path.resolve(strict=True))
        if value not in sys.path:
            sys.path.append(value)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    mode = result.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    result.add_argument("--expected-terminal-raw-sha256")
    return result


def _artifact_payload(record: Any) -> dict[str, object]:
    return {
        "relative_path": record.relative_path,
        "raw_sha256": record.raw_sha256,
        "size_bytes": record.size_bytes,
        "volume_serial_number": int(record.volume_serial_number, 16),
        "file_id_128": record.file_id_128,
    }


def _plain_directory(path: Path, expected_names: set[str], *, label: str) -> None:
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        capture_identity,
    )

    capture_identity(path, directory=True)
    names = {entry.name for entry in path.iterdir()}
    if names != expected_names:
        raise TerminalEvidenceError(f"{label} exact universe differs")


def _stable_ref(project: Path, relative: str) -> tuple[bytes, dict[str, object]]:
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        stable_read,
    )

    raw, record = stable_read(project / relative, relative_path=relative)
    return raw, _artifact_payload(record)


def _canonical_object(raw: bytes, *, label: str) -> dict[str, Any]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TerminalEvidenceError(f"{label} JSON differs") from exc
    if type(value) is not dict or canonical_pretty_bytes(value) != raw:
        raise TerminalEvidenceError(f"{label} canonical bytes differ")
    return value


def _validate_prefix(project: Path) -> dict[str, object]:
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        exact_root,
    )

    root, identity = exact_root(
        project / PREDICTION_ROOT_RELATIVE,
        expected_files=PARTIAL_LEAVES,
    )
    if identity != EXPECTED_PREFIX_ROOT_IDENTITY:
        raise TerminalEvidenceError("partial prediction root identity differs")
    refs: dict[str, dict[str, object]] = {}
    values: dict[str, dict[str, Any]] = {}
    for leaf in PARTIAL_LEAVES:
        raw, ref = _stable_ref(project, f"{PREDICTION_ROOT_RELATIVE}/{leaf}")
        if ref != EXPECTED_PREFIX_REFS[leaf]:
            raise TerminalEvidenceError(f"partial prediction ref differs: {leaf}")
        refs[leaf] = ref
        if leaf.endswith(".json"):
            values[leaf] = _canonical_object(raw, label=leaf)
    receipt = values["HELDOUT_PREDICTION_FREEZE_RECEIPT.json"]
    manifest = values["PREDICTION_MANIFEST.json"]
    if (
        receipt.get("prediction_ref") != refs["PREDICTIONS.csv"]
        or receipt.get("prediction_manifest_ref") != refs["PREDICTION_MANIFEST.json"]
        or receipt.get("source_manifest_ref") != refs["SOURCE_MANIFEST.json"]
        or receipt.get("truth_open_count") != 0
        or receipt.get("heldout_protected_open_count") != 0
        or receipt.get("score_open_count") != 0
        or manifest.get("truth_open_count") != 0
        or manifest.get("heldout_protected_open_count") != 0
        or manifest.get("score_open_count") != 0
    ):
        raise TerminalEvidenceError("partial prediction binding/access receipt differs")
    return {
        "root_relative_path": PREDICTION_ROOT_RELATIVE,
        "root_identity": identity,
        "exact_leaf_universe": list(PARTIAL_LEAVES),
        "leaf_refs": [refs[leaf] for leaf in PARTIAL_LEAVES],
        "missing_required_finalization_leaves": [
            "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
            "CHECKSUMS.sha256",
            "AUDIT_SEAL.json",
        ],
        "prefix_is_not_a_sealed_prediction_bundle": True,
    }


def _validate_work(project: Path) -> dict[str, object]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        semantic_sha256,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        capture_identity,
    )

    root = (project / WORK_ROOT_RELATIVE).resolve(strict=True)
    _plain_directory(
        root,
        {"bce", "c4", "PREDICTIONS.csv", "PREDICTION_EXECUTION_RECEIPT.json"},
        label="numeric work root",
    )
    identity = capture_identity(root, directory=True)
    if identity != EXPECTED_WORK_ROOT_IDENTITY:
        raise TerminalEvidenceError("numeric work root identity differs")
    work_prediction_raw, work_prediction_ref = _stable_ref(
        project, f"{WORK_ROOT_RELATIVE}/PREDICTIONS.csv"
    )
    if hashlib.sha256(work_prediction_raw).hexdigest() != EXPECTED_WORK_PREDICTION_RAW_SHA256:
        raise TerminalEvidenceError("numeric work prediction bytes differ")
    execution_raw, execution_ref = _stable_ref(
        project, f"{WORK_ROOT_RELATIVE}/PREDICTION_EXECUTION_RECEIPT.json"
    )
    if execution_ref["raw_sha256"] != EXPECTED_EXECUTION_RECEIPT_RAW_SHA256:
        raise TerminalEvidenceError("numeric execution receipt bytes differ")
    execution = _canonical_object(execution_raw, label="prediction execution receipt")

    parsed: dict[str, list[dict[str, Any]]] = {"bce": [], "c4": []}
    records: dict[str, list[dict[str, object]]] = {"bce": [], "c4": []}
    aliases = [f"heldout_seed_{ordinal:02d}" for ordinal in range(1, 6)]
    for lane, receipt_leaf, surface_leaf in (
        ("bce", "BCE_RECEIPT.json", "BCE_SURFACE.csv"),
        ("c4", "C4_RECEIPT.json", "C4_SURFACE.csv"),
    ):
        lane_root = root / lane
        _plain_directory(lane_root, set(aliases), label=f"{lane} lane")
        for seed_index, alias in enumerate(aliases):
            alias_root = lane_root / alias
            _plain_directory(
                alias_root,
                {f"dgp_{dgp}" for dgp in "ABCDEFGHIJ"},
                label=f"{lane} {alias}",
            )
            for dgp_index, dgp in enumerate("ABCDEFGHIJ"):
                task_root = alias_root / f"dgp_{dgp}"
                _plain_directory(
                    task_root,
                    {receipt_leaf, surface_leaf},
                    label=f"{lane} {alias} dgp_{dgp}",
                )
                relative = (
                    f"{WORK_ROOT_RELATIVE}/{lane}/{alias}/dgp_{dgp}/{receipt_leaf}"
                )
                raw, ref = _stable_ref(project, relative)
                value = _canonical_object(raw, label=relative)
                ordinal = seed_index * 10 + dgp_index
                slot = ordinal % 16
                expected_environment = (
                    BCE_NUMERIC_ENVIRONMENT if lane == "bce" else BASE_NUMERIC_ENVIRONMENT
                )
                runtime = value.get("worker_runtime", {})
                if (
                    value.get("task", {}).get("task_ordinal") != ordinal
                    or value.get("task", {}).get("seed_alias") != alias
                    or value.get("task", {}).get("dgp_id") != dgp
                    or value.get("truth_open_count") != 0
                    or value.get("protected_open_count") != 0
                    or value.get("score_open_count") != 0
                    or runtime.get("worker_slot") != slot
                    or runtime.get("environment") != expected_environment
                ):
                    raise TerminalEvidenceError(f"numeric {lane} receipt differs: {ordinal}")
                parsed[lane].append(value)
                records[lane].append(ref)
    if (
        execution.get("schema_version")
        != "expected_pe.four_model.heldout_prediction_execution.v1"
        or execution.get("status") != "PASS_FOUR_MODEL_PREDICTIONS_BUILT_PRETRUTH"
        or execution.get("prediction_raw_sha256")
        != EXPECTED_WORK_PREDICTION_RAW_SHA256
        or execution.get("bce_receipts") != parsed["bce"]
        or execution.get("c4_receipts") != parsed["c4"]
        or execution.get("truth_open_count") != 0
        or execution.get("protected_open_count") != 0
        or execution.get("score_open_count") != 0
    ):
        raise TerminalEvidenceError("numeric execution receipt binding differs")
    bce_semantic = semantic_sha256(records["bce"])
    c4_semantic = semantic_sha256(records["c4"])
    receipt_hashes = [
        record["raw_sha256"] for lane in ("bce", "c4") for record in records[lane]
    ]
    if (
        bce_semantic != EXPECTED_BCE_RECEIPT_RECORDS_SEMANTIC_SHA256
        or c4_semantic != EXPECTED_C4_RECEIPT_RECORDS_SEMANTIC_SHA256
        or semantic_sha256(receipt_hashes)
        != EXPECTED_RECEIPT_HASHES_SEMANTIC_SHA256
    ):
        raise TerminalEvidenceError("numeric task receipt inventory differs")
    return {
        "root_relative_path": WORK_ROOT_RELATIVE,
        "root_identity": identity,
        "root_entry_universe": [
            "PREDICTIONS.csv",
            "PREDICTION_EXECUTION_RECEIPT.json",
            "bce",
            "c4",
        ],
        "work_prediction_ref": work_prediction_ref,
        "execution_receipt_ref": execution_ref,
        "bce_receipt_count": 50,
        "c4_receipt_count": 50,
        "bce_receipt_raw_sha256_in_task_order": [
            record["raw_sha256"] for record in records["bce"]
        ],
        "c4_receipt_raw_sha256_in_task_order": [
            record["raw_sha256"] for record in records["c4"]
        ],
        "bce_receipt_records_semantic_sha256": bce_semantic,
        "c4_receipt_records_semantic_sha256": c4_semantic,
        "all_receipt_hashes_semantic_sha256": EXPECTED_RECEIPT_HASHES_SEMANTIC_SHA256,
        "bce_observed_environment": BCE_NUMERIC_ENVIRONMENT,
        "c4_observed_environment": BASE_NUMERIC_ENVIRONMENT,
        "numeric_surfaces_reopened_for_terminal_publication": False,
        "numeric_predictions_rerun_for_terminal_publication": False,
    }


def _validate_authorities(project: Path) -> tuple[dict[str, object], dict[str, Any]]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.execution_authority import (
        read_execution_authority,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.r2_protocol_lock import (
        read_r2_protocol_lock,
    )

    authority = read_execution_authority(
        project / AUTHORITY_RELATIVE,
        project_root=project,
        expected_run_id=RUN_ID,
        expected_raw_sha256=AUTHORITY_RAW_SHA256,
    )
    protocol = read_r2_protocol_lock(
        project / PROTOCOL_RELATIVE,
        project_root=project,
        expected_run_id=RUN_ID,
        expected_raw_sha256=PROTOCOL_RAW_SHA256,
    )
    if (
        authority.get("execution_authority_semantic_sha256")
        != EXECUTION_AUTHORITY_SEMANTIC_SHA256
        or authority.get("r2_protocol_binding_semantic_sha256")
        != PROTOCOL_BINDING_SEMANTIC_SHA256
        or protocol.get("r2_protocol_binding_semantic_sha256")
        != PROTOCOL_BINDING_SEMANTIC_SHA256
        or authority.get("truth_open_count") != 0
        or authority.get("heldout_content_open_count") != 0
        or authority.get("score_open_count") != 0
    ):
        raise TerminalEvidenceError("R2 authority/protocol binding differs")
    authority_raw, authority_ref = _stable_ref(project, AUTHORITY_RELATIVE)
    protocol_raw, protocol_ref = _stable_ref(project, PROTOCOL_RELATIVE)
    if (
        hashlib.sha256(authority_raw).hexdigest() != AUTHORITY_RAW_SHA256
        or hashlib.sha256(protocol_raw).hexdigest() != PROTOCOL_RAW_SHA256
    ):
        raise TerminalEvidenceError("R2 authority/protocol raw bytes differ")
    return {
        "execution_authority_ref": authority_ref,
        "execution_authority_semantic_sha256": EXECUTION_AUTHORITY_SEMANTIC_SHA256,
        "protocol_lock_ref": protocol_ref,
        "protocol_binding_semantic_sha256": PROTOCOL_BINDING_SEMANTIC_SHA256,
        "source_records_semantic_sha256": authority["source_records_semantic_sha256"],
        "generation_plan_semantic_sha256": authority[
            "generation_plan_semantic_sha256"
        ],
        "survivor_freeze_semantic_sha256": authority[
            "qualification_survivor_freeze_semantic_sha256"
        ],
    }, authority


def _validate_postgen(project: Path) -> dict[str, object]:
    raw, ref = _stable_ref(project, POSTGEN_GO_RELATIVE)
    if ref["raw_sha256"] != POSTGEN_GO_RAW_SHA256:
        raise TerminalEvidenceError("R2 post-generation GO raw bytes differ")
    value = _canonical_object(raw, label="R2 post-generation GO")
    if (
        value.get("status") != "GO_R2_POST_GENERATION_P0_0_P1_0_P2_0"
        or value.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or value.get("findings") != []
        or value.get("audit_semantic_sha256") != POSTGEN_GO_SEMANTIC_SHA256
        or value.get("authority", {}).get("execution_authority_semantic_sha256")
        != EXECUTION_AUTHORITY_SEMANTIC_SHA256
        or value.get("public_evidence", {}).get("truth_open_count") != 0
        or value.get("public_evidence", {}).get("score_open_count") != 0
        or value.get("vault_metadata_evidence", {}).get("truth_content_open_count") != 0
    ):
        raise TerminalEvidenceError("R2 post-generation GO contract differs")
    return {
        "post_generation_go_ref": ref,
        "post_generation_go_semantic_sha256": POSTGEN_GO_SEMANTIC_SHA256,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "truth_content_open_count": 0,
        "score_open_count": 0,
    }


def _diagnostic_sources(
    project: Path, authority: Mapping[str, Any]
) -> list[dict[str, object]]:
    source = authority["source_manifest"]
    records = [
        row
        for field in (
            "adapter_source_records",
            "c2_c3_frozen_numeric_source_records",
            "c4_source_tree_records",
            "c4_source_file_records",
        )
        for row in source[field]
    ]
    by_relative = {row["relative_path"]: row for row in records}
    result: list[dict[str, object]] = []
    for relative, expected_hash in DIAGNOSTIC_SOURCE_SHA256.items():
        _, ref = _stable_ref(project, relative)
        authority_record = by_relative.get(relative)
        if (
            ref["raw_sha256"] != expected_hash
            or authority_record
            != {
                "relative_path": relative,
                "raw_sha256": ref["raw_sha256"],
                "size_bytes": ref["size_bytes"],
            }
        ):
            raise TerminalEvidenceError(f"diagnostic frozen source differs: {relative}")
        result.append(ref)
    return result


def _build_terminal_payload(project: Path) -> dict[str, object]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        semantic_sha256,
    )

    terminal_root = project / "outputs" / TERMINAL_ROOT_NAME
    activation = (
        project
        / "outputs/model_zoo_pe_model_portfolio_heldout_activation_r2_20260824T000005"
    )
    certification = (
        project
        / "outputs/model_zoo_pe_model_portfolio_heldout_certification_result_"
        "r2_20260824T000005"
    )
    if terminal_root.exists():
        raise TerminalEvidenceError("terminal evidence identity is already consumed")
    if activation.exists() or certification.exists():
        raise TerminalEvidenceError("activation or certification output already exists")
    prefix = _validate_prefix(project)
    work = _validate_work(project)
    authorities, authority = _validate_authorities(project)
    postgen = _validate_postgen(project)
    diagnostic_sources = _diagnostic_sources(project, authority)
    protocol_binding = authority["r2_protocol_lock"]["r2_protocol_binding"]
    reserved = protocol_binding["reservation_contract"]["reserved_seeds"]
    core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r2_prediction_publication_terminal.v1",
        "status": "TERMINAL_UNSEALED_PREDICTION_PREFIX_NO_ACTIVATION_OR_SCORING",
        "run_id": RUN_ID,
        "terminal": True,
        "retry_allowed": False,
        "recovery_allowed": False,
        "certification_authority": False,
        "terminal_publisher_outside_frozen_source_closure": True,
        "terminal_output_root_relative_path": f"outputs/{TERMINAL_ROOT_NAME}",
        "terminal_output_file_universe": [TERMINAL_LEAF],
        "failure_codes_in_order": list(FAILURE_CODES),
        "failures": [
            {
                "code": FAILURE_CODES[0],
                "deterministic": True,
                "stage": "independent_audit_launched_before_publication_handles_closed",
                "finding": (
                    "The publisher invoked the independent path-based auditor while "
                    "the outputs/root publication directory handles still requested "
                    "write/add rights and shared only read. Windows symmetric sharing "
                    "therefore denied the auditor's directory identity reopen."
                ),
                "numeric_prediction_failure": False,
            },
            {
                "code": FAILURE_CODES[1],
                "deterministic": True,
                "stage": "read_only_independent_audit_after_handles_closed",
                "finding": (
                    "The frozen auditor expected the seven-variable base environment "
                    "for BCE, while frozen prediction execution intentionally merged "
                    "the BCE resource policy and receipts contain HIP_VISIBLE_DEVICES "
                    "and ROCR_VISIBLE_DEVICES as two additional GPU-blocking variables."
                ),
                "numeric_prediction_failure": False,
            },
        ],
        "authorities": authorities,
        "post_generation_go": postgen,
        "partial_prediction_prefix": prefix,
        "numeric_work_evidence": work,
        "diagnostic_frozen_source_refs": diagnostic_sources,
        "seed_disposition": {
            "quarantine_seeds_never_generate_or_score": protocol_binding[
                "quarantine_seeds_never_generate_or_score"
            ],
            "heldout_seeds_in_order": protocol_binding["heldout_seeds_in_order"],
            "all_reserved_seeds_in_registry_order": reserved,
            "all_reserved_seeds_conservatively_spent": True,
            "seed_reuse_allowed": False,
            "additional_recovery_reservation_allowed": False,
        },
        "prohibitions": {
            "existing_prediction_files_rewritten": False,
            "existing_prediction_files_deleted": False,
            "numeric_predictions_rerun": False,
            "prediction_finalization_recovered": False,
            "prediction_bundle_activated": False,
            "heldout_scorer_invoked": False,
            "model_selection_or_tuning_performed": False,
        },
        "access": {
            "truth_open_count": 0,
            "heldout_protected_open_count": 0,
            "score_open_count": 0,
        },
    }
    return {**core, "terminal_semantic_sha256": semantic_sha256(core)}


def _publish_terminal(project: Path, raw: bytes) -> dict[str, object]:
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.secure_publication import (
        HeldDirectory,
        claim_output_root,
        publish_leaf,
        reconcile_tree,
    )

    outputs = HeldDirectory.open_existing(project / "outputs")
    root = None
    leaf = None
    try:
        root = claim_output_root(
            path=project / "outputs" / TERMINAL_ROOT_NAME,
            project_root=project,
            outputs_parent=outputs,
        )
        leaf = publish_leaf(parent=root, final_leaf=TERMINAL_LEAF, raw=raw)
        reconcile_tree(
            outputs_parent=outputs,
            output_root=root,
            files=(leaf,),
            expected_names=(TERMINAL_LEAF,),
        )
        leaf.assert_live()
        return {
            "terminal_ref": {
                "relative_path": leaf.path.relative_to(project).as_posix(),
                "raw_sha256": leaf.raw_sha256,
                "size_bytes": leaf.size_bytes,
                "volume_serial_number": int(leaf.volume_serial_number, 16),
                "file_id_128": leaf.file_id_128,
            },
            "terminal_root_identity": root.identity_payload(),
        }
    finally:
        if leaf is not None:
            leaf.close()
        if root is not None:
            root.close()
        outputs.close()


def main() -> int:
    _bootstrap()
    arguments = parser().parse_args()
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )

    project = PROJECT_ROOT.resolve(strict=True)
    payload = _build_terminal_payload(project)
    raw = canonical_pretty_bytes(payload)
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    if arguments.apply:
        expected = arguments.expected_terminal_raw_sha256
        if type(expected) is not str or _SHA256.fullmatch(expected) is None:
            raise TerminalEvidenceError(
                "apply requires --expected-terminal-raw-sha256 from a prior dry-run"
            )
        if expected != raw_sha256:
            raise TerminalEvidenceError("dry-run terminal raw SHA-256 authority differs")
        published = _publish_terminal(project, raw)
        result = {
            "status": "TERMINAL_EVIDENCE_PUBLISHED_NO_RECOVERY_NO_SCORING",
            "mode": "APPLY",
            "terminal_raw_sha256": raw_sha256,
            "terminal_semantic_sha256": payload["terminal_semantic_sha256"],
            **published,
            "truth_open_count": 0,
            "heldout_protected_open_count": 0,
            "score_open_count": 0,
        }
    else:
        if arguments.expected_terminal_raw_sha256 is not None:
            raise TerminalEvidenceError("dry-run does not accept an expected terminal hash")
        result = {
            "status": "PASS_TERMINAL_EVIDENCE_DRY_RUN_NO_MUTATION",
            "mode": "DRY_RUN",
            "planned_terminal_root_relative_path": f"outputs/{TERMINAL_ROOT_NAME}",
            "planned_terminal_leaf": TERMINAL_LEAF,
            "terminal_raw_sha256": raw_sha256,
            "terminal_semantic_sha256": payload["terminal_semantic_sha256"],
            "terminal_size_bytes": len(raw),
            "apply_executed": False,
            "truth_open_count": 0,
            "heldout_protected_open_count": 0,
            "score_open_count": 0,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
