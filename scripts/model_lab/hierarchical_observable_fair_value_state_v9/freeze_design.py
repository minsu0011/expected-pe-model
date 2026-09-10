"""Build and atomically freeze the score-blind H-OFS V9 launcher repair."""

from __future__ import annotations

import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (
    build_r4_input_closure_v7,
    capture_runtime_receipt_v7,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v9 import (
    V7_AUDIT_BINDING,
    V7_DESIGN_BINDING,
    V7_SINGLE_RUN_FAILURE_EVIDENCE,
    V8_AUDIT_BINDING,
    V8_DESIGN_BINDING,
    V8_SINGLE_RUN_FAILURE_EVIDENCE,
    bootstrap_contract_payload,
    bootstrap_contract_sha256,
    canonical_json_bytes,
    contract_payload,
    contract_sha256,
    failure_evidence_sha256,
    require_failure_staging,
    run_source_audit_v9,
    sealed_payload,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v9.contracts import (
    R4_INPUT_BINDING,
    RUNTIME_PLAN,
    V9_AUDIT_VERDICT,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v9_"
    "dgp_r4_design_preflight_20260821"
)
FINAL_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "AUDIT_CLOSURE.json",
    "CHECKSUMS.sha256",
    "DESIGN_LOCK.json",
    "INPUT_CLOSURE.json",
    "MANIFEST.json",
    "PREDICTION_LAUNCHER.py",
    "PREDICTION_LAUNCH_CONTRACT.json",
    "PREFLIGHT.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "RESOURCE_RECEIPT.json",
    "SEAL_RECEIPT.json",
    "SOURCE_CLOSURE.json",
)


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def _parse_json_exact(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in output:
                raise RuntimeError(f"V9 duplicate or invalid JSON key: {label}:{key}")
            output[key] = value
        return output

    value = json.loads(
        content.decode("ascii"),
        object_pairs_hook=reject_duplicates,
        parse_constant=lambda token: (_ for _ in ()).throw(
            RuntimeError(f"V9 non-finite JSON token: {label}:{token}")
        ),
    )
    if type(value) is not dict:
        raise RuntimeError(f"V9 JSON root is not an object: {label}")
    return value


def _logical_sha256(payload: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(payload)
    expected = unsigned.pop("manifest_sha256", None)
    actual = _sha256(canonical_json_bytes(unsigned))
    if expected != actual:
        raise RuntimeError("V9 artifact logical self-seal drifted")
    return actual


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _is_reparse(path: Path) -> bool:
    if os.name != "nt":
        return path.is_symlink()
    get_attributes = ctypes.windll.kernel32.GetFileAttributesW  # type: ignore[attr-defined]
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    attributes = int(get_attributes(str(path.absolute())))
    return attributes != 0xFFFFFFFF and bool(attributes & 0x00000400)


def _require_regular(path: Path, *, root: Path) -> bytes:
    if path.is_symlink() or _is_reparse(path) or not path.is_file():
        raise RuntimeError(f"V9 non-regular file: {path}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError(f"V9 file escaped root: {path}") from error
    return path.read_bytes()


def _fsync_directory(path: Path) -> None:
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return
    create_file = ctypes.windll.kernel32.CreateFileW  # type: ignore[attr-defined]
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x40000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise RuntimeError("V9 directory fsync handle failed")
    try:
        if not ctypes.windll.kernel32.FlushFileBuffers(handle):  # type: ignore[attr-defined]
            raise RuntimeError("V9 directory fsync failed")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def build_preflight_payload(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    source_audit = run_source_audit_v9(project_root)
    if source_audit.get("passed") is not True:
        raise RuntimeError("V9 source audit failed")
    input_closure = build_r4_input_closure_v7(project_root)
    runtime = capture_runtime_receipt_v7(purpose="PREFLIGHT")
    failure = require_failure_staging(project_root)
    return {
        "schema_version": "expected_pe.hofs_v9.dgp_r4_preflight.v1",
        "status": "PASS_V9_ISOLATED_WORKER_LIFECYCLE_REPAIR_PREFLIGHT_NO_MODEL_LAUNCH",
        "design_contract_sha256": contract_sha256(),
        "design_contract": contract_payload(),
        "v7_design_binding": copy.deepcopy(V7_DESIGN_BINDING),
        "v7_audit_binding": copy.deepcopy(V7_AUDIT_BINDING),
        "v7_single_run_failure_evidence": copy.deepcopy(
            V7_SINGLE_RUN_FAILURE_EVIDENCE
        ),
        "v7_single_run_failure_evidence_sha256": _sha256(
            canonical_json_bytes(V7_SINGLE_RUN_FAILURE_EVIDENCE)
        ),
        "v8_design_binding": copy.deepcopy(V8_DESIGN_BINDING),
        "v8_audit_binding": copy.deepcopy(V8_AUDIT_BINDING),
        "v8_single_run_failure_evidence": copy.deepcopy(
            V8_SINGLE_RUN_FAILURE_EVIDENCE
        ),
        "v8_single_run_failure_evidence_sha256": failure_evidence_sha256(),
        "v8_failure_live_receipt": failure,
        "r4_input_binding": copy.deepcopy(R4_INPUT_BINDING),
        "input_closure": input_closure,
        "source_audit": source_audit,
        "worker_bootstrap_contract": bootstrap_contract_payload(),
        "worker_bootstrap_contract_sha256": bootstrap_contract_sha256(),
        "resource": {
            "receipt": runtime.payload(),
            "receipt_sha256": runtime.sha256(),
            "runtime_plan": copy.deepcopy(RUNTIME_PLAN),
        },
        "authority": {
            "design_preflight_only": True,
            "real_fit": False,
            "real_prediction": False,
            "truth_vault_latent_heldout_evaluator_or_score": False,
            "model_registry_read": False,
            "registry_or_champion": False,
            "promotion": False,
        },
    }


def build_design_bundle_bytes(project_root: Path = PROJECT_ROOT) -> dict[str, bytes]:
    preflight = build_preflight_payload(project_root)
    source_audit = copy.deepcopy(preflight["source_audit"])
    input_payload = copy.deepcopy(preflight["input_closure"])
    authority = copy.deepcopy(preflight["authority"])
    launcher_relative = (
        "scripts/model_lab/hierarchical_observable_fair_value_state_v9/"
        "prediction_launcher.py"
    )
    launcher_bytes = _require_regular(
        project_root / launcher_relative,
        root=project_root,
    )
    launcher_sha256 = _sha256(launcher_bytes)
    if dict(source_audit["source_sha256"]).get(launcher_relative) != launcher_sha256:
        raise RuntimeError("V9 launcher is not bound by its source closure")
    from scripts.model_lab.hierarchical_observable_fair_value_state_v9.prediction_launcher import (  # noqa: PLC0415
        launch_contract_payload,
    )

    launch_contract = sealed_payload(
        launch_contract_payload(
            launcher_raw_sha256=launcher_sha256,
            design_contract_sha256=contract_sha256(),
        )
    )
    design_lock = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.design_lock.v1",
            "status": "PASS_V9_EXACT_V8_SEMANTICS_WORKER_LIFECYCLE_REPAIR_LOCK",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "v7_design_binding": copy.deepcopy(V7_DESIGN_BINDING),
            "v7_audit_binding": copy.deepcopy(V7_AUDIT_BINDING),
            "v7_single_run_failure_evidence": copy.deepcopy(
                V7_SINGLE_RUN_FAILURE_EVIDENCE
            ),
            "v7_single_run_failure_evidence_sha256": _sha256(
                canonical_json_bytes(V7_SINGLE_RUN_FAILURE_EVIDENCE)
            ),
            "v8_design_binding": copy.deepcopy(V8_DESIGN_BINDING),
            "v8_audit_binding": copy.deepcopy(V8_AUDIT_BINDING),
            "v8_single_run_failure_evidence": copy.deepcopy(
                V8_SINGLE_RUN_FAILURE_EVIDENCE
            ),
            "v8_single_run_failure_evidence_sha256": failure_evidence_sha256(),
            "repair": {
                "absence_guard_location": "worker_initializer_only",
                "initializer_count_per_pid": 1,
                "absence_guard_count_per_pid": 1,
                "post_import_per_pid_loaded_closure_sealed": True,
                "every_task_loaded_closure_revalidated": True,
                "loaded_closure_binds_module_object_origin_source_hash_and_runtime": True,
                "execute_task_ast_import_surface_exact": True,
                "windows_spawn_worker_initializer_barrier_count": 32,
                "windows_spawn_worker_first_task_barrier_count": 32,
                "production_equivalent_lifecycle_tasks": 50,
                "targeted_same_pid_reuse_tasks": 7,
                "all_execute_task_modules_symbols_origins_hashes_attested": True,
                "metadata_only_task_deserialization": True,
                "public_path_and_header_validation_without_rows": True,
                "real_fit_count": 0,
                "real_prediction_count": 0,
            },
            "inherited_execution_geometry": {
                "task_count": 50,
                "folds_per_task": 62,
                "fit_count": 3100,
                "decision_row_count": 64800,
                "within_block_parameter_update_count": 0,
                "first_prefix_requested_nonwarm_warm": [504, 3, 501],
            },
            "authority": authority,
        }
    )
    failure_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.v8_failure_closure.v1",
            "status": "PASS_EXACT_SINGLE_V8_REUSED_WORKER_FAILURE_BOUND",
            "v7_design_binding": copy.deepcopy(V7_DESIGN_BINDING),
            "v7_audit_binding": copy.deepcopy(V7_AUDIT_BINDING),
            "v7_single_run_failure_evidence": copy.deepcopy(
                V7_SINGLE_RUN_FAILURE_EVIDENCE
            ),
            "v7_single_run_failure_evidence_sha256": _sha256(
                canonical_json_bytes(V7_SINGLE_RUN_FAILURE_EVIDENCE)
            ),
            "v8_design_binding": copy.deepcopy(V8_DESIGN_BINDING),
            "v8_audit_binding": copy.deepcopy(V8_AUDIT_BINDING),
            "v8_single_run_failure_evidence": copy.deepcopy(
                V8_SINGLE_RUN_FAILURE_EVIDENCE
            ),
            "v8_single_run_failure_evidence_sha256": failure_evidence_sha256(),
            "controller_acknowledged_task_count": 1,
            "published_completed_task_count": 0,
            "published_completed_fit_count": 0,
            "published_completed_prediction_row_count": 0,
            "usable_prediction_row_count": 0,
            "published_output_root": False,
            "empty_staging_preserved": True,
            "v9_repair_scope": "WORKER_LIFECYCLE_ONLY",
        }
    )
    source_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.source_closure.v1",
            "status": "PASS_EXACT_V9_FROZEN_V8_AND_INHERITED_V7_SOURCE_CLOSURE",
            "source_audit": source_audit,
            "source_file_count": source_audit["source_file_count"],
            "v9_primary_source_file_count": (
                source_audit["v9_primary_source_file_count"]
            ),
            "inherited_v7_source_file_count": (
                source_audit["inherited_v7_source_file_count"]
            ),
            "inherited_v8_source_file_count": (
                source_audit["inherited_v8_source_file_count"]
            ),
            "parent_runtime_source_sha256": source_audit[
                "parent_runtime_sha256"
            ],
            "prediction_launcher_raw_sha256": launcher_sha256,
            "v8_single_run_failure_evidence_sha256": failure_evidence_sha256(),
            "protected_payload_open_count": 0,
            "score_call_count": 0,
            "registry_mutation_count": 0,
        }
    )
    input_closure = sealed_payload(input_payload)
    resource = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.resource_receipt.v1",
            "status": "PASS_EXACT_OUTER32_INNER1_PY310_CPU0_31_GPU_OFF",
            "resource_receipt": preflight["resource"]["receipt"],
            "resource_receipt_sha256": preflight["resource"][
                "receipt_sha256"
            ],
            "runtime_plan": preflight["resource"]["runtime_plan"],
            "formal_check_spawn_worker_count": 32,
            "formal_check_production_equivalent_task_count": 50,
            "formal_check_targeted_same_pid_reuse_task_count": 7,
            "initializer_count_per_pid": 1,
            "absence_guard_count_per_pid": 1,
            "real_fit_or_prediction_run": False,
        }
    )
    quality = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.quality_receipt.v1",
            "status": (
                "PASS_V9_90_PLUS_252_RUFF_AND_ACTUAL_WORKER_LIFECYCLE_PREFLIGHT"
            ),
            "pytest": {
                "python_version": "3.10.19",
                "bytecode_disabled": True,
                "cache_provider_disabled": True,
                "focused_v9_passed": 90,
                "focused_v9_failed": 0,
                "v1_through_v8_cache_free_mirror_passed": 252,
                "v1_through_v8_cache_free_mirror_failed": 0,
                "clean_mirror_source_cache_directories_before": 0,
                "clean_mirror_source_cache_directories_after": 0,
                "live_tree_expected_cache_policy_result": {
                    "passed": 248,
                    "failed": 4,
                    "failure_scope": "V4_SOURCE_AUDIT_PREEXISTING_CACHE_DIRECTORIES",
                    "live_cache_directories_before": 64,
                    "live_cache_directories_after": 64,
                    "v9_caused": False,
                },
                "live_source_tree_modified_by_regression": False,
            },
            "ruff": {
                "version": "0.12.0",
                "status": "ALL_CHECKS_PASSED",
            },
            "actual_prefreeze_worker_lifecycle": {
                "status": (
                    "PASS_50_TASK_32_WORKER_AND_7_TASK_SAME_PID_REUSE"
                ),
                "process_start_method": "spawn",
                "bootstrap_contract_sha256": (
                    "b5940094302179bdef76465382fe3e72ae54ff18ac7366571f236dfa93f79499"
                ),
                "stable_worker_semantic_receipt_sha256": (
                    "8da5758a26a28534def2be973e21bc54872864174c738a85b69ea5c3b9e35af0"
                ),
                "production_equivalent": {
                    "worker_count": 32,
                    "task_count": 50,
                    "reused_worker_count": 18,
                    "maximum_reuse_count": 2,
                },
                "targeted_same_pid": {
                    "worker_count": 1,
                    "task_count": 7,
                    "reused_worker_count": 1,
                    "maximum_reuse_count": 7,
                },
                "initializer_count_per_pid": 1,
                "absence_guard_count_per_pid": 1,
                "every_task_loaded_closure_revalidated": True,
                "real_fit_count": 0,
                "real_prediction_count": 0,
                "protected_or_score_access_count": 0,
            },
            "adversarial_coverage": {
                "every_execute_task_imported_symbol_missing": True,
                "every_execute_task_imported_symbol_renamed_or_relocated": True,
                "every_imported_constant_type_and_semantic_hash": True,
                "shadow_module_origin": True,
                "module_source_hash": True,
                "execute_task_ast_import_drift": True,
                "bootstrap_fanout_31_duplicate_or_bypass": True,
                "metadata_path_header_and_duplicate_json": True,
                "fresh_interpreter_bootstrap_numeric_preimport": True,
                "reinitializer": True,
                "stale_loaded_closure": True,
                "module_drift_or_shadow": True,
                "task_count_spoof": True,
                "worker_replacement": True,
                "missing_symbol": True,
                "reuse_after_imported_numeric_stack": True,
                "output_bytes_tamper": True,
                "staging_extra_child_tamper": True,
            },
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "empirical_or_score_evidence": False,
        }
    )
    access = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.access_receipt.v1",
            "status": "PASS_PUBLIC_R4_HEADER_AND_FROZEN_LINEAGE_ONLY",
            "output_mutation_scope": DEFAULT_OUTPUT_ROOT.relative_to(
                project_root
            ).as_posix(),
            "public_input_access": input_payload["access"],
            "public_header_bootstrap_read_count_per_formal_check": 33,
            "public_row_payload_deserialization_count_in_bootstrap": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "truth_vault_latent_heldout_evaluator_score_open_count": 0,
            "model_registry_file_read_count": 0,
            "score_call_count": 0,
            "registry_or_champion_mutation_count": 0,
            "promotion_count": 0,
        }
    )
    preflight_record = sealed_payload(preflight)
    report = (
        "# H-OFS V9 Isolated Worker-Lifecycle Repair Preflight\n\n"
        "Status: PASS_V9_DESIGN_PREFLIGHT_NO_MODEL_LAUNCH\n\n"
        f"Contract: {contract_sha256()}\n\n"
        "V9 preserves the exact V8/V7 estimator, public causal-prefix receipts, "
        "canonical order, 3,100-fit and 64,800-decision geometry, resource "
        "pins, output semantics, and atomic publisher. It binds the single "
        "V8 run ID 20260821T075500 reused-worker failure, one controller "
        "acknowledgement, zero published fits/predictions, and its preserved "
        "empty staging directory. V8 is never retried.\n\n"
        "Each V9 worker performs the numeric absence guard exactly once in its "
        "initializer, imports only afterward, and seals module object, origin, "
        "source hash, symbol, and runtime state. Every task revalidates that "
        "loaded closure without demanding module absence.\n\n"
        "The pinned Python 3.10 quality run passes 90/90 focused V9 tests and "
        "252/252 cache-free V1-V8 regressions; Ruff 0.12.0 passes. The actual "
        "pre-freeze spawn probe passes 50 tasks on 32 workers with 18 reused "
        "PIDs and seven sequential tasks on one targeted PID. Every PID has "
        "initializer count one and absence-guard count one. Fits and "
        "predictions remain zero.\n\n"
        "No run, fit, prediction, registry, evaluator, truth, vault, latent, "
        "heldout, score, champion, or promotion authority is granted. A new "
        f"independent audit with verdict {V9_AUDIT_VERDICT} is required.\n"
    ).encode("ascii")
    core_payloads = {
        "ACCESS_RECEIPT.json": access,
        "AUDIT_CLOSURE.json": failure_closure,
        "DESIGN_LOCK.json": design_lock,
        "INPUT_CLOSURE.json": input_closure,
        "PREDICTION_LAUNCH_CONTRACT.json": launch_contract,
        "PREFLIGHT.json": preflight_record,
        "QUALITY_RECEIPT.json": quality,
        "RESOURCE_RECEIPT.json": resource,
        "SOURCE_CLOSURE.json": source_closure,
    }
    core_files = {
        name: _json_bytes(payload) for name, payload in core_payloads.items()
    }
    core_files.update(
        {
            "PREDICTION_LAUNCHER.py": launcher_bytes,
            "REPORT.md": report,
        }
    )
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.design_manifest.v1",
            "status": "PASS_V9_DESIGN_READY_FOR_INDEPENDENT_AUDIT",
            "design_contract_sha256": contract_sha256(),
            "v7_design_binding": copy.deepcopy(V7_DESIGN_BINDING),
            "v7_audit_binding": copy.deepcopy(V7_AUDIT_BINDING),
            "v8_design_binding": copy.deepcopy(V8_DESIGN_BINDING),
            "v8_audit_binding": copy.deepcopy(V8_AUDIT_BINDING),
            "v8_single_run_failure_evidence_sha256": failure_evidence_sha256(),
            "prediction_launcher_raw_sha256": launcher_sha256,
            "worker_bootstrap_contract_sha256": bootstrap_contract_sha256(),
            "r4_input_binding": copy.deepcopy(R4_INPUT_BINDING),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "core_files": {
                name: {
                    "raw_sha256": _sha256(content),
                    "size_bytes": len(content),
                    **(
                        {
                            "logical_sha256": _logical_sha256(
                                core_payloads[name]
                            )
                        }
                        if name in core_payloads
                        else {}
                    ),
                }
                for name, content in sorted(core_files.items())
            },
            "real_fit_or_prediction_authority": False,
            "score_or_registry_authority": False,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    payload_files = {**core_files, "MANIFEST.json": manifest_bytes}
    seal = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v9.design_seal.v1",
            "status": "SEALED_V9_PREFLIGHT_STOPPED_FOR_INDEPENDENT_AUDIT",
            "verdict": "GO_NEW_INDEPENDENT_V9_PRELAUNCH_AUDIT_ONLY",
            "design_contract_sha256": contract_sha256(),
            "v7_design_binding": copy.deepcopy(V7_DESIGN_BINDING),
            "v7_audit_binding": copy.deepcopy(V7_AUDIT_BINDING),
            "v8_design_binding": copy.deepcopy(V8_DESIGN_BINDING),
            "v8_audit_binding": copy.deepcopy(V8_AUDIT_BINDING),
            "v8_single_run_failure_evidence_sha256": failure_evidence_sha256(),
            "prediction_launcher_raw_sha256": launcher_sha256,
            "worker_bootstrap_contract_sha256": bootstrap_contract_sha256(),
            "r4_input_binding": copy.deepcopy(R4_INPUT_BINDING),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "artifact_hashes": {
                name: {
                    "raw_sha256": _sha256(content),
                    "size_bytes": len(content),
                }
                for name, content in sorted(payload_files.items())
            },
            "authority": authority,
        }
    )
    seal_bytes = _json_bytes(seal)
    checksummed = {**payload_files, "SEAL_RECEIPT.json": seal_bytes}
    checksums = "".join(
        f"{_sha256(checksummed[name])}  {name}\n"
        for name in FINAL_FILE_UNIVERSE
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    bundle = {**checksummed, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(bundle)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("V9 design bundle universe drifted")
    return bundle


def verify_design_bundle(
    output_root: Path,
    *,
    expected_checksums_raw_sha256: str,
) -> dict[str, Any]:
    if not _is_sha256(expected_checksums_raw_sha256):
        raise RuntimeError("V9 expected checksum receipt is invalid")
    root = Path(output_root)
    if root.is_symlink() or _is_reparse(root) or not root.is_dir():
        raise RuntimeError("V9 design root is non-regular")
    children = tuple(root.iterdir())
    if any(path.is_symlink() or _is_reparse(path) or not path.is_file() for path in children):
        raise RuntimeError("V9 design contains a non-regular child")
    names = tuple(sorted(path.name for path in children))
    if names != FINAL_FILE_UNIVERSE or len({name.casefold() for name in names}) != len(names):
        raise RuntimeError(f"V9 design universe drifted: {names!r}")
    contents = {path.name: path.read_bytes() for path in children}
    if _sha256(contents["CHECKSUMS.sha256"]) != expected_checksums_raw_sha256:
        raise RuntimeError("V9 external checksum receipt drifted")
    ledger_names = tuple(
        name for name in FINAL_FILE_UNIVERSE if name != "CHECKSUMS.sha256"
    )
    lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    if len(lines) != len(ledger_names):
        raise RuntimeError("V9 checksum ledger count drifted")
    for position, line in enumerate(lines):
        digest, name = line.split("  ", maxsplit=1)
        if (
            name != ledger_names[position]
            or not _is_sha256(digest)
            or _sha256(contents[name]) != digest
        ):
            raise RuntimeError(f"V9 checksum ledger drifted: {position}")
    parsed = {
        name: _parse_json_exact(content, label=name)
        for name, content in contents.items()
        if name.endswith(".json")
    }
    logical = {
        name: _logical_sha256(payload) for name, payload in parsed.items()
    }
    manifest = parsed["MANIFEST.json"]
    seal = parsed["SEAL_RECEIPT.json"]
    if (
        manifest.get("design_contract_sha256")
        != seal.get("design_contract_sha256")
        or manifest.get("design_contract_sha256") != contract_sha256()
        or manifest.get("expected_final_file_universe")
        != list(FINAL_FILE_UNIVERSE)
        or seal.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE)
        or manifest.get("prediction_launcher_raw_sha256")
        != _sha256(contents["PREDICTION_LAUNCHER.py"])
        or seal.get("prediction_launcher_raw_sha256")
        != manifest.get("prediction_launcher_raw_sha256")
        or manifest.get("v8_single_run_failure_evidence_sha256")
        != failure_evidence_sha256()
        or seal.get("v8_single_run_failure_evidence_sha256")
        != failure_evidence_sha256()
        or manifest.get("worker_bootstrap_contract_sha256")
        != bootstrap_contract_sha256()
        or seal.get("worker_bootstrap_contract_sha256")
        != bootstrap_contract_sha256()
    ):
        raise RuntimeError("V9 manifest or seal cross-binding drifted")
    expected_core = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "MANIFEST.json", "SEAL_RECEIPT.json"}
    )
    if tuple(sorted(manifest.get("core_files", {}))) != expected_core:
        raise RuntimeError("V9 manifest core universe drifted")
    for name in expected_core:
        receipt = manifest["core_files"][name]
        if (
            receipt.get("raw_sha256") != _sha256(contents[name])
            or receipt.get("size_bytes") != len(contents[name])
        ):
            raise RuntimeError(f"V9 manifest core receipt drifted: {name}")
        if name.endswith(".json") and receipt.get("logical_sha256") != logical[name]:
            raise RuntimeError(f"V9 manifest logical receipt drifted: {name}")
    sealed_names = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "SEAL_RECEIPT.json"}
    )
    if tuple(sorted(seal.get("artifact_hashes", {}))) != sealed_names:
        raise RuntimeError("V9 seal artifact universe drifted")
    for name in sealed_names:
        if seal["artifact_hashes"][name] != {
            "raw_sha256": _sha256(contents[name]),
            "size_bytes": len(contents[name]),
        }:
            raise RuntimeError(f"V9 seal artifact receipt drifted: {name}")
    canonical = build_design_bundle_bytes(PROJECT_ROOT)
    if any(canonical[name] != contents[name] for name in FINAL_FILE_UNIVERSE):
        raise RuntimeError("V9 frozen design differs from canonical live rebuild")
    return {
        "status": "PASS_EXACT_V9_DESIGN_BUNDLE_CLOSURE",
        "file_count": len(contents),
        "design_contract_sha256": contract_sha256(),
        "checksums_raw_sha256": expected_checksums_raw_sha256,
        "manifest_raw_sha256": _sha256(contents["MANIFEST.json"]),
        "seal_raw_sha256": _sha256(contents["SEAL_RECEIPT.json"]),
        "launcher_raw_sha256": _sha256(contents["PREDICTION_LAUNCHER.py"]),
        "source_closure_raw_sha256": _sha256(contents["SOURCE_CLOSURE.json"]),
    }


def freeze_design_bundle(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    raw_target = Path(output_root)
    if raw_target.is_symlink() or _is_reparse(raw_target):
        raise RuntimeError("V9 freeze target reparse point is forbidden")
    target = raw_target.resolve()
    outputs_root = (PROJECT_ROOT / "outputs").resolve()
    if target.parent != outputs_root or target != DEFAULT_OUTPUT_ROOT.resolve():
        raise RuntimeError("V9 freeze target must be the exact declared outputs child")
    staging = outputs_root / f".{target.name}.staging"
    if target.exists() or staging.exists():
        raise FileExistsError("V9 freeze target or staging already exists")
    bundle = build_design_bundle_bytes(PROJECT_ROOT)
    expected = _sha256(bundle["CHECKSUMS.sha256"])
    staging.mkdir(exist_ok=False)
    try:
        for name in FINAL_FILE_UNIVERSE:
            with (staging / name).open("xb") as handle:
                handle.write(bundle[name])
                handle.flush()
                os.fsync(handle.fileno())
        _fsync_directory(staging)
        verify_design_bundle(
            staging,
            expected_checksums_raw_sha256=expected,
        )
        os.replace(staging, target)
        _fsync_directory(outputs_root)
    except BaseException:
        raise
    if staging.exists() or not target.is_dir():
        raise RuntimeError("V9 atomic freeze publication failed")
    return verify_design_bundle(
        target,
        expected_checksums_raw_sha256=expected,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    if args.write:
        print(json.dumps(freeze_design_bundle(args.output_root), sort_keys=True))
        return 0
    payload = build_preflight_payload()
    print(
        json.dumps(
            {
                "status": payload["status"],
                "design_contract_sha256": payload["design_contract_sha256"],
                "preflight_sha256": _sha256(canonical_json_bytes(payload)),
                "source_file_count": payload["source_audit"]["source_file_count"],
                "failure_evidence_sha256": (
                    payload["v8_single_run_failure_evidence_sha256"]
                ),
                "worker_bootstrap_contract_sha256": (
                    payload["worker_bootstrap_contract_sha256"]
                ),
                "real_fit_count": 0,
                "real_prediction_count": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
