"""Build and atomically freeze the score-free H-OFS V10 authority repair."""

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

from research.model_zoo.hierarchical_observable_fair_value_state_v10 import (
    FUTURE_AUDIT_VERDICT,
    V9_AUDIT_BINDING,
    V9_DESIGN_BINDING,
    contract_payload,
    contract_sha256,
    run_source_audit_v10,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v10.contracts import (
    PINNED_AFFINITY_MASK,
    PINNED_CPU_IDS,
    PINNED_GPU_ENVIRONMENT,
    PINNED_OUTER_WORKERS,
    PINNED_PYTHON_EXECUTABLE,
    PINNED_PYTHON_EXECUTABLE_SHA256,
    PINNED_PYTHON_VERSION,
    PINNED_RAM_MIN_FREE_GIB,
    PINNED_RAM_SOFT_BUDGET_GIB,
    PINNED_THREAD_ENVIRONMENT,
    R4_INPUT_BINDING,
    canonical_json_bytes,
    sealed_payload,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_hierarchical_observable_fair_value_state_v10_"
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
V9_DESIGN_FILE_UNIVERSE = (
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
V9_AUDIT_FILE_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "AUDIT.json",
    "CHECKSUMS.sha256",
    "MANIFEST.json",
    "PROBE_RECEIPT.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "SEAL_RECEIPT.json",
    "build_audit.py",
    "independent_probe.py",
)
V8_FAILED_RUN = {
    "run_id": "20260821T075500",
    "final_root": (
        "outputs/model_zoo_hierarchical_observable_fair_value_state_v8_"
        "dgp_r4_prediction_only_20260821T075500"
    ),
    "staging_root": (
        "outputs/.model_zoo_hierarchical_observable_fair_value_state_v8_"
        "dgp_r4_prediction_only_20260821T075500.staging"
    ),
    "staging_creation_time_utc_ns": 1_787_298_916_351_775_400,
    "failure_evidence_sha256": (
        "151425ff324aa2e650c0b58c05f3cc56348fa7d129cbbfadd2e2efbcf984fed3"
    ),
}


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
                raise RuntimeError(f"V10 duplicate or invalid JSON key: {label}:{key}")
            output[key] = value
        return output

    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                RuntimeError(f"V10 non-finite JSON token: {label}:{token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"V10 invalid JSON: {label}") from error
    if type(value) is not dict:
        raise RuntimeError(f"V10 JSON root is not an object: {label}")
    return value


def _logical_sha256(payload: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(payload)
    expected = unsigned.pop("manifest_sha256", None)
    actual = _sha256(canonical_json_bytes(unsigned))
    if expected != actual:
        raise RuntimeError("V10 artifact logical self-seal drifted")
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
        raise RuntimeError(f"V10 non-regular file: {path}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError(f"V10 file escaped root: {path}") from error
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
        raise RuntimeError("V10 directory fsync handle failed")
    try:
        if not ctypes.windll.kernel32.FlushFileBuffers(handle):  # type: ignore[attr-defined]
            raise RuntimeError("V10 directory fsync failed")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def _verify_checksum_bundle(
    root: Path,
    *,
    expected_universe: tuple[str, ...],
    expected_checksums_raw_sha256: str,
    label: str,
) -> tuple[dict[str, bytes], dict[str, dict[str, Any]]]:
    if root.is_symlink() or _is_reparse(root) or not root.is_dir():
        raise RuntimeError(f"{label} root is non-regular")
    children = tuple(root.iterdir())
    if any(
        path.is_symlink() or _is_reparse(path) or not path.is_file()
        for path in children
    ):
        raise RuntimeError(f"{label} contains a non-regular child")
    names = tuple(sorted(path.name for path in children))
    if names != expected_universe or len({name.casefold() for name in names}) != len(
        names
    ):
        raise RuntimeError(f"{label} exact file universe drifted")
    contents = {name: _require_regular(root / name, root=root) for name in names}
    if _sha256(contents["CHECKSUMS.sha256"]) != expected_checksums_raw_sha256:
        raise RuntimeError(f"{label} external checksum pin drifted")
    ledger_names = tuple(name for name in expected_universe if name != "CHECKSUMS.sha256")
    lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    if len(lines) != len(ledger_names):
        raise RuntimeError(f"{label} checksum ledger count drifted")
    for position, line in enumerate(lines):
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError(f"{label} malformed checksum line: {position}")
        digest, name = parts
        if (
            name != ledger_names[position]
            or not _is_sha256(digest)
            or _sha256(contents[name]) != digest
        ):
            raise RuntimeError(f"{label} checksum ledger drifted: {position}")
    parsed = {
        name: _parse_json_exact(content, label=f"{label}:{name}")
        for name, content in contents.items()
        if name.endswith(".json")
    }
    for payload in parsed.values():
        _logical_sha256(payload)
    return contents, parsed


def _verify_v8_empty_staging(project_root: Path) -> dict[str, Any]:
    final_root = project_root / V8_FAILED_RUN["final_root"]
    staging_root = project_root / V8_FAILED_RUN["staging_root"]
    if (
        final_root.exists()
        or not staging_root.is_dir()
        or staging_root.is_symlink()
        or _is_reparse(staging_root)
    ):
        raise RuntimeError("V10 inherited V8 failure roots drifted")
    stat_result = staging_root.stat()
    if (
        stat_result.st_ctime_ns != V8_FAILED_RUN["staging_creation_time_utc_ns"]
        or stat_result.st_mtime_ns
        != V8_FAILED_RUN["staging_creation_time_utc_ns"]
        or tuple(staging_root.iterdir())
    ):
        raise RuntimeError("V10 inherited V8 empty staging drifted")
    return {
        "status": "PASS_V8_FAILED_RUN_EMPTY_STAGING_UNCHANGED_NEVER_RETRIED",
        "run_id": V8_FAILED_RUN["run_id"],
        "final_root": V8_FAILED_RUN["final_root"],
        "final_root_exists": False,
        "staging_root": V8_FAILED_RUN["staging_root"],
        "staging_root_exists": True,
        "staging_child_count": 0,
        "staging_reparse_point": False,
        "staging_creation_time_utc_ns": V8_FAILED_RUN[
            "staging_creation_time_utc_ns"
        ],
        "failure_evidence_sha256": V8_FAILED_RUN["failure_evidence_sha256"],
        "retry_count_by_v10": 0,
    }


def verify_v9_lineage(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    design_root = project_root / str(V9_DESIGN_BINDING["path"])
    audit_root = project_root / str(V9_AUDIT_BINDING["path"])
    design, design_json = _verify_checksum_bundle(
        design_root,
        expected_universe=V9_DESIGN_FILE_UNIVERSE,
        expected_checksums_raw_sha256=str(
            V9_DESIGN_BINDING["checksums_raw_sha256"]
        ),
        label="V9 frozen design",
    )
    pinned_design_files = {
        "MANIFEST.json": V9_DESIGN_BINDING["manifest_raw_sha256"],
        "SEAL_RECEIPT.json": V9_DESIGN_BINDING["seal_raw_sha256"],
        "INPUT_CLOSURE.json": V9_DESIGN_BINDING["input_closure_raw_sha256"],
        "PREDICTION_LAUNCHER.py": V9_DESIGN_BINDING[
            "prediction_launcher_raw_sha256"
        ],
        "SOURCE_CLOSURE.json": V9_DESIGN_BINDING["source_closure_raw_sha256"],
    }
    if any(
        _sha256(design[name]) != expected
        for name, expected in pinned_design_files.items()
    ):
        raise RuntimeError("V10 inherited V9 design raw pin drifted")
    design_manifest = design_json["MANIFEST.json"]
    design_seal = design_json["SEAL_RECEIPT.json"]
    if (
        design_manifest.get("design_contract_sha256")
        != V9_DESIGN_BINDING["design_contract_sha256"]
        or design_seal.get("design_contract_sha256")
        != V9_DESIGN_BINDING["design_contract_sha256"]
        or design_manifest.get("expected_final_file_universe")
        != list(V9_DESIGN_FILE_UNIVERSE)
        or design_seal.get("expected_final_file_universe")
        != list(V9_DESIGN_FILE_UNIVERSE)
        or design_manifest.get("real_fit_or_prediction_authority") is not False
        or design_manifest.get("score_or_registry_authority") is not False
    ):
        raise RuntimeError("V10 inherited V9 design cross-seal drifted")

    audit, audit_json = _verify_checksum_bundle(
        audit_root,
        expected_universe=V9_AUDIT_FILE_UNIVERSE,
        expected_checksums_raw_sha256=str(
            V9_AUDIT_BINDING["checksums_raw_sha256"]
        ),
        label="V9 independent audit",
    )
    pinned_audit_files = {
        "AUDIT.json": V9_AUDIT_BINDING["audit_raw_sha256"],
        "MANIFEST.json": V9_AUDIT_BINDING["manifest_raw_sha256"],
        "SEAL_RECEIPT.json": V9_AUDIT_BINDING["seal_raw_sha256"],
    }
    if any(
        _sha256(audit[name]) != expected
        for name, expected in pinned_audit_files.items()
    ):
        raise RuntimeError("V10 inherited V9 audit raw pin drifted")
    audit_payload = audit_json["AUDIT.json"]
    audit_seal = audit_json["SEAL_RECEIPT.json"]
    finding_ids = [row.get("finding_id") for row in audit_payload.get("findings", [])]
    if (
        _logical_sha256(audit_payload)
        != V9_AUDIT_BINDING["audit_semantic_sha256"]
        or audit_payload.get("verdict") != V9_AUDIT_BINDING["verdict"]
        or audit_payload.get("severity_counts")
        != V9_AUDIT_BINDING["severity_counts"]
        or finding_ids != V9_AUDIT_BINDING["finding_ids"]
        or audit_payload.get("prediction_only_launch_authority") is not False
        or audit_seal.get("verdict") != V9_AUDIT_BINDING["verdict"]
        or audit_seal.get("finding_count") != 2
        or audit_seal.get("authority")
        != {
            "evaluator": False,
            "prediction_only_launch": False,
            "promotion": False,
            "registry_or_champion": False,
            "score": False,
        }
    ):
        raise RuntimeError("V10 inherited V9 NO_GO audit cross-seal drifted")
    return {
        "schema_version": "expected_pe.hofs_v10.v9_lineage_closure.v1",
        "status": "PASS_EXACT_IMMUTABLE_V9_DESIGN_AND_NO_GO_AUDIT_BOUND",
        "v9_design_binding": copy.deepcopy(V9_DESIGN_BINDING),
        "v9_audit_binding": copy.deepcopy(V9_AUDIT_BINDING),
        "v9_design_file_count": len(design),
        "v9_design_checksum_ledger_entry_count": len(design) - 1,
        "v9_audit_file_count": len(audit),
        "v9_audit_checksum_ledger_entry_count": len(audit) - 1,
        "v9_audit_payload": copy.deepcopy(audit_payload),
        "v8_empty_staging": _verify_v8_empty_staging(project_root),
        "v9_source_or_artifact_mutation_count": 0,
        "v9_model_retry_count": 0,
    }


def _inherited_input_closure(
    project_root: Path,
    lineage: dict[str, Any],
) -> dict[str, Any]:
    input_path = (
        project_root
        / str(lineage["v9_design_binding"]["path"])
        / "INPUT_CLOSURE.json"
    )
    content = _require_regular(input_path, root=project_root)
    if _sha256(content) != V9_DESIGN_BINDING["input_closure_raw_sha256"]:
        raise RuntimeError("V10 inherited V9 input closure raw pin drifted")
    payload = _parse_json_exact(content, label="V9:INPUT_CLOSURE.json")
    _logical_sha256(payload)
    public_files = payload.get("public_files")
    if (
        type(public_files) is not list
        or len(public_files) != R4_INPUT_BINDING["bound_public_file_count"]
        or _sha256(canonical_json_bytes(public_files))
        != R4_INPUT_BINDING["bound_public_files_sha256"]
        or payload.get("public_files_sha256")
        != R4_INPUT_BINDING["bound_public_files_sha256"]
        or payload.get("input_binding", {}).get("checksums_raw_sha256")
        != R4_INPUT_BINDING["checksums_raw_sha256"]
    ):
        raise RuntimeError("V10 inherited public R4 input closure drifted")
    return sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.inherited_r4_input_closure.v1",
            "status": "PASS_EXACT_V9_PUBLIC_R4_INPUT_CLOSURE_INHERITED_NO_REOPEN",
            "r4_input_binding": copy.deepcopy(R4_INPUT_BINDING),
            "v9_input_closure_raw_sha256": _sha256(content),
            "v9_input_closure_semantic_sha256": _logical_sha256(payload),
            "inherited_input_closure": payload,
            "input_payload_open_count_by_v10": 0,
            "public_header_open_count_by_v10": 0,
            "protected_or_score_open_count": 0,
        }
    )


def _authority() -> dict[str, bool]:
    return {
        "score_free_design_preflight_only": True,
        "independent_audit_verdict": False,
        "production_key_or_key_pin": False,
        "execution_or_run": False,
        "real_fit": False,
        "real_prediction": False,
        "truth_qualification_heldout_evaluator_or_score": False,
        "registry_or_champion": False,
        "promotion": False,
    }


def build_preflight_payload(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    source_audit = run_source_audit_v10(project_root)
    if source_audit.get("passed") is not True:
        raise RuntimeError("V10 source audit failed")
    lineage = verify_v9_lineage(project_root)
    return {
        "schema_version": "expected_pe.hofs_v10.dgp_r4_design_preflight.v1",
        "status": "PASS_V10_SCORE_FREE_REPAIR_PREFLIGHT_AWAITS_INDEPENDENT_AUDIT",
        "design_contract_sha256": contract_sha256(),
        "design_contract": contract_payload(),
        "lineage": lineage,
        "source_audit": source_audit,
        "r4_input_binding": copy.deepcopy(R4_INPUT_BINDING),
        "production_key_boundary": {
            "signature_algorithm": "Ed25519_RFC8032_STRICT_VERIFY_ONLY",
            "production_private_key_present": False,
            "production_signing_api_present": False,
            "production_public_key_value_present": False,
            "production_public_key_pin_present": False,
            "status": "FAIL_CLOSED_UNTIL_NEW_AUDIT_AND_CUSTODIAN_PIN_INJECTION",
            "future_required_audit_verdict": FUTURE_AUDIT_VERDICT,
            "fixture_private_key_location": (
                "tests/model_lab/"
                "test_hierarchical_observable_fair_value_state_v10.py"
            ),
            "fixture_is_production_authority": False,
        },
        "authority": _authority(),
    }


def build_design_bundle_bytes(project_root: Path = PROJECT_ROOT) -> dict[str, bytes]:
    preflight = build_preflight_payload(project_root)
    lineage = copy.deepcopy(preflight["lineage"])
    source_audit = copy.deepcopy(preflight["source_audit"])
    authority = copy.deepcopy(preflight["authority"])
    input_closure = _inherited_input_closure(project_root, lineage)
    launcher_relative = (
        "scripts/model_lab/hierarchical_observable_fair_value_state_v10/"
        "prediction_launcher.py"
    )
    launcher_bytes = _require_regular(
        project_root / launcher_relative,
        root=project_root,
    )
    launcher_sha256 = _sha256(launcher_bytes)
    if dict(source_audit["source_sha256"]).get(launcher_relative) != launcher_sha256:
        raise RuntimeError("V10 launcher is not bound by the source closure")

    launch_contract = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.score_free_launch_contract.v1",
            "status": "FROZEN_CHECK_ONLY_NO_EXECUTION_MODE",
            "design_contract_sha256": contract_sha256(),
            "launcher_relative_path": launcher_relative,
            "launcher_raw_sha256": launcher_sha256,
            "cli_modes": ["--check"],
            "run_mode_present": False,
            "worker_entry_visibility": "MODULE_INTERNAL_NOT_PACKAGE_EXPORTED",
            "production_key_interface": {
                "private_key_or_signer_present": False,
                "public_key_value_present": False,
                "public_key_pin_present": False,
                "detached_public_key_and_sha256_pin_required": True,
                "domain_separation_required": True,
                "exact_future_audit_verdict": FUTURE_AUDIT_VERDICT,
                "current_status": "FAIL_CLOSED_NO_PRODUCTION_AUTHORITY",
            },
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "authority": authority,
        }
    )
    design_lock = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.design_lock.v1",
            "status": "PASS_EXACT_TWO_FINDING_SCORE_FREE_REPAIR_LOCK",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "v9_lineage": lineage,
            "repair": {
                "finding_scope": copy.deepcopy(V9_AUDIT_BINDING["finding_ids"]),
                "signed_capability_binds_exact_independent_go": True,
                "signed_capability_binds_run_session_and_task_manifest": True,
                "signed_capability_binds_custodian_consumption_and_one_shot": True,
                "per_task_signature_reverification": True,
                "per_task_atomic_shared_consumption_before_downstream": True,
                "module_internal_worker_entry": True,
                "initializer_generates_actual_guard_receipt": True,
                "public_or_optional_guard_receipt_builder": False,
                "none_guard_receipt_fallback": False,
                "direct_task_dispatch_before_initializer": "FAIL_CLOSED",
                "mismatched_run_or_task": "FAIL_CLOSED",
                "duplicate_replay_or_concurrent_duplicate": "FAIL_CLOSED",
                "preloaded_numeric_before_initializer": "FAIL_CLOSED",
            },
            "production_key_boundary": preflight["production_key_boundary"],
            "unchanged_scope": {
                "v9_source_or_artifact_mutation_count": 0,
                "v9_retry_count": 0,
                "estimator_feature_order_geometry_or_output_change": False,
                "real_fit_count": 0,
                "real_prediction_count": 0,
            },
            "authority": authority,
        }
    )
    audit_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.v9_no_go_repair_closure.v1",
            "status": "PASS_V9_NO_GO_EXACT_TWO_FINDINGS_BOUND_NOT_OVERRIDDEN",
            "v9_design_binding": copy.deepcopy(V9_DESIGN_BINDING),
            "v9_audit_binding": copy.deepcopy(V9_AUDIT_BINDING),
            "v9_audit_payload": lineage["v9_audit_payload"],
            "v8_empty_staging": lineage["v8_empty_staging"],
            "repair_mapping": {
                "HOFS_V9_P0_DIRECT_WORKER_AUTHORITY_BYPASS": (
                    "STRICT_SIGNED_GO_RUN_TASK_AND_ATOMIC_ONE_SHOT_GATE"
                ),
                "HOFS_V9_P1_FORGEABLE_ABSENCE_GUARD_RECEIPT": (
                    "INTERNAL_INITIALIZER_GENERATED_NONOPTIONAL_ACTUAL_GUARD"
                ),
            },
            "builder_independent_audit_verdict": False,
            "builder_overrides_v9_no_go": False,
            "new_independent_v10_audit_required": True,
            "authority": authority,
        }
    )
    source_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.source_closure.v1",
            "status": "PASS_EXACT_NINE_FILE_SCORE_FREE_REPAIR_SOURCE_CLOSURE",
            "source_audit": source_audit,
            "source_file_count": source_audit["source_file_count"],
            "prediction_launcher_raw_sha256": launcher_sha256,
            "production_signing_api_count": 0,
            "production_private_key_literal_count": 0,
            "production_public_key_literal_count": 0,
            "launcher_run_mode_count": 0,
            "real_fit_or_prediction_call_count": 0,
            "protected_or_score_access_count": 0,
            "registry_mutation_count": 0,
        }
    )
    resource = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.resource_receipt.v1",
            "status": "PASS_PINNED_PY310_OUTER32_INNER1_GPU_OFF_SCORE_FREE",
            "runtime": {
                "python_version": PINNED_PYTHON_VERSION,
                "python_executable": PINNED_PYTHON_EXECUTABLE,
                "python_executable_sha256": PINNED_PYTHON_EXECUTABLE_SHA256,
                "logical_cpu_count": 32,
                "cpu_ids": list(PINNED_CPU_IDS),
                "affinity_mask_hex": f"0x{PINNED_AFFINITY_MASK:08X}",
                "max_outer_workers": PINNED_OUTER_WORKERS,
                "inner_threads": 1,
                "thread_environment": [
                    list(value) for value in PINNED_THREAD_ENVIRONMENT
                ],
                "gpu_environment": [list(value) for value in PINNED_GPU_ENVIRONMENT],
                "gpu_used": False,
                "ram_soft_budget_gib": PINNED_RAM_SOFT_BUDGET_GIB,
                "ram_min_free_gib": PINNED_RAM_MIN_FREE_GIB,
            },
            "score_free_benchmark_process_bound": {
                "controller": 1,
                "manager_ledger_service": 1,
                "workers": 32,
                "maximum_local_processes": 34,
            },
            "benchmark": {
                "production_equivalent": {
                    "worker_count": 32,
                    "task_count": 50,
                    "initializer_count_per_pid": 1,
                    "absence_guard_count_per_pid": 1,
                    "signature_reverification_count": 50,
                    "atomic_consumption_count": 50,
                    "reused_worker_count": 18,
                    "maximum_reuse_count": 2,
                },
                "targeted_same_pid": {
                    "worker_count": 1,
                    "task_count": 7,
                    "initializer_count_per_pid": 1,
                    "absence_guard_count_per_pid": 1,
                    "signature_reverification_count": 7,
                    "atomic_consumption_count": 7,
                    "maximum_reuse_count": 7,
                },
                "fixture_only": True,
                "public_input_open_count": 0,
                "downstream_callback_invocation_count": 0,
                "real_fit_count": 0,
                "real_prediction_count": 0,
            },
            "production_run_performed": False,
        }
    )
    quality = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.quality_receipt.v1",
            "status": "PASS_V10_18_PLUS_LEGACY342_RUFF_AND_FIXTURE_LIFECYCLE",
            "pytest": {
                "python_version": PINNED_PYTHON_VERSION,
                "bytecode_disabled": True,
                "cache_provider_disabled": True,
                "focused_v10_passed": 18,
                "focused_v10_failed": 0,
                "clean_mirror_v1_through_v9_passed": 342,
                "clean_mirror_v1_through_v9_failed": 0,
                "clean_mirror_source_cache_directories_before": 0,
                "clean_mirror_source_cache_directories_after": 0,
                "initial_discarded_environment_attempt_count": 1,
                "discarded_attempt_reason": (
                    "MIRROR_COPY_DID_NOT_PRESERVE_FROZEN_EMPTY_STAGING_TIMESTAMPS"
                ),
                "mirror_metadata_repaired_from_frozen_v8_evidence_only": True,
                "live_v8_or_v9_mutation_count": 0,
            },
            "ruff": {"version": "0.12.0", "status": "ALL_CHECKS_PASSED"},
            "fixture_lifecycle_benchmark": resource["benchmark"],
            "adversarial_coverage": {
                "forged_signature_or_payload": True,
                "wrong_public_key_or_pin": True,
                "wrong_audit_verdict_or_nonzero_findings": True,
                "expired_or_non_one_shot_capability": True,
                "mismatched_task_manifest": True,
                "mismatched_run_or_task_identity": True,
                "duplicate_and_replay": True,
                "concurrent_duplicate_exactly_one_winner": True,
                "direct_task_dispatch": True,
                "initializer_marker_bypass": True,
                "preloaded_numpy": True,
                "package_worker_export_absence": True,
                "optional_guard_receipt_absence": True,
                "launcher_run_fit_prediction_surface_absence": True,
            },
            "production_private_key_present": False,
            "production_public_key_value_present": False,
            "fixture_private_key_location": (
                "tests/model_lab/"
                "test_hierarchical_observable_fair_value_state_v10.py"
            ),
            "fixture_is_production_authority": False,
            "public_input_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
        }
    )
    access = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.access_receipt.v1",
            "status": "PASS_FROZEN_LINEAGE_AND_SOURCE_ONLY_ZERO_MODEL_ACCESS",
            "output_mutation_scope": DEFAULT_OUTPUT_ROOT.relative_to(
                project_root
            ).as_posix(),
            "v9_design_file_read_count": len(V9_DESIGN_FILE_UNIVERSE),
            "v9_audit_file_read_count": len(V9_AUDIT_FILE_UNIVERSE),
            "v8_empty_staging_metadata_read_count": 1,
            "public_input_payload_open_count": 0,
            "public_input_header_open_count": 0,
            "truth_qualification_heldout_evaluator_or_score_open_count": 0,
            "model_registry_file_read_count": 0,
            "registry_or_champion_mutation_count": 0,
            "score_call_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "promotion_count": 0,
        }
    )
    preflight_record = sealed_payload(preflight)
    report = (
        "# H-OFS V10 score-free authority repair preflight\n\n"
        "Status: PASS_V10_REPAIR_DESIGN_AWAITS_INDEPENDENT_AUDIT\n\n"
        f"Contract: {contract_sha256()}\n\n"
        "V10 preserves V9 and its sealed NO_GO audit without retrying either. "
        "It repairs only the direct worker authority bypass and forgeable "
        "absence-guard receipt findings. The V8 failed-run final root remains "
        "absent and its exact empty staging directory remains unchanged.\n\n"
        "The production surface is verify-only. No production private key, "
        "signer, public-key value, or public-key pin is present. Therefore the "
        "bundle fails closed until a new independent zero-finding V10 audit "
        "binds the exact required GO verdict and a separate custodian injects "
        "the matching detached public key and one-shot authority. The only "
        "private seed is a test fixture in the focused test source.\n\n"
        "The initializer generates its own nonoptional absence-guard receipt. "
        "Every task re-verifies the signed audit/run/session/task capability "
        "and atomically consumes the exact task before any downstream access. "
        "The frozen launcher exposes check only; it has no run, fit, public "
        "input, prediction, score, or registry path.\n\n"
        "Cache-disabled checks pass 18 focused V10 tests and 342 clean-mirror "
        "V1-V9 regressions. Ruff passes. Fixture-only spawn probes pass 50 "
        "tasks on 32 workers and seven tasks in one reused PID with zero "
        "public input opens, downstream callbacks, fits, or predictions.\n\n"
        "This builder makes no independent audit decision and grants no "
        "execution authority. A different auditor must inspect this sealed "
        "bundle before any future integration.\n"
    ).encode("ascii")
    core_payloads = {
        "ACCESS_RECEIPT.json": access,
        "AUDIT_CLOSURE.json": audit_closure,
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
        {"PREDICTION_LAUNCHER.py": launcher_bytes, "REPORT.md": report}
    )
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.design_manifest.v1",
            "status": "PASS_V10_SCORE_FREE_REPAIR_READY_FOR_OTHER_AUDITOR",
            "design_contract_sha256": contract_sha256(),
            "v9_design_binding": copy.deepcopy(V9_DESIGN_BINDING),
            "v9_audit_binding": copy.deepcopy(V9_AUDIT_BINDING),
            "prediction_launcher_raw_sha256": launcher_sha256,
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "core_files": {
                name: {
                    "raw_sha256": _sha256(content),
                    "size_bytes": len(content),
                    **(
                        {"logical_sha256": _logical_sha256(core_payloads[name])}
                        if name in core_payloads
                        else {}
                    ),
                }
                for name, content in sorted(core_files.items())
            },
            "production_private_key_present": False,
            "production_public_key_value_present": False,
            "production_public_key_pin_present": False,
            "independent_audit_verdict": False,
            "execution_authority": False,
            "real_fit_or_prediction_authority": False,
            "score_or_registry_authority": False,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    payload_files = {**core_files, "MANIFEST.json": manifest_bytes}
    seal = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v10.design_seal.v1",
            "status": "SEALED_V10_SCORE_FREE_REPAIR_AWAITS_INDEPENDENT_AUDIT",
            "verdict": "STOP_AT_V10_DESIGN_PREFLIGHT_AUDIT_REQUIRED",
            "design_contract_sha256": contract_sha256(),
            "v9_design_binding": copy.deepcopy(V9_DESIGN_BINDING),
            "v9_audit_binding": copy.deepcopy(V9_AUDIT_BINDING),
            "prediction_launcher_raw_sha256": launcher_sha256,
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "artifact_hashes": {
                name: {
                    "raw_sha256": _sha256(content),
                    "size_bytes": len(content),
                }
                for name, content in sorted(payload_files.items())
            },
            "production_key_boundary": preflight["production_key_boundary"],
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
        raise RuntimeError("V10 design bundle universe drifted")
    return bundle


def verify_design_bundle(
    output_root: Path,
    *,
    expected_checksums_raw_sha256: str,
) -> dict[str, Any]:
    if not _is_sha256(expected_checksums_raw_sha256):
        raise RuntimeError("V10 expected checksum receipt is invalid")
    contents, parsed = _verify_checksum_bundle(
        Path(output_root),
        expected_universe=FINAL_FILE_UNIVERSE,
        expected_checksums_raw_sha256=expected_checksums_raw_sha256,
        label="V10 frozen design",
    )
    logical = {
        name: _logical_sha256(payload) for name, payload in parsed.items()
    }
    manifest = parsed["MANIFEST.json"]
    seal = parsed["SEAL_RECEIPT.json"]
    launch_contract = parsed["PREDICTION_LAUNCH_CONTRACT.json"]
    launcher_sha256 = _sha256(contents["PREDICTION_LAUNCHER.py"])
    if (
        manifest.get("design_contract_sha256") != contract_sha256()
        or seal.get("design_contract_sha256") != contract_sha256()
        or manifest.get("expected_final_file_universe")
        != list(FINAL_FILE_UNIVERSE)
        or seal.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE)
        or manifest.get("prediction_launcher_raw_sha256") != launcher_sha256
        or seal.get("prediction_launcher_raw_sha256") != launcher_sha256
        or launch_contract.get("launcher_raw_sha256") != launcher_sha256
        or launch_contract.get("run_mode_present") is not False
        or manifest.get("production_private_key_present") is not False
        or manifest.get("production_public_key_value_present") is not False
        or manifest.get("production_public_key_pin_present") is not False
        or manifest.get("independent_audit_verdict") is not False
        or manifest.get("execution_authority") is not False
        or manifest.get("real_fit_or_prediction_authority") is not False
        or manifest.get("score_or_registry_authority") is not False
        or seal.get("verdict") != "STOP_AT_V10_DESIGN_PREFLIGHT_AUDIT_REQUIRED"
        or seal.get("authority") != _authority()
    ):
        raise RuntimeError("V10 manifest, launch contract, or seal drifted")
    expected_core = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "MANIFEST.json", "SEAL_RECEIPT.json"}
    )
    if tuple(sorted(manifest.get("core_files", {}))) != expected_core:
        raise RuntimeError("V10 manifest core universe drifted")
    for name in expected_core:
        receipt = manifest["core_files"][name]
        if (
            receipt.get("raw_sha256") != _sha256(contents[name])
            or receipt.get("size_bytes") != len(contents[name])
        ):
            raise RuntimeError(f"V10 manifest core receipt drifted: {name}")
        if name.endswith(".json") and receipt.get("logical_sha256") != logical[name]:
            raise RuntimeError(f"V10 manifest logical receipt drifted: {name}")
    sealed_names = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "SEAL_RECEIPT.json"}
    )
    if tuple(sorted(seal.get("artifact_hashes", {}))) != sealed_names:
        raise RuntimeError("V10 seal artifact universe drifted")
    for name in sealed_names:
        if seal["artifact_hashes"][name] != {
            "raw_sha256": _sha256(contents[name]),
            "size_bytes": len(contents[name]),
        }:
            raise RuntimeError(f"V10 seal artifact receipt drifted: {name}")
    canonical = build_design_bundle_bytes(PROJECT_ROOT)
    if any(canonical[name] != contents[name] for name in FINAL_FILE_UNIVERSE):
        raise RuntimeError("V10 frozen design differs from canonical live rebuild")
    return {
        "status": "PASS_EXACT_V10_SCORE_FREE_REPAIR_DESIGN_BUNDLE_CLOSURE",
        "file_count": len(contents),
        "checksum_ledger_entry_count": len(contents) - 1,
        "design_contract_sha256": contract_sha256(),
        "checksums_raw_sha256": expected_checksums_raw_sha256,
        "manifest_raw_sha256": _sha256(contents["MANIFEST.json"]),
        "manifest_semantic_sha256": logical["MANIFEST.json"],
        "seal_raw_sha256": _sha256(contents["SEAL_RECEIPT.json"]),
        "seal_semantic_sha256": logical["SEAL_RECEIPT.json"],
        "launcher_raw_sha256": launcher_sha256,
        "source_closure_raw_sha256": _sha256(contents["SOURCE_CLOSURE.json"]),
        "independent_audit_verdict": False,
        "execution_authority": False,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def freeze_design_bundle(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    raw_target = Path(output_root)
    if raw_target.is_symlink() or _is_reparse(raw_target):
        raise RuntimeError("V10 freeze target reparse point is forbidden")
    target = raw_target.resolve()
    outputs_root = (PROJECT_ROOT / "outputs").resolve()
    if target.parent != outputs_root or target != DEFAULT_OUTPUT_ROOT.resolve():
        raise RuntimeError("V10 freeze target must be the exact declared outputs child")
    staging = outputs_root / f".{target.name}.staging"
    if target.exists() or staging.exists():
        raise FileExistsError("V10 freeze target or staging already exists")
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
        raise RuntimeError("V10 atomic freeze publication failed")
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
    preflight = build_preflight_payload()
    print(
        json.dumps(
            {
                "status": preflight["status"],
                "design_contract_sha256": preflight["design_contract_sha256"],
                "preflight_sha256": _sha256(canonical_json_bytes(preflight)),
                "source_file_count": preflight["source_audit"]["source_file_count"],
                "v9_design_file_count": preflight["lineage"]["v9_design_file_count"],
                "v9_audit_file_count": preflight["lineage"]["v9_audit_file_count"],
                "production_private_key_present": False,
                "production_public_key_value_present": False,
                "production_public_key_pin_present": False,
                "independent_audit_verdict": False,
                "execution_authority": False,
                "real_fit_count": 0,
                "real_prediction_count": 0,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
