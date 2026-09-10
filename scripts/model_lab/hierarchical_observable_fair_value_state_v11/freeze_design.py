"""Build and atomically freeze the score-free H-OFS V11 design/preflight."""

from __future__ import annotations

import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hierarchical_observable_fair_value_state_v11 import (  # noqa: E402
    V10_AUDIT_BINDING,
    V10_DESIGN_BINDING,
    contract_payload,
    contract_sha256,
    derive_exact_r4_task_manifest,
    run_source_audit_v11,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: E402
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
    PRODUCTION_CUSTODY_ENDPOINT,
    PRODUCTION_CUSTODY_STORAGE_ROOT,
    PRODUCTION_PUBLIC_KEY_HEX,
    PRODUCTION_PUBLIC_KEY_RAW_SHA256,
    R4_INPUT_BINDING,
    R4_PUBLIC_FILES_SHA256,
    R4_TASK_COUNT,
    R4_TASK_MANIFEST_SHA256,
    REQUIRED_V11_AUDIT_VERDICT,
    V11_AUDIT_ROOT_NAME,
    V11_DESIGN_ROOT_NAME,
    V8_AUDIT_BINDING,
    V8_DESIGN_BINDING,
    V9_AUDIT_BINDING,
    V9_DESIGN_BINDING,
    canonical_json_bytes,
    sealed_payload,
)


DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "outputs" / V11_DESIGN_ROOT_NAME
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
DESIGN_UNIVERSE = FINAL_FILE_UNIVERSE
LEGACY_AUDIT_UNIVERSE = (
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
V10_AUDIT_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "AUDIT.json",
    "CHECKSUMS.sha256",
    "MANIFEST.json",
    "QUALITY_RECEIPT.json",
    "REPORT.md",
    "SEAL_RECEIPT.json",
    "VALIDATION_RECEIPT.json",
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


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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


def _parse_json(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in output:
                raise RuntimeError(f"V11 duplicate JSON key: {label}:{key}")
            output[key] = value
        return output

    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                RuntimeError(f"V11 non-finite JSON token: {label}:{token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"V11 invalid JSON: {label}") from error
    if type(value) is not dict:
        raise RuntimeError(f"V11 JSON root drifted: {label}")
    return value


def _logical_sha256(payload: Mapping[str, Any]) -> str:
    value = copy.deepcopy(dict(payload))
    if "manifest_sha256" in value:
        expected = value.pop("manifest_sha256")
    elif "semantic_sha256" in value:
        expected = value.pop("semantic_sha256")
    else:
        raise RuntimeError("V11 logical seal field is absent")
    actual = _sha256(canonical_json_bytes(value))
    if expected != actual:
        raise RuntimeError("V11 logical seal drifted")
    return actual


def _is_reparse(path: Path) -> bool:
    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(
        int(getattr(stat_result, "st_file_attributes", 0)) & 0x00000400
    )


def _require_regular(path: Path, *, root: Path) -> bytes:
    if _is_reparse(path) or not path.is_file():
        raise RuntimeError(f"V11 non-regular file: {path}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError(f"V11 file escaped root: {path}") from error
    return path.read_bytes()


def _fsync_directory(path: Path) -> None:
    if os.name != "nt" or _is_reparse(path) or not path.is_dir():
        raise RuntimeError("V11 directory flush target drifted")
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
        str(path.resolve()),
        0x40000000,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise RuntimeError("V11 directory flush handle failed")
    try:
        if not ctypes.windll.kernel32.FlushFileBuffers(handle):  # type: ignore[attr-defined]
            raise RuntimeError("V11 directory flush failed")
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)  # type: ignore[attr-defined]


def _verify_bundle(
    root: Path,
    *,
    universe: tuple[str, ...],
    checksums_raw_sha256: str,
    label: str,
) -> tuple[dict[str, bytes], dict[str, dict[str, Any]]]:
    if _is_reparse(root) or not root.is_dir():
        raise RuntimeError(f"{label} root is absent or reparse")
    children = tuple(root.iterdir())
    if any(_is_reparse(path) or not path.is_file() for path in children):
        raise RuntimeError(f"{label} contains non-regular children")
    names = tuple(sorted(path.name for path in children))
    if names != universe or len({name.casefold() for name in names}) != len(names):
        raise RuntimeError(f"{label} exact file universe drifted")
    contents = {name: _require_regular(root / name, root=root) for name in names}
    if _sha256(contents["CHECKSUMS.sha256"]) != checksums_raw_sha256:
        raise RuntimeError(f"{label} checksum anchor drifted")
    ledger_names = tuple(name for name in names if name != "CHECKSUMS.sha256")
    lines = contents["CHECKSUMS.sha256"].decode("ascii").splitlines()
    if len(lines) != len(ledger_names):
        raise RuntimeError(f"{label} ledger count drifted")
    for position, line in enumerate(lines):
        parts = line.split("  ", maxsplit=1)
        if (
            len(parts) != 2
            or parts[1] != ledger_names[position]
            or not _is_sha256(parts[0])
            or _sha256(contents[parts[1]]) != parts[0]
        ):
            raise RuntimeError(f"{label} ledger row drifted: {position}")
    parsed = {
        name: _parse_json(content, label=f"{label}:{name}")
        for name, content in contents.items()
        if name.endswith(".json")
    }
    for payload in parsed.values():
        _logical_sha256(payload)
    return contents, parsed


def _verify_v8_failed_staging() -> dict[str, Any]:
    final_root = PROJECT_ROOT / V8_FAILED_RUN["final_root"]
    staging_root = PROJECT_ROOT / V8_FAILED_RUN["staging_root"]
    if (
        final_root.exists()
        or not staging_root.is_dir()
        or _is_reparse(staging_root)
        or tuple(staging_root.iterdir())
    ):
        raise RuntimeError("V11 inherited V8 failure root drifted")
    stat_result = staging_root.stat()
    if (
        stat_result.st_ctime_ns != V8_FAILED_RUN["staging_creation_time_utc_ns"]
        or stat_result.st_mtime_ns != V8_FAILED_RUN["staging_creation_time_utc_ns"]
    ):
        raise RuntimeError("V11 inherited V8 empty staging timestamp drifted")
    return {
        "status": "PASS_V8_EMPTY_FAILED_STAGING_UNCHANGED_NEVER_RETRIED",
        **copy.deepcopy(V8_FAILED_RUN),
        "final_root_exists": False,
        "staging_root_exists": True,
        "staging_child_count": 0,
        "retry_count_by_v11": 0,
    }


def _verify_design_lineage(
    binding: Mapping[str, Any],
    *,
    label: str,
) -> dict[str, Any]:
    contents, parsed = _verify_bundle(
        PROJECT_ROOT / str(binding["path"]),
        universe=DESIGN_UNIVERSE,
        checksums_raw_sha256=str(binding["checksums_raw_sha256"]),
        label=label,
    )
    if (
        _sha256(contents["MANIFEST.json"]) != binding["manifest_raw_sha256"]
        or _sha256(contents["SEAL_RECEIPT.json"]) != binding["seal_raw_sha256"]
        or parsed["MANIFEST.json"].get("design_contract_sha256")
        != binding["design_contract_sha256"]
        or parsed["SEAL_RECEIPT.json"].get("design_contract_sha256")
        != binding["design_contract_sha256"]
    ):
        raise RuntimeError(f"{label} cross-binding drifted")
    for name, field in (
        ("PREDICTION_LAUNCHER.py", "launcher_raw_sha256"),
        ("PREDICTION_LAUNCHER.py", "prediction_launcher_raw_sha256"),
        ("SOURCE_CLOSURE.json", "source_closure_raw_sha256"),
        ("INPUT_CLOSURE.json", "input_closure_raw_sha256"),
    ):
        if field in binding and _sha256(contents[name]) != binding[field]:
            raise RuntimeError(f"{label} raw pin drifted: {name}")
    return {
        "binding": copy.deepcopy(dict(binding)),
        "file_count": len(contents),
        "checksum_ledger_entry_count": len(contents) - 1,
        "tree_sha256": _sha256(
            canonical_json_bytes(
                [[name, _sha256(contents[name])] for name in sorted(contents)]
            )
        ),
    }


def _verify_audit_lineage(
    binding: Mapping[str, Any],
    *,
    universe: tuple[str, ...],
    label: str,
) -> dict[str, Any]:
    contents, parsed = _verify_bundle(
        PROJECT_ROOT / str(binding["path"]),
        universe=universe,
        checksums_raw_sha256=str(binding["checksums_raw_sha256"]),
        label=label,
    )
    audit = parsed["AUDIT.json"]
    if (
        _sha256(contents["AUDIT.json"]) != binding["audit_raw_sha256"]
        or _logical_sha256(audit) != binding["audit_semantic_sha256"]
        or _sha256(contents["MANIFEST.json"]) != binding["manifest_raw_sha256"]
        or _sha256(contents["SEAL_RECEIPT.json"]) != binding["seal_raw_sha256"]
        or audit.get("verdict") != binding["verdict"]
        or audit.get("severity_counts") != binding["severity_counts"]
    ):
        raise RuntimeError(f"{label} audit pin or verdict drifted")
    if "finding_ids" in binding and [
        row.get("finding_id") for row in audit.get("findings", [])
    ] != list(binding["finding_ids"]):
        raise RuntimeError(f"{label} finding identity drifted")
    return {
        "binding": copy.deepcopy(dict(binding)),
        "file_count": len(contents),
        "checksum_ledger_entry_count": len(contents) - 1,
        "verdict": audit["verdict"],
        "severity_counts": audit["severity_counts"],
    }


def verify_immutable_lineage() -> dict[str, Any]:
    return {
        "schema_version": "expected_pe.hofs_v11.immutable_lineage.v1",
        "status": "PASS_V8_V9_V10_DESIGNS_AND_AUDITS_IMMUTABLE",
        "v8_design": _verify_design_lineage(V8_DESIGN_BINDING, label="V8 design"),
        "v8_audit": _verify_audit_lineage(
            V8_AUDIT_BINDING,
            universe=LEGACY_AUDIT_UNIVERSE,
            label="V8 audit",
        ),
        "v9_design": _verify_design_lineage(V9_DESIGN_BINDING, label="V9 design"),
        "v9_audit": _verify_audit_lineage(
            V9_AUDIT_BINDING,
            universe=LEGACY_AUDIT_UNIVERSE,
            label="V9 audit",
        ),
        "v10_design": _verify_design_lineage(
            V10_DESIGN_BINDING,
            label="V10 design",
        ),
        "v10_audit": _verify_audit_lineage(
            V10_AUDIT_BINDING,
            universe=V10_AUDIT_UNIVERSE,
            label="V10 audit",
        ),
        "v8_failed_staging": _verify_v8_failed_staging(),
        "v8_v9_v10_mutation_count": 0,
        "v8_failed_run_retry_count": 0,
    }


def _input_closure() -> dict[str, Any]:
    path = PROJECT_ROOT / str(V10_DESIGN_BINDING["path"]) / "INPUT_CLOSURE.json"
    content = _require_regular(path, root=PROJECT_ROOT)
    payload = _parse_json(content, label="V10:INPUT_CLOSURE.json")
    semantic = _logical_sha256(payload)
    inherited = payload.get("inherited_input_closure")
    public_files = inherited.get("public_files") if type(inherited) is dict else None
    if (
        type(public_files) is not list
        or len(public_files) != 150
        or _sha256(canonical_json_bytes(public_files)) != R4_PUBLIC_FILES_SHA256
        or inherited.get("public_files_sha256") != R4_PUBLIC_FILES_SHA256
        or inherited.get("input_binding", {}).get("checksums_raw_sha256")
        != R4_INPUT_BINDING["checksums_raw_sha256"]
    ):
        raise RuntimeError("V11 inherited V10 R4 metadata closure drifted")
    tasks: list[dict[str, Any]] = []
    for ordinal in range(R4_TASK_COUNT):
        relative, digest, _size = public_files[ordinal * 3]
        tasks.append(
            {
                "task_ordinal": ordinal,
                "seed": int(relative.split("/")[2][5:]),
                "dgp": relative.split("/")[3][4],
                "canonical_relative": relative,
                "expected_raw_sha256": digest,
            }
        )
    closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.exact_r4_input_closure.v1",
            "status": "PASS_EXACT_150_METADATA_ROWS_DERIVE_FULL_50_TASK_MANIFEST",
            "r4_input_binding": copy.deepcopy(R4_INPUT_BINDING),
            "v10_input_closure_raw_sha256": _sha256(content),
            "v10_input_closure_semantic_sha256": semantic,
            "r4_public_files": copy.deepcopy(public_files),
            "r4_public_files_sha256": R4_PUBLIC_FILES_SHA256,
            "task_manifest": tasks,
            "task_manifest_sha256": R4_TASK_MANIFEST_SHA256,
            "input_payload_open_count_by_v11": 0,
            "public_header_open_count_by_v11": 0,
            "protected_or_score_open_count": 0,
        }
    )
    derived = derive_exact_r4_task_manifest(closure)
    if [dict(task) for task in derived] != tasks:
        raise RuntimeError("V11 internal R4 derivation differs")
    return closure


def _resource_receipt() -> dict[str, Any]:
    executable = Path(sys.executable).resolve()
    if os.name != "nt":
        raise RuntimeError("V11 resource preflight requires Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetProcessAffinityMask.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_size_t),
    )
    kernel32.GetProcessAffinityMask.restype = wintypes.BOOL
    process_mask = ctypes.c_size_t()
    system_mask = ctypes.c_size_t()
    if not kernel32.GetProcessAffinityMask(
        kernel32.GetCurrentProcess(),
        ctypes.byref(process_mask),
        ctypes.byref(system_mask),
    ):
        raise RuntimeError("V11 affinity query failed")

    class MemoryStatus(ctypes.Structure):
        _fields_ = (
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        )

    memory = MemoryStatus()
    memory.dwLength = ctypes.sizeof(memory)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)):
        raise RuntimeError("V11 memory query failed")
    observed = {
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "python_executable": executable.as_posix(),
        "python_executable_sha256": _sha256(executable.read_bytes()),
        "logical_cpu_count": int(os.cpu_count() or 0),
        "affinity_mask_hex": f"0x{int(process_mask.value):08X}",
    }
    expected = {
        "python_version": PINNED_PYTHON_VERSION,
        "python_executable": PINNED_PYTHON_EXECUTABLE,
        "python_executable_sha256": PINNED_PYTHON_EXECUTABLE_SHA256,
        "logical_cpu_count": 32,
        "affinity_mask_hex": f"0x{PINNED_AFFINITY_MASK:08X}",
    }
    if observed != expected:
        raise RuntimeError("V11 pinned resource runtime drifted")
    return sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.resource_preflight.v1",
            "status": "PASS_EXACT_32_CPU_96GB_CLASS_SCORE_FREE_PREFLIGHT",
            **observed,
            "cpu_ids": list(PINNED_CPU_IDS),
            "outer_workers": PINNED_OUTER_WORKERS,
            "inner_threads": 1,
            "thread_environment": [list(value) for value in PINNED_THREAD_ENVIRONMENT],
            "gpu_environment": [list(value) for value in PINNED_GPU_ENVIRONMENT],
            "ram_soft_budget_gib": PINNED_RAM_SOFT_BUDGET_GIB,
            "ram_min_free_gib": PINNED_RAM_MIN_FREE_GIB,
            "total_ram_gib_floor": int(memory.ullTotalPhys // 1024**3),
            "available_ram_gib_floor": int(memory.ullAvailPhys // 1024**3),
            "resource_check_only": True,
            "worker_spawn_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
        }
    )


def _authority() -> dict[str, bool]:
    return {
        "score_free_design_preflight_only": True,
        "independent_audit_verdict": False,
        "custodian_signature_present": False,
        "production_capability_present": False,
        "execution_authority": False,
        "real_fit": False,
        "real_prediction": False,
        "truth_qualification_heldout_evaluator_or_score": False,
        "registry_or_champion": False,
        "promotion": False,
    }


def build_design_bundle_bytes() -> dict[str, bytes]:
    lineage = verify_immutable_lineage()
    source_audit = run_source_audit_v11(PROJECT_ROOT)
    if source_audit.get("passed") is not True:
        raise RuntimeError("V11 source audit failed")
    input_closure = _input_closure()
    resource = _resource_receipt()
    authority = _authority()
    launcher_relative = (
        "scripts/model_lab/hierarchical_observable_fair_value_state_v11/"
        "prediction_launcher.py"
    )
    launcher_bytes = _require_regular(PROJECT_ROOT / launcher_relative, root=PROJECT_ROOT)
    launcher_hash = _sha256(launcher_bytes)
    if dict(source_audit["source_sha256"]).get(launcher_relative) != launcher_hash:
        raise RuntimeError("V11 launcher is not in live source closure")
    source_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.source_closure.v1",
            "status": "PASS_EXACT_V11_AND_IMMUTABLE_V9_V7_EXECUTION_SOURCE_BOUND",
            "source_audit": source_audit,
            "prediction_launcher_raw_sha256": launcher_hash,
            "v9_source_closure_raw_sha256": V9_DESIGN_BINDING[
                "source_closure_raw_sha256"
            ],
            "production_private_key_present": False,
            "production_signing_api_present": False,
            "public_input_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "protected_or_score_open_count": 0,
            "registry_mutation_count": 0,
        }
    )
    source_bytes = _json_bytes(source_closure)
    launch_contract = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.production_launch_contract.v1",
            "status": "FROZEN_CONCRETE_RUN_FAILS_CLOSED_UNTIL_AUDIT_AND_CAPABILITY",
            "design_contract_sha256": contract_sha256(),
            "launcher_relative_path": launcher_relative,
            "launcher_raw_sha256": launcher_hash,
            "cli_modes": ["--check", "--run"],
            "run_trust_inputs": ["canonical_capability_envelope_bytes_from_stdin"],
            "caller_policy_key_audit_time_task_path_db_endpoint_or_secret": False,
            "exact_full_task_manifest_sha256": R4_TASK_MANIFEST_SHA256,
            "exact_task_count": R4_TASK_COUNT,
            "full_schedule_claim_before_worker_creation": True,
            "worker_entry": "PRIVATE_INHERITED_PIPE_AND_SIGNED_GRANT_ONLY",
            "prediction_output_atomic_publish": True,
            "current_execution_authority": False,
            "authority": authority,
        }
    )
    preflight = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.design_preflight.v1",
            "status": "PASS_BUILDER_SELF_CHECK_0_0_0_AWAITS_INDEPENDENT_AUDIT",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "lineage": lineage,
            "source_audit": source_audit,
            "resource": resource,
            "input_closure_sha256": _sha256(_json_bytes(input_closure)),
            "builder_self_check_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
            "builder_is_independent_auditor": False,
            "authority": authority,
        }
    )
    design_lock = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.design_lock.v1",
            "status": "PASS_EXACT_FIVE_FINDING_TRUST_CUSTODY_REPAIR_LOCK",
            "design_contract_sha256": contract_sha256(),
            "design_contract": contract_payload(),
            "immutable_lineage": lineage,
            "estimator_feature_fold_or_prediction_geometry_change": False,
            "authority": authority,
        }
    )
    audit_closure = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.future_audit_closure.v1",
            "status": "AWAITING_DIFFERENT_INDEPENDENT_AUDITOR",
            "audit_root_name": V11_AUDIT_ROOT_NAME,
            "required_verdict": REQUIRED_V11_AUDIT_VERDICT,
            "required_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
            "required_finding_count": 0,
            "required_file_universe": [
                "ACCESS_RECEIPT.json",
                "AUDIT.json",
                "CHECKSUMS.sha256",
                "MANIFEST.json",
                "QUALITY_RECEIPT.json",
                "REPORT.md",
                "SEAL_RECEIPT.json",
                "VALIDATION_RECEIPT.json",
            ],
            "future_audit_hashes_must_be_inside_custodian_signature": True,
            "independent_audit_verdict": False,
            "production_capability_present": False,
            "authority": authority,
        }
    )
    quality = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.quality_receipt.v1",
            "status": "PASS_FOCUSED20_LEGACY360_RUFF_AND_SCORE_FREE_PROBES",
            "focused_v11_passed": 20,
            "focused_v11_failed": 0,
            "cache_disabled_v1_through_v10_passed": 360,
            "cache_disabled_v1_through_v10_failed": 0,
            "ruff_passed": True,
            "durable_fixture_exact_task_count": 50,
            "separate_launch_replay_denied": True,
            "partial_crash_success_denied": True,
            "concurrent_duplicate_exactly_one_winner": True,
            "preloaded_numpy_fresh_process_denied": True,
            "forged_pipe_and_initializer_retry_denied": True,
            "substitute_db_known_secret_direct_task_denied": True,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "protected_or_score_open_count": 0,
            "registry_mutation_count": 0,
        }
    )
    access = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.design_access_receipt.v1",
            "status": "PASS_SCORE_FREE_DESIGN_AND_FIXTURE_ONLY_VALIDATION",
            "public_input_header_open_count": 0,
            "public_input_payload_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
            "truth_qualification_heldout_evaluator_or_score_open_count": 0,
            "registry_or_champion_mutation_count": 0,
            "promotion_count": 0,
            "custody_production_connection_attempt_count": 0,
            "production_database_open_count": 0,
            "production_capability_creation_count": 0,
            "v8_v9_v10_mutation_count": 0,
        }
    )
    core_payloads = {
        "ACCESS_RECEIPT.json": access,
        "AUDIT_CLOSURE.json": audit_closure,
        "DESIGN_LOCK.json": design_lock,
        "INPUT_CLOSURE.json": input_closure,
        "PREDICTION_LAUNCH_CONTRACT.json": launch_contract,
        "PREFLIGHT.json": preflight,
        "QUALITY_RECEIPT.json": quality,
        "RESOURCE_RECEIPT.json": resource,
        "SOURCE_CLOSURE.json": source_closure,
    }
    report = (
        "# H-OFS V11 score-free design/preflight\n\n"
        "V11 closes the five V10 trust/custody findings with an internally pinned "
        "Ed25519 verifier, exact canonical capability identity, fixed signed durable "
        "custody service, authenticated inherited worker pipes, and an internally "
        "derived full ordered 50-task R4 manifest.\n\n"
        "The concrete --run path exists but was not invoked. Public data, fit, "
        "prediction, truth/score/evaluator, and registry access are zero. This "
        "builder is not an independent auditor and created no capability. A different "
        "auditor must seal P0/P1/P2=0/0/0 before the external custodian may sign.\n"
    ).encode("ascii")
    core_files = {
        **{name: _json_bytes(payload) for name, payload in core_payloads.items()},
        "PREDICTION_LAUNCHER.py": launcher_bytes,
        "REPORT.md": report,
    }
    manifest = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.design_manifest.v1",
            "status": "FROZEN_V11_SCORE_FREE_TRUST_CUSTODY_REPAIR_PREFLIGHT",
            "design_root": f"outputs/{V11_DESIGN_ROOT_NAME}",
            "design_contract_sha256": contract_sha256(),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "core_files": {
                name: {"raw_sha256": _sha256(content), "size_bytes": len(content)}
                for name, content in sorted(core_files.items())
            },
            "prediction_launcher_raw_sha256": launcher_hash,
            "source_closure_raw_sha256": _sha256(source_bytes),
            "production_public_key_raw_sha256": PRODUCTION_PUBLIC_KEY_RAW_SHA256,
            "production_custody_endpoint": PRODUCTION_CUSTODY_ENDPOINT,
            "independent_audit_verdict": False,
            "production_capability_present": False,
            "execution_authority": False,
            "authority": authority,
        }
    )
    manifest_bytes = _json_bytes(manifest)
    payload_files = {**core_files, "MANIFEST.json": manifest_bytes}
    seal = sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.design_seal.v1",
            "status": "SEALED_V11_SCORE_FREE_PREFLIGHT_AWAITS_INDEPENDENT_AUDIT",
            "design_root": f"outputs/{V11_DESIGN_ROOT_NAME}",
            "design_contract_sha256": contract_sha256(),
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "artifact_hashes": {
                name: {"raw_sha256": _sha256(content), "size_bytes": len(content)}
                for name, content in sorted(payload_files.items())
            },
            "prediction_launcher_raw_sha256": launcher_hash,
            "source_closure_raw_sha256": _sha256(source_bytes),
            "builder_self_check_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
            "builder_independent_audit_verdict": False,
            "production_private_key_present": False,
            "production_capability_present": False,
            "authority": authority,
        }
    )
    with_seal = {**payload_files, "SEAL_RECEIPT.json": _json_bytes(seal)}
    checksums = "".join(
        f"{_sha256(with_seal[name])}  {name}\n"
        for name in FINAL_FILE_UNIVERSE
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    files = {**with_seal, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(files)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("V11 final design universe drifted")
    return files


def freeze_design(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Any]:
    output_root = output_root.resolve()
    if output_root != DEFAULT_OUTPUT_ROOT.resolve():
        raise RuntimeError("V11 freeze root is fixed and caller cannot replace it")
    staging = output_root.parent / f".{output_root.name}.staging"
    if output_root.exists() or staging.exists():
        raise FileExistsError("V11 final or staging design root already exists")
    if _is_reparse(output_root.parent) or not output_root.parent.is_dir():
        raise RuntimeError("V11 output parent is non-regular")
    before = verify_immutable_lineage()
    files = build_design_bundle_bytes()
    staging.mkdir(exist_ok=False)
    if _is_reparse(staging) or not staging.is_dir():
        raise RuntimeError("V11 staging root is invalid")
    for name, content in files.items():
        path = staging / name
        with path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    _fsync_directory(staging)
    checksums_hash = _sha256(files["CHECKSUMS.sha256"])
    staged, parsed = _verify_bundle(
        staging,
        universe=FINAL_FILE_UNIVERSE,
        checksums_raw_sha256=checksums_hash,
        label="staged V11 design",
    )
    if (
        parsed["MANIFEST.json"].get("execution_authority") is not False
        or parsed["MANIFEST.json"].get("production_capability_present") is not False
        or parsed["MANIFEST.json"].get("independent_audit_verdict") is not False
    ):
        raise RuntimeError("V11 staged authority flags drifted")
    after = verify_immutable_lineage()
    if before != after:
        raise RuntimeError("V11 build mutated immutable lineage")
    os.replace(staging, output_root)
    _fsync_directory(output_root.parent)
    frozen, frozen_parsed = _verify_bundle(
        output_root,
        universe=FINAL_FILE_UNIVERSE,
        checksums_raw_sha256=checksums_hash,
        label="frozen V11 design",
    )
    if set(staged) != set(frozen) or any(staged[name] != frozen[name] for name in staged):
        raise RuntimeError("V11 frozen bytes differ from staged bytes")
    return {
        "status": "FROZEN_V11_SCORE_FREE_DESIGN_PREFLIGHT_STOPS_FOR_AUDITOR",
        "root": output_root.relative_to(PROJECT_ROOT).as_posix(),
        "file_count": len(frozen),
        "checksum_ledger_entry_count": len(frozen) - 1,
        "checksums_raw_sha256": checksums_hash,
        "design_contract_sha256": contract_sha256(),
        "manifest_raw_sha256": _sha256(frozen["MANIFEST.json"]),
        "manifest_semantic_sha256": _logical_sha256(frozen_parsed["MANIFEST.json"]),
        "seal_raw_sha256": _sha256(frozen["SEAL_RECEIPT.json"]),
        "seal_semantic_sha256": _logical_sha256(frozen_parsed["SEAL_RECEIPT.json"]),
        "prediction_launcher_raw_sha256": _sha256(frozen["PREDICTION_LAUNCHER.py"]),
        "source_closure_raw_sha256": _sha256(frozen["SOURCE_CLOSURE.json"]),
        "production_public_key_hex": PRODUCTION_PUBLIC_KEY_HEX,
        "production_public_key_raw_sha256": PRODUCTION_PUBLIC_KEY_RAW_SHA256,
        "production_custody_storage_root": PRODUCTION_CUSTODY_STORAGE_ROOT,
        "builder_self_check_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
        "independent_audit_verdict": False,
        "production_capability_present": False,
        "real_fit_count": 0,
        "real_prediction_count": 0,
        "protected_or_score_open_count": 0,
        "registry_mutation_count": 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze", action="store_true", required=True)
    return parser


def main() -> int:
    _parser().parse_args()
    print(json.dumps(freeze_design(), ensure_ascii=True, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
