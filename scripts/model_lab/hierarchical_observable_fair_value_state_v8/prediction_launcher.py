"""Formal score-blind H-OFS V8 R4 prediction-only launcher and publisher.

The module is stdlib-only until :func:`preimport_guard` has accepted the exact
runtime.  ``--check`` validates the frozen V8 repair design and its exact V7
lineage, source closure, launch contract, public R4 closure, and runtime without
fitting or predicting.  ``--run`` additionally requires detached pins for a
future independent V8 GO audit, performs the exact inherited block plan, and
publishes a verified output root with one same-parent atomic rename.

There is deliberately no score, evaluator, registry, champion, promotion, or
protected-payload API in this file.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import copy
import csv
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import multiprocessing
import os
from pathlib import Path
import re
import sys
import time
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
LAUNCHER_PATH = Path(__file__).resolve()
LAUNCHER_RELATIVE_PATH = (
    "scripts/model_lab/hierarchical_observable_fair_value_state_v8/"
    "prediction_launcher.py"
)
V8_DESIGN_ROOT = (
    OUTPUTS_ROOT
    / "model_zoo_hierarchical_observable_fair_value_state_v8_"
    "dgp_r4_design_preflight_20260821"
)
V8_AUDIT_ROOT = (
    OUTPUTS_ROOT
    / "model_zoo_hierarchical_observable_fair_value_state_v8_"
    "independent_prelaunch_audit_20260821"
)
R4_ROOT = OUTPUTS_ROOT / "model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
OUTPUT_ROOT_PREFIX = (
    "model_zoo_hierarchical_observable_fair_value_state_v8_"
    "dgp_r4_prediction_only_"
)
RUN_ID_PATTERN = re.compile(r"[0-9]{8}T[0-9]{6}\Z")

PINNED_PYTHON_VERSION = "3.10.19"
PINNED_PYTHON_EXECUTABLE = (
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
PINNED_PYTHON_EXECUTABLE_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
PINNED_AFFINITY_MASK = 0xFFFFFFFF
PINNED_OUTER_WORKERS = 32
PINNED_THREAD_ENVIRONMENT = (
    ("OMP_NUM_THREADS", "1"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("MKL_NUM_THREADS", "1"),
    ("NUMEXPR_NUM_THREADS", "1"),
)
PINNED_GPU_ENVIRONMENT = (("CUDA_VISIBLE_DEVICES", "-1"),)

SEEDS = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
DGPS = tuple("ABCDEFGHIJ")
ROWS_PER_TASK = 1800
SCORE_START = 504
SCORE_END = 1800
BLOCK_ROWS = 21
FOLDS_PER_TASK = 62
TASK_COUNT = 50
FIT_COUNT = 3100
DECISION_COUNT = 64800
ALLOWED_CAUSAL_INVALID_POSITIONS = (0, 1, 2)
FIRST_FOLD_WARM_ROWS = 501

EXPECTED_V8_SOURCE_PATHS = (
    "research/model_zoo/hierarchical_observable_fair_value_state_v8/__init__.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v8/bootstrap.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v8/contracts.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v8/source_audit.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v8/DESIGN.md",
    "scripts/model_lab/hierarchical_observable_fair_value_state_v8/freeze_design.py",
    LAUNCHER_RELATIVE_PATH,
    "tests/model_lab/test_hierarchical_observable_fair_value_state_v8.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/__init__.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/adapter.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/artifacts.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/contracts.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/custody.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/dgp_r4.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/estimator.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/features.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/runner.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/runtime.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/source_audit.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/validation.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/DESIGN.md",
    "scripts/model_lab/hierarchical_observable_fair_value_state_v7/prediction_launcher.py",
)

V8_DESIGN_UNIVERSE = tuple(
    sorted(
        {
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
        }
    )
)
V8_AUDIT_UNIVERSE = tuple(
    sorted(
        {
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
        }
    )
)
FINAL_FILE_UNIVERSE = tuple(
    sorted(
        {
            "ACCESS_RECEIPT.json",
            "BLOCK_RECEIPTS.jsonl",
            "CHECKSUMS.sha256",
            "EXECUTION_RECEIPT.json",
            "IMMUTABILITY_RECEIPT.json",
            "INPUT_RECEIPT.json",
            "LAUNCH_CONTRACT.json",
            "MANIFEST.json",
            "PREDICTIONS.csv",
            "REPORT.md",
            "RUNTIME_RECEIPT.json",
            "SEAL_RECEIPT.json",
            "TASK_RECEIPTS.jsonl",
            "prediction_launcher.py",
        }
    )
)
PREDICTION_COLUMNS = (
    "task_ordinal",
    "task_seed",
    "task_dgp",
    "fold_index",
    "source_row_position",
    "entity_id",
    "decision_date",
    "hofs_v7_expected_pe",
    "hofs_v7_pe_p10",
    "hofs_v7_pe_p90",
    "hofs_v7_log_scale",
    "hofs_v7_tail_guard_weight",
    "parameter_sha256",
    "decision_block_ordered_membership_sha256",
    "decision_block_set_membership_sha256",
    "decision_source_positions_sha256",
    "output_manifest_sha256",
    "within_block_parameter_update_count",
)
FORBIDDEN_OUTPUT_COLUMN_TOKENS = (
    "truth",
    "target",
    "score",
    "evaluator",
    "vault",
    "latent",
    "heldout",
    "observed",
)
V8_AUDIT_VERDICT = "GO_SCORE_BLIND_PREDICTION_ONLY_LAUNCH_EXACT_FROZEN_V8_ONLY"


for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def require_sha256(value: object, *, label: str) -> str:
    if not is_sha256(value):
        raise RuntimeError(f"{label} must be one lowercase SHA-256")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def pretty_json_bytes(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        ).encode("ascii")
        + b"\n"
    )


def sealed(payload: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(payload)
    result.pop("manifest_sha256", None)
    result["manifest_sha256"] = sha256_bytes(canonical_json_bytes(result))
    return result


def parse_json_exact(content: bytes, *, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise RuntimeError(f"duplicate/invalid JSON key: {label}:{key}")
            result[key] = value
        return result

    try:
        value = json.loads(
            content.decode("ascii"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda token: (_ for _ in ()).throw(
                RuntimeError(f"non-finite JSON token: {label}:{token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid JSON artifact: {label}") from error
    if type(value) is not dict:
        raise RuntimeError(f"JSON root must be an object: {label}")
    return value


def logical_sha256(payload: dict[str, Any]) -> str:
    expected = payload.get("manifest_sha256")
    unsigned = copy.deepcopy(payload)
    unsigned.pop("manifest_sha256", None)
    actual = sha256_bytes(canonical_json_bytes(unsigned))
    if expected != actual:
        raise RuntimeError("logical JSON self-seal drifted")
    return actual


def is_reparse(path: Path) -> bool:
    if os.name != "nt":
        return path.is_symlink()
    get_attributes = ctypes.windll.kernel32.GetFileAttributesW  # type: ignore[attr-defined]
    get_attributes.argtypes = [ctypes.c_wchar_p]
    get_attributes.restype = ctypes.c_uint32
    attributes = int(get_attributes(str(path.absolute())))
    return attributes != 0xFFFFFFFF and bool(attributes & 0x00000400)


def require_regular_file(path: Path, *, allowed_root: Path) -> bytes:
    root = allowed_root.resolve()
    if allowed_root.is_symlink() or is_reparse(allowed_root) or not root.is_dir():
        raise RuntimeError(f"invalid allowlisted root: {allowed_root}")
    resolved = path.resolve()
    if (
        path.is_symlink()
        or is_reparse(path)
        or not path.is_file()
        or root not in resolved.parents
    ):
        raise RuntimeError(f"non-regular or escaping allowlisted file: {path}")
    current = path.parent
    while current.resolve() != root:
        if current.is_symlink() or is_reparse(current) or not current.is_dir():
            raise RuntimeError(f"reparse/non-directory parent in allowlisted path: {current}")
        if current.parent == current:
            raise RuntimeError("allowlisted parent chain escaped root")
        current = current.parent
    return path.read_bytes()


def require_exact_bundle(
    root: Path,
    *,
    universe: tuple[str, ...],
    expected_checksums_raw_sha256: str,
) -> tuple[dict[str, bytes], dict[str, str]]:
    expected_checksum = require_sha256(
        expected_checksums_raw_sha256,
        label="external bundle checksum receipt",
    )
    if root.is_symlink() or is_reparse(root) or not root.is_dir():
        raise RuntimeError(f"invalid frozen bundle root: {root}")
    children = tuple(root.iterdir())
    if any(path.is_symlink() or is_reparse(path) or not path.is_file() for path in children):
        raise RuntimeError(f"non-regular frozen bundle child: {root}")
    names = tuple(sorted(path.name for path in children))
    if names != universe or len({name.casefold() for name in names}) != len(names):
        raise RuntimeError(f"frozen bundle universe drifted: {root}:{names!r}")
    contents = {name: (root / name).read_bytes() for name in names}
    checksum_content = contents["CHECKSUMS.sha256"]
    if sha256_bytes(checksum_content) != expected_checksum:
        raise RuntimeError(f"frozen external checksum receipt drifted: {root}")
    expected_names = tuple(name for name in universe if name != "CHECKSUMS.sha256")
    lines = checksum_content.decode("ascii").splitlines()
    if len(lines) != len(expected_names):
        raise RuntimeError("frozen checksum ledger count drifted")
    hashes: dict[str, str] = {"CHECKSUMS.sha256": expected_checksum}
    for position, line in enumerate(lines):
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError("frozen checksum syntax drifted")
        digest, name = parts
        if name != expected_names[position] or not is_sha256(digest):
            raise RuntimeError("frozen checksum order/type drifted")
        if sha256_bytes(contents[name]) != digest:
            raise RuntimeError(f"frozen checksum mismatch: {root}:{name}")
        hashes[name] = digest
    for name, content in contents.items():
        if name.endswith(".json"):
            logical_sha256(parse_json_exact(content, label=f"{root.name}:{name}"))
    return contents, hashes


def current_affinity_mask() -> int:
    if os.name != "nt":
        raise RuntimeError("H-OFS V8 prediction-only launch requires Windows")
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
        raise RuntimeError(f"GetProcessAffinityMask failed: {ctypes.get_last_error()}")
    return int(process_mask.value)


def available_memory_gib() -> float:
    if os.name != "nt":
        raise RuntimeError("H-OFS V8 prediction-only launch requires Windows")

    class MemoryStatusEx(ctypes.Structure):
        _fields_ = [
            ("dwLength", wintypes.DWORD),
            ("dwMemoryLoad", wintypes.DWORD),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(  # type: ignore[attr-defined]
        ctypes.byref(status)
    ):
        raise RuntimeError("GlobalMemoryStatusEx failed")
    return float(status.ullAvailPhys) / float(1024**3)


def preimport_guard() -> dict[str, Any]:
    imported_numeric = sorted(
        name for name in ("numpy", "pandas", "threadpoolctl") if name in sys.modules
    )
    if imported_numeric:
        raise RuntimeError(f"numeric package imported before runtime guard: {imported_numeric}")
    executable = Path(sys.executable).resolve()
    observed = {
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "python_executable": executable.as_posix(),
        "python_executable_sha256": sha256_bytes(executable.read_bytes()),
        "logical_cpu_count": int(os.cpu_count() or 0),
        "outer_workers": PINNED_OUTER_WORKERS,
        "inner_threads": 1,
        "affinity_mask_hex": f"0x{current_affinity_mask():08X}",
        "thread_environment": [
            [name, os.environ.get(name, "")] for name, _ in PINNED_THREAD_ENVIRONMENT
        ],
        "gpu_environment": [
            [name, os.environ.get(name, "")] for name, _ in PINNED_GPU_ENVIRONMENT
        ],
    }
    expected = {
        "python_version": PINNED_PYTHON_VERSION,
        "python_executable": PINNED_PYTHON_EXECUTABLE,
        "python_executable_sha256": PINNED_PYTHON_EXECUTABLE_SHA256,
        "logical_cpu_count": 32,
        "outer_workers": PINNED_OUTER_WORKERS,
        "inner_threads": 1,
        "affinity_mask_hex": f"0x{PINNED_AFFINITY_MASK:08X}",
        "thread_environment": [list(value) for value in PINNED_THREAD_ENVIRONMENT],
        "gpu_environment": [list(value) for value in PINNED_GPU_ENVIRONMENT],
    }
    if observed != expected:
        drifted = sorted(name for name in expected if observed[name] != expected[name])
        raise RuntimeError(f"pre-import exact runtime drifted: {drifted}")
    return observed


def worker_initializer() -> None:
    preimport_guard()


def v8_worker_bootstrap_initializer(
    serialized_task: bytes,
    project_root_text: str,
    allowed_source_hashes: dict[str, str],
    initializer_barrier: Any,
    receipt_queue: Any,
) -> None:
    preimport_guard()
    from research.model_zoo.hierarchical_observable_fair_value_state_v8.bootstrap import (  # noqa: PLC0415
        worker_bootstrap_initializer,
    )

    worker_bootstrap_initializer(
        serialized_task,
        project_root_text,
        allowed_source_hashes,
        initializer_barrier,
        receipt_queue,
    )


def launch_contract_payload(
    *,
    launcher_raw_sha256: str,
    design_contract_sha256: str,
) -> dict[str, Any]:
    return {
        "schema_version": "expected_pe.hofs_v8.prediction_launch_contract.v1",
        "status": "FROZEN_V8_PREDICTION_ONLY_LAUNCHER_AWAITS_INDEPENDENT_AUDIT",
        "design_contract_sha256": require_sha256(
            design_contract_sha256,
            label="V8 design contract hash",
        ),
        "source_path": LAUNCHER_RELATIVE_PATH,
        "source_raw_sha256": require_sha256(
            launcher_raw_sha256,
            label="launcher raw hash",
        ),
        "embedded_filename": "PREDICTION_LAUNCHER.py",
        "modes": ["check", "run"],
        "common_detached_pins": [
            "design_checksums_raw_sha256",
            "design_contract_sha256",
        ],
        "run_only_detached_pins": [
            "audit_checksums_raw_sha256",
            "audit_raw_sha256",
            "audit_semantic_sha256",
            "run_id",
        ],
        "run_id_pattern": "[0-9]{8}T[0-9]{6}",
        "future_independent_audit_required": True,
        "required_audit_verdict": V8_AUDIT_VERDICT,
        "required_audit_severity_counts": {"P0": 0, "P1": 0, "P2": 0},
        "execution_geometry": {
            "task_count": TASK_COUNT,
            "folds_per_task": FOLDS_PER_TASK,
            "fit_count": FIT_COUNT,
            "decision_row_count": DECISION_COUNT,
            "process_start_method": "spawn",
            "maximum_outer_workers": PINNED_OUTER_WORKERS,
            "inner_threads": 1,
            "within_block_parameter_update_count": 0,
        },
        "output_file_universe": list(FINAL_FILE_UNIVERSE),
        "formal_check_worker_bootstrap": {
            "process_start_method": "spawn",
            "exact_initializer_worker_count": 32,
            "execute_task_ast_import_surface_bound": True,
            "all_imported_modules_symbols_origins_and_hashes_attested": True,
            "metadata_only_task_deserialization": True,
            "public_canonical_path_and_header_validation": True,
            "real_fit_count": 0,
            "real_prediction_count": 0,
        },
        "publication": {
            "unique_final_root": True,
            "same_parent_dot_staging": True,
            "exclusive_file_creation": True,
            "file_and_directory_fsync": True,
            "prepublish_exact_universe_verification": True,
            "atomic_publish": "os.replace",
            "postpublish_exact_universe_verification": True,
            "staging_residue_forbidden": True,
        },
        "authority": {
            "design_preflight_real_fit_or_prediction": False,
            "future_run_prediction_only_after_external_audit": True,
            "truth_vault_latent_heldout_evaluator_score_access": False,
            "registry_champion_promotion": False,
        },
    }


def _strict_pair_map(value: object, *, expected_paths: tuple[str, ...]) -> dict[str, str]:
    if type(value) is not list or len(value) != len(expected_paths):
        raise RuntimeError("source closure pair count drifted")
    output: dict[str, str] = {}
    ordered: list[str] = []
    for row in value:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not str
            or not is_sha256(row[1])
            or row[0] in output
        ):
            raise RuntimeError("source closure pair syntax/uniqueness drifted")
        output[row[0]] = row[1]
        ordered.append(row[0])
    if tuple(ordered) != expected_paths:
        raise RuntimeError("source closure path order/universe drifted")
    return output


def verify_design_and_public_surfaces(
    *,
    design_checksums_raw_sha256: str,
    design_contract_sha256: str,
    launcher_bytes: bytes,
) -> dict[str, Any]:
    contents, hashes = require_exact_bundle(
        V8_DESIGN_ROOT,
        universe=V8_DESIGN_UNIVERSE,
        expected_checksums_raw_sha256=design_checksums_raw_sha256,
    )
    manifest = parse_json_exact(contents["MANIFEST.json"], label="V8:MANIFEST")
    if manifest.get("design_contract_sha256") != design_contract_sha256:
        raise RuntimeError("V8 design contract binding drifted")
    if manifest.get("expected_final_file_universe") != list(V8_DESIGN_UNIVERSE):
        raise RuntimeError("V8 design manifest universe drifted")
    from research.model_zoo.hierarchical_observable_fair_value_state_v8.contracts import (  # noqa: PLC0415
        V7_AUDIT_BINDING,
        V7_DESIGN_BINDING,
        V7_SINGLE_RUN_FAILURE_EVIDENCE,
        failure_evidence_sha256,
    )

    failure_closure = parse_json_exact(
        contents["AUDIT_CLOSURE.json"],
        label="V8:V7_FAILURE_CLOSURE",
    )
    if (
        failure_closure.get("v7_design_binding") != V7_DESIGN_BINDING
        or failure_closure.get("v7_audit_binding") != V7_AUDIT_BINDING
        or failure_closure.get("v7_single_run_failure_evidence")
        != V7_SINGLE_RUN_FAILURE_EVIDENCE
        or failure_closure.get("v7_single_run_failure_evidence_sha256")
        != failure_evidence_sha256()
        or failure_closure.get("completed_task_count") != 0
        or failure_closure.get("completed_fit_count") != 0
        or failure_closure.get("completed_prediction_row_count") != 0
    ):
        raise RuntimeError("V8 exact V7 single-run failure binding drifted")

    source_closure = parse_json_exact(
        contents["SOURCE_CLOSURE.json"],
        label="V8:SOURCE_CLOSURE",
    )
    source_audit = source_closure.get("source_audit")
    if type(source_audit) is not dict or source_closure.get("source_file_count") != len(
        EXPECTED_V8_SOURCE_PATHS
    ):
        raise RuntimeError("V8 source closure count drifted")
    source_map = _strict_pair_map(
        source_audit.get("source_sha256"),
        expected_paths=EXPECTED_V8_SOURCE_PATHS,
    )
    source_snapshot: dict[str, list[Any]] = {}
    for relative, expected in source_map.items():
        content = require_regular_file(PROJECT_ROOT / relative, allowed_root=PROJECT_ROOT)
        actual = sha256_bytes(content)
        if actual != expected:
            raise RuntimeError(f"V8 source byte drifted: {relative}")
        source_snapshot[relative] = [actual, len(content)]
    launcher_sha256 = sha256_bytes(launcher_bytes)
    if source_map.get(LAUNCHER_RELATIVE_PATH) != launcher_sha256:
        raise RuntimeError("V8 source closure does not bind the executing launcher")
    if contents["PREDICTION_LAUNCHER.py"] != launcher_bytes:
        raise RuntimeError("embedded V8 prediction launcher differs from executing bytes")

    launch_contract = parse_json_exact(
        contents["PREDICTION_LAUNCH_CONTRACT.json"],
        label="V8:PREDICTION_LAUNCH_CONTRACT",
    )
    logical_sha256(launch_contract)
    expected_contract = launch_contract_payload(
        launcher_raw_sha256=launcher_sha256,
        design_contract_sha256=design_contract_sha256,
    )
    unsigned_contract = dict(launch_contract)
    unsigned_contract.pop("manifest_sha256", None)
    if unsigned_contract != expected_contract:
        raise RuntimeError("embedded V8 prediction launch contract drifted")

    input_closure = parse_json_exact(
        contents["INPUT_CLOSURE.json"],
        label="V8:INPUT_CLOSURE",
    )
    input_binding = input_closure.get("input_binding")
    public_files = input_closure.get("public_files")
    if (
        type(input_binding) is not dict
        or input_binding.get("path")
        != "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
        or type(public_files) is not list
        or len(public_files) != 150
    ):
        raise RuntimeError("V8 public input closure drifted")
    if sha256_bytes(canonical_json_bytes(public_files)) != input_binding.get(
        "bound_public_files_sha256"
    ):
        raise RuntimeError("V8 public semantic ledger drifted")
    public_snapshot: dict[str, list[Any]] = {}
    allowed_suffixes = (
        "/canonical150.csv",
        "/v04_overlay.csv",
        "/comparator_diagnostics.csv",
    )
    for row in public_files:
        if (
            type(row) is not list
            or len(row) != 3
            or type(row[0]) is not str
            or not row[0].endswith(allowed_suffixes)
            or not is_sha256(row[1])
            or type(row[2]) is not int
        ):
            raise RuntimeError("V7 public ledger row drifted")
        relative, expected_digest, expected_size = row
        content = require_regular_file(R4_ROOT / Path(relative), allowed_root=R4_ROOT)
        if sha256_bytes(content) != expected_digest or len(content) != expected_size:
            raise RuntimeError(f"public R4 file drifted: {relative}")
        if relative in public_snapshot:
            raise RuntimeError("public R4 ledger path is duplicated")
        public_snapshot[relative] = [expected_digest, expected_size]
    metadata_pins = {
        "FREEZE_RECEIPT.json": "freeze_receipt_raw_sha256",
        "CHECKSUMS.sha256": "checksums_raw_sha256",
        "PUBLIC_HASH_LEDGER.json": "public_hash_ledger_raw_sha256",
        "TASK_DIAGNOSTICS.csv": "task_diagnostics_raw_sha256",
        "SOURCE_MANIFEST.csv": "source_manifest_raw_sha256",
    }
    metadata_snapshot: dict[str, list[Any]] = {}
    for name, pin in metadata_pins.items():
        content = require_regular_file(R4_ROOT / name, allowed_root=R4_ROOT)
        digest = sha256_bytes(content)
        if digest != input_binding.get(pin):
            raise RuntimeError(f"public R4 metadata pin drifted: {name}")
        metadata_snapshot[name] = [digest, len(content)]
    snapshot = {
        "v8_design_files": dict(sorted(hashes.items())),
        "v8_and_inherited_source_files": dict(sorted(source_snapshot.items())),
        "public_r4_files": dict(sorted(public_snapshot.items())),
        "public_r4_metadata": dict(sorted(metadata_snapshot.items())),
    }
    return {
        "contents": contents,
        "hashes": hashes,
        "source_map": source_map,
        "input_closure": input_closure,
        "launch_contract": launch_contract,
        "snapshot": snapshot,
        "snapshot_sha256": sha256_bytes(canonical_json_bytes(snapshot)),
        "group_sha256": {
            name: sha256_bytes(canonical_json_bytes(value))
            for name, value in snapshot.items()
        },
        "group_counts": {name: len(value) for name, value in snapshot.items()},
    }


def verify_independent_go_audit(
    *,
    audit_checksums_raw_sha256: str,
    audit_raw_sha256: str,
    audit_semantic_sha256: str,
    design_checksums_raw_sha256: str,
    design_contract_sha256: str,
) -> dict[str, Any]:
    contents, hashes = require_exact_bundle(
        V8_AUDIT_ROOT,
        universe=V8_AUDIT_UNIVERSE,
        expected_checksums_raw_sha256=audit_checksums_raw_sha256,
    )
    audit = parse_json_exact(contents["AUDIT.json"], label="V8:AUDIT")
    if (
        sha256_bytes(contents["AUDIT.json"])
        != require_sha256(audit_raw_sha256, label="V8 audit raw hash")
        or logical_sha256(audit)
        != require_sha256(audit_semantic_sha256, label="V8 audit semantic hash")
        or audit.get("verdict") != V8_AUDIT_VERDICT
        or audit.get("severity_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or audit.get("findings") != []
        or audit.get("finding_count") != 0
        or audit.get("prediction_only_launch_authority") is not True
        or audit.get("audited_bundle_checksums_raw_sha256")
        != design_checksums_raw_sha256
        or audit.get("design_contract_sha256") != design_contract_sha256
    ):
        raise RuntimeError("V8 independent GO audit drifted")
    seal_receipt = parse_json_exact(contents["SEAL_RECEIPT.json"], label="V8:AUDIT_SEAL")
    if (
        seal_receipt.get("verdict") != V8_AUDIT_VERDICT
        or seal_receipt.get("severity_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or seal_receipt.get("finding_count") != 0
        or seal_receipt.get("authority", {}).get("prediction_only_launch") is not True
        or seal_receipt.get("authority", {}).get("score") is not False
        or seal_receipt.get("authority", {}).get("registry_or_champion") is not False
        or seal_receipt.get("authority", {}).get("promotion") is not False
    ):
        raise RuntimeError("V8 independent audit authority seal drifted")
    return {
        "hashes": hashes,
        "audit": audit,
        "seal": seal_receipt,
        "checksums_raw_sha256": audit_checksums_raw_sha256,
        "raw_sha256": audit_raw_sha256,
        "semantic_sha256": audit_semantic_sha256,
    }


def _identity_rows(frame: Any, identity_columns: tuple[str, str]) -> list[list[str]]:
    return [
        [str(entity), date.isoformat()]
        for entity, date in frame.loc[:, list(identity_columns)].itertuples(
            index=False,
            name=None,
        )
    ]


def _require_v7_prefix_receipt(
    fit_receipt: Any,
    *,
    expected_requested: int,
    seed: int,
    dgp: str,
    fold_index: int,
) -> tuple[list[list[Any]], list[list[Any]]]:
    count_rows = fit_receipt.prefix_entity_row_counts
    position_rows = fit_receipt.prefix_entity_causal_invalid_positions
    if (
        count_rows
        != (("DGP_ISSUER", expected_requested, 3, expected_requested - 3),)
        or position_rows
        != (("DGP_ISSUER", ALLOWED_CAUSAL_INVALID_POSITIONS),)
        or fit_receipt.requested_row_count != expected_requested
        or fit_receipt.causal_prefix_nonwarm_row_count != 3
        or fit_receipt.dropped_nonwarm_row_count != 3
        or fit_receipt.fit_row_count != expected_requested - 3
        or fit_receipt.fit_row_count < FIRST_FOLD_WARM_ROWS
    ):
        raise RuntimeError(
            f"worker V7 prefix position/warm receipt drifted: {seed}/{dgp}/{fold_index}"
        )
    return (
        [list(row) for row in count_rows],
        [[entity, list(positions)] for entity, positions in position_rows],
    )


def execute_task(
    task_ordinal: int,
    seed: int,
    dgp: str,
    canonical_relative: str,
    expected_raw_sha256: str,
) -> dict[str, Any]:
    worker_guard = preimport_guard()

    import numpy as np  # noqa: PLC0415
    import pandas as pd  # noqa: PLC0415

    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: PLC0415
        adapt_r4_canonical_source_v7,
        build_hierarchical_state_features_v7,
        build_r4_fold_plan_v7,
        fit_chronological_prefix_v7,
        run_frozen_decision_block_v7,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v7.contracts import (  # noqa: PLC0415
        IDENTITY_COLUMNS,
        OUTPUT_COLUMNS,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v7.dgp_r4 import (  # noqa: PLC0415
        R4_CANONICAL_COLUMNS,
    )

    path = R4_ROOT / Path(canonical_relative)
    content = require_regular_file(path, allowed_root=R4_ROOT)
    if sha256_bytes(content) != expected_raw_sha256:
        raise RuntimeError(f"worker public canonical hash drifted: {seed}/{dgp}")
    canonical = pd.read_csv(io.BytesIO(content))
    source = adapt_r4_canonical_source_v7(canonical)
    if tuple(source.columns) != R4_CANONICAL_COLUMNS or len(source) != ROWS_PER_TASK:
        raise RuntimeError(f"worker canonical source schema drifted: {seed}/{dgp}")
    if not source.index.equals(pd.RangeIndex(ROWS_PER_TASK)):
        raise RuntimeError(f"worker canonical source index drifted: {seed}/{dgp}")
    canonical_probe = source.loc[:, ["symbol", "date"]].sort_values(
        ["date", "symbol"],
        kind="mergesort",
    )
    actual_rows = [
        [str(symbol), pd.Timestamp(date).isoformat()]
        for symbol, date in source.loc[:, ["symbol", "date"]].itertuples(
            index=False,
            name=None,
        )
    ]
    probe_rows = [
        [str(symbol), pd.Timestamp(date).isoformat()]
        for symbol, date in canonical_probe.itertuples(index=False, name=None)
    ]
    if actual_rows != probe_rows:
        raise RuntimeError(
            f"worker input is not already canonical; silent sort forbidden: {seed}/{dgp}"
        )
    full_state = build_hierarchical_state_features_v7(source)
    full_state.assert_live_integrity()
    if _identity_rows(full_state.identities, IDENTITY_COLUMNS) != actual_rows:
        raise RuntimeError(f"worker source/state identity parity drifted: {seed}/{dgp}")
    observed = source["observed_pe"].copy()
    research_groups = pd.Series(
        [f"DGP_{dgp}"] * ROWS_PER_TASK,
        index=source.index,
        dtype="object",
    )
    plan = tuple(
        item for item in build_r4_fold_plan_v7() if item.seed == seed and item.dgp == dgp
    )
    if len(plan) != FOLDS_PER_TASK:
        raise RuntimeError(f"worker fold plan drifted: {seed}/{dgp}")

    prediction_rows: list[dict[str, Any]] = []
    block_receipts: list[dict[str, Any]] = []
    fit_runtime_payload: dict[str, Any] | None = None
    inference_runtime_payload: dict[str, Any] | None = None
    for spec in plan:
        start = spec.decision_block_start_inclusive
        end = spec.decision_block_end_exclusive
        requested = full_state.identities.iloc[start:end].copy()
        if requested.index.tolist() != list(range(start, end)):
            raise RuntimeError(f"worker requested source positions drifted: {seed}/{dgp}")
        requested_rows = _identity_rows(requested, IDENTITY_COLUMNS)
        requested_probe = sorted(requested_rows, key=lambda row: (row[1], row[0]))
        if requested_rows != requested_probe:
            raise RuntimeError(
                f"worker requested block is not already canonical: {seed}/{dgp}/{spec.fold_index}"
            )
        capability = fit_chronological_prefix_v7(
            source,
            decision_block_identities=requested,
            observed_pe=observed,
            research_dgp_groups=research_groups,
        )
        fit = capability.fit
        parameters = fit.parameters
        fit_receipt = fit.fit_receipt
        output = run_frozen_decision_block_v7(
            source,
            requested_identities=requested,
            parameters=parameters,
        )
        parameter_sha256 = parameters.sha256()
        fit_receipt_sha256 = fit_receipt.sha256()
        output_manifest = output.output_manifest_payload()
        output_manifest_sha256 = output.output_manifest_sha256
        expected_positions = tuple(range(start, end))
        if (
            parameters.decision_source_positions != expected_positions
            or fit_receipt.decision_source_positions != expected_positions
            or output.parameter_sha256 != parameter_sha256
            or parameters.convergence_receipt_sha256 != fit_receipt_sha256
            or output.input_rows != spec.decision_row_count
            or len(output.values) != spec.decision_row_count
            or tuple(output.values.columns) != OUTPUT_COLUMNS
            or output.within_block_parameter_update_count != 0
            or parameters.within_block_parameter_update_count != 0
            or fit_receipt.within_block_parameter_update_count != 0
        ):
            raise RuntimeError(
                f"worker fit/output block custody drifted: {seed}/{dgp}/{spec.fold_index}"
            )
        if (
            parameters.decision_block_ordered_membership_sha256
            != fit_receipt.decision_block_ordered_membership_sha256
            or parameters.decision_block_ordered_membership_sha256
            != output.decision_block_ordered_membership_sha256
            or parameters.decision_block_set_membership_sha256
            != fit_receipt.decision_block_set_membership_sha256
            or parameters.decision_block_set_membership_sha256
            != output.decision_block_set_membership_sha256
            or parameters.decision_source_positions_sha256
            != fit_receipt.decision_source_positions_sha256
            or parameters.decision_source_positions_sha256
            != output.decision_source_positions_sha256
            or parameters.decision_block_ordered_membership_sha256
            == parameters.decision_block_set_membership_sha256
        ):
            raise RuntimeError(
                f"worker ordered/set/source custody drifted: {seed}/{dgp}/{spec.fold_index}"
            )
        count_rows, invalid_position_rows = _require_v7_prefix_receipt(
            fit_receipt,
            expected_requested=start,
            seed=seed,
            dgp=dgp,
            fold_index=spec.fold_index,
        )
        if fit_receipt.source_regime_fallback_count != 0 or output.regime_fallback_count != 0:
            raise RuntimeError(
                f"worker malformed-regime receipt drifted: {seed}/{dgp}/{spec.fold_index}"
            )
        if fit_runtime_payload is None:
            fit_runtime_payload = fit.resource_receipt.payload()
        elif fit_runtime_payload != fit.resource_receipt.payload():
            raise RuntimeError(f"worker fit runtime receipt drifted within task: {seed}/{dgp}")
        if inference_runtime_payload is None:
            inference_runtime_payload = output.inference_resource_receipt.payload()
        elif inference_runtime_payload != output.inference_resource_receipt.payload():
            raise RuntimeError(
                f"worker inference runtime receipt drifted within task: {seed}/{dgp}"
            )

        block_receipt = sealed(
            {
                "schema_version": "expected_pe.hofs_v8.prediction_block_receipt.v1",
                "task_ordinal": task_ordinal,
                "seed": seed,
                "dgp": dgp,
                "fold_index": spec.fold_index,
                "fit_prefix_end_exclusive": spec.fit_prefix_end_exclusive,
                "fit_start_date": parameters.fit_start_date,
                "fit_end_date": parameters.fit_end_date,
                "decision_block_start_inclusive": start,
                "decision_block_end_exclusive": end,
                "decision_block_start_date": parameters.decision_block_start_date,
                "decision_block_end_date": parameters.decision_block_end_date,
                "decision_block_first_entity_id": parameters.decision_block_first_entity_id,
                "decision_block_last_entity_id": parameters.decision_block_last_entity_id,
                "decision_row_count": parameters.decision_row_count,
                "decision_distinct_date_count": parameters.decision_distinct_date_count,
                "decision_ordered_identity_rows": [
                    list(row) for row in parameters.decision_ordered_identity_rows
                ],
                "decision_source_state_sha256": parameters.decision_source_state_sha256,
                "decision_source_positions": list(parameters.decision_source_positions),
                "decision_source_row_count": parameters.decision_source_row_count,
                "decision_block_ordered_membership_sha256": (
                    parameters.decision_block_ordered_membership_sha256
                ),
                "decision_block_set_membership_sha256": (
                    parameters.decision_block_set_membership_sha256
                ),
                "decision_source_positions_sha256": (
                    parameters.decision_source_positions_sha256
                ),
                "within_block_parameter_update_count": 0,
                "distinct_parameter_hashes_within_block": 1,
                "parameter_sha256": parameter_sha256,
                "fit_receipt_sha256": fit_receipt_sha256,
                "fit_resource_receipt_sha256": fit.resource_receipt.sha256(),
                "inference_resource_receipt_sha256": (
                    output.inference_resource_receipt_sha256
                ),
                "output_manifest": output_manifest,
                "output_manifest_sha256": output_manifest_sha256,
                "requested_row_count": fit_receipt.requested_row_count,
                "fit_row_count": fit_receipt.fit_row_count,
                "causal_prefix_nonwarm_row_count": (
                    fit_receipt.causal_prefix_nonwarm_row_count
                ),
                "warm_prefix_row_count": (
                    fit_receipt.requested_row_count
                    - fit_receipt.causal_prefix_nonwarm_row_count
                ),
                "prefix_entity_row_counts": count_rows,
                "prefix_entity_row_counts_sha256": (
                    fit_receipt.prefix_entity_row_counts_sha256
                ),
                "prefix_entity_causal_invalid_positions": invalid_position_rows,
                "prefix_entity_causal_invalid_positions_sha256": (
                    fit_receipt.prefix_entity_causal_invalid_positions_sha256
                ),
                "source_regime_fallback_count": fit_receipt.source_regime_fallback_count,
                "decision_regime_fallback_count": output.regime_fallback_count,
                "irls_iterations": fit_receipt.irls_iterations,
                "irls_converged": fit_receipt.irls_converged,
                "final_kkt_violation": fit_receipt.final_kkt_violation,
            }
        )
        block_receipts.append(block_receipt)

        identity_rows = _identity_rows(output.identities, IDENTITY_COLUMNS)
        if identity_rows != requested_rows:
            raise RuntimeError(
                f"worker output/requested identity order drifted: {seed}/{dgp}/{spec.fold_index}"
            )
        numeric = output.values.to_numpy(dtype=np.float64)
        if (
            not np.isfinite(numeric).all()
            or not (numeric[:, :3] > 0.0).all()
            or not (numeric[:, 1] <= numeric[:, 0]).all()
            or not (numeric[:, 0] <= numeric[:, 2]).all()
        ):
            raise RuntimeError(
                f"worker output numeric gate failed: {seed}/{dgp}/{spec.fold_index}"
            )
        for local_position, ((entity, date), values) in enumerate(
            zip(identity_rows, numeric.tolist(), strict=True)
        ):
            prediction_rows.append(
                {
                    "task_ordinal": task_ordinal,
                    "task_seed": seed,
                    "task_dgp": dgp,
                    "fold_index": spec.fold_index,
                    "source_row_position": start + local_position,
                    "entity_id": entity,
                    "decision_date": date,
                    "hofs_v7_expected_pe": float(values[0]),
                    "hofs_v7_pe_p10": float(values[1]),
                    "hofs_v7_pe_p90": float(values[2]),
                    "hofs_v7_log_scale": float(values[3]),
                    "hofs_v7_tail_guard_weight": float(values[4]),
                    "parameter_sha256": parameter_sha256,
                    "decision_block_ordered_membership_sha256": (
                        output.decision_block_ordered_membership_sha256
                    ),
                    "decision_block_set_membership_sha256": (
                        output.decision_block_set_membership_sha256
                    ),
                    "decision_source_positions_sha256": (
                        output.decision_source_positions_sha256
                    ),
                    "output_manifest_sha256": output_manifest_sha256,
                    "within_block_parameter_update_count": 0,
                }
            )

    if (
        len(block_receipts) != FOLDS_PER_TASK
        or len(prediction_rows) != SCORE_END - SCORE_START
        or fit_runtime_payload is None
        or inference_runtime_payload is None
    ):
        raise RuntimeError(f"worker task aggregate geometry drifted: {seed}/{dgp}")
    if [row["source_row_position"] for row in prediction_rows] != list(
        range(SCORE_START, SCORE_END)
    ):
        raise RuntimeError(f"worker decision coverage drifted: {seed}/{dgp}")
    task_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_task_receipt.v1",
            "task_ordinal": task_ordinal,
            "seed": seed,
            "dgp": dgp,
            "canonical_relative_path": canonical_relative,
            "canonical_raw_sha256": expected_raw_sha256,
            "fit_count": len(block_receipts),
            "prediction_identity_count": len(prediction_rows),
            "first_prediction_identity": [
                prediction_rows[0]["entity_id"],
                prediction_rows[0]["decision_date"],
            ],
            "last_prediction_identity": [
                prediction_rows[-1]["entity_id"],
                prediction_rows[-1]["decision_date"],
            ],
            "block_receipts_sha256": sha256_bytes(canonical_json_bytes(block_receipts)),
            "prediction_rows_sha256": sha256_bytes(canonical_json_bytes(prediction_rows)),
            "within_block_parameter_update_count": 0,
            "causal_invalid_positions": list(ALLOWED_CAUSAL_INVALID_POSITIONS),
            "first_fold_warm_prefix_row_count": FIRST_FOLD_WARM_ROWS,
            "unexpected_malformed_regime_count": 0,
            "decision_causal_invalid_count": 0,
        }
    )
    return {
        "task_ordinal": task_ordinal,
        "seed": seed,
        "dgp": dgp,
        "worker_pid": os.getpid(),
        "worker_preimport_guard": worker_guard,
        "fit_runtime_payload": fit_runtime_payload,
        "inference_runtime_payload": inference_runtime_payload,
        "task_receipt": task_receipt,
        "block_receipts": block_receipts,
        "prediction_rows": prediction_rows,
    }


def serialize_jsonl(rows: list[dict[str, Any]]) -> bytes:
    return b"".join(canonical_json_bytes(row) + b"\n" for row in rows)


def serialize_predictions(rows: list[dict[str, Any]]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=list(PREDICTION_COLUMNS),
        extrasaction="raise",
        lineterminator="\n",
    )
    writer.writeheader()
    for row in rows:
        if tuple(row) != PREDICTION_COLUMNS:
            raise RuntimeError("prediction record field order drifted")
        writer.writerow(row)
    return buffer.getvalue().encode("ascii")


def write_bytes(path: Path, content: bytes) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite output artifact: {path}")
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def fsync_directory(path: Path) -> None:
    if os.name != "nt" or not path.is_dir():
        raise RuntimeError(f"directory flush requires one existing Windows directory: {path}")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        ctypes.c_wchar_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    flush_file_buffers = kernel32.FlushFileBuffers
    flush_file_buffers.argtypes = (wintypes.HANDLE,)
    flush_file_buffers.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(path.resolve()),
        0x40000000,  # GENERIC_WRITE
        0x00000007,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise RuntimeError(f"CreateFileW directory flush open failed: {ctypes.get_last_error()}")
    flushed = bool(flush_file_buffers(handle))
    flush_error = ctypes.get_last_error() if not flushed else 0
    closed = bool(close_handle(handle))
    close_error = ctypes.get_last_error() if not closed else 0
    if not flushed:
        raise RuntimeError(f"FlushFileBuffers directory flush failed: {flush_error}")
    if not closed:
        raise RuntimeError(f"CloseHandle directory flush failed: {close_error}")


def _typed_prediction_row(row: dict[str, str]) -> dict[str, Any]:
    integer_names = {
        "task_ordinal",
        "task_seed",
        "fold_index",
        "source_row_position",
        "within_block_parameter_update_count",
    }
    float_names = set(PREDICTION_COLUMNS[7:12])
    output: dict[str, Any] = {}
    for name in PREDICTION_COLUMNS:
        value = row[name]
        if name in integer_names:
            output[name] = int(value)
        elif name in float_names:
            output[name] = float(value)
        else:
            output[name] = value
    return output


def verify_prediction_csv(content: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    reader = csv.DictReader(io.StringIO(content.decode("ascii"), newline=""))
    if tuple(reader.fieldnames or ()) != PREDICTION_COLUMNS:
        raise RuntimeError("published prediction CSV schema drifted")
    forbidden = sorted(
        name
        for name in PREDICTION_COLUMNS
        if any(token in name.casefold() for token in FORBIDDEN_OUTPUT_COLUMN_TOKENS)
    )
    if forbidden:
        raise RuntimeError(f"forbidden prediction output columns survived: {forbidden}")
    rows = [_typed_prediction_row(dict(row)) for row in reader]
    if len(rows) != DECISION_COUNT:
        raise RuntimeError("published prediction CSV row count drifted")
    identities: set[tuple[int, str, str, str]] = set()
    minimum = [math.inf] * 5
    maximum = [-math.inf] * 5
    numeric_names = PREDICTION_COLUMNS[7:12]
    for position, row in enumerate(rows):
        expected_task = position // (SCORE_END - SCORE_START)
        expected_source = SCORE_START + position % (SCORE_END - SCORE_START)
        expected_fold = min((expected_source - SCORE_START) // BLOCK_ROWS, FOLDS_PER_TASK - 1)
        identity = (
            row["task_seed"],
            row["task_dgp"],
            row["entity_id"],
            row["decision_date"],
        )
        values = [row[name] for name in numeric_names]
        if (
            identity in identities
            or row["task_ordinal"] != expected_task
            or row["source_row_position"] != expected_source
            or row["fold_index"] != expected_fold
            or not all(math.isfinite(value) for value in values)
            or not all(value > 0.0 for value in values[:3])
            or not values[1] <= values[0] <= values[2]
            or row["within_block_parameter_update_count"] != 0
            or any(
                not is_sha256(row[name])
                for name in PREDICTION_COLUMNS[12:17]
            )
        ):
            raise RuntimeError(f"published prediction row custody failed: {position}")
        identities.add(identity)
        minimum = [min(left, right) for left, right in zip(minimum, values, strict=True)]
        maximum = [max(left, right) for left, right in zip(maximum, values, strict=True)]
    return (
        {
            "row_count": len(rows),
            "unique_identity_count": len(identities),
            "forbidden_column_hits": forbidden,
            "numeric_minimum": dict(zip(numeric_names, minimum, strict=True)),
            "numeric_maximum": dict(zip(numeric_names, maximum, strict=True)),
        },
        rows,
    )


def _parse_jsonl(content: bytes, *, label: str, expected_count: int) -> list[dict[str, Any]]:
    lines = content.decode("ascii").splitlines()
    if len(lines) != expected_count:
        raise RuntimeError(f"{label} JSONL count drifted")
    rows: list[dict[str, Any]] = []
    for position, line in enumerate(lines):
        payload = parse_json_exact(line.encode("ascii"), label=f"{label}:{position}")
        logical_sha256(payload)
        rows.append(payload)
    return rows


def verify_output_bundle(
    root: Path,
    *,
    expected_checksums_raw_sha256: str,
) -> dict[str, Any]:
    contents, hashes = require_exact_bundle(
        root,
        universe=FINAL_FILE_UNIVERSE,
        expected_checksums_raw_sha256=expected_checksums_raw_sha256,
    )
    manifest = parse_json_exact(contents["MANIFEST.json"], label="OUTPUT:MANIFEST")
    seal_receipt = parse_json_exact(contents["SEAL_RECEIPT.json"], label="OUTPUT:SEAL")
    if (
        manifest.get("schema_version")
        != "expected_pe.hofs_v8.prediction_only_root_manifest.v1"
        or manifest.get("status") != "PASS_PREDICTION_ONLY_OUTPUT_READY_FOR_ATOMIC_PUBLISH"
        or manifest.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE)
        or manifest.get("fit_count") != FIT_COUNT
        or manifest.get("prediction_identity_count") != DECISION_COUNT
        or manifest.get("prediction_only_authority") is not True
        or manifest.get("score_registry_promotion_authority") is not False
    ):
        raise RuntimeError("output manifest semantics drifted")
    if (
        seal_receipt.get("schema_version")
        != "expected_pe.hofs_v8.prediction_output_seal.v1"
        or seal_receipt.get("status") != "SEALED_SCORE_BLIND_PREDICTION_ONLY_OUTPUT"
        or seal_receipt.get("expected_final_file_universe") != list(FINAL_FILE_UNIVERSE)
        or seal_receipt.get("fit_count") != FIT_COUNT
        or seal_receipt.get("prediction_identity_count") != DECISION_COUNT
        or seal_receipt.get("authority", {}).get("prediction_only_output") is not True
        or seal_receipt.get("authority", {}).get("score") is not False
        or seal_receipt.get("authority", {}).get("evaluator") is not False
        or seal_receipt.get("authority", {}).get("registry_or_champion") is not False
        or seal_receipt.get("authority", {}).get("promotion") is not False
    ):
        raise RuntimeError("output seal semantics drifted")
    expected_core = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "MANIFEST.json", "SEAL_RECEIPT.json"}
    )
    if tuple(sorted(manifest.get("core_files", {}))) != expected_core:
        raise RuntimeError("output manifest core universe drifted")
    for name in expected_core:
        receipt = manifest["core_files"][name]
        if receipt.get("raw_sha256") != hashes[name] or receipt.get("size_bytes") != len(
            contents[name]
        ):
            raise RuntimeError(f"output manifest raw/size binding drifted: {name}")
        if name.endswith(".json"):
            logical = logical_sha256(parse_json_exact(contents[name], label=f"OUTPUT:{name}"))
            if receipt.get("logical_sha256") != logical:
                raise RuntimeError(f"output manifest logical binding drifted: {name}")
    expected_sealed = tuple(
        name
        for name in FINAL_FILE_UNIVERSE
        if name not in {"CHECKSUMS.sha256", "SEAL_RECEIPT.json"}
    )
    if tuple(sorted(seal_receipt.get("artifact_hashes", {}))) != expected_sealed:
        raise RuntimeError("output seal artifact universe drifted")
    for name in expected_sealed:
        if seal_receipt["artifact_hashes"][name] != {
            "raw_sha256": hashes[name],
            "size_bytes": len(contents[name]),
        }:
            raise RuntimeError(f"output seal raw/size binding drifted: {name}")

    block_rows = _parse_jsonl(
        contents["BLOCK_RECEIPTS.jsonl"],
        label="BLOCK",
        expected_count=FIT_COUNT,
    )
    task_rows = _parse_jsonl(
        contents["TASK_RECEIPTS.jsonl"],
        label="TASK",
        expected_count=TASK_COUNT,
    )
    prediction_receipt, prediction_rows = verify_prediction_csv(contents["PREDICTIONS.csv"])
    parameter_hashes: set[str] = set()
    for position, block in enumerate(block_rows):
        task_ordinal = position // FOLDS_PER_TASK
        fold_index = position % FOLDS_PER_TASK
        start = SCORE_START + fold_index * BLOCK_ROWS
        end = min(start + BLOCK_ROWS, SCORE_END)
        selected = prediction_rows[
            task_ordinal * (SCORE_END - SCORE_START) + start - SCORE_START :
            task_ordinal * (SCORE_END - SCORE_START) + end - SCORE_START
        ]
        if (
            block.get("task_ordinal") != task_ordinal
            or block.get("fold_index") != fold_index
            or block.get("decision_block_start_inclusive") != start
            or block.get("decision_block_end_exclusive") != end
            or block.get("decision_row_count") != end - start
            or block.get("within_block_parameter_update_count") != 0
            or block.get("distinct_parameter_hashes_within_block") != 1
            or block.get("decision_source_positions") != list(range(start, end))
            or block.get("causal_prefix_nonwarm_row_count") != 3
            or block.get("warm_prefix_row_count") != start - 3
            or block.get("prefix_entity_causal_invalid_positions")
            != [["DGP_ISSUER", list(ALLOWED_CAUSAL_INVALID_POSITIONS)]]
            or block.get("decision_ordered_identity_rows")
            != [[row["entity_id"], row["decision_date"]] for row in selected]
            or any(row["parameter_sha256"] != block.get("parameter_sha256") for row in selected)
            or any(
                row["decision_block_ordered_membership_sha256"]
                != block.get("decision_block_ordered_membership_sha256")
                for row in selected
            )
            or any(
                row["decision_block_set_membership_sha256"]
                != block.get("decision_block_set_membership_sha256")
                for row in selected
            )
            or any(
                row["decision_source_positions_sha256"]
                != block.get("decision_source_positions_sha256")
                for row in selected
            )
            or any(
                row["output_manifest_sha256"] != block.get("output_manifest_sha256")
                for row in selected
            )
            or sha256_bytes(canonical_json_bytes(block.get("output_manifest")))
            != block.get("output_manifest_sha256")
        ):
            raise RuntimeError(f"published block cross-custody drifted: {position}")
        parameter_hashes.add(block["parameter_sha256"])
    if len(parameter_hashes) != FIT_COUNT:
        raise RuntimeError("published parameter-hash block uniqueness drifted")
    for task_ordinal, task in enumerate(task_rows):
        first_block = task_ordinal * FOLDS_PER_TASK
        task_blocks = block_rows[first_block : first_block + FOLDS_PER_TASK]
        first_prediction = task_ordinal * (SCORE_END - SCORE_START)
        task_predictions = prediction_rows[
            first_prediction : first_prediction + SCORE_END - SCORE_START
        ]
        if (
            task.get("task_ordinal") != task_ordinal
            or task.get("fit_count") != FOLDS_PER_TASK
            or task.get("prediction_identity_count") != SCORE_END - SCORE_START
            or task.get("block_receipts_sha256")
            != sha256_bytes(canonical_json_bytes(task_blocks))
            or task.get("prediction_rows_sha256")
            != sha256_bytes(canonical_json_bytes(task_predictions))
            or task.get("causal_invalid_positions")
            != list(ALLOWED_CAUSAL_INVALID_POSITIONS)
            or task.get("first_fold_warm_prefix_row_count") != FIRST_FOLD_WARM_ROWS
            or task.get("decision_causal_invalid_count") != 0
        ):
            raise RuntimeError(f"published task cross-custody drifted: {task_ordinal}")
    execution = parse_json_exact(
        contents["EXECUTION_RECEIPT.json"],
        label="OUTPUT:EXECUTION",
    )
    if (
        execution.get("fit_count") != FIT_COUNT
        or execution.get("prediction_identity_count") != DECISION_COUNT
        or execution.get("within_block_parameter_update_count") != 0
        or execution.get("causal_prefix_nonwarm_count") != FIT_COUNT * 3
        or execution.get("warm_prefix_row_count") != 3_538_650
        or execution.get("prediction_records_sha256")
        != sha256_bytes(canonical_json_bytes(prediction_rows))
        or execution.get("block_receipts_semantic_sha256")
        != sha256_bytes(canonical_json_bytes(block_rows))
        or execution.get("task_receipts_semantic_sha256")
        != sha256_bytes(canonical_json_bytes(task_rows))
    ):
        raise RuntimeError("output execution cross-seal drifted")
    return {
        "status": "PASS_EXACT_SEALED_V8_PREDICTION_ONLY_OUTPUT_BUNDLE",
        "file_count": len(contents),
        "checksums_raw_sha256": expected_checksums_raw_sha256,
        "manifest_raw_sha256": hashes["MANIFEST.json"],
        "seal_raw_sha256": hashes["SEAL_RECEIPT.json"],
        "execution_raw_sha256": hashes["EXECUTION_RECEIPT.json"],
        "predictions_raw_sha256": hashes["PREDICTIONS.csv"],
        "block_receipts_raw_sha256": hashes["BLOCK_RECEIPTS.jsonl"],
        "task_receipts_raw_sha256": hashes["TASK_RECEIPTS.jsonl"],
        "prediction_csv": prediction_receipt,
    }


def report_bytes() -> bytes:
    return (
        "# H-OFS V8 Score-Blind Prediction-Only Execution\n\n"
        "Status: sealed and atomically published prediction-only output.\n\n"
        "The exact frozen V8 design and externally pinned independent GO audit were verified "
        "before launch. Exactly 50 public R4 tasks, 3,100 chronological block fits, and 64,800 "
        "canonically ordered prediction identities were executed with Windows spawn, CPU0-31, "
        "outer32, inner1, Python 3.10.19, and GPU disabled.\n\n"
        "Every fit permits causal invalid positions only at [0,1,2], provides at least 501 warm "
        "rows, and receipts exact per-entity positions. Each decision block binds canonical "
        "first/last identities, ordered membership, set membership, ordered source positions, "
        "one unchanged parameter hash, and zero within-block updates.\n\n"
        "No registry, evaluator, truth, vault, latent, heldout, score, or prior frozen prediction "
        "payload was opened. No scoring, champion selection, promotion, or registry mutation was "
        "performed or authorized.\n"
    ).encode("ascii")


def _validate_public_causal_evidence(closure: dict[str, Any]) -> None:
    receipts = closure.get("task_causal_prefix_receipts")
    if type(receipts) is not list or len(receipts) != TASK_COUNT:
        raise RuntimeError("V7 public causal-prefix receipt count drifted")
    expected_tasks = [(seed, dgp) for seed in SEEDS for dgp in DGPS]
    for position, (receipt, expected_task) in enumerate(zip(receipts, expected_tasks, strict=True)):
        per_entity = receipt.get("per_entity") if type(receipt) is dict else None
        if (
            type(receipt) is not dict
            or (receipt.get("seed"), receipt.get("dgp")) != expected_task
            or type(per_entity) is not list
            or len(per_entity) != 1
            or type(per_entity[0]) is not dict
            or per_entity[0].get("entity_id") != "DGP_ISSUER"
            or per_entity[0].get("first_prefix_requested_row_count") != SCORE_START
            or per_entity[0].get("causal_invalid_positions")
            != list(ALLOWED_CAUSAL_INVALID_POSITIONS)
            or not is_sha256(
                per_entity[0].get("causal_invalid_identity_membership_sha256")
            )
            or per_entity[0].get("observed_pe_nonfinite_positions") != [0, 1]
            or per_entity[0].get("causal_offset_nonfinite_positions")
            != list(ALLOWED_CAUSAL_INVALID_POSITIONS)
            or per_entity[0].get("first_prefix_nonwarm_row_count") != 3
            or per_entity[0].get("first_prefix_warm_row_count") != FIRST_FOLD_WARM_ROWS
            or per_entity[0].get("later_unexpected_invalid_row_count") != 0
            or per_entity[0].get("decision_invalid_row_count") != 0
            or per_entity[0].get("estimator_sufficiency_minimum_warm_rows")
            != FIRST_FOLD_WARM_ROWS
            or per_entity[0].get("estimator_sufficiency_passed") is not True
            or receipt.get("per_entity_sha256")
            != sha256_bytes(canonical_json_bytes(per_entity))
            or receipt.get("validity_predicate")
            != "finite_positive_observed_pe_and_finite_causal_offset"
        ):
            raise RuntimeError(f"V7 public causal-prefix receipt drifted: {position}")
    expected_sha = sha256_bytes(canonical_json_bytes(receipts))
    if closure.get("task_causal_prefix_receipts_sha256") != expected_sha:
        raise RuntimeError("V7 public causal-prefix semantic seal drifted")


def _validate_live_v8_surface(
    *,
    design: dict[str, Any],
    design_contract_sha256: str,
) -> tuple[dict[str, Any], Any]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (  # noqa: PLC0415
        build_r4_input_closure_v7,
        capture_runtime_receipt_v7,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v8 import (  # noqa: PLC0415
        contract_sha256,
        require_failure_staging,
    )

    if contract_sha256() != design_contract_sha256:
        raise RuntimeError("live V8 contract differs from detached design-contract pin")
    require_failure_staging(PROJECT_ROOT)
    closure = build_r4_input_closure_v7(PROJECT_ROOT)
    frozen = design["input_closure"]
    compared_keys = (
        "input_binding",
        "public_files",
        "public_files_sha256",
        "task_regime_receipts",
        "task_regime_receipts_sha256",
        "task_causal_prefix_receipts",
        "task_causal_prefix_receipts_sha256",
        "geometry",
        "access",
    )
    if any(closure.get(key) != frozen.get(key) for key in compared_keys):
        raise RuntimeError("live public R4 closure differs from frozen V8 input closure")
    geometry = closure.get("geometry", {})
    if (
        geometry.get("task_count") != TASK_COUNT
        or geometry.get("folds_per_task") != FOLDS_PER_TASK
        or geometry.get("fit_count") != FIT_COUNT
        or geometry.get("decision_row_count") != DECISION_COUNT
        or geometry.get("within_block_parameter_update_count") != 0
    ):
        raise RuntimeError("live V8 inherited R4 geometry drifted")
    _validate_public_causal_evidence(closure)
    runtime = capture_runtime_receipt_v7(purpose="PREFLIGHT")
    return closure, runtime


def _output_roots(run_id: str) -> tuple[Path, Path]:
    if type(run_id) is not str or RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise RuntimeError("run ID must be exact YYYYMMDDTHHMMSS digits")
    if OUTPUTS_ROOT.is_symlink() or is_reparse(OUTPUTS_ROOT) or not OUTPUTS_ROOT.is_dir():
        raise RuntimeError("outputs root custody drifted")
    final_root = OUTPUTS_ROOT / f"{OUTPUT_ROOT_PREFIX}{run_id}"
    staging_root = OUTPUTS_ROOT / f".{final_root.name}.staging"
    if (
        final_root.resolve().parent != OUTPUTS_ROOT.resolve()
        or staging_root.resolve().parent != OUTPUTS_ROOT.resolve()
        or final_root.name.casefold() == staging_root.name.casefold()
    ):
        raise RuntimeError("prediction output root escaped its exact parent")
    return final_root, staging_root


def run_worker_bootstrap_check(
    *,
    design: dict[str, Any],
    launcher_bytes: bytes,
) -> dict[str, Any]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v8.bootstrap import (  # noqa: PLC0415
        validate_execute_task_import_ast,
        validate_fanout_receipts,
        worker_bootstrap_ping,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v8.contracts import (  # noqa: PLC0415
        BOOTSTRAP_SAMPLE_TASK,
        BOOTSTRAP_WORKER_COUNT,
        bootstrap_contract_sha256,
        sealed_payload,
    )

    if BOOTSTRAP_WORKER_COUNT != PINNED_OUTER_WORKERS:
        raise RuntimeError("V8 bootstrap worker/resource count cross-binding drifted")
    ast_receipt = validate_execute_task_import_ast(launcher_bytes.decode("utf-8"))
    serialized_task = canonical_json_bytes(BOOTSTRAP_SAMPLE_TASK)
    context = multiprocessing.get_context("spawn")
    initializer_barrier = context.Barrier(BOOTSTRAP_WORKER_COUNT)
    receipt_queue = context.Queue()
    pings: list[dict[str, Any]] = []
    try:
        with ProcessPoolExecutor(
            max_workers=BOOTSTRAP_WORKER_COUNT,
            mp_context=context,
            initializer=v8_worker_bootstrap_initializer,
            initargs=(
                serialized_task,
                str(PROJECT_ROOT),
                dict(design["source_map"]),
                initializer_barrier,
                receipt_queue,
            ),
        ) as executor:
            futures = [
                executor.submit(worker_bootstrap_ping, position)
                for position in range(BOOTSTRAP_WORKER_COUNT)
            ]
            # Drain initializer receipts while workers are alive.  Each receipt
            # is larger than the Windows multiprocessing pipe buffer in
            # aggregate; deferring reads until executor shutdown can otherwise
            # block worker queue-feeder shutdown before the parent starts
            # reading.
            worker_receipts = [
                receipt_queue.get(timeout=75.0)
                for _ in range(BOOTSTRAP_WORKER_COUNT)
            ]
            pings = [future.result() for future in futures]
    finally:
        receipt_queue.close()
        receipt_queue.join_thread()
    if (
        sorted(ping.get("position") for ping in pings)
        != list(range(BOOTSTRAP_WORKER_COUNT))
        or any(
            type(ping.get("worker_pid")) is not int
            or type(ping.get("attestation_manifest_sha256")) is not str
            for ping in pings
        )
    ):
        raise RuntimeError("V8 bootstrap ping universe drifted")
    fanout = validate_fanout_receipts(worker_receipts)
    attestation_seals_by_pid = {
        receipt["worker_pid"]: receipt["manifest_sha256"]
        for receipt in worker_receipts
    }
    if any(
        ping["worker_pid"] not in attestation_seals_by_pid
        or ping["attestation_manifest_sha256"]
        != attestation_seals_by_pid[ping["worker_pid"]]
        for ping in pings
    ):
        raise RuntimeError("V8 bootstrap ping did not bind an attested worker")
    payload = {
        "schema_version": "expected_pe.hofs_v8.formal_worker_bootstrap.v1",
        "status": "PASS_EXACT_32_SPAWN_IMPORT_SYMBOL_ORIGIN_HEADER_BOOTSTRAP",
        "process_start_method": "spawn",
        "bootstrap_contract_sha256": bootstrap_contract_sha256(),
        "execute_task_import_ast": ast_receipt,
        "fanout": fanout,
        "ping_count": len(pings),
        "metadata_only_task_sha256": sha256_bytes(serialized_task),
        "real_fit_count": 0,
        "real_prediction_count": 0,
        "protected_or_score_access_count": 0,
        "registry_or_champion_mutation_count": 0,
        "promotion_count": 0,
    }
    return sealed_payload(payload)


def check_only(
    *,
    design_checksums_raw_sha256: str,
    design_contract_sha256: str,
) -> dict[str, Any]:
    guard = preimport_guard()
    launcher_bytes = require_regular_file(LAUNCHER_PATH, allowed_root=PROJECT_ROOT)
    design = verify_design_and_public_surfaces(
        design_checksums_raw_sha256=design_checksums_raw_sha256,
        design_contract_sha256=design_contract_sha256,
        launcher_bytes=launcher_bytes,
    )
    closure, runtime = _validate_live_v8_surface(
        design=design,
        design_contract_sha256=design_contract_sha256,
    )
    bootstrap = run_worker_bootstrap_check(
        design=design,
        launcher_bytes=launcher_bytes,
    )
    if require_regular_file(LAUNCHER_PATH, allowed_root=PROJECT_ROOT) != launcher_bytes:
        raise RuntimeError("prediction launcher changed during check-only validation")
    return {
        "status": "PASS_FORMAL_V8_PREDICTION_ONLY_LAUNCH_CHECK_WITH_32_WORKER_BOOTSTRAP",
        "preimport_guard": guard,
        "available_memory_gib": available_memory_gib(),
        "design_checksums_raw_sha256": design_checksums_raw_sha256,
        "design_contract_sha256": design_contract_sha256,
        "launcher_raw_sha256": sha256_bytes(launcher_bytes),
        "frozen_snapshot_sha256": design["snapshot_sha256"],
        "public_files_sha256": closure["public_files_sha256"],
        "task_causal_prefix_receipts_sha256": (
            closure["task_causal_prefix_receipts_sha256"]
        ),
        "fit_count": FIT_COUNT,
        "prediction_identity_count": DECISION_COUNT,
        "resource_receipt_sha256": runtime.sha256(),
        "worker_bootstrap_receipt": bootstrap,
        "real_fit_count": 0,
        "real_prediction_count": 0,
    }


def run_authorized(
    *,
    design_checksums_raw_sha256: str,
    design_contract_sha256: str,
    audit_checksums_raw_sha256: str,
    audit_raw_sha256: str,
    audit_semantic_sha256: str,
    run_id: str,
) -> dict[str, Any]:
    parent_guard = preimport_guard()
    available_gib = available_memory_gib()
    if available_gib < 12.0:
        raise RuntimeError(f"launch requires at least 12 GiB available RAM, found {available_gib}")
    launcher_bytes = require_regular_file(LAUNCHER_PATH, allowed_root=PROJECT_ROOT)
    design_before = verify_design_and_public_surfaces(
        design_checksums_raw_sha256=design_checksums_raw_sha256,
        design_contract_sha256=design_contract_sha256,
        launcher_bytes=launcher_bytes,
    )
    audit = verify_independent_go_audit(
        audit_checksums_raw_sha256=audit_checksums_raw_sha256,
        audit_raw_sha256=audit_raw_sha256,
        audit_semantic_sha256=audit_semantic_sha256,
        design_checksums_raw_sha256=design_checksums_raw_sha256,
        design_contract_sha256=design_contract_sha256,
    )
    public_closure, launch_runtime = _validate_live_v8_surface(
        design=design_before,
        design_contract_sha256=design_contract_sha256,
    )
    worker_bootstrap = run_worker_bootstrap_check(
        design=design_before,
        launcher_bytes=launcher_bytes,
    )
    final_root, staging_root = _output_roots(run_id)
    if final_root.exists() or staging_root.exists():
        raise FileExistsError("unique final prediction root or staging root already exists")
    staging_root.mkdir(exist_ok=False)
    if staging_root.is_symlink() or is_reparse(staging_root):
        raise RuntimeError("created prediction staging root is a reparse point")

    task_public_hashes = {
        row[0]: row[1]
        for row in public_closure["public_files"]
        if row[0].endswith("/canonical150.csv")
    }
    tasks: list[tuple[int, int, str, str, str]] = []
    ordinal = 0
    for seed in SEEDS:
        for dgp in DGPS:
            relative = f"replays/pass_1/seed_{seed}/dgp_{dgp}/canonical150.csv"
            digest = task_public_hashes.get(relative)
            if not is_sha256(digest):
                raise RuntimeError(f"missing task public canonical pin: {seed}/{dgp}")
            tasks.append((ordinal, seed, dgp, relative, digest))
            ordinal += 1
    if len(tasks) != TASK_COUNT:
        raise RuntimeError("launch task universe drifted")

    started_utc = datetime.now(timezone.utc).isoformat()
    started_monotonic = time.monotonic()
    results: dict[int, dict[str, Any]] = {}
    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=PINNED_OUTER_WORKERS,
        mp_context=context,
        initializer=worker_initializer,
    ) as executor:
        future_to_task = {
            executor.submit(execute_task, *task): task[:3] for task in tasks
        }
        for future in as_completed(future_to_task):
            task_ordinal, seed, dgp = future_to_task[future]
            result = future.result()
            if result.get("task_ordinal") != task_ordinal:
                raise RuntimeError("worker task ordinal drifted")
            results[task_ordinal] = result
            print(
                json.dumps(
                    {
                        "event": "TASK_COMPLETE",
                        "completed": len(results),
                        "total": TASK_COUNT,
                        "seed": seed,
                        "dgp": dgp,
                        "worker_pid": result["worker_pid"],
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
    if tuple(sorted(results)) != tuple(range(TASK_COUNT)):
        raise RuntimeError("completed task universe drifted")
    ordered_results = [results[position] for position in range(TASK_COUNT)]
    worker_pids = sorted({int(result["worker_pid"]) for result in ordered_results})
    if len(worker_pids) != PINNED_OUTER_WORKERS:
        raise RuntimeError(f"exact outer worker process count drifted: {len(worker_pids)}")
    if any(result["worker_preimport_guard"] != parent_guard for result in ordered_results):
        raise RuntimeError("worker pre-import runtime guard drifted")
    fit_runtime_payload = ordered_results[0]["fit_runtime_payload"]
    inference_runtime_payload = ordered_results[0]["inference_runtime_payload"]
    if any(result["fit_runtime_payload"] != fit_runtime_payload for result in ordered_results):
        raise RuntimeError("fit runtime receipts drifted across workers")
    if any(
        result["inference_runtime_payload"] != inference_runtime_payload
        for result in ordered_results
    ):
        raise RuntimeError("inference runtime receipts drifted across workers")

    task_receipts = [result["task_receipt"] for result in ordered_results]
    block_receipts = [
        receipt for result in ordered_results for receipt in result["block_receipts"]
    ]
    predictions = [
        row for result in ordered_results for row in result["prediction_rows"]
    ]
    if (
        len(task_receipts) != TASK_COUNT
        or len(block_receipts) != FIT_COUNT
        or len(predictions) != DECISION_COUNT
    ):
        raise RuntimeError("launch aggregate task/fit/prediction geometry drifted")
    for task_ordinal, result in enumerate(ordered_results):
        rows = result["prediction_rows"]
        if (
            len(rows) != SCORE_END - SCORE_START
            or {row["task_ordinal"] for row in rows} != {task_ordinal}
            or [row["source_row_position"] for row in rows]
            != list(range(SCORE_START, SCORE_END))
        ):
            raise RuntimeError(f"launch ordered decision coverage drifted: {task_ordinal}")
    for block_position, receipt in enumerate(block_receipts):
        expected_task = block_position // FOLDS_PER_TASK
        expected_fold = block_position % FOLDS_PER_TASK
        if (
            receipt.get("task_ordinal") != expected_task
            or receipt.get("fold_index") != expected_fold
            or receipt.get("decision_row_count")
            != (BLOCK_ROWS if expected_fold < FOLDS_PER_TASK - 1 else 15)
            or receipt.get("within_block_parameter_update_count") != 0
            or receipt.get("distinct_parameter_hashes_within_block") != 1
        ):
            raise RuntimeError(f"launch block receipt ordering drifted: {block_position}")
    parameter_hashes = {receipt["parameter_sha256"] for receipt in block_receipts}
    if len(parameter_hashes) != FIT_COUNT:
        raise RuntimeError("one unique frozen parameter receipt per exact block drifted")
    requested_total = sum(receipt["requested_row_count"] for receipt in block_receipts)
    invalid_total = sum(
        receipt["causal_prefix_nonwarm_row_count"] for receipt in block_receipts
    )
    warm_total = sum(receipt["warm_prefix_row_count"] for receipt in block_receipts)
    if (requested_total, invalid_total, warm_total) != (3_547_950, 9_300, 3_538_650):
        raise RuntimeError("aggregate requested/invalid/warm receipt drifted")

    prediction_bytes = serialize_predictions(predictions)
    prediction_validation, reparsed_predictions = verify_prediction_csv(prediction_bytes)
    if reparsed_predictions != predictions:
        raise RuntimeError("prediction CSV typed round-trip drifted")
    block_bytes = serialize_jsonl(block_receipts)
    task_bytes = serialize_jsonl(task_receipts)
    design_after = verify_design_and_public_surfaces(
        design_checksums_raw_sha256=design_checksums_raw_sha256,
        design_contract_sha256=design_contract_sha256,
        launcher_bytes=launcher_bytes,
    )
    if design_after["snapshot"] != design_before["snapshot"]:
        raise RuntimeError("source/public/V8 immutable surface changed during launch")
    if require_regular_file(LAUNCHER_PATH, allowed_root=PROJECT_ROOT) != launcher_bytes:
        raise RuntimeError("prediction launcher changed during execution")
    ended_utc = datetime.now(timezone.utc).isoformat()
    elapsed_seconds = time.monotonic() - started_monotonic

    input_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_input_receipt.v1",
            "status": "PASS_EXACT_PUBLIC_R4_INPUT_AND_CAUSAL_PREFIX_CLOSURE",
            "input_binding": public_closure["input_binding"],
            "public_file_count": len(public_closure["public_files"]),
            "public_files_sha256": public_closure["public_files_sha256"],
            "task_regime_receipts_sha256": public_closure["task_regime_receipts_sha256"],
            "task_causal_prefix_receipts_sha256": (
                public_closure["task_causal_prefix_receipts_sha256"]
            ),
            "geometry": public_closure["geometry"],
            "allowed_causal_invalid_positions": list(ALLOWED_CAUSAL_INVALID_POSITIONS),
            "first_fold_warm_prefix_row_count": FIRST_FOLD_WARM_ROWS,
            "decision_causal_invalid_count": 0,
            "unexpected_malformed_regime_count": 0,
        }
    )
    immutability_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_immutability_receipt.v1",
            "status": "PASS_SOURCE_PUBLIC_V8_BYTES_UNCHANGED_PRE_TO_POST_EXECUTION",
            "before_snapshot_sha256": design_before["snapshot_sha256"],
            "after_snapshot_sha256": design_after["snapshot_sha256"],
            "group_sha256": design_after["group_sha256"],
            "group_counts": design_after["group_counts"],
            "v8_design_checksums_raw_sha256": design_checksums_raw_sha256,
            "v8_audit_checksums_raw_sha256": audit_checksums_raw_sha256,
            "v8_audit_raw_sha256": audit_raw_sha256,
            "v8_audit_semantic_sha256": audit_semantic_sha256,
            "launcher_raw_sha256": sha256_bytes(launcher_bytes),
            "source_or_public_mutation_count": 0,
        }
    )
    runtime_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_runtime_receipt.v1",
            "status": "PASS_EXACT_PINNED_RUNTIME_ALL_FITS_AND_INFERENCE",
            "parent_preimport_guard": parent_guard,
            "formal_worker_bootstrap_receipt": worker_bootstrap,
            "launch_preflight_resource_receipt": launch_runtime.payload(),
            "launch_preflight_resource_receipt_sha256": launch_runtime.sha256(),
            "fit_resource_receipt": fit_runtime_payload,
            "fit_resource_receipt_sha256": sha256_bytes(
                canonical_json_bytes(fit_runtime_payload)
            ),
            "inference_resource_receipt": inference_runtime_payload,
            "inference_resource_receipt_sha256": sha256_bytes(
                canonical_json_bytes(inference_runtime_payload)
            ),
            "outer_worker_process_count": len(worker_pids),
            "worker_process_ids": worker_pids,
            "available_memory_gib_before_launch": available_gib,
        }
    )
    execution_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_execution_receipt.v1",
            "status": "PASS_EXACT_3100_FITS_64800_ORDERED_PREDICTIONS_READY_TO_SEAL",
            "started_utc": started_utc,
            "ended_utc": ended_utc,
            "elapsed_seconds": elapsed_seconds,
            "task_count": len(task_receipts),
            "folds_per_task": FOLDS_PER_TASK,
            "fit_count": len(block_receipts),
            "prediction_identity_count": len(predictions),
            "decision_rows_per_task": SCORE_END - SCORE_START,
            "distinct_parameter_sha256_count": len(parameter_hashes),
            "within_block_parameter_update_count": 0,
            "requested_prefix_row_count": requested_total,
            "causal_prefix_nonwarm_count": invalid_total,
            "warm_prefix_row_count": warm_total,
            "allowed_causal_invalid_positions": list(ALLOWED_CAUSAL_INVALID_POSITIONS),
            "minimum_warm_prefix_rows_per_entity": FIRST_FOLD_WARM_ROWS,
            "decision_causal_invalid_count": 0,
            "canonical_input_order_required": (
                "decision_date_then_entity_id_stable_mergesort"
            ),
            "silent_sort_count": 0,
            "fit_end_strictly_before_every_decision_row": True,
            "same_parameter_sha256_for_every_row_within_each_block": True,
            "separate_ordered_and_set_membership_sha256": True,
            "ordered_source_positions_sha256_bound": True,
            "prediction_columns": list(PREDICTION_COLUMNS),
            "forbidden_prediction_column_hits": [],
            "prediction_validation": prediction_validation,
            "prediction_records_sha256": sha256_bytes(canonical_json_bytes(predictions)),
            "block_receipts_semantic_sha256": sha256_bytes(
                canonical_json_bytes(block_receipts)
            ),
            "task_receipts_semantic_sha256": sha256_bytes(
                canonical_json_bytes(task_receipts)
            ),
            "score_call_count": 0,
            "registry_or_champion_mutation_count": 0,
            "promotion_count": 0,
        }
    )
    access_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_access_receipt.v1",
            "status": "PASS_PUBLIC_R4_ONLY_NO_PROTECTED_OR_REGISTRY_ACCESS",
            "real_fit_count": FIT_COUNT,
            "real_prediction_block_count": FIT_COUNT,
            "prediction_identity_count": DECISION_COUNT,
            "public_r4_task_count": TASK_COUNT,
            "public_r4_bound_file_count": 150,
            "model_registry_file_read_count": 0,
            "truth_vault_latent_heldout_artifact_open_count": 0,
            "evaluator_artifact_open_count": 0,
            "score_artifact_open_count": 0,
            "frozen_prediction_payload_open_count": 0,
            "score_call_count": 0,
            "registry_or_champion_mutation_count": 0,
            "promotion_count": 0,
            "persistent_parameter_artifact_count": 0,
            "authority": {
                "prediction_only_execution_record": True,
                "score": False,
                "evaluator": False,
                "truth_or_vault": False,
                "registry_or_champion": False,
                "promotion": False,
            },
        }
    )
    core_payloads = {
        "ACCESS_RECEIPT.json": access_receipt,
        "EXECUTION_RECEIPT.json": execution_receipt,
        "IMMUTABILITY_RECEIPT.json": immutability_receipt,
        "INPUT_RECEIPT.json": input_receipt,
        "RUNTIME_RECEIPT.json": runtime_receipt,
    }
    core_files: dict[str, bytes] = {
        name: pretty_json_bytes(payload) for name, payload in core_payloads.items()
    }
    core_files.update(
        {
            "BLOCK_RECEIPTS.jsonl": block_bytes,
            "LAUNCH_CONTRACT.json": design_before["contents"][
                "PREDICTION_LAUNCH_CONTRACT.json"
            ],
            "PREDICTIONS.csv": prediction_bytes,
            "REPORT.md": report_bytes(),
            "TASK_RECEIPTS.jsonl": task_bytes,
            "prediction_launcher.py": launcher_bytes,
        }
    )
    logical_core_payloads = {
        **core_payloads,
        "LAUNCH_CONTRACT.json": parse_json_exact(
            core_files["LAUNCH_CONTRACT.json"],
            label="OUTPUT:LAUNCH_CONTRACT_BUILD",
        ),
    }
    final_relative = f"outputs/{final_root.name}"
    manifest = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_only_root_manifest.v1",
            "status": "PASS_PREDICTION_ONLY_OUTPUT_READY_FOR_ATOMIC_PUBLISH",
            "final_root": final_relative,
            "v8_design_contract_sha256": design_contract_sha256,
            "v8_design_checksums_raw_sha256": design_checksums_raw_sha256,
            "v8_audit_checksums_raw_sha256": audit_checksums_raw_sha256,
            "v8_audit_raw_sha256": audit["raw_sha256"],
            "v8_audit_semantic_sha256": audit["semantic_sha256"],
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "core_files": {
                name: {
                    "raw_sha256": sha256_bytes(content),
                    "size_bytes": len(content),
                    **(
                        {"logical_sha256": logical_sha256(logical_core_payloads[name])}
                        if name in logical_core_payloads
                        else {}
                    ),
                }
                for name, content in sorted(core_files.items())
            },
            "fit_count": FIT_COUNT,
            "prediction_identity_count": DECISION_COUNT,
            "prediction_only_authority": True,
            "score_registry_promotion_authority": False,
        }
    )
    manifest_bytes = pretty_json_bytes(manifest)
    payload_files = {**core_files, "MANIFEST.json": manifest_bytes}
    seal_receipt = sealed(
        {
            "schema_version": "expected_pe.hofs_v8.prediction_output_seal.v1",
            "status": "SEALED_SCORE_BLIND_PREDICTION_ONLY_OUTPUT",
            "final_root": final_relative,
            "expected_final_file_universe": list(FINAL_FILE_UNIVERSE),
            "artifact_hashes": {
                name: {"raw_sha256": sha256_bytes(content), "size_bytes": len(content)}
                for name, content in sorted(payload_files.items())
            },
            "fit_count": FIT_COUNT,
            "prediction_identity_count": DECISION_COUNT,
            "authority": {
                "prediction_only_output": True,
                "score": False,
                "evaluator": False,
                "registry_or_champion": False,
                "promotion": False,
            },
        }
    )
    seal_bytes = pretty_json_bytes(seal_receipt)
    checksummed = {**payload_files, "SEAL_RECEIPT.json": seal_bytes}
    checksums = "".join(
        f"{sha256_bytes(checksummed[name])}  {name}\n"
        for name in FINAL_FILE_UNIVERSE
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    final_files = {**checksummed, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(final_files)) != FINAL_FILE_UNIVERSE:
        raise RuntimeError("prediction publisher final universe drifted")
    for name, content in final_files.items():
        write_bytes(staging_root / name, content)
    fsync_directory(staging_root)
    checksums_raw_sha256 = sha256_bytes(checksums)
    staging_verification = verify_output_bundle(
        staging_root,
        expected_checksums_raw_sha256=checksums_raw_sha256,
    )
    if final_root.exists():
        raise FileExistsError("final prediction root appeared before atomic publish")
    os.replace(staging_root, final_root)
    fsync_directory(OUTPUTS_ROOT)
    if staging_root.exists() or not final_root.is_dir():
        raise RuntimeError("atomic prediction-root publish failed")
    published_verification = verify_output_bundle(
        final_root,
        expected_checksums_raw_sha256=checksums_raw_sha256,
    )
    if published_verification != staging_verification:
        raise RuntimeError("post-publish output verification differs from staging verification")
    return {
        **published_verification,
        "status": "SEALED_AND_ATOMICALLY_PUBLISHED_V8_PREDICTION_ONLY_OUTPUT",
        "final_root": final_relative,
        "staging_residue_count": 0,
        "elapsed_seconds": elapsed_seconds,
        "worker_process_count": len(worker_pids),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    parser.add_argument("--design-checksums-raw-sha256", required=True)
    parser.add_argument("--design-contract-sha256", required=True)
    parser.add_argument("--audit-checksums-raw-sha256")
    parser.add_argument("--audit-raw-sha256")
    parser.add_argument("--audit-semantic-sha256")
    parser.add_argument("--run-id")
    return parser


def main() -> int:
    args = _parser().parse_args()
    design_checksums = require_sha256(
        args.design_checksums_raw_sha256,
        label="V8 design checksums raw hash",
    )
    design_contract = require_sha256(
        args.design_contract_sha256,
        label="V8 design contract hash",
    )
    if args.check:
        if any(
            value is not None
            for value in (
                args.audit_checksums_raw_sha256,
                args.audit_raw_sha256,
                args.audit_semantic_sha256,
                args.run_id,
            )
        ):
            raise RuntimeError("check mode forbids audit pins and run ID")
        result = check_only(
            design_checksums_raw_sha256=design_checksums,
            design_contract_sha256=design_contract,
        )
    else:
        audit_checksums = require_sha256(
            args.audit_checksums_raw_sha256,
            label="V8 audit checksums raw hash",
        )
        audit_raw = require_sha256(args.audit_raw_sha256, label="V8 audit raw hash")
        audit_semantic = require_sha256(
            args.audit_semantic_sha256,
            label="V8 audit semantic hash",
        )
        if type(args.run_id) is not str:
            raise RuntimeError("run mode requires an exact run ID")
        result = run_authorized(
            design_checksums_raw_sha256=design_checksums,
            design_contract_sha256=design_contract,
            audit_checksums_raw_sha256=audit_checksums,
            audit_raw_sha256=audit_raw,
            audit_semantic_sha256=audit_semantic,
            run_id=args.run_id,
        )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
