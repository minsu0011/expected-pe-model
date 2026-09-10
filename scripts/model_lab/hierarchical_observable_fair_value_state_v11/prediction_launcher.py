"""Frozen score-free H-OFS V11 trust/custody launcher preflight.

``--check`` is score-free.  The concrete ``--run`` surface accepts canonical
capability bytes from stdin alone, reopens the exact frozen design and
independent GO audit, atomically claims all 50 tasks at the fixed custodian,
and creates receive-only inherited OS pipes containing distinct
custodian-signed worker grants.  This frozen preflight never calls ``--run``.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
from ctypes import wintypes
import hashlib
import importlib
import json
import multiprocessing
from multiprocessing.connection import PipeConnection
import os
from pathlib import Path
import sys
import time
from typing import Any


LAUNCHER_PATH = Path(__file__).resolve()
LAUNCHER_RELATIVE_PATH = (
    "scripts/model_lab/hierarchical_observable_fair_value_state_v11/"
    "prediction_launcher.py"
)


def _resolve_project_root() -> Path:
    candidates = (LAUNCHER_PATH.parents[3], LAUNCHER_PATH.parents[2])
    sentinel = (
        "research/model_zoo/hierarchical_observable_fair_value_state_v11/"
        "contracts.py"
    )
    matches = [candidate for candidate in candidates if (candidate / sentinel).is_file()]
    if len(matches) != 1:
        raise RuntimeError("H-OFS V11 project-root closure is ambiguous or absent")
    return matches[0]


PROJECT_ROOT = _resolve_project_root()
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
OUTPUT_ROOT_PREFIX = (
    "model_zoo_hierarchical_observable_fair_value_state_v11_"
    "dgp_r4_prediction_only_"
)
PREDICTION_OUTPUT_UNIVERSE = (
    "ACCESS_RECEIPT.json",
    "BLOCK_RECEIPTS.jsonl",
    "CHECKSUMS.sha256",
    "CUSTODY_RECEIPT.json",
    "EXECUTION_RECEIPT.json",
    "MANIFEST.json",
    "PREDICTIONS.csv",
    "REPORT.md",
    "SEAL_RECEIPT.json",
    "TASK_RECEIPTS.jsonl",
    "prediction_launcher.py",
)
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _sealed(payload: dict[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(payload)
    output.pop("manifest_sha256", None)
    output["manifest_sha256"] = _sha256(_canonical_json_bytes(output))
    return output


def _pretty_json_bytes(value: dict[str, Any]) -> bytes:
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


def _is_reparse(path: Path) -> bool:
    try:
        stat_result = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(
        int(getattr(stat_result, "st_file_attributes", 0)) & 0x00000400
    )


def _require_contained_regular(path: Path, *, root: Path) -> bytes:
    if _is_reparse(path) or not path.is_file():
        raise RuntimeError(f"H-OFS V11 non-regular file: {path}")
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as error:
        raise RuntimeError(f"H-OFS V11 file escaped root: {path}") from error
    return path.read_bytes()


def _write_new_bytes(path: Path, content: bytes) -> None:
    if path.exists() or _is_reparse(path.parent) or not path.parent.is_dir():
        raise RuntimeError(f"H-OFS V11 output target custody drifted: {path}")
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if os.name != "nt" or _is_reparse(path) or not path.is_dir():
        raise RuntimeError("H-OFS V11 directory flush target drifted")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
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
        raise RuntimeError("H-OFS V11 directory flush handle failed")
    try:
        if not kernel32.FlushFileBuffers(handle):
            raise RuntimeError("H-OFS V11 directory flush failed")
    finally:
        kernel32.CloseHandle(handle)


def _current_affinity_mask() -> int:
    if os.name != "nt":
        raise RuntimeError("H-OFS V11 resource preflight requires Windows")
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
        raise RuntimeError("H-OFS V11 GetProcessAffinityMask failed")
    return int(process_mask.value)


def _memory_status() -> tuple[int, int]:
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

    status = MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise RuntimeError("H-OFS V11 GlobalMemoryStatusEx failed")
    gib = 1024**3
    return int(status.ullTotalPhys // gib), int(status.ullAvailPhys // gib)


def _prepare_parent_runtime() -> dict[str, Any]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: PLC0415
        PINNED_AFFINITY_MASK,
        PINNED_GPU_ENVIRONMENT,
        PINNED_RAM_MIN_FREE_GIB,
        PINNED_THREAD_ENVIRONMENT,
    )

    imported = sorted(
        name
        for name in sys.modules
        if any(
            name == root or name.startswith(root + ".")
            for root in ("numpy", "pandas", "threadpoolctl")
        )
    )
    if imported:
        raise RuntimeError(
            f"H-OFS V11 forbidden numeric module preloaded in parent: {imported}"
        )
    for name, value in PINNED_THREAD_ENVIRONMENT + PINNED_GPU_ENVIRONMENT:
        os.environ[name] = value
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.c_size_t)
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    if not kernel32.SetProcessAffinityMask(
        kernel32.GetCurrentProcess(),
        ctypes.c_size_t(PINNED_AFFINITY_MASK),
    ):
        raise RuntimeError("H-OFS V11 SetProcessAffinityMask failed")
    total_ram_gib, available_ram_gib = _memory_status()
    if available_ram_gib < PINNED_RAM_MIN_FREE_GIB:
        raise RuntimeError("H-OFS V11 insufficient free RAM for authorized run")
    return {
        "parent_pid": os.getpid(),
        "affinity_mask_hex": f"0x{_current_affinity_mask():08X}",
        "total_ram_gib_floor": total_ram_gib,
        "available_ram_gib_floor": available_ram_gib,
        "thread_environment": [list(value) for value in PINNED_THREAD_ENVIRONMENT],
        "gpu_environment": [list(value) for value in PINNED_GPU_ENVIRONMENT],
        "forbidden_preimport_modules": imported,
    }


def _load_exact_v9_source_map_after_authority() -> dict[str, str]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: PLC0415
        V9_DESIGN_BINDING,
    )

    root = PROJECT_ROOT / str(V9_DESIGN_BINDING["path"])
    source_path = root / "SOURCE_CLOSURE.json"
    content = _require_contained_regular(source_path, root=root)
    if _sha256(content) != V9_DESIGN_BINDING["source_closure_raw_sha256"]:
        raise RuntimeError("H-OFS V11 frozen V9 source-closure pin drifted")
    try:
        payload = json.loads(content.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("H-OFS V11 frozen V9 source closure is invalid") from error
    rows = payload.get("source_audit", {}).get("source_sha256")
    if type(rows) is not list or len(rows) != 30:
        raise RuntimeError("H-OFS V11 frozen V9 source-map universe drifted")
    source_map: dict[str, str] = {}
    for row in rows:
        if (
            type(row) is not list
            or len(row) != 2
            or type(row[0]) is not str
            or type(row[1]) is not str
            or len(row[1]) != 64
            or row[0] in source_map
        ):
            raise RuntimeError("H-OFS V11 frozen V9 source-map receipt drifted")
        source_content = _require_contained_regular(PROJECT_ROOT / row[0], root=PROJECT_ROOT)
        if _sha256(source_content) != row[1]:
            raise RuntimeError(f"H-OFS V11 immutable V9/V7 source drifted: {row[0]}")
        source_map[row[0]] = row[1]
    return source_map


def _initialize_frozen_v9_numeric_surface(
    *,
    runtime_identity: dict[str, Any],
    first_task_barrier: Any,
) -> dict[str, Any]:
    """Install immutable V9/V7 numeric code after V11 authority, without I/O."""

    source_map = _load_exact_v9_source_map_after_authority()
    bootstrap = importlib.import_module(
        "research.model_zoo.hierarchical_observable_fair_value_state_v9.bootstrap"
    )
    if getattr(bootstrap, "_WORKER_LIFECYCLE", None) is not None:
        raise RuntimeError("H-OFS V11 numeric surface was already initialized")
    loaded_closure = bootstrap._build_loaded_closure(  # noqa: SLF001
        project_root=PROJECT_ROOT,
        allowed_source_hashes=source_map,
        preimport_guard_receipt=runtime_identity,
    )
    initializer_receipt = bootstrap.sealed_payload(
        {
            "schema_version": "expected_pe.hofs_v11.numeric_initializer_receipt.v1",
            "status": "PASS_V11_AUTHORITY_PRECEDED_IMMUTABLE_V9_V7_IMPORT",
            "worker_pid": os.getpid(),
            "initializer_count_per_pid": 1,
            "absence_guard_count_per_pid": 1,
            "loaded_closure": loaded_closure,
            "public_header_or_payload_open_count": 0,
            "real_fit_count": 0,
            "real_prediction_count": 0,
        }
    )
    bootstrap._WORKER_LIFECYCLE = {  # noqa: SLF001
        "worker_pid": os.getpid(),
        "project_root": PROJECT_ROOT,
        "allowed_source_hashes": source_map,
        "preimport_guard_receipt": copy.deepcopy(runtime_identity),
        "initializer_receipt": initializer_receipt,
        "loaded_closure": copy.deepcopy(loaded_closure),
        "first_task_barrier": first_task_barrier,
        "validated_task_count": 0,
    }
    return initializer_receipt


def _inherited_worker_message(
    *,
    capability_envelope_bytes: bytes,
    custodian_signed_worker_grant: bytes,
) -> bytes:
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: PLC0415
        PRODUCTION_INHERITED_CHANNEL_DOMAIN,
    )

    if (
        type(capability_envelope_bytes) is not bytes
        or not capability_envelope_bytes
        or type(custodian_signed_worker_grant) is not bytes
        or not custodian_signed_worker_grant
    ):
        raise RuntimeError("H-OFS V11 inherited message requires exact signed bytes")
    return _canonical_json_bytes(
        {
            "schema_version": "expected_pe.hofs_v11.inherited_worker_channel.v1",
            "domain_hex": PRODUCTION_INHERITED_CHANNEL_DOMAIN.hex(),
            "canonical_capability_envelope_hex": capability_envelope_bytes.hex(),
            "custodian_signed_worker_grant_hex": (
                custodian_signed_worker_grant.hex()
            ),
        }
    )


def _prepare_exact_full_schedule_for_future_audited_launcher(
    capability_envelope_bytes: bytes,
) -> tuple[tuple[PipeConnection, ...], dict[str, Any]]:
    """Claim the complete schedule before returning authenticated worker pipes."""

    from research.model_zoo.hierarchical_observable_fair_value_state_v11.authority import (  # noqa: PLC0415
        verify_production_capability,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: PLC0415
        PINNED_OUTER_WORKERS,
        R4_TASK_COUNT,
        R4_TASK_MANIFEST_SHA256,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.custody import (  # noqa: PLC0415
        ProductionCustodyClient,
    )

    capability = verify_production_capability(capability_envelope_bytes)
    client = ProductionCustodyClient()
    claim, grants = client.claim_full_schedule(capability)
    receivers: list[PipeConnection] = []
    senders: list[PipeConnection] = []
    try:
        for grant in grants:
            receiver, sender = multiprocessing.Pipe(duplex=False)
            if (
                type(receiver) is not PipeConnection
                or type(sender) is not PipeConnection
                or not receiver.readable
                or receiver.writable
                or sender.readable
                or not sender.writable
            ):
                raise RuntimeError("H-OFS V11 inherited OS pipe geometry drifted")
            receivers.append(receiver)
            senders.append(sender)
        for sender, grant in zip(senders, grants):
            sender.send_bytes(
                _inherited_worker_message(
                    capability_envelope_bytes=capability.envelope_bytes,
                    custodian_signed_worker_grant=grant,
                )
            )
            sender.close()
        senders.clear()
    except BaseException:
        for connection in senders + receivers:
            connection.close()
        client.fail_schedule(
            capability=capability,
            failure_code="INHERITED_WORKER_CHANNEL_PREPARATION_FAILED",
        )
        raise
    if (
        len(receivers) != PINNED_OUTER_WORKERS
        or claim["task_count"] != R4_TASK_COUNT
        or claim["task_manifest_sha256"] != R4_TASK_MANIFEST_SHA256
        or claim["success"] is not False
    ):
        for receiver in receivers:
            receiver.close()
        client.fail_schedule(
            capability=capability,
            failure_code="FULL_SCHEDULE_CLAIM_RECEIPT_DRIFTED",
        )
        raise RuntimeError("H-OFS V11 exact full schedule claim drifted")
    return tuple(receivers), claim


def _finalize_exact_full_schedule_for_future_audited_launcher(
    capability_envelope_bytes: bytes,
) -> dict[str, Any]:
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.authority import (  # noqa: PLC0415
        verify_production_capability,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: PLC0415
        R4_TASK_COUNT,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.custody import (  # noqa: PLC0415
        ProductionCustodyClient,
    )

    capability = verify_production_capability(capability_envelope_bytes)
    receipt = ProductionCustodyClient().finish_full_schedule(capability=capability)
    expected = {
        "status": "DURABLE_FULL_50_TASK_SCHEDULE_COMPLETED",
        "capability_identity_sha256": capability.capability_identity_sha256,
        "completed_task_count": R4_TASK_COUNT,
        "task_count": R4_TASK_COUNT,
        "success": True,
    }
    if receipt != expected:
        raise RuntimeError("H-OFS V11 signed full-schedule completion drifted")
    return receipt


def _v11_authorized_worker_loop(
    inherited_receiver: PipeConnection,
    task_queue: Any,
    result_queue: Any,
    first_task_barrier: Any,
) -> None:
    """Private spawned entry; no caller task identity reaches downstream."""

    current_task: int | None = None
    try:
        from research.model_zoo.hierarchical_observable_fair_value_state_v11.lifecycle import (  # noqa: PLC0415
            _claim_exact_task_before_downstream,
            _complete_exact_task_after_downstream,
            _install_worker_from_inherited_channel,
        )

        installer_receipt = _install_worker_from_inherited_channel(
            inherited_receiver
        )
        numeric_receipt = _initialize_frozen_v9_numeric_surface(
            runtime_identity=installer_receipt["runtime_identity"],
            first_task_barrier=first_task_barrier,
        )
        v9_launcher = importlib.import_module(
            "scripts.model_lab.hierarchical_observable_fair_value_state_v9."
            "prediction_launcher"
        )
        result_queue.put(
            {
                "kind": "INITIALIZED",
                "worker_pid": os.getpid(),
                "worker_slot": installer_receipt["worker_slot"],
                "installer_receipt": installer_receipt,
                "numeric_receipt": numeric_receipt,
            }
        )
        while True:
            item = task_queue.get()
            if item is None:
                break
            if type(item) is not int or isinstance(item, bool):
                raise RuntimeError("H-OFS V11 internal task queue ordinal drifted")
            current_task = item
            authority_receipt = _claim_exact_task_before_downstream(item)
            task = authority_receipt["task"]
            result = v9_launcher.execute_task(
                task["task_ordinal"],
                task["seed"],
                task["dgp"],
                task["canonical_relative"],
                task["expected_raw_sha256"],
            )
            completion_receipt = _complete_exact_task_after_downstream(item)
            result_queue.put(
                {
                    "kind": "TASK_COMPLETED",
                    "task_ordinal": item,
                    "worker_pid": os.getpid(),
                    "authority_receipt": authority_receipt,
                    "completion_receipt": completion_receipt,
                    "prediction_result": result,
                }
            )
            current_task = None
    except BaseException as error:
        try:
            result_queue.put(
                {
                    "kind": "WORKER_FAILED_CLOSED",
                    "worker_pid": os.getpid(),
                    "task_ordinal": current_task,
                    "error_type": type(error).__name__,
                    "error_message": str(error)[:1000],
                }
            )
        finally:
            raise


def _prediction_output_roots(run_id: str) -> tuple[Path, Path]:
    if (
        type(run_id) is not str
        or len(run_id) != 15
        or run_id[8] != "T"
        or not (run_id[:8] + run_id[9:]).isdigit()
        or _is_reparse(OUTPUTS_ROOT)
        or not OUTPUTS_ROOT.is_dir()
    ):
        raise RuntimeError("H-OFS V11 output root or signed run ID drifted")
    final_root = OUTPUTS_ROOT / f"{OUTPUT_ROOT_PREFIX}{run_id}"
    staging_root = OUTPUTS_ROOT / f".{final_root.name}.staging"
    if (
        final_root.resolve().parent != OUTPUTS_ROOT.resolve()
        or staging_root.resolve().parent != OUTPUTS_ROOT.resolve()
        or final_root.name.casefold() == staging_root.name.casefold()
    ):
        raise RuntimeError("H-OFS V11 prediction root escaped exact parent")
    return final_root, staging_root


def _publish_prediction_only_output(
    *,
    capability: Any,
    full_claim_receipt: dict[str, Any],
    completion_receipt: dict[str, Any],
    parent_runtime: dict[str, Any],
    initializer_receipts: list[dict[str, Any]],
    task_messages: list[dict[str, Any]],
) -> dict[str, Any]:
    v9_launcher = importlib.import_module(
        "scripts.model_lab.hierarchical_observable_fair_value_state_v9."
        "prediction_launcher"
    )
    ordered = sorted(task_messages, key=lambda row: row["task_ordinal"])
    if (
        [row["task_ordinal"] for row in ordered] != list(range(50))
        or len(initializer_receipts) != 32
        or len({row["worker_pid"] for row in initializer_receipts}) != 32
        or len({row["worker_slot"] for row in initializer_receipts}) != 32
    ):
        raise RuntimeError("H-OFS V11 exact worker/task result universe drifted")
    results = [row["prediction_result"] for row in ordered]
    for ordinal, (message, task) in enumerate(zip(ordered, capability.tasks)):
        result = message["prediction_result"]
        if (
            result.get("task_ordinal") != ordinal
            or result.get("seed") != task["seed"]
            or result.get("dgp") != task["dgp"]
            or message["authority_receipt"].get("task") != dict(task)
            or message["completion_receipt"].get("task_ordinal") != ordinal
        ):
            raise RuntimeError(f"H-OFS V11 task output binding drifted: {ordinal}")
    predictions = [row for result in results for row in result["prediction_rows"]]
    blocks = [row for result in results for row in result["block_receipts"]]
    task_receipts = [
        {
            "task_ordinal": message["task_ordinal"],
            "worker_pid": message["worker_pid"],
            "authority": message["authority_receipt"],
            "completion": message["completion_receipt"],
            "model_task_receipt": message["prediction_result"]["task_receipt"],
        }
        for message in ordered
    ]
    if len(predictions) != 64_800 or len(blocks) != 3_100:
        raise RuntimeError("H-OFS V11 inherited prediction geometry drifted")
    prediction_bytes = v9_launcher.serialize_predictions(predictions)
    prediction_validation, reparsed = v9_launcher.verify_prediction_csv(
        prediction_bytes
    )
    if reparsed != predictions:
        raise RuntimeError("H-OFS V11 prediction typed round-trip drifted")
    block_bytes = v9_launcher.serialize_jsonl(blocks)
    task_bytes = v9_launcher.serialize_jsonl(task_receipts)
    launcher_bytes = _require_contained_regular(LAUNCHER_PATH, root=PROJECT_ROOT)
    final_root, staging_root = _prediction_output_roots(capability.run_id)
    if final_root.exists() or staging_root.exists():
        raise FileExistsError("H-OFS V11 unique prediction root already exists")
    staging_root.mkdir(exist_ok=False)
    if _is_reparse(staging_root) or not staging_root.is_dir():
        raise RuntimeError("H-OFS V11 staging root is non-regular")
    final_relative = f"outputs/{final_root.name}"
    access = _sealed(
        {
            "schema_version": "expected_pe.hofs_v11.prediction_access.v1",
            "status": "PASS_PREDICTION_ONLY_ACCESS_BOUNDARY",
            "public_canonical_open_count": 50,
            "real_fit_count": 3_100,
            "real_prediction_block_count": 3_100,
            "prediction_identity_count": 64_800,
            "truth_qualification_heldout_evaluator_or_score_open_count": 0,
            "registry_or_champion_mutation_count": 0,
            "promotion_count": 0,
        }
    )
    custody = _sealed(
        {
            "schema_version": "expected_pe.hofs_v11.output_custody.v1",
            "status": "PASS_DURABLE_EXACT_50_TASK_SCHEDULE_COMPLETED",
            "capability_identity_sha256": capability.capability_identity_sha256,
            "full_schedule_claim": full_claim_receipt,
            "full_schedule_completion": completion_receipt,
            "initializer_worker_count": len(initializer_receipts),
            "completed_task_count": len(task_messages),
            "partial_schedule_success": False,
        }
    )
    execution = _sealed(
        {
            "schema_version": "expected_pe.hofs_v11.prediction_execution.v1",
            "status": "PASS_AUTHORIZED_EXACT_R4_PREDICTION_ONLY_EXECUTION",
            "run_id": capability.run_id,
            "capability_identity_sha256": capability.capability_identity_sha256,
            "signed_message_sha256": capability.signed_message_sha256,
            "task_manifest_sha256": capability.payload["task_manifest_sha256"],
            "task_count": 50,
            "fit_count": 3_100,
            "prediction_identity_count": 64_800,
            "parent_runtime": parent_runtime,
            "worker_pids": sorted(row["worker_pid"] for row in initializer_receipts),
            "prediction_validation": prediction_validation,
            "score_or_registry_authority": False,
        }
    )
    report = (
        "# H-OFS V11 prediction-only output\n\n"
        "This root contains the exact 50-task R4 prediction schedule authorized "
        "by one canonical custodian-signed V11 capability. No truth, score, "
        "evaluator, registry, champion, or promotion surface was accessed.\n"
    ).encode("ascii")
    core = {
        "ACCESS_RECEIPT.json": _pretty_json_bytes(access),
        "BLOCK_RECEIPTS.jsonl": block_bytes,
        "CUSTODY_RECEIPT.json": _pretty_json_bytes(custody),
        "EXECUTION_RECEIPT.json": _pretty_json_bytes(execution),
        "PREDICTIONS.csv": prediction_bytes,
        "REPORT.md": report,
        "TASK_RECEIPTS.jsonl": task_bytes,
        "prediction_launcher.py": launcher_bytes,
    }
    manifest = _sealed(
        {
            "schema_version": "expected_pe.hofs_v11.prediction_manifest.v1",
            "status": "PASS_PREDICTION_ONLY_OUTPUT_READY_FOR_ATOMIC_PUBLISH",
            "final_root": final_relative,
            "capability_identity_sha256": capability.capability_identity_sha256,
            "expected_file_universe": list(PREDICTION_OUTPUT_UNIVERSE),
            "core_files": {
                name: {"raw_sha256": _sha256(content), "size_bytes": len(content)}
                for name, content in sorted(core.items())
            },
            "prediction_only_authority": True,
            "score_registry_promotion_authority": False,
        }
    )
    manifest_bytes = _pretty_json_bytes(manifest)
    sealed_files = {**core, "MANIFEST.json": manifest_bytes}
    seal = _sealed(
        {
            "schema_version": "expected_pe.hofs_v11.prediction_output_seal.v1",
            "status": "SEALED_SCORE_BLIND_PREDICTION_ONLY_OUTPUT",
            "final_root": final_relative,
            "expected_file_universe": list(PREDICTION_OUTPUT_UNIVERSE),
            "artifact_hashes": {
                name: {"raw_sha256": _sha256(content), "size_bytes": len(content)}
                for name, content in sorted(sealed_files.items())
            },
            "fit_count": 3_100,
            "prediction_identity_count": 64_800,
            "authority": {
                "prediction_only_output": True,
                "score": False,
                "evaluator": False,
                "registry_or_champion": False,
                "promotion": False,
            },
        }
    )
    with_seal = {**sealed_files, "SEAL_RECEIPT.json": _pretty_json_bytes(seal)}
    checksums = "".join(
        f"{_sha256(with_seal[name])}  {name}\n"
        for name in PREDICTION_OUTPUT_UNIVERSE
        if name != "CHECKSUMS.sha256"
    ).encode("ascii")
    files = {**with_seal, "CHECKSUMS.sha256": checksums}
    if tuple(sorted(files)) != PREDICTION_OUTPUT_UNIVERSE:
        raise RuntimeError("H-OFS V11 prediction file universe drifted")
    for name, content in files.items():
        _write_new_bytes(staging_root / name, content)
    _fsync_directory(staging_root)
    for line in checksums.decode("ascii").splitlines():
        digest, name = line.split("  ", maxsplit=1)
        if _sha256((staging_root / name).read_bytes()) != digest:
            raise RuntimeError("H-OFS V11 staged prediction checksum drifted")
    if final_root.exists():
        raise FileExistsError("H-OFS V11 final root appeared before atomic publish")
    os.replace(staging_root, final_root)
    _fsync_directory(OUTPUTS_ROOT)
    if staging_root.exists() or not final_root.is_dir() or _is_reparse(final_root):
        raise RuntimeError("H-OFS V11 atomic prediction publish failed")
    return {
        "status": "SEALED_AND_ATOMICALLY_PUBLISHED_V11_PREDICTION_ONLY_OUTPUT",
        "final_root": final_relative,
        "checksums_raw_sha256": _sha256(checksums),
        "file_count": len(files),
        "checksum_ledger_entry_count": len(files) - 1,
        "capability_identity_sha256": capability.capability_identity_sha256,
        "task_count": 50,
        "prediction_identity_count": 64_800,
    }


def run_authorized_prediction_only(capability_envelope_bytes: bytes) -> dict[str, Any]:
    """Concrete production run: capability bytes are the only trust input."""

    from research.model_zoo.hierarchical_observable_fair_value_state_v11.authority import (  # noqa: PLC0415
        verify_production_capability,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.custody import (  # noqa: PLC0415
        ProductionCustodyClient,
    )

    parent_runtime = _prepare_parent_runtime()
    capability = verify_production_capability(capability_envelope_bytes)
    final_root, staging_root = _prediction_output_roots(capability.run_id)
    if final_root.exists() or staging_root.exists():
        raise FileExistsError("H-OFS V11 signed run output identity already exists")
    receivers, full_claim = _prepare_exact_full_schedule_for_future_audited_launcher(
        capability.envelope_bytes
    )
    context = multiprocessing.get_context("spawn")
    first_task_barrier = context.Barrier(32)
    result_queue = context.Queue()
    task_queues = [context.Queue() for _ in range(32)]
    processes: list[multiprocessing.Process] = []
    custody_finalized = False
    try:
        for slot in range(32):
            process = context.Process(
                target=_v11_authorized_worker_loop,
                args=(
                    receivers[slot],
                    task_queues[slot],
                    result_queue,
                    first_task_barrier,
                ),
                name=f"hofs-v11-worker-{slot:02d}",
            )
            process.start()
            processes.append(process)
            receivers[slot].close()
        initialized: list[dict[str, Any]] = []
        deadline = time.monotonic() + 180.0
        while len(initialized) < 32:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("H-OFS V11 worker initialization timed out")
            message = result_queue.get(timeout=remaining)
            if message.get("kind") != "INITIALIZED":
                raise RuntimeError(f"H-OFS V11 worker failed before fanout: {message}")
            initialized.append(message)
        if (
            len({row["worker_pid"] for row in initialized}) != 32
            or {row["worker_slot"] for row in initialized} != set(range(32))
        ):
            raise RuntimeError("H-OFS V11 worker initializer fanout drifted")
        for ordinal in range(50):
            task_queues[ordinal % 32].put(ordinal)
        for task_queue in task_queues:
            task_queue.put(None)
        completed: list[dict[str, Any]] = []
        deadline = time.monotonic() + 3_600.0
        while len(completed) < 50:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("H-OFS V11 authorized task schedule timed out")
            message = result_queue.get(timeout=min(remaining, 60.0))
            if message.get("kind") != "TASK_COMPLETED":
                raise RuntimeError(f"H-OFS V11 worker schedule failed closed: {message}")
            completed.append(message)
        for process in processes:
            process.join(timeout=30.0)
            if process.exitcode != 0:
                raise RuntimeError("H-OFS V11 worker exited nonzero")
        completion = _finalize_exact_full_schedule_for_future_audited_launcher(
            capability.envelope_bytes
        )
        custody_finalized = True
        return _publish_prediction_only_output(
            capability=capability,
            full_claim_receipt=full_claim,
            completion_receipt=completion,
            parent_runtime=parent_runtime,
            initializer_receipts=initialized,
            task_messages=completed,
        )
    except BaseException:
        for process in processes:
            if process.is_alive():
                process.terminate()
            process.join(timeout=10.0)
        if not custody_finalized:
            ProductionCustodyClient().fail_schedule(
                capability=capability,
                failure_code="AUTHORIZED_RUN_FAILED_BEFORE_FULL_SUCCESS",
            )
        raise
    finally:
        for receiver in receivers:
            if not receiver.closed:
                receiver.close()
        for task_queue in task_queues:
            task_queue.close()
            task_queue.join_thread()
        result_queue.close()
        result_queue.join_thread()


def check_only() -> dict[str, Any]:
    """Read only source/runtime metadata; never contact custody or open R4 data."""

    from research.model_zoo.hierarchical_observable_fair_value_state_v11.contracts import (  # noqa: PLC0415
        PINNED_AFFINITY_MASK,
        PINNED_OUTER_WORKERS,
        PRODUCTION_PUBLIC_KEY_RAW_SHA256,
        R4_TASK_COUNT,
        R4_TASK_MANIFEST_SHA256,
        contract_sha256,
    )
    from research.model_zoo.hierarchical_observable_fair_value_state_v11.custody import (  # noqa: PLC0415
        production_custody_service_preflight,
    )

    total_ram_gib, available_ram_gib = _memory_status()
    return {
        "schema_version": "expected_pe.hofs_v11.check_only.v1",
        "status": "PASS_V11_SCORE_FREE_PREFLIGHT_AWAITS_INDEPENDENT_AUDIT_AND_SIGNATURE",
        "contract_sha256": contract_sha256(),
        "launcher_raw_sha256": _sha256(LAUNCHER_PATH.read_bytes()),
        "launcher_relative_path": LAUNCHER_RELATIVE_PATH,
        "production_public_key_raw_sha256": PRODUCTION_PUBLIC_KEY_RAW_SHA256,
        "exact_r4_task_manifest_sha256": R4_TASK_MANIFEST_SHA256,
        "exact_r4_task_count": R4_TASK_COUNT,
        "outer_workers": PINNED_OUTER_WORKERS,
        "observed_affinity_mask_hex": f"0x{_current_affinity_mask():08X}",
        "required_affinity_mask_hex": f"0x{PINNED_AFFINITY_MASK:08X}",
        "total_ram_gib_floor": total_ram_gib,
        "available_ram_gib_floor": available_ram_gib,
        "custody": production_custody_service_preflight(),
        "production_capability_present": False,
        "independent_v11_audit_present": False,
        "custody_connection_attempt_count": 0,
        "run_mode_present": True,
        "run_trust_input": "EXACT_CANONICAL_CAPABILITY_ENVELOPE_BYTES_FROM_STDIN_ONLY",
        "public_input_open_count": 0,
        "real_fit_count": 0,
        "real_prediction_count": 0,
        "protected_or_score_open_count": 0,
        "registry_mutation_count": 0,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--run", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.check:
        result = check_only()
    else:
        envelope = sys.stdin.buffer.read(4_000_001)
        if not envelope or len(envelope) > 4_000_000:
            raise RuntimeError("H-OFS V11 production capability stdin size drifted")
        result = run_authorized_prediction_only(envelope)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
