"""Isolated protected/public worker dispatcher for heldout generation."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SITE_PACKAGES = (
    PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages"
).resolve(strict=True)
V3_DESIGN_LOCK = PROJECT_ROOT / (
    "outputs/model_zoo_dgp_exploration_v3_design_20260820/DESIGN_LOCK.json"
)
V3_DESIGN_LOCK_RAW_SHA256 = (
    "cae42b76858f72e0ad0690ccc49a761421b8c17665028a6eb8a498b6cac2f295"
)
V3_REPLAY_INVENTORY_COMBINED_SHA256 = (
    "6305758d1820bd00e7e23f121839d1fe6479b49ca2c54976c3a5d568a9c1ff77"
)
V3_CHILD_RUNTIME_COMBINED_SHA256 = {
    "v03": "747a4c997a0e844a5bbd9336fd9bb2867b04c1ba3bb9cf8bac4a1cb0dbfc5f6e",
    "v04": "6d8b846aeaef60c0020e1c8a846f4eee8bd8a0bebf98123c25ff5f25d3a6fc5d",
}
_FRAME = struct.Struct(">QQ")
_MAX_PUBLIC_CHANNEL_BYTES = 512 * 1024 * 1024
_CPU_0_31_MASK = (1 << 32) - 1


class WorkerError(RuntimeError):
    """Fail-closed child worker error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise WorkerError("worker requires -I -B")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise WorkerError("Python environment controls are forbidden")
    if sys.pycache_prefix is None:
        raise WorkerError("worker pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise WorkerError("worker pycache prefix is not empty")
    for path in (PROJECT_ROOT, PROJECT_ROOT / "src", SITE_PACKAGES):
        resolved = str(path.resolve(strict=True))
        if resolved not in sys.path:
            sys.path.append(resolved)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.SetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.c_size_t)
    kernel32.SetProcessAffinityMask.restype = wintypes.BOOL
    if not kernel32.SetProcessAffinityMask(
        kernel32.GetCurrentProcess(), ctypes.c_size_t(_CPU_0_31_MASK)
    ):
        raise WorkerError("worker CPU0-31 affinity assignment failed")
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.runtime_custody import (
        require_process_resources,
    )

    require_process_resources()


def _task(ordinal: int) -> Any:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.generation import (
        heldout_tasks,
    )

    tasks = heldout_tasks()
    if ordinal not in range(len(tasks)):
        raise WorkerError("task ordinal escaped heldout plan")
    return tasks[ordinal]


def _design() -> tuple[dict[str, Any], dict[str, Any]]:
    raw = V3_DESIGN_LOCK.resolve(strict=True).read_bytes()
    if hashlib.sha256(raw).hexdigest() != V3_DESIGN_LOCK_RAW_SHA256:
        raise WorkerError("public replay design lock bytes differ")
    try:
        payload = json.loads(raw.decode("ascii"))
        inventory = payload["replay_inventory"]
        runtime = payload["child_runtime_reference"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise WorkerError("public replay design lock schema differs") from exc
    if (
        type(inventory) is not dict
        or inventory.get("combined_sha256") != V3_REPLAY_INVENTORY_COMBINED_SHA256
        or type(runtime) is not dict
        or set(runtime) != {"v03", "v04"}
        or any(
            type(runtime[name]) is not dict
            or runtime[name].get("combined_sha256") != expected
            for name, expected in V3_CHILD_RUNTIME_COMBINED_SHA256.items()
        )
    ):
        raise WorkerError("public replay inventory/runtime binding differs")
    return inventory, runtime


def _read_outer_channel() -> tuple[bytes, bytes]:
    raw = sys.stdin.buffer.read(_MAX_PUBLIC_CHANNEL_BYTES + 1)
    if len(raw) <= _FRAME.size or len(raw) > _MAX_PUBLIC_CHANNEL_BYTES:
        raise WorkerError("outer public channel size differs")
    first_size, second_size = _FRAME.unpack(raw[: _FRAME.size])
    if (
        first_size <= 0
        or second_size <= 0
        or first_size + second_size + _FRAME.size != len(raw)
    ):
        raise WorkerError("outer public channel framing differs")
    split = _FRAME.size + first_size
    return raw[_FRAME.size : split], raw[split:]


def _protected_two_pass(args: argparse.Namespace) -> int:
    import io

    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.protected_generation import (
        generate_two_pass_task,
    )

    task = _task(args.task_ordinal)
    pass_1 = io.BytesIO()
    pass_2 = io.BytesIO()
    generate_two_pass_task(
        task=task,
        pass_1_root=Path(args.pass_1_root),
        pass_2_root=Path(args.pass_2_root),
        pass_1_stream=pass_1,
        pass_2_stream=pass_2,
        project_root=PROJECT_ROOT,
    )
    first = pass_1.getvalue()
    second = pass_2.getvalue()
    sys.stdout.buffer.write(_FRAME.pack(len(first), len(second)))
    sys.stdout.buffer.write(first)
    sys.stdout.buffer.write(second)
    sys.stdout.buffer.flush()
    return 0


def _public_two_pass(args: argparse.Namespace) -> int:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import is_reparse
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.secure_publication import (
        HeldDirectory,
        publish_leaf,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        ArtifactRef,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.public_generation import (
        _require_no_protected_imports,
        replay_two_public_channels,
    )

    _require_no_protected_imports()
    task = _task(args.task_ordinal)
    first, second = _read_outer_channel()
    inventory, runtime = _design()
    result = replay_two_public_channels(
        task=task,
        pass_1_raw=first,
        pass_2_raw=second,
        expected_inventory=inventory,
        expected_child_runtime=runtime,
    )
    output = Path(args.public_task_root).resolve(strict=True)
    if not output.is_dir() or is_reparse(output):
        raise WorkerError("public task output root differs")
    root = HeldDirectory.open_existing(output)
    files = []
    try:
        canonical = publish_leaf(
            parent=root, final_leaf="canonical150.csv", raw=result.canonical_raw
        )
        files.append(canonical)
        overlay = publish_leaf(
            parent=root, final_leaf="v04_overlay.csv", raw=result.overlay_raw
        )
        files.append(overlay)

        def artifact_ref(published: Any) -> dict[str, object]:
            published.assert_live()
            return ArtifactRef(
                relative_path=published.path.relative_to(PROJECT_ROOT).as_posix(),
                raw_sha256=published.raw_sha256,
                size_bytes=published.size_bytes,
                volume_serial_number=int(published.volume_serial_number, 16),
                file_id_128=published.file_id_128,
            ).payload()

        task_manifest_core = {
            "schema_version": "expected_pe.four_model.heldout_public_task_manifest.v1",
            "status": "PASS_TWO_PUBLIC_REPLAYS_FROZEN_PRETRUTH",
            "task": task.payload(),
            "public_replay_design_lock_raw_sha256": V3_DESIGN_LOCK_RAW_SHA256,
            "canonical_ref": artifact_ref(canonical),
            "overlay_ref": artifact_ref(overlay),
            "public_frame_raw_sha256": result.public_frame_raw_sha256,
            "public_frame_rows": result.public_frame_rows,
            "public_frame_raw_hashes_equal": True,
            "public_frame_rows_equal": True,
            "canonical_replay_bytes_equal": True,
            "overlay_replay_bytes_equal": True,
            "protected_generator_imported": False,
            "truth_open_count": 0,
            "score_open_count": 0,
        }
        task_manifest = {
            **task_manifest_core,
            "task_manifest_semantic_sha256": semantic_sha256(task_manifest_core),
        }
        task_manifest_file = publish_leaf(
            parent=root,
            final_leaf="PUBLIC_TASK_MANIFEST.json",
            raw=canonical_pretty_bytes(task_manifest),
        )
        files.append(task_manifest_file)
        receipt = {
            **result.receipt,
            "public_replay_design_lock_raw_sha256": V3_DESIGN_LOCK_RAW_SHA256,
            "canonical_ref": artifact_ref(canonical),
            "overlay_ref": artifact_ref(overlay),
            "task_manifest_ref": artifact_ref(task_manifest_file),
            "task_manifest_semantic_sha256": task_manifest[
                "task_manifest_semantic_sha256"
            ],
        }
        receipt_file = publish_leaf(
            parent=root,
            final_leaf="PUBLIC_REPLAY_RECEIPT.json",
            raw=canonical_pretty_bytes(receipt),
        )
        files.append(receipt_file)
        expected = (
            "PUBLIC_REPLAY_RECEIPT.json",
            "PUBLIC_TASK_MANIFEST.json",
            "canonical150.csv",
            "v04_overlay.csv",
        )
        if root.inventory() != tuple(sorted(expected, key=str.casefold)):
            raise WorkerError("public task output file universe differs")
        for published in files:
            published.assert_live()
        _require_no_protected_imports()
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0
    finally:
        for published in reversed(files):
            published.close()
        root.close()


def _protected_finalize(args: argparse.Namespace) -> int:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.protected_vault_manifest import (
        publish_vault_manifest,
    )

    manifest = publish_vault_manifest(
        vault_root=Path(args.vault_root), project_root=PROJECT_ROOT
    )
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    return 0


def _public_check() -> int:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.public_generation import (
        _require_no_protected_imports,
    )

    _require_no_protected_imports()
    print(
        json.dumps(
            {
                "status": "PASS_COLD_PUBLIC_WORKER_NO_PROTECTED_IMPORT",
                "protected_generator_imported": False,
                "generator_invocation_count": 0,
                "truth_open_count": 0,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _load_public_task(
    *, task: Any, task_root: Path
) -> tuple[bytes, bytes, dict[str, Any], dict[str, Any]]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        raw_sha256,
        semantic_sha256,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        ArtifactRef,
    )

    root = task_root.resolve(strict=True)
    expected = {
        "PUBLIC_REPLAY_RECEIPT.json",
        "PUBLIC_TASK_MANIFEST.json",
        "canonical150.csv",
        "v04_overlay.csv",
    }
    if {path.name for path in root.iterdir()} != expected:
        raise WorkerError("numeric public task file universe differs")
    manifest_raw = (root / "PUBLIC_TASK_MANIFEST.json").read_bytes()
    receipt_raw = (root / "PUBLIC_REPLAY_RECEIPT.json").read_bytes()
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
        receipt = json.loads(receipt_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError("numeric public task JSON differs") from exc
    if (
        type(manifest) is not dict
        or type(receipt) is not dict
        or canonical_pretty_bytes(manifest) != manifest_raw
        or canonical_pretty_bytes(receipt) != receipt_raw
        or manifest.get("schema_version")
        != "expected_pe.four_model.heldout_public_task_manifest.v1"
        or manifest.get("status") != "PASS_TWO_PUBLIC_REPLAYS_FROZEN_PRETRUTH"
        or manifest.get("task") != task.payload()
    ):
        raise WorkerError("numeric public task manifest binding differs")
    stored_semantic = manifest.get("task_manifest_semantic_sha256")
    unsigned = dict(manifest)
    unsigned.pop("task_manifest_semantic_sha256", None)
    if stored_semantic != semantic_sha256(unsigned):
        raise WorkerError("numeric public task manifest self-seal differs")
    canonical_ref = ArtifactRef.from_mapping(manifest.get("canonical_ref"))
    overlay_ref = ArtifactRef.from_mapping(manifest.get("overlay_ref"))
    task_manifest_ref = ArtifactRef.from_mapping(receipt.get("task_manifest_ref"))
    canonical_raw = (root / "canonical150.csv").read_bytes()
    overlay_raw = (root / "v04_overlay.csv").read_bytes()
    if (
        canonical_ref.raw_sha256 != raw_sha256(canonical_raw)
        or canonical_ref.size_bytes != len(canonical_raw)
        or overlay_ref.raw_sha256 != raw_sha256(overlay_raw)
        or overlay_ref.size_bytes != len(overlay_raw)
        or task_manifest_ref.raw_sha256 != raw_sha256(manifest_raw)
        or task_manifest_ref.size_bytes != len(manifest_raw)
        or receipt.get("task_manifest_semantic_sha256") != stored_semantic
    ):
        raise WorkerError("numeric public task ArtifactRef differs")
    return canonical_raw, overlay_raw, manifest, receipt


def _numeric_task(args: argparse.Namespace, *, lane: str) -> int:
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (
        EXACT_ENVIRONMENT,
    )

    runtime_receipt: dict[str, object]
    if lane == "bce":
        from research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.resource import (
            seal_worker_runtime,
        )

        runtime = seal_worker_runtime(args.worker_slot)
        runtime_receipt = {
            "worker_slot": runtime.slot,
            "cpu_ids": list(runtime.cpu_ids),
            "affinity_mask": runtime.affinity_mask,
            "environment": dict(runtime.environment),
            "inner_threads": 1,
        }
    else:
        runtime_receipt = {
            "worker_slot": args.worker_slot,
            "cpu_ids": list(range(32)),
            "affinity_mask": _CPU_0_31_MASK,
            "environment": dict(EXACT_ENVIRONMENT),
            "inner_threads": 1,
        }

    import pandas as pd

    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        atomic_write_new,
        canonical_csv_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        ArtifactRef,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.numeric_services import (
        build_bce_task_surface,
        build_c4_task_surface,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        stable_read,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.public_generation import (
        _require_no_protected_imports,
    )

    _require_no_protected_imports()
    task = _task(args.task_ordinal)
    canonical_raw, overlay_raw, manifest, receipt = _load_public_task(
        task=task, task_root=Path(args.public_task_root)
    )
    if lane == "bce":
        result = build_bce_task_surface(canonical_raw, overlay_raw, task=task)
        surface_leaf = "BCE_SURFACE.csv"
        receipt_leaf = "BCE_RECEIPT.json"
    elif lane == "c4":
        result = build_c4_task_surface(
            canonical_raw,
            task=task,
            canonical_ref=manifest["canonical_ref"],
            task_manifest_ref=receipt["task_manifest_ref"],
            task_manifest_semantic_sha256=receipt[
                "task_manifest_semantic_sha256"
            ],
        )
        surface_leaf = "C4_SURFACE.csv"
        receipt_leaf = "C4_RECEIPT.json"
    else:  # pragma: no cover - dispatcher has a fixed lane universe
        raise WorkerError("numeric lane differs")
    result.receipt["worker_runtime"] = runtime_receipt
    if type(result.surface) is not pd.DataFrame:
        raise WorkerError("numeric worker surface differs")
    output = Path(args.numeric_task_root).resolve(strict=True)
    if any(output.iterdir()):
        raise WorkerError("numeric task output root is not empty")
    surface_raw = canonical_csv_bytes(result.surface)
    surface_path = output / surface_leaf
    atomic_write_new(surface_path, surface_raw)
    observed_raw, observed = stable_read(
        surface_path,
        relative_path=surface_path.relative_to(PROJECT_ROOT).as_posix(),
    )
    if observed_raw != surface_raw:
        raise WorkerError("numeric surface changed after publication")
    result.receipt.update(
        {
            "surface_leaf": surface_leaf,
            "surface_raw_sha256": observed.raw_sha256,
            "surface_size_bytes": observed.size_bytes,
            "surface_ref": ArtifactRef(
                relative_path=observed.relative_path,
                raw_sha256=observed.raw_sha256,
                size_bytes=observed.size_bytes,
                volume_serial_number=int(observed.volume_serial_number, 16),
                file_id_128=observed.file_id_128,
            ).payload(),
        }
    )
    atomic_write_new(output / receipt_leaf, canonical_pretty_bytes(result.receipt))
    _require_no_protected_imports()
    print(json.dumps(result.receipt, sort_keys=True, separators=(",", ":")))
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    protected = commands.add_parser("protected-two-pass")
    protected.add_argument("--task-ordinal", required=True, type=int)
    protected.add_argument("--pass-1-root", required=True)
    protected.add_argument("--pass-2-root", required=True)
    public = commands.add_parser("public-two-pass")
    public.add_argument("--task-ordinal", required=True, type=int)
    public.add_argument("--public-task-root", required=True)
    finalize = commands.add_parser("protected-finalize")
    finalize.add_argument("--vault-root", required=True)
    commands.add_parser("public-check")
    for name in ("numeric-bce", "numeric-c4"):
        numeric = commands.add_parser(name)
        numeric.add_argument("--task-ordinal", required=True, type=int)
        numeric.add_argument("--public-task-root", required=True)
        numeric.add_argument("--numeric-task-root", required=True)
        numeric.add_argument("--worker-slot", required=True, type=int)
    return root


def main() -> int:
    _bootstrap()
    args = parser().parse_args()
    if args.command == "protected-two-pass":
        return _protected_two_pass(args)
    if args.command == "public-two-pass":
        return _public_two_pass(args)
    if args.command == "protected-finalize":
        return _protected_finalize(args)
    if args.command == "public-check":
        return _public_check()
    if args.command == "numeric-bce":
        return _numeric_task(args, lane="bce")
    if args.command == "numeric-c4":
        return _numeric_task(args, lane="c4")
    raise WorkerError("unsupported worker command")


if __name__ == "__main__":
    raise SystemExit(main())
