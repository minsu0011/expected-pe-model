"""Detached independent audit and evaluator-plumbing rehearsal for R3."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
from pathlib import Path
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_PACKAGES = (PROJECT_ROOT.parent / ".venv_pe_model_lab_py310/Lib/site-packages").resolve(
    strict=True
)
_CPU_0_31_MASK = (1 << 32) - 1
_PREFIX_NAMES = (
    "PREDICTIONS.csv",
    "REHEARSAL_EXECUTION_RECEIPT.json",
    "REHEARSAL_MANIFEST.json",
    "REHEARSAL_SOURCE_LOCK.json",
)
_SEALED_NAMES = (
    *_PREFIX_NAMES,
    "REHEARSAL_AUDIT.json",
    "CHECKSUMS.sha256",
    "REHEARSAL_SEAL.json",
)


class RehearsalAuditError(RuntimeError):
    """Fail-closed independent rehearsal audit error."""


def _bootstrap() -> None:
    if not (sys.flags.isolated and sys.dont_write_bytecode):
        raise RehearsalAuditError("R3 auditor requires -I -B")
    if any(name.upper().startswith("PYTHON") for name in os.environ):
        raise RehearsalAuditError("R3 auditor forbids Python environment controls")
    if sys.pycache_prefix is None:
        raise RehearsalAuditError("R3 auditor pycache prefix is absent")
    prefix = Path(sys.pycache_prefix).resolve(strict=True)
    if any(prefix.iterdir()):
        raise RehearsalAuditError("R3 auditor pycache prefix is not empty")
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
        raise RehearsalAuditError("R3 auditor CPU0-31 assignment failed")


def _artifact(record: Any) -> dict[str, object]:
    return {
        "relative_path": record.relative_path,
        "raw_sha256": record.raw_sha256,
        "size_bytes": record.size_bytes,
        "volume_serial_number": int(record.volume_serial_number, 16),
        "file_id_128": record.file_id_128,
    }


def _read(path: Path, *, relative: str) -> tuple[bytes, dict[str, object]]:
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        stable_read,
    )

    raw, record = stable_read(path, relative_path=relative)
    return raw, _artifact(record)


def _json(raw: bytes, *, label: str) -> dict[str, Any]:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
    )

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalAuditError(f"{label} JSON differs") from exc
    if type(value) is not dict or canonical_pretty_bytes(value) != raw:
        raise RehearsalAuditError(f"{label} canonical bytes differ")
    return value


def _self_seal(value: dict[str, Any], field: str, *, label: str) -> str:
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        semantic_sha256,
    )

    unsigned = dict(value)
    stored = unsigned.pop(field, None)
    if type(stored) is not str or stored != semantic_sha256(unsigned):
        raise RehearsalAuditError(f"{label} self-seal differs")
    return stored


def _validate_source_lock(value: dict[str, Any]) -> str:
    from scripts.model_lab.pe_four_model_r3_rehearsal_contract import (
        REHEARSAL_SOURCE_RELATIVES,
    )

    if (
        value.get("schema_version") != "expected_pe.four_model.r3_rehearsal.source_lock.v1"
        or value.get("status") != "FROZEN_BEFORE_NONRESERVED_GENERATION"
        or value.get("source_relatives_in_order") != list(REHEARSAL_SOURCE_RELATIVES)
        or type(value.get("source_records")) is not list
        or len(value["source_records"]) != len(REHEARSAL_SOURCE_RELATIVES)
    ):
        raise RehearsalAuditError("R3 source lock contract differs")
    for relative, record in zip(REHEARSAL_SOURCE_RELATIVES, value["source_records"], strict=True):
        path = (PROJECT_ROOT / relative).resolve(strict=True)
        raw = path.read_bytes()
        if record != {
            "relative_path": relative,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }:
            raise RehearsalAuditError(f"R3 live source differs: {relative}")
    return _self_seal(value, "source_lock_semantic_sha256", label="R3 source lock")


def _audit(args: argparse.Namespace) -> int:
    import pandas as pd

    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.artifacts import (
        canonical_csv_bytes,
    )
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        exact_root,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        BCE_TASK_SURFACE_COLUMNS,
        C1_ID,
        HOFS_TASK_SURFACE_COLUMNS,
        IDENTITY_COLUMNS,
        MODEL_IDS_IN_ORDER,
        PREDICTION_COLUMNS,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1 import (
        independent_audit,
    )
    from scripts.model_lab.pe_four_model_r3_rehearsal_contract import (
        REHEARSAL_DGP_IDS,
        REHEARSAL_IDENTITY_COUNT,
        REHEARSAL_PREDICTION_ROW_COUNT,
        REHEARSAL_SEED_ALIASES,
        REHEARSAL_SEEDS,
        REHEARSAL_TASK_COUNT,
        rehearsal_tasks,
    )

    producer = "research.model_zoo.pe_four_model_fresh_heldout_authority_v1.prediction"
    if producer in sys.modules:
        raise RehearsalAuditError("R3 independent auditor imported prediction producer")
    root, root_identity = exact_root(Path(args.prediction_root), expected_files=_PREFIX_NAMES)
    work = Path(args.numeric_work_root).resolve(strict=True)
    if any(token in str(work).casefold() for token in ("vault", "truth", "latent")):
        raise RehearsalAuditError("R3 auditor received a protected namespace")
    expected_work = {"bce", "c4"}
    if {path.name for path in work.iterdir()} != expected_work:
        raise RehearsalAuditError("R3 numeric lane universe differs")
    for lane in expected_work:
        lane_root = work / lane
        if {path.name for path in lane_root.iterdir()} != set(REHEARSAL_SEED_ALIASES):
            raise RehearsalAuditError("R3 numeric seed-alias universe differs")
        for alias in REHEARSAL_SEED_ALIASES:
            if {path.name for path in (lane_root / alias).iterdir()} != {
                f"dgp_{dgp}" for dgp in REHEARSAL_DGP_IDS
            }:
                raise RehearsalAuditError("R3 numeric DGP universe differs")

    raws: dict[str, bytes] = {}
    refs: dict[str, dict[str, object]] = {}
    for name in _PREFIX_NAMES:
        relative = (root / name).relative_to(PROJECT_ROOT).as_posix()
        raws[name], refs[name] = _read(root / name, relative=relative)
    manifest = _json(raws["REHEARSAL_MANIFEST.json"], label="R3 manifest")
    execution = _json(raws["REHEARSAL_EXECUTION_RECEIPT.json"], label="R3 execution receipt")
    source = _json(raws["REHEARSAL_SOURCE_LOCK.json"], label="R3 source lock")
    manifest_semantic = _self_seal(manifest, "manifest_semantic_sha256", label="R3 manifest")
    execution_semantic = _self_seal(
        execution, "execution_semantic_sha256", label="R3 execution receipt"
    )
    source_semantic = _validate_source_lock(source)
    integer_root_identity = {
        "volume_serial_number": int(root_identity["volume_serial_number"], 16),
        "file_id_128": root_identity["file_id_128"],
    }
    if (
        manifest.get("schema_version")
        != "expected_pe.four_model.r3_full_nonreserved_rehearsal.manifest.v1"
        or manifest.get("status") != "FROZEN_PRODUCTION_SCALE_PREFIX_PRETRUTH"
        or manifest.get("run_id") != args.run_id
        or manifest.get("nonreserved_seeds_in_order") != list(REHEARSAL_SEEDS)
        or manifest.get("seed_aliases_in_order") != list(REHEARSAL_SEED_ALIASES)
        or manifest.get("dgp_ids_in_order") != list(REHEARSAL_DGP_IDS)
        or manifest.get("task_count") != REHEARSAL_TASK_COUNT
        or manifest.get("identity_count") != REHEARSAL_IDENTITY_COUNT
        or manifest.get("prediction_row_count") != REHEARSAL_PREDICTION_ROW_COUNT
        or manifest.get("model_ids_in_order") != list(MODEL_IDS_IN_ORDER)
        or manifest.get("prediction_ref") != refs["PREDICTIONS.csv"]
        or manifest.get("execution_receipt_ref") != refs["REHEARSAL_EXECUTION_RECEIPT.json"]
        or manifest.get("source_lock_ref") != refs["REHEARSAL_SOURCE_LOCK.json"]
        or manifest.get("execution_semantic_sha256") != execution_semantic
        or manifest.get("source_lock_semantic_sha256") != source_semantic
        or manifest.get("output_root_identity") != integer_root_identity
        or manifest.get("candidate_tuning_allowed") is not False
        or manifest.get("formal_seed_reservation_count") != 0
        or manifest.get("truth_open_count") != 0
        or manifest.get("score_open_count") != 0
        or manifest.get("heldout_content_open_count") != 0
    ):
        raise RehearsalAuditError("R3 rehearsal manifest binding differs")
    if (
        execution.get("status") != "PASS_50_PROTECTED_PUBLIC_AND_100_NUMERIC_COLD_WORKERS"
        or execution.get("task_count") != REHEARSAL_TASK_COUNT
        or execution.get("protected_process_count") != REHEARSAL_TASK_COUNT
        or execution.get("public_process_count") != REHEARSAL_TASK_COUNT
        or execution.get("bce_process_count") != REHEARSAL_TASK_COUNT
        or execution.get("c4_process_count") != REHEARSAL_TASK_COUNT
        or execution.get("all_child_processes_reaped") is not True
        or execution.get("truth_open_count") != 0
        or execution.get("score_open_count") != 0
        or execution.get("reserved_generator_invocation_count") != 0
    ):
        raise RehearsalAuditError("R3 execution evidence differs")

    try:
        prediction = pd.read_csv(io.BytesIO(raws["PREDICTIONS.csv"]), float_precision="round_trip")
    except (UnicodeDecodeError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        raise RehearsalAuditError("R3 prediction CSV differs") from exc
    if (
        tuple(map(str, prediction.columns)) != PREDICTION_COLUMNS
        or len(prediction) != REHEARSAL_PREDICTION_ROW_COUNT
        or prediction["pe_model_id"].eq(C1_ID).any()
    ):
        raise RehearsalAuditError("R3 prediction geometry differs")

    expected_tasks: list[pd.DataFrame] = []
    for ordinal, task in enumerate(rehearsal_tasks()):
        bce_root = work / "bce" / task.seed_alias / f"dgp_{task.dgp_id}"
        c4_root = work / "c4" / task.seed_alias / f"dgp_{task.dgp_id}"
        bce, bce_ref = independent_audit._surface(  # noqa: SLF001
            PROJECT_ROOT,
            bce_root / "BCE_SURFACE.csv",
            BCE_TASK_SURFACE_COLUMNS,
            label="R3 BCE",
        )
        c4, c4_ref = independent_audit._surface(  # noqa: SLF001
            PROJECT_ROOT,
            c4_root / "C4_SURFACE.csv",
            HOFS_TASK_SURFACE_COLUMNS,
            label="R3 C4",
        )
        bce_receipt_raw, _ = _read(
            bce_root / "BCE_RECEIPT.json",
            relative=(bce_root / "BCE_RECEIPT.json").relative_to(PROJECT_ROOT).as_posix(),
        )
        c4_receipt_raw, _ = _read(
            c4_root / "C4_RECEIPT.json",
            relative=(c4_root / "C4_RECEIPT.json").relative_to(PROJECT_ROOT).as_posix(),
        )
        bce_receipt = _json(bce_receipt_raw, label="R3 BCE receipt")
        c4_receipt = _json(c4_receipt_raw, label="R3 C4 receipt")
        slot = ordinal % 16
        independent_audit._validate_numeric_worker_runtime(  # noqa: SLF001
            bce_receipt.get("worker_runtime"), lane="bce", worker_slot=slot
        )
        independent_audit._validate_numeric_worker_runtime(  # noqa: SLF001
            c4_receipt.get("worker_runtime"), lane="c4", worker_slot=slot
        )
        if (
            bce_receipt.get("task") != task.payload()
            or bce_receipt.get("c1_formula_invocation_count") != 0
            or bce_receipt.get("c1_prediction_row_count") != 0
            or bce_receipt.get("surface_ref") != bce_ref
            or c4_receipt.get("task") != task.payload()
            or c4_receipt.get("surface_ref") != c4_ref
        ):
            raise RehearsalAuditError("R3 numeric receipt/task binding differs")
        expected_tasks.append(
            independent_audit._expected_task(bce, c4, task=task)  # noqa: SLF001
        )
    recomputed = pd.concat(expected_tasks, ignore_index=True)
    recomputed_raw = canonical_csv_bytes(recomputed)
    if recomputed_raw != raws["PREDICTIONS.csv"]:
        raise RehearsalAuditError("R3 independent formula bytes differ")
    identities = recomputed.loc[recomputed["model_ordinal"].eq(0), list(IDENTITY_COLUMNS)]
    common_semantic = independent_audit._common_identity_semantic(  # noqa: SLF001
        recomputed
    )
    if (
        len(identities) != REHEARSAL_IDENTITY_COUNT
        or identities.duplicated().any()
        or manifest.get("common_identity_semantic_sha256") != common_semantic
    ):
        raise RehearsalAuditError("R3 common identity universe differs")
    checks = {
        "nonreserved_seed_plan_exact": True,
        "production_task_geometry_exact": True,
        "prediction_recomputed_exact": True,
        "model_order_exact": True,
        "c1_absent": True,
        "prefix_fileids_and_hashes_exact": True,
        "numeric_surface_fileids_and_hashes_exact": True,
        "bce_nine_variable_environment_exact": True,
        "c4_seven_variable_environment_exact": True,
        "source_lock_exact": True,
        "public_only_auditor_inputs": True,
    }
    core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r3_rehearsal.independent_audit.v1",
        "status": "GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH",
        "verdict": "GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH",
        "run_id": args.run_id,
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "findings": [],
        "checks": checks,
        "prediction_ref": refs["PREDICTIONS.csv"],
        "manifest_ref": refs["REHEARSAL_MANIFEST.json"],
        "execution_receipt_ref": refs["REHEARSAL_EXECUTION_RECEIPT.json"],
        "source_lock_ref": refs["REHEARSAL_SOURCE_LOCK.json"],
        "manifest_semantic_sha256": manifest_semantic,
        "execution_semantic_sha256": execution_semantic,
        "source_lock_semantic_sha256": source_semantic,
        "prediction_recomputed_raw_sha256": hashlib.sha256(recomputed_raw).hexdigest(),
        "common_identity_semantic_sha256": common_semantic,
        "output_root_identity": integer_root_identity,
        "task_count": REHEARSAL_TASK_COUNT,
        "identity_count": REHEARSAL_IDENTITY_COUNT,
        "prediction_row_count": REHEARSAL_PREDICTION_ROW_COUNT,
        "model_ids_in_order": list(MODEL_IDS_IN_ORDER),
        "independent_formula_recomputation": True,
        "prediction_producer_imported": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    audit = {**core, "audit_semantic_sha256": semantic_sha256(core)}
    if producer in sys.modules:
        raise RehearsalAuditError("R3 auditor imported prediction producer late")
    sys.stdout.buffer.write(canonical_pretty_bytes(audit))
    sys.stdout.buffer.flush()
    return 0


def _plumbing(args: argparse.Namespace) -> int:
    from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
        exact_root,
    )
    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.canonical import (
        canonical_pretty_bytes,
        semantic_sha256,
    )

    for supplied in (args.activation_root, args.prediction_root):
        if any(token in supplied.casefold() for token in ("vault", "truth", "latent", "heldout")):
            raise RehearsalAuditError("detached evaluator received a blocked path")
    activation_root, activation_identity = exact_root(
        Path(args.activation_root), expected_files=("ACTIVATION.json",)
    )
    prediction_root, prediction_identity = exact_root(
        Path(args.prediction_root), expected_files=_SEALED_NAMES
    )
    activation_raw, activation_ref = _read(
        activation_root / "ACTIVATION.json",
        relative=(activation_root / "ACTIVATION.json").relative_to(PROJECT_ROOT).as_posix(),
    )
    seal_raw, seal_ref = _read(
        prediction_root / "REHEARSAL_SEAL.json",
        relative=(prediction_root / "REHEARSAL_SEAL.json").relative_to(PROJECT_ROOT).as_posix(),
    )
    activation = _json(activation_raw, label="R3 rehearsal activation")
    seal = _json(seal_raw, label="R3 rehearsal seal")
    activation_semantic = _self_seal(
        activation, "activation_semantic_sha256", label="R3 activation"
    )
    seal_semantic = _self_seal(seal, "seal_semantic_sha256", label="R3 seal")
    expected_prediction_identity = {
        "volume_serial_number": int(prediction_identity["volume_serial_number"], 16),
        "file_id_128": prediction_identity["file_id_128"],
    }
    if (
        activation.get("schema_version") != "expected_pe.four_model.r3_rehearsal.activation.v1"
        or activation.get("status") != "PASS_REHEARSAL_ACTIVATION_PRETRUTH"
        or activation.get("run_id") != args.run_id
        or activation.get("prediction_root_identity") != expected_prediction_identity
        or activation.get("seal_ref") != seal_ref
        or activation.get("seal_semantic_sha256") != seal_semantic
        or activation.get("truth_open_count") != 0
        or activation.get("score_open_count") != 0
        or activation.get("heldout_content_open_count") != 0
        or seal.get("authorization_commit_published_last") is not True
        or seal.get("status") != "SEALED_GO_FULL_NONRESERVED_REHEARSAL_PRETRUTH"
    ):
        raise RehearsalAuditError("detached evaluator activation chain differs")
    core: dict[str, object] = {
        "schema_version": "expected_pe.four_model.r3_rehearsal.detached_plumbing.v1",
        "status": "PASS_DETACHED_EVALUATOR_PLUMBING_SIMULATION",
        "run_id": args.run_id,
        "activation_ref": activation_ref,
        "activation_semantic_sha256": activation_semantic,
        "activation_root_identity": {
            "volume_serial_number": int(activation_identity["volume_serial_number"], 16),
            "file_id_128": activation_identity["file_id_128"],
        },
        "prediction_root_identity": expected_prediction_identity,
        "seal_ref": seal_ref,
        "seal_semantic_sha256": seal_semantic,
        "activation_reopened_by_path": True,
        "seal_reopened_by_path": True,
        "fileid_validation": True,
        "truth_path_received": False,
        "latent_path_received": False,
        "protected_path_received": False,
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_content_open_count": 0,
    }
    receipt = {**core, "plumbing_semantic_sha256": semantic_sha256(core)}
    sys.stdout.buffer.write(canonical_pretty_bytes(receipt))
    sys.stdout.buffer.flush()
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit")
    audit.add_argument("--prediction-root", required=True)
    audit.add_argument("--numeric-work-root", required=True)
    audit.add_argument("--run-id", required=True)
    plumbing = commands.add_parser("plumbing")
    plumbing.add_argument("--activation-root", required=True)
    plumbing.add_argument("--prediction-root", required=True)
    plumbing.add_argument("--run-id", required=True)
    return result


def main() -> int:
    _bootstrap()
    args = parser().parse_args()
    if args.command == "audit":
        return _audit(args)
    if args.command == "plumbing":
        return _plumbing(args)
    raise RehearsalAuditError("R3 auditor command differs")


if __name__ == "__main__":
    raise SystemExit(main())
