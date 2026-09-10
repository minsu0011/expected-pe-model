"""One-shot held-custody freezer for the R8-r8 static no-authority bundle.

The source lock is one of the nineteen members of the atomically published tree.
The mutable script directory is never written.  All governed source bytes and the
outer bootstrap remain held against write/delete replacement until the final tree
has been reopened by FileId and rehashed.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCRIPT_ROOT = Path(__file__).resolve().parent
OUTPUT_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)
STAGING_NAME = f".{OUTPUT_ROOT.name}.stg"
EXPECTED_PYCACHE_PREFIX = PROJECT_ROOT / "build" / (
    "pc_r8r8_static_freeze_actual_once_20260822"
)
PINNED_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_BASE_PYTHON = Path(
    r"C:\Users\minsu\anaconda3\envs\myenv\python.exe"
)
EXACT_ARGUMENT = "--freeze-r8-r8-static-source-no-authority-no-generation-no-fresh"
EXACT_FLAGS = (
    "-I",
    "-S",
    "-B",
    "-E",
    "-X",
    f"pycache_prefix={EXPECTED_PYCACHE_PREFIX}",
)
SCRIPT_EXACT_UNIVERSE = (
    "build_static_evidence.py",
    "freeze_static_evidence.py",
    "trusted_bootstrap.py",
)


class StaticFreezeError(RuntimeError):
    """Raised before any result may be treated as a valid static freeze."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _python_environment_names() -> tuple[str, ...]:
    return tuple(
        sorted(
            (name for name in os.environ if name.upper().startswith("PYTHON")),
            key=lambda item: (item.casefold(), item),
        )
    )


def _require_exact_script_universe() -> None:
    with os.scandir(SCRIPT_ROOT) as stream:
        children = sorted(stream, key=lambda item: item.name.casefold())
    actual: list[str] = []
    for child in children:
        path = Path(child.path)
        metadata = os.lstat(path)
        if _is_reparse(path) or not stat.S_ISREG(metadata.st_mode):
            raise StaticFreezeError("script root contains a non-plain-file entry")
        actual.append(child.name)
    if tuple(actual) != SCRIPT_EXACT_UNIVERSE:
        raise StaticFreezeError("three-file freezer script universe drifted")


def _require_exact_launch() -> Mapping[str, object]:
    entry = str(Path(__file__).resolve())
    expected_orig_argv = (
        str(PINNED_BASE_PYTHON),
        *EXACT_FLAGS,
        entry,
        EXACT_ARGUMENT,
    )
    python_environment_names = _python_environment_names()
    if sys.argv != [entry, EXACT_ARGUMENT]:
        raise StaticFreezeError("exact one-shot static freeze argument required")
    if (
        tuple(sys.orig_argv) != expected_orig_argv
        or sys.executable != str(PINNED_PYTHON)
        or sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.ignore_environment != 1
        or sys.flags.dont_write_bytecode != 1
        or getattr(sys.flags, "safe_path", None) not in {None, 1}
        or sys.pycache_prefix != str(EXPECTED_PYCACHE_PREFIX)
        or python_environment_names
    ):
        raise StaticFreezeError("exact full command or isolated interpreter state drifted")
    _require_exact_script_universe()
    return {
        "status": "PASS_EXACT_FULL_COMMAND_AND_PYTHON_ENVIRONMENT_COUNT_ZERO",
        "orig_argv": list(expected_orig_argv),
        "orig_argv_exact_full_equality": True,
        "venv_executable": str(PINNED_PYTHON),
        "base_executable_orig_argv_zero": str(PINNED_BASE_PYTHON),
        "environment_entry_count_inspected": len(os.environ),
        "python_environment_control_names": [],
        "python_environment_control_count": 0,
    }


def _source_rows(source_lock_raw: bytes) -> tuple[tuple[str, str, int], ...]:
    try:
        payload = json.loads(source_lock_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StaticFreezeError("in-memory SOURCE_LOCK is not valid JSON") from exc
    values = payload.get("source_sha256")
    if type(values) is not list:
        raise StaticFreezeError("SOURCE_LOCK source rows are absent")
    rows: list[tuple[str, str, int]] = []
    seen: set[str] = set()
    for value in values:
        if (
            type(value) is not list
            or len(value) != 3
            or type(value[0]) is not str
            or type(value[1]) is not str
            or type(value[2]) is not int
            or value[0] in seen
        ):
            raise StaticFreezeError("SOURCE_LOCK source row is malformed or duplicated")
        relative, digest, size = value
        path = PROJECT_ROOT / relative
        if (
            path.resolve(strict=True).is_relative_to(PROJECT_ROOT.resolve(strict=True))
            is not True
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or size < 0
        ):
            raise StaticFreezeError("SOURCE_LOCK source row escaped or is invalid")
        seen.add(relative)
        rows.append((relative, digest, size))
    if rows != sorted(rows):
        raise StaticFreezeError("SOURCE_LOCK source rows are not in canonical order")
    return tuple(rows)


def _receipt_key(receipt: Mapping[str, Any]) -> tuple[int, str, str, int]:
    return (
        int(receipt["volume_serial_number"]),
        str(receipt["file_id_128"]),
        str(receipt["raw_sha256"]),
        int(receipt["size_bytes"]),
    )


def _inventory_key(rows: tuple[Mapping[str, Any], ...]) -> dict[str, tuple[object, ...]]:
    result: dict[str, tuple[object, ...]] = {}
    for row in rows:
        observed = row.get("observed_name")
        if type(observed) is not str or observed.casefold() in result:
            raise StaticFreezeError("outputs inventory contains an invalid/aliased name")
        result[observed.casefold()] = (
            observed,
            row.get("kind"),
            row.get("reparse"),
            row.get("volume_serial_number"),
            row.get("file_id_128"),
        )
    return result


def _publish_held_bundle(
    *,
    outputs: Any,
    bundle: Mapping[str, bytes],
) -> Mapping[str, object]:
    before_final = outputs.observe_direct_child(OUTPUT_ROOT.name)
    before_staging = outputs.observe_direct_child(STAGING_NAME)
    if before_final["exists"] or before_staging["exists"]:
        raise StaticFreezeError("one-shot final or staging identity is already spent")
    root_inventory_before = _inventory_key(
        outputs.observe_direct_children_force_inclusive()
    )
    staging, create_receipt = outputs.create_held_direct_child_directory(STAGING_NAME)
    artifacts: dict[str, Any] = {}
    artifact_stack = ExitStack()
    try:
        for name in sorted(bundle):
            if Path(name).name != name or not name:
                raise StaticFreezeError("bundle member is not one direct child")
            artifact = staging.create_new_direct_child_artifact(name, bundle[name])
            artifacts[name] = artifact
            artifact_stack.callback(artifact.close)
        write_receipts = {name: dict(artifacts[name].receipt()) for name in sorted(artifacts)}
        observed_staging = staging.observe_direct_children_force_inclusive(
            protected_child_names=frozenset(bundle)
        )
        if tuple(sorted(str(row["observed_name"]) for row in observed_staging)) != tuple(
            sorted(bundle)
        ):
            raise StaticFreezeError("held staging tree universe drifted")
        for name, raw in bundle.items():
            receipt = write_receipts[name]
            if receipt["raw_sha256"] != _sha256(raw) or receipt["size_bytes"] != len(raw):
                raise StaticFreezeError("held staging artifact hash or size drifted")

        pre_rename = {
            name: dict(artifacts[name].prepare_for_parent_rename())
            for name in sorted(artifacts)
        }
        rename_receipt = dict(
            outputs.rename_held_direct_child_no_replace(staging, OUTPUT_ROOT.name)
        )
        reopened = {
            name: dict(artifacts[name].reopen_after_parent_rename())
            for name in sorted(artifacts)
        }
        final_receipts = {name: dict(artifacts[name].receipt()) for name in sorted(artifacts)}
        observed_final = staging.observe_direct_children_force_inclusive(
            protected_child_names=frozenset(bundle)
        )
        if tuple(sorted(str(row["observed_name"]) for row in observed_final)) != tuple(
            sorted(bundle)
        ):
            raise StaticFreezeError("final held tree universe drifted")
        for name, raw in bundle.items():
            keys = {
                _receipt_key(write_receipts[name]),
                _receipt_key(pre_rename[name]["final_writer_receipt"]),
                _receipt_key(reopened[name]),
                _receipt_key(final_receipts[name]),
            }
            if len(keys) != 1 or next(iter(keys))[2:] != (_sha256(raw), len(raw)):
                raise StaticFreezeError("artifact FileId/hash continuity drifted")

        if outputs.observe_direct_child(STAGING_NAME)["exists"]:
            raise StaticFreezeError("staging name survived handle-based publication")
        final_observation = outputs.reopen_held_direct_child(staging, OUTPUT_ROOT.name)
        root_inventory_after = _inventory_key(
            outputs.observe_direct_children_force_inclusive(
                protected_child_names=frozenset({OUTPUT_ROOT.name})
            )
        )
        before_names = set(root_inventory_before)
        after_names = set(root_inventory_after)
        final_key = OUTPUT_ROOT.name.casefold()
        if (
            after_names - before_names != {final_key}
            or before_names - after_names
            or any(root_inventory_before[name] != root_inventory_after[name] for name in before_names)
            or root_inventory_after[final_key][1] != "directory"
            or root_inventory_after[final_key][2] is not False
            or root_inventory_after[final_key][3] != final_observation["volume_serial_number"]
            or root_inventory_after[final_key][4] != final_observation["file_id_128"]
        ):
            raise StaticFreezeError("outputs inventory changed beyond one exact final tree")

        artifact_records = [
            [
                name,
                final_receipts[name]["volume_serial_number"],
                final_receipts[name]["file_id_128"],
                final_receipts[name]["raw_sha256"],
                final_receipts[name]["size_bytes"],
            ]
            for name in sorted(final_receipts)
        ]
        return {
            "status": "PASS_HELD_19_FILE_ATOMIC_NO_REPLACE_PUBLICATION",
            "final_root": str(OUTPUT_ROOT),
            "file_count": len(bundle),
            "checksums_raw_sha256": _sha256(bundle["CHECKSUMS.sha256"]),
            "artifact_records": artifact_records,
            "artifact_records_semantic_sha256": _sha256(_canonical(artifact_records)),
            "staging_create_volume_serial_number": create_receipt["held_child_receipt"][
                "volume_serial_number"
            ],
            "staging_create_file_id_128": create_receipt["held_child_receipt"][
                "file_id_128"
            ],
            "rename_volume_serial_number": rename_receipt["volume_serial_number"],
            "rename_file_id_128": rename_receipt["file_id_128"],
            "final_volume_serial_number": final_observation["volume_serial_number"],
            "final_file_id_128": final_observation["file_id_128"],
            "handle_based_no_replace_rename": True,
            "final_relative_reopen_all_members": True,
            "unexpected_outputs_namespace_delta_count": 0,
        }
    finally:
        cleanup_failure: BaseException | None = None
        try:
            artifact_stack.close()
        except BaseException as exc:
            cleanup_failure = exc
        try:
            staging.close()
        except BaseException as exc:
            cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None:
            raise StaticFreezeError(
                "published artifact or staging custody cleanup was incomplete"
            ) from cleanup_failure


def main() -> int:
    launch_preflight = _require_exact_launch()
    sys.path[:0] = [str(PROJECT_ROOT), str(PROJECT_ROOT / "src")]
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (
        SupervisorArchiveCustody,
        SupervisorDirectoryCustody,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.no_bytecode import (
        HeldExistingNoBytecodeWindow,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (
        OUTER_BOOTSTRAP_RELATIVE,
        R7_SOURCE_LOCK_RELATIVE,
        build_source_lock_bytes,
        build_static_bundle_bytes,
        verify_static_bundle_bytes,
    )

    with HeldExistingNoBytecodeWindow(
        path=EXPECTED_PYCACHE_PREFIX,
        ancestry_root=Path(EXPECTED_PYCACHE_PREFIX.anchor),
    ) as no_bytecode_window:
        provisional_source_lock = build_source_lock_bytes()
        rows = _source_rows(provisional_source_lock)
        expected_by_relative = {
            relative: (digest, size) for relative, digest, size in rows
        }
        held_relatives = tuple(
            sorted({*expected_by_relative, OUTER_BOOTSTRAP_RELATIVE, R7_SOURCE_LOCK_RELATIVE})
        )
        with ExitStack() as source_stack:
            source_custodies = {
                relative: source_stack.enter_context(
                    SupervisorArchiveCustody(
                        path=PROJECT_ROOT / relative,
                        root=Path((PROJECT_ROOT / relative).anchor),
                    )
                )
                for relative in held_relatives
            }
            held_source_records: list[list[object]] = []
            for relative in held_relatives:
                custody = source_custodies[relative]
                raw = custody.raw_bytes()
                receipt = custody.receipt()
                if relative in expected_by_relative and expected_by_relative[relative] != (
                    _sha256(raw),
                    len(raw),
                ):
                    raise StaticFreezeError("held source differs from provisional SOURCE_LOCK")
                held_source_records.append(
                    [
                        relative,
                        receipt["volume_serial_number"],
                        receipt["file_id_128"],
                        _sha256(raw),
                        len(raw),
                    ]
                )

            source_lock_raw = build_source_lock_bytes()
            if source_lock_raw != provisional_source_lock:
                raise StaticFreezeError("SOURCE_LOCK changed after source custody opened")
            bundle = build_static_bundle_bytes(source_lock_raw)
            verification = verify_static_bundle_bytes(bundle)
            if len(bundle) != 19 or "SOURCE_LOCK.json" not in bundle:
                raise StaticFreezeError("static bundle is not the exact 19-file design")

            with SupervisorDirectoryCustody(
                path=OUTPUT_ROOT.parent,
                ancestry_root=Path(OUTPUT_ROOT.anchor),
                rename_capable=False,
            ) as outputs:
                outputs_before = dict(outputs.receipt())
                publication = _publish_held_bundle(outputs=outputs, bundle=bundle)
                outputs_after = dict(outputs.receipt())
                if (
                    outputs_before["volume_serial_number"]
                    != outputs_after["volume_serial_number"]
                    or outputs_before["file_id_128"] != outputs_after["file_id_128"]
                ):
                    raise StaticFreezeError("held outputs parent identity changed")

            for relative in held_relatives:
                custody = source_custodies[relative]
                before = held_source_records[held_relatives.index(relative)]
                after_receipt = custody.receipt()
                after_raw = custody.raw_bytes()
                if (
                    after_receipt["volume_serial_number"] != before[1]
                    or after_receipt["file_id_128"] != before[2]
                    or _sha256(after_raw) != before[3]
                    or len(after_raw) != before[4]
                ):
                    raise StaticFreezeError("held source changed across final publication")

            receipt = {
                "schema_version": "expected_pe.r8.r8.static_one_shot_freeze_receipt.v2",
                "status": "FROZEN_NO_GO_PENDING_DIFFERENT_INDEPENDENT_POST_FREEZE_AUDIT",
                "launch_preflight": launch_preflight,
                "source_lock_raw_sha256": _sha256(source_lock_raw),
                "source_lock_size_bytes": len(source_lock_raw),
                "held_source_record_count": len(held_source_records),
                "held_source_records_semantic_sha256": _sha256(
                    _canonical(held_source_records)
                ),
                "bundle_verification": verification,
                "publication": publication,
                "no_bytecode_custody": no_bytecode_window.receipt(),
                "production_execution_authorized": False,
                "authority_generation_fresh_truth_signer_counts": {
                    "authority": 0,
                    "generation": 0,
                    "fresh": 0,
                    "truth": 0,
                    "signer": 0,
                },
            }
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
