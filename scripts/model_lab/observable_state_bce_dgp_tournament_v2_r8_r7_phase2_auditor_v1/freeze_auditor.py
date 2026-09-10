"""Deterministically freeze the separate R8-r7 Phase-2 AUDITOR.pyz source.

This builder has no signer, key, authority, live binding, process launch, or
fresh/heldout capability.  Its output remains NO_GO until a separately frozen
EXECUTION.pyz and an independently audited third-party binding lock exist.
"""

from __future__ import annotations

from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (  # noqa: E402, E501
    SupervisorArchiveCustody,
    SupervisorArtifactCustody,
    SupervisorDirectoryCustody,
)
PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_auditor_v1"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_auditor_v1"
)
TEST_RELATIVE = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_auditor_v1.py"
)
STATIC_FS_PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_static_design_v1"
)
VENDOR_STATIC_INIT_RELATIVE = f"{PACKAGE_RELATIVE}/vendor_static_package_init.py"
VENDOR_RESEARCH_INIT_RELATIVE = f"{PACKAGE_RELATIVE}/vendor_research_init.py"
VENDOR_MODEL_ZOO_INIT_RELATIVE = f"{PACKAGE_RELATIVE}/vendor_model_zoo_init.py"
STATIC_CANONICAL_RELATIVE = f"{STATIC_FS_PACKAGE_RELATIVE}/canonical.py"
STATIC_FILESYSTEM_RELATIVE = f"{STATIC_FS_PACKAGE_RELATIVE}/filesystem_identity.py"
FREEZE_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "phase2_auditor_source_freeze_v1_no_go_20260822"
)
FREEZE_ROOT = PROJECT_ROOT.joinpath(*FREEZE_ROOT_RELATIVE.split("/"))
STAGING = OUTPUTS_ROOT / f".{FREEZE_ROOT.name}.staging"
FAILURE = OUTPUTS_ROOT / f".{FREEZE_ROOT.name}.fail"
FAILURE_STAGING = OUTPUTS_ROOT / f".{FREEZE_ROOT.name}.fstg"
FREEZE_FLAG = "--freeze-r8-r7-phase2-auditor-source-no-launch-no-fresh"
PINNED_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_PYTHON_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
PINNED_RUFF = Path(r"C:\Users\minsu\anaconda3\Scripts\ruff.exe")
PINNED_RUFF_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)
ARCHITECTURE_LOCK = (
    PROJECT_ROOT
    / "research/model_zoo/portfolio_governance_v1/"
    "PHASE2_R8_R7_EXECUTION_ARCHITECTURE_LOCK_V2.json"
)
ARCHITECTURE_LOCK_SHA256 = (
    "62fa37b06e1a5df1588e36bdba40dcf6b2dcc95513272ecad5245868d7ca13c7"
)
STATIC_ROOT = OUTPUTS_ROOT / (
    "model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "static_design_source_freeze_v1_a3_no_go_20260822"
)
STATIC_CHECKSUMS_SHA256 = (
    "bfde56de2a99d41835ceb5751024648025c980c1113a712bc8012cfe04a34bf2"
)
STATIC_CLOSURE_SHA256 = (
    "b369ad3960db2276b917872bb032b919c92b68a6713fec6ab05fc1b961b77766"
)
AUDITOR_ARCHIVE_RELATIVE = f"{FREEZE_ROOT_RELATIVE}/AUDITOR.pyz"
BINDING_LOCK_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "phase2_execution_binding_lock_v1_no_go_20260822/EXECUTION_BINDING_LOCK.json"
)
LIVE_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "phase2_bound_execution_v1_20260822"
)
READINESS_RELATIVE = f"{LIVE_ROOT_RELATIVE}/READINESS.json"
JOB_WITNESS_RELATIVE = f"{LIVE_ROOT_RELATIVE}/AUDITOR_JOB_WITNESS.json"
AUDITOR_RELEASE_ACK_RELATIVE = f"{LIVE_ROOT_RELATIVE}/AUDITOR_RELEASE_ACK.json"
SUPPLEMENTAL_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "phase2_live_supplemental_audit_v1_20260822"
)
LIVE_PYCACHE_PREFIX = Path(
    r"C:\Users\minsu\Documents\EPS\build\pc_r8r7_phase2_actual_once_20260822\auditor"
)
LIVE_FLAG = "--live-supplemental-audit-bound-r8-r7-phase2"
VERIFY_FLAG = "--verify-frozen-r8-r7-phase2-auditor-no-live-input"

PACKAGE_FILES = (
    "__init__.py",
    "anchors.py",
    "archive_entry.py",
    "archive_identity.py",
    "canonical.py",
    "command_lock.py",
    "constants.py",
    "contracts.py",
    "ed25519.py",
    "endpoint.py",
    "filesystem_identity.py",
    "generation_closure.py",
    "publication.py",
    "readiness.py",
    "runtime.py",
    "source_identity.py",
    "win32_live.py",
)
RUNTIME_RELATIVES = tuple(f"{PACKAGE_RELATIVE}/{name}" for name in PACKAGE_FILES) + (
    f"{SCRIPT_RELATIVE}/archive_main.py",
    VENDOR_STATIC_INIT_RELATIVE,
    VENDOR_RESEARCH_INIT_RELATIVE,
    VENDOR_MODEL_ZOO_INIT_RELATIVE,
    STATIC_CANONICAL_RELATIVE,
    STATIC_FILESYSTEM_RELATIVE,
)
EXECUTION_QUALITY_SUPPORT_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_execution_v1"
)
QUALITY_SUPPORT_RELATIVES = tuple(
    f"{EXECUTION_QUALITY_SUPPORT_RELATIVE}/{name}"
    for name in (
        "__init__.py",
        "backend.py",
        "binding.py",
        "canonical.py",
        "contracts.py",
        "generation_closure.py",
        "import_closure.py",
        "readiness.py",
        "signing.py",
        "supervision.py",
        "telemetry.py",
    )
)
SOURCE_RELATIVES = RUNTIME_RELATIVES + (
    f"{SCRIPT_RELATIVE}/freeze_auditor.py",
    TEST_RELATIVE,
) + QUALITY_SUPPORT_RELATIVES


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _plain_source(path: Path) -> bytes:
    absolute = Path(os.path.abspath(path))
    chain = [absolute]
    while chain[-1].parent != chain[-1]:
        chain.append(chain[-1].parent)
    for component in reversed(chain):
        metadata = os.lstat(component)
        if stat.S_ISLNK(metadata.st_mode) or int(
            getattr(metadata, "st_file_attributes", 0)
        ) & 0x400:
            raise RuntimeError(f"reparse source component rejected: {component}")
    metadata = os.stat(absolute)
    if not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"source is not a regular file: {path}")
    raw = absolute.read_bytes()
    if len(raw) != metadata.st_size:
        raise RuntimeError(f"source size changed while reading: {path}")
    return raw


def _source_member(relative: str) -> str:
    if relative == f"{SCRIPT_RELATIVE}/archive_main.py":
        return "__main__.py"
    if relative == VENDOR_STATIC_INIT_RELATIVE:
        return f"{STATIC_FS_PACKAGE_RELATIVE}/__init__.py"
    if relative == VENDOR_RESEARCH_INIT_RELATIVE:
        return "research/__init__.py"
    if relative == VENDOR_MODEL_ZOO_INIT_RELATIVE:
        return "research/model_zoo/__init__.py"
    if relative in RUNTIME_RELATIVES:
        return relative
    return f"FROZEN_SOURCE/{relative}"


def collect_sources() -> tuple[dict[str, bytes], dict[str, Any]]:
    raw_by_relative = {
        relative: _plain_source(PROJECT_ROOT.joinpath(*relative.split("/")))
        for relative in SOURCE_RELATIVES
    }
    records = [
        {
            "source_relative": relative,
            "archive_member": _source_member(relative),
            "raw_sha256": sha(raw),
            "size_bytes": len(raw),
        }
        for relative, raw in sorted(raw_by_relative.items())
    ]
    members = [row["archive_member"] for row in records]
    if len(records) != len(set(members)):
        raise RuntimeError("archive source member collision")
    identity = {
        "schema_version": "expected_pe.r8.r7.phase2_auditor.source_identity.v1",
        "record_count": len(records),
        "records": records,
        "records_semantic_sha256": sha(canonical(records)),
    }
    return raw_by_relative, identity


def _collect_held_sources(
    stack: ExitStack,
) -> tuple[
    dict[str, bytes],
    dict[str, Any],
    dict[str, SupervisorArchiveCustody],
    SupervisorArchiveCustody,
    SupervisorArchiveCustody,
]:
    """Hold every source and tool without write/delete sharing across quality."""

    python_custody = stack.enter_context(
        SupervisorArchiveCustody(path=PINNED_PYTHON, root=Path(PINNED_PYTHON.anchor))
    )
    ruff_custody = stack.enter_context(
        SupervisorArchiveCustody(path=PINNED_RUFF, root=Path(PINNED_RUFF.anchor))
    )
    if sha(python_custody.raw_bytes()) != PINNED_PYTHON_SHA256:
        raise RuntimeError("pinned Python raw hash drifted under custody")
    if sha(ruff_custody.raw_bytes()) != PINNED_RUFF_SHA256:
        raise RuntimeError("pinned Ruff raw hash drifted under custody")
    held = {
        relative: stack.enter_context(
            SupervisorArchiveCustody(
                path=PROJECT_ROOT.joinpath(*relative.split("/")),
                root=PROJECT_ROOT,
            )
        )
        for relative in SOURCE_RELATIVES
    }
    raw_by_relative = {
        relative: custody.raw_bytes() for relative, custody in held.items()
    }
    records = [
        {
            "source_relative": relative,
            "archive_member": _source_member(relative),
            "raw_sha256": sha(raw),
            "size_bytes": len(raw),
        }
        for relative, raw in sorted(raw_by_relative.items())
    ]
    members = [row["archive_member"] for row in records]
    if len(records) != len(set(members)):
        raise RuntimeError("archive source member collision")
    identity = {
        "schema_version": "expected_pe.r8.r7.phase2_auditor.source_identity.v1",
        "record_count": len(records),
        "records": records,
        "records_semantic_sha256": sha(canonical(records)),
    }
    return raw_by_relative, identity, held, python_custody, ruff_custody


def _require_custody_stable(
    held: Mapping[str, SupervisorArchiveCustody],
    raw_by_relative: Mapping[str, bytes],
) -> None:
    for relative, custody in held.items():
        receipt = custody.receipt()
        if (
            custody.raw_bytes() != raw_by_relative[relative]
            or receipt["raw_sha256"] != sha(raw_by_relative[relative])
            or receipt["write_share_allowed"] is not False
            or receipt["delete_share_allowed"] is not False
        ):
            raise RuntimeError("held source custody changed across quality gate")


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100444 << 16
    info.flag_bits = 0
    return info


def build_archive(
    raw_by_relative: Mapping[str, bytes], source_identity_raw: bytes
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        rows = [
            (_source_member(relative), raw)
            for relative, raw in raw_by_relative.items()
        ] + [("SOURCE_IDENTITY.json", source_identity_raw)]
        for member, raw in sorted(rows):
            archive.writestr(_zip_info(member), raw)
    return buffer.getvalue()


def _file_identity(path: Path) -> tuple[int, str, int]:
    metadata = os.stat(path)
    return int(metadata.st_dev), f"{int(metadata.st_ino):032x}", int(metadata.st_size)


def build_command_lock(
    *,
    archive_raw: bytes,
    source_identity: Mapping[str, Any],
    source_identity_raw: bytes,
    python_receipt: Mapping[str, Any] | None = None,
) -> bytes:
    if python_receipt is None:
        volume, file_id, size = _file_identity(PINNED_PYTHON)
    else:
        volume = int(python_receipt["volume_serial_number"])
        file_id = str(python_receipt["file_id_128"])
        size = int(python_receipt["size_bytes"])
    archive_path = PROJECT_ROOT.joinpath(*AUDITOR_ARCHIVE_RELATIVE.split("/"))
    live_template = [
        str(PINNED_PYTHON),
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={LIVE_PYCACHE_PREFIX}",
        str(archive_path),
        LIVE_FLAG,
        "{decimal_query_handle}",
    ]
    payload = {
        "schema_version": "expected_pe.r8.r7.phase2_auditor.command_lock.v1",
        "status": "FROZEN_SOURCE_NO_EXECUTION_AUTHORITY_AWAITING_THIRD_BINDING_LOCK",
        "role": "LIVE_SUPPLEMENTAL_AUDITOR",
        "architecture_lock_raw_sha256": ARCHITECTURE_LOCK_SHA256,
        "static_a3_checksums_raw_sha256": STATIC_CHECKSUMS_SHA256,
        "static_a3_closure_schema_raw_sha256": STATIC_CLOSURE_SHA256,
        "auditor_archive_relative": AUDITOR_ARCHIVE_RELATIVE,
        "auditor_archive_raw_sha256": sha(archive_raw),
        "source_identity_raw_sha256": sha(source_identity_raw),
        "source_records_semantic_sha256": source_identity[
            "records_semantic_sha256"
        ],
        "python_executable": str(PINNED_PYTHON),
        "python_executable_raw_sha256": PINNED_PYTHON_SHA256,
        "python_executable_volume_serial_number": volume,
        "python_executable_file_id_128": file_id,
        "python_executable_size_bytes": size,
        "execution_binding_lock_relative": BINDING_LOCK_RELATIVE,
        "live_root_relative": LIVE_ROOT_RELATIVE,
        "readiness_relative": READINESS_RELATIVE,
        "job_witness_relative": JOB_WITNESS_RELATIVE,
        "auditor_release_ack_relative": AUDITOR_RELEASE_ACK_RELATIVE,
        "supplemental_root_relative": SUPPLEMENTAL_ROOT_RELATIVE,
        "live_argv_template": live_template,
        "verify_argv": [
            str(PINNED_PYTHON),
            "-I",
            "-B",
            str(archive_path),
            VERIFY_FLAG,
        ],
        "mutable_workspace_import_count": 0,
        "inherited_query_handle_count": 1,
        "caller_selected_roots_allowed": False,
        "caller_selected_keys_allowed": False,
        "caller_selected_commands_allowed": False,
        "self_go_allowed": False,
        "actual_process_launch_count": 0,
        "required_next_gate": "POST_FREEZE_TWO_ARCHIVE_BINDING_AND_PRELAUNCH_AUDIT",
    }
    return canonical(payload)


def _sanitized_environment() -> dict[str, str]:
    permitted = {
        "ALLUSERSPROFILE",
        "APPDATA",
        "COMMONPROGRAMFILES",
        "COMMONPROGRAMFILES(X86)",
        "COMMONPROGRAMW6432",
        "COMPUTERNAME",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LOCALAPPDATA",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PATH",
        "PATHEXT",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "PUBLIC",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERDOMAIN",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in permitted}
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTEST_ADDOPTS"] = ""
    environment["PYTHONHASHSEED"] = "0"
    return environment


def _run(command: list[str], *, cwd: Path, environment: Mapping[str, str]) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=180,
    )
    return {
        "argv": command,
        "returncode": completed.returncode,
        "stdout_sha256": sha(completed.stdout),
        "stderr_sha256": sha(completed.stderr),
        "stdout_tail": completed.stdout.decode("utf-8", "replace")[-4000:],
        "stderr_tail": completed.stderr.decode("utf-8", "replace")[-4000:],
    }


def quality(raw_by_relative: Mapping[str, bytes]) -> dict[str, Any]:
    if sha(PINNED_PYTHON.read_bytes()) != PINNED_PYTHON_SHA256:
        raise RuntimeError("pinned Python raw hash drifted")
    if sha(PINNED_RUFF.read_bytes()) != PINNED_RUFF_SHA256:
        raise RuntimeError("pinned Ruff raw hash drifted")
    for relative, raw in raw_by_relative.items():
        if relative.endswith(".py"):
            compile(raw, relative, "exec", dont_inherit=True)
    with tempfile.TemporaryDirectory(prefix="r8r7_phase2_auditor_quality_") as temp:
        mirror = Path(temp) / "mirror"
        mirror.mkdir()
        for relative, raw in raw_by_relative.items():
            target = mirror.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        config = mirror / "pytest.ini"
        config.write_bytes(b"[pytest]\naddopts =\n")
        environment = _sanitized_environment()
        bootstrap = (
            "import pathlib,sys;"
            "root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root));"
            "import pytest;raise SystemExit(pytest.main(sys.argv[2:]))"
        )
        pytest_base = [
            str(PINNED_PYTHON),
            "-I",
            "-B",
            "-c",
            bootstrap,
            str(mirror),
            "-c",
            str(config),
            "-p",
            "no:cacheprovider",
            "--noconftest",
            "--confcutdir",
            str(mirror),
            str(mirror.joinpath(*TEST_RELATIVE.split("/"))),
        ]
        collected = _run(
            [*pytest_base, "--collect-only", "-q"],
            cwd=mirror,
            environment=environment,
        )
        executed = _run(pytest_base, cwd=mirror, environment=environment)
        ruff_targets = [
            str(mirror.joinpath(*relative.split("/")))
            for relative in SOURCE_RELATIVES
            if relative.endswith(".py")
        ]
        ruff = _run(
            [str(PINNED_RUFF), "check", "--no-cache", *ruff_targets],
            cwd=mirror,
            environment=environment,
        )
        if any(result["returncode"] != 0 for result in (collected, executed, ruff)):
            raise RuntimeError("isolated quality gate failed")
        return {
            "schema_version": "expected_pe.r8.r7.phase2_auditor.quality.v1",
            "status": "PASS_ISOLATED_SYNTHETIC_NO_LIVE",
            "compile_source_count": len(raw_by_relative),
            "pytest_collection": collected,
            "pytest_execution": executed,
            "ruff": ruff,
            "plugin_autoload_disabled": True,
            "cacheprovider_disabled": True,
            "mutable_workspace_import_count": 0,
            "live_process_launch_count": 0,
            "fresh_truth_heldout_access_count": 0,
        }


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _preflight() -> None:
    if not OUTPUTS_ROOT.is_dir():
        raise RuntimeError("outputs root is unavailable")
    for path in (FREEZE_ROOT, STAGING, FAILURE, FAILURE_STAGING):
        if path.exists():
            raise RuntimeError(f"frozen output identity is already consumed: {path.name}")
    if sha(_plain_source(ARCHITECTURE_LOCK)) != ARCHITECTURE_LOCK_SHA256:
        raise RuntimeError("architecture lock drifted")
    if sha(_plain_source(STATIC_ROOT / "CHECKSUMS.sha256")) != STATIC_CHECKSUMS_SHA256:
        raise RuntimeError("static a3 checksum anchor drifted")
    if sha(_plain_source(STATIC_ROOT / "CLOSURE_SCHEMA.json")) != STATIC_CLOSURE_SHA256:
        raise RuntimeError("static a3 closure anchor drifted")
    longest = max(
        len(str(FREEZE_ROOT / name))
        for name in (
            "AUDITOR.pyz",
            "SOURCE_IDENTITY.json",
            "COMMAND_LOCK.json",
            "QUALITY_RECEIPT.json",
            "SOURCE_LOCK.json",
            "MANIFEST.json",
            "SELF_CHECK.json",
            "REPORT.md",
            "CHECKSUMS.sha256",
        )
    )
    if longest > 240:
        raise RuntimeError("planned frozen artifact path exceeds 240 characters")


def _direct_inventory(
    parent: SupervisorDirectoryCustody,
) -> dict[str, Mapping[str, Any]]:
    rows = tuple(dict(row) for row in parent.observe_direct_children_force_inclusive())
    names = [row.get("observed_name") for row in rows]
    if (
        any(type(name) is not str or not name for name in names)
        or names != sorted(names, key=lambda value: (value.casefold(), value))
        or len({name.casefold() for name in names}) != len(names)
        or any(
            row.get("exists") is not True
            or row.get("reparse") is not False
            or row.get("reparse_tag") != 0
            or row.get("file_id_128") is None
            for row in rows
        )
    ):
        raise RuntimeError("freeze publication inventory is unsafe")
    return {str(row["observed_name"]): row for row in rows}


def _identity_projection(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return tuple(
        row.get(key)
        for key in (
            "observed_name",
            "kind",
            "reparse",
            "reparse_tag",
            "volume_serial_number",
            "file_id_128",
        )
    )


def _publish_frozen_tree(artifacts: Mapping[str, bytes]) -> Mapping[str, Any]:
    """Held-parent CREATE_NEW publication with same-parent no-replace rename."""

    complete = dict(artifacts)
    if (
        not complete
        or any(
            type(name) is not str
            or Path(name).name != name
            or type(raw) is not bytes
            for name, raw in complete.items()
        )
    ):
        raise RuntimeError("freeze artifact bundle is invalid")
    outputs: SupervisorDirectoryCustody | None = None
    child: SupervisorDirectoryCustody | None = None
    held_artifacts: list[SupervisorArtifactCustody] = []
    try:
        outputs = SupervisorDirectoryCustody(
            path=OUTPUTS_ROOT,
            ancestry_root=PROJECT_ROOT,
        )
        before = _direct_inventory(outputs)
        folded = {name.casefold() for name in before}
        planned = (FREEZE_ROOT.name, STAGING.name, FAILURE.name, FAILURE_STAGING.name)
        if any(name.casefold() in folded for name in planned):
            raise RuntimeError("freeze output identity is already consumed")
        child, _created = outputs.create_held_direct_child_directory(STAGING.name)
        for name, raw in sorted(complete.items()):
            held_artifacts.append(child.create_new_direct_child_artifact(name, raw))
        staged = _direct_inventory(child)
        receipts = {item.name: dict(item.receipt()) for item in held_artifacts}
        if set(staged) != set(complete) or any(
            staged[name]["file_id_128"] != receipt["file_id_128"]
            or staged[name]["volume_serial_number"]
            != receipt["volume_serial_number"]
            or receipt["raw_sha256"] != sha(complete[name])
            for name, receipt in receipts.items()
        ):
            raise RuntimeError("freeze staging artifact universe drifted")
        for artifact in held_artifacts:
            artifact.prepare_for_parent_rename()
        rename = outputs.rename_held_direct_child_no_replace(child, FREEZE_ROOT.name)
        for artifact in held_artifacts:
            artifact.reopen_after_parent_rename()
        after = _direct_inventory(outputs)
        if set(after) != {*before, FREEZE_ROOT.name} or any(
            _identity_projection(after[name]) != _identity_projection(row)
            for name, row in before.items()
        ):
            raise RuntimeError("freeze publication direct-child delta drifted")
        final = after[FREEZE_ROOT.name]
        if (
            final.get("kind") != "directory"
            or final.get("volume_serial_number") != rename["volume_serial_number"]
            or final.get("file_id_128") != rename["file_id_128"]
            or outputs.observe_direct_child(STAGING.name).get("exists") is not False
            or outputs.observe_direct_child(FAILURE.name).get("exists") is not False
            or outputs.observe_direct_child(FAILURE_STAGING.name).get("exists")
            is not False
        ):
            raise RuntimeError("freeze final/staging/failure identity drifted")
        for artifact in held_artifacts:
            artifact.receipt()
        return {
            "status": "PASS_HELD_PARENT_ATOMIC_NO_REPLACE_SOURCE_FREEZE",
            "volume_serial_number": rename["volume_serial_number"],
            "file_id_128": rename["file_id_128"],
            "artifact_count": len(held_artifacts),
            "staging_absent": True,
            "failure_absent": True,
            "failure_staging_absent": True,
        }
    finally:
        failures: list[BaseException] = []
        for held in (*reversed(held_artifacts), child, outputs):
            if held is None:
                continue
            try:
                held.close()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError(
                "freeze publication custody cleanup failed: "
                + "; ".join(str(item) for item in failures)
            ) from failures[0]


def main() -> int:
    if sys.argv != [sys.argv[0], FREEZE_FLAG]:
        return 64
    _preflight()
    source_window = ExitStack()
    try:
        (
            raw_by_relative,
            source_identity,
            held_sources,
            python_custody,
            ruff_custody,
        ) = _collect_held_sources(source_window)
        source_identity_raw = canonical(source_identity)
        python_receipt = dict(python_custody.receipt())
        ruff_receipt = dict(ruff_custody.receipt())
        quality_receipt = quality(raw_by_relative)
        _require_custody_stable(held_sources, raw_by_relative)
        if (
            python_custody.receipt() != python_receipt
            or ruff_custody.receipt() != ruff_receipt
        ):
            raise RuntimeError("held tool custody changed across quality gate")
        archive_raw = build_archive(raw_by_relative, source_identity_raw)
        command_raw = build_command_lock(
            archive_raw=archive_raw,
            source_identity=source_identity,
            source_identity_raw=source_identity_raw,
            python_receipt=python_receipt,
        )
    finally:
        source_window.close()
    source_lock_raw = canonical(
        {
            "schema_version": "expected_pe.r8.r7.phase2_auditor.source_lock.v1",
            "status": "EXACT_SOURCE_BYTES_FROZEN",
            "record_count": source_identity["record_count"],
            "records": source_identity["records"],
            "records_semantic_sha256": source_identity[
                "records_semantic_sha256"
            ],
        }
    )
    quality_raw = canonical(quality_receipt)
    manifest_raw = canonical(
        {
            "schema_version": "expected_pe.r8.r7.phase2_auditor.manifest.v1",
            "status": "FROZEN_NO_LAUNCH_EXTERNAL_BINDING_REQUIRED",
            "archive_role": "LIVE_SUPPLEMENTAL_AUDITOR",
            "architecture_lock_raw_sha256": ARCHITECTURE_LOCK_SHA256,
            "static_a3_checksums_raw_sha256": STATIC_CHECKSUMS_SHA256,
            "static_a3_closure_schema_raw_sha256": STATIC_CLOSURE_SHA256,
            "source_record_count": source_identity["record_count"],
            "source_records_semantic_sha256": source_identity[
                "records_semantic_sha256"
            ],
            "mutable_workspace_import_count": 0,
            "inherited_query_handle_count": 1,
            "actual_process_launch_count": 0,
            "signer_key_authority_generation_count": 0,
            "fresh_truth_heldout_access_count": 0,
            "production_activation_authorized": False,
            "required_external_binding_lock": BINDING_LOCK_RELATIVE,
        }
    )
    self_check_raw = canonical(
        {
            "schema_version": "expected_pe.r8.r7.phase2_auditor.self_check.v1",
            "status": "PASS_SOURCE_FREEZE_ONLY",
            "archive_raw_sha256": sha(archive_raw),
            "source_identity_raw_sha256": sha(source_identity_raw),
            "command_lock_raw_sha256": sha(command_raw),
            "quality_receipt_raw_sha256": sha(quality_raw),
            "actual_archive_publication_count_before_builder": 0,
            "phase2_process_launch_count": 0,
            "self_go": False,
        }
    )
    report_raw = (
        "# R8-r7 Phase-2 standalone auditor source freeze\n\n"
        "This is a deterministic AUDITOR.pyz source freeze only. It has no execution "
        "authority and was not launched. A separately frozen EXECUTION.pyz, a canonical "
        "two-archive binding lock, and independent prelaunch P0/P1/P2=0/0/0 are mandatory.\n"
    ).encode("utf-8")
    artifacts = {
        "AUDITOR.pyz": archive_raw,
        "COMMAND_LOCK.json": command_raw,
        "MANIFEST.json": manifest_raw,
        "QUALITY_RECEIPT.json": quality_raw,
        "REPORT.md": report_raw,
        "SELF_CHECK.json": self_check_raw,
        "SOURCE_IDENTITY.json": source_identity_raw,
        "SOURCE_LOCK.json": source_lock_raw,
    }
    ledger_raw = "".join(
        f"{sha(raw)}  {name}\n" for name, raw in sorted(artifacts.items())
    ).encode("ascii")
    publication_receipt = _publish_frozen_tree(
        {**artifacts, "CHECKSUMS.sha256": ledger_raw}
    )
    print(
        canonical(
            {
                "status": "FROZEN_NO_LAUNCH_EXTERNAL_BINDING_REQUIRED",
                "root": FREEZE_ROOT_RELATIVE,
                "checksums_raw_sha256": sha(ledger_raw),
                "auditor_pyz_raw_sha256": sha(archive_raw),
                "source_identity_raw_sha256": sha(source_identity_raw),
                "source_records_semantic_sha256": source_identity[
                    "records_semantic_sha256"
                ],
                "publication_receipt": publication_receipt,
            }
        ).decode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
