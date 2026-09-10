"""Deterministically freeze EXECUTION.pyz without live launch or authority."""

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

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.archive_entry import (  # noqa: E402, E501
    IMPORT_CLOSURE_FLAG,
    IMPORT_CLOSURE_FINAL_REPLAY_FLAG,
    RESOURCE_SMOKE_CHILD_FLAG,
    RESOURCE_SMOKE_FINAL_REPLAY_FLAG,
    RESOURCE_SMOKE_STAGING_FLAG,
    VERIFY_FLAG,
    verify_archive_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.contracts import (  # noqa: E402, E501
    ARCHITECTURE_LOCK_RAW_SHA256,
    ARCHITECTURE_LOCK_RELATIVE,
    AUDITOR_ARCHIVE_RELATIVE,
    BINDING_LOCK_RELATIVE,
    EXECUTION_ARCHIVE_RELATIVE,
    EXECUTION_BINDING_LOCK_KEYS,
    EXECUTION_FREEZE_ROOT_RELATIVE,
    STATIC_A3_CHECKSUMS_RAW_SHA256,
    STATIC_A3_CLOSURE_SCHEMA_RAW_SHA256,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.generation_closure import (  # noqa: E402, E501
    VENDORED_SOURCE_RECORD_COUNT,
    capture_generation_external_input_closure,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.import_closure import (  # noqa: E402, E501
    validate_import_closure_receipt,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.source_identity import (  # noqa: E402, E501
    SourceRecord,
    build_source_identity,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.supervision import (  # noqa: E402, E501
    LAUNCH_PYCACHE_PREFIX,
    PINNED_PYTHON,
    PINNED_PYTHON_RAW_SHA256,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (  # noqa: E402, E501
    SupervisorArchiveCustody,
    SupervisorArtifactCustody,
    SupervisorDirectoryCustody,
)


PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_execution_v1"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_execution_v1"
)
TEST_RELATIVE = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_execution_v1.py"
)
STATIC_PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_static_design_v1"
)
FREEZE_ROOT = PROJECT_ROOT.joinpath(*EXECUTION_FREEZE_ROOT_RELATIVE.split("/"))
STAGING = OUTPUTS_ROOT / f".{FREEZE_ROOT.name}.staging"
FAILURE = OUTPUTS_ROOT / f".{FREEZE_ROOT.name}.fail"
FAILURE_STAGING = OUTPUTS_ROOT / f".{FREEZE_ROOT.name}.fstg"
FREEZE_FLAG = "--freeze-r8-r7-phase2-execution-source-no-live"
FREEZE_BLOCKERS = (
    "QUALIFICATION_POLICY_V2_STILL_PINS_SUPERSEDED_ARCHITECTURE_V2",
    "V3_NO_FRESH_NATIVE_RESOURCE_IMPORT_AND_ROLE_DISPATCH_SMOKE_NOT_YET_PASS",
    "LIVE_ROLE_DISPATCH_AND_BOUNDED_CHOREOGRAPHY_INCOMPLETE",
    "ACTUAL_100_INVOCATION_RESOURCE_AND_REPLAY_AGGREGATE_INCOMPLETE",
)
PINNED_RUFF = Path(r"C:\Users\minsu\anaconda3\Scripts\ruff.exe")
PINNED_RUFF_RAW_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)

PACKAGE_FILES = (
    "__init__.py",
    "archive_entry.py",
    "authority.py",
    "backend.py",
    "binding.py",
    "canonical.py",
    "contracts.py",
    "fixed_inputs.py",
    "generation.py",
    "generation_closure.py",
    "import_closure.py",
    "orchestrator.py",
    "phase2_comparator_child.py",
    "pipe_protocol.py",
    "pipe_runtime.py",
    "post_audit.py",
    "publication.py",
    "readiness.py",
    "resource_smoke.py",
    "signing.py",
    "source_identity.py",
    "supervision.py",
    "telemetry.py",
    "vendor_model_zoo_init.py",
    "vendor_research_init.py",
    "vendor_static_package_init.py",
    "win32_runtime.py",
)
LOCAL_SOURCE_RELATIVES = tuple(
    f"{PACKAGE_RELATIVE}/{name}" for name in PACKAGE_FILES
) + (
    f"{SCRIPT_RELATIVE}/archive_main.py",
    f"{SCRIPT_RELATIVE}/freeze_execution.py",
    TEST_RELATIVE,
    f"{STATIC_PACKAGE_RELATIVE}/canonical.py",
    f"{STATIC_PACKAGE_RELATIVE}/filesystem_identity.py",
)


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


def _source_member(relative: str) -> str:
    prefix = f"{PACKAGE_RELATIVE}/"
    if relative.startswith(prefix):
        name = relative[len(prefix) :]
        aliases = {
            "vendor_research_init.py": "research/__init__.py",
            "vendor_model_zoo_init.py": "research/model_zoo/__init__.py",
            "vendor_static_package_init.py": (
                f"{STATIC_PACKAGE_RELATIVE}/__init__.py"
            ),
        }
        return aliases.get(name, f"phase2_execution/{name}")
    if relative == f"{SCRIPT_RELATIVE}/archive_main.py":
        return "__main__.py"
    if relative in {
        f"{STATIC_PACKAGE_RELATIVE}/canonical.py",
        f"{STATIC_PACKAGE_RELATIVE}/filesystem_identity.py",
    }:
        return relative
    return f"FROZEN_SOURCE/{relative}"


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
        raise RuntimeError(f"source is not one regular file: {absolute}")
    raw = absolute.read_bytes()
    if len(raw) != metadata.st_size:
        raise RuntimeError(f"source changed while reading: {absolute}")
    return raw


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100444 << 16
    info.flag_bits = 0
    return info


def _command_lock() -> bytes:
    return canonical(
        {
            "schema_version": "expected_pe.r8.r7.phase2_execution.command_lock.v1",
            "status": "FROZEN_NO_LAUNCH_EXTERNAL_BINDING_REQUIRED",
            "pinned_python": PINNED_PYTHON,
            "pinned_python_raw_sha256": PINNED_PYTHON_RAW_SHA256,
            "fixed_pycache_prefix": LAUNCH_PYCACHE_PREFIX,
            "verify_argv_suffix": [VERIFY_FLAG],
            "import_closure_argv_suffix": [IMPORT_CLOSURE_FLAG],
            "import_closure_final_replay_argv_suffix": [
                IMPORT_CLOSURE_FINAL_REPLAY_FLAG
            ],
            "resource_smoke_staging_argv_suffix": [
                RESOURCE_SMOKE_STAGING_FLAG
            ],
            "resource_smoke_final_replay_argv_suffix": [
                RESOURCE_SMOKE_FINAL_REPLAY_FLAG
            ],
            "resource_smoke_child_argv_suffix": [RESOURCE_SMOKE_CHILD_FLAG],
            "supervisor_argv_suffix": [
                "--supervisor-execute-bound-qualification"
            ],
            "child_role_argv_suffixes": {
                "SIGNER": ["--signer-child-bound-memory-only"],
                "ISSUANCE_AUTHORITY": [
                    "--issuance-authority-bound-qualification"
                ],
                "COMMON_GENERATION_CONTROLLER": ["--common-controller-bound"],
                "COMMON_GENERATION_WORKER": [
                    "--common-worker-bound",
                    "{fixed_ordinal_0_to_99}",
                ],
            },
            "caller_supplied_root_count": 0,
            "caller_supplied_command_count": 0,
            "caller_supplied_key_count": 0,
            "private_key_disk_write_allowed": False,
            "actual_createprocess_call_count_at_freeze": 0,
            "actual_signer_launch_count_at_freeze": 0,
            "actual_authority_issuance_count_at_freeze": 0,
            "actual_generation_count_at_freeze": 0,
            "actual_fresh_or_heldout_access_count_at_freeze": 0,
            "actual_process_launch_count": 0,
        }
    )


def _architecture_binding() -> bytes:
    return canonical(
        {
            "schema_version": (
                "expected_pe.r8.r7.phase2.execution.architecture_binding.v1"
            ),
            "status": "FROZEN_SOURCE_NO_LIVE_AUTHORITY",
            "architecture_lock_raw_sha256": ARCHITECTURE_LOCK_RAW_SHA256,
            "static_a3_checksums_raw_sha256": STATIC_A3_CHECKSUMS_RAW_SHA256,
            "static_a3_closure_schema_raw_sha256": (
                STATIC_A3_CLOSURE_SCHEMA_RAW_SHA256
            ),
            "execution_archive_relative": EXECUTION_ARCHIVE_RELATIVE,
            "auditor_archive_relative": AUDITOR_ARCHIVE_RELATIVE,
            "external_binding_lock_relative": BINDING_LOCK_RELATIVE,
            "external_binding_lock_schema": (
                "expected_pe.r8.r7.phase2.execution_binding_lock.v1"
            ),
            "external_binding_lock_exact_keys": sorted(
                EXECUTION_BINDING_LOCK_KEYS
            ),
            "counterpart_final_hash_embedded": False,
            "freeze_before_binding_lock": True,
            "launch_before_external_binding_go": False,
        }
    )


def _collect_source_bytes(
    *, stack: ExitStack, generation_closure: Mapping[str, Any]
) -> tuple[dict[str, bytes], dict[str, str]]:
    source_bytes: dict[str, bytes] = {}
    source_members: dict[str, str] = {}
    for relative in LOCAL_SOURCE_RELATIVES:
        held = stack.enter_context(
            SupervisorArchiveCustody(
                path=PROJECT_ROOT.joinpath(*relative.split("/")), root=PROJECT_ROOT
            )
        )
        source_bytes[relative] = held.raw_bytes()
        source_members[relative] = _source_member(relative)
    for record in generation_closure["vendored_sources"]["records"]:
        relative = record["source_relative"]
        if relative in source_bytes:
            raise RuntimeError("vendored/local execution source collision")
        held = stack.enter_context(
            SupervisorArchiveCustody(
                path=PROJECT_ROOT.joinpath(*relative.split("/")), root=PROJECT_ROOT
            )
        )
        raw = held.raw_bytes()
        receipt = held.receipt()
        if (
            receipt["raw_sha256"] != record["raw_sha256"]
            or receipt["size_bytes"] != record["size_bytes"]
        ):
            raise RuntimeError("held vendored generation source drifted")
        source_bytes[relative] = raw
        source_members[relative] = record["archive_member"]
    if len(generation_closure["vendored_sources"]["records"]) != VENDORED_SOURCE_RECORD_COUNT:
        raise RuntimeError("vendored generation source count drifted")
    return source_bytes, source_members


def _build_archive(
    *,
    source_bytes: Mapping[str, bytes],
    source_members: Mapping[str, str],
    generated: Mapping[str, bytes],
) -> tuple[bytes, bytes, Mapping[str, Any]]:
    records = [
        SourceRecord(
            source_relative=relative,
            archive_member=source_members[relative],
            raw_sha256=sha(raw),
            size_bytes=len(raw),
        )
        for relative, raw in source_bytes.items()
    ] + [
        SourceRecord(
            source_relative=f"GENERATED/{member}",
            archive_member=member,
            raw_sha256=sha(raw),
            size_bytes=len(raw),
        )
        for member, raw in generated.items()
    ]
    identity = build_source_identity(records)
    identity_raw = canonical(identity)
    members = {
        source_members[relative]: raw for relative, raw in source_bytes.items()
    }
    members.update(generated)
    members["SOURCE_IDENTITY.json"] = identity_raw
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for member, raw in sorted(members.items()):
            archive.writestr(_zip_info(member), raw)
    archive_raw = buffer.getvalue()
    verify_archive_bytes(archive_raw)
    return archive_raw, identity_raw, identity


def _quality(
    *, source_bytes: Mapping[str, bytes], source_members: Mapping[str, str]
) -> Mapping[str, Any]:
    for relative, raw in source_bytes.items():
        if relative.endswith(".py"):
            compile(raw, relative, "exec", dont_inherit=True)
    selected = [
        relative
        for relative in LOCAL_SOURCE_RELATIVES
        if relative.endswith(".py")
    ]
    with tempfile.TemporaryDirectory(prefix="r8r7_phase2_execution_quality_") as text:
        mirror = Path(text) / "mirror"
        mirror.mkdir()
        for relative, raw in source_bytes.items():
            target = mirror.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper()
            in {
                "APPDATA",
                "COMSPEC",
                "LOCALAPPDATA",
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "TEMP",
                "TMP",
                "WINDIR",
            }
        }
        environment.update(
            {
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                "PYTEST_ADDOPTS": "",
                "PYTHONHASHSEED": "0",
            }
        )
        config = mirror / "pytest.ini"
        config.write_bytes(b"[pytest]\naddopts =\n")
        bootstrap = (
            "import pathlib,sys;root=pathlib.Path(sys.argv[1]);"
            "sys.path.insert(0,str(root));import pytest;"
            "raise SystemExit(pytest.main(sys.argv[2:]))"
        )
        pytest_argv = [
            PINNED_PYTHON,
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

        def run(argv: list[str]) -> Mapping[str, Any]:
            result = subprocess.run(
                argv,
                cwd=mirror,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=240,
            )
            return {
                "argv": argv,
                "returncode": result.returncode,
                "stdout_sha256": sha(result.stdout),
                "stderr_sha256": sha(result.stderr),
                "stdout_tail": result.stdout.decode("utf-8", "replace")[-4000:],
                "stderr_tail": result.stderr.decode("utf-8", "replace")[-4000:],
            }

        collected = run([*pytest_argv, "--collect-only", "-q"])
        executed = run(pytest_argv)
        ruff = run(
            [
                str(PINNED_RUFF),
                "check",
                "--no-cache",
                *[
                    str(mirror.joinpath(*relative.split("/")))
                    for relative in selected
                ],
            ]
        )
        if any(item["returncode"] != 0 for item in (collected, executed, ruff)):
            raise RuntimeError("isolated execution source quality failed")
        return {
            "schema_version": "expected_pe.r8.r7.phase2_execution.quality.v1",
            "status": "PASS_ISOLATED_SYNTHETIC_NO_LIVE",
            "compile_source_count": sum(
                relative.endswith(".py") for relative in source_bytes
            ),
            "archive_member_count": len(set(source_members.values())),
            "pytest_collection": collected,
            "pytest_execution": executed,
            "ruff": ruff,
            "plugin_autoload_disabled": True,
            "cacheprovider_disabled": True,
            "actual_phase2_createprocess_count": 0,
            "actual_signer_key_generation_count": 0,
            "actual_generation_count": 0,
            "fresh_truth_heldout_access_count": 0,
        }


class _StagingPublication:
    def __init__(self) -> None:
        self.outputs = SupervisorDirectoryCustody(
            path=OUTPUTS_ROOT, ancestry_root=PROJECT_ROOT
        )
        self.before = {
            row["observed_name"]: dict(row)
            for row in self.outputs.observe_direct_children_force_inclusive()
        }
        folded = {name.casefold() for name in self.before}
        planned = (FREEZE_ROOT.name, STAGING.name, FAILURE.name, FAILURE_STAGING.name)
        if any(name.casefold() in folded for name in planned):
            self.outputs.close()
            raise RuntimeError("execution freeze identity is already consumed")
        self.child, _ = self.outputs.create_held_direct_child_directory(STAGING.name)
        self.artifacts: list[SupervisorArtifactCustody] = []

    def add(self, name: str, raw: bytes) -> Mapping[str, Any]:
        if any(item.name.casefold() == name.casefold() for item in self.artifacts):
            raise RuntimeError("duplicate execution freeze artifact")
        artifact = self.child.create_new_direct_child_artifact(name, raw)
        self.artifacts.append(artifact)
        receipt = dict(artifact.receipt())
        if receipt["raw_sha256"] != sha(raw):
            raise RuntimeError("staged execution artifact drifted")
        return receipt

    def finish(self) -> Mapping[str, Any]:
        for artifact in self.artifacts:
            artifact.prepare_for_parent_rename()
        rename = self.outputs.rename_held_direct_child_no_replace(
            self.child, FREEZE_ROOT.name
        )
        for artifact in self.artifacts:
            artifact.reopen_after_parent_rename()
            artifact.receipt()
        return {
            "status": "PASS_HELD_PARENT_ATOMIC_NO_REPLACE_SOURCE_FREEZE",
            "volume_serial_number": rename["volume_serial_number"],
            "file_id_128": rename["file_id_128"],
            "artifact_count": len(self.artifacts),
        }

    def close(self) -> None:
        failures: list[BaseException] = []
        for held in (*reversed(self.artifacts), self.child, self.outputs):
            try:
                held.close()
            except BaseException as exc:
                failures.append(exc)
        if failures:
            raise RuntimeError("execution freeze custody close failed") from failures[0]


def _preflight() -> None:
    if not OUTPUTS_ROOT.is_dir():
        raise RuntimeError("outputs root is unavailable")
    for path in (FREEZE_ROOT, STAGING, FAILURE, FAILURE_STAGING):
        if path.exists():
            raise RuntimeError(f"execution freeze identity consumed: {path.name}")
    architecture = PROJECT_ROOT.joinpath(*ARCHITECTURE_LOCK_RELATIVE.split("/"))
    if sha(_plain_source(architecture)) != ARCHITECTURE_LOCK_RAW_SHA256:
        raise RuntimeError("Phase2 architecture lock drifted")
    if sha(_plain_source(Path(PINNED_PYTHON))) != PINNED_PYTHON_RAW_SHA256:
        raise RuntimeError("pinned Python drifted")
    if sha(_plain_source(PINNED_RUFF)) != PINNED_RUFF_RAW_SHA256:
        raise RuntimeError("pinned Ruff drifted")
    names = (
        "EXECUTION.pyz",
        "SOURCE_IDENTITY.json",
        "COMMAND_LOCK.json",
        "ARCHITECTURE_BINDING.json",
        "ARCHITECTURE_LOCK.json",
        "GENERATION_EXTERNAL_INPUT_CLOSURE.json",
        "IMPORT_CLOSURE_RECEIPT.json",
        "QUALITY_RECEIPT.json",
        "MANIFEST.json",
        "SOURCE_LOCK.json",
        "SELF_CHECK.json",
        "REPORT.md",
        "CHECKSUMS.sha256",
    )
    if max(len(str(root / name)) for root in (FREEZE_ROOT, STAGING) for name in names) > 240:
        raise RuntimeError("execution freeze path exceeds 240 characters")


def main() -> int:
    if sys.argv != [sys.argv[0], FREEZE_FLAG]:
        return 64
    if FREEZE_BLOCKERS:
        raise RuntimeError(
            "execution source freeze is blocked: " + ";".join(FREEZE_BLOCKERS)
        )
    _preflight()
    source_window = ExitStack()
    publication: _StagingPublication | None = None
    try:
        python_custody = source_window.enter_context(
            SupervisorArchiveCustody(
                path=Path(PINNED_PYTHON), root=Path(Path(PINNED_PYTHON).anchor)
            )
        )
        ruff_custody = source_window.enter_context(
            SupervisorArchiveCustody(
                path=PINNED_RUFF, root=Path(PINNED_RUFF.anchor)
            )
        )
        if (
            python_custody.receipt()["raw_sha256"] != PINNED_PYTHON_RAW_SHA256
            or ruff_custody.receipt()["raw_sha256"] != PINNED_RUFF_RAW_SHA256
        ):
            raise RuntimeError("held source-freeze tool drifted")
        generation_closure = capture_generation_external_input_closure(
            stack=source_window
        )
        generation_closure_raw = canonical(generation_closure)
        source_bytes, source_members = _collect_source_bytes(
            stack=source_window, generation_closure=generation_closure
        )
        architecture_raw = source_window.enter_context(
            SupervisorArchiveCustody(
                path=PROJECT_ROOT.joinpath(*ARCHITECTURE_LOCK_RELATIVE.split("/")),
                root=PROJECT_ROOT,
            )
        ).raw_bytes()
        command_raw = _command_lock()
        architecture_binding_raw = _architecture_binding()
        archive_raw, source_identity_raw, source_identity = _build_archive(
            source_bytes=source_bytes,
            source_members=source_members,
            generated={
                "ARCHITECTURE_BINDING.json": architecture_binding_raw,
                "ARCHITECTURE_LOCK.json": architecture_raw,
                "COMMAND_LOCK.json": command_raw,
            },
        )
        quality = _quality(source_bytes=source_bytes, source_members=source_members)
        quality_raw = canonical(quality)
        publication = _StagingPublication()
        initial = {
            "ARCHITECTURE_BINDING.json": architecture_binding_raw,
            "ARCHITECTURE_LOCK.json": architecture_raw,
            "COMMAND_LOCK.json": command_raw,
            "EXECUTION.pyz": archive_raw,
            "GENERATION_EXTERNAL_INPUT_CLOSURE.json": generation_closure_raw,
            "QUALITY_RECEIPT.json": quality_raw,
            "SOURCE_IDENTITY.json": source_identity_raw,
        }
        for name, raw in sorted(initial.items()):
            publication.add(name, raw)
        smoke = subprocess.run(
            [
                PINNED_PYTHON,
                "-I",
                "-B",
                str(STAGING / "EXECUTION.pyz"),
                IMPORT_CLOSURE_FLAG,
            ],
            cwd=PROJECT_ROOT,
            env={
                "COMSPEC": os.environ["COMSPEC"],
                "PATH": os.environ["PATH"],
                "SYSTEMROOT": os.environ["SYSTEMROOT"],
                "WINDIR": os.environ["WINDIR"],
                "PYTHONHASHSEED": "0",
                "PYTHONNOUSERSITE": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=240,
        )
        if smoke.returncode != 0 or not smoke.stdout.endswith(b"\n"):
            raise RuntimeError(
                "frozen candidate import smoke failed: "
                + smoke.stderr.decode("utf-8", "replace")[-2000:]
            )
        try:
            import_receipt = validate_import_closure_receipt(
                json.loads(smoke.stdout)
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("candidate import smoke output is invalid") from exc
        import_raw = canonical(import_receipt)
        if import_raw + b"\n" != smoke.stdout:
            raise RuntimeError("candidate import smoke output is noncanonical")
        import_file_receipt = publication.add(
            "IMPORT_CLOSURE_RECEIPT.json", import_raw
        )
        source_lock_raw = canonical(
            {
                "schema_version": "expected_pe.r8.r7.phase2_execution.source_lock.v1",
                "status": "EXACT_SOURCE_BYTES_FROZEN",
                "record_count": source_identity["record_count"],
                "records": source_identity["records"],
                "records_semantic_sha256": source_identity[
                    "records_semantic_sha256"
                ],
            }
        )
        manifest_raw = canonical(
            {
                "schema_version": "expected_pe.r8.r7.phase2_execution.manifest.v1",
                "status": "FROZEN_NO_LAUNCH_EXTERNAL_BINDING_REQUIRED",
                "archive_raw_sha256": sha(archive_raw),
                "source_identity_raw_sha256": sha(source_identity_raw),
                "source_records_semantic_sha256": source_identity[
                    "records_semantic_sha256"
                ],
                "generation_external_input_closure_raw_sha256": sha(
                    generation_closure_raw
                ),
                "generation_import_closure_receipt_raw_sha256": sha(import_raw),
                "generation_import_closure_receipt_semantic_sha256": (
                    import_receipt["semantic_sha256"]
                ),
                "generation_import_closure_receipt_volume_serial_number": (
                    import_file_receipt["volume_serial_number"]
                ),
                "generation_import_closure_receipt_file_id_128": (
                    import_file_receipt["file_id_128"]
                ),
                "generation_import_closure_receipt_size_bytes": (
                    import_file_receipt["size_bytes"]
                ),
                "mutable_workspace_import_count": 0,
                "actual_phase2_createprocess_count": 0,
                "actual_signer_key_generation_count": 0,
                "actual_authority_issuance_count": 0,
                "actual_generation_count": 0,
                "fresh_truth_heldout_access_count": 0,
                "production_activation_authorized": False,
                "required_external_binding_lock": BINDING_LOCK_RELATIVE,
            }
        )
        self_check_raw = canonical(
            {
                "schema_version": "expected_pe.r8.r7.phase2_execution.self_check.v1",
                "status": "PASS_SOURCE_FREEZE_AND_SPENT_IMPORT_ONLY",
                "archive_verification": verify_archive_bytes(archive_raw),
                "import_closure_semantic_sha256": import_receipt[
                    "semantic_sha256"
                ],
                "actual_phase2_createprocess_count": 0,
                "actual_signer_key_generation_count": 0,
                "actual_generation_count": 0,
                "self_go": False,
            }
        )
        report_raw = (
            "# R8-r7 Phase-2 EXECUTION.pyz source freeze\n\n"
            "Frozen source plus a no-generation spent import receipt only. No signer "
            "key, authority, generation, fresh, heldout, or live Phase-2 process was "
            "created. The independent third binding lock remains mandatory.\n"
        ).encode("utf-8")
        later = {
            "MANIFEST.json": manifest_raw,
            "REPORT.md": report_raw,
            "SELF_CHECK.json": self_check_raw,
            "SOURCE_LOCK.json": source_lock_raw,
        }
        for name, raw in sorted(later.items()):
            publication.add(name, raw)
        ledger_inputs = {**initial, "IMPORT_CLOSURE_RECEIPT.json": import_raw, **later}
        ledger_raw = "".join(
            f"{sha(raw)}  {name}\n" for name, raw in sorted(ledger_inputs.items())
        ).encode("ascii")
        publication.add("CHECKSUMS.sha256", ledger_raw)
        publication_receipt = publication.finish()
        print(
            canonical(
                {
                    "status": "FROZEN_NO_LAUNCH_EXTERNAL_BINDING_REQUIRED",
                    "root": EXECUTION_FREEZE_ROOT_RELATIVE,
                    "archive_raw_sha256": sha(archive_raw),
                    "source_identity_raw_sha256": sha(source_identity_raw),
                    "source_records_semantic_sha256": source_identity[
                        "records_semantic_sha256"
                    ],
                    "generation_external_input_closure_raw_sha256": sha(
                        generation_closure_raw
                    ),
                    "generation_import_closure_receipt_raw_sha256": sha(
                        import_raw
                    ),
                    "generation_import_closure_receipt_semantic_sha256": (
                        import_receipt["semantic_sha256"]
                    ),
                    "checksums_raw_sha256": sha(ledger_raw),
                    "publication_receipt": publication_receipt,
                }
            ).decode("utf-8")
        )
        return 0
    finally:
        primary = sys.exc_info()[1]
        cleanup_failure: BaseException | None = None
        if publication is not None:
            try:
                publication.close()
            except BaseException as exc:
                cleanup_failure = exc
        try:
            source_window.close()
        except BaseException as exc:
            cleanup_failure = cleanup_failure or exc
        if cleanup_failure is not None and primary is None:
            raise cleanup_failure


if __name__ == "__main__":
    raise SystemExit(main())
