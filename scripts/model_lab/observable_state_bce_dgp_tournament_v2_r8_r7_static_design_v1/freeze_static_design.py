"""Freeze R8-r7 static design/source with every production capability disabled."""

from __future__ import annotations

import base64
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping
import zipfile
from xml.etree import ElementTree

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.canonical import (
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.closure import (
    CLOSURE_KEYS,
    REOPENED_HASH_FIELDS,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (
    SupervisorArchiveCustody,
    SupervisorDirectoryCustody,
    _raw_resolved_guid_path,
    _raw_resolved_path,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.preflight import (
    require_clean_r8_r7_preflight,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.publication import (
    PERMITTED_STATIC_DESIGN_CHILD_NAME,
    _bound_plan,
    _publish_bound_artifacts_no_go,
    _require_trusted_outputs_identity,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.source_identity import (
    SourceRecord,
    build_source_identity,
    parse_source_identity,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.traceability import (
    build_blocker_trace,
    validate_blocker_trace,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.win32_supervision import (
    build_win32_supervision_blueprint,
    validate_win32_supervision_blueprint,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
OUTPUTS_ROOT = PROJECT_ROOT / "outputs"
OUTPUT_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r7_static_design_source_freeze_v1_a3_no_go_20260822"
)
OUTPUT_ROOT = PROJECT_ROOT / OUTPUT_ROOT_RELATIVE
STAGING = OUTPUT_ROOT.parent / f".{OUTPUT_ROOT.name}.stg"
PACKAGE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_static_design_v1"
)
SCRIPT_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_static_design_v1"
)
TEST_RELATIVE = (
    "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_"
    "r8_r7_static_design_v1.py"
)
LAUNCHER_RELATIVE = f"{SCRIPT_RELATIVE}/a3_once.ps1"
ONE_SHOT_LAUNCHER_PREFIX = Path(
    "C:/Users/minsu/Documents/EPS/build/pc_r8r7_a3_freeze_actual_once_20260822"
)
LAUNCHER_QUOTE_FREE_BOOTSTRAP = (
    "import base64,sys;exec(base64.b64decode(sys.argv[1]))"
)
LAUNCHER_INVOCATION_SOURCE = (
    "import runpy,sys\n"
    "project=r'C:\\Users\\minsu\\Documents\\EPS\\"
    "PE_Regime_Engine_v0.4.0_Bottleneck_Overlay'\n"
    "script=r'C:\\Users\\minsu\\Documents\\EPS\\"
    "PE_Regime_Engine_v0.4.0_Bottleneck_Overlay\\scripts\\model_lab\\"
    "observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1\\"
    "freeze_static_design.py'\n"
    "sys.path.insert(0,project)\n"
    "sys.argv=[script,'--freeze-r8-r7-static-design-source-no-signer-no-phase2-"
    "no-fresh']\n"
    "runpy.run_path(script,run_name='__main__')\n"
)
LAUNCHER_INVOCATION_SOURCE_BASE64 = base64.b64encode(
    LAUNCHER_INVOCATION_SOURCE.encode("utf-8")
).decode("ascii")
GENERATION_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
GENERATION_PYTHON_EXPECTED_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
RUFF_EXECUTABLE = Path("C:/Users/minsu/anaconda3/Scripts/ruff.exe")
RUFF_EXECUTABLE_EXPECTED_SHA256 = (
    "3e6622f4ca670a20eacb5a2e9f25b9511b255f6153582252ee1838a6c29beb5f"
)
RUFF_EXPECTED_VERSION = "ruff 0.12.0"
SCOPED_TEST_CASE_COUNT = 85
QUALITY_SUBPROCESS_COUNT = 5
PYTEST_CONFIG_BYTES = b"[pytest]\naddopts =\n"
R8_R6_R2_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r6_"
    "independent_supplemental_auditor_source_freeze_v2_attempt_r2_no_go_20260822"
)
R8_R6_R2_ROOT = PROJECT_ROOT / R8_R6_R2_ROOT_RELATIVE
ATTEMPT_R1_FORENSIC_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "static_design_source_freeze_v1_attempt_r1_terminal_forensic_no_go_20260822"
)
ATTEMPT_R1_FORENSIC_ROOT = PROJECT_ROOT / ATTEMPT_R1_FORENSIC_ROOT_RELATIVE
ATTEMPT_A2_FORENSIC_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r7_"
    "static_design_source_freeze_v1_a2_terminal_forensic_no_go_20260822"
)
ATTEMPT_A2_FORENSIC_ROOT = PROJECT_ROOT / ATTEMPT_A2_FORENSIC_ROOT_RELATIVE
PREDECESSOR_HASHES = {
    "r8_r6_r2/CHECKSUMS.sha256": "ba8591c5c03b5d45fd695495c6e777743ddc8d5079447568833127df52acee96",
    "r8_r6_r2/COMMAND_LOCK.json": "730320036b9e5a8feaa451a03aa4b2dc09ee30c1b5bcbc65f4ffd65d5686a39d",
    "r8_r6_r2/SEAL.json": "51767a92f7a6c7ff719586b66a713fdbc6978465f3a8dd071a6c23d1e8c73aad",
    "r8_r6_r2/SOURCE_IDENTITY.json": "5df76df885996e2131bd5cbbee9ea26c33ccae0da190d5262a2284ccfc3edfa9",
    "r8_r6_r2/MINIMUM_R8_R7_DELTA.json": "46ebd7cd9e6bdd31e1a61fe5a9ba7bd97958f4dcdd025f5e90181d0cb18d928e",
    "r8_r6_r2/FULL_REPOSITORY_TEST_SNAPSHOT.json": (
        "d3e8f4835bcdaf6708318287a8d95325b0dc73d1d3482ef01e8053308080ddeb"
    ),
    "r8_r7_attempt_r1_forensic/CHECKSUMS.sha256": (
        "a4bd7300f93a91d87bc8dc380c1a1c5d4389ef06c78448d344205b6774d7ded2"
    ),
    "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256": (
        "35e7fd3248b04a4f99a199f0279892088bba3d210823dff6bab305833f7bd7aa"
    ),
}
RUNTIME_NAMES = (
    "__init__.py",
    "archive_entry.py",
    "artifact_contract.py",
    "canonical.py",
    "closure.py",
    "consumer_reopen.py",
    "evidence.py",
    "filesystem_identity.py",
    "preflight.py",
    "publication.py",
    "source_identity.py",
    "terminal.py",
    "traceability.py",
    "win32_supervision.py",
)
PYTEST_RECORDER_PREFIX = "R8R7_PYTEST_RECORDER="
PYTEST_ISOLATED_BOOTSTRAP = r"""
import json
import os
import sys

import pytest


class R8R7Recorder:
    def __init__(self):
        self.collected_nodeids = []
        self.deselected_nodeids = []
        self.call_outcomes = {"passed": 0, "failed": 0, "skipped": 0}
        self.conftest_plugin_count = -1
        self.autoloaded_plugin_distribution_count = -1

    def pytest_sessionstart(self, session):
        manager = session.config.pluginmanager
        self.conftest_plugin_count = len(manager._conftest_plugins)
        self.autoloaded_plugin_distribution_count = len(manager.list_plugin_distinfo())

    def pytest_collection_modifyitems(self, items):
        self.collected_nodeids = [item.nodeid.replace("\\", "/") for item in items]

    def pytest_deselected(self, items):
        self.deselected_nodeids.extend(
            item.nodeid.replace("\\", "/") for item in items
        )

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            self.call_outcomes[report.outcome] += 1


recorder = R8R7Recorder()
sys.path.insert(0, sys.argv.pop(1))
exit_status = int(pytest.main(sys.argv[1:], plugins=[recorder]))
payload = {
    "autoloaded_plugin_distribution_count": (
        recorder.autoloaded_plugin_distribution_count
    ),
    "call_outcomes": recorder.call_outcomes,
    "collected_nodeids": recorder.collected_nodeids,
    "conftest_plugin_count": recorder.conftest_plugin_count,
    "deselected_nodeids": recorder.deselected_nodeids,
    "dont_write_bytecode": sys.dont_write_bytecode,
    "isolated": sys.flags.isolated,
    "plugin_autoload": os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD"),
    "pycache_prefix": sys.pycache_prefix,
    "pytest_exit_status": exit_status,
}
print("R8R7_PYTEST_RECORDER=" + json.dumps(payload, sort_keys=True, separators=(",", ":")))
raise SystemExit(exit_status)
""".strip()


def _source_relatives() -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                *(f"{PACKAGE_RELATIVE}/{name}" for name in RUNTIME_NAMES),
                f"{SCRIPT_RELATIVE}/archive_main.py",
                f"{SCRIPT_RELATIVE}/freeze_static_design.py",
                LAUNCHER_RELATIVE,
                TEST_RELATIVE,
            }
        )
    )


def _read_custodied(path: Path) -> tuple[bytes, Mapping[str, Any]]:
    with SupervisorArchiveCustody(path=path, root=Path(path.anchor)) as custody:
        raw = custody.raw_bytes()
        receipt = custody.receipt()
    return raw, receipt


def _runtime_sources() -> tuple[list[SourceRecord], dict[str, bytes]]:
    raw_by_relative = {
        relative: _read_custodied(PROJECT_ROOT / relative)[0]
        for relative in _source_relatives()
    }
    return _runtime_sources_from_bytes(raw_by_relative)


def _runtime_sources_from_bytes(
    raw_by_relative: Mapping[str, bytes],
) -> tuple[list[SourceRecord], dict[str, bytes]]:
    records: list[SourceRecord] = []
    members: dict[str, bytes] = {}
    for name in RUNTIME_NAMES:
        relative = f"{PACKAGE_RELATIVE}/{name}"
        raw = raw_by_relative[relative]
        member = f"auditor_r8_r7/{name}"
        records.append(SourceRecord(relative, member, sha256_bytes(raw), len(raw)))
        members[member] = raw
    main_relative = f"{SCRIPT_RELATIVE}/archive_main.py"
    main_raw = raw_by_relative[main_relative]
    records.append(
        SourceRecord(main_relative, "__main__.py", sha256_bytes(main_raw), len(main_raw))
    )
    members["__main__.py"] = main_raw
    launcher_raw = raw_by_relative[LAUNCHER_RELATIVE]
    records.append(
        SourceRecord(
            LAUNCHER_RELATIVE,
            "ONE_SHOT_LAUNCHER.ps1",
            sha256_bytes(launcher_raw),
            len(launcher_raw),
        )
    )
    members["ONE_SHOT_LAUNCHER.ps1"] = launcher_raw
    return records, members


def _source_lock(runtime_records: list[SourceRecord]) -> Mapping[str, Any]:
    raw_by_relative: dict[str, bytes] = {}
    custody_by_relative: dict[str, Mapping[str, Any]] = {}
    for relative in _source_relatives():
        raw, custody = _read_custodied(PROJECT_ROOT / relative)
        raw_by_relative[relative] = raw
        custody_by_relative[relative] = custody
    return _source_lock_from_bytes(
        runtime_records=runtime_records,
        raw_by_relative=raw_by_relative,
        custody_by_relative=custody_by_relative,
    )


def _source_lock_from_bytes(
    *,
    runtime_records: list[SourceRecord],
    raw_by_relative: Mapping[str, bytes],
    custody_by_relative: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any]:
    runtime = {record.source_relative: record for record in runtime_records}
    rows: list[dict[str, Any]] = []
    for relative in _source_relatives():
        raw = raw_by_relative[relative]
        custody = custody_by_relative[relative]
        archived = runtime.get(relative)
        if archived is not None and (
            archived.raw_sha256 != sha256_bytes(raw)
            or archived.size_bytes != len(raw)
        ):
            raise RuntimeError("runtime source changed between archive and source lock")
        rows.append(
            {
                "relative_path": relative,
                "raw_sha256": sha256_bytes(raw),
                "size_bytes": len(raw),
                "runtime_archive_member": (
                    None if archived is None else archived.archive_member
                ),
                "runtime_member": archived is not None,
                "custody": custody,
            }
        )
    return {
        "schema_version": "expected_pe.r8.r7.static_design.source_lock.v1",
        "status": "FROZEN_DESIGN_ONLY_AWAITING_INDEPENDENT_AUDIT",
        "record_count": len(rows),
        "records": rows,
        "records_semantic_sha256": sha256_bytes(canonical_json_bytes(rows)),
    }


def _zipinfo(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _build_archive(
    *, source_identity_raw: bytes, members: Mapping[str, bytes]
) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        archive.writestr(_zipinfo("SOURCE_IDENTITY.json"), source_identity_raw)
        for name, raw in sorted(members.items()):
            archive.writestr(_zipinfo(name), raw)
    return buffer.getvalue()


def _verify_archive(
    *, raw: bytes, source_identity: Mapping[str, Any]
) -> Mapping[str, Any]:
    with zipfile.ZipFile(io.BytesIO(raw), "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise RuntimeError("R8-r7 archive contains duplicate members")
        identity_raw = archive.read("SOURCE_IDENTITY.json")
        identity = json.loads(identity_raw)
        if canonical_json_bytes(identity) != identity_raw:
            raise RuntimeError("R8-r7 source identity is non-canonical")
        parsed = parse_source_identity(identity)
        if parsed != source_identity:
            raise RuntimeError("R8-r7 freeze/runtime source identity diverged")
        expected = {"SOURCE_IDENTITY.json"}
        for record in parsed["records"]:
            member_raw = archive.read(record["archive_member"])
            if (
                len(member_raw) != record["size_bytes"]
                or sha256_bytes(member_raw) != record["raw_sha256"]
            ):
                raise RuntimeError("R8-r7 archive member drifted")
            expected.add(record["archive_member"])
        if set(names) != expected:
            raise RuntimeError("R8-r7 archive member universe drifted")
    return {
        "status": "PASS_DISABLED_DESIGN_VERIFIER_ARCHIVE_EXACT_REOPEN",
        "archive_raw_sha256": sha256_bytes(raw),
        "archive_size_bytes": len(raw),
        "member_count": len(names),
        "source_identity_raw_sha256": sha256_bytes(identity_raw),
        "source_records_semantic_sha256": parsed["records_semantic_sha256"],
    }


def _predecessor_chain(
    *, outputs_custody: SupervisorDirectoryCustody
) -> Mapping[str, Any]:
    if type(outputs_custody) is not SupervisorDirectoryCustody:
        raise RuntimeError("predecessor chain requires exact outputs custody")
    outputs_custody.receipt()
    paths = {
        "r8_r6_r2/CHECKSUMS.sha256": (
            R8_R6_R2_ROOT,
            R8_R6_R2_ROOT / "CHECKSUMS.sha256",
        ),
        "r8_r6_r2/COMMAND_LOCK.json": (
            R8_R6_R2_ROOT,
            R8_R6_R2_ROOT / "COMMAND_LOCK.json",
        ),
        "r8_r6_r2/SEAL.json": (
            R8_R6_R2_ROOT,
            R8_R6_R2_ROOT / "SEAL.json",
        ),
        "r8_r6_r2/SOURCE_IDENTITY.json": (
            R8_R6_R2_ROOT,
            R8_R6_R2_ROOT / "SOURCE_IDENTITY.json",
        ),
        "r8_r6_r2/MINIMUM_R8_R7_DELTA.json": (
            R8_R6_R2_ROOT,
            R8_R6_R2_ROOT / "MINIMUM_R8_R7_DELTA.json",
        ),
        "r8_r6_r2/FULL_REPOSITORY_TEST_SNAPSHOT.json": (
            R8_R6_R2_ROOT,
            R8_R6_R2_ROOT / "FULL_REPOSITORY_TEST_SNAPSHOT.json",
        ),
        "r8_r7_attempt_r1_forensic/CHECKSUMS.sha256": (
            ATTEMPT_R1_FORENSIC_ROOT,
            ATTEMPT_R1_FORENSIC_ROOT / "CHECKSUMS.sha256",
        ),
        "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256": (
            ATTEMPT_A2_FORENSIC_ROOT,
            ATTEMPT_A2_FORENSIC_ROOT / "CHECKSUMS.sha256",
        ),
    }
    rows = []
    payloads: dict[str, Any] = {}
    with ExitStack() as predecessor_window:
        held: dict[str, SupervisorArchiveCustody] = {}
        initial_receipts: dict[str, Mapping[str, Any]] = {}
        for identity, (root, path) in sorted(paths.items()):
            if root.parent != outputs_custody.path or path.parent != root:
                raise RuntimeError(f"predecessor binding escaped outputs: {identity}")
            custody = predecessor_window.enter_context(
                SupervisorArchiveCustody(
                    path=path,
                    root=root,
                    held_parent=outputs_custody,
                )
            )
            held[identity] = custody
            raw = custody.raw_bytes()
            receipt = custody.receipt()
            initial_receipts[identity] = receipt
            if sha256_bytes(raw) != PREDECESSOR_HASHES[identity]:
                raise RuntimeError(f"predecessor drifted: {identity}")
            if path.suffix == ".json":
                parsed = json.loads(raw)
                if canonical_json_bytes(parsed) != raw:
                    raise RuntimeError(
                        f"predecessor JSON is non-canonical: {identity}"
                    )
                payloads[identity] = parsed
            rows.append(
                {
                    "identity": identity,
                    "relative_path": path.relative_to(PROJECT_ROOT).as_posix(),
                    "raw_sha256": sha256_bytes(raw),
                    "size_bytes": len(raw),
                    "custody": receipt,
                }
            )
        command = payloads["r8_r6_r2/COMMAND_LOCK.json"]
        if (
            command.get("production_command") is not None
            or command.get("production_execution_allowed") is not False
            or command.get("signer_launch_allowed") is not False
            or command.get("authority_issuance_allowed") is not False
        ):
            raise RuntimeError("R8-r6 predecessor is no longer disabled")
        full_snapshot = payloads["r8_r6_r2/FULL_REPOSITORY_TEST_SNAPSHOT.json"]
        if (
            full_snapshot.get("full_repository_suite_passed") is not False
            or full_snapshot.get("snapshot_preserved_instead_of_false_pass") is not True
            or full_snapshot.get("collection", {}).get("collected_test_count") != 2017
            or len(full_snapshot.get("bounded_first_three", {}).get("failures", []))
            != 3
            or full_snapshot.get("post_r2_workspace_collection_snapshot", {}).get(
                "classification"
            )
            != "CONCURRENT_UNRELATED_WORKSPACE_TEST_NAMING_COLLISION"
        ):
            raise RuntimeError("R8-r6 full-repository nonpass snapshot drifted")
        if any(
            custody.receipt() != initial_receipts[identity]
            for identity, custody in held.items()
        ):
            raise RuntimeError("simultaneously held predecessor custody drifted")
        result = {
            "schema_version": "expected_pe.r8.r7.predecessor_chain.v1",
            "status": (
                "R8_R6_R2_AND_R8_R7_ATTEMPTS_R1_A2_NO_GO_IMMUTABLY_PINNED"
            ),
            "record_count": len(rows),
            "records": rows,
            "all_predecessor_file_custodies_held_simultaneously": True,
            "predecessor_custody_count": len(held),
            "peak_simultaneous_predecessor_file_custody_count": len(held),
            "attempt_r1_forensic_checksums_raw_sha256": PREDECESSOR_HASHES[
                "r8_r7_attempt_r1_forensic/CHECKSUMS.sha256"
            ],
            "attempt_a2_forensic_checksums_raw_sha256": PREDECESSOR_HASHES[
                "r8_r7_attempt_a2_forensic/CHECKSUMS.sha256"
            ],
            "r8_r6_production_execution_allowed": False,
            "r8_r7_attempt_r1_production_execution_allowed": False,
            "r8_r7_attempt_a2_production_execution_allowed": False,
            "r8_r7_design_only_allowed": True,
            "r8_r7_phase2_allowed": False,
            "full_repository_status": {
                "full_repository_suite_passed": False,
                "full_repository_suite_pass_claimed": False,
                "historical_collection": full_snapshot["collection"],
                "historical_bounded_first_three": full_snapshot[
                    "bounded_first_three"
                ],
                "isolated_causality_repeat": full_snapshot[
                    "isolated_causality_repeat"
                ],
                "concurrent_workspace_collection_collision": full_snapshot[
                    "post_r2_workspace_collection_snapshot"
                ],
                "separation_assertion": (
                    "SCOPED_R8_R7_GATE_IS_DISTINCT_FROM_PREEXISTING_2017_TEST_"
                    "NONPASS_AND_CONCURRENT_TCN_IMPORT_MISMATCH"
                ),
            },
        }
    return result


def _run(
    command: list[str],
    *,
    python_pycache_prefix: Path | None = None,
    cwd: Path = PROJECT_ROOT,
) -> tuple[Mapping[str, Any], bytes, bytes]:
    environment = dict(os.environ)
    removed_python = sorted(
        key for key in environment if key.upper().startswith("PYTHON")
    )
    removed_pytest = sorted(
        key for key in environment if key.upper().startswith("PYTEST")
    )
    for key in tuple(environment):
        if key.upper().startswith(("PYTHON", "PYTEST")):
            environment.pop(key)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    environment["PYTEST_ADDOPTS"] = ""
    environment["PYTEST_PLUGINS"] = ""
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONPATH"] = ""
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    pycache_before: list[str] | None = None
    if python_pycache_prefix is not None:
        prefix = python_pycache_prefix.resolve(strict=True)
        if not prefix.is_dir():
            raise RuntimeError("quality pycache prefix is not a directory")
        pycache_before = sorted(item.name for item in prefix.iterdir())
        if pycache_before:
            raise RuntimeError("quality pycache prefix was not fresh and empty")
        environment["PYTHONPYCACHEPREFIX"] = str(prefix)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        check=False,
        timeout=600,
    )
    pycache_after = (
        None
        if python_pycache_prefix is None
        else sorted(item.name for item in python_pycache_prefix.iterdir())
    )
    receipt = {
        "command": command,
        "returncode": result.returncode,
        "stdout_raw_sha256": sha256_bytes(result.stdout),
        "stderr_raw_sha256": sha256_bytes(result.stderr),
        "stdout_tail": result.stdout.decode(errors="replace")[-2000:],
        "stderr_tail": result.stderr.decode(errors="replace")[-2000:],
        "environment_contract": {
            "removed_inherited_python_environment_names": removed_python,
            "removed_inherited_pytest_environment_names": removed_pytest,
            "uncontrolled_python_environment_count_after_sanitization": 0,
            "uncontrolled_pytest_environment_count_after_sanitization": 0,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTEST_ADDOPTS": "",
            "PYTEST_PLUGINS": "",
            "PYTHONNOUSERSITE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONPATH": "",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
            "dedicated_python_pycache_prefix": python_pycache_prefix is not None,
            "pycache_entry_names_before": pycache_before,
            "pycache_entry_names_after": pycache_after,
            "pycache_empty_before_and_after": (
                python_pycache_prefix is None
                or (pycache_before == [] and pycache_after == [])
            ),
        },
    }
    return receipt, result.stdout, result.stderr


def _pytest_command_prefix(
    *,
    python_executable: str,
    pycache_prefix: Path,
    config: Path,
    isolated_source_root: Path,
) -> list[str]:
    return [
        python_executable,
        "-I",
        "-B",
        "-X",
        f"pycache_prefix={pycache_prefix.resolve(strict=True)}",
        "-c",
        PYTEST_ISOLATED_BOOTSTRAP,
        str(isolated_source_root.resolve(strict=True)),
        "-q",
        "-p",
        "no:cacheprovider",
        "--noconftest",
        "-c",
        str(config.resolve(strict=True)),
        f"--rootdir={isolated_source_root.resolve(strict=True)}",
    ]


def _materialize_held_source_mirror(
    *, root: Path, held_source_bytes: Mapping[str, bytes]
) -> Mapping[str, bytes]:
    expected = set(_source_relatives())
    if set(held_source_bytes) != expected:
        raise RuntimeError("held source mirror input universe drifted")
    mirror = dict(held_source_bytes)
    for relative in (
        "research/__init__.py",
        "research/model_zoo/__init__.py",
        "scripts/__init__.py",
        "scripts/model_lab/__init__.py",
        f"{SCRIPT_RELATIVE}/__init__.py",
        "tests/__init__.py",
        "tests/model_lab/__init__.py",
    ):
        if relative in mirror:
            raise RuntimeError("synthetic namespace marker collided with held source")
        mirror[relative] = b""
    # The production builder opens this fixed directory through held directory
    # custody.  Recreate only that empty directory in the isolated source mirror;
    # it is not part of the held source-file universe.
    (root / "outputs").mkdir(parents=False, exist_ok=False)
    for relative, raw in sorted(mirror.items()):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_new_quality_isolation(target, raw)
    return mirror


def _require_exact_custody_bytes(
    *, custody: SupervisorArchiveCustody, expected: bytes, label: str
) -> Mapping[str, Any]:
    receipt = custody.receipt()
    if (
        receipt.get("raw_sha256") != sha256_bytes(expected)
        or receipt.get("size_bytes") != len(expected)
        or custody.raw_bytes() != expected
    ):
        raise RuntimeError(f"{label} custody bytes differ from expected held bytes")
    return receipt


def _parse_collected_nodeids(stdout: bytes) -> list[str]:
    payload = _parse_pytest_recorder(stdout)
    nodeids = payload["collected_nodeids"]
    if not nodeids or len(nodeids) != len(set(nodeids)):
        raise RuntimeError("pytest collection did not emit unique exact nodeids")
    if any(not nodeid.startswith(f"{TEST_RELATIVE}::") for nodeid in nodeids):
        raise RuntimeError("pytest collection escaped the scoped test module")
    return nodeids


def _parse_pytest_recorder(stdout: bytes) -> Mapping[str, Any]:
    marker = PYTEST_RECORDER_PREFIX.encode("ascii")
    lines = [line[len(marker) :] for line in stdout.splitlines() if line.startswith(marker)]
    if len(lines) != 1:
        raise RuntimeError("pytest on-site recorder evidence is missing or duplicated")
    try:
        payload = json.loads(lines[0].decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("pytest on-site recorder evidence is malformed") from exc
    expected = {
        "autoloaded_plugin_distribution_count",
        "call_outcomes",
        "collected_nodeids",
        "conftest_plugin_count",
        "deselected_nodeids",
        "dont_write_bytecode",
        "isolated",
        "plugin_autoload",
        "pycache_prefix",
        "pytest_exit_status",
    }
    if not isinstance(payload, dict) or set(payload) != expected:
        raise RuntimeError("pytest on-site recorder schema drifted")
    return payload


def _parse_executed_nodeids(junit_raw: bytes) -> list[str]:
    try:
        root = ElementTree.fromstring(junit_raw)
    except ElementTree.ParseError as exc:
        raise RuntimeError("pytest JUnit evidence is malformed") from exc
    nodeids: list[str] = []
    for testcase in root.iter("testcase"):
        if any(testcase.find(name) is not None for name in ("failure", "error", "skipped")):
            raise RuntimeError("pytest JUnit evidence contains a non-pass testcase")
        name = testcase.get("name")
        if not name or "::" in name:
            raise RuntimeError("pytest JUnit testcase name is not top-level canonical")
        nodeids.append(f"{TEST_RELATIVE}::{name}")
    return nodeids


def _quality(
    *,
    python_custody: SupervisorArchiveCustody,
    ruff_custody: SupervisorArchiveCustody,
    python_receipt: Mapping[str, Any],
    ruff_receipt: Mapping[str, Any],
    full_repository_status: Mapping[str, Any],
    test_source_raw_sha256: str,
    held_source_bytes: Mapping[str, bytes],
) -> Mapping[str, Any]:
    if (
        type(python_custody) is not SupervisorArchiveCustody
        or type(ruff_custody) is not SupervisorArchiveCustody
    ):
        raise RuntimeError("quality tool custody concrete types drifted")
    if (
        python_custody.receipt() != python_receipt
        or ruff_custody.receipt() != ruff_receipt
    ):
        raise RuntimeError("quality tool custody changed before subprocess launch")
    python_executable = os.path.normpath(_raw_resolved_path(python_custody.handle))
    ruff_executable = os.path.normpath(_raw_resolved_path(ruff_custody.handle))
    python_volume_guid_identity_path = _raw_resolved_guid_path(
        python_custody.handle
    )
    ruff_volume_guid_identity_path = _raw_resolved_guid_path(ruff_custody.handle)
    if (
        not os.path.isabs(python_executable)
        or not os.path.isabs(ruff_executable)
        or python_executable.casefold().startswith("\\\\?\\volume{")
        or ruff_executable.casefold().startswith("\\\\?\\volume{")
    ):
        raise RuntimeError("quality tool DOS final launch path is invalid")
    quality_result: dict[str, Any]
    with tempfile.TemporaryDirectory(prefix="r8r7_quality_isolation_") as temporary:
        control_root = Path(temporary).resolve(strict=True)
        isolated_source_root = control_root / "held_source_mirror"
        isolated_source_root.mkdir(parents=False, exist_ok=False)
        mirror = _materialize_held_source_mirror(
            root=isolated_source_root,
            held_source_bytes=held_source_bytes,
        )
        config = control_root / "pytest.ini"
        _write_new_quality_isolation(config, PYTEST_CONFIG_BYTES)
        probe_prefix = control_root / "probe_pycache_empty"
        collection_prefix = control_root / "collection_pycache_empty"
        execution_prefix = control_root / "execution_pycache_empty"
        for prefix in (probe_prefix, collection_prefix, execution_prefix):
            prefix.mkdir(parents=False, exist_ok=False)
        junit = control_root / "executed.xml"
        with ExitStack() as quality_window:
            config_lock = quality_window.enter_context(
                SupervisorArchiveCustody(path=config, root=control_root)
            )
            mirror_locks = {
                relative: quality_window.enter_context(
                    SupervisorArchiveCustody(
                        path=isolated_source_root / relative,
                        root=control_root,
                    )
                )
                for relative in sorted(mirror)
            }
            config_receipt_before = _require_exact_custody_bytes(
                custody=config_lock,
                expected=PYTEST_CONFIG_BYTES,
                label="pytest config",
            )
            mirror_receipts_before = {
                relative: _require_exact_custody_bytes(
                    custody=custody,
                    expected=mirror[relative],
                    label=f"held source mirror {relative}",
                )
                for relative, custody in mirror_locks.items()
            }
            probe_code = (
                "import json,os,sys;"
                "print(json.dumps({"
                "'dont_write_bytecode':sys.dont_write_bytecode,"
                "'isolated':sys.flags.isolated,"
                "'pycache_prefix':sys.pycache_prefix,"
                "'plugin_autoload':os.environ.get('PYTEST_DISABLE_PLUGIN_AUTOLOAD')"
                "},sort_keys=True,separators=(',',':')))"
            )
            probe, probe_stdout, _probe_stderr = _run(
                [
                    python_executable,
                    "-I",
                    "-B",
                    "-X",
                    f"pycache_prefix={probe_prefix}",
                    "-c",
                    probe_code,
                ],
                python_pycache_prefix=probe_prefix,
                cwd=isolated_source_root,
            )
            collection, collection_stdout, _collection_stderr = _run(
                [
                    *_pytest_command_prefix(
                        python_executable=python_executable,
                        pycache_prefix=collection_prefix,
                        config=config,
                        isolated_source_root=isolated_source_root,
                    ),
                    "--collect-only",
                    TEST_RELATIVE,
                ],
                python_pycache_prefix=collection_prefix,
                cwd=isolated_source_root,
            )
            collection_site = _parse_pytest_recorder(collection_stdout)
            nodeids = _parse_collected_nodeids(collection_stdout)
            pytest, pytest_stdout, _pytest_stderr = _run(
                [
                    *_pytest_command_prefix(
                        python_executable=python_executable,
                        pycache_prefix=execution_prefix,
                        config=config,
                        isolated_source_root=isolated_source_root,
                    ),
                    f"--junitxml={junit}",
                    *nodeids,
                ],
                python_pycache_prefix=execution_prefix,
                cwd=isolated_source_root,
            )
            execution_site = _parse_pytest_recorder(pytest_stdout)
            probe_payload = json.loads(probe_stdout)
            junit_raw = junit.read_bytes() if junit.is_file() else b""
            executed_nodeids = _parse_executed_nodeids(junit_raw)
            ruff, _ruff_stdout, _ruff_stderr = _run(
                [
                    ruff_executable,
                    "check",
                    "--isolated",
                    "--no-cache",
                    PACKAGE_RELATIVE,
                    SCRIPT_RELATIVE,
                    TEST_RELATIVE,
                ],
                cwd=isolated_source_root,
            )
            ruff_version, _version_stdout, _version_stderr = _run(
                [ruff_executable, "--version"],
                cwd=isolated_source_root,
            )
            config_receipt_after = _require_exact_custody_bytes(
                custody=config_lock,
                expected=PYTEST_CONFIG_BYTES,
                label="pytest config after quality",
            )
            mirror_receipts_after = {
                relative: _require_exact_custody_bytes(
                    custody=custody,
                    expected=mirror[relative],
                    label=f"held source mirror after quality {relative}",
                )
                for relative, custody in mirror_locks.items()
            }
            mirror_universe_after = sorted(
                path.relative_to(isolated_source_root).as_posix()
                for path in isolated_source_root.rglob("*")
                if path.is_file()
            )
        pycache_evidence = [
            probe["environment_contract"],
            collection["environment_contract"],
            pytest["environment_contract"],
        ]
        quality_result = {
            "pytest": pytest,
            "pytest_collection": collection,
            "python_clean_cache_probe": probe,
            "python_clean_cache_probe_payload": probe_payload,
            "pytest_config_custody_before": config_receipt_before,
            "pytest_config_custody_after": config_receipt_after,
            "pytest_config_raw_sha256": sha256_bytes(config.read_bytes()),
            "pytest_config_expected_raw_sha256": sha256_bytes(PYTEST_CONFIG_BYTES),
            "pytest_config_expected_size_bytes": len(PYTEST_CONFIG_BYTES),
            "pytest_config_custody_matches_expected_bytes": (
                config_receipt_before["raw_sha256"]
                == config_receipt_after["raw_sha256"]
                == sha256_bytes(PYTEST_CONFIG_BYTES)
                and config_receipt_before["size_bytes"]
                == config_receipt_after["size_bytes"]
                == len(PYTEST_CONFIG_BYTES)
            ),
            "held_source_mirror_record_count": len(mirror),
            "held_source_mirror_records_semantic_sha256": sha256_bytes(
                canonical_json_bytes(
                    [
                        {
                            "relative_path": relative,
                            "raw_sha256": sha256_bytes(raw),
                            "size_bytes": len(raw),
                        }
                        for relative, raw in sorted(mirror.items())
                    ]
                )
            ),
            "held_source_mirror_receipts_before": mirror_receipts_before,
            "held_source_mirror_receipts_after": mirror_receipts_after,
            "held_source_mirror_file_universe_after": mirror_universe_after,
            "subprocess_executable_launch_paths": [
                probe["command"][0],
                collection["command"][0],
                pytest["command"][0],
                ruff["command"][0],
                ruff_version["command"][0],
            ],
            "held_source_mirror_exact_custody_stable": (
                mirror_receipts_after == mirror_receipts_before
                and mirror_universe_after == sorted(mirror)
                and all(
                    mirror_receipts_before[relative]["raw_sha256"]
                    == sha256_bytes(raw)
                    and mirror_receipts_before[relative]["size_bytes"] == len(raw)
                    for relative, raw in mirror.items()
                )
            ),
            "pytest_noconftest": True,
            "pytest_plugin_autoload_disabled": True,
            "pytest_collection_on_site_evidence": collection_site,
            "pytest_execution_on_site_evidence": execution_site,
            "pytest_isolated_bootstrap_raw_sha256": sha256_bytes(
                PYTEST_ISOLATED_BOOTSTRAP.encode("utf-8")
            ),
            "installed_pytest_imported_before_project_root_insertion": True,
            "fresh_pycache_prefix_count": 3,
            "fresh_pycache_prefix_evidence": pycache_evidence,
            "all_pycache_prefixes_empty_before_and_after": all(
                row["pycache_empty_before_and_after"] for row in pycache_evidence
            ),
            "collected_nodeids": nodeids,
            "executed_nodeids": executed_nodeids,
            "collected_nodeids_semantic_sha256": sha256_bytes(
                canonical_json_bytes(nodeids)
            ),
            "junit_raw_sha256": sha256_bytes(junit_raw),
            "junit_size_bytes": len(junit_raw),
            "ruff_operated_only_on_held_source_mirror": True,
            "ruff_cache_reads_and_writes_disabled": True,
            "ruff_completed_while_all_mirror_handles_were_held": True,
            "ruff_source_arguments": [
                PACKAGE_RELATIVE,
                SCRIPT_RELATIVE,
                TEST_RELATIVE,
            ],
        }
    quality_result["temporary_isolation_root_removed_after_gate"] = not control_root.exists()
    pytest = quality_result["pytest"]
    collection = quality_result["pytest_collection"]
    nodeids = quality_result["collected_nodeids"]
    executed_nodeids = quality_result["executed_nodeids"]
    count = len(nodeids)
    if (
        quality_result["python_clean_cache_probe"]["returncode"]
        or pytest["returncode"]
        or collection["returncode"]
        or ruff["returncode"]
        or ruff_version["returncode"]
        or ruff_version["stdout_tail"].strip() != RUFF_EXPECTED_VERSION
        or count != SCOPED_TEST_CASE_COUNT
        or executed_nodeids != nodeids
        or quality_result["pytest_collection_on_site_evidence"]
        != {
            "autoloaded_plugin_distribution_count": 0,
            "call_outcomes": {"failed": 0, "passed": 0, "skipped": 0},
            "collected_nodeids": nodeids,
            "conftest_plugin_count": 0,
            "deselected_nodeids": [],
            "dont_write_bytecode": True,
            "isolated": 1,
            "plugin_autoload": "1",
            "pycache_prefix": str(collection_prefix.resolve()),
            "pytest_exit_status": 0,
        }
        or quality_result["pytest_execution_on_site_evidence"]
        != {
            "autoloaded_plugin_distribution_count": 0,
            "call_outcomes": {
                "failed": 0,
                "passed": count,
                "skipped": 0,
            },
            "collected_nodeids": nodeids,
            "conftest_plugin_count": 0,
            "deselected_nodeids": [],
            "dont_write_bytecode": True,
            "isolated": 1,
            "plugin_autoload": "1",
            "pycache_prefix": str(execution_prefix.resolve()),
            "pytest_exit_status": 0,
        }
        or quality_result["python_clean_cache_probe_payload"]
        != {
            "dont_write_bytecode": True,
            "isolated": 1,
            "plugin_autoload": "1",
            "pycache_prefix": str(probe_prefix.resolve()),
        }
        or not quality_result["all_pycache_prefixes_empty_before_and_after"]
        or not quality_result["held_source_mirror_exact_custody_stable"]
        or not quality_result["pytest_config_custody_matches_expected_bytes"]
        or not quality_result["temporary_isolation_root_removed_after_gate"]
        or quality_result["subprocess_executable_launch_paths"]
        != [python_executable] * 3 + [ruff_executable] * 2
        or python_custody.receipt() != python_receipt
        or ruff_custody.receipt() != ruff_receipt
    ):
        raise RuntimeError("R8-r7 scoped source quality failed")
    return {
        "schema_version": "expected_pe.r8.r7.static_design.quality.v1",
        "status": "PASS_SCOPED_DESIGN_ONLY_FULL_REPOSITORY_PASS_NOT_CLAIMED",
        **quality_result,
        "ruff": ruff,
        "ruff_version": ruff_version,
        "python_executable_custody": python_receipt,
        "ruff_executable_custody": ruff_receipt,
        "python_executable_dos_final_launch_path": python_executable,
        "ruff_executable_dos_final_launch_path": ruff_executable,
        "python_executable_volume_guid_identity_path": (
            python_volume_guid_identity_path
        ),
        "ruff_executable_volume_guid_identity_path": ruff_volume_guid_identity_path,
        "all_five_subprocesses_used_held_dos_final_launch_paths": True,
        "volume_guid_executable_launch_count": 0,
        "volume_guid_paths_used_for_identity_evidence_only": True,
        "tool_image_handles_held_across_all_five_subprocesses": True,
        "tool_image_custody_rechecked_after_all_five_subprocesses": True,
        "selected_test_case_count": count,
        "executed_test_case_count": len(executed_nodeids),
        "test_source_raw_sha256": test_source_raw_sha256,
        "quality_subprocess_count": QUALITY_SUBPROCESS_COUNT,
        "production_or_signer_subprocess_count": 0,
        "r8r7_blocker_negative_test_count": 6,
        "real_signer_test_count": 0,
        "production_phase2_test_count": 0,
        "fresh_truth_heldout_test_count": 0,
        "full_repository_suite_pass_claimed": False,
        "inherited_full_repository_nonpass_snapshot": {
            "relative_path": (
                f"{R8_R6_R2_ROOT_RELATIVE}/FULL_REPOSITORY_TEST_SNAPSHOT.json"
            ),
            "raw_sha256": PREDECESSOR_HASHES[
                "r8_r6_r2/FULL_REPOSITORY_TEST_SNAPSHOT.json"
            ],
            "separated_status": full_repository_status,
        },
    }


def _one_shot_launcher_contract(
    source_identity: Mapping[str, Any],
) -> Mapping[str, Any]:
    launcher_records = [
        record
        for record in source_identity["records"]
        if record["source_relative"] == LAUNCHER_RELATIVE
    ]
    if len(launcher_records) != 1:
        raise RuntimeError("a3 source identity lacks the exact one-shot launcher")
    launcher = launcher_records[0]
    return {
        "schema_version": "expected_pe.r8.r7.a3.one_shot_launcher.v1",
        "source_relative": LAUNCHER_RELATIVE,
        "source_raw_sha256": launcher["raw_sha256"],
        "source_size_bytes": launcher["size_bytes"],
        "one_shot_prefix": str(ONE_SHOT_LAUNCHER_PREFIX),
        "python_argv": [
            str(GENERATION_PYTHON),
            "-I",
            "-B",
            "-X",
            f"pycache_prefix={ONE_SHOT_LAUNCHER_PREFIX}",
            "-c",
            LAUNCHER_QUOTE_FREE_BOOTSTRAP,
            LAUNCHER_INVOCATION_SOURCE_BASE64,
        ],
        "invocation_source_raw_sha256": sha256_bytes(
            LAUNCHER_INVOCATION_SOURCE.encode("utf-8")
        ),
        "prefix_must_be_absent_before_atomic_create": True,
        "created_prefix_must_be_empty": True,
        "preexisting_prefix_builder_launch_count": 0,
        "authorized_builder_source_launch_count": 1,
        "four_output_identities_rechecked_before_dispatch": True,
    }


def _command_lock(
    *,
    archive_raw: bytes,
    source_identity_raw: bytes,
    source_identity: Mapping[str, Any],
    python_receipt: Mapping[str, Any],
) -> Mapping[str, Any]:
    return {
        "schema_version": "expected_pe.r8.r7.static_design.command_lock.v2",
        "status": "FROZEN_DESIGN_ONLY_AWAITING_INDEPENDENT_AUDIT",
        "production_command": None,
        "production_execution_allowed": False,
        "signer_authority": None,
        "signer_launch_allowed": False,
        "binding_freeze_allowed": False,
        "supplemental_go_publication_allowed": False,
        "endpoint_contact_allowed": False,
        "authority_issuance_allowed": False,
        "qualification_generation_allowed": False,
        "fresh_truth_heldout_access_allowed": False,
        "self_go_audit_allowed": False,
        "frozen_archive_relative": f"{OUTPUT_ROOT_RELATIVE}/AUDITOR.pyz",
        "frozen_archive_raw_sha256": sha256_bytes(archive_raw),
        "source_identity_raw_sha256": sha256_bytes(source_identity_raw),
        "source_records_semantic_sha256": source_identity[
            "records_semantic_sha256"
        ],
        "python_executable": str(GENERATION_PYTHON),
        "python_executable_raw_sha256": python_receipt["raw_sha256"],
        "python_executable_volume_serial_number": python_receipt[
            "volume_serial_number"
        ],
        "python_executable_file_id_128": python_receipt["file_id_128"],
        "python_executable_size_bytes": python_receipt["size_bytes"],
        "one_shot_launcher": _one_shot_launcher_contract(source_identity),
        "required_next_gate": "INDEPENDENT_STATIC_ADVERSARIAL_AUDIT",
    }


def _write_new_quality_isolation(path: Path, raw: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _adjacent_bytecode_preflight() -> Mapping[str, Any]:
    records: list[Mapping[str, Any]] = []
    for relative in _source_relatives():
        source = PROJECT_ROOT / relative
        cache = source.parent / "__pycache__"
        if not cache.is_dir():
            continue
        prefixes = (f"{source.stem}.", f"{source.stem}.pyc")
        with os.scandir(cache) as entries:
            for entry in entries:
                if not entry.name.endswith(".pyc") or not entry.name.startswith(prefixes):
                    continue
                metadata = entry.stat(follow_symlinks=False)
                records.append(
                    {
                        "relative_path": Path(entry.path)
                        .relative_to(PROJECT_ROOT)
                        .as_posix(),
                        "size_bytes": metadata.st_size,
                        "mtime_ns_diagnostic_only": metadata.st_mtime_ns,
                    }
                )
    records.sort(key=lambda row: row["relative_path"])
    return {
        "schema_version": "expected_pe.r8.r7.adjacent_bytecode_preflight.v1",
        "status": "PASS_NO_ADJACENT_PYC" if not records else "FAIL_ADJACENT_PYC",
        "adjacent_pyc_count": len(records),
        "adjacent_pyc_records": records,
        "pyc_execution_allowed_for_static_freeze": False,
        "cleanup_performed_by_builder": False,
    }


def _require_no_adjacent_bytecode() -> Mapping[str, Any]:
    receipt = _adjacent_bytecode_preflight()
    if receipt["adjacent_pyc_count"]:
        raise RuntimeError("adjacent source bytecode blocks R8-r7 static freeze")
    return receipt


def _require_freeze_launcher_isolation() -> Mapping[str, Any]:
    configured = os.environ.get("PYTHONPYCACHEPREFIX")
    if not configured:
        raise RuntimeError("freeze launcher lacks a dedicated pycache prefix")
    expected_raw = str(ONE_SHOT_LAUNCHER_PREFIX)
    if configured != expected_raw or sys.pycache_prefix != expected_raw:
        raise RuntimeError("freeze launcher pycache prefix is not the exact a3 identity")
    prefix = Path(configured)
    if not prefix.is_absolute() or prefix != ONE_SHOT_LAUNCHER_PREFIX:
        raise RuntimeError("freeze launcher pycache prefix is not absolute")
    resolved = prefix.resolve(strict=True)
    expected_resolved = ONE_SHOT_LAUNCHER_PREFIX.resolve(strict=True)
    if resolved != expected_resolved or str(resolved) != expected_raw:
        raise RuntimeError("freeze launcher pycache prefix resolved identity drifted")
    with SupervisorDirectoryCustody(
        path=prefix,
        ancestry_root=prefix,
        rename_capable=False,
    ) as prefix_custody:
        prefix_receipt = prefix_custody.receipt()
        entries = sorted(item.name for item in resolved.iterdir())
        prefix_receipt_after_inventory = prefix_custody.receipt()
    if (
        not resolved.is_dir()
        or entries
        or prefix_receipt_after_inventory != prefix_receipt
        or prefix_receipt["path"] != expected_raw
        or prefix_receipt["reparse_ancestor_count"] != 0
        or prefix_receipt["volume_serial_number"] < 0
        or len(prefix_receipt["file_id_128"]) != 32
        or sys.dont_write_bytecode is not True
        or os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
        or os.environ.get("PYTEST_DISABLE_PLUGIN_AUTOLOAD") != "1"
    ):
        raise RuntimeError("freeze launcher isolation contract drifted")
    return {
        "status": "PASS_FRESH_EMPTY_FREEZE_LAUNCHER_PYCACHE",
        "prefix_path": expected_raw,
        "prefix_resolved_path": str(resolved),
        "prefix_path_raw_sha256": sha256_bytes(str(resolved).encode("utf-8")),
        "prefix_entry_names": entries,
        "prefix_volume_serial_number": prefix_receipt["volume_serial_number"],
        "prefix_file_id_128": prefix_receipt["file_id_128"],
        "prefix_reparse_ancestor_count": 0,
        "prefix_directory_custody_stable": True,
        "sys_dont_write_bytecode": True,
        "sys_pycache_prefix_matches_environment": True,
        "pytest_plugin_autoload_disabled": True,
    }


def _freeze_with_outputs_custody(
    *,
    outputs_custody: SupervisorDirectoryCustody,
    launcher_isolation_before: Mapping[str, Any],
    adjacent_bytecode_preflight: Mapping[str, Any],
) -> Mapping[str, Any]:
    plan = _bound_plan(PERMITTED_STATIC_DESIGN_CHILD_NAME)
    outputs_receipt_before = outputs_custody.receipt()
    trusted_outputs_receipt = _require_trusted_outputs_identity(outputs_custody)
    if (
        OUTPUT_ROOT.name != PERMITTED_STATIC_DESIGN_CHILD_NAME
        or STAGING.name != plan.staging_name
        or Path(outputs_custody.path) != OUTPUTS_ROOT
        or outputs_receipt_before["rename_capable"]
        or outputs_receipt_before["delete_share_allowed"]
        or trusted_outputs_receipt != outputs_receipt_before
    ):
        raise RuntimeError("R8-r7 held outputs policy binding drifted")
    preflight_before = require_clean_r8_r7_preflight(outputs_custody)
    planned_children_before = {
        name: outputs_custody.observe_direct_child(name)
        for name in (
            plan.final_name,
            plan.staging_name,
            plan.failure_name,
            plan.failure_staging_name,
        )
    }
    if any(row["exists"] for row in planned_children_before.values()):
        raise RuntimeError("R8-r7 bound publication identity already exists")
    predecessor_before = _predecessor_chain(outputs_custody=outputs_custody)
    if Path(sys.executable).resolve(strict=True) != GENERATION_PYTHON.resolve(strict=True):
        raise RuntimeError("R8-r7 freeze must run under the pinned Python executable")
    with ExitStack() as source_window:
        python_custody = source_window.enter_context(
            SupervisorArchiveCustody(
                path=GENERATION_PYTHON,
                root=Path(GENERATION_PYTHON.anchor),
            )
        )
        ruff_custody = source_window.enter_context(
            SupervisorArchiveCustody(
                path=RUFF_EXECUTABLE,
                root=Path(RUFF_EXECUTABLE.anchor),
            )
        )
        python_raw = python_custody.raw_bytes()
        python_receipt = python_custody.receipt()
        ruff_raw = ruff_custody.raw_bytes()
        ruff_receipt = ruff_custody.receipt()
        if sha256_bytes(python_raw) != GENERATION_PYTHON_EXPECTED_SHA256:
            raise RuntimeError("pinned Python executable hash drifted")
        if sha256_bytes(ruff_raw) != RUFF_EXECUTABLE_EXPECTED_SHA256:
            raise RuntimeError("pinned Ruff executable hash drifted")
        custodies = {
            relative: source_window.enter_context(
                SupervisorArchiveCustody(
                    path=PROJECT_ROOT / relative,
                    root=PROJECT_ROOT,
                )
            )
            for relative in _source_relatives()
        }
        raw_by_relative = {
            relative: custody.raw_bytes()
            for relative, custody in custodies.items()
        }
        custody_before = {
            relative: custody.receipt()
            for relative, custody in custodies.items()
        }
        runtime_records, members = _runtime_sources_from_bytes(raw_by_relative)
        source_lock = _source_lock_from_bytes(
            runtime_records=runtime_records,
            raw_by_relative=raw_by_relative,
            custody_by_relative=custody_before,
        )
        quality = dict(
            _quality(
                python_custody=python_custody,
                ruff_custody=ruff_custody,
                python_receipt=python_receipt,
                ruff_receipt=ruff_receipt,
                full_repository_status=predecessor_before["full_repository_status"],
                test_source_raw_sha256=sha256_bytes(raw_by_relative[TEST_RELATIVE]),
                held_source_bytes=raw_by_relative,
            )
        )
        custody_after = {
            relative: custody.receipt()
            for relative, custody in custodies.items()
        }
        source_lock_after_quality = _source_lock_from_bytes(
            runtime_records=runtime_records,
            raw_by_relative=raw_by_relative,
            custody_by_relative=custody_after,
        )
        if source_lock_after_quality != source_lock:
            raise RuntimeError("tested source custody changed across quality gate")
        quality["tested_source_lock_raw_sha256"] = sha256_bytes(
            canonical_json_bytes(source_lock)
        )
        quality["all_source_handles_held_no_share_write_delete_during_gate"] = True
        source_identity = build_source_identity(runtime_records)
        source_identity_raw = canonical_json_bytes(source_identity)
        archive_raw = _build_archive(
            source_identity_raw=source_identity_raw,
            members=members,
        )
        archive_reopen = _verify_archive(
            raw=archive_raw, source_identity=source_identity
        )
        test_raw = raw_by_relative[TEST_RELATIVE]
    blueprint = build_win32_supervision_blueprint()
    validate_win32_supervision_blueprint(blueprint)
    trace = build_blocker_trace(
        test_relative=TEST_RELATIVE,
        test_source_raw=test_raw,
        quality_receipt=quality,
    )
    validate_blocker_trace(
        trace,
        test_relative=TEST_RELATIVE,
        test_source_raw=test_raw,
        quality_receipt=quality,
    )
    command_lock = _command_lock(
        archive_raw=archive_raw,
        source_identity_raw=source_identity_raw,
        source_identity=source_identity,
        python_receipt=python_receipt,
    )
    closure_schema = {
        "schema_version": "expected_pe.r8.r7.identity_closure_schema.v1",
        "status": "EXACT_SCHEMA_DESIGN_ONLY",
        "exact_claim_keys": sorted(CLOSURE_KEYS),
        "reopened_artifact_hash_fields": dict(REOPENED_HASH_FIELDS),
        "consumers": ["IMMEDIATE_ISSUANCE", "SIGNER", "AUTHORITY"],
        "same_validator_for_all_consumers": True,
        "production_authority_enabled": False,
    }
    static_design = {
        "schema_version": "expected_pe.r8.r7.static_design.v1",
        "status": "FROZEN_DESIGN_ONLY_NO_GO_AWAITING_INDEPENDENT_AUDIT",
        "scope": [
            "DESIGN_ONLY",
            "VERIFY_ONLY_ARCHIVE",
            "NO_EXECUTION_PACKAGE",
            "NO_SIGNER",
            "NO_PHASE2",
            "NO_FRESH",
        ],
        "standalone_design_verifier": {
            "format": "PYZ",
            "runtime_mode": "VERIFY_FROZEN_SOURCE_AND_EXIT_78",
            "successful_verification_exit_code": 78,
            "live_package_import_count": 0,
            "archive_raw_sha256": sha256_bytes(archive_raw),
            "source_records_semantic_sha256": source_identity[
                "records_semantic_sha256"
            ],
            "supervisor_held_archive_handle_share_mode": "FILE_SHARE_READ_ONLY",
            "write_delete_share_allowed": False,
            "positive_supplemental_auditor_implemented": False,
            "generator_runtime_implemented": False,
            "signer_or_authority_capability_present": False,
        },
        "execution_package_blockers": [
            "SEPARATE_PHASE2_EXECUTION_SOURCE_AND_ARCHIVE_REQUIRED",
            "INDEPENDENT_EXECUTION_PACKAGE_PRELAUNCH_AUDIT_REQUIRED",
            "MEMORY_ONLY_SIGNER_PUBLIC_KEY_AND_READINESS_BINDING_REQUIRED",
            "INITIALIZATION_ONLY_RESUME_WITH_AUTHORITY_GATE_CLOSED_REQUIRED",
            "EXACT_JOB_QUERY_HANDLE_CLOSE_AND_SOLE_OWNER_PROOF_REQUIRED",
            "FINAL_BINDING_SUPPLEMENTAL_AUDIT_REQUIRED",
            "SIGNER_ALIVE_ZERO_COUNTER_RECHECK_REQUIRED",
        ],
        "win32_supervision": blueprint,
        "file_identity_contract": {
            "authoritative_fields": [
                "volume_serial_number",
                "file_id_128",
                "size_bytes",
                "raw_sha256",
                "reparse_free_ancestry",
            ],
            "mode_and_mtime_authoritative": False,
            "supervisor_archive_handle_held_through_publication": True,
            "archive_relative_rejects_posix_windows_drive_unc_device_paths": True,
            "archive_relative_rejects_dos_device_and_trim_aliases": True,
            "archive_path_resolved_beneath_trusted_root_before_custody": True,
            "lexical_outputs_child_not_resolved_before_nofollow_custody": True,
            "outputs_volume_serial_and_file_id_pinned_before_any_write": True,
            "outputs_root_and_ancestry_held_open_reparse_point": True,
            "all_directory_custody_handles_deny_delete_share": True,
            "direct_children_force_inclusive_nofollow": True,
            "staging_directory_delete_handle_held_through_rename": True,
            "rename_target_derived_from_parent_volume_guid_handle_path": True,
            "dos_drive_mapping_fallback_allowed": False,
            "local_ntfs_required_for_static_publication": True,
        },
        "time_contract": {
            "strict_heartbeat_progress": True,
            "maximum_heartbeat_age_at_publication_seconds": 5,
            "maximum_snapshot_to_publication_seconds": 1,
            "minimum_expiry_margin_seconds": 30,
            "request_count": 0,
            "signature_count": 0,
            "process_handles_held_through_publication": True,
        },
        "publication_contract": {
            "all_candidate_writes_and_fsync_before_rename_bracket": True,
            "evidence_revalidated_immediately_before_atomic_rename": True,
            "evidence_revalidated_immediately_after_atomic_rename": True,
            "maximum_atomic_rename_bracket_seconds": 1,
            "injected_utc_and_independent_monotonic_bounds_both_required": True,
            "nonzero_zero_state_counts_rejected": True,
            "malformed_counts_record_measurement_failure": True,
            "all_clock_validation_io_fsync_rename_exceptions_seal_no_go": True,
            "precheck_and_collision_failures_use_same_canonical_no_go_contract": True,
            "occupied_failure_identity_returns_hashed_no_overwrite_fallback": True,
            "public_root_override_allowed": False,
            "public_policy_is_exact_module_singleton": True,
            "public_child_is_exact_built_in_str_and_exact_ordinal_identity": True,
            "invalid_child_policy_clock_or_evidence_causes_zero_filesystem_io": True,
            "invalid_request_uses_fixed_time_constant_hashed_fallback": True,
            "four_child_preflight_before_publication_required": True,
            "four_child_exact_delta_postcondition_required": True,
            "internal_dual_clean_preflight_brackets_full_root_baseline": True,
            "full_root_direct_child_file_ids_compared_before_after": True,
            "only_bound_final_child_may_be_added_to_full_root_inventory": True,
            "all_preexisting_root_child_identities_must_remain_unchanged": True,
            "approved_staging_rename_increments_parent_namespace_epoch_once": True,
            "checksum_ledger_name_reserved_case_insensitively": True,
            "artifact_names_use_the_nt_child_create_lexical_gate_before_io": True,
            "negative_name_reservation_claimed": False,
            "set_file_information_by_handle_file_rename_info_used": True,
            "rename_replace_if_exists": False,
            "rename_root_directory_field": None,
            "non_null_root_directory_host_probe_win32_error": 87,
            "held_parent_volume_guid_absolute_target_used": True,
            "independent_final_reopen_rehash_before_success_return": True,
            "maximum_legacy_windows_artifact_path_characters": 240,
            "published_candidate_is_non_authoritative_no_go": True,
            "positive_publication_function_exists": False,
        },
        "availability_threat_model": {
            "exported_singleton_and_exact_child_are_not_authentication": True,
            "unauthorized_local_import_can_only_consume_no_go_identity": True,
            "unauthorized_local_import_cannot_grant_signer_or_go_authority": True,
            "designated_identity_availability_requires_isolated_supervisor_cli": True,
            "production_cli_enabled_in_this_source_freeze": False,
        },
        "quality_source_custody_contract": {
            "source_handles_held_no_share_write_delete_across_pytest_and_ruff": True,
            "python_and_ruff_image_handles_held_across_all_subprocesses": True,
            "python_and_ruff_launched_by_held_handle_dos_final_paths": True,
            "python_and_ruff_volume_guid_paths_are_identity_evidence_only": True,
            "volume_guid_executable_launch_count": 0,
            "python_and_ruff_image_custody_rechecked_after_subprocesses": True,
            "tested_source_lock_raw_sha256": quality[
                "tested_source_lock_raw_sha256"
            ],
            "archive_built_from_the_same_held_bytes": True,
            "external_one_shot_launcher_is_a_held_archived_source_member": True,
            "launcher_self_hash_claimed": False,
            "launcher_hash_bound_by_source_identity_and_source_lock": True,
            "post_quality_custody_rechecked_before_archive_build": True,
            "fresh_empty_pycache_prefix_per_python_subprocess": True,
            "pytest_plugin_autoload_disabled": True,
            "pytest_conftest_loading_disabled": True,
            "pytest_config_bytes_held_no_share_write_delete": True,
            "ruff_no_cache_cli_required": True,
            "collected_and_executed_nodeids_exactly_equal": True,
            "test_source_and_quality_receipt_hash_bound_into_trace": True,
            "pytest_executes_only_fresh_mirror_of_held_source_bytes": True,
            "isolated_source_mirror_files_held_across_collection_and_execution": True,
            "every_mirror_custody_hash_and_size_match_expected_held_bytes": True,
            "pytest_config_custody_hash_and_size_match_fixed_expected_bytes": True,
            "on_site_plugin_conftest_deselection_outcome_evidence": True,
            "junit_executed_nodeids_equal_collected_nodeids": True,
        },
        "identity_closure": closure_schema,
        "production_command": None,
        "signer_authority": None,
        "go_authority": None,
    }
    negative_matrix = {
        "schema_version": "expected_pe.r8.r7.negative_test_matrix.v1",
        "status": "PASS_SYNTHETIC_DESIGN_REJECTIONS",
        "blocker_trace": trace,
        "additional_rejections": [
            "equal heartbeat",
            "nonzero request/signature counter",
            "late publication",
            "reparse ancestor",
            "hidden vault/journal/staging identity",
            "negative receipt overwrite",
            "mutable source schema",
            "arbitrary but rehashed semantic artifact",
            "null/noncanonical frozen archive path",
            "hidden non-staging Phase2 identity",
            "nested uncollectable trace test",
            "nonzero publication zero-state count",
            "clock/write/fsync/rename publication exception",
            "slow atomic rename bracket",
            "post-test source substitution while custody window is held",
            "pre-existing timestamp pyc execution",
            "pytest plugin or conftest autoload",
            "trace test hidden by __test__ false or deselection",
            "Windows drive-relative or DOS device archive path",
            "constant injected clock hiding monotonic rename delay",
            "root/staging/failure-receipt collision or malformed counts",
            "caller-supplied policy/root/clock/evidence callback",
            "drive-relative/UNC/extended/device/nested/ADS publication child",
            "DOS alias including superscript/case/extension/trailing trim variant",
            "created staging FileId substitution before first artifact write",
            "outputs root trust drift preventing terminal failure write",
            "post-rename FileId mismatch",
            "case-insensitive final collision",
            "failure and failure-staging collision",
            "non-null RootDirectory ERROR_INVALID_PARAMETER host behavior",
            "legacy Windows path length above 240 characters",
        ],
        "production_or_signer_process_launch_count": 0,
        "quality_subprocess_count": QUALITY_SUBPROCESS_COUNT,
    }
    predecessor_after = _predecessor_chain(outputs_custody=outputs_custody)
    preflight_after = require_clean_r8_r7_preflight(outputs_custody)
    adjacent_bytecode_after = _require_no_adjacent_bytecode()
    launcher_isolation_after = _require_freeze_launcher_isolation()
    if (
        predecessor_after != predecessor_before
        or preflight_after != preflight_before
        or adjacent_bytecode_after != adjacent_bytecode_preflight
    ):
        raise RuntimeError("predecessor/preflight changed during R8-r7 design freeze")
    if launcher_isolation_after != launcher_isolation_before:
        raise RuntimeError("freeze launcher isolation changed during source freeze")
    self_check = {
        "schema_version": "expected_pe.r8.r7.static_design.self_check.v1",
        "status": "PASS_SOURCE_DESIGN_FREEZE_ONLY_NO_AUTHORITY",
        "archive_reopen": archive_reopen,
        "preflight_before": preflight_before,
        "preflight_after_analysis": preflight_after,
        "adjacent_bytecode_preflight_before": adjacent_bytecode_preflight,
        "adjacent_bytecode_preflight_after_analysis": adjacent_bytecode_after,
        "outputs_directory_custody_before": outputs_receipt_before,
        "planned_publication_children_before": planned_children_before,
        "freeze_launcher_isolation_before": launcher_isolation_before,
        "freeze_launcher_isolation_after": launcher_isolation_after,
        "predecessor_chain_raw_sha256": sha256_bytes(
            canonical_json_bytes(predecessor_before)
        ),
        "r8r7_blocker_trace_count": trace["row_count"],
        "production_command": None,
        "signer_authority": None,
        "go_authority": None,
        "quality_subprocess_count": QUALITY_SUBPROCESS_COUNT,
        "production_createprocess_count": 0,
        "signer_or_auditor_createprocess_count": 0,
        "signer_launch_count": 0,
        "binding_freeze_count": 0,
        "production_supplemental_audit_count": 0,
        "endpoint_contact_count": 0,
        "authority_issuance_count": 0,
        "qualification_generation_count": 0,
        "fresh_truth_heldout_access_count": 0,
        "self_go_audit_count": 0,
    }
    report = (
        "# R8-r7 static design/source freeze\n\n"
        "Status: **FROZEN DESIGN-ONLY NO_GO - independent audit required**.\n\n"
        "AUDITOR.pyz is a disabled source verifier: it verifies the frozen archive and "
        "exits 78. It is not a positive supplemental auditor or generator runtime. The "
        "exact unnamed Job Object/query-handle blueprint, creation-time process/file "
        "identity window, strict heartbeat publication contract, and common "
        "issuance/signer/authority closure schema are design inputs for a separate "
        "Phase2 execution package and independent prelaunch audit. No CreateProcessW "
        "call, signer, binding, public key, readiness proof, endpoint, authority, "
        "generation, fresh truth, heldout access, production command, signer authority, "
        "or GO was emitted.\n"
    ).encode("utf-8")
    artifacts: dict[str, bytes] = {
        "AUDITOR.pyz": archive_raw,
        "BLOCKER_TRACE.json": canonical_json_bytes(trace),
        "CLOSURE_SCHEMA.json": canonical_json_bytes(closure_schema),
        "COMMAND_LOCK.json": canonical_json_bytes(command_lock),
        "FULL_REPOSITORY_STATUS.json": canonical_json_bytes(
            predecessor_before["full_repository_status"]
        ),
        "NEGATIVE_TEST_MATRIX.json": canonical_json_bytes(negative_matrix),
        "PREDECESSOR_CHAIN.json": canonical_json_bytes(predecessor_before),
        "QUALITY_RECEIPT.json": canonical_json_bytes(quality),
        "REPORT.md": report,
        "SELF_CHECK.json": canonical_json_bytes(self_check),
        "SOURCE_IDENTITY.json": source_identity_raw,
        "SOURCE_LOCK.json": canonical_json_bytes(source_lock),
        "STATIC_DESIGN.json": canonical_json_bytes(static_design),
    }
    seal = {
        "schema_version": "expected_pe.r8.r7.static_design.seal.v1",
        "status": "SEALED_DESIGN_ONLY_NO_GO_AWAITING_INDEPENDENT_AUDIT",
        "verdict": "NO_GO",
        "production_command": None,
        "signer_authority": None,
        "go_authority": None,
        "signer_launch_allowed": False,
        "authority_issuance_allowed": False,
        "generation_allowed": False,
        "file_records": [
            {
                "relative_path": name,
                "raw_sha256": sha256_bytes(raw),
                "size_bytes": len(raw),
            }
            for name, raw in sorted(artifacts.items())
        ],
    }
    artifacts["SEAL.json"] = canonical_json_bytes(seal)
    manifest = {
        "schema_version": "expected_pe.r8.r7.static_design.manifest.v1",
        "status": "FROZEN_DESIGN_ONLY_NO_GO",
        "output_root_relative": OUTPUT_ROOT_RELATIVE,
        "record_count": len(artifacts),
        "records": [
            {
                "relative_path": name,
                "raw_sha256": sha256_bytes(raw),
                "size_bytes": len(raw),
            }
            for name, raw in sorted(artifacts.items())
        ],
        "production_command": None,
        "signer_authority": None,
        "go_authority": None,
    }
    artifacts["MANIFEST.json"] = canonical_json_bytes(manifest)
    persistence = _publish_bound_artifacts_no_go(
        root_custody=outputs_custody,
        plan=plan,
        artifacts=artifacts,
    )
    if (
        persistence["status"] != "PERSISTED_BOUND_NEW_NO_OVERWRITE"
        or Path(persistence["final_root"]) != OUTPUT_ROOT
        or not persistence["held_handle_rename_used"]
        or not persistence["independent_reopen_rehash_before_return"]
    ):
        raise RuntimeError("bound R8-r7 static publication postcondition failed")
    with SupervisorArchiveCustody(
        path=OUTPUT_ROOT / "AUDITOR.pyz",
        root=OUTPUT_ROOT,
        held_parent=outputs_custody,
    ) as frozen:
        final_archive_custody = frozen.receipt()
    if final_archive_custody["raw_sha256"] != sha256_bytes(archive_raw):
        raise RuntimeError("published R8-r7 archive custody reopen drifted")
    if _predecessor_chain(outputs_custody=outputs_custody) != predecessor_before:
        raise RuntimeError("predecessor changed during R8-r7 publication")
    preflight_after_publication = require_clean_r8_r7_preflight(outputs_custody)
    names_before_publication = set(preflight_before["direct_child_names"])
    names_after_publication = set(preflight_after_publication["direct_child_names"])
    final_observation = outputs_custody.observe_direct_child(plan.final_name)
    if (
        preflight_after_publication["forbidden_identity_count"] != 0
        or preflight_after_publication["outputs_root_identity"]
        != preflight_before["outputs_root_identity"]
        or names_after_publication.difference(names_before_publication)
        != {plan.final_name}
        or names_before_publication.difference(names_after_publication)
        or not final_observation["exists"]
        or final_observation["kind"] != "directory"
        or final_observation["reparse"]
    ):
        raise RuntimeError("publication did not produce the exact designated final delta")
    outputs_receipt_after_publication = outputs_custody.receipt()
    return {
        "status": "FROZEN_R8_R7_STATIC_DESIGN_SOURCE_NO_GO",
        "root": str(OUTPUT_ROOT),
        "checksums_raw_sha256": persistence["checksums_raw_sha256"],
        "archive_raw_sha256": sha256_bytes(archive_raw),
        "source_identity_raw_sha256": sha256_bytes(source_identity_raw),
        "source_records_semantic_sha256": source_identity[
            "records_semantic_sha256"
        ],
        "blocker_trace_count": trace["row_count"],
        "production_command": None,
        "signer_authority": None,
        "go_authority": None,
        "bound_publication_receipt": persistence,
        "preflight_after_publication": preflight_after_publication,
        "exact_designated_final_delta": {
            "added_names": [plan.final_name],
            "removed_names": [],
            "final_observation": final_observation,
        },
        "outputs_directory_custody_after_publication": (
            outputs_receipt_after_publication
        ),
        "signer_launch_count": 0,
        "fresh_truth_heldout_access_count": 0,
    }


def freeze() -> Mapping[str, Any]:
    """Open the fixed outputs root internally; no caller path authority exists."""

    launcher_isolation_before = _require_freeze_launcher_isolation()
    adjacent_bytecode_preflight = _require_no_adjacent_bytecode()
    with SupervisorDirectoryCustody(
        path=OUTPUTS_ROOT,
        ancestry_root=OUTPUTS_ROOT,
        rename_capable=False,
    ) as outputs_custody:
        return _freeze_with_outputs_custody(
            outputs_custody=outputs_custody,
            launcher_isolation_before=launcher_isolation_before,
            adjacent_bytecode_preflight=adjacent_bytecode_preflight,
        )


def _builder_terminal_in_memory_no_go() -> Mapping[str, Any]:
    payload = {
        "schema_version": "expected_pe.r8.r7.static_builder_terminal_no_go.v1",
        "status": "SEALED_IN_MEMORY_BUILDER_NO_GO",
        "verdict": "NO_GO",
        "generated_at_utc": "1970-01-01T00:00:00+00:00",
        "persisted_receipt_claimed": False,
        "partial_static_staging_or_final_state_possible": True,
        "required_next_action": "INDEPENDENT_FILESYSTEM_AUDIT_NO_RERUN",
        "production_command": None,
        "signer_authority": None,
        "go_authority": None,
        "production_authority_granted": False,
        "signer_launch_count": 0,
        "authority_issuance_count": 0,
        "qualification_generation_count": 0,
        "fresh_truth_heldout_access_count": 0,
    }
    return {
        **payload,
        "receipt_bundle_raw_sha256": sha256_bytes(canonical_json_bytes(payload)),
    }


def main() -> int:
    if sys.argv != [
        sys.argv[0],
        "--freeze-r8-r7-static-design-source-no-signer-no-phase2-no-fresh",
    ]:
        return 64
    try:
        result = freeze()
    except BaseException:
        result = _builder_terminal_in_memory_no_go()
        sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
        return 78
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
