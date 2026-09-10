from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v3.contract import (  # noqa: E402
    CHILD_PYCACHE_PREFIX,
    MANIFEST_RAW_SHA256,
    MANIFEST_RELATIVE,
    MANIFEST_SIZE_BYTES,
    PINNED_VENV_PYTHON,
    RUNTIME_CLOSURE_RAW_SHA256,
    RUNTIME_CLOSURE_RELATIVE,
    RUNTIME_CLOSURE_SIZE_BYTES,
    RUNTIME_RECORD_COUNT,
    RUNTIME_RECORDS_SEMANTIC_SHA256,
    STUB_TEMPLATE_FILE_ID_128,
    STUB_TEMPLATE_RAW_SHA256,
    STUB_TEMPLATE_RELATIVE,
    STUB_TEMPLATE_SIZE_BYTES,
    STUB_TEMPLATE_VOLUME_SERIAL_NUMBER,
    SUPERVISOR_CLAIM_PREFIX,
    SUPERVISOR_FILE_ID_128,
    SUPERVISOR_RAW_SHA256,
    SUPERVISOR_RELATIVE,
    SUPERVISOR_SIZE_BYTES,
    SUPERVISOR_VOLUME_SERIAL_NUMBER,
    canonical_json_bytes,
    derive_fixed_119_records,
    load_closure_manifest,
    sha256_bytes,
    validate_live_records,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v3.contract import (
    PROJECT_ROOT as CONTRACT_PROJECT_ROOT,
)

SCRIPT_ROOT = PROJECT_ROOT / Path(RUNTIME_CLOSURE_RELATIVE).parent
SUPERVISOR_PATH = PROJECT_ROOT / SUPERVISOR_RELATIVE
RUNTIME_PATH = PROJECT_ROOT / RUNTIME_CLOSURE_RELATIVE
MANIFEST_PATH = PROJECT_ROOT / MANIFEST_RELATIVE
TEMPLATE_PATH = PROJECT_ROOT / STUB_TEMPLATE_RELATIVE
BUILDER_PATH = SCRIPT_ROOT / "build_static_child_runtime_closure.py"
R7_SOURCE_LOCK_PATH = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_"
    "qualification_generation/SOURCE_LOCK.json"
)
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _supervisor() -> Any:
    spec = importlib.util.spec_from_file_location(
        "r8r8_preimport_source_supervisor_v3_under_test",
        SUPERVISOR_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _identity(supervisor: Any, path: Path, *, directory: bool = False) -> tuple[int, str]:
    handle = supervisor._open_no_share_write_delete(path, directory=directory)
    try:
        return supervisor._identity(handle)
    finally:
        supervisor._close_checked(handle)


def _fixed_environment(supervisor: Any) -> dict[str, str]:
    return dict(supervisor.FIXED_CHILD_ENVIRONMENT)


def test_contract_source_and_runtime_manifests_are_exact() -> None:
    assert CONTRACT_PROJECT_ROOT == PROJECT_ROOT
    manifest_raw = MANIFEST_PATH.read_bytes()
    assert len(manifest_raw) == MANIFEST_SIZE_BYTES
    assert sha256_bytes(manifest_raw) == MANIFEST_RAW_SHA256
    manifest = load_closure_manifest()
    assert manifest["schema_version"].endswith(".v3")
    records = derive_fixed_119_records(
        manifest=manifest,
        r7_source_lock_raw=R7_SOURCE_LOCK_PATH.read_bytes(),
    )
    assert validate_live_records(records)["record_count"] == 119

    runtime_raw = RUNTIME_PATH.read_bytes()
    assert len(runtime_raw) == RUNTIME_CLOSURE_SIZE_BYTES
    assert sha256_bytes(runtime_raw) == RUNTIME_CLOSURE_RAW_SHA256
    runtime = json.loads(runtime_raw)
    assert runtime["schema_version"].endswith("runtime_closure.v3")
    assert runtime["runtime_record_count"] == RUNTIME_RECORD_COUNT == 2265
    assert len(runtime["runtime_records"]) == RUNTIME_RECORD_COUNT
    assert (
        sha256_bytes(canonical_json_bytes(runtime["runtime_records"]))
        == runtime["runtime_records_semantic_sha256"]
        == RUNTIME_RECORDS_SEMANTIC_SHA256
    )
    assert runtime["directory_record_count"] == 130
    assert len(runtime["directory_records"]) == 130
    assert runtime["absent_paths"] == [r"C:\Users\minsu\anaconda3\envs\myenv\python310.zip"]
    assert runtime["fixed_child_environment"] == {
        "PATH": (
            r"C:\Users\minsu\anaconda3\envs\myenv;"
            r"C:\Users\minsu\anaconda3\envs\myenv\DLLs;"
            r"C:\Users\minsu\anaconda3\envs\myenv\Library\bin;"
            r"C:\Windows\System32;C:\Windows"
        ),
        "SYSTEMROOT": r"C:\Windows",
        "WINDIR": r"C:\Windows",
    }


def test_runtime_manifest_covers_the_full_fixed_search_universe() -> None:
    payload = json.loads(RUNTIME_PATH.read_bytes())
    observed = {
        os.path.normcase(str(Path(row["final_path"]))) for row in payload["runtime_records"]
    }
    base = Path(r"C:\Users\minsu\anaconda3\envs\myenv")
    lib = base / "Lib"
    site = lib / "site-packages"
    expected: set[str] = set()
    expected.update(os.path.normcase(str(path)) for path in base.iterdir() if path.is_file())
    for root in (base / "DLLs", lib, base / "Library/bin"):
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if root == lib:
                try:
                    path.relative_to(site)
                except ValueError:
                    pass
                else:
                    continue
            expected.add(os.path.normcase(str(path)))
    expected.update(
        {
            os.path.normcase(r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\pyvenv.cfg"),
            os.path.normcase(str(PINNED_VENV_PYTHON)),
        }
    )
    system_names = {
        Path(row["final_path"]).name.casefold()
        for row in payload["runtime_records"]
        if row["role"] == "PINNED_SYSTEM_IMAGE"
    }
    assert expected <= observed
    assert "conhost.exe" in system_names
    assert {"python.exe", "python310.dll", "_ctypes.pyd", "libcrypto-3-x64.dll"} <= {
        Path(value).name.casefold() for value in observed
    }
    assert not any(str(site).casefold() in str(Path(value)).casefold() for value in observed)
    for row in payload["directory_records"]:
        if row["protection_required"] is not True:
            continue
        directory = Path(row["final_path"])
        assert {
            os.path.normcase(str(path)) for path in directory.iterdir() if path.is_file()
        } <= observed


def test_runtime_builder_reproduces_the_pinned_manifest_bytes() -> None:
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("PYTHON")
    }
    completed = subprocess.run(
        (
            str(PINNED_VENV_PYTHON),
            "-I",
            "-S",
            "-B",
            "-E",
            str(BUILDER_PATH),
            "--emit-full-static-child-runtime-closure-v3-no-execution",
        ),
        cwd=PROJECT_ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert completed.returncode == 0
    assert completed.stderr == b""
    assert completed.stdout == RUNTIME_PATH.read_bytes()


def test_supervisor_template_and_self_identity_are_pinned() -> None:
    supervisor = _supervisor()
    raw = SUPERVISOR_PATH.read_bytes()
    template = TEMPLATE_PATH.read_bytes()
    assert len(raw) == SUPERVISOR_SIZE_BYTES
    assert hashlib.sha256(raw).hexdigest() == SUPERVISOR_RAW_SHA256
    assert _identity(supervisor, SUPERVISOR_PATH) == (
        SUPERVISOR_VOLUME_SERIAL_NUMBER,
        SUPERVISOR_FILE_ID_128,
    )
    assert len(template) == STUB_TEMPLATE_SIZE_BYTES
    assert hashlib.sha256(template).hexdigest() == STUB_TEMPLATE_RAW_SHA256
    assert _identity(supervisor, TEMPLATE_PATH) == (
        STUB_TEMPLATE_VOLUME_SERIAL_NUMBER,
        STUB_TEMPLATE_FILE_ID_128,
    )
    rendered = supervisor._render_stub_template(
        template,
        supervisor_raw_sha256=SUPERVISOR_RAW_SHA256,
        supervisor_size_bytes=SUPERVISOR_SIZE_BYTES,
        supervisor_volume_serial_number=SUPERVISOR_VOLUME_SERIAL_NUMBER,
        supervisor_file_id_128=SUPERVISOR_FILE_ID_128,
    )
    assert b"__SUPERVISOR_" not in rendered
    compile(rendered, "<fixed-v3-stub>", "exec")


def test_protected_directory_denies_same_user_and_restores_exact_acl() -> None:
    supervisor = _supervisor()
    with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / "build") as temporary:
        directory = Path(temporary)
        (directory / "held.txt").write_bytes(b"fixed")
        volume, file_id = _identity(supervisor, directory, directory=True)
        inventory = supervisor._directory_inventory(directory)
        held = supervisor._HeldProtectedDirectory(
            path=directory,
            expected_volume=volume,
            expected_file_id=file_id,
            expected_child_count=len(inventory),
            expected_children_semantic_sha256=sha256_bytes(_canonical(inventory)),
        )
        child_code = """import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);out={}
for name,op in (('file',lambda:(p/'x').write_bytes(b'x')),('dir',lambda:(p/'d').mkdir())):
 try: op();out[name]='ALLOWED'
 except OSError as exc: out[name]=['DENIED',exc.winerror,exc.errno]
print(json.dumps(out,sort_keys=True))"""
        try:
            completed = subprocess.run(
                (
                    str(PINNED_VENV_PYTHON),
                    "-I",
                    "-S",
                    "-B",
                    "-E",
                    "-c",
                    child_code,
                    str(directory),
                ),
                env=_fixed_environment(supervisor),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=30,
                text=True,
            )
            assert completed.returncode == 0
            result = json.loads(completed.stdout)
            assert result["file"][0] == result["dir"][0] == "DENIED"
            assert held.verify()["dacl"]["dacl_protected"] is True
            restored = held.restore()
            assert restored["original_dacl_access_list_exact_match"] is True
            (directory / "after.txt").write_text("restored", encoding="ascii")
        finally:
            held.close()


def test_preprotected_directory_is_verified_and_restore_is_delegated() -> None:
    supervisor = _supervisor()
    with tempfile.TemporaryDirectory(dir=PROJECT_ROOT / "build") as temporary:
        directory = Path(temporary)
        (directory / "held.txt").write_bytes(b"fixed")
        volume, file_id = _identity(supervisor, directory, directory=True)
        inventory = supervisor._directory_inventory(directory)
        native_handle = supervisor._open_directory_for_dacl(directory)
        native_original = supervisor._OwnedOriginalDacl(native_handle)
        held = None
        try:
            supervisor._apply_exact_dacl(
                native_handle,
                supervisor.PROTECTED_DIRECTORY_READ_ONLY_SDDL,
            )
            held = supervisor._HeldProtectedDirectory(
                path=directory,
                expected_volume=volume,
                expected_file_id=file_id,
                expected_child_count=len(inventory),
                expected_children_semantic_sha256=sha256_bytes(_canonical(inventory)),
            )
            active = held.verify()
            assert active["external_native_protection"] is True
            delegated = held.restore()
            assert delegated == {
                "dacl_restore_delegated_to_native_launcher": True,
                "dacl_restored": False,
                "external_native_protection": True,
                "file_id_128": file_id,
                "final_path": str(directory),
                "protected_dacl": active["dacl"],
                "volume_serial_number": volume,
            }
        finally:
            if held is not None:
                held.close()
            native_original.restore(native_handle)
            native_original.close()
            supervisor._close_checked(native_handle)
        (directory / "after.txt").write_bytes(b"restored")


def test_full_119_source_and_2265_runtime_custody_roundtrip() -> None:
    supervisor = _supervisor()
    owners = supervisor._CheckedOwners()
    try:
        sources, source_receipt = supervisor._hold_fixed_closure(owners)
        files, executable, directories, runtime_receipt = supervisor._hold_runtime_closure(owners)
        assert len(sources) == 119
        assert len(files) == RUNTIME_RECORD_COUNT
        assert len(directories) == 129
        assert executable.path == PINNED_VENV_PYTHON
        assert source_receipt["status"] == ("PASS_119_SOURCES_HELD_BEFORE_PROJECT_IMPORT")
        assert runtime_receipt["directory_custody"]["status"].startswith("PASS_ALL_USER_WRITABLE")
        restored = [directory.restore() for directory in directories]
        assert len(restored) == 129
        assert all(row["original_dacl_access_list_exact_match"] is True for row in restored)
    finally:
        owners.close(None)


def test_suspended_job_monitor_accepts_only_the_fixed_three_images() -> None:
    supervisor = _supervisor()
    payload = json.loads(RUNTIME_PATH.read_bytes())
    row = next(
        item
        for item in payload["runtime_records"]
        if os.path.normcase(item["final_path"]) == os.path.normcase(str(PINNED_VENV_PYTHON))
    )
    executable = supervisor._HeldFile(
        path=PINNED_VENV_PYTHON,
        expected_sha256=row["raw_sha256"],
        expected_size=row["size_bytes"],
    )
    command = (
        str(PINNED_VENV_PYTHON),
        "-I",
        "-S",
        "-B",
        "-E",
        "-c",
        (
            "import json,time;time.sleep(.15);"
            "print(json.dumps({'ok':True},sort_keys=True,separators=(',',':')))"
        ),
    )
    supervisor.EXACT_CHILD_COMMAND = command
    supervisor._parse_freezer_stdout = lambda raw: json.loads(raw)
    try:
        receipt = supervisor._run_child(
            command,
            _fixed_environment(supervisor),
            executable,
        )
    finally:
        executable.close()
    assert receipt["exit_code"] == 0
    assert receipt["child_freezer_receipt"] == {"ok": True}
    job = receipt["job"]
    assert job["assigned_while_suspended"] is True
    assert job["resumed_only_after_job_and_monitor_ready"] is True
    assert job["total_processes_exactly_three"] is True
    assert job["monitor"]["observed_process_image_set_exact_match"] is True


def test_direct_path_invocation_is_denied_without_consuming_identities() -> None:
    before = tuple(
        path.exists() for path in (SUPERVISOR_CLAIM_PREFIX, CHILD_PYCACHE_PREFIX, DESIGN_ROOT)
    )
    assert before == (False, False, False)
    completed = subprocess.run(
        (
            str(PINNED_VENV_PYTHON),
            "-I",
            "-S",
            "-B",
            "-E",
            str(SUPERVISOR_PATH),
        ),
        cwd=PROJECT_ROOT,
        env={
            key: value for key, value in os.environ.items() if not key.upper().startswith("PYTHON")
        },
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
        text=True,
    )
    assert completed.returncode != 0
    assert "DENIED_DIRECT_PATH_INVOCATION" in completed.stderr
    assert (
        tuple(
            path.exists() for path in (SUPERVISOR_CLAIM_PREFIX, CHILD_PYCACHE_PREFIX, DESIGN_ROOT)
        )
        == before
    )


def test_supervisor_ast_is_fixed_stdlib_only_and_fail_closed() -> None:
    source = SUPERVISOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "research" not in imported_roots
    assert "sys.path" not in source
    assert "CREATE_SUSPENDED" in source
    assert "AssignProcessToJobObject" in source
    assert "PROTECTED_DIRECTORY_READ_ONLY_SDDL" in source
    assert "FIXED_CHILD_ENVIRONMENT" in source
    assert "dynamic_production_discovery" in source
    assert 'authority_minted": False' in source


@pytest.mark.parametrize("forbidden", ["PYTHONPATH", "pythonhashseed", "PyThOnHoMe"])
def test_case_insensitive_python_environment_controls_are_rejected(
    forbidden: str,
) -> None:
    supervisor = _supervisor()
    original = dict(os.environ)
    try:
        os.environ[forbidden] = "attack"
        with pytest.raises(supervisor.SupervisorError, match="forbidden"):
            supervisor._require_no_python_environment()
    finally:
        os.environ.clear()
        os.environ.update(original)
