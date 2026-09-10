from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v2.contract import (
    CHILD_PYCACHE_PREFIX,
    MANIFEST_RAW_SHA256,
    MANIFEST_RELATIVE,
    MANIFEST_SIZE_BYTES,
    PINNED_VENV_PYTHON,
    PROJECT_ROOT,
    R8_SOURCE_LOCK_RAW_SHA256,
    RECORDS_119_SEMANTIC_SHA256,
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
    derive_fixed_119_records,
    load_closure_manifest,
    require_no_python_environment_controls,
    validate_live_records,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.no_bytecode import (
    HeldExistingNoBytecodeWindow,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (
    build_source_lock_bytes,
)


SCRIPT_ROOT = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v2"
)
SUPERVISOR_PATH = PROJECT_ROOT / SUPERVISOR_RELATIVE
TEMPLATE_PATH = PROJECT_ROOT / STUB_TEMPLATE_RELATIVE
RUNTIME_PATH = PROJECT_ROOT / RUNTIME_CLOSURE_RELATIVE
MANIFEST_PATH = PROJECT_ROOT / MANIFEST_RELATIVE
BUILDER_PATH = SCRIPT_ROOT / "build_static_child_runtime_closure.py"
R7_SOURCE_LOCK = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_"
    "qualification_generation/SOURCE_LOCK.json"
)
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)


def _load(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _supervisor() -> Any:
    return _load(SUPERVISOR_PATH, "r8r8_preimport_supervisor_v2_test")


def _clean_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }


def test_v1_and_authoritative_r8_sources_are_byte_preserved() -> None:
    expected = {
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v1/__init__.py": (
            "6bcd195457ba0a2acb099353e4bccb4ecbd1aca623c51a43c6ab57145f143838"
        ),
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v1/contract.py": (
            "911e65a1e16e7785359d52356d46078f17853cea1a6e159c54f3c02b629ec7e1"
        ),
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v1/SOURCE_CLOSURE_MANIFEST.json": (
            "b2d51e5885f6ef1e48c35dcd3b890edab21a1fc9c3bd9d8968a81416bacf6f0a"
        ),
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v1/STDLIB_LAUNCH_STUB.txt": (
            "6bf8a76b2846b90f859dc3fd26f3f2b721f1d47bd60a265206841ec8348a6e9a"
        ),
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v1/trusted_supervisor.py": (
            "dc85fdaf2545e90e8f60753709a87e328012c7dcff3f4165e51913d2c7efe7ea"
        ),
        "tests/model_lab/test_observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v1.py": (
            "249c022f39bdf2756314692f69521127d790aad4bd7af2c09e8c2bd095cbc4c7"
        ),
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation/freeze_static_evidence.py": (
            "8afb4e486219ef816eb6d99ec3011827f328e22ecd507ae0ae8d9984fa1b3310"
        ),
        "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation/trusted_bootstrap.py": (
            "6a48af9b5c1b557d63e312558490c0af2bd1a3ddc8c332505d51bc81a4d8aba7"
        ),
    }
    assert {
        relative: hashlib.sha256((PROJECT_ROOT / relative).read_bytes()).hexdigest()
        for relative in expected
    } == expected


def test_source_manifest_derives_exact_live_119_and_current_lock() -> None:
    raw = MANIFEST_PATH.read_bytes()
    assert len(raw) == MANIFEST_SIZE_BYTES
    assert hashlib.sha256(raw).hexdigest() == MANIFEST_RAW_SHA256
    manifest = load_closure_manifest()
    records = derive_fixed_119_records(
        manifest=manifest,
        r7_source_lock_raw=R7_SOURCE_LOCK.read_bytes(),
    )
    assert validate_live_records(records) == {
        "status": "PASS_119_LIVE_SOURCE_RECORDS_MATCH",
        "record_count": 119,
        "records_semantic_sha256": RECORDS_119_SEMANTIC_SHA256,
    }
    assert hashlib.sha256(build_source_lock_bytes()).hexdigest() == R8_SOURCE_LOCK_RAW_SHA256


def test_runtime_closure_is_byte_identical_to_fixed_source_build() -> None:
    builder = _load(BUILDER_PATH, "r8r8_runtime_closure_builder_test")
    payload = builder.build_payload()
    expected_raw = builder._canonical(payload) + b"\n"
    actual_raw = RUNTIME_PATH.read_bytes()
    assert actual_raw == expected_raw
    assert len(actual_raw) == RUNTIME_CLOSURE_SIZE_BYTES
    assert hashlib.sha256(actual_raw).hexdigest() == RUNTIME_CLOSURE_RAW_SHA256
    assert payload["runtime_record_count"] == RUNTIME_RECORD_COUNT == 298
    assert payload["runtime_records_semantic_sha256"] == RUNTIME_RECORDS_SEMANTIC_SHA256
    assert sum(row["size_bytes"] for row in payload["runtime_records"]) == 185688713


def test_source_and_runtime_dual_custody_hold_and_reverify() -> None:
    supervisor = _supervisor()
    owners = supervisor._CheckedOwners()
    try:
        sources, source_receipt = supervisor._hold_fixed_closure(owners)
        runtime, executable, runtime_receipt = supervisor._hold_runtime_closure(owners)
        assert len(sources) == 119
        assert len(runtime) == 298
        assert len(owners._items) == 419
        assert [item.verify() for item in sources] == source_receipt["records"]
        assert [item.verify() for item in runtime] == runtime_receipt["runtime_receipts"]
        assert executable.path == PINNED_VENV_PYTHON
    finally:
        owners.close()
    assert len(owners.closed_labels) == 419


def test_stub_template_full_reconstruction_has_no_self_report() -> None:
    supervisor = _supervisor()
    raw = SUPERVISOR_PATH.read_bytes()
    custody = supervisor._HeldFile(
        path=SUPERVISOR_PATH,
        expected_sha256=SUPERVISOR_RAW_SHA256,
        expected_size=SUPERVISOR_SIZE_BYTES,
    )
    try:
        assert custody.volume_serial_number == SUPERVISOR_VOLUME_SERIAL_NUMBER
        assert custody.file_id_128 == SUPERVISOR_FILE_ID_128
        template = TEMPLATE_PATH.read_bytes()
        assert hashlib.sha256(template).hexdigest() == STUB_TEMPLATE_RAW_SHA256
        assert len(template) == STUB_TEMPLATE_SIZE_BYTES
        rendered = supervisor._render_stub_template(
            template,
            supervisor_raw_sha256=SUPERVISOR_RAW_SHA256,
            supervisor_size_bytes=SUPERVISOR_SIZE_BYTES,
            supervisor_volume_serial_number=SUPERVISOR_VOLUME_SERIAL_NUMBER,
            supervisor_file_id_128=SUPERVISOR_FILE_ID_128,
        )
        ast.parse(rendered, filename="audited-rendered-stdlib-stub")
        text = rendered.decode("ascii")
        assert f'SUPERVISOR_SHA="{SUPERVISOR_RAW_SHA256}"' in text
        assert f"SUPERVISOR_SIZE={SUPERVISOR_SIZE_BYTES}" in text
        assert f'SUPERVISOR_FILE_ID="{SUPERVISOR_FILE_ID_128}"' in text
        assert "__SUPERVISOR_" not in text
        assert "_STUB_RAW_SHA256" not in text
        assert "_STUB_RAW_SHA256" not in SUPERVISOR_PATH.read_text(encoding="utf-8")
    finally:
        custody.close()


def test_mutated_template_cannot_enter_pinned_custody(tmp_path: Path) -> None:
    supervisor = _supervisor()
    attacked = tmp_path / "STDLIB_LAUNCH_STUB_TEMPLATE.txt"
    attacked.write_bytes(TEMPLATE_PATH.read_bytes() + b"print('attack')\n")
    with pytest.raises(supervisor.SupervisorError, match="identity/hash changed"):
        supervisor._HeldFile(
            path=attacked,
            expected_sha256=STUB_TEMPLATE_RAW_SHA256,
            expected_size=STUB_TEMPLATE_SIZE_BYTES,
        )


def test_template_and_runtime_manifest_file_ids_are_pinned() -> None:
    supervisor = _supervisor()
    for path, digest, size, volume, file_id in (
        (
            TEMPLATE_PATH,
            STUB_TEMPLATE_RAW_SHA256,
            STUB_TEMPLATE_SIZE_BYTES,
            STUB_TEMPLATE_VOLUME_SERIAL_NUMBER,
            STUB_TEMPLATE_FILE_ID_128,
        ),
        (
            RUNTIME_PATH,
            RUNTIME_CLOSURE_RAW_SHA256,
            RUNTIME_CLOSURE_SIZE_BYTES,
            supervisor.RUNTIME_CLOSURE_VOLUME_SERIAL_NUMBER,
            supervisor.RUNTIME_CLOSURE_FILE_ID_128,
        ),
    ):
        held = supervisor._HeldFile(
            path=path,
            expected_sha256=digest,
            expected_size=size,
        )
        try:
            assert (held.volume_serial_number, held.file_id_128) == (volume, file_id)
        finally:
            held.close()


def test_protected_dacl_denies_same_user_separate_process_mutations(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor()
    held = supervisor._HeldCreatedDirectory(
        parent=tmp_path,
        child_name="synthetic_protected_prefix",
    )
    child_code = """import json,os,pathlib,sys
p=pathlib.Path(sys.argv[1]);q=p.with_name('renamed');out={}
try: out['list']=os.listdir(p)
except OSError as e: out['list']=['ERR',e.winerror,e.errno]
for name,op in (('file',lambda:(p/'x.pyc').write_bytes(b'x')),('subdir',lambda:(p/'sub').mkdir()),('rename',lambda:p.rename(q)),('delete',lambda:p.rmdir())):
 try: op();out[name]='ALLOWED'
 except OSError as e: out[name]=['DENIED',e.winerror,e.errno]
print(json.dumps(out,sort_keys=True))"""
    try:
        completed = subprocess.run(
            (
                str(PINNED_VENV_PYTHON),
                "-I",
                "-B",
                "-E",
                "-c",
                child_code,
                str(held.path),
            ),
            env=_clean_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            text=True,
        )
        assert completed.returncode == 0
        assert completed.stderr == ""
        result = json.loads(completed.stdout)
        assert result["list"] == []
        for operation in ("file", "subdir", "rename", "delete"):
            assert result[operation][0] == "DENIED"
            assert result[operation][1] in {None, 5, 32}
        assert held.verify()["dacl_continuity"] is True
    finally:
        held.restore_test_cleanup_dacl()
        held.close()
    held.path.rmdir()


def test_unchanged_freezer_borrowed_prefix_accepts_protected_dacl(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor()
    held = supervisor._HeldCreatedDirectory(
        parent=tmp_path,
        child_name="synthetic_borrowed_prefix",
    )
    try:
        with HeldExistingNoBytecodeWindow(
            path=held.path,
            ancestry_root=Path(held.path.anchor),
        ) as borrowed:
            receipt = borrowed.receipt()
        assert receipt["postrun_entry_count"] == 0
        assert receipt["held_before"]["file_id_128"] == held.file_id_128
        assert receipt["held_after"]["file_id_128"] == held.file_id_128
        assert held.verify()["dacl_continuity"] is True
    finally:
        held.restore_test_cleanup_dacl()
        held.close()
    held.path.rmdir()


def test_preexisting_prefix_with_timestamp_pyc_is_consumed_no_retry(
    tmp_path: Path,
) -> None:
    supervisor = _supervisor()
    prefix = tmp_path / "synthetic_preexisting_prefix"
    (prefix / "__pycache__").mkdir(parents=True)
    (prefix / "__pycache__" / "attack.cpython-310.pyc").write_bytes(b"attack")
    with pytest.raises(supervisor.SupervisorError, match="create-new failed"):
        supervisor._HeldCreatedDirectory(parent=tmp_path, child_name=prefix.name)


def test_held_process_image_and_creation_identity_survive_exit() -> None:
    supervisor = _supervisor()
    payload = json.loads(RUNTIME_PATH.read_bytes())
    row = next(
        item
        for item in payload["runtime_records"]
        if os.path.normcase(item["final_path"])
        == os.path.normcase(str(PINNED_VENV_PYTHON))
    )
    executable = supervisor._HeldFile(
        path=PINNED_VENV_PYTHON,
        expected_sha256=row["raw_sha256"],
        expected_size=row["size_bytes"],
    )
    process = subprocess.Popen(
        (
            str(PINNED_VENV_PYTHON),
            "-I",
            "-B",
            "-E",
            "-c",
            "import time;time.sleep(0.25)",
        ),
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
    )
    try:
        before = supervisor._capture_process_evidence(process, executable)
        stdout, stderr = process.communicate(timeout=10)
        after = supervisor._verify_process_evidence_after_exit(
            process,
            before,
            executable,
        )
        assert process.returncode == 0
        assert stdout == stderr == b""
        assert before["same_as_held_venv_executable"] is True
        assert after["creation_time_100ns"] == before["creation_time_100ns"]
        assert after["held_executable_identity_unchanged"] is True
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        executable.close()


@pytest.mark.parametrize("name", ["PYTHONPATH", "pythonpath", "PyThOnHaShSeEd"])
def test_case_insensitive_python_environment_is_rejected(name: str) -> None:
    with pytest.raises(RuntimeError, match="controls are forbidden"):
        require_no_python_environment_controls({name: "attack", "SYSTEMROOT": "x"})


def test_direct_invocation_denied_and_production_identities_absent() -> None:
    before = tuple(
        path.exists()
        for path in (SUPERVISOR_CLAIM_PREFIX, CHILD_PYCACHE_PREFIX, DESIGN_ROOT)
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
        env=_clean_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        text=True,
    )
    assert completed.returncode != 0
    assert "DENIED_DIRECT_PATH_INVOCATION" in completed.stderr
    assert tuple(
        path.exists()
        for path in (SUPERVISOR_CLAIM_PREFIX, CHILD_PYCACHE_PREFIX, DESIGN_ROOT)
    ) == before


def test_supervisor_ast_has_no_project_import_or_caller_control() -> None:
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
    assert "_STUB_RAW_SHA256" not in source
    assert "caller_selected_path_count" in source
    assert "authority_minted\": False" in source
    assert "_STUB_SOURCE_HANDLE\" not in globals()" in source


def test_no_production_or_bytecode_identity_was_created() -> None:
    assert not SUPERVISOR_CLAIM_PREFIX.exists()
    assert not CHILD_PYCACHE_PREFIX.exists()
    assert not DESIGN_ROOT.exists()
    assert not Path(f"{DESIGN_ROOT}.staging").exists()
    for root in (
        SCRIPT_ROOT,
        PROJECT_ROOT
        / "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "preimport_source_supervisor_v2",
    ):
        assert not any(
            item.name == "__pycache__" or item.suffix in {".pyc", ".pyo"}
            for item in root.rglob("*")
        )
