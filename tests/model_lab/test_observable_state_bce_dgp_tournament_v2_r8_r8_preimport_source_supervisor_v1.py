from __future__ import annotations

import ast
import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
from typing import Any

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_preimport_source_supervisor_v1.contract import (
    CHILD_PYCACHE_PREFIX,
    MANIFEST_RAW_SHA256,
    MANIFEST_RELATIVE,
    MANIFEST_SIZE_BYTES,
    PINNED_VENV_PYTHON,
    PROJECT_ROOT,
    R8_SOURCE_LOCK_RAW_SHA256,
    RECORDS_119_SEMANTIC_SHA256,
    STUB_RAW_SHA256,
    STUB_RELATIVE,
    STUB_SIZE_BYTES,
    SUPERVISOR_CLAIM_PREFIX,
    SUPERVISOR_FILE_ID_128,
    SUPERVISOR_RAW_SHA256,
    SUPERVISOR_RELATIVE,
    SUPERVISOR_SIZE_BYTES,
    SUPERVISOR_VOLUME_SERIAL_NUMBER,
    SupervisorContractError,
    consume_test_identity_once,
    derive_fixed_119_records,
    exact_freezer_command,
    load_closure_manifest,
    require_no_python_environment_controls,
    validate_candidate_bytes,
    validate_live_records,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_static_design_v1.filesystem_identity import (
    SupervisorArchiveCustody,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (
    build_source_lock_bytes,
)


SUPERVISOR_PATH = PROJECT_ROOT / SUPERVISOR_RELATIVE
STUB_PATH = PROJECT_ROOT / STUB_RELATIVE
MANIFEST_PATH = PROJECT_ROOT / MANIFEST_RELATIVE
DESIGN_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)
R7_SOURCE_LOCK = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_"
    "qualification_generation/SOURCE_LOCK.json"
)


def _load_supervisor() -> Any:
    spec = importlib.util.spec_from_file_location(
        "r8r8_preimport_source_supervisor_test", SUPERVISOR_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _environment_without_python() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }


def test_manifest_derives_exact_current_117_plus_two_records() -> None:
    manifest = load_closure_manifest()
    r7_raw = R7_SOURCE_LOCK.read_bytes()
    records = derive_fixed_119_records(
        manifest=manifest, r7_source_lock_raw=r7_raw
    )
    current_raw = build_source_lock_bytes()
    assert hashlib.sha256(current_raw).hexdigest() == R8_SOURCE_LOCK_RAW_SHA256
    current = json.loads(current_raw)
    assert len(current["source_sha256"]) == 117
    assert [list(row) for row in records[:0]] == []
    source_rows = {
        tuple(row) for row in records if row[0] not in {
            manifest["outer_bootstrap_record"][0],
            manifest["r7_source_lock_record"][0],
        }
    }
    assert source_rows == {tuple(row) for row in current["source_sha256"]}
    assert len(records) == 119


def test_all_119_live_paths_hash_size_and_semantic_match() -> None:
    manifest = load_closure_manifest()
    records = derive_fixed_119_records(
        manifest=manifest, r7_source_lock_raw=R7_SOURCE_LOCK.read_bytes()
    )
    receipt = validate_live_records(records)
    assert receipt == {
        "status": "PASS_119_LIVE_SOURCE_RECORDS_MATCH",
        "record_count": 119,
        "records_semantic_sha256": RECORDS_119_SEMANTIC_SHA256,
    }


def test_all_119_sources_are_held_simultaneously_and_reverify() -> None:
    supervisor = _load_supervisor()
    owners = supervisor._CheckedOwners()
    try:
        held, receipt = supervisor._hold_fixed_closure(owners)
        assert len(held) == 119
        assert receipt["source_record_count"] == 119
        assert receipt["records_semantic_sha256"] == RECORDS_119_SEMANTIC_SHA256
        assert receipt["all_handles_still_open"] is True
        assert [item.verify() for item in held] == receipt["records"]
    finally:
        owners.close()
    assert len(owners.closed_labels) == 120


def test_manifest_raw_pin_and_zero_authority_are_exact() -> None:
    raw = MANIFEST_PATH.read_bytes()
    assert len(raw) == MANIFEST_SIZE_BYTES
    assert hashlib.sha256(raw).hexdigest() == MANIFEST_RAW_SHA256
    payload = json.loads(raw)
    assert payload["total_record_count"] == 119
    assert payload["authority_generation_fresh_truth_signer_counts"] == {
        "authority": 0,
        "fresh": 0,
        "generation": 0,
        "signer": 0,
        "truth": 0,
    }


def test_transient_source_substitution_fails_hash_validation(tmp_path: Path) -> None:
    target = tmp_path / "source.py"
    target.write_bytes(b"trusted\n")
    record = ["source.py", hashlib.sha256(b"trusted\n").hexdigest(), 8]
    target.write_bytes(b"attack!\n")
    with pytest.raises(SupervisorContractError, match="live source record drifted"):
        validate_live_records((record,), project_root=tmp_path)


def test_held_file_denies_write_delete_and_replace_until_close(
    tmp_path: Path,
) -> None:
    supervisor = _load_supervisor()
    target = tmp_path / "held.txt"
    target.write_bytes(b"held")
    custody = supervisor._HeldFile(
        path=target,
        expected_sha256=hashlib.sha256(b"held").hexdigest(),
        expected_size=4,
    )
    attacker = tmp_path / "attacker.txt"
    attacker.write_bytes(b"evil")
    with pytest.raises(OSError) as replace_error:
        os.replace(attacker, target)
    assert replace_error.value.winerror == 32
    with pytest.raises(OSError) as delete_error:
        target.unlink()
    assert delete_error.value.winerror == 32
    with pytest.raises(OSError) as write_error:
        target.write_bytes(b"evil")
    assert (
        write_error.value.winerror == 32
        or isinstance(write_error.value, PermissionError)
        and write_error.value.errno == 13
    )
    assert custody.verify()["write_share_allowed"] is False
    custody.close()
    target.unlink()


def test_reparse_ancestry_wrong_case_and_unsafe_relative_are_rejected(
    tmp_path: Path,
) -> None:
    supervisor = _load_supervisor()
    actual = tmp_path / "CaseDir"
    actual.mkdir()
    leaf = actual / "Source.PY"
    leaf.write_bytes(b"x")
    with pytest.raises(supervisor.SupervisorError, match="exact lexical path case"):
        supervisor._HeldFile(
            path=tmp_path / "casedir" / "source.py",
            expected_sha256=hashlib.sha256(b"x").hexdigest(),
            expected_size=1,
        )
    target = tmp_path / "junction_target"
    target.mkdir()
    (target / "source.py").write_bytes(b"x")
    junction = tmp_path / "junction"
    completed = subprocess.run(
        ("cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
        text=True,
    )
    if completed.returncode == 0:
        with pytest.raises(supervisor.SupervisorError, match="reparse ancestry"):
            supervisor._HeldFile(
                path=junction / "source.py",
                expected_sha256=hashlib.sha256(b"x").hexdigest(),
                expected_size=1,
            )
    manifest = load_closure_manifest()
    attacked = dict(manifest)
    attacked["r8_delta_rows"] = [
        *manifest["r8_delta_rows"][:-1],
        ["../escape.py", "0" * 64, 0],
    ]
    with pytest.raises(SupervisorContractError, match="record value drifted"):
        derive_fixed_119_records(
            manifest=attacked, r7_source_lock_raw=R7_SOURCE_LOCK.read_bytes()
        )


@pytest.mark.parametrize(
    "name",
    ["PYTHONPATH", "pythonpath", "PyThOnHaShSeEd", "PYTHONPYCACHEPREFIX"],
)
def test_every_case_insensitive_python_environment_control_is_rejected(
    name: str,
) -> None:
    with pytest.raises(SupervisorContractError, match="controls are forbidden"):
        require_no_python_environment_controls({name: "attack", "SYSTEMROOT": "x"})


def test_fixed_child_command_rejects_caller_prefix() -> None:
    command = exact_freezer_command()
    assert command[0] == str(PINNED_VENV_PYTHON)
    assert command[1:7] == (
        "-I",
        "-S",
        "-B",
        "-E",
        "-X",
        f"pycache_prefix={CHILD_PYCACHE_PREFIX}",
    )
    with pytest.raises(SupervisorContractError, match="caller-selected"):
        exact_freezer_command(pycache_prefix=CHILD_PYCACHE_PREFIX.parent / "attack")


def test_stdlib_child_prefix_is_create_new_held_empty_and_consumed(
    tmp_path: Path,
) -> None:
    supervisor = _load_supervisor()
    prefix = supervisor._HeldCreatedDirectory(
        parent=tmp_path,
        child_name="synthetic_child_prefix",
    )
    receipt = prefix.verify()
    assert receipt["direct_child_entry_count"] == 0
    assert receipt["create_disposition"] == "FILE_CREATE"
    assert receipt["write_share_allowed"] is False
    assert receipt["delete_share_allowed"] is False
    (prefix.path / "attack.pyc").write_bytes(b"attack")
    with pytest.raises(supervisor.SupervisorError, match="is not empty"):
        prefix.verify()
    prefix.close()
    with pytest.raises(supervisor.SupervisorError, match="create-new failed"):
        supervisor._HeldCreatedDirectory(
            parent=tmp_path,
            child_name="synthetic_child_prefix",
        )


def test_child_stdout_requires_one_canonical_freezer_receipt() -> None:
    supervisor = _load_supervisor()
    payload = {
        "schema_version": "expected_pe.r8.r8.static_one_shot_freeze_receipt.v2",
        "status": "FROZEN_NO_GO_PENDING_DIFFERENT_INDEPENDENT_POST_FREEZE_AUDIT",
        "source_lock_raw_sha256": R8_SOURCE_LOCK_RAW_SHA256,
        "held_source_record_count": 119,
        "production_execution_authorized": False,
        "authority_generation_fresh_truth_signer_counts": {
            "authority": 0,
            "fresh": 0,
            "generation": 0,
            "signer": 0,
            "truth": 0,
        },
    }
    raw = supervisor._canonical(payload) + b"\n"
    assert supervisor._parse_freezer_stdout(raw) == payload
    with pytest.raises(supervisor.SupervisorError, match="one bounded canonical"):
        supervisor._parse_freezer_stdout(raw + raw)
    with pytest.raises(supervisor.SupervisorError, match="semantics drifted"):
        supervisor._parse_freezer_stdout(
            supervisor._canonical({**payload, "held_source_record_count": 118})
            + b"\n"
        )


def test_direct_path_and_extra_interpreter_flag_invocations_fail_before_main() -> None:
    before = tuple(path.exists() for path in (SUPERVISOR_CLAIM_PREFIX, CHILD_PYCACHE_PREFIX, DESIGN_ROOT))
    assert before == (False, False, False)
    for extra in ((), ("-O",), ("-X", "dev")):
        completed = subprocess.run(
            (
                str(PINNED_VENV_PYTHON),
                "-I",
                "-S",
                "-B",
                "-E",
                *extra,
                str(SUPERVISOR_PATH),
            ),
            cwd=PROJECT_ROOT,
            env=_environment_without_python(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
            text=True,
        )
        assert completed.returncode != 0
        assert "DENIED_DIRECT_PATH_INVOCATION" in completed.stderr
    assert tuple(path.exists() for path in (SUPERVISOR_CLAIM_PREFIX, CHILD_PYCACHE_PREFIX, DESIGN_ROOT)) == before


def test_injected_supervisor_hash_and_size_fail_closed() -> None:
    raw = SUPERVISOR_PATH.read_bytes()
    validate_candidate_bytes(
        raw,
        expected_sha256=SUPERVISOR_RAW_SHA256,
        expected_size=SUPERVISOR_SIZE_BYTES,
    )
    with pytest.raises(SupervisorContractError, match="candidate hash drifted"):
        validate_candidate_bytes(
            raw,
            expected_sha256="0" * 64,
            expected_size=SUPERVISOR_SIZE_BYTES,
        )
    with pytest.raises(SupervisorContractError, match="candidate hash drifted"):
        validate_candidate_bytes(
            raw,
            expected_sha256=SUPERVISOR_RAW_SHA256,
            expected_size=SUPERVISOR_SIZE_BYTES + 1,
        )


def test_supervisor_file_id_pin_and_stdlib_stub_raw_pin() -> None:
    raw = SUPERVISOR_PATH.read_bytes()
    assert len(raw) == SUPERVISOR_SIZE_BYTES
    assert hashlib.sha256(raw).hexdigest() == SUPERVISOR_RAW_SHA256
    with SupervisorArchiveCustody(
        path=SUPERVISOR_PATH, root=Path(SUPERVISOR_PATH.anchor)
    ) as custody:
        receipt = custody.receipt()
        assert receipt["volume_serial_number"] == SUPERVISOR_VOLUME_SERIAL_NUMBER
        assert receipt["file_id_128"] == SUPERVISOR_FILE_ID_128
        assert receipt["write_share_allowed"] is False
        assert receipt["delete_share_allowed"] is False
    stub = STUB_PATH.read_bytes()
    assert len(stub) == STUB_SIZE_BYTES
    assert hashlib.sha256(stub).hexdigest() == STUB_RAW_SHA256
    ast.parse(stub, filename=str(STUB_PATH))
    text = stub.decode("ascii")
    assert f'SUPERVISOR_SHA="{SUPERVISOR_RAW_SHA256}"' in text
    assert f'SUPERVISOR_FILE_ID="{SUPERVISOR_FILE_ID_128}"' in text
    assert "NtCreateFile" in text
    assert "compile(raw,SUPERVISOR" in text


def test_preexisting_timestamp_pyc_cannot_trigger_any_project_import(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supervisor = _load_supervisor()
    attacked_cache = tmp_path / (
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r8_"
        "qualification_generation/__pycache__"
    )
    attacked_cache.mkdir(parents=True)
    attack_pyc = attacked_cache / "no_bytecode.cpython-310.pyc"
    attack_pyc.write_bytes(b"preexisting-timestamp-pyc-attack")
    preexisting_prefix = tmp_path / "synthetic_preexisting_prefix"
    (preexisting_prefix / "__pycache__").mkdir(parents=True)
    (preexisting_prefix / "__pycache__" / "attack.pyc").write_bytes(b"attack")
    with pytest.raises(supervisor.SupervisorError, match="create-new failed"):
        supervisor._HeldCreatedDirectory(
            parent=tmp_path,
            child_name=preexisting_prefix.name,
        )

    original_import = builtins.__import__

    def deny_project_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "research" or name.startswith("research."):
            raise AssertionError(f"project import attempted: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", deny_project_import)
    prefix = supervisor._HeldCreatedDirectory(
        parent=tmp_path,
        child_name="synthetic_no_import_prefix",
    )
    prefix.close()
    assert attack_pyc.read_bytes() == b"preexisting-timestamp-pyc-attack"


def test_supervisor_ast_has_zero_project_import_and_live_main_is_not_called() -> None:
    source = SUPERVISOR_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)
    import_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert import_roots <= {
        "__future__",
        "ctypes",
        "hashlib",
        "json",
        "os",
        "pathlib",
        "stat",
        "subprocess",
        "sys",
        "threading",
        "time",
        "typing",
    }
    assert "research" not in import_roots
    assert "sys.path" not in source
    assert "HeldNoBytecodeWindow" not in source
    assert "authority_minted\": False" in source
    assert "_STUB_SOURCE_HANDLE\" not in globals()" in source


def test_cleanup_attempts_all_owners_and_failure_identity_is_consumed(
    tmp_path: Path,
) -> None:
    supervisor = _load_supervisor()
    calls: list[str] = []

    class Owner:
        def __init__(self, name: str, fail: bool) -> None:
            self.name = name
            self.fail = fail

        def close(self) -> None:
            calls.append(self.name)
            if self.fail:
                raise RuntimeError(self.name)

    owners = supervisor._CheckedOwners()
    owners.own("one", Owner("one", True))
    owners.own("two", Owner("two", False))
    owners.own("three", Owner("three", True))
    with pytest.raises(supervisor.SupervisorError, match="2 cleanup operation"):
        owners.close()
    assert calls == ["three", "two", "one"]
    consumed = consume_test_identity_once(tmp_path, "synthetic_attempt")
    assert consumed.is_dir()
    with pytest.raises(FileExistsError):
        consume_test_identity_once(tmp_path, "synthetic_attempt")


def test_scoped_tests_created_no_production_identity() -> None:
    assert not SUPERVISOR_CLAIM_PREFIX.exists()
    assert not CHILD_PYCACHE_PREFIX.exists()
    assert not DESIGN_ROOT.exists()
