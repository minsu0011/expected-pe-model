from __future__ import annotations

import builtins
import hashlib
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
from types import ModuleType
from typing import Any

import pytest

import research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3 as runtime_v3
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3 import (
    ISOLATED_LANE_ID,
    PRODUCTION_EXECUTION_STATUS,
    QualificationRuntimeV3Error,
    SHARED_LANE_ID,
    build_task_manifest_rows,
    contract_bundle_bytes,
    run_isolated_c4_lane,
    run_shared_c1_c3_lane,
    validate_task_manifest_rows,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3 import (
    contracts,
    custody,
    lanes,
    spent,
)


_V1_V2_FROZEN_HASHES = {
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/__init__.py": "cfd5aa88678292ee9691cb12a3e170ba3e01df879dc291e19c3c3a8d490df892",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/contracts.py": "198b5d611edda31d8bd1fb3809eae2a1245795a11da7aaa2f887db227ddfabde",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/lanes.py": "6cef6400f488339f65b9cff04e76fa2f43d49086047d1e247e15927bad04984d",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/monitor.py": "f0a249d4f583b9896e64bb558ef9bd1bf90745be1018c312cac160f06b8fc702",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/DESIGN.md": "9f6c13810e5816c691491bbc51a23bbab0bc48dd77279265765e0bd1fb853e7a",
    "tests/model_lab/test_pe_c1_c4_fresh_qualification_runtime_v1.py": "3d54ab241c3f0edbbdfbc2158b49d0cb0761b45cf8dac2e5d73e3b8847b476cc",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v2/__init__.py": "4d34f84e50839ba003a9b5c480b38bfa8520deb6675af585f721ca6bbab7597d",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v2/contracts.py": "ae7649236242e46c73d639bba9a860814ee938f2c24d9e81729e95799da100bc",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v2/lanes.py": "24a9b3a72fc71dad7211442ae8d9d52a2d910399d1e55a76431292b228ec12a5",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v2/monitor.py": "b992bfc8cd126625d8225bde9465c2ed1a37d7e863f911441d8f679515ca82cb",
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v2/DESIGN.md": "5e0facd8a651db288281a43fb1d15fd7a2b403fd99fc137a000728df6d3729a9",
    "tests/model_lab/test_pe_c1_c4_fresh_qualification_runtime_v2.py": "bb9b52c876ab5763ff67405472817a13d07a445de73c2d19c4bdc9d0e038f812",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _assert_json_primitives(value: object) -> None:
    assert type(value) in {dict, list, str, int, float, bool, type(None)}
    if type(value) is dict:
        assert all(type(key) is str for key in value)
        for nested in value.values():
            _assert_json_primitives(nested)
    elif type(value) is list:
        for nested in value:
            _assert_json_primitives(nested)
    elif type(value) is float:
        assert value == value and value not in {float("inf"), float("-inf")}


def _cold_python(
    code: str,
    *,
    timeout: float = 300.0,
    executable: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONHASHSEED"] = "0"
    return subprocess.run(
        [sys.executable if executable is None else executable, "-I", "-B", "-c", code],
        cwd=_project_root(),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _cold_closure_receipt(lane: str) -> dict[str, object]:
    code = f"""
import json, pathlib, sys
root = pathlib.Path({str(_project_root())!r})
sys.path.insert(0, str(root))
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3.contracts import C4_FIXED_DATA_RECORDS, C4_SOURCE_RECORDS, C4_SYNTHETIC_PACKAGES, SHARED_SOURCE_RECORDS
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3.custody import HeldModuleClosure
if {lane!r} == 'shared':
    closure = HeldModuleClosure(lane_id='shared_c1_c3', project_root=root, source_records=SHARED_SOURCE_RECORDS)
    entries = (
        'research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.resource',
        'research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.core',
        'research.model_zoo.pe_c1_c3_fresh_qualification_service_v1.runtime',
    )
else:
    closure = HeldModuleClosure(lane_id='isolated_c4', project_root=root, source_records=C4_SOURCE_RECORDS, external_records=C4_FIXED_DATA_RECORDS, synthetic_packages=C4_SYNTHETIC_PACKAGES)
    entries = ('research.model_zoo.hofs_v12_fresh_qualification_service_v1.service',)
with closure:
    for entry in entries:
        closure.import_module(entry)
    closure.assert_complete()
    print('RUNTIME_V3_RECEIPT:' + closure.receipt_bytes().decode('utf-8').replace('\\n', ''))
"""
    completed = _cold_python(code)
    assert completed.returncode == 0, completed.stderr
    line = next(
        row for row in completed.stdout.splitlines() if row.startswith("RUNTIME_V3_RECEIPT:")
    )
    return json.loads(line.removeprefix("RUNTIME_V3_RECEIPT:"))


def _run_spent(mode: str) -> dict[str, object]:
    code = f"""
import runpy, pathlib, sys
root = pathlib.Path({str(_project_root())!r})
sys.path.insert(0, str(root))
sys.argv = ['spent.py', {mode!r}]
runpy.run_module('research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3.spent', run_name='__main__')
"""
    executable = None
    if mode == "c4-spent-no-publish":
        executable = (
            "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
        )
    completed = _cold_python(code, timeout=600.0, executable=executable)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_v1_and_v2_failed_audited_attempts_are_byte_preserved() -> None:
    root = _project_root()
    for relative, expected in _V1_V2_FROZEN_HASHES.items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected


class _Poison:
    def __getattribute__(self, name: str) -> Any:
        raise AssertionError(f"denied entry inspected caller input: {name}")

    def __iter__(self):
        raise AssertionError("denied entry iterated caller input")

    def __len__(self) -> int:
        raise AssertionError("denied entry measured caller input")


@pytest.mark.parametrize("entry", [run_shared_c1_c3_lane, run_isolated_c4_lane])
def test_production_entries_deny_before_input_import_or_caller_grant(
    entry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    original_import = builtins.__import__

    def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith(
            (
                "research.model_zoo.pe_c1_c3_fresh_qualification_service_v1",
                "research.model_zoo.hofs_v12_fresh_qualification_service_v1",
                "numpy",
                "pandas",
                "sklearn",
                "lightgbm",
            )
        ):
            imported.append(name)
            raise AssertionError(f"numeric import occurred: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(QualificationRuntimeV3Error, match="denied before input/import"):
        entry(_Poison())
    assert imported == []
    assert tuple(inspect.signature(entry).parameters) == ("tasks",)


def test_denial_is_literal_and_no_grant_minter_or_loader_is_public() -> None:
    assert PRODUCTION_EXECUTION_STATUS.startswith("DENIED_")
    source = inspect.getsource(lanes)
    for forbidden in ("importlib", "sys.modules", "Path(", "signature", "grant["):
        assert forbidden not in source
    public = set(runtime_v3.__all__)
    assert not any(
        token in name.casefold()
        for name in public
        for token in ("grant", "capability", "mint", "custody", "spent", "publish", "monitor")
    )


def test_contract_bundle_is_raw_bytes_and_truthfully_remains_denied() -> None:
    bundle = contract_bundle_bytes()
    assert type(bundle) is tuple and len(bundle) == 6
    assert all(type(raw) is bytes and raw.endswith(b"\n") for raw in bundle)
    parsed = [json.loads(raw) for raw in bundle]
    for payload in parsed:
        _assert_json_primitives(payload)
    assert parsed[-1]["status"] == PRODUCTION_EXECUTION_STATUS
    assert set(parsed[-1]["counts"].values()) == {0}
    parsed[0]["status"] = "tampered"
    assert json.loads(bundle[0])["status"] != "tampered"


def test_source_declaration_is_exact_current_and_excludes_hofs_init_publisher() -> None:
    root = _project_root()
    for records in (contracts.SHARED_SOURCE_RECORDS, contracts.C4_SOURCE_RECORDS):
        for relative, raw_sha256, size_bytes in records:
            raw = (root / relative).read_bytes()
            assert len(raw) == size_bytes
            assert hashlib.sha256(raw).hexdigest() == raw_sha256
    assert len(contracts.SHARED_SOURCE_RECORDS) == 23
    assert len(contracts.C4_SOURCE_RECORDS) == 25
    c4_relatives = {row[0] for row in contracts.C4_SOURCE_RECORDS}
    package = "research/model_zoo/hofs_v12_fresh_qualification_service_v1/"
    assert package + "__init__.py" not in c4_relatives
    assert package + "publisher.py" not in c4_relatives


def test_external_issuer_interface_is_not_caller_selected_or_materialized() -> None:
    payload = json.loads(contracts.issuer_interface_contract_bytes())
    assert payload["status"] == "REQUIRED_NOT_MATERIALIZED_IN_SOURCE_REVISION_V3"
    assert payload["transport"] == (
        "INHERITED_READ_ONLY_SINGLE_MESSAGE_CHANNEL_NOT_CALLER_ARGUMENT"
    )
    assert payload["inherited_channel_count"] == 1
    assert payload["caller_supplied_grant_parameter_allowed"] is False
    assert payload["caller_constructible_capability_allowed"] is False
    assert payload["grant_nonce_single_use_required"] is True
    assert payload["held_channel_and_source_handles_required_through_execution"] is True


def test_task_manifest_exact_50_order_and_bool_attacks() -> None:
    rows = build_task_manifest_rows()
    assert len(rows) == 50
    assert tuple(row[0] for row in rows) == tuple(range(50))
    assert tuple(row[3] for row in rows) == tuple(index % 16 for index in range(50))
    assert tuple(row[1] for row in rows[::10]) == tuple(
        f"qualification_seed_{index:02d}" for index in range(1, 6)
    )
    assert tuple(row[2] for row in rows[:10]) == tuple("ABCDEFGHIJ")
    for column in (0, 3):
        attacked = list(rows)
        mutable = list(attacked[0])
        mutable[column] = True
        attacked[0] = tuple(mutable)
        with pytest.raises(QualificationRuntimeV3Error):
            validate_task_manifest_rows(attacked)
    with pytest.raises(QualificationRuntimeV3Error):
        validate_task_manifest_rows((*rows[:-1], rows[0]))


def test_resource_and_external_boundaries_are_exact_and_not_implemented() -> None:
    resource = json.loads(contracts.resource_contract_bytes())
    shared = resource["shared_lane"]
    isolated = resource["isolated_c4_lane"]
    assert shared["outer_workers"] == 16
    assert shared["worker_slot_to_cpu_ids"] == [
        [2 * slot, 2 * slot + 1] for slot in range(16)
    ]
    assert shared["environment"] == dict(contracts.SHARED_THREAD_ENVIRONMENT)
    assert isolated["outer_workers"] == 16
    assert isolated["logical_cpu_ids_per_worker"] == list(range(32))
    assert isolated["affinity_mask_hex"] == "0xFFFFFFFF"
    assert isolated["environment"] == dict(contracts.THREAD_ENVIRONMENT)
    boundary = json.loads(contracts.external_boundaries_contract_bytes())
    assert boundary["monitor"]["exact_evaluator_fields"] == list(
        contracts.RUNTIME_RECEIPT_FIELDS
    )
    assert len(boundary["monitor"]["exact_evaluator_fields"]) == 13
    assert boundary["monitor"]["constructor_native_resource_ownership_in_this_package"] is False
    assert boundary["monitor"]["runtime_v2_sampler_reused"] is False
    assert boundary["publication"]["implemented_in_this_package"] is False


def test_held_file_denies_write_and_replace_until_close(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    stage = tmp_path / "replacement.py"
    target.write_bytes(b"VALUE = 1\n")
    stage.write_bytes(b"VALUE = 2\n")
    raw = target.read_bytes()
    record = ("payload.py", hashlib.sha256(raw).hexdigest(), len(raw))
    held = custody.HeldFileSet(project_root=tmp_path, records=(record,))
    with held:
        receipt = held.receipt_rows()[0]
        assert receipt["write_share_allowed"] is False
        assert receipt["delete_share_allowed"] is False
        assert type(receipt["volume_serial_number"]) is int
        assert len(receipt["file_id_128"]) == 32
        with pytest.raises(OSError):
            target.write_bytes(b"tampered\n")
        with pytest.raises(OSError):
            os.replace(stage, target)
    os.replace(stage, target)
    assert target.read_bytes() == b"VALUE = 2\n"


def test_wrong_hash_and_reparse_attack_fail_before_bytes_are_exposed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "payload.py"
    target.write_bytes(b"VALUE = 1\n")
    with pytest.raises(QualificationRuntimeV3Error, match="bytes differ"):
        with custody.HeldFileSet(
            project_root=tmp_path,
            records=(("payload.py", "0" * 64, len(target.read_bytes())),),
        ):
            raise AssertionError("wrong hash reached body")
    raw = target.read_bytes()
    original = custody._metadata_is_reparse  # noqa: SLF001

    def injected(path: Path) -> bool:
        if Path(os.path.abspath(path)) == Path(os.path.abspath(target)):
            return True
        return original(path)

    monkeypatch.setattr(custody, "_metadata_is_reparse", injected)
    with pytest.raises(QualificationRuntimeV3Error, match="reparse path rejected"):
        with custody.HeldFileSet(
            project_root=tmp_path,
            records=(("payload.py", hashlib.sha256(raw).hexdigest(), len(raw)),),
        ):
            raise AssertionError("reparse attack reached body")


@pytest.mark.parametrize(
    "injected",
    [
        "numpy.runtime_v3_injected",
        "research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3evil",
        "research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3.evil",
    ],
)
def test_preexisting_cache_injection_fails_before_file_open(injected: str) -> None:
    sys.modules[injected] = ModuleType(injected)
    try:
        closure = custody.HeldModuleClosure(
            lane_id=SHARED_LANE_ID,
            project_root=_project_root(),
            source_records=contracts.SHARED_SOURCE_RECORDS,
        )
        with pytest.raises(QualificationRuntimeV3Error, match="module cache rejected"):
            closure.__enter__()
    finally:
        sys.modules.pop(injected, None)


def test_caller_declared_arbitrary_project_closure_cannot_mint_pass(
    tmp_path: Path,
) -> None:
    target = tmp_path / "arbitrary.py"
    target.write_bytes(b"PASSED = True\n")
    raw = target.read_bytes()
    with pytest.raises(QualificationRuntimeV3Error, match="source universe differs"):
        custody.HeldModuleClosure(
            lane_id=SHARED_LANE_ID,
            project_root=tmp_path,
            source_records=(("arbitrary.py", hashlib.sha256(raw).hexdigest(), len(raw)),),
        )


def test_held_byte_reread_and_handle_lifetime_attacks_fail(tmp_path: Path) -> None:
    target = tmp_path / "payload.py"
    target.write_bytes(b"VALUE = 1\n")
    raw = target.read_bytes()
    held = custody.HeldFileSet(
        project_root=tmp_path,
        records=(("payload.py", hashlib.sha256(raw).hexdigest(), len(raw)),),
    )
    held.__enter__()
    original_read = custody._read_handle  # noqa: SLF001
    try:
        target_handle = held._file_handles["payload.py"]  # noqa: SLF001

        def swapped(handle: int) -> bytes:
            if handle == target_handle:
                return b"VALUE = 2\n"
            return original_read(handle)

        custody._read_handle = swapped  # type: ignore[assignment]  # noqa: SLF001
        with pytest.raises(QualificationRuntimeV3Error, match="changed after initial"):
            held.raw("payload.py")
        custody._read_handle = original_read  # type: ignore[assignment]  # noqa: SLF001
        custody._close_handle(target_handle)  # noqa: SLF001
        with pytest.raises(QualificationRuntimeV3Error):
            held.assert_live()
        with pytest.raises(QualificationRuntimeV3Error, match="close operation"):
            held.close()
    finally:
        custody._read_handle = original_read  # type: ignore[assignment]  # noqa: SLF001
        if held._open:  # noqa: SLF001
            try:
                held.close()
            except QualificationRuntimeV3Error:
                pass


def test_undeclared_project_import_is_rejected_by_cold_finder() -> None:
    code = f"""
import pathlib, sys
root = pathlib.Path({str(_project_root())!r})
sys.path.insert(0, str(root))
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3.contracts import SHARED_SOURCE_RECORDS
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v3.custody import HeldModuleClosure, QualificationRuntimeV3Error
closure = HeldModuleClosure(lane_id='shared_c1_c3', project_root=root, source_records=SHARED_SOURCE_RECORDS)
with closure:
    try:
        __import__('research.model_zoo.runtime_v3_undeclared_attack')
    except QualificationRuntimeV3Error:
        print('PASS')
    else:
        raise AssertionError('undeclared import succeeded')
"""
    completed = _cold_python(code)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "PASS"


@pytest.mark.parametrize(
    ("lane", "expected_count", "synthetic"),
    [("shared", 23, []), ("c4", 26, ["research.model_zoo.hofs_v12_fresh_qualification_service_v1"])],
)
def test_cold_held_loader_declared_equals_actual_and_original_hofs_is_zero(
    lane: str,
    expected_count: int,
    synthetic: list[str],
) -> None:
    receipt = _cold_closure_receipt(lane)
    assert receipt["declared_module_count"] == expected_count
    assert receipt["actual_module_count"] == expected_count
    assert receipt["declared_module_names"] == receipt["actual_module_names"]
    assert receipt["actual_synthetic_package_names"] == synthetic
    assert receipt["original_hofs_init_import_count"] == 0
    assert receipt["hofs_publisher_import_count"] == 0
    assert receipt["declared_numeric_project_source_normal_workspace_import_count"] == 0
    assert receipt["ancestor_reparse_count"] == 0
    assert receipt["external_runtime_file_id_closure_complete"] is False
    assert receipt["qualification_execution_eligible"] is False


def test_unheld_external_extension_cannot_activate_production() -> None:
    boundary = json.loads(contracts.external_boundaries_contract_bytes())
    source = inspect.getsource(custody.HeldModuleClosure.external_origin_observation_bytes)
    assert "extension_swap_prevention_materialized" in source
    assert "qualification_execution_eligible" in source
    assert boundary["status"] == "EXTERNAL_MONITOR_AND_PUBLICATION_NOT_IMPLEMENTED_HERE"
    with pytest.raises(QualificationRuntimeV3Error):
        run_isolated_c4_lane(_Poison())


def test_c4_spent_runtime_preflight_precedes_environment_and_numeric_import() -> None:
    source = inspect.getsource(spent._run_c4_spent_equivalence)  # noqa: SLF001
    assert source.index("_validate_c4_spent_python_runtime()") < source.index(
        "_set_environment(THREAD_ENVIRONMENT)"
    )
    if sys.version_info[:3] != (3, 10, 19):
        with pytest.raises(QualificationRuntimeV3Error, match="exact frozen V7 Python"):
            spent._validate_c4_spent_python_runtime()  # noqa: SLF001


@pytest.mark.parametrize(
    ("mode", "lane"),
    [
        ("shared-spent-no-publish", SHARED_LANE_ID),
        ("c4-spent-no-publish", ISOLATED_LANE_ID),
    ],
)
def test_spent_held_loader_numeric_equivalence_without_authority_or_publication(
    mode: str,
    lane: str,
) -> None:
    receipt = _run_spent(mode)
    _assert_json_primitives(receipt)
    assert receipt["status"] == (
        "PASS_SPENT_PUBLIC_NO_AUTHORITY_HELD_LOADER_NUMERIC_EQUIVALENCE"
    )
    assert receipt["lane_id"] == lane
    assert receipt["external_runtime_closure_qualification_eligible"] is False
    assert set(receipt["counts"].values()) == {0}
    assert receipt["equivalence"]["evidence_class"] == (
        "SPENT_PUBLIC_NOT_QUALIFICATION_CERTIFICATION"
    )
    if lane == SHARED_LANE_ID:
        assert receipt["equivalence"]["mismatch_count"] == 0
    else:
        assert receipt["equivalence"]["numeric_mismatch_count"] == 0
        assert receipt["equivalence"]["identity_mismatch_count"] == 0
        assert receipt["equivalence"]["surface_log_mismatch_count"] == 0


def test_no_sampler_publisher_or_output_writer_exists_in_v3_source() -> None:
    root = _project_root() / "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v3"
    assert not (root / "monitor.py").exists()
    assert not (root / "publisher.py").exists()
    for leaf in ("__init__.py", "contracts.py", "custody.py", "lanes.py", "spent.py"):
        source = (root / leaf).read_text(encoding="utf-8")
        assert "os.rename(" not in source
        assert ".write_bytes(" not in source
        assert "publish_spent" not in source
