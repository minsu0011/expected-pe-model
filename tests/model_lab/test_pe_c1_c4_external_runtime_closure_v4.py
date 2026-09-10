from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import json
import os
from pathlib import Path
from typing import Any

import pytest

from research.model_zoo import pe_c1_c4_external_runtime_closure_v4 as runtime_v4
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4 import boundary
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4 import closure
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4 import contracts
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4 import lanes
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4 import monitor


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _canonical(payload: object) -> bytes:
    return contracts.canonical_json_bytes(payload)


class _Poison:
    def __getattribute__(self, name: str) -> Any:
        raise AssertionError(f"denied production entry inspected caller input: {name}")

    def __iter__(self):
        raise AssertionError("denied production entry iterated caller input")

    def __len__(self) -> int:
        raise AssertionError("denied production entry measured caller input")


def _boundary_payload() -> dict[str, object]:
    handles = [
        {"role": "stdin_activation", "handle_value": 101},
        {"role": "stdout", "handle_value": 102},
        {"role": "stderr", "handle_value": 103},
    ]
    return {
        "schema_version": (
            "expected_pe.qualification.external_runtime_closure.v4.process_boundary_evidence"
        ),
        "status": contracts.PREBINDING_SOURCE_STATUS,
        "application_argv": [],
        "close_fds": True,
        "startup_handle_list": handles,
        "actual_inherited_handles": [dict(row) for row in handles],
        "supervisor_pid": 1001,
        "supervisor_creation_time_100ns": 10_001,
        "worker_pid": 1002,
        "worker_creation_time_100ns": 10_002,
        "monitor_pid": 1003,
        "monitor_creation_time_100ns": 10_003,
        "environment": dict(contracts.PINNED_CHILD_ENVIRONMENT),
    }


def _monitor_payload(*, lane_id: str = contracts.SHARED_LANE_ID) -> dict[str, object]:
    controller_pid = 100
    controller_creation = 10_000
    terminals = [
        {
            "process_role": "controller",
            "worker_ordinal": -1,
            "pid": controller_pid,
            "creation_time_100ns": controller_creation,
            "exit_code": 0,
        }
    ]
    for ordinal in range(contracts.OUTER_WORKERS):
        terminals.append(
            {
                "process_role": "worker",
                "worker_ordinal": ordinal,
                "pid": 200 + ordinal,
                "creation_time_100ns": 20_000 + ordinal,
                "exit_code": 0,
            }
        )
    process_rows = [
        {
            "pid": controller_pid,
            "parent_pid": 0,
            "creation_time_100ns": controller_creation,
            "rss_bytes": 1_000,
        }
    ]
    process_rows.extend(
        {
            "pid": 200 + ordinal,
            "parent_pid": controller_pid,
            "creation_time_100ns": 20_000 + ordinal,
            "rss_bytes": 100,
        }
        for ordinal in range(contracts.OUTER_WORKERS)
    )
    samples = [
        {
            "observed_perf_counter_ns": 120_000_000,
            "processes": [dict(row) for row in process_rows],
            "gpu_processes": [],
        },
        {
            "observed_perf_counter_ns": 170_000_000,
            "processes": [dict(row) for row in process_rows],
            "gpu_processes": [],
        },
    ]
    return {
        "schema_version": ("expected_pe.qualification.external_runtime_closure.v4.monitor_receipt"),
        "status": contracts.MONITOR_STATUS,
        "lane_id": lane_id,
        "owner_role": contracts.MONITOR_OWNER_ROLE,
        "owner_pid": 999,
        "owner_creation_time_100ns": 9_999,
        "controller_pid": controller_pid,
        "controller_creation_time_100ns": controller_creation,
        "job_binding_sha256": "a" * 64,
        "job_query_handle_acquired_perf_counter_ns": 100_000_000,
        "nvml_init_started_perf_counter_ns": 101_000_000,
        "nvml_init_completed_perf_counter_ns": 102_000_000,
        "sampling_started_perf_counter_ns": 103_000_000,
        "samples": samples,
        "terminal_processes": terminals,
        "stop_requested_perf_counter_ns": 190_000_000,
        "nvml_shutdown_started_perf_counter_ns": 191_000_000,
        "nvml_shutdown_completed_perf_counter_ns": 192_000_000,
        "receipt_sealed_perf_counter_ns": 193_000_000,
        "sample_count": 2,
        "sample_interval_max_ms": 50.0,
        "peak_process_tree_rss_bytes": 2_600,
        "gpu_process_observation_count": 0,
        "peak_vram_bytes": 0,
        "sampler_failure_count": 0,
    }


def _fake_runtime_records(monkeypatch: pytest.MonkeyPatch) -> tuple[tuple[object, ...], ...]:
    interpreter = r"C:\fixture\venv\Scripts\python.exe"
    stdlib = r"C:\fixture\base\Lib"
    site = r"C:\fixture\venv\Lib\site-packages"
    project = r"C:\fixture\project"
    monkeypatch.setattr(contracts, "PINNED_INTERPRETER_FINAL_PATH", interpreter)
    monkeypatch.setattr(contracts, "PINNED_STDLIB_ROOT_FINAL_PATH", stdlib)
    monkeypatch.setattr(contracts, "PINNED_SITE_PACKAGES_ROOT_FINAL_PATH", site)
    monkeypatch.setattr(contracts, "PINNED_PROJECT_ROOT_FINAL_PATH", project)
    paths = (
        (contracts.INTERPRETER_KIND, interpreter),
        (contracts.STDLIB_SOURCE_KIND, stdlib + r"\json\__init__.py"),
        (contracts.STDLIB_EXTENSION_KIND, stdlib + r"\lib-dynload\_hashlib.pyd"),
        (contracts.SITE_PACKAGE_SOURCE_KIND, site + r"\numpy\__init__.py"),
        (contracts.SITE_PACKAGE_EXTENSION_KIND, site + r"\numpy\core.pyd"),
        (contracts.NATIVE_DLL_KIND, site + r"\numpy\.libs\openblas.dll"),
        (contracts.PACKAGE_DATA_KIND, site + r"\lightgbm\VERSION.txt"),
        (contracts.PROJECT_SOURCE_KIND, project + r"\research\model.py"),
    )
    return tuple(
        (kind, path, f"{ordinal + 1:064x}", ordinal + 1, 17, f"{ordinal + 1:032x}")
        for ordinal, (kind, path) in enumerate(paths)
    )


def _win32_identity(path: Path, *, directory: bool) -> tuple[dict[str, object], bytes | None]:
    handle, receipt, raw = closure._open_held_path(path, directory=directory)  # noqa: SLF001
    try:
        return receipt, raw
    finally:
        closure._checked_close_handle(handle)  # noqa: SLF001


def _held_fixture_rows(
    target: Path,
) -> tuple[tuple[tuple[object, ...], ...], tuple[tuple[object, ...], ...]]:
    file_receipt, raw = _win32_identity(target, directory=False)
    assert raw is not None
    records = (
        (
            contracts.PROJECT_SOURCE_KIND,
            str(Path(os.path.abspath(target))),
            hashlib.sha256(raw).hexdigest(),
            len(raw),
            file_receipt["volume_serial_number"],
            file_receipt["file_id_128"],
        ),
    )
    ancestry: list[tuple[object, ...]] = []
    for directory in closure._directory_chain(target.parent):  # noqa: SLF001
        receipt, directory_raw = _win32_identity(directory, directory=True)
        assert directory_raw is None
        ancestry.append(
            (
                str(Path(os.path.abspath(directory))),
                receipt["volume_serial_number"],
                receipt["file_id_128"],
            )
        )
    ancestry.sort(key=lambda row: closure._path_key(str(row[0])))  # noqa: SLF001
    return records, tuple(ancestry)


def test_source_is_isolated_stdlib_only_and_contains_no_execution_side_effects() -> None:
    root = _project_root() / "research/model_zoo/pe_c1_c4_external_runtime_closure_v4"
    leaves = sorted(root.glob("*.py"))
    assert {leaf.name for leaf in leaves} == {
        "__init__.py",
        "boundary.py",
        "closure.py",
        "contracts.py",
        "lanes.py",
        "monitor.py",
    }
    forbidden_calls = {
        "Popen",
        "run",
        "check_call",
        "check_output",
        "os.replace",
        "os.rename",
        "write_bytes",
        "write_text",
    }
    third_party_roots = {
        "numpy",
        "pandas",
        "scipy",
        "sklearn",
        "lightgbm",
        "joblib",
        "pynvml",
        "nvidia",
    }
    for leaf in leaves:
        source = leaf.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(leaf))
        assert "pe_c1_c4_fresh_qualification_runtime_v3" not in source
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".")[0] not in third_party_roots for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in third_party_roots
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_calls
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in forbidden_calls


@pytest.mark.parametrize("entry", [lanes.run_shared_c1_c3_lane, lanes.run_isolated_c4_lane])
def test_production_denies_before_input_or_numeric_import(
    entry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    original_import = builtins.__import__

    def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith(("numpy", "pandas", "sklearn", "lightgbm", "research.model_zoo.hofs")):
            imported.append(name)
            raise AssertionError(f"numeric import occurred: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(
        contracts.ExternalRuntimeClosureV4Error,
        match="denied before input/import",
    ):
        entry(_Poison())
    assert imported == []
    assert tuple(inspect.signature(entry).parameters) == ("tasks",)


def test_source_contract_is_truthfully_prebinding_only_with_all_zero_counts() -> None:
    bundle = contracts.contract_bundle_bytes()
    assert type(bundle) is tuple and len(bundle) == 4
    assert all(type(raw) is bytes and raw.endswith(b"\n") for raw in bundle)
    manifest, monitor_contract, boundary_contract, state = map(json.loads, bundle)
    assert manifest["manifest_status"] == "DENIED_RUNTIME_RECORDS_NOT_FINAL_BOUND"
    assert manifest["runtime_record_count"] == 0
    assert manifest["ancestry_record_count"] == 0
    assert manifest["caller_selected_path_allowed"] is False
    assert manifest["caller_selected_record_allowed"] is False
    assert manifest["project_source_and_native_loader_dependencies_fail_closed"] is True
    assert monitor_contract["max_sample_interval_ms"] == 100.0
    assert monitor_contract["sampler_native_resources_implemented_in_this_source_revision"] is False
    assert boundary_contract["canonical_application_argv_count"] == 0
    assert boundary_contract["decoy_inheritable_handle_allowed"] is False
    assert state["production_execution_eligible"] is False
    assert state["production_execution_status"].startswith("DENIED_")
    assert set(state["counts"].values()) == {0}
    assert set(state["counts"]) >= {
        "signer_access_count",
        "authority_access_count",
        "generation_count",
        "fresh_access_count",
        "truth_access_count",
        "heldout_access_count",
    }


def test_supported_closure_construction_has_no_caller_path_or_record() -> None:
    assert (
        tuple(inspect.signature(runtime_v4.open_frozen_external_runtime_closure).parameters) == ()
    )
    assert tuple(inspect.signature(closure.FrozenExternalRuntimeClosure).parameters) == ()
    assert tuple(inspect.signature(contracts.validate_frozen_runtime_records).parameters) == ()
    assert tuple(inspect.signature(contracts.validate_frozen_ancestry_records).parameters) == ()
    assert not any(
        "record" in name.casefold() or "path" in name.casefold() for name in runtime_v4.__all__
    )
    with pytest.raises(TypeError):
        runtime_v4.open_frozen_external_runtime_closure(Path("caller"))  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        closure.FrozenExternalRuntimeClosure(records=())  # type: ignore[call-arg]
    with pytest.raises(
        contracts.ExternalRuntimeClosureV4Error,
        match="manifest is not final-bound",
    ):
        with runtime_v4.open_frozen_external_runtime_closure():
            raise AssertionError("pending manifest unexpectedly opened")


def test_frozen_record_schema_requires_every_external_and_project_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _fake_runtime_records(monkeypatch)
    assert contracts._validate_runtime_records(records) == records  # noqa: SLF001
    attacked = tuple(row for row in records if row[0] != contracts.NATIVE_DLL_KIND)
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="incomplete"):
        contracts._validate_runtime_records(attacked)  # noqa: SLF001
    attacked = tuple(row for row in records if row[0] != contracts.PROJECT_SOURCE_KIND)
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="incomplete"):
        contracts._validate_runtime_records(attacked)  # noqa: SLF001


def test_path_alias_hardlink_identity_and_native_escape_attacks_fail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = list(_fake_runtime_records(monkeypatch))
    duplicate_path = list(records[-1])
    duplicate_path[1] = records[-2][1].swapcase()
    records[-1] = tuple(duplicate_path)
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="alias/duplicate"):
        contracts._validate_runtime_records(tuple(records))  # noqa: SLF001

    records = list(_fake_runtime_records(monkeypatch))
    duplicate_identity = list(records[-1])
    duplicate_identity[4:] = records[-2][4:]
    records[-1] = tuple(duplicate_identity)
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="FileId alias"):
        contracts._validate_runtime_records(tuple(records))  # noqa: SLF001

    records = list(_fake_runtime_records(monkeypatch))
    native = next(index for index, row in enumerate(records) if row[0] == contracts.NATIVE_DLL_KIND)
    escaped = list(records[native])
    escaped[1] = r"D:\caller\injected.dll"
    records[native] = tuple(escaped)
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="escaped frozen roots"):
        contracts._validate_runtime_records(tuple(records))  # noqa: SLF001


def test_ancestry_schema_rejects_alias_and_noncanonical_order() -> None:
    valid = (
        ("C:\\", 1, "1" * 32),
        (r"C:\alpha", 1, "2" * 32),
    )
    assert contracts._validate_ancestry_records(valid) == valid  # noqa: SLF001
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="alias/duplicate"):
        contracts._validate_ancestry_records(  # noqa: SLF001
            (*valid, (r"c:\ALPHA", 1, "3" * 32))
        )
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="not canonical-path sorted"):
        contracts._validate_ancestry_records(tuple(reversed(valid)))  # noqa: SLF001


@pytest.mark.skipif(os.name != "nt", reason="Win32 held-handle adversarial contract")
def test_held_runtime_denies_write_replace_and_exposes_no_native_handle(tmp_path: Path) -> None:
    target = tmp_path / "runtime.dll"
    replacement = tmp_path / "replacement.dll"
    target.write_bytes(b"frozen-runtime\n")
    replacement.write_bytes(b"replacement\n")
    records, ancestry = _held_fixture_rows(target)
    held = closure._HeldRuntimeSet(records, ancestry)  # noqa: SLF001
    with held:
        row = held.receipt_rows()[0]
        assert row["write_share_allowed"] is False
        assert row["delete_share_allowed"] is False
        assert "handle" not in row and "handle_value" not in row
        with pytest.raises(OSError):
            target.write_bytes(b"swap\n")
        with pytest.raises(OSError):
            os.replace(replacement, target)
    os.replace(replacement, target)
    assert target.read_bytes() == b"replacement\n"


@pytest.mark.skipif(os.name != "nt", reason="Win32 held-handle adversarial contract")
def test_reparse_and_post_open_byte_swap_attacks_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "runtime.pyd"
    target.write_bytes(b"extension-v1\n")
    original_reparse = closure._metadata_is_reparse  # noqa: SLF001

    def injected_reparse(path: Path) -> bool:
        if closure._path_key(path) == closure._path_key(target):  # noqa: SLF001
            return True
        return original_reparse(path)

    monkeypatch.setattr(closure, "_metadata_is_reparse", injected_reparse)
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="reparse path rejected"):
        closure._open_held_path(target, directory=False)  # noqa: SLF001
    monkeypatch.setattr(closure, "_metadata_is_reparse", original_reparse)

    records, ancestry = _held_fixture_rows(target)
    held = closure._HeldRuntimeSet(records, ancestry)  # noqa: SLF001
    held.__enter__()
    original_read = closure._read_handle  # noqa: SLF001
    try:
        target_handle = held._file_handles[closure._path_key(target)]  # noqa: SLF001

        def swapped(handle: int) -> bytes:
            if handle == target_handle:
                return b"extension-v2\n"
            return original_read(handle)

        monkeypatch.setattr(closure, "_read_handle", swapped)
        with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="liveness/bytes"):
            held.assert_live()
    finally:
        monkeypatch.setattr(closure, "_read_handle", original_read)
        held.close()


def test_boundary_accepts_exact_three_handles_and_rejects_decoy() -> None:
    payload = _boundary_payload()
    assert boundary.validate_process_boundary_evidence_bytes(_canonical(payload)) == payload
    attacked = json.loads(_canonical(payload))
    attacked["actual_inherited_handles"].append({"role": "decoy", "handle_value": 104})
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="exactly three"):
        boundary.validate_process_boundary_evidence_bytes(_canonical(attacked))


@pytest.mark.parametrize("attack", ["argv", "environment", "pid_reuse", "close_fds"])
def test_extra_argv_environment_pid_reuse_and_close_fds_attacks_fail(attack: str) -> None:
    payload = _boundary_payload()
    if attack == "argv":
        payload["application_argv"] = ["--caller-path=C:\\attack"]
        message = "argv"
    elif attack == "environment":
        environment = payload["environment"]
        assert type(environment) is dict
        environment["CALLER_EXTRA"] = "1"
        message = "environment differs"
    elif attack == "pid_reuse":
        payload["worker_pid"] = payload["supervisor_pid"]
        payload["worker_creation_time_100ns"] = 99_999
        message = "PID reuse"
    else:
        payload["close_fds"] = False
        message = "close_fds"
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match=message):
        boundary.validate_process_boundary_evidence_bytes(_canonical(payload))


def test_duplicate_member_and_noncanonical_json_are_rejected() -> None:
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="duplicate JSON member"):
        contracts.parse_canonical_json_bytes(b'{"a":1,"a":2}\n')
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="not the exact canonical"):
        contracts.parse_canonical_json_bytes(b'{"a": 1}\n')


def test_external_monitor_validates_owner_lifecycle_rss_and_common_gpu0() -> None:
    payload = _monitor_payload()
    assert monitor.validate_external_monitor_receipt_bytes(_canonical(payload)) == payload
    evaluator = json.loads(monitor.evaluator_receipt_bytes(_canonical(payload)))
    assert set(evaluator) == set(monitor.EVALUATOR_RECEIPT_FIELDS)
    assert len(evaluator) == 13
    assert evaluator["lane_id"] == contracts.SHARED_LANE_ID
    assert evaluator["peak_process_tree_rss_bytes"] == 2_600
    assert evaluator["gpu_process_observation_count"] == 0
    assert evaluator["peak_vram_bytes"] == 0


def test_monitor_rejects_gpu_process_and_vram_observation() -> None:
    payload = _monitor_payload()
    samples = payload["samples"]
    assert type(samples) is list
    samples[0]["gpu_processes"] = [{"device_ordinal": 0, "pid": 200, "used_vram_bytes": 1_024}]
    payload["gpu_process_observation_count"] = 1
    payload["peak_vram_bytes"] = 1_024
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="GPU0 proof failed"):
        monitor.validate_external_monitor_receipt_bytes(_canonical(payload))


@pytest.mark.parametrize("attack", ["sample_gap", "hung_shutdown", "reordered_owner"])
def test_monitor_rejects_gap_hung_sampler_and_owner_order(attack: str) -> None:
    payload = _monitor_payload()
    if attack == "sample_gap":
        samples = payload["samples"]
        assert type(samples) is list
        samples[1]["observed_perf_counter_ns"] = 270_000_001
        payload["stop_requested_perf_counter_ns"] = 290_000_001
        payload["nvml_shutdown_started_perf_counter_ns"] = 291_000_001
        payload["nvml_shutdown_completed_perf_counter_ns"] = 292_000_001
        payload["receipt_sealed_perf_counter_ns"] = 293_000_001
        payload["sample_interval_max_ms"] = 150.000001
        message = "exceeds 100"
    elif attack == "hung_shutdown":
        payload["nvml_shutdown_completed_perf_counter_ns"] = 5_192_000_001
        payload["receipt_sealed_perf_counter_ns"] = 5_193_000_001
        message = "shutdown exceeded"
    else:
        payload["nvml_init_started_perf_counter_ns"] = 99_000_000
        message = "lifecycle order"
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match=message):
        monitor.validate_external_monitor_receipt_bytes(_canonical(payload))


def test_monitor_rejects_pid_reuse_owner_alias_and_unobserved_terminal() -> None:
    payload = _monitor_payload()
    samples = payload["samples"]
    assert type(samples) is list
    samples[1]["processes"][1]["creation_time_100ns"] = 88_888
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="PID reuse"):
        monitor.validate_external_monitor_receipt_bytes(_canonical(payload))

    payload = _monitor_payload()
    payload["owner_pid"] = payload["controller_pid"]
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="external"):
        monitor.validate_external_monitor_receipt_bytes(_canonical(payload))

    payload = _monitor_payload()
    samples = payload["samples"]
    assert type(samples) is list
    for sample in samples:
        sample["processes"] = sample["processes"][:-1]
    payload["peak_process_tree_rss_bytes"] = 2_500
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="never sampled"):
        monitor.validate_external_monitor_receipt_bytes(_canonical(payload))


class _DummyHeld:
    def __init__(self, records: tuple[tuple[object, ...], ...]) -> None:
        self._records = records
        self.live_checks = 0

    def assert_live(self) -> None:
        self.live_checks += 1


def _load_observation(records: tuple[tuple[object, ...], ...]) -> dict[str, object]:
    rows = [closure._runtime_row_dict(row) for row in records]  # noqa: SLF001
    return {
        "schema_version": (
            "expected_pe.qualification.external_runtime_closure.v4.load_observation"
        ),
        "status": "PASS_EXTERNAL_SUPERVISOR_OBSERVATION_PREBINDING_ONLY",
        "supervisor_pid": 1001,
        "supervisor_creation_time_100ns": 10_001,
        "worker_pid": 1002,
        "worker_creation_time_100ns": 10_002,
        "records": rows,
        "record_count": len(rows),
        "records_semantic_sha256": hashlib.sha256(_canonical(rows)).hexdigest(),
        "native_loader_scan_complete": True,
        "python_import_audit_complete": True,
        "data_open_audit_complete": True,
        "unclassified_load_count": 0,
    }


def test_actual_load_evidence_requires_exact_native_and_project_held_universe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = _fake_runtime_records(monkeypatch)
    held = _DummyHeld(records)
    candidate = closure.FrozenExternalRuntimeClosure()
    candidate._held = held  # type: ignore[assignment]  # noqa: SLF001
    evidence = _load_observation(records)
    assert candidate.validate_observed_load_closure(_canonical(evidence)) == evidence
    assert held.live_checks == 1

    attacked = _load_observation(
        tuple(row for row in records if row[0] != contracts.NATIVE_DLL_KIND)
    )
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="actual loaded closure"):
        candidate.validate_observed_load_closure(_canonical(attacked))

    attacked = _load_observation(records)
    attacked["unclassified_load_count"] = 1
    with pytest.raises(contracts.ExternalRuntimeClosureV4Error, match="unclassified"):
        candidate.validate_observed_load_closure(_canonical(attacked))


def test_public_surface_exposes_no_signer_authority_generation_or_monitor_constructor() -> None:
    public = set(runtime_v4.__all__)
    forbidden_tokens = ("signer", "authority", "generation", "fresh", "truth", "heldout")
    assert not any(token in name.casefold() for name in public for token in forbidden_tokens)
    assert "validate_external_monitor_receipt_bytes" not in public
    assert not any(
        isinstance(value, type) and "Sampler" in name for name, value in vars(monitor).items()
    )
    source = inspect.getsource(monitor)
    assert "ctypes.CDLL" not in source
    assert "nvmlInit" not in source
    assert "nvmlShutdown(" not in source


def test_contract_bytes_do_not_mutate_after_caller_json_change() -> None:
    first = contracts.contract_bundle_bytes()
    parsed = json.loads(first[0])
    parsed["manifest_status"] = "caller-tampered"
    second = contracts.contract_bundle_bytes()
    assert first == second
    assert json.loads(second[0])["manifest_status"] != "caller-tampered"
