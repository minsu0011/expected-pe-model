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

from research.model_zoo import pe_c1_c4_external_runtime_closure_v4_r2 as runtime_r2
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4_r2 import child_entry
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4_r2 import contracts
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4_r2 import custody
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4_r2 import lanes
from research.model_zoo.pe_c1_c4_external_runtime_closure_v4_r2 import supervisor


_V4_HASHES = {
    "__init__.py": "b1ff4631193c1d991889340a55e83fe864bc96ec37d6e427d5d617bbac3b469a",
    "boundary.py": "3b23e11e9efece533c7b683aede7b1b16133b6a355f6a6729b8b6a131b5fbbf5",
    "closure.py": "5905c0a180bd4c08e6d029a2009f644fec34910c14132b87e76e7337098956ce",
    "contracts.py": "b6192cf12a14986b777474b921f1cc914feb5c640a47864adea6772e45d768cf",
    "DESIGN.md": "4a54bbe0ece1407624f694e61db4198f98d0e1d03f79119cc8da0bd3a5883fa1",
    "lanes.py": "dd89d4c6fd2e3a70832ae160e3867dfd63bf1f8452a959e112c39b38260e0223",
    "monitor.py": "2680e05ff6a0c5784ac416b2d367ba5fc870456c24a9dcb397014c960db8bba8",
}
_V3_HASHES = {
    "__init__.py": "ad27b4b3821f67dc7b32e102a0dbecf24c658b7a1721281742f79cd8c6d958cd",
    "contracts.py": "311e0d7c43d0cfbce82896a0c07189bda3f808b182746de9c39ae2ce87a97121",
    "custody.py": "7d75d1923da84b23082ff2f4ebbc7dd02cc8af951ba4b00d5a5e058a0a30329f",
    "DESIGN.md": "bedf49d4eb4357b6f297c2182bd50cf5e6d70d59e81c6c8d922a242d5c00af71",
    "lanes.py": "72797e66e09a15252d13b30d9dbcd881117f04907f871093c7ddc51cf01cd5dd",
    "spent.py": "610d7d9a63ebd2f0a7ea9f698719e1df8b4c5f69685b18babb8e87a92c58c269",
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


class _Poison:
    def __getattribute__(self, name: str) -> Any:
        raise AssertionError(f"production denial inspected caller input: {name}")

    def __iter__(self):
        raise AssertionError("production denial iterated caller input")


def _monitor_receipt() -> dict[str, object]:
    controller = {
        "pid": 100,
        "creation_time_100ns": 200,
        "image_path": contracts.PINNED_PROCESS_IMAGE,
    }
    samples = [
        {
            "observed_perf_counter_ns": 1_030_000_000,
            "processes": [{**controller, "rss_bytes": 1_000}],
            "gpu_processes": [],
        },
        {
            "observed_perf_counter_ns": 1_055_000_000,
            "processes": [{**controller, "rss_bytes": 1_100}],
            "gpu_processes": [],
        },
    ]
    return {
        "schema_version": "expected_pe.external_runtime_closure.v4_r2.monitor_receipt",
        "status": "PASS_EXTERNAL_JOB_TREE_RSS_NVML_SPENT_ONLY",
        "pass_ordinal": 1,
        "owner_identity": {
            "pid": 300,
            "creation_time_100ns": 400,
            "image_path": contracts.PINNED_PROCESS_IMAGE,
        },
        "owner_thread_id": 500,
        "nvml_init_thread_id": 500,
        "sample_thread_id": 500,
        "nvml_shutdown_thread_id": 500,
        "job_owner_acquired_perf_counter_ns": 1_000_000_000,
        "nvml_init_started_perf_counter_ns": 1_010_000_000,
        "nvml_init_completed_perf_counter_ns": 1_020_000_000,
        "sampling_started_perf_counter_ns": 1_030_000_000,
        "sampling_ended_perf_counter_ns": 1_055_000_000,
        "nvml_shutdown_started_perf_counter_ns": 1_060_000_000,
        "nvml_shutdown_completed_perf_counter_ns": 1_070_000_000,
        "receipt_sealed_perf_counter_ns": 1_080_000_000,
        "controller_pid": 100,
        "controller_creation_time_100ns": 200,
        "samples": samples,
        "sample_count": 2,
        "sample_interval_max_ms": 25.0,
        "peak_process_tree_rss_bytes": 1_100,
        "gpu_process_observation_count": 0,
        "peak_vram_bytes": 0,
        "pid_reuse_observation_count": 0,
        "sampler_failure_count": 0,
        "hung_sampler_count": 0,
    }


def _equivalence_pass() -> dict[str, object]:
    file_rows = [
        {
            "kind": "interpreter",
            "final_canonical_path": contracts.PINNED_PROCESS_IMAGE,
            "raw_sha256": "a" * 64,
            "size_bytes": 1,
            "volume_serial_number": 1,
            "file_id_128": "b" * 32,
            "observation_sources": ["supervisor_process_image"],
            "reparse_tag": 0,
            "write_share_allowed": False,
            "delete_share_allowed": False,
        }
    ]
    ancestry = [
        {
            "final_canonical_path": "C:\\",
            "volume_serial_number": 1,
            "file_id_128": "c" * 32,
            "file_attributes": 16,
            "reparse_tag": 0,
            "directory": True,
            "write_share_allowed": False,
            "delete_share_allowed": False,
        }
    ]
    return {
        "closure_file_records": file_rows,
        "closure_file_record_count": 1,
        "closure_file_records_semantic_sha256": contracts.sha256_bytes(
            contracts.canonical_json_bytes(file_rows)
        ),
        "closure_ancestry_records": ancestry,
        "closure_ancestry_record_count": 1,
        "closure_ancestry_records_semantic_sha256": contracts.sha256_bytes(
            contracts.canonical_json_bytes(ancestry)
        ),
        "fixed_imported_modules": [*contracts.DISCOVERY_MODULES, contracts.SYNTHETIC_HOFS_ENTRY],
        "native_module_path_count": 1,
        "pass_receipt_raw_sha256": "d" * 64,
    }


def test_v4_and_runtime_v3_are_byte_preserved() -> None:
    root = _project_root() / "research/model_zoo"
    for package, hashes in (
        ("pe_c1_c4_external_runtime_closure_v4", _V4_HASHES),
        ("pe_c1_c4_fresh_qualification_runtime_v3", _V3_HASHES),
    ):
        for leaf, expected in hashes.items():
            assert hashlib.sha256((root / package / leaf).read_bytes()).hexdigest() == expected


def test_contracts_are_spent_only_and_all_authority_counts_zero() -> None:
    parsed = [json.loads(raw) for raw in contracts.contract_bundle_bytes()]
    assert len(parsed) == 4
    discovery, custody_contract, monitor_contract, denial = parsed
    assert discovery["evidence_class"] == "SPENT_IMPORT_ONLY_NO_FRESH_NO_SCORE"
    assert discovery["application_argv_count"] == 0
    assert discovery["close_fds"] is True
    assert discovery["independent_pass_count"] == 2
    assert discovery["model_callable_invocation_allowed"] is False
    assert discovery["caller_selected_module_path_or_record_allowed"] is False
    assert custody_contract["process_tree_loaded_native_dll"] is True
    assert custody_contract["held_through_child_exit_and_receipt_seal"] is True
    assert monitor_contract["external_monitor_process"] is True
    assert monitor_contract["max_sample_interval_ms"] == 100.0
    assert denial["production_execution_status"].startswith("DENIED_")
    assert denial["production_execution_eligible"] is False
    assert set(denial["counts"].values()) == {0}
    assert set(denial["counts"]) >= {
        "signer_access_count",
        "authority_access_count",
        "generation_count",
        "fresh_access_count",
        "truth_access_count",
        "heldout_access_count",
        "prediction_artifact_access_count",
        "score_access_count",
    }


def test_r2_source_is_isolated_and_child_has_import_only_workload() -> None:
    root = _project_root() / "research/model_zoo/pe_c1_c4_external_runtime_closure_v4_r2"
    sources = {path.name: path.read_text(encoding="utf-8") for path in root.glob("*.py")}
    assert len(sources) == 9
    for source in sources.values():
        assert "pe_c1_c4_external_runtime_closure_v4." not in source
        assert "pe_c1_c4_fresh_qualification_runtime_v3" not in source
        ast.parse(source)
    child_tree = ast.parse(sources["child_entry.py"])
    forbidden_calls = {"fit", "predict", "predict_proba", "score", "evaluate", "run_task"}
    assert not any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in forbidden_calls
        for node in ast.walk(child_tree)
    )
    assert child_entry.FIXED_MODULES == contracts.DISCOVERY_MODULES
    assert child_entry.SYNTHETIC_ENTRY == contracts.SYNTHETIC_HOFS_ENTRY
    assert "subprocess" not in sources["child_entry.py"]
    assert "subprocess" not in sources["monitor_entry.py"]
    assert 'ctypes.CDLL("nvml.dll"' not in sources["supervisor.py"]
    assert 'ctypes.CDLL("nvml.dll"' not in sources["child_entry.py"]


@pytest.mark.parametrize("entry", [lanes.run_shared_c1_c3_lane, lanes.run_isolated_c4_lane])
def test_production_entries_deny_before_input_or_numeric_import(
    entry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    imported: list[str] = []
    original = builtins.__import__

    def guarded(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith(("numpy", "pandas", "lightgbm", "sklearn")):
            imported.append(name)
            raise AssertionError(f"numeric import occurred: {name}")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    with pytest.raises(contracts.RuntimeClosureR2Error, match="denied before input/import"):
        entry(_Poison())
    assert imported == []
    assert tuple(inspect.signature(entry).parameters) == ("tasks",)


def test_two_pass_entry_has_no_caller_path_module_or_record_parameter() -> None:
    assert tuple(inspect.signature(supervisor.run_two_pass_spent_discovery).parameters) == ()
    assert tuple(inspect.signature(supervisor.run_discovery_pass).parameters) == ("pass_ordinal",)
    assert tuple(runtime_r2.__all__) == (
        "DISCOVERY_STATUS",
        "PRODUCTION_EXECUTION_STATUS",
        "RuntimeClosureR2Error",
        "SOURCE_STATUS",
        "ZERO_COUNTS",
        "contract_bundle_bytes",
        "run_isolated_c4_lane",
        "run_shared_c1_c3_lane",
    )


def test_exact_environment_rejects_extra_or_changed_member() -> None:
    exact = dict(contracts.EXACT_CHILD_ENVIRONMENT)
    assert contracts.validate_exact_environment(exact) == dict(sorted(exact.items()))
    attacked = dict(exact)
    attacked["CALLER_EXTRA"] = "1"
    with pytest.raises(contracts.RuntimeClosureR2Error, match="extra"):
        contracts.validate_exact_environment(attacked)
    attacked = dict(exact)
    attacked["CUDA_VISIBLE_DEVICES"] = "0"
    with pytest.raises(contracts.RuntimeClosureR2Error, match="changed"):
        contracts.validate_exact_environment(attacked)


class _FakeProtocol:
    role_names = ("stdin_control", "stdout_protocol", "stderr", "job_query")
    handle_roles = {"job_query": 44}


def test_bootstrap_exact_handle_ledger_rejects_decoy_duplicate() -> None:
    payload = {
        "schema_version": "expected_pe.external_runtime_closure.v4_r2.monitor_bootstrap",
        "event": "bootstrap_handles",
        "actual_stdio_handles": {
            "stdin_control": 11,
            "stdout_protocol": 22,
            "stderr": 33,
        },
        "process_identity": {
            "pid": 1,
            "creation_time_100ns": 2,
            "image_path": contracts.PINNED_PROCESS_IMAGE,
        },
        "application_argv_count": 0,
    }
    protocol = _FakeProtocol()
    assert (
        supervisor._bind_bootstrap_handles(  # noqa: SLF001
            protocol, payload, role="monitor"
        )["pid"]
        == 1
    )
    assert protocol.handle_roles == {
        "stdin_control": 11,
        "stdout_protocol": 22,
        "stderr": 33,
        "job_query": 44,
    }
    attacked = json.loads(json.dumps(payload))
    attacked["actual_stdio_handles"]["stderr"] = 22
    protocol = _FakeProtocol()
    with pytest.raises(contracts.RuntimeClosureR2Error, match="stdio handle"):
        supervisor._bind_bootstrap_handles(protocol, attacked, role="monitor")  # noqa: SLF001
    attacked = json.loads(json.dumps(payload))
    attacked["actual_stdio_handles"]["decoy"] = 55
    protocol = _FakeProtocol()
    with pytest.raises(contracts.RuntimeClosureR2Error, match="stdio handle"):
        supervisor._bind_bootstrap_handles(protocol, attacked, role="monitor")  # noqa: SLF001


def test_monitor_receipt_validates_owner_rss_gpu0_and_timestamps() -> None:
    payload = _monitor_receipt()
    supervisor._validate_monitor_receipt(  # noqa: SLF001
        payload,
        pass_ordinal=1,
        controller_identity={
            "pid": 100,
            "creation_time_100ns": 200,
            "image_path": contracts.PINNED_PROCESS_IMAGE,
        },
    )


@pytest.mark.parametrize("attack", ["gap", "pid_reuse", "gpu", "hung", "owner_alias"])
def test_monitor_adversarial_gap_pid_reuse_gpu_hung_and_owner_alias_fail(attack: str) -> None:
    payload = _monitor_receipt()
    if attack == "gap":
        payload["samples"][1]["observed_perf_counter_ns"] = 1_230_000_000
        payload["sampling_ended_perf_counter_ns"] = 1_230_000_000
        payload["nvml_shutdown_started_perf_counter_ns"] = 1_240_000_000
        payload["nvml_shutdown_completed_perf_counter_ns"] = 1_250_000_000
        payload["receipt_sealed_perf_counter_ns"] = 1_260_000_000
        payload["sample_interval_max_ms"] = 200.0
        message = "gap"
    elif attack == "pid_reuse":
        payload["samples"][1]["processes"][0]["creation_time_100ns"] = 201
        message = "PID reuse"
    elif attack == "gpu":
        payload["samples"][0]["gpu_processes"] = [
            {"device_ordinal": 0, "pid": 100, "used_vram_bytes": 1}
        ]
        payload["gpu_process_observation_count"] = 1
        payload["peak_vram_bytes"] = 1
        message = "GPU0"
    elif attack == "hung":
        payload["nvml_shutdown_completed_perf_counter_ns"] = 7_060_000_001
        payload["receipt_sealed_perf_counter_ns"] = 7_070_000_001
        message = "shutdown"
    else:
        payload["owner_identity"]["pid"] = 100
        message = "owner identity"
    with pytest.raises(contracts.RuntimeClosureR2Error, match=message):
        supervisor._validate_monitor_receipt(  # noqa: SLF001
            payload,
            pass_ordinal=1,
            controller_identity={
                "pid": 100,
                "creation_time_100ns": 200,
                "image_path": contracts.PINNED_PROCESS_IMAGE,
            },
        )


def test_two_pass_closure_difference_fails_closed() -> None:
    first = _equivalence_pass()
    second = json.loads(json.dumps(first))
    summary = supervisor.validate_two_pass_equivalence(first, second)
    assert summary["closure_equality"] is True
    assert summary["independent_pass_count"] == 2
    assert set(summary["counts"].values()) == {0}
    second["closure_file_records"][0]["raw_sha256"] = "e" * 64
    with pytest.raises(contracts.RuntimeClosureR2Error, match="passes differ"):
        supervisor.validate_two_pass_equivalence(first, second)


@pytest.mark.skipif(os.name != "nt", reason="Win32 held custody")
def test_observed_custody_reparse_alias_and_swap_attacks_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "runtime.pyd"
    target.write_bytes(b"native-v1\n")
    monkeypatch.setattr(custody, "_classify", lambda _path: "site_package_extension")
    original_reparse = custody._metadata_is_reparse  # noqa: SLF001

    def reparse(path: Path) -> bool:
        return custody._path_key(path) == custody._path_key(target) or original_reparse(path)  # noqa: SLF001

    monkeypatch.setattr(custody, "_metadata_is_reparse", reparse)
    with pytest.raises(contracts.RuntimeClosureR2Error, match="reparse path"):
        with custody.ObservedClosureCustody(((str(target), ("test",)),)):
            raise AssertionError("reparse attack reached body")
    monkeypatch.setattr(custody, "_metadata_is_reparse", original_reparse)
    held = custody.ObservedClosureCustody(((str(target), ("test",)),))
    held.__enter__()
    original_read = custody._read_handle  # noqa: SLF001
    try:
        file_handle = next(iter(held._file_handles.values()))  # noqa: SLF001

        def swapped(handle: int) -> bytes:
            if handle == file_handle:
                return b"native-v2\n"
            return original_read(handle)

        monkeypatch.setattr(custody, "_read_handle", swapped)
        with pytest.raises(contracts.RuntimeClosureR2Error, match="drifted"):
            held.assert_live()
    finally:
        monkeypatch.setattr(custody, "_read_handle", original_read)
        held.close()

    alias = tmp_path / "alias.pyd"
    os.link(target, alias)
    with pytest.raises(contracts.RuntimeClosureR2Error, match="FileId alias"):
        with custody.ObservedClosureCustody(((str(target), ("test",)), (str(alias), ("test",)))):
            raise AssertionError("hard-link alias reached body")


@pytest.mark.skipif(os.name != "nt", reason="fixed Windows Py3.10/NVML discovery")
def test_live_no_fresh_spent_discovery_pass() -> None:
    receipt = supervisor.run_discovery_pass(1)
    assert receipt["status"] == "PASS_ACTUAL_SPENT_IMPORT_ONLY_CLOSURE_HELD"
    assert receipt["child_zero_application_argv"] is True
    assert receipt["child_close_fds"] is True
    assert receipt["child_handle_list_count"] == 3
    assert receipt["monitor_handle_list_count"] == 4
    assert receipt["child_decoy_handle_inherited"] is False
    assert receipt["monitor_decoy_handle_inherited"] is False
    assert receipt["closure_file_record_count"] > 100
    assert receipt["closure_ancestry_record_count"] > 10
    kinds = {row["kind"] for row in receipt["closure_file_records"]}
    assert kinds >= {
        "interpreter",
        "project_source",
        "stdlib_source",
        "site_package_source",
        "site_package_extension",
        "native_loader_dependency",
        "system_native_dependency",
    }
    assert all(row["volume_serial_number"] > 0 for row in receipt["closure_file_records"])
    assert all(row["file_id_128"] != "0" * 32 for row in receipt["closure_file_records"])
    assert receipt["monitor_receipt"]["sample_interval_max_ms"] <= 100.0
    assert receipt["monitor_receipt"]["gpu_process_observation_count"] == 0
    assert receipt["monitor_receipt"]["peak_vram_bytes"] == 0
    assert set(receipt["counts"].values()) == {0}
