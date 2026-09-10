from __future__ import annotations

import builtins
from dataclasses import FrozenInstanceError
import hashlib
import inspect
import json
from pathlib import Path
import time
from typing import Any

import pytest

import research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v2 as runtime_v2
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v2 import (
    C4_NUMERIC_EXECUTION_STATUS,
    ISOLATED_LANE_ID,
    ObservedGpuProcess,
    ObservedProcess,
    QualificationRuntimeV2Error,
    RuntimeSample,
    SHARED_LANE_ID,
    SHARED_NUMERIC_EXECUTION_STATUS,
    TerminalProcess,
    build_c4_assignment_plan,
    contract_payload,
    run_isolated_c4_lane,
    run_shared_c1_c3_lane,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v2 import contracts, lanes, monitor
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.contract import (
    validate_runtime_bindings,
)


V1_FROZEN_HASHES = {
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/__init__.py": (
        "cfd5aa88678292ee9691cb12a3e170ba3e01df879dc291e19c3c3a8d490df892"
    ),
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/contracts.py": (
        "198b5d611edda31d8bd1fb3809eae2a1245795a11da7aaa2f887db227ddfabde"
    ),
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/lanes.py": (
        "6cef6400f488339f65b9cff04e76fa2f43d49086047d1e247e15927bad04984d"
    ),
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/monitor.py": (
        "f0a249d4f583b9896e64bb558ef9bd1bf90745be1018c312cac160f06b8fc702"
    ),
    "research/model_zoo/pe_c1_c4_fresh_qualification_runtime_v1/DESIGN.md": (
        "9f6c13810e5816c691491bbc51a23bbab0bc48dd77279265765e0bd1fb853e7a"
    ),
    "tests/model_lab/test_pe_c1_c4_fresh_qualification_runtime_v1.py": (
        "3d54ab241c3f0edbbdfbc2158b49d0cb0761b45cf8dac2e5d73e3b8847b476cc"
    ),
}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _terminals() -> tuple[TerminalProcess, ...]:
    return (
        TerminalProcess("controller", 0, 1_000, 10_000, 0),
        *(
            TerminalProcess("worker", ordinal, 2_000 + ordinal, 20_000 + ordinal, 0)
            for ordinal in range(16)
        ),
    )


def _processes(*, parent_pid: int = 1_000) -> tuple[ObservedProcess, ...]:
    return (
        ObservedProcess(1_000, 900, 10_000, 10_000),
        *(
            ObservedProcess(
                2_000 + ordinal,
                parent_pid,
                20_000 + ordinal,
                1_000 + ordinal,
            )
            for ordinal in range(16)
        ),
    )


def _samples(
    *,
    gap_ns: int = 50_000_000,
    processes: tuple[ObservedProcess, ...] | None = None,
    gpu: tuple[ObservedGpuProcess, ...] = (),
) -> tuple[RuntimeSample, ...]:
    rows = _processes() if processes is None else processes
    return (
        RuntimeSample(1_000_000_000, rows),
        RuntimeSample(1_000_000_000 + gap_ns, rows, gpu),
    )


def _candidate(lane_id: str = ISOLATED_LANE_ID):
    return monitor._build_receipt_candidate_bytes(  # noqa: SLF001
        lane_id=lane_id,
        samples=_samples(),
        terminal_processes=_terminals(),
    )


def test_v1_failed_audited_attempt_is_byte_preserved() -> None:
    root = _project_root()
    for relative, expected in V1_FROZEN_HASHES.items():
        assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == expected


class _Poison:
    def __getattribute__(self, name: str) -> Any:
        raise AssertionError(f"denied entry inspected caller object: {name}")

    def __iter__(self):
        raise AssertionError("denied entry iterated caller object")

    def __len__(self) -> int:
        raise AssertionError("denied entry measured caller object")


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        (run_shared_c1_c3_lane, "shared C1-C3 numeric execution"),
        (run_isolated_c4_lane, "isolated C4 numeric execution"),
    ],
)
def test_both_numeric_entries_deny_before_input_grant_or_import(
    entry: Any,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forbidden_imports: list[str] = []
    original_import = builtins.__import__

    def guarded_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith(
            (
                "research.model_zoo.pe_c1_c3_fresh_qualification_service_v1",
                "research.model_zoo.hofs_v12_fresh_qualification_service_v1",
            )
        ):
            forbidden_imports.append(name)
            raise AssertionError(f"numeric package imported: {name}")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    with pytest.raises(QualificationRuntimeV2Error, match=message):
        entry(_Poison(), external_grant=_Poison())
    assert forbidden_imports == []


def test_denial_is_a_source_literal_not_a_caller_grant_validator() -> None:
    assert SHARED_NUMERIC_EXECUTION_STATUS.startswith("DENIED_")
    assert C4_NUMERIC_EXECUTION_STATUS.startswith("DENIED_")
    source = inspect.getsource(lanes)
    assert "importlib" not in source
    assert "sys.modules" not in source
    assert "Path(" not in source
    assert "signature" not in source.lower()
    assert "file_id" not in source.lower()
    assert "grant[" not in source


def test_contract_truthfully_marks_import_closure_and_authority_pending() -> None:
    payload = contract_payload()
    assert payload["status"] == "SOURCE_ONLY_BOTH_NUMERIC_LANES_DENIED"
    assert payload["shared_lane"]["source_closure_status"].startswith("PENDING_")
    assert payload["isolated_c4_lane"]["source_closure_status"].startswith("PENDING_")
    future = payload["future_activation"]
    assert future == {
        "authority_requirement": (
            "EXACT_EXTERNAL_SIGNED_NONCE_FILE_ID_SOURCE_LOCK_AND_TASK_MANIFEST_GRANT"
        ),
        "loader_policy": (
            "VENDORED_CLEAN_PACKAGE_OR_HELD_DIRECT_VERIFIED_BYTES_NO_ORIGINAL_PACKAGE_INIT"
        ),
        "original_package_init_import_allowed": False,
        "publisher_import_allowed": False,
        "cached_module_reuse_allowed": False,
        "source_verify_then_normal_import_allowed": False,
        "complete_declared_equals_actual_import_closure_required": True,
    }
    assert payload["authority_counts"] == {
        "qualification_access_count": 0,
        "fresh_access_count": 0,
        "truth_access_count": 0,
        "heldout_access_count": 0,
        "score_access_count": 0,
        "publication_count": 0,
    }


def test_c4_declaration_preserves_exact_resource_and_ordinal_contract() -> None:
    plan = build_c4_assignment_plan()
    assert len(plan) == 50
    assert tuple(item.task_ordinal for item in plan) == tuple(range(50))
    assert tuple(item.worker_ordinal for item in plan) == tuple(index % 16 for index in range(50))
    c4 = contract_payload()["isolated_c4_lane"]
    assert c4["outer_workers"] == 16
    assert c4["cpu_ids"] == list(range(32))
    assert c4["affinity_mask_hex"] == "0xFFFFFFFF"
    assert c4["inner_threads"] == 1
    assert c4["thread_environment"]["CUDA_VISIBLE_DEVICES"] == "-1"


@pytest.mark.parametrize(
    "constructor",
    [
        lambda: contracts.C4TaskAssignment(True, "qualification_seed_01", "A", 0),
        lambda: contracts.C4TaskAssignment(0, "qualification_seed_01", "A", True),
        lambda: TerminalProcess("worker", True, 2_000, 20_000, 0),
        lambda: TerminalProcess("worker", 0, True, 20_000, 0),
        lambda: TerminalProcess("worker", 0, 2_000, True, 0),
        lambda: TerminalProcess("worker", 0, 2_000, 20_000, True),
        lambda: RuntimeSample(True, _processes()),
    ],
)
def test_bool_identity_and_ordinal_attacks_fail(constructor: Any) -> None:
    with pytest.raises(QualificationRuntimeV2Error):
        constructor()


def test_candidate_is_private_deeply_immutable_cross_bound_bytes() -> None:
    candidate = _candidate()
    assert not hasattr(runtime_v2, "ReceiptCandidateBytes")
    assert not any("candidate" in name.lower() for name in runtime_v2.__all__)
    assert all(
        type(getattr(candidate, field)) in {bytes, str}
        for field in candidate.__dataclass_fields__
    )
    with pytest.raises(FrozenInstanceError):
        candidate.evaluator_receipt_bytes = b"tampered"
    parsed = json.loads(candidate.evaluator_receipt_bytes)
    parsed["peak_vram_bytes"] = 1
    assert json.loads(candidate.evaluator_receipt_bytes)["peak_vram_bytes"] == 0
    identity = json.loads(candidate.process_identity_evidence_bytes)
    authority = json.loads(candidate.authority_state_bytes)
    assert identity["evaluator_receipt_sha256"] == candidate.evaluator_receipt_sha256
    assert authority["evaluator_receipt_sha256"] == candidate.evaluator_receipt_sha256
    assert authority["process_identity_evidence_sha256"] == (
        candidate.process_identity_evidence_sha256
    )
    assert set(authority["counts"].values()) == {0}


def test_candidate_receipt_still_matches_evaluator_exact_13_fields() -> None:
    shared = _candidate(SHARED_LANE_ID)
    isolated = _candidate(ISOLATED_LANE_ID)
    shared_receipt = json.loads(shared.evaluator_receipt_bytes)
    isolated_receipt = json.loads(isolated.evaluator_receipt_bytes)
    assert set(shared_receipt) == set(contracts.RUNTIME_FIELDS)
    validated = validate_runtime_bindings(
        [
            {
                "raw_sha256": shared.evaluator_receipt_sha256,
                "file_id": {"volume_serial_number": 1, "file_id_128": "1" * 32},
                "receipt": shared_receipt,
            },
            {
                "raw_sha256": isolated.evaluator_receipt_sha256,
                "file_id": {"volume_serial_number": 1, "file_id_128": "2" * 32},
                "receipt": isolated_receipt,
            },
        ]
    )
    assert tuple(item["receipt"]["lane_id"] for item in validated) == (
        SHARED_LANE_ID,
        ISOLATED_LANE_ID,
    )


@pytest.mark.parametrize(
    "attack",
    ["late_gap", "gpu", "missing", "parent", "nonzero", "duplicate"],
)
def test_receipt_measurement_attacks_fail_closed(attack: str) -> None:
    samples = _samples()
    terminals = _terminals()
    if attack == "late_gap":
        samples = _samples(gap_ns=100_000_001)
    elif attack == "gpu":
        samples = _samples(
            gpu=(ObservedGpuProcess(device_ordinal=0, pid=2_000, used_vram_bytes=0),)
        )
    elif attack == "missing":
        samples = _samples(processes=_processes()[:-1])
    elif attack == "parent":
        samples = _samples(processes=_processes(parent_pid=999))
    elif attack == "nonzero":
        terminals = (*terminals[:-1], TerminalProcess("worker", 15, 2_015, 20_015, 1))
    else:
        terminals = (*terminals[:-1], TerminalProcess("worker", 15, 2_014, 20_014, 0))
    with pytest.raises(QualificationRuntimeV2Error):
        monitor._build_receipt_candidate_bytes(  # noqa: SLF001
            lane_id=ISOLATED_LANE_ID,
            samples=samples,
            terminal_processes=terminals,
        )


def test_inaccessible_or_disappearing_active_descendant_is_not_filtered() -> None:
    parents = {1_000: 900, 2_000: 1_000}

    def disappearing_query(pid: int, parent_pid: int) -> ObservedProcess | None:
        if pid == 2_000:
            return None
        return ObservedProcess(pid, parent_pid, 10_000, 1_000)

    with pytest.raises(QualificationRuntimeV2Error, match="disappeared"):
        monitor._collect_descendant_processes(  # noqa: SLF001
            parents,
            1_000,
            disappearing_query,
        )

    def inaccessible_query(pid: int, parent_pid: int) -> ObservedProcess:
        if pid == 2_000:
            raise QualificationRuntimeV2Error("active descendant is inaccessible")
        return ObservedProcess(pid, parent_pid, 10_000, 1_000)

    with pytest.raises(QualificationRuntimeV2Error, match="inaccessible"):
        monitor._collect_descendant_processes(  # noqa: SLF001
            parents,
            1_000,
            inaccessible_query,
        )


class _FailingSnapshotKernel:
    def CreateToolhelp32Snapshot(self, flags: int, pid: int) -> int:
        assert (flags, pid) == (monitor._TH32CS_SNAPPROCESS, 0)  # noqa: SLF001
        return 123

    def Process32FirstW(self, handle: int, entry: object) -> bool:
        assert handle == 123
        return False

    def CloseHandle(self, handle: int) -> bool:
        assert handle == 123
        return False


class _FailingProcessKernel:
    def OpenProcess(self, access: int, inherit: bool, pid: int) -> int:
        assert access == (
            monitor._PROCESS_QUERY_LIMITED_INFORMATION  # noqa: SLF001
            | monitor._PROCESS_VM_READ  # noqa: SLF001
        )
        assert (inherit, pid) == (False, 2_000)
        return 456

    def GetProcessTimes(self, *args: object) -> bool:
        assert args[0] == 456
        return False

    def CloseHandle(self, handle: int) -> bool:
        assert handle == 456
        return False


def test_native_primary_and_close_handle_failures_are_aggregated() -> None:
    with pytest.raises(QualificationRuntimeV2Error) as snapshot_failure:
        monitor._process_parent_snapshot(_FailingSnapshotKernel())  # noqa: SLF001
    assert "Process32FirstW failed" in str(snapshot_failure.value)
    assert "process snapshot CloseHandle failed" in str(snapshot_failure.value)

    with pytest.raises(QualificationRuntimeV2Error) as process_failure:
        monitor._query_process(  # noqa: SLF001
            _FailingProcessKernel(),
            object(),
            pid=2_000,
            parent_pid=1_000,
        )
    assert "GetProcessTimes failed" in str(process_failure.value)
    assert "process 2000 CloseHandle failed" in str(process_failure.value)


class _Probe:
    def __init__(
        self,
        *,
        fail_sample_at: int | None = None,
        close_failure: bool = False,
        block_after_first_seconds: float = 0.0,
    ) -> None:
        self.calls = 0
        self.closed = False
        self.fail_sample_at = fail_sample_at
        self.close_failure = close_failure
        self.block_after_first_seconds = block_after_first_seconds

    def sample(
        self,
        root_pid: int,
        root_creation_time_100ns: int,
    ) -> tuple[tuple[ObservedProcess, ...], tuple[ObservedGpuProcess, ...]]:
        assert (root_pid, root_creation_time_100ns) == (1_000, 10_000)
        self.calls += 1
        if self.calls > 1 and self.block_after_first_seconds:
            time.sleep(self.block_after_first_seconds)
        if self.fail_sample_at == self.calls:
            raise QualificationRuntimeV2Error("injected sample failure")
        return _processes(), ()

    def close(self) -> None:
        self.closed = True
        if self.close_failure:
            raise QualificationRuntimeV2Error("injected close failure")


def _test_sampler(probe: _Probe, *, interval_ms: float = 5.0):
    return monitor.ExternalProcessTreeSampler._from_probe_for_tests(  # noqa: SLF001
        root_pid=1_000,
        root_creation_time_100ns=10_000,
        lane_id=ISOLATED_LANE_ID,
        sample_interval_ms=interval_ms,
        probe=probe,
    )


def test_invalid_construction_closes_probe_and_aggregates_close_failure() -> None:
    probe = _Probe(close_failure=True)
    with pytest.raises(QualificationRuntimeV2Error) as captured:
        _test_sampler(probe, interval_ms=100.0)
    message = str(captured.value)
    assert "configured sample interval" in message
    assert "injected close failure" in message
    assert probe.closed is True


def test_sampler_aggregates_sampling_and_close_failures() -> None:
    probe = _Probe(fail_sample_at=2, close_failure=True)
    sampler = _test_sampler(probe)
    sampler.start()
    deadline = time.monotonic() + 1.0
    while not probe.closed and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(QualificationRuntimeV2Error) as captured:
        sampler.stop(_terminals())
    message = str(captured.value)
    assert "injected sample failure" in message
    assert "injected close failure" in message
    assert probe.closed is True


def test_sampler_thread_owns_probe_through_join_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = _Probe(block_after_first_seconds=0.1)
    sampler = _test_sampler(probe)
    monkeypatch.setattr(monitor, "_SAMPLER_JOIN_TIMEOUT_SECONDS", 0.001)
    sampler.start()
    deadline = time.monotonic() + 1.0
    while probe.calls < 2 and time.monotonic() < deadline:
        time.sleep(0.001)
    with pytest.raises(QualificationRuntimeV2Error, match="lifetime remains owned"):
        sampler.stop(_terminals())
    deadline = time.monotonic() + 1.0
    while not probe.closed and time.monotonic() < deadline:
        time.sleep(0.005)
    assert probe.closed is True


def test_sampler_success_returns_only_immutable_candidate_bytes() -> None:
    probe = _Probe()
    sampler = _test_sampler(probe)
    sampler.start()
    deadline = time.monotonic() + 1.0
    while sampler.sample_count < 3 and time.monotonic() < deadline:
        time.sleep(0.005)
    candidate = sampler.stop(_terminals())
    assert probe.closed is True
    assert candidate.evaluator_receipt_sha256 == hashlib.sha256(
        candidate.evaluator_receipt_bytes
    ).hexdigest()
    assert not hasattr(candidate, "receipt")


def test_native_abi_and_no_writer_surface() -> None:
    source = inspect.getsource(monitor)
    for required in (
        "CreateToolhelp32Snapshot.argtypes",
        "Process32FirstW.argtypes",
        "Process32NextW.argtypes",
        "OpenProcess.argtypes",
        "GetProcessTimes.argtypes",
        "CloseHandle.argtypes",
        "GetProcessMemoryInfo.argtypes",
        "nvmlDeviceGetComputeRunningProcesses_v3.argtypes",
        "nvmlShutdown.argtypes",
    ):
        assert required in source
    for module in (lanes, monitor):
        module_source = inspect.getsource(module)
        assert "os.rename" not in module_source
        assert "write_bytes" not in module_source
        assert "publish" not in module.__all__
