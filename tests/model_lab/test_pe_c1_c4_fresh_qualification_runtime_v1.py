from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import inspect
import sys
import time
from typing import Any

import pytest

from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v1 import (
    C4_EXECUTION_AUTHORITY_STATUS,
    C4ScheduledTask,
    ISOLATED_LANE_ID,
    ObservedGpuProcess,
    ObservedProcess,
    QualificationRuntimeError,
    RuntimeSample,
    RuntimeReceiptArtifact,
    SHARED_LANE_ID,
    TerminalProcess,
    build_c4_assignment_plan,
    contract_payload,
    run_isolated_c4_lane,
    run_shared_c1_c3_lane,
    validate_runtime_receipt,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v1 import lanes, monitor
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.contract import (
    validate_runtime_bindings,
)


def _terminals() -> tuple[TerminalProcess, ...]:
    return (
        TerminalProcess(
            process_role="controller",
            worker_ordinal=0,
            pid=1_000,
            creation_time_100ns=10_000,
            exit_code=0,
        ),
        *(
            TerminalProcess(
                process_role="worker",
                worker_ordinal=ordinal,
                pid=2_000 + ordinal,
                creation_time_100ns=20_000 + ordinal,
                exit_code=0,
            )
            for ordinal in range(16)
        ),
    )


def _processes(*, parent_override: int | None = None) -> tuple[ObservedProcess, ...]:
    return (
        ObservedProcess(
            pid=1_000,
            parent_pid=900,
            creation_time_100ns=10_000,
            rss_bytes=10_000,
        ),
        *(
            ObservedProcess(
                pid=2_000 + ordinal,
                parent_pid=1_000 if parent_override is None else parent_override,
                creation_time_100ns=20_000 + ordinal,
                rss_bytes=1_000 + ordinal,
            )
            for ordinal in range(16)
        ),
    )


def _samples(
    *,
    gap_ns: int = 50_000_000,
    gpu: tuple[ObservedGpuProcess, ...] = (),
    processes: tuple[ObservedProcess, ...] | None = None,
) -> tuple[RuntimeSample, ...]:
    frozen_processes = _processes() if processes is None else processes
    return (
        RuntimeSample(
            observed_perf_counter_ns=1_000_000_000,
            processes=frozen_processes,
        ),
        RuntimeSample(
            observed_perf_counter_ns=1_000_000_000 + gap_ns,
            processes=frozen_processes,
            gpu_processes=gpu,
        ),
    )


def _artifact(lane_id: str = ISOLATED_LANE_ID):
    return monitor._build_runtime_artifact_from_samples(  # noqa: SLF001
        lane_id=lane_id,
        samples=_samples(),
        terminal_processes=_terminals(),
    )


def test_source_contract_is_exactly_non_authoritative() -> None:
    payload = contract_payload()
    assert payload["status"] == "SOURCE_ONLY_NO_ACTUAL_QUALIFICATION_EXECUTION"
    assert payload["authority"] == {
        "qualification_access_count": 0,
        "fresh_access_count": 0,
        "truth_access_count": 0,
        "heldout_access_count": 0,
        "score_access_count": 0,
        "publication_count": 0,
    }
    c4 = payload["c4_scheduler"]
    assert c4["task_count"] == 50
    assert c4["outer_workers"] == 16
    assert c4["cpu_ids"] == list(range(32))
    assert c4["affinity_mask_hex"] == "0xFFFFFFFF"
    assert c4["inner_threads"] == 1
    assert c4["environment"] == {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
    }
    assert c4["execution_authority_status"].startswith("DENIED_")
    assert c4["source_pin_records_semantic_sha256"] == (
        "c1a27fcfadbe60646b40791397b235d078d0b5e39f0902b6811f9996e433e073"
    )
    assert [row["raw_sha256"] for row in c4["source_pin_records"]] == [
        "f102f337ddf5fc51a3411b1ef779fa993e5bd2287357e67c181b1b4be5e611c2",
        "36319ec65dbe3b8145fcfc46ae33a055aee64339f09cfd1e391cfb660bb3f822",
        "f67973761529bc94b7279cc09c5d3c1d18ebe996b308a6064fb52a4281abeabc",
        "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c",
    ]
    assert payload["shared_lane_source"]["source_pin_records_semantic_sha256"] == (
        "e14de09609951f1dc3920953ad73cbb6e9bf26d35a6cbe608a4583d4ab97cf32"
    )
    assert payload["shared_lane_source"]["stable_rehash_before_runner_import"] is True
    assert payload["monitor"]["atomic_output_authority"] is False


def test_c4_assignment_plan_is_exact_50_task_ordinal_queue() -> None:
    plan = build_c4_assignment_plan()
    assert len(plan) == 50
    assert tuple(item.task_ordinal for item in plan) == tuple(range(50))
    assert tuple(item.worker_ordinal for item in plan) == tuple(index % 16 for index in range(50))
    assert tuple((item.seed_alias, item.dgp_id) for item in plan) == tuple(
        (f"qualification_seed_{index // 10 + 1:02d}", chr(ord("A") + index % 10))
        for index in range(50)
    )
    assert [item.task_ordinal for item in plan if item.worker_ordinal == 0] == [0, 16, 32, 48]


class _PoisonTasks:
    def __len__(self) -> int:
        raise AssertionError("denied C4 path inspected task length")

    def __iter__(self):
        raise AssertionError("denied C4 path inspected tasks")


def test_spent_only_c4_call_fails_before_tasks_or_hofs_import(monkeypatch: pytest.MonkeyPatch) -> None:
    assert C4_EXECUTION_AUTHORITY_STATUS.startswith("DENIED_")
    called = {"source": 0, "validator": 0, "backend": 0}

    def forbidden_source() -> None:
        called["source"] += 1
        raise AssertionError("denied C4 path inspected source pins")

    def forbidden_validator(value: object) -> None:
        called["validator"] += 1
        raise AssertionError(value)

    def forbidden_backend(value: object) -> None:
        called["backend"] += 1
        raise AssertionError(value)

    monkeypatch.setattr(lanes, "_verify_c4_source_pins", forbidden_source)
    monkeypatch.setattr(lanes, "_validate_c4_task_universe", forbidden_validator)
    monkeypatch.setattr(lanes, "_run_authorized_c4_lane", forbidden_backend)
    with pytest.raises(QualificationRuntimeError, match="denied before input inspection"):
        run_isolated_c4_lane(
            _PoisonTasks(),  # type: ignore[arg-type]
            final_binding={},
            authority_receipt={},
        )
    assert called == {"source": 0, "validator": 0, "backend": 0}
    assert "research.model_zoo.hofs_v12_fresh_qualification_service_v1.service" not in sys.modules


def test_hofs_execution_dependencies_match_independently_approved_pins() -> None:
    assert lanes._verify_c4_source_pins() == (  # noqa: SLF001
        "c1a27fcfadbe60646b40791397b235d078d0b5e39f0902b6811f9996e433e073"
    )


def test_shared_runner_dependencies_are_rehashed_before_import() -> None:
    assert lanes._verify_shared_source_pins() == (  # noqa: SLF001
        "e14de09609951f1dc3920953ad73cbb6e9bf26d35a6cbe608a4583d4ab97cf32"
    )


def test_shared_source_pin_drift_stops_before_runner_import(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = list(lanes.SHARED_SOURCE_PIN_RECORDS)
    relative, _, size = records[0]
    records[0] = (relative, "0" * 64, size)
    imported = {"count": 0}

    def forbidden_loader() -> None:
        imported["count"] += 1
        raise AssertionError("drifted shared runner was imported")

    monkeypatch.setattr(lanes, "SHARED_SOURCE_PIN_RECORDS", tuple(records))
    monkeypatch.setattr(lanes, "_load_shared_runner", forbidden_loader)
    with pytest.raises(QualificationRuntimeError, match="source pin bytes differ"):
        run_shared_c1_c3_lane(tuple(object() for _ in range(50)))
    assert imported["count"] == 0


def _c4_scheduled_tasks() -> tuple[C4ScheduledTask, ...]:
    return tuple(
        C4ScheduledTask(
            task_ordinal=ordinal,
            canonical_input=f"synthetic-spent-task-{ordinal:02d}".encode(),
            external_binding={
                "task_ordinal": ordinal,
                "synthetic_binding_id": f"binding-{ordinal:02d}",
            },
        )
        for ordinal in range(50)
    )


def test_c4_final_grant_binds_exact_ordered_task_bytes_and_external_bindings() -> None:
    supplied = _c4_scheduled_tasks()
    frozen = lanes._validate_c4_task_universe(supplied)  # noqa: SLF001
    semantic = lanes._c4_task_manifest_semantic_sha256(frozen)  # noqa: SLF001
    grant = {"task_manifest_semantic_sha256": semantic}
    assert lanes._validate_c4_task_manifest_binding(grant, frozen) == semantic  # noqa: SLF001

    tampered = (*frozen[:-1], replace(frozen[-1], canonical_input=b"tampered"))
    tampered = lanes._validate_c4_task_universe(tampered)  # noqa: SLF001
    with pytest.raises(QualificationRuntimeError, match="task manifest semantic"):
        lanes._validate_c4_task_manifest_binding(grant, tampered)  # noqa: SLF001


def test_c4_task_binding_is_deep_frozen_before_manifest_hash() -> None:
    supplied = list(_c4_scheduled_tasks())
    mutable_binding = dict(supplied[0].external_binding)
    supplied[0] = replace(supplied[0], external_binding=mutable_binding)
    frozen = lanes._validate_c4_task_universe(supplied)  # noqa: SLF001
    before = lanes._c4_task_manifest_semantic_sha256(frozen)  # noqa: SLF001
    mutable_binding["synthetic_binding_id"] = "caller-mutated"
    after = lanes._c4_task_manifest_semantic_sha256(frozen)  # noqa: SLF001
    assert before == after
    assert frozen[0].external_binding["synthetic_binding_id"] == "binding-00"


@dataclass(frozen=True)
class _SyntheticBatch:
    tasks: tuple[int, ...]
    runtime_receipt: dict[str, Any]


def test_shared_lane_calls_existing_runner_contract_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, int]] = []

    def fake_runner(tasks: object, *, max_workers: int) -> _SyntheticBatch:
        calls.append((tasks, max_workers))
        return _SyntheticBatch(
            tasks=tuple(range(50)),
            runtime_receipt={
                "qualification_runtime_artifact_authority": False,
                "external_measured_v2_runtime_receipt_binding_required": True,
                "truth_received": False,
                "score_computed": False,
                "heldout_received": False,
                "publication_authority": False,
            },
        )

    monkeypatch.setattr(lanes, "_load_shared_runner", lambda: fake_runner)
    injected = tuple(object() for _ in range(50))
    result = run_shared_c1_c3_lane(injected)
    assert calls == [(injected, 16)]
    assert result.tasks == tuple(range(50))
    assert result.internal_runtime_receipt["qualification_runtime_artifact_authority"] is False


def test_measured_receipt_is_evaluator_exact_and_retains_process_identities() -> None:
    shared = _artifact(SHARED_LANE_ID)
    isolated = _artifact(ISOLATED_LANE_ID)
    assert tuple(shared.receipt) != ()
    assert shared.receipt["sample_interval_max_ms"] == 50.0
    assert shared.receipt["peak_process_tree_rss_bytes"] == sum(
        item.rss_bytes for item in _processes()
    )
    assert shared.receipt["peak_vram_bytes"] == 0
    assert shared.receipt["gpu_process_observation_count"] == 0
    assert len(shared.process_identity_records) == 17
    assert shared.raw_sha256 == hashlib.sha256(shared.raw_bytes).hexdigest()
    validated = validate_runtime_bindings(
        [
            {
                "raw_sha256": shared.raw_sha256,
                "file_id": {"volume_serial_number": 1, "file_id_128": "1" * 32},
                "receipt": shared.receipt,
            },
            {
                "raw_sha256": isolated.raw_sha256,
                "file_id": {"volume_serial_number": 1, "file_id_128": "2" * 32},
                "receipt": isolated.receipt,
            },
        ]
    )
    assert tuple(item["receipt"]["lane_id"] for item in validated) == (
        SHARED_LANE_ID,
        ISOLATED_LANE_ID,
    )


def test_public_artifact_type_cannot_be_caller_minted() -> None:
    artifact = _artifact()
    with pytest.raises(QualificationRuntimeError, match="measured monitor"):
        RuntimeReceiptArtifact(
            receipt=artifact.receipt,
            raw_bytes=artifact.raw_bytes,
            raw_sha256=artifact.raw_sha256,
            process_identity_records=artifact.process_identity_records,
            authority_counts=artifact.authority_counts,
            _mint_token=object(),
        )


def test_exact_100ms_measured_gap_is_allowed() -> None:
    artifact = monitor._build_runtime_artifact_from_samples(  # noqa: SLF001
        lane_id=ISOLATED_LANE_ID,
        samples=_samples(gap_ns=100_000_000),
        terminal_processes=_terminals(),
    )
    assert artifact.receipt["sample_interval_max_ms"] == 100.0


@pytest.mark.parametrize(
    "attack",
    [
        "late_gap",
        "gpu",
        "missing_identity",
        "parent_drift",
        "duplicate_terminal",
        "nonzero_exit",
        "reordered_terminal",
        "duplicate_timestamp",
    ],
)
def test_monitor_attacks_fail_closed(attack: str) -> None:
    samples = _samples()
    terminals = _terminals()
    if attack == "late_gap":
        samples = _samples(gap_ns=100_000_001)
    elif attack == "gpu":
        samples = _samples(
            gpu=(ObservedGpuProcess(device_ordinal=0, pid=2_000, used_vram_bytes=1),)
        )
    elif attack == "missing_identity":
        samples = _samples(processes=_processes()[:-1])
    elif attack == "parent_drift":
        samples = _samples(processes=_processes(parent_override=999))
    elif attack == "duplicate_terminal":
        terminals = (*terminals[:-1], replace(terminals[-1], pid=terminals[-2].pid))
    elif attack == "nonzero_exit":
        terminals = (*terminals[:-1], replace(terminals[-1], exit_code=1))
    elif attack == "reordered_terminal":
        terminals = (terminals[1], terminals[0], *terminals[2:])
    else:
        samples = _samples(gap_ns=0)
    with pytest.raises(QualificationRuntimeError):
        monitor._build_runtime_artifact_from_samples(  # noqa: SLF001
            lane_id=ISOLATED_LANE_ID,
            samples=samples,
            terminal_processes=terminals,
        )


def test_runtime_receipt_rejects_bool_interval_and_extra_field() -> None:
    receipt = dict(_artifact().receipt)
    receipt["sample_interval_max_ms"] = True
    with pytest.raises(QualificationRuntimeError, match="finite JSON number"):
        validate_runtime_receipt(receipt, lane_id=ISOLATED_LANE_ID)
    receipt = dict(_artifact().receipt)
    receipt["caller_claim"] = True
    with pytest.raises(QualificationRuntimeError, match="field universe"):
        validate_runtime_receipt(receipt, lane_id=ISOLATED_LANE_ID)


def test_memory_floor_rejects_zero_rss_before_receipt_materialization() -> None:
    with pytest.raises(QualificationRuntimeError, match="process RSS"):
        ObservedProcess(
            pid=1_000,
            parent_pid=900,
            creation_time_100ns=10_000,
            rss_bytes=0,
        )


class _SyntheticProbe:
    def __init__(self, *, delay_seconds: float = 0.0, close_failure: bool = False) -> None:
        self.closed = False
        self.delay_seconds = delay_seconds
        self.close_failure = close_failure

    def sample(
        self,
        root_pid: int,
        root_creation_time_100ns: int,
    ) -> tuple[tuple[ObservedProcess, ...], tuple[ObservedGpuProcess, ...]]:
        assert (root_pid, root_creation_time_100ns) == (1_000, 10_000)
        if self.delay_seconds:
            time.sleep(self.delay_seconds)
        return _processes(), ()

    def close(self) -> None:
        self.closed = True
        if self.close_failure:
            raise QualificationRuntimeError("injected probe close failure")


def test_sampler_measures_real_perf_counter_gaps_with_synthetic_probe() -> None:
    probe = _SyntheticProbe()
    sampler = monitor.ExternalProcessTreeSampler._from_probe_for_tests(  # noqa: SLF001
        root_pid=1_000,
        root_creation_time_100ns=10_000,
        lane_id=ISOLATED_LANE_ID,
        sample_interval_ms=5.0,
        probe=probe,
    )
    sampler.start()
    deadline = time.monotonic() + 1.0
    while sampler.sample_count < 3 and time.monotonic() < deadline:
        time.sleep(0.005)
    artifact = sampler.stop(_terminals())
    assert artifact.receipt["sample_count"] >= 2
    assert 0.0 < artifact.receipt["sample_interval_max_ms"] <= 100.0
    assert probe.closed is True


def test_sampler_rejects_an_actually_measured_gap_over_100ms() -> None:
    probe = _SyntheticProbe(delay_seconds=0.11)
    sampler = monitor.ExternalProcessTreeSampler._from_probe_for_tests(  # noqa: SLF001
        root_pid=1_000,
        root_creation_time_100ns=10_000,
        lane_id=ISOLATED_LANE_ID,
        sample_interval_ms=5.0,
        probe=probe,
    )
    sampler.start()
    deadline = time.monotonic() + 1.0
    while sampler.sample_count < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(QualificationRuntimeError, match="gap exceeds"):
        sampler.stop(_terminals())
    assert probe.closed is True


def test_sampler_close_failure_cannot_return_a_pass_receipt() -> None:
    probe = _SyntheticProbe(close_failure=True)
    sampler = monitor.ExternalProcessTreeSampler._from_probe_for_tests(  # noqa: SLF001
        root_pid=1_000,
        root_creation_time_100ns=10_000,
        lane_id=ISOLATED_LANE_ID,
        sample_interval_ms=5.0,
        probe=probe,
    )
    sampler.start()
    deadline = time.monotonic() + 1.0
    while sampler.sample_count < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    with pytest.raises(QualificationRuntimeError, match="injected probe close failure"):
        sampler.stop(_terminals())
    assert probe.closed is True


def test_native_sampler_declares_exact_win32_and_nvml_abis() -> None:
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


def test_in_memory_boundary_exposes_no_publisher_or_file_writer() -> None:
    import research.model_zoo.pe_c1_c4_fresh_qualification_runtime_v1 as runtime_package

    assert not any("publish" in name.lower() for name in runtime_package.__all__)
    assert not any("write" in name.lower() for name in runtime_package.__all__)
    for module in (lanes, monitor):
        source = inspect.getsource(module)
        assert "os.rename" not in source
        assert "write_bytes" not in source
        assert "builtins.open" not in source
