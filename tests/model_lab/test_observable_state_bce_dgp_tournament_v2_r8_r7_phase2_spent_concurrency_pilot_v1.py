from __future__ import annotations

import copy
import os
from pathlib import Path
import subprocess
import sys

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_spent_concurrency_pilot_v1.contracts import (
    ACTIVATION_LITERAL,
    AUTHORITY_COUNTER_KEYS,
    CONCURRENCY_LEVELS,
    DGPS,
    EVIDENCE_CLASS,
    FAILED_R1_OUTPUT_ROOT_RELATIVE,
    FAILED_R2_OUTPUT_ROOT_RELATIVE,
    OUTPUT_ROOT_RELATIVE,
    PILOT_TASKS,
    PROJECT_ROOT,
    SPENT_REFERENCE_OUTPUT_LEDGER_SEMANTIC_SHA256,
    SPENT_SEEDS,
    TOTAL_PILOT_INVOCATIONS,
    zero_authority_counters,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_spent_concurrency_pilot_v1.native_metrics import (
    ProcessTreeMonitor,
    descendant_pids,
    physical_memory,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_spent_concurrency_pilot_v1.pilot import (
    _validate_stage_results,
    immutable_fixed_input_projection,
    output_absent,
    r7_raw_header_contract_finding,
    validate_source_owned_sys_path,
    verify_fixed_inputs,
)


def test_fixed_nested_task_waves_cover_the_spent_universe_evenly() -> None:
    assert CONCURRENCY_LEVELS == (1, 2, 4, 8, 16)
    assert TOTAL_PILOT_INVOCATIONS == 31
    assert len(PILOT_TASKS) == 16 == len(set(PILOT_TASKS))
    assert all(seed in SPENT_SEEDS and dgp in DGPS for seed, dgp in PILOT_TASKS)
    assert set(seed for seed, _ in PILOT_TASKS) == set(SPENT_SEEDS)
    assert set(dgp for _, dgp in PILOT_TASKS) == set(DGPS)
    for smaller, larger in zip(CONCURRENCY_LEVELS, CONCURRENCY_LEVELS[1:]):
        assert PILOT_TASKS[:smaller] == PILOT_TASKS[:larger][:smaller]


def test_authority_boundary_is_exactly_all_zero() -> None:
    counters = zero_authority_counters()
    assert tuple(counters) == AUTHORITY_COUNTER_KEYS
    assert set(counters.values()) == {0}
    assert EVIDENCE_CLASS == "SPENT_RESEARCH_ONLY_NO_AUTHORITY"
    assert "QUALIFICATION" not in ACTIVATION_LITERAL


def test_live_fixed_inputs_match_r7_and_frozen_r4_reference() -> None:
    receipt = verify_fixed_inputs()
    assert receipt["status"] == "PASS_EXACT_R7_SOURCE_AND_SPENT_REFERENCE"
    assert receipt["source_lock"]["declared_source_count"] == 95
    assert receipt["reference_task_count"] == 50
    assert (
        receipt["reference_output_ledger_semantic_sha256"]
        == SPENT_REFERENCE_OUTPUT_LEDGER_SEMANTIC_SHA256
    )
    assert receipt["authority_counters"] == zero_authority_counters()
    finding = receipt["r7_raw_header_contract_p0"]
    assert finding == r7_raw_header_contract_finding(
        PROJECT_ROOT / "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
    )
    assert finding["production_r7_execution_callable"] is False
    dynamic = copy.deepcopy(receipt)
    dynamic["physical_memory_preflight"]["available_physical_memory_bytes"] -= 1
    assert immutable_fixed_input_projection(dynamic) == immutable_fixed_input_projection(
        receipt
    )
    drift = copy.deepcopy(receipt)
    drift["source_lock"]["source_semantic_sha256"] = "0" * 64
    assert immutable_fixed_input_projection(drift) != immutable_fixed_input_projection(
        receipt
    )


def test_source_owned_sys_path_rejects_missing_and_wrong_prefixes() -> None:
    expected = [str(PROJECT_ROOT), str(PROJECT_ROOT / "src"), "stdlib"]
    validate_source_owned_sys_path(expected)
    with pytest.raises(Exception, match="prefix drifted"):
        validate_source_owned_sys_path([str(PROJECT_ROOT), "stdlib"])
    with pytest.raises(Exception, match="prefix drifted"):
        validate_source_owned_sys_path([str(PROJECT_ROOT / "wrong"), expected[1]])
    with pytest.raises(Exception, match="duplicated"):
        validate_source_owned_sys_path([*expected, str(PROJECT_ROOT)])


def test_descendant_closure_is_transitive_and_excludes_unrelated_processes() -> None:
    snapshot = {
        10: {"parent_pid": 1},
        11: {"parent_pid": 10},
        12: {"parent_pid": 11},
        13: {"parent_pid": 99},
    }
    assert descendant_pids(snapshot, 10) == (10, 11, 12)


@pytest.mark.skipif(os.name != "nt", reason="Windows native evidence")
def test_native_monitor_observes_a_harmless_child_and_memory_floor() -> None:
    monitor = ProcessTreeMonitor(os.getpid(), sample_interval_seconds=0.05)
    monitor.start()
    child = subprocess.Popen(
        [sys.executable, "-I", "-B", "-c", "import time;time.sleep(0.75)"],
        close_fds=True,
    )
    assert child.wait(timeout=5.0) == 0
    receipt = monitor.stop()
    assert receipt["sample_count"] >= 2
    assert receipt["memory_floor_held"] is True
    assert receipt["peak_process_tree_rss_bytes"] > 0
    assert any(row["pid"] == child.pid for row in receipt["processes"])
    memory = physical_memory()
    assert memory["total_physical_memory_bytes"] >= 80 * 1024**3


class _FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self.exitcode = 0


def test_stage_validator_requires_barrier_work_and_native_pid_overlap() -> None:
    pids = [41001, 41002]
    processes = [_FakeProcess(pid) for pid in pids]
    ready = [
        {
            "invocation_ordinal": ordinal,
            "task_key": f"{PILOT_TASKS[ordinal][0]}:{PILOT_TASKS[ordinal][1]}",
            "pid": pid,
            "ready_perf_counter_ns": 100 + ordinal,
        }
        for ordinal, pid in enumerate(pids)
    ]
    results = [
        {
            "status": "PASS_EXACT_PINNED_NUMERIC_CHILD_BYTES_AND_RESOURCES",
            "invocation_ordinal": ordinal,
            "task_key": f"{PILOT_TASKS[ordinal][0]}:{PILOT_TASKS[ordinal][1]}",
            "pid": pid,
            "work_started_perf_counter_ns": 200 + ordinal,
            "work_finished_perf_counter_ns": 1_000 - ordinal,
            "elapsed_seconds": 0.000_000_8,
            "canonical150_reference_byte_equal": True,
            "v04_overlay_reference_byte_equal": True,
            "authority_counters": zero_authority_counters(),
        }
        for ordinal, pid in enumerate(pids)
    ]
    monitor = {
        "processes": [
            {
                "pid": pid,
                "first_observed_perf_counter_ns": 250 + ordinal,
                "last_observed_perf_counter_ns": 900 - ordinal,
            }
            for ordinal, pid in enumerate(pids)
        ]
    }
    receipt = _validate_stage_results(
        requested=2,
        processes=processes,  # type: ignore[arg-type]
        ready_rows=ready,
        results=results,
        monitor=monitor,
        stage_started_ns=0,
        barrier_released_ns=150,
        stage_finished_ns=2_000,
    )
    assert receipt["actual_distinct_worker_pid_count"] == 2
    assert receipt["actual_work_overlap"]["all_requested_workers_overlapped"] is True
    assert (
        receipt["native_pid_observation_overlap"]
        ["all_requested_worker_pids_observed_concurrently"]
        is True
    )


def test_stage_validator_rejects_nonoverlapping_work() -> None:
    processes = [_FakeProcess(42001), _FakeProcess(42002)]
    ready = [
        {
            "invocation_ordinal": ordinal,
            "task_key": f"{PILOT_TASKS[ordinal][0]}:{PILOT_TASKS[ordinal][1]}",
            "pid": process.pid,
            "ready_perf_counter_ns": 100,
        }
        for ordinal, process in enumerate(processes)
    ]
    results = [
        {
            "status": "PASS_EXACT_PINNED_NUMERIC_CHILD_BYTES_AND_RESOURCES",
            "invocation_ordinal": ordinal,
            "task_key": f"{PILOT_TASKS[ordinal][0]}:{PILOT_TASKS[ordinal][1]}",
            "pid": process.pid,
            "work_started_perf_counter_ns": 100 + ordinal * 200,
            "work_finished_perf_counter_ns": 200 + ordinal * 200,
            "elapsed_seconds": 0.1,
            "canonical150_reference_byte_equal": True,
            "v04_overlay_reference_byte_equal": True,
            "authority_counters": zero_authority_counters(),
        }
        for ordinal, process in enumerate(processes)
    ]
    monitor = {
        "processes": [
            {
                "pid": process.pid,
                "first_observed_perf_counter_ns": 0,
                "last_observed_perf_counter_ns": 1_000,
            }
            for process in processes
        ]
    }
    with pytest.raises(Exception, match="did not overlap actual work"):
        _validate_stage_results(
            requested=2,
            processes=processes,  # type: ignore[arg-type]
            ready_rows=ready,
            results=results,
            monitor=monitor,
            stage_started_ns=0,
            barrier_released_ns=150,
            stage_finished_ns=2_000,
        )


def test_output_identity_is_fixed_absent_and_source_has_no_authority_import() -> None:
    assert OUTPUT_ROOT_RELATIVE == (
        "outputs/r8r7_phase2_spent_concurrency_pilot_v1_r3_20260822"
    )
    assert output_absent() is True
    assert (PROJECT_ROOT / FAILED_R1_OUTPUT_ROOT_RELATIVE).is_dir()
    assert (
        PROJECT_ROOT
        / FAILED_R1_OUTPUT_ROOT_RELATIVE
        / ".count_1.staging"
        / "FAILURE.json"
    ).is_file()
    assert (PROJECT_ROOT / FAILED_R2_OUTPUT_ROOT_RELATIVE).is_dir()
    assert (PROJECT_ROOT / FAILED_R2_OUTPUT_ROOT_RELATIVE / "PILOT_RECEIPT.json").is_file()
    source = Path(__file__).parents[2].joinpath(
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r8_r7_"
        "phase2_spent_concurrency_pilot_v1/pilot.py"
    ).read_text("utf-8")
    assert "phase2_execution_v1.signing" not in source
    assert "issue_qualification" not in source
    assert "HELDOUT_SEEDS" not in source
    assert "QUALIFICATION_SEEDS" not in source
    assert str(PROJECT_ROOT).casefold() in str(Path(__file__).resolve()).casefold()
