"""No-fit checks for the Structural V7 full-load execution revision."""

from __future__ import annotations

import json
from pathlib import Path

from research.model_zoo.aggressive_lab.full_load_resources import (
    CPU_IDS,
    CPU_INNER_THREADS,
    MAX_OUTER_WORKERS,
    RAM_MIN_FREE_GIB,
    RAM_SOFT_BUDGET_GIB,
    assert_full_load_process,
)
from research.model_zoo.structural_v7.contracts import CANDIDATES
from research.model_zoo.structural_v7.data import load_spent_unscored_inputs
from research.model_zoo.structural_v7.evaluation_identity import (
    validate_exact_evaluation_identity,
)
from research.model_zoo.structural_v7.folds import (
    build_base_fold_calls,
    build_outer_folds,
)
from research.model_zoo.structural_v7_full_load.contracts import (
    COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    GPU_CANDIDATE_IDS,
    lane_gpu_usage_receipt,
    load_common_full_load_lock,
)
from research.model_zoo.structural_v7_full_load.post_freeze_pins import (
    DEPENDENCY_MANIFEST_RAW_SHA256,
    DESIGN_LOCK_RAW_SHA256,
    PREFLIGHT_RAW_SHA256,
    load_design_lock,
    load_preflight,
    verify_full_dependency_freeze,
)
from research.model_zoo.structural_v7_full_load.parallel_runner import (
    assemble_base_surfaces,
    assemble_prediction_frames,
)
from research.model_zoo.structural_v7_full_load.topology import (
    build_full_load_topology,
)


ROOT = Path(__file__).resolve().parents[2]


def test_common_full_load_lock_and_lane_gpu_non_use_are_exact() -> None:
    common = load_common_full_load_lock(ROOT)
    assert common["cpu_ids"] == list(range(32))
    assert common["max_outer_workers"] == 32
    assert common["cpu_inner_threads"] == 1
    assert common["ram_soft_budget_gib"] == 80.0
    assert common["ram_min_free_gib"] == 12.0
    assert common["gpu"]["index"] == 0
    assert GPU_CANDIDATE_IDS == ()
    assert lane_gpu_usage_receipt()["candidate_gpu_usage"] is False
    receipt = assert_full_load_process(outer_workers=1)
    assert receipt.cpu_ids == CPU_IDS == tuple(range(32))
    assert receipt.cpu_inner_threads == CPU_INNER_THREADS == 1
    assert MAX_OUTER_WORKERS == 32
    assert RAM_SOFT_BUDGET_GIB == 80.0 and RAM_MIN_FREE_GIB == 12.0


def test_transitive_dependency_design_and_preflight_pins_are_exact() -> None:
    receipt = verify_full_dependency_freeze(ROOT)
    assert receipt.manifest_raw_sha256 == DEPENDENCY_MANIFEST_RAW_SHA256
    assert receipt.v7_v2_manifest_raw_sha256 == (
        "a0d960ad2dd48740810f501943fa6f7bed01dcd94063b5a92674aa8ae5a41b30"
    )
    assert len(DESIGN_LOCK_RAW_SHA256) == len(PREFLIGHT_RAW_SHA256) == 64
    design = load_design_lock(ROOT)
    preflight = load_preflight(ROOT)
    assert design["common_full_load_lock_raw_sha256"] == (
        COMMON_FULL_LOAD_LOCK_RAW_SHA256
    )
    assert design["candidate_count"] == len(CANDIDATES) == 10
    assert design["candidate_or_minimum_change_from_v2"] is False
    assert design["lane_gpu_usage"]["candidate_gpu_usage"] is False
    assert preflight["status"] == (
        "GO_FULL_LOAD_SOURCE_READY_ROOT_LAUNCH_APPROVAL_REQUIRED"
    )
    assert preflight["fit_calls_executed"] == 0
    assert preflight["prediction_rows_generated"] == 0
    assert preflight["evaluation_truth_opened"] is False
    assert preflight["scores_computed"] is False


def test_full_load_topology_is_exact_and_truth_blind() -> None:
    spent_inputs, evidence = load_spent_unscored_inputs(ROOT)
    topology = build_full_load_topology(spent_inputs)
    assert len(topology.base_tasks) == 5 * 2 * 74 == 740
    assert len(topology.candidate_tasks) == 5 * 10 * 62 == 3100
    assert topology.outer_schedule_sha256 == (
        "fe6f8038ded6f880cb885489278e02be484caf0a5f113df6e903fb3a1dcd111a"
    )
    assert evidence["evaluation_data_used"] is False


def test_launchers_guard_before_resource_import_and_fit_or_truth() -> None:
    run_source = (
        ROOT / "scripts/model_lab/structural_v7_full_load/run_full_screen.py"
    ).read_text(encoding="utf-8")
    for start, end in (
        ("def _initialize_base_worker", "def _initialize_candidate_worker"),
        ("def _initialize_candidate_worker", "def _base_task"),
        ("def main", 'if __name__ == "__main__"'),
    ):
        block = run_source[run_source.index(start) : run_source.index(end)]
        assert block.index("verify_full_dependency_freeze") < block.index(
            "full_load_resources"
        )
    main_block = run_source[run_source.index("def main") :]
    assert main_block.index("verify_full_dependency_freeze(args.project_root)") < (
        main_block.index("parallel_runner import")
    )

    evaluator = (
        ROOT / "scripts/model_lab/structural_v7_full_load/evaluate_full_screen.py"
    ).read_text(encoding="utf-8")
    main = evaluator[evaluator.index("def main") :]
    assert main.index("verify_full_dependency_freeze") < main.index(
        "full_load_resources"
    )
    assert main.index("validate_exact_evaluation_identity(predictions") < main.index(
        "EVALUATE_INPUTS.json"
    )


def test_cpu_estimators_do_not_select_gpu() -> None:
    spec = (
        ROOT / "src/pe_regime_v04/model_lab/models/wave1/spec.py"
    ).read_text(encoding="utf-8")
    assert '"device": "cpu"' in spec
    assert '"n_jobs": 1' in spec
    models = (
        ROOT / "research/model_zoo/structural_v7/models.py"
    ).read_text(encoding="utf-8")
    assert "n_jobs=1" in models
    design_path = (
        ROOT / "outputs/model_zoo_structural_v7_full_load_design_20260820/DESIGN_LOCK.json"
    )
    design = json.loads(design_path.read_text(encoding="utf-8"))
    assert design["lane_gpu_usage"]["gpu_candidate_ids"] == []


def test_parallel_assembly_yields_exact_identity_without_fitting() -> None:
    spent_inputs, _ = load_spent_unscored_inputs(ROOT)
    topology = build_full_load_topology(spent_inputs)
    base_calls = {
        seed: build_base_fold_calls(data.dates) for seed, data in spent_inputs.items()
    }
    outer_calls = {
        seed: build_outer_folds(data.dates) for seed, data in spent_inputs.items()
    }
    base_results = []
    for seed, model_id, fold_index in topology.base_tasks:
        fold = base_calls[seed][fold_index]
        base_results.append(
            {
                "task": (seed, model_id, fold_index),
                "prediction": [20.0] * fold.test_rows,
                "diagnostic": {
                    "seed": seed,
                    "model_id": model_id,
                    "fold_id": fold.fold_id,
                    "runtime_seconds": 0.0,
                },
                "worker_receipt": None,
            }
        )
    surfaces, diagnostics, runtime = assemble_base_surfaces(spent_inputs, base_results)
    candidate_results = []
    for seed, candidate_id, outer_index in topology.candidate_tasks:
        outer = outer_calls[seed][outer_index]
        candidate_results.append(
            {
                "task": (seed, candidate_id, outer_index),
                "prediction": [21.0] * outer.test_rows,
                "diagnostic": {
                    "seed": seed,
                    "model_id": candidate_id,
                    "fold_id": outer.fold_id,
                    "runtime_seconds": 0.0,
                },
                "worker_receipt": None,
            }
        )
    predictions, all_diagnostics, all_runtime = assemble_prediction_frames(
        spent_inputs,
        surfaces,
        candidate_results,
        diagnostics,
        runtime,
    )
    receipt = validate_exact_evaluation_identity(predictions, spent_inputs)
    assert receipt.total_rows == 71280
    assert len(all_diagnostics) == 740 + 3100
    assert set(all_runtime) == {
        "v04_expected_pe",
        "xgboost_cpu_common",
        "spline_ridge_common",
        *(candidate.candidate_id for candidate in CANDIDATES),
    }
