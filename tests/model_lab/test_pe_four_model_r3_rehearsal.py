from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.model_lab import pe_four_model_r3_rehearsal as controller
from scripts.model_lab.pe_four_model_r3_rehearsal_contract import (
    REHEARSAL_DGP_IDS,
    REHEARSAL_IDENTITY_COUNT,
    REHEARSAL_PREDICTION_ROW_COUNT,
    REHEARSAL_SEED_ALIASES,
    REHEARSAL_SEEDS,
    REHEARSAL_SOURCE_RELATIVES,
    REHEARSAL_TASK_COUNT,
    rehearsal_tasks,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_frozen_nonreserved_fixture_has_exact_production_geometry() -> None:
    tasks = rehearsal_tasks()
    assert REHEARSAL_SEEDS == tuple(range(9_900_001, 9_900_006))
    assert REHEARSAL_SEED_ALIASES == tuple(f"heldout_seed_{ordinal:02d}" for ordinal in range(1, 6))
    assert REHEARSAL_DGP_IDS == tuple("ABCDEFGHIJ")
    assert len(tasks) == REHEARSAL_TASK_COUNT == 50
    assert REHEARSAL_IDENTITY_COUNT == 64_800
    assert REHEARSAL_PREDICTION_ROW_COUNT == 259_200
    assert [task.task_ordinal for task in tasks] == list(range(50))
    assert [(task.data_seed, task.dgp_id) for task in tasks] == [
        (seed, dgp) for seed in REHEARSAL_SEEDS for dgp in REHEARSAL_DGP_IDS
    ]
    assert all(task.estimator_rng_seed == task.data_seed for task in tasks)
    assert all(task.estimator_rng_alias == task.seed_alias for task in tasks)


def test_fixture_is_live_registry_disjoint_without_mutation() -> None:
    before, _, spent = controller._registry_state()
    assert set(REHEARSAL_SEEDS).isdisjoint(spent)
    after, _, spent_after = controller._registry_state()
    assert after == before
    assert spent_after == spent
    assert len(hashlib.sha256(before).hexdigest()) == 64


def test_source_lock_closes_exact_rehearsal_and_production_paths() -> None:
    raw, lock = controller._source_lock()
    assert lock["status"] == "FROZEN_BEFORE_NONRESERVED_GENERATION"
    assert lock["source_relatives_in_order"] == list(REHEARSAL_SOURCE_RELATIVES)
    assert len(lock["source_records"]) == len(REHEARSAL_SOURCE_RELATIVES)
    assert lock["formal_seed_reservation_count"] == 0
    assert hashlib.sha256(raw).hexdigest()
    for record in lock["source_records"]:
        path = PROJECT_ROOT / str(record["relative_path"])
        observed = path.read_bytes()
        assert record["raw_sha256"] == hashlib.sha256(observed).hexdigest()
        assert record["size_bytes"] == len(observed)


def test_planned_path_budget_and_output_names_are_r3_only() -> None:
    run_id = "unit"
    build_root = PROJECT_ROOT / "build" / f"pe_r3r_{run_id}"
    prediction = PROJECT_ROOT / "outputs" / f"model_zoo_pe_four_model_r3_rehearsal_{run_id}"
    activation = (
        PROJECT_ROOT / "outputs" / (f"model_zoo_pe_four_model_r3_rehearsal_activation_{run_id}")
    )
    paths = controller._planned_paths(build_root, prediction, activation)
    assert max(map(lambda path: len(str(path)), paths)) <= controller.MAX_PATH_BUDGET
    assert all("_r2_" not in str(path).casefold() for path in paths)


def test_controller_uses_rehearsal_loader_and_exact_handle_transition() -> None:
    source = (PROJECT_ROOT / "scripts/model_lab/pe_four_model_r3_rehearsal.py").read_text(
        encoding="utf-8"
    )
    source_lock_position = source.index("source_lock_raw, source_lock = _source_lock()")
    generation_position = source.index("with ThreadPoolExecutor(max_workers=GENERATION_WORKERS)")
    assert source_lock_position < generation_position
    assert "prediction_execution import _surface" not in source
    assert '_read_surface(numeric, lane="bce", task=task)' in source
    assert "_release_prefix_write_custody(" in source
    assert "_reacquire_commit_directory_custody(" in source
    assert '"status": "GO_FREEZE_R3_SEED_POLICY_THEN_RESERVE_ONCE"' in source
    assert "GO_RESERVE_EXACTLY_FIVE_UNTOUCHED_R3_SEEDS_ONCE" not in source
    assert (
        source.index('final_leaf="REHEARSAL_AUDIT.json"')
        < source.index('final_leaf="CHECKSUMS.sha256"')
        < source.index('final_leaf="REHEARSAL_SEAL.json"')
    )


def test_cold_worker_delegates_only_to_actual_production_roles() -> None:
    source = (PROJECT_ROOT / "scripts/model_lab/pe_four_model_r3_rehearsal_worker.py").read_text(
        encoding="utf-8"
    )
    assert "heldout_role_worker._task = rehearsal_task" in source
    for function in ("_protected_two_pass", "_public_two_pass", "_numeric_task"):
        assert f"heldout_role_worker.{function}" in source
    assert "protected-finalize" not in source


def test_detached_auditor_has_independent_formula_and_blocked_path_guards() -> None:
    source = (PROJECT_ROOT / "scripts/model_lab/pe_four_model_r3_rehearsal_auditor.py").read_text(
        encoding="utf-8"
    )
    assert "independent_audit._expected_task" in source
    assert "prediction producer" in source
    assert '("vault", "truth", "latent", "heldout")' in source
    assert "PASS_DETACHED_EVALUATOR_PLUMBING_SIMULATION" in source
