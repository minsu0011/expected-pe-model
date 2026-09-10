"""Frozen non-reserved geometry for the production-scale R3 rehearsal."""

from __future__ import annotations

from typing import Any, Final


REHEARSAL_SEEDS: Final = (9_900_001, 9_900_002, 9_900_003, 9_900_004, 9_900_005)
REHEARSAL_SEED_ALIASES: Final = tuple(f"heldout_seed_{ordinal:02d}" for ordinal in range(1, 6))
REHEARSAL_DGP_IDS: Final = tuple("ABCDEFGHIJ")
REHEARSAL_TASK_COUNT: Final = 50
REHEARSAL_IDENTITY_COUNT: Final = 64_800
REHEARSAL_PREDICTION_ROW_COUNT: Final = 259_200
REHEARSAL_ROWS_PER_TASK: Final = 1_296
REHEARSAL_SOURCE_RELATIVES: Final = (
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/protected_generation.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/public_generation.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/numeric_services.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/prediction.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/independent_audit.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/generation_execution.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/prediction_execution.py",
    "research/model_zoo/pe_four_model_fresh_heldout_authority_v1/publisher.py",
    "research/model_zoo/pe_five_model_qualification_prediction_auditor_v1/filesystem.py",
    "research/model_zoo/pe_five_model_qualification_prediction_auditor_v1/secure_publication.py",
    "scripts/model_lab/pe_four_model_fresh_heldout_authority_v1/heldout_role_worker.py",
    "scripts/model_lab/pe_four_model_r3_rehearsal_contract.py",
    "scripts/model_lab/pe_four_model_r3_rehearsal_worker.py",
    "scripts/model_lab/pe_four_model_r3_rehearsal_auditor.py",
    "scripts/model_lab/pe_four_model_r3_rehearsal.py",
)


def rehearsal_task(ordinal: int) -> Any:
    """Build a nominal HeldoutTask without entering its reserved-seed constructor."""

    from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
        HeldoutTask,
    )

    if type(ordinal) is not int or ordinal not in range(REHEARSAL_TASK_COUNT):
        raise ValueError("R3 rehearsal task ordinal differs")
    seed_index, dgp_index = divmod(ordinal, len(REHEARSAL_DGP_IDS))
    seed = REHEARSAL_SEEDS[seed_index]
    alias = REHEARSAL_SEED_ALIASES[seed_index]
    task = object.__new__(HeldoutTask)
    object.__setattr__(task, "task_ordinal", ordinal)
    object.__setattr__(task, "data_seed", seed)
    object.__setattr__(task, "seed_alias", alias)
    object.__setattr__(task, "estimator_rng_seed", seed)
    object.__setattr__(task, "estimator_rng_alias", alias)
    object.__setattr__(task, "dgp_id", REHEARSAL_DGP_IDS[dgp_index])
    return task


def rehearsal_tasks() -> tuple[Any, ...]:
    tasks = tuple(rehearsal_task(ordinal) for ordinal in range(REHEARSAL_TASK_COUNT))
    if (
        len(tasks) != REHEARSAL_TASK_COUNT
        or len({(task.data_seed, task.dgp_id) for task in tasks}) != REHEARSAL_TASK_COUNT
    ):
        raise ValueError("R3 rehearsal task universe differs")
    return tasks


__all__ = [
    "REHEARSAL_DGP_IDS",
    "REHEARSAL_IDENTITY_COUNT",
    "REHEARSAL_PREDICTION_ROW_COUNT",
    "REHEARSAL_ROWS_PER_TASK",
    "REHEARSAL_SEED_ALIASES",
    "REHEARSAL_SEEDS",
    "REHEARSAL_SOURCE_RELATIVES",
    "REHEARSAL_TASK_COUNT",
    "rehearsal_task",
    "rehearsal_tasks",
]
