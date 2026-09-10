"""Research-only C4-R2 numerical-availability successor."""

from .contracts import (
    FINAL_VARIANT_ID,
    RESEARCH_THRESHOLDS,
    VARIANTS,
    C4R2ContractError,
    SolverVariant,
)
from .runner import run_source_task, run_spent_batch, run_worker_benchmark
from .scoring import score_spent_predictions

__all__ = [
    "C4R2ContractError",
    "FINAL_VARIANT_ID",
    "RESEARCH_THRESHOLDS",
    "SolverVariant",
    "VARIANTS",
    "run_source_task",
    "run_spent_batch",
    "run_worker_benchmark",
    "score_spent_predictions",
]
