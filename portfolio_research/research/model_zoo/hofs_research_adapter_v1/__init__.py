"""Spent-public, score-free H-OFS research prediction adapter."""

from .contracts import (
    ADAPTER_ID,
    BENCHMARK_FOLD_INDICES,
    BENCHMARK_WORKERS,
    EVIDENCE_CLASS,
    FULL_OUTER_WORKERS,
    MODEL_ID,
    PREDICTION_COLUMNS,
    design_payload,
    design_sha256,
)
from .inputs import TaskSpec, build_public_task_plan

__all__ = [
    "ADAPTER_ID",
    "BENCHMARK_FOLD_INDICES",
    "BENCHMARK_WORKERS",
    "EVIDENCE_CLASS",
    "FULL_OUTER_WORKERS",
    "MODEL_ID",
    "PREDICTION_COLUMNS",
    "TaskSpec",
    "build_public_task_plan",
    "design_payload",
    "design_sha256",
]
