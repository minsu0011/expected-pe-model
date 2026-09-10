"""Truth-free, detached PE qualification evaluator primitives."""

from .contract import (
    CANDIDATE_IDS,
    CHAMPION_ID,
    MODEL_IDS,
    FinalPretruthBinding,
    OneShotCustodyVerification,
    QualificationContract,
    QualificationEvaluatorError,
)
from .evaluator import EvaluationResult, evaluate_qualification

__all__ = [
    "CANDIDATE_IDS",
    "CHAMPION_ID",
    "MODEL_IDS",
    "EvaluationResult",
    "FinalPretruthBinding",
    "OneShotCustodyVerification",
    "QualificationContract",
    "QualificationEvaluatorError",
    "evaluate_qualification",
]
