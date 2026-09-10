"""Spent-only pre-certification research tournament.

This package has no formal certification, promotion, registry, or fresh-data
authority.  Its only real-data entrypoint is hard-bound to the already spent
R4 research surface declared in :mod:`.contracts`.
"""

from .contracts import (
    BCE_B_ID,
    BCE_D_ID,
    FIXED_040_ID,
    FIVE_CANDIDATE_SLOTS,
    RESEARCH_EVIDENCE_CLASS,
    design_lock_payload,
)
from .evaluator import TournamentResult, evaluate_spent_bce_surface

__all__ = [
    "BCE_B_ID",
    "BCE_D_ID",
    "FIXED_040_ID",
    "FIVE_CANDIDATE_SLOTS",
    "RESEARCH_EVIDENCE_CLASS",
    "TournamentResult",
    "design_lock_payload",
    "evaluate_spent_bce_surface",
]
