"""Frozen research contract for C4-R2 numerical robustness."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Any, Final


class C4R2ContractError(RuntimeError):
    """Raised when the C4-R2 research boundary drifts."""


@dataclass(frozen=True)
class SolverVariant:
    variant_id: str
    irls_max_iterations: int
    irls_tolerance: float
    block_v04_fallback: bool
    same_huber_objective: bool = True
    same_box_constraints: bool = True

    def __post_init__(self) -> None:
        if (
            type(self.variant_id) is not str
            or not self.variant_id.startswith("c4_r2_")
            or type(self.irls_max_iterations) is not int
            or self.irls_max_iterations not in (50, 80, 100)
            or type(self.irls_tolerance) is not float
            or self.irls_tolerance != 1e-8
            or type(self.block_v04_fallback) is not bool
            or self.same_huber_objective is not True
            or self.same_box_constraints is not True
        ):
            raise C4R2ContractError("solver variant contract drifted")

    def payload(self) -> dict[str, Any]:
        return asdict(self)


VARIANTS: Final = (
    SolverVariant("c4_r2_a_irls50_reference", 50, 1e-8, False),
    SolverVariant("c4_r2_b_irls80", 80, 1e-8, False),
    SolverVariant("c4_r2_c_irls100", 100, 1e-8, False),
    SolverVariant("c4_r2_d_irls50_block_v04", 50, 1e-8, True),
    SolverVariant("c4_r2_e_irls80_block_v04", 80, 1e-8, True),
)
VARIANT_BY_ID: Final = {item.variant_id: item for item in VARIANTS}
FINAL_VARIANT_ID: Final = "c4_r2_e_irls80_block_v04"
GLOBAL_HOFS_LOG_SHRINK: Final = 0.5
NUMERIC_FAILURE_MESSAGES: Final = (
    "box-constrained Huber IRLS did not converge",
    "fixed-order box QP failed its KKT gate",
)
RESEARCH_THRESHOLDS: Final = {
    "valid_input_availability_min": 1.0,
    "known_nonconvergence_handled_min": 1.0,
    "nan_or_inf_max": 0,
    "deterministic_digest_equality": True,
    "spent_mae_gain_min": 0.18,
    "spent_rmse_gain_min": 0.18,
    "spent_joint_tail_failures_max": 0,
    "spent_worst_dgp_harm_max": 0.01,
    "spent_worst_cell_harm_max": 0.03,
    "full_spent_fallback_rows_max": 0,
}


def canonical_json_bytes(value: Any, *, pretty: bool = False) -> bytes:
    options: dict[str, Any] = {
        "sort_keys": True,
        "ensure_ascii": True,
        "allow_nan": False,
    }
    if pretty:
        options["indent"] = 2
    else:
        options["separators"] = (",", ":")
    return (json.dumps(value, **options) + ("\n" if pretty else "")).encode("ascii")


def semantic_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def variant(variant_id: str) -> SolverVariant:
    try:
        return VARIANT_BY_ID[variant_id]
    except KeyError as exc:
        raise C4R2ContractError("unknown C4-R2 variant") from exc


__all__ = [
    "C4R2ContractError",
    "FINAL_VARIANT_ID",
    "GLOBAL_HOFS_LOG_SHRINK",
    "NUMERIC_FAILURE_MESSAGES",
    "RESEARCH_THRESHOLDS",
    "SolverVariant",
    "VARIANTS",
    "canonical_json_bytes",
    "semantic_sha256",
    "variant",
]
