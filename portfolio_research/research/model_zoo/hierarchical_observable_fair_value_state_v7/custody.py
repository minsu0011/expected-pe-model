"""Canonical decision-block order and source-position custody for H-OFS V7."""

from __future__ import annotations

import hashlib

import pandas as pd

from .contracts import (
    IDENTITY_COLUMNS,
    HierarchicalStateV7ContractError,
    canonical_json_bytes,
)
from .features import validate_bound_identities
from .validation import require_exact_int, require_exact_tuple, require_sha256


CANONICAL_DECISION_ORDER = "decision_date_then_entity_id_stable_mergesort"


def _identity_rows(identities: pd.DataFrame) -> list[tuple[str, str]]:
    return [
        (str(entity), pd.Timestamp(date).isoformat())
        for entity, date in identities.loc[:, list(IDENTITY_COLUMNS)].itertuples(
            index=False,
            name=None,
        )
    ]


def require_canonical_decision_identity_order_v7(
    identities: pd.DataFrame,
    *,
    expected_index: pd.Index | None = None,
) -> pd.DataFrame:
    """Reject unless identities already have the one frozen stable order.

    The comparison deliberately does not return or substitute the sorted frame.
    Sorting is performed only on a detached probe so a caller cannot receive a
    silently repaired request.
    """

    validated = validate_bound_identities(
        identities,
        expected_index=identities.index if expected_index is None else expected_index,
    )
    if validated.duplicated(list(IDENTITY_COLUMNS)).any():
        raise HierarchicalStateV7ContractError(
            "requested decision entity/date identity is duplicated"
        )
    date_column = IDENTITY_COLUMNS[1]
    entity_column = IDENTITY_COLUMNS[0]
    canonical_probe = validated.loc[:, list(IDENTITY_COLUMNS)].sort_values(
        [date_column, entity_column],
        kind="mergesort",
    )
    if _identity_rows(validated) != _identity_rows(canonical_probe):
        raise HierarchicalStateV7ContractError(
            "requested decision identities are not already in exact canonical "
            "decision_date/entity_id stable mergesort order"
        )
    return validated.copy()


def decision_block_ordered_membership_sha256_v7(identities: pd.DataFrame) -> str:
    """Hash the mandatory canonical row sequence with an order-specific domain."""

    canonical = require_canonical_decision_identity_order_v7(identities)
    rows = _identity_rows(canonical)
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "hash_domain": "H_OFS_V7_DECISION_BLOCK_ORDERED_MEMBERSHIP",
                "identity_columns": list(IDENTITY_COLUMNS),
                "order_policy": CANONICAL_DECISION_ORDER,
                "ordered_entity_date_membership": [list(row) for row in rows],
                "row_count": len(rows),
            }
        )
    ).hexdigest()


def decision_block_set_membership_sha256_v7(identities: pd.DataFrame) -> str:
    """Hash the exact identity set independently of caller row order."""

    validated = validate_bound_identities(identities, expected_index=identities.index)
    if validated.duplicated(list(IDENTITY_COLUMNS)).any():
        raise HierarchicalStateV7ContractError(
            "requested decision entity/date identity is duplicated"
        )
    rows = sorted(_identity_rows(validated), key=lambda row: (row[1], row[0]))
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "hash_domain": "H_OFS_V7_DECISION_BLOCK_SET_MEMBERSHIP",
                "identity_columns": list(IDENTITY_COLUMNS),
                "set_entity_date_membership": [list(row) for row in rows],
                "row_count": len(rows),
            }
        )
    ).hexdigest()


def decision_block_canonical_endpoints_v7(
    identities: pd.DataFrame,
) -> tuple[str, str, str, str, int]:
    """Return first entity/date, last entity/date, and distinct-date count."""

    canonical = require_canonical_decision_identity_order_v7(identities)
    rows = _identity_rows(canonical)
    if not rows:
        raise HierarchicalStateV7ContractError("decision block must be non-empty")
    distinct_dates = len({date for _, date in rows})
    if distinct_dates < 2:
        raise HierarchicalStateV7ContractError(
            "one frozen decision block must contain multiple decision dates"
        )
    first_entity, first_date = rows[0]
    last_entity, last_date = rows[-1]
    return first_entity, first_date, last_entity, last_date, distinct_dates


def decision_source_positions_sha256_v7(
    identities: pd.DataFrame,
    *,
    source_state_sha256: str,
    source_positions: tuple[int, ...],
    source_row_count: int,
) -> str:
    """Bind canonical identities to their exact ordered source-state positions."""

    canonical = require_canonical_decision_identity_order_v7(identities)
    require_sha256(source_state_sha256, label="decision source state binding")
    require_exact_int(source_row_count, label="decision source row count", minimum=1)
    positions = require_exact_tuple(
        source_positions,
        label="decision source positions",
        length=len(canonical),
    )
    for offset, value in enumerate(positions):
        require_exact_int(
            value,
            label=f"decision source positions[{offset}]",
            minimum=0,
        )
    if (
        source_row_count < len(canonical)
        or len(set(positions)) != len(positions)
        or any(position >= source_row_count for position in positions)
        or any(left >= right for left, right in zip(positions, positions[1:], strict=False))
    ):
        raise HierarchicalStateV7ContractError(
            "canonical decision source positions must be unique, in range, and strictly increasing"
        )
    rows = _identity_rows(canonical)
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "hash_domain": "H_OFS_V7_DECISION_SOURCE_POSITIONS",
                "order_policy": CANONICAL_DECISION_ORDER,
                "ordered_membership_sha256": (
                    decision_block_ordered_membership_sha256_v7(canonical)
                ),
                "set_membership_sha256": decision_block_set_membership_sha256_v7(canonical),
                "source_state_sha256": source_state_sha256,
                "source_row_count": source_row_count,
                "ordered_identity_source_positions": [
                    {
                        "entity_id": entity,
                        "decision_date": date,
                        "source_position": position,
                    }
                    for (entity, date), position in zip(rows, positions, strict=True)
                ],
            }
        )
    ).hexdigest()


__all__ = [
    "CANONICAL_DECISION_ORDER",
    "decision_block_canonical_endpoints_v7",
    "decision_block_ordered_membership_sha256_v7",
    "decision_block_set_membership_sha256_v7",
    "decision_source_positions_sha256_v7",
    "require_canonical_decision_identity_order_v7",
]
