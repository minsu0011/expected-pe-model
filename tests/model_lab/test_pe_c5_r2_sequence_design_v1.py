from __future__ import annotations

import pytest

from research.model_zoo.pe_c5_r2_sequence_design_v1.contracts import (
    ALLOWED_INPUT_NAMES,
    LOOKBACK,
    SequenceContractError,
    SequenceSampleReceipt,
    build_sample_receipts,
)


def test_every_source_position_is_strictly_before_label() -> None:
    receipts = build_sample_receipts(range(504, 1800))
    assert len(receipts) == 1296
    assert all(max(item.source_positions) < item.label_position for item in receipts)
    assert receipts[0].source_positions == tuple(range(504 - LOOKBACK, 504))
    assert receipts[-1].anchor_position == 1798


def test_same_row_source_is_rejected() -> None:
    with pytest.raises(SequenceContractError):
        SequenceSampleReceipt(
            label_position=504,
            source_positions=tuple(range(442, 505)),
            input_names=ALLOWED_INPUT_NAMES,
            anchor_position=503,
        )


def test_target_or_true_feature_is_rejected() -> None:
    forbidden = (*ALLOWED_INPUT_NAMES[:-1], "true_log_fair_pe")
    with pytest.raises(SequenceContractError):
        SequenceSampleReceipt(
            label_position=504,
            source_positions=tuple(range(441, 504)),
            input_names=forbidden,
            anchor_position=503,
        )


def test_unsorted_or_duplicate_labels_are_rejected() -> None:
    with pytest.raises(SequenceContractError):
        build_sample_receipts([505, 504])
    with pytest.raises(SequenceContractError):
        build_sample_receipts([504, 504])
