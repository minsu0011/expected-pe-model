from __future__ import annotations

from research.model_zoo.hofs_research_adapter_v1.contracts import MODEL_ID
from research.model_zoo.pre_certification_research_tournament_v1.hofs_extension import (
    EXTENDED_CANDIDATE_IDS,
    EXTENDED_MODEL_IDS,
    EXTENSION_OUTPUT_ROOT,
    HOFS_CHECKSUMS_SHA256,
    HOFS_MANIFEST_SHA256,
    HOFS_STANDARDIZED_SHA256,
)


def test_extension_has_exact_five_model_surface() -> None:
    assert len(EXTENDED_MODEL_IDS) == 5
    assert len(EXTENDED_CANDIDATE_IDS) == 4
    assert EXTENDED_MODEL_IDS[-1] == MODEL_ID
    assert EXTENDED_CANDIDATE_IDS[-1] == MODEL_ID
    assert len(set(EXTENDED_MODEL_IDS)) == 5


def test_extension_is_new_isolated_output_identity() -> None:
    assert "hofs_r2_extension" in EXTENSION_OUTPUT_ROOT
    assert "bce_spent_r4" not in EXTENSION_OUTPUT_ROOT


def test_hofs_full_inputs_are_exactly_hash_pinned() -> None:
    for digest in (
        HOFS_MANIFEST_SHA256,
        HOFS_CHECKSUMS_SHA256,
        HOFS_STANDARDIZED_SHA256,
    ):
        assert len(digest) == 64
        assert set(digest) <= set("0123456789abcdef")
