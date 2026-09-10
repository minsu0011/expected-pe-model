from __future__ import annotations

import numpy as np
import pytest

from research.model_zoo.pe_c4_release_candidate_v1.runtime import (
    C4InferenceError,
    infer_c4_or_v04,
)


def test_exact_c4_formula_is_deterministic() -> None:
    champion = np.asarray([10.0, 20.0])
    raw = np.log(np.asarray([40.0, 5.0]))
    first = infer_c4_or_v04(champion, raw, upstream_status="PASS")
    second = infer_c4_or_v04(champion, raw, upstream_status="PASS")
    np.testing.assert_array_equal(first.expected_pe, second.expected_pe)
    np.testing.assert_allclose(first.expected_pe, [20.0, 10.0], rtol=1e-15)
    assert first.selected_model_id == "hofs_v4_expected_pe"
    assert first.fallback_used is False


def test_upstream_failure_falls_back_to_v04_byte_exact_vector() -> None:
    champion = np.asarray([11.0, 19.0], dtype=np.float64)
    result = infer_c4_or_v04(champion, None, upstream_status="NONCONVERGENCE")
    np.testing.assert_array_equal(result.expected_pe, champion)
    assert result.selected_model_id == "v04_expected_pe"
    assert result.fallback_used is True
    assert result.fallback_reason == "HOFS_UPSTREAM_UNAVAILABLE"


@pytest.mark.parametrize(
    ("champion", "hofs"),
    [([0.0], [1.0]), ([1.0], [float("nan")]), ([1.0, 2.0], [1.0])],
)
def test_invalid_input_fails_closed(champion, hofs) -> None:
    with pytest.raises(C4InferenceError):
        infer_c4_or_v04(champion, hofs, upstream_status="PASS")
