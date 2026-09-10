from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest


RESEARCH_PROVENANCE_NODEIDS = frozenset(
    {
        (
            "tests/test_fundamental_vintage.py::"
            "test_candidate_design_lock_and_artifact_provenance_are_self_verifying"
        ),
        (
            "tests/test_lagged_market_conditioned.py::"
            "test_candidate_design_lock_and_artifact_provenance_are_self_verifying"
        ),
        (
            "tests/test_market_conditioned.py::"
            "test_sealed_21_seed_formula_and_metrics_reproduce_exactly"
        ),
        (
            "tests/test_matured_proxy_gate.py::"
            "test_design_lock_candidate_and_pre_reservation_contract_are_self_consistent"
        ),
        (
            "tests/test_ml_incumbent_smoothing.py::"
            "test_candidate_design_lock_and_artifact_provenance_are_self_verifying"
        ),
    }
)

_BUNDLED_CANONICAL_FIXTURE_NODEIDS = frozenset(
    {
        (
            "tests/test_in_memory_integration.py::"
            "test_fundamental_vintage_tail_is_price_free_and_isolated_from_prior_83_columns"
        ),
        (
            "tests/test_in_memory_integration.py::"
            "test_lagged_market_conditioned_tail_is_default_off_and_isolated_from_prior_87"
        ),
        (
            "tests/test_in_memory_integration.py::"
            "test_matured_proxy_tail_is_default_off_and_isolated_from_prior_96"
        ),
    }
)

_TEMP_V03_CONTEXT_NODEIDS = frozenset(
    {
        (
            "tests/test_multiseed_validation_harness.py::"
            "test_long_root_is_rejected_before_manifest_output_or_subprocess"
        ),
        (
            "tests/test_multiseed_validation_harness.py::"
            "test_manifest_seals_and_revalidates_path_policy"
        ),
    }
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_LEGACY_WARMUP_CSV = (
    _REPOSITORY_ROOT / "outputs" / "warmup_seed42_v03" / "DEMO_PE_Regime_DEMO_BENCH.csv"
).resolve()
_BUNDLED_CANONICAL_CSV = (
    _REPOSITORY_ROOT / "sample_data" / "v03_canonical_high_sample.csv"
).resolve()


def pytest_itemcollected(item: pytest.Item) -> None:
    """Partition every test exactly once and reject provenance-marker bypasses."""

    nodeid = item.nodeid.replace("\\", "/")
    expected_research = nodeid in RESEARCH_PROVENANCE_NODEIDS
    has_research = any(item.iter_markers(name="research_provenance"))
    has_release = any(item.iter_markers(name="release_scope"))

    if has_research and not expected_research:
        raise pytest.UsageError(
            "research_provenance is restricted to the exact sealed allowlist; "
            f"unauthorized marker on {nodeid}"
        )
    if expected_research and has_release:
        raise pytest.UsageError(
            f"sealed research-provenance test cannot also be release_scope: {nodeid}"
        )

    if expected_research and not has_research:
        item.add_marker(pytest.mark.research_provenance)
        has_research = True
    elif not expected_research and not has_release:
        item.add_marker(pytest.mark.release_scope)
        has_release = True

    if has_research == has_release:
        raise pytest.UsageError(f"test must belong to exactly one release partition: {nodeid}")


@pytest.fixture(autouse=True)
def _self_contained_release_fixtures(request: pytest.FixtureRequest) -> None:
    """Replace five repository-context dependencies with packaged or temporary fixtures."""

    nodeid = request.node.nodeid.replace("\\", "/")
    if nodeid in _BUNDLED_CANONICAL_FIXTURE_NODEIDS:
        monkeypatch = request.getfixturevalue("monkeypatch")
        original_read_csv = pd.read_csv

        def read_csv(path_or_buffer, *args, **kwargs):
            try:
                requested_path = Path(path_or_buffer).resolve()
            except (OSError, TypeError, ValueError):
                requested_path = None
            if requested_path == _LEGACY_WARMUP_CSV:
                path_or_buffer = _BUNDLED_CANONICAL_CSV
                kwargs.setdefault("float_precision", "round_trip")
            return original_read_csv(path_or_buffer, *args, **kwargs)

        monkeypatch.setattr(pd, "read_csv", read_csv)

    if nodeid in _TEMP_V03_CONTEXT_NODEIDS:
        monkeypatch = request.getfixturevalue("monkeypatch")
        tmp_path = request.getfixturevalue("tmp_path")
        release_root = tmp_path / "PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
        v03_root = tmp_path / "PE_Regime_Engine_v0.2.0"

        demo_path = v03_root / "src" / "pe_regime_engine" / "demo.py"
        demo_path.parent.mkdir(parents=True)
        demo_path.write_text(
            "DEMO_GENERATOR_VERSION = 'smooth_fair_pe_pit_truth_xnys_v5'\n",
            encoding="utf-8",
        )
        v03_config = v03_root / "config" / "high_accuracy.yaml"
        v03_config.parent.mkdir(parents=True)
        v03_config.write_text("fixture: true\n", encoding="utf-8")

        v04_config = release_root / "config" / "v04_bottleneck.yaml"
        v04_config.parent.mkdir(parents=True)
        v04_config.write_bytes((_REPOSITORY_ROOT / "config" / "v04_bottleneck.yaml").read_bytes())
        monkeypatch.setattr(request.node.module, "ROOT", release_root)
