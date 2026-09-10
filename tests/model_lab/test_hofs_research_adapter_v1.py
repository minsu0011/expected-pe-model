from __future__ import annotations

import inspect
import math

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.hofs_research_adapter_v1.artifacts import SOURCE_PATHS
from research.model_zoo.hofs_research_adapter_v1.contracts import (
    BENCHMARK_FOLD_INDICES,
    BENCHMARK_TASK_COUNT,
    BENCHMARK_WORKERS,
    CANONICAL_INPUT_LEDGER_SHA256,
    DGPS,
    FULL_OUTER_WORKERS,
    MODEL_ID,
    NONINFORMATIVE_GROUP_LABEL,
    PREDICTION_COLUMNS,
    SEEDS,
    design_payload,
    semantic_sha256,
)
from research.model_zoo.hofs_research_adapter_v1.inputs import (
    build_public_task_plan,
    project_root,
    verify_numeric_source_closure,
)
from research.model_zoo.hofs_research_adapter_v1.publisher import publish_atomic
from research.model_zoo.hofs_research_adapter_v1.worker import (
    _windows_process_memory,
    execute_task,
)
from research.model_zoo.pre_certification_research_tournament_v1.adapters import (
    NORMALIZED_PREDICTION_COLUMNS,
    normalize_hofs_rows,
)
from research.model_zoo.pre_certification_research_tournament_v1.contracts import (
    COMMON_IDENTITIES,
    RESEARCH_EVIDENCE_CLASS,
    SCORE_END,
    SCORE_ROWS_PER_TASK,
    SCORE_START,
)
from scripts.model_lab.hofs_research_adapter_v1.run_adapter import run


def test_design_is_isolated_research_only_and_fail_closed() -> None:
    design = design_payload()
    assert design["evidence_class"] == "RESEARCH_ONLY"
    assert design["authority"] == {
        "formal_model_identity": False,
        "service_identity": False,
        "certification": False,
        "qualification": False,
        "promotion": False,
        "registry_or_champion_mutation": False,
        "score": False,
        "prediction_research_only": True,
    }
    assert design["numeric_lineage"]["legacy_launcher_or_service_called"] is False
    assert design["numeric_lineage"]["seed_or_dgp_numeric_input"] is False
    assert design["missing_and_fallback"]["champion_prediction_fallback"] == "FORBIDDEN"
    assert design["missing_and_fallback"]["zero_fill"] is False
    assert design["missing_and_fallback"]["partial_publish"] is False
    assert design["resources"]["full_outer_workers"] == 16
    assert design["resources"]["inner_threads"] == 1


def test_exact_public_task_plan_is_50_canonical_files_only() -> None:
    tasks = build_public_task_plan()
    assert len(tasks) == 50
    assert tuple((task.seed, task.dgp) for task in tasks) == tuple(
        (seed, dgp) for seed in SEEDS for dgp in DGPS
    )
    assert [task.ordinal for task in tasks] == list(range(50))
    assert all(task.canonical_relative_path.endswith("/canonical150.csv") for task in tasks)
    assert all("/pass_1/" in task.canonical_relative_path for task in tasks)
    assert semantic_sha256([task.ledger_payload() for task in tasks]) == (
        CANONICAL_INPUT_LEDGER_SHA256
    )


def test_audited_v7_numeric_source_closure_is_exact() -> None:
    receipt = verify_numeric_source_closure()
    assert receipt["file_count"] == 12
    assert receipt["status"] == "PASS_EXACT_AUDITED_V7_NUMERIC_SOURCE_CLOSURE"
    assert len(receipt["semantic_sha256"]) == 64


def test_seed_and_dgp_are_not_passed_as_numeric_nuisance_labels() -> None:
    worker_source = inspect.getsource(execute_task)
    assert "f\"DGP_{task.dgp}\"" not in worker_source
    assert "NONINFORMATIVE_GROUP_LABEL" in worker_source
    assert NONINFORMATIVE_GROUP_LABEL == "PUBLIC_TASK_SINGLE_GROUP"

    from research.model_zoo.hierarchical_observable_fair_value_state_v7.estimator import (
        _dgp_contrast,
    )

    design, transform = _dgp_contrast(np.zeros(8, dtype=np.int64), 1)
    assert design.shape == (8, 0)
    assert transform.shape == (1, 0)


def _synthetic_full_hofs_rows() -> pd.DataFrame:
    task_ordinals = np.repeat(np.arange(50, dtype=np.int64), SCORE_ROWS_PER_TASK)
    seeds = np.repeat(np.repeat(np.asarray(SEEDS), len(DGPS)), SCORE_ROWS_PER_TASK)
    dgps = np.repeat(np.tile(np.asarray(DGPS, dtype=object), len(SEEDS)), SCORE_ROWS_PER_TASK)
    positions = np.tile(np.arange(SCORE_START, SCORE_END, dtype=np.int64), 50)
    dates = pd.bdate_range("2001-01-01", periods=SCORE_END)[SCORE_START:SCORE_END]
    date_text = np.tile([date.isoformat() for date in dates], 50)
    fold_indices = (positions - SCORE_START) // 21
    return pd.DataFrame(
        {
            "task_ordinal": task_ordinals,
            "task_seed": seeds,
            "task_dgp": dgps,
            "fold_index": fold_indices,
            "source_row_position": positions,
            "entity_id": "DGP_ISSUER",
            "decision_date": date_text,
            "hofs_v7_expected_pe": 20.0,
            "hofs_v7_pe_p10": 18.0,
            "hofs_v7_pe_p90": 22.0,
            "hofs_v7_log_scale": math.log(0.05),
            "hofs_v7_tail_guard_weight": 0.9,
            "parameter_sha256": "a" * 64,
            "decision_block_ordered_membership_sha256": "b" * 64,
            "decision_block_set_membership_sha256": "c" * 64,
            "decision_source_positions_sha256": "d" * 64,
            "output_manifest_sha256": "e" * 64,
            "within_block_parameter_update_count": 0,
        },
        columns=PREDICTION_COLUMNS,
    )


def test_tournament_standardized_adapter_maps_dates_and_fold_ids() -> None:
    source = _synthetic_full_hofs_rows()
    normalized = normalize_hofs_rows(source, new_model_id=MODEL_ID)
    assert tuple(normalized.columns) == NORMALIZED_PREDICTION_COLUMNS
    assert len(normalized) == COMMON_IDENTITIES
    assert normalized.iloc[0]["fold_id"] == "fold_012"
    assert normalized.iloc[21]["fold_id"] == "fold_013"
    assert normalized.iloc[-1]["fold_id"] == "fold_073"
    assert normalized.iloc[0]["date"] == source.iloc[0]["decision_date"][:10]
    assert set(normalized["evidence_class"]) == {RESEARCH_EVIDENCE_CLASS}
    assert set(normalized["pe_model_id"]) == {MODEL_ID}
    assert np.allclose(normalized["uncertainty"].to_numpy(), 0.05)


def test_tournament_standardized_adapter_rejects_fold_drift() -> None:
    source = _synthetic_full_hofs_rows()
    source.loc[0, "fold_index"] = 1
    with pytest.raises(RuntimeError, match="prediction domain"):
        normalize_hofs_rows(source, new_model_id=MODEL_ID)


@pytest.mark.parametrize(
    ("column", "value", "message"),
    (
        ("hofs_v7_log_scale", float("nan"), "prediction domain"),
        ("hofs_v7_log_scale", 0.0, "prediction domain"),
        ("hofs_v7_tail_guard_weight", 1.01, "prediction domain"),
        ("source_row_position", 504.5, "integer custody"),
        ("within_block_parameter_update_count", 1, "prediction domain"),
        ("parameter_sha256", "not-a-sha", "prediction domain"),
        ("hofs_v7_expected_pe", 0.0, "prediction domain"),
    ),
)
def test_tournament_standardized_adapter_rejects_invalid_actual_fields(
    column: str,
    value: object,
    message: str,
) -> None:
    source = _synthetic_full_hofs_rows()
    if column == "source_row_position":
        source[column] = source[column].astype(np.float64)
    source.loc[0, column] = value
    with pytest.raises(RuntimeError, match=message):
        normalize_hofs_rows(source, new_model_id=MODEL_ID)


def test_microbenchmark_and_full_guards_are_fixed() -> None:
    assert BENCHMARK_WORKERS == (4, 8, 12, 16)
    assert BENCHMARK_TASK_COUNT == 16
    assert BENCHMARK_FOLD_INDICES == (0, 20, 40, 61)
    assert FULL_OUTER_WORKERS == 16
    with pytest.raises(RuntimeError, match="coordination token"):
        run("full")


def test_windows_peak_rss_receipt_is_available() -> None:
    receipt = _windows_process_memory()
    assert receipt["peak_rss_bytes"] >= receipt["rss_bytes"] > 0
    assert receipt["private_bytes"] > 0


def test_source_universe_exists_and_legacy_launchers_are_not_imported() -> None:
    root = project_root()
    assert all((root / relative).is_file() for relative in SOURCE_PATHS)
    package_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "research/model_zoo/hofs_research_adapter_v1").glob("*.py")
    )
    assert "prediction_launcher" not in package_sources
    assert "hierarchical_observable_fair_value_state_v9" not in package_sources
    assert "hierarchical_observable_fair_value_state_v11" not in package_sources


def test_atomic_publisher_rejects_external_destination() -> None:
    with pytest.raises(RuntimeError, match="outside the fixed adapter universe"):
        publish_atomic("outputs/not_the_adapter", {"A.txt": b"x"})


def test_preflight_does_not_fit_or_predict() -> None:
    receipt = run("preflight")
    assert receipt["task_count"] == 50
    assert receipt["fit_or_prediction_count"] == 0
    assert receipt["status"] == "PASS_RESEARCH_ONLY_HOFS_ADAPTER_PREFLIGHT"


def test_prediction_schema_matches_tournament_hofs_source_contract() -> None:
    from research.model_zoo.pre_certification_research_tournament_v1.adapters import (
        HOFS_SOURCE_COLUMNS,
    )

    assert PREDICTION_COLUMNS == HOFS_SOURCE_COLUMNS
    assert len(PREDICTION_COLUMNS) == 18
    assert SCORE_END - SCORE_START == SCORE_ROWS_PER_TASK
