from __future__ import annotations

from pathlib import Path
import shutil

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.models.wave1.artifacts import PREDICTION_COLUMNS, file_record
from pe_regime_v04.model_lab.models.wave1.evaluation import evaluate_wave1_predictions
from pe_regime_v04.model_lab.models.wave1.registration import (
    append_planned_wave1_definitions,
    reconcile_wave1_result_records,
    verify_result_resume_state_against_binding,
)
from pe_regime_v04.model_lab.models.wave1.reporting import (
    registry_ready_records,
    write_wave1_research_outputs,
)
from pe_regime_v04.model_lab.models.wave1.spec import (
    BASELINE_MODEL_IDS,
    CANDIDATE_MODEL_IDS,
)
from pe_regime_v04.model_lab.registry import (
    ModelRegistration,
    load_feature_registry,
    load_model_registry,
    validate_registry_cross_references,
)
from registry_test_support import write_pre_wave1_registry_fixture


def _full_model_evaluation():  # type: ignore[no-untyped-def]
    dates = pd.date_range("2015-01-02", periods=3, freq="B")
    truth_by_seed: dict[int, pd.DataFrame] = {}
    rows: list[dict[str, object]] = []
    all_models = (*CANDIDATE_MODEL_IDS, *BASELINE_MODEL_IDS)
    for seed_position, seed in enumerate((6301, 6421, 6521, 6607, 6701)):
        truth = np.asarray([10.0, 11.0, 12.0]) * (1.0 + seed_position * 0.001)
        truth_by_seed[seed] = pd.DataFrame({"date": dates, "true_fair_pe": truth})
        for model_position, model_id in enumerate(all_models):
            multiplier = 1.0 + 0.002 * (model_position + 1)
            for row_position, date in enumerate(dates):
                rows.append(
                    {
                        "seed": seed,
                        "date": date,
                        "symbol": "SYNTH",
                        "fold_id": "fold_000",
                        "test_start_position": 252,
                        "model_id": model_id,
                        "prediction": truth[row_position] * multiplier,
                    }
                )
    predictions = pd.DataFrame(rows).loc[:, list(PREDICTION_COLUMNS)]
    runtime = {model_id: 0.01 for model_id in all_models}
    return evaluate_wave1_predictions(
        predictions,
        truth_by_seed,
        runtime_seconds_by_model=runtime,
        strict_expected_rows_per_seed=3,
    )


def test_common_parquet_family_reports_and_registry_ready_records(tmp_path: Path) -> None:
    result = _full_model_evaluation()
    dummy_record = {"path": "C:/sealed.json", "bytes": 1, "sha256": "0" * 64}
    artifacts = write_wave1_research_outputs(
        result,
        tmp_path,
        execution_binding=dummy_record,
        execution_precommit=dummy_record,
        candidate_model_ids=CANDIDATE_MODEL_IDS,
        baseline_model_ids=BASELINE_MODEL_IDS,
    )
    wide = pd.read_parquet(artifacts["common_oos_matrix"]["wide_parquet"]["path"], engine="pyarrow")
    prediction_columns = [column for column in wide if column.startswith("prediction__")]
    assert len(wide) == 15
    assert len(prediction_columns) == 21
    assert list(wide.columns[:3]) == ["seed", "date", "true_fair_pe"]
    assert len(artifacts["family_artifacts"]) == 9
    for family in artifacts["family_artifacts"]:
        assert Path(family["model_report"]["path"]).is_file()
        assert Path(family["results_csv"]["path"]).is_file()
        assert Path(family["config_json"]["path"]).is_file()
        assert Path(family["oos_predictions_parquet"]["path"]).is_file()


def test_registry_ready_results_form_valid_append_only_revision_one_events(
    tmp_path: Path,
) -> None:
    result = _full_model_evaluation()
    registry = tmp_path / "registry"
    feature_paths, model_paths = write_pre_wave1_registry_fixture(registry)
    append_planned_wave1_definitions(feature_paths=feature_paths, model_paths=model_paths)
    bound_csv = tmp_path / "bound_model_registry.csv"
    bound_json = tmp_path / "bound_model_registry.json"
    shutil.copy2(model_paths.csv_path, bound_csv)
    shutil.copy2(model_paths.json_path, bound_json)
    bound_inventory = [
        {
            "label": "research/model_zoo/model_registry.csv",
            "snapshot": file_record(bound_csv),
        },
        {
            "label": "research/model_zoo/model_registry.json",
            "snapshot": file_record(bound_json),
        },
    ]
    payload = registry_ready_records(result)
    records = tuple(ModelRegistration.from_record(item) for item in payload["result_records"])
    assert payload["evidence_stage"] == "SPENT_SEED_STAGE1_CHEAP_SCREEN"
    assert payload["stage2_tuning_authorized"] is False
    assert payload["lock_authorized"] is False
    assert all(item.status == "RESEARCH_ONLY" for item in records)
    assert all(item.tuning_status == "UNTESTED" for item in records)
    assert all(item.locked_status == "UNTESTED" for item in records)
    assert all(
        item["screen_status"].startswith("SCREEN_")
        and item["stage2_tuning_authorized"] is False
        and item["lock_authorized"] is False
        for item in payload["screen_decisions"]
    )

    def interrupt(kind: str, _identifier: str, appended: int) -> None:
        if kind == "result" and appended == 4:
            raise RuntimeError("injected result interruption")

    with pytest.raises(RuntimeError, match="injected result interruption"):
        reconcile_wave1_result_records(model_paths, records, after_append=interrupt)
    assert (
        verify_result_resume_state_against_binding(
            model_paths=model_paths,
            runtime_verified_files=bound_inventory,
            records=records,
        )
        == 4
    )
    resumed = reconcile_wave1_result_records(model_paths, records)
    assert len(resumed.result_skipped_exact) == 4
    assert len(resumed.result_appended) == 13
    repeated = reconcile_wave1_result_records(model_paths, records)
    assert len(repeated.result_skipped_exact) == 17
    assert not repeated.result_appended
    validate_registry_cross_references(
        load_model_registry(model_paths),
        load_feature_registry(feature_paths),
        formal_run=True,
    )
