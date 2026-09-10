from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab import (
    PIT_LONG_SIDECAR_COLUMNS,
    ContractError,
    FeatureMetadata,
    VerifiedPITSidecar,
    apply_identical_common_mask,
    attach_prediction_identity,
    merge_evaluation_truth,
    merge_pit_feature_sidecar,
    load_verified_pit_feature_sidecar,
    prepare_evaluation_truth,
    prepare_model_input,
    prepare_pit_feature_sidecar_asof,
)


CUTOFF_POLICY_ID = "DGP_FUNDAMENTAL_1230_UTC"


def _sidecar_feature(observed_feature: FeatureMetadata) -> FeatureMetadata:
    return replace(
        observed_feature,
        feature_id="synthetic_rate",
        column_name="synthetic_rate",
        description="Synthetic rate used only to test the sidecar contract",
        source="unit-test sidecar",
        feature_family="MACRO",
        provenance_reference="tests/model_lab/test_dataset.py",
        audit_notes="Synthetic metadata; no real macro feature is registered.",
    )


def _long_sidecar() -> pd.DataFrame:
    rows = [
        (
            "market",
            "synthetic_rate",
            "2015-01-02T09:00:00+00:00",
            "2015-01-02T10:00:00+00:00",
            "2015-01-02",
            "synthetic",
            0,
            False,
            1.0,
        ),
        (
            "market",
            "synthetic_rate",
            "2015-01-02T09:00:00+00:00",
            "2015-01-02T12:00:00+00:00",
            "2015-01-02",
            "synthetic",
            1,
            False,
            2.0,
        ),
        (
            "market",
            "synthetic_rate",
            "2015-01-02T09:00:00+00:00",
            "2015-01-02T13:00:00+00:00",
            "2015-01-02",
            "synthetic",
            2,
            False,
            3.0,
        ),
        (
            "market",
            "synthetic_rate",
            "2015-01-02T09:00:00+00:00",
            "2015-01-02T11:00:00+00:00",
            "2015-01-08",
            "synthetic",
            0,
            False,
            99.0,
        ),
    ]
    return pd.DataFrame(rows, columns=PIT_LONG_SIDECAR_COLUMNS)


def _sidecar_bytes(sidecar: pd.DataFrame) -> bytes:
    return sidecar.to_csv(index=False, lineterminator="\n").encode("utf-8")


def _verified_sidecar(sidecar: pd.DataFrame) -> VerifiedPITSidecar:
    return VerifiedPITSidecar(_sidecar_bytes(sidecar))


def test_prepare_model_input_enforces_150_columns_and_selects_only_declared_feature(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    assert prepared.features.columns.tolist() == ["observed_pe"]
    assert prepared.identity.columns.tolist() == ["date"]
    assert prepared.source_columns == tuple(canonical_150.columns)
    assert "true_fair_pe" not in prepared.features


def test_real_canonical_150_header_uses_external_seed_metadata(
    observed_feature: FeatureMetadata,
) -> None:
    root = Path(__file__).resolve().parents[2]
    sample = pd.read_csv(root / "sample_data" / "v03_canonical_high_sample.csv", nrows=3)
    assert len(sample.columns) == 150
    assert "date" in sample.columns
    assert "seed" not in sample.columns
    assert "true_fair_pe" not in sample.columns
    prepared = prepare_model_input(sample, [observed_feature])
    assert prepared.identity.columns.tolist() == ["date"]
    output = attach_prediction_identity(
        prepared,
        pd.Series([10.0] * len(sample), index=sample.index),
        seed=6301,
        model_id="header_regression",
        fold_id="fold_000",
    )
    assert output["seed"].tolist() == [6301] * len(sample)
    assert len(output.columns) == 5

    detached_truth = pd.read_csv(
        root / "sample_data" / "v03_canonical_high_sample_truth.csv", nrows=3
    )
    assert "seed" not in detached_truth.columns
    prepared_truth = prepare_evaluation_truth(detached_truth, seed=6301)
    assert prepared_truth.columns.tolist() == ["seed", "date", "true_fair_pe"]
    assert prepared_truth["seed"].tolist() == [6301] * len(detached_truth)


def test_prepare_model_input_rejects_width_truth_and_evaluation_feature(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    with pytest.raises(ContractError, match="width"):
        prepare_model_input(canonical_150.drop(columns="input_000"), [observed_feature])
    contaminated = canonical_150.rename(columns={"input_000": "true_fair_pe"})
    with pytest.raises(ContractError, match="true_fair_pe"):
        prepare_model_input(contaminated, [observed_feature])
    truth = replace(
        observed_feature,
        feature_id="truth",
        column_name="true_fair_pe",
        availability="evaluation_only",
        evaluation_only=True,
        allowed_for_fit=False,
        allowed_for_predict=False,
        point_in_time_safe=False,
    )
    with pytest.raises(ContractError, match="true_fair_pe"):
        prepare_model_input(contaminated, [truth])
    missing = replace(observed_feature, column_name="not_present")
    with pytest.raises(ContractError, match="missing feature"):
        prepare_model_input(canonical_150, [missing])


@pytest.mark.parametrize("control_column", ["seed", "fold_id", "model_id"])
def test_prepare_model_input_rejects_experiment_controls_in_canonical_header(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
    control_column: str,
) -> None:
    contaminated = canonical_150.rename(columns={"input_000": control_column})
    with pytest.raises(ContractError, match="reserved control"):
        prepare_model_input(contaminated, [observed_feature])


def test_prepare_model_input_never_selects_current_identity_as_numeric_feature(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    identity_feature = replace(
        observed_feature,
        feature_id="identity_date",
        column_name="date",
        dtype="datetime64[ns]",
    )
    with pytest.raises(ContractError, match="identity columns cannot be selected"):
        prepare_model_input(canonical_150, [identity_feature])


def test_prepare_model_input_rejects_index_identity_channels(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    named = canonical_150.copy()
    named.index = pd.Index(range(len(named)), name="seed")
    with pytest.raises(ContractError, match="unnamed zero-based RangeIndex"):
        prepare_model_input(named, [observed_feature])
    shifted = canonical_150.copy()
    shifted.index = pd.RangeIndex(1, len(shifted) + 1)
    with pytest.raises(ContractError, match="unnamed zero-based RangeIndex"):
        prepare_model_input(shifted, [observed_feature])
    multi = canonical_150.copy()
    multi.index = pd.MultiIndex.from_arrays(
        [[6301] * len(multi), range(len(multi))], names=["seed", "row"]
    )
    with pytest.raises(ContractError, match="unnamed zero-based RangeIndex"):
        prepare_model_input(multi, [observed_feature])


def test_attach_prediction_requires_exact_index(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    output = attach_prediction_identity(
        prepared,
        pd.Series([10.0, 11.0, 12.0, 13.0], index=prepared.features.index),
        seed=1,
        model_id="candidate",
        fold_id="fold_000",
    )
    assert output.columns.tolist() == ["seed", "date", "fold_id", "model_id", "prediction"]
    with pytest.raises(ContractError, match="index"):
        attach_prediction_identity(
            prepared,
            pd.Series([10.0] * 4, index=pd.RangeIndex(1, 5)),
            seed=1,
            model_id="candidate",
            fold_id="fold_000",
        )


@pytest.mark.parametrize("phase", ["fit", "predict"])
def test_legacy_wide_sidecar_cannot_create_model_input(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
    phase: str,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    feature = _sidecar_feature(observed_feature)
    sidecar = pd.DataFrame(
        {
            "date": canonical_150["date"],
            "synthetic_rate": [1.0, 2.0, 3.0, 4.0],
        }
    )
    with pytest.raises(ContractError, match="cannot produce fit/predict input"):
        merge_pit_feature_sidecar(
            prepared,
            sidecar,
            [feature],
            phase=phase,
        )


def test_pit_sidecars_cannot_overwrite_unselected_canonical_columns(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    collision = replace(
        _sidecar_feature(observed_feature),
        column_name="input_000",
    )
    exact = pd.DataFrame(
        {
            "date": canonical_150["date"],
            "input_000": [1.0, 2.0, 3.0, 4.0],
        }
    )
    with pytest.raises(ContractError, match="cannot produce fit/predict input"):
        merge_pit_feature_sidecar(
            prepared,
            exact,
            [collision],
            available_at_column=None,
        )

    long = _long_sidecar()
    cutoffs = pd.Series(
        [f"{date:%Y-%m-%d}T12:30:00+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    with pytest.raises(ContractError, match="canonical header"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            _verified_sidecar(long),
            [collision],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )


def test_long_pit_sidecar_selects_latest_eligible_revision_with_intraday_cutoff(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    feature = _sidecar_feature(observed_feature)
    cutoffs = pd.Series(
        [f"{date:%Y-%m-%d}T12:30:00+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    source = _long_sidecar()
    artifact = _verified_sidecar(source)
    with pytest.raises(ContractError, match="VerifiedPITSidecar"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            source,
            [feature],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )
    result = prepare_pit_feature_sidecar_asof(
        prepared,
        artifact,
        [feature],
        decision_cutoffs=cutoffs,
        cutoff_policy_id=CUTOFF_POLICY_ID,
        entity_ids="market",
    )
    assert result.prepared.features["synthetic_rate"].tolist() == [2.0, 3.0, 3.0, 3.0]
    assert result.selection_provenance["revision_id"].tolist() == [1, 2, 2, 2]
    assert result.selection_provenance["effective_session"].max() == pd.Timestamp("2015-01-02")
    assert len(result.normalized_source_sha256) == len(result.selection_sha256) == 64
    assert result.raw_sidecar_sha256 == artifact.raw_sidecar_sha256
    assert result.schema_sha256 == artifact.schema_sha256
    assert result.sidecar_serialization == artifact.serialization
    assert result.cutoff_policy_id == CUTOFF_POLICY_ID
    assert len(result.decision_cutoff_sha256) == 64
    reversed_source = source.iloc[::-1].reset_index(drop=True)
    reversed_artifact = _verified_sidecar(reversed_source)
    reversed_result = prepare_pit_feature_sidecar_asof(
        prepared,
        reversed_artifact,
        [feature],
        decision_cutoffs=cutoffs,
        cutoff_policy_id=CUTOFF_POLICY_ID,
        entity_ids="market",
    )
    assert reversed_result.normalized_source_sha256 == result.normalized_source_sha256
    assert reversed_result.selection_sha256 == result.selection_sha256
    assert reversed_result.raw_sidecar_sha256 != result.raw_sidecar_sha256


def test_long_pit_sidecar_rejects_ambiguous_or_leaky_source_records(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    feature = _sidecar_feature(observed_feature)
    cutoffs = pd.Series(
        [f"{date:%Y-%m-%d}T12:30:00+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    source = _long_sidecar()
    duplicated = pd.concat([source, source.iloc[[0]]], ignore_index=True)
    with pytest.raises(ContractError, match="duplicate/conflicting"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            _verified_sidecar(duplicated),
            [feature],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )
    nonfinite = source.copy()
    nonfinite.loc[0, "value"] = np.inf
    with pytest.raises(ContractError, match="explicitly masked"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            _verified_sidecar(nonfinite),
            [feature],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )
    naive = source.copy()
    naive["available_at"] = pd.to_datetime(naive["available_at"]).dt.tz_localize(None)
    with pytest.raises(ContractError, match="timezone-aware"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            _verified_sidecar(naive),
            [feature],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )
    rollback = source.copy()
    rollback.loc[rollback["revision_id"].eq(2), "available_at"] = "2015-01-02T11:00:00+00:00"
    with pytest.raises(ContractError, match="revision chronology"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            _verified_sidecar(rollback),
            [feature],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )
    too_early = pd.Series(
        [f"{date:%Y-%m-%d}T12:30:00+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    late_source = source.copy()
    late_source["observed_at"] = "2015-01-02T13:00:00+00:00"
    late_source["available_at"] = "2015-01-02T13:00:00+00:00"
    with pytest.raises(ContractError, match="no eligible sidecar revision"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            _verified_sidecar(late_source),
            [feature],
            decision_cutoffs=too_early,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )


@pytest.mark.parametrize(
    ("offset", "clock", "message"),
    [
        (pd.Timedelta(0), "12:31:00", "sealed UTC cutoff time"),
        (pd.Timedelta(days=1), "12:30:00", "exact prepared effective session"),
    ],
)
def test_long_pit_sidecar_cutoff_is_bound_to_session_and_sealed_policy(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
    offset: pd.Timedelta,
    clock: str,
    message: str,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    source = _long_sidecar()
    artifact = _verified_sidecar(source)
    cutoffs = pd.Series(
        [f"{date + offset:%Y-%m-%d}T{clock}+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    with pytest.raises(ContractError, match=message):
        prepare_pit_feature_sidecar_asof(
            prepared,
            artifact,
            [_sidecar_feature(observed_feature)],
            decision_cutoffs=cutoffs,
            cutoff_policy_id=CUTOFF_POLICY_ID,
            entity_ids="market",
        )

    valid_cutoffs = pd.Series(
        [f"{date:%Y-%m-%d}T12:30:00+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    with pytest.raises(ContractError, match="unknown code-owned cutoff policy"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            artifact,
            [_sidecar_feature(observed_feature)],
            decision_cutoffs=valid_cutoffs,
            cutoff_policy_id="CALLER_CHOSEN_2359_UTC",
            entity_ids="market",
        )


def test_verified_sidecar_recomputes_hashes_and_rejects_arbitrary_claims(
    tmp_path: Path,
) -> None:
    raw = _sidecar_bytes(_long_sidecar())
    artifact = VerifiedPITSidecar(raw)
    assert artifact.raw_sidecar_sha256 == hashlib.sha256(raw).hexdigest()
    assert len(artifact.schema_sha256) == 64
    with pytest.raises(AttributeError, match="immutable"):
        artifact.raw_sidecar_sha256 = "0" * 64
    with pytest.raises(ContractError, match="recomputed artifact hash"):
        VerifiedPITSidecar(raw, expected_raw_sidecar_sha256="0" * 64)
    with pytest.raises(ContractError, match="recomputed artifact hash"):
        VerifiedPITSidecar(raw, expected_schema_sha256="0" * 64)

    path = tmp_path / "public_factors.csv"
    path.write_bytes(raw)
    loaded = load_verified_pit_feature_sidecar(
        path,
        expected_raw_sidecar_sha256=artifact.raw_sidecar_sha256,
        expected_schema_sha256=artifact.schema_sha256,
    )
    assert loaded.raw_sidecar_sha256 == artifact.raw_sidecar_sha256
    path.write_bytes(raw.replace(b"synthetic_rate", b"synthetic_rates", 1))
    with pytest.raises(ContractError, match="recomputed artifact hash"):
        load_verified_pit_feature_sidecar(
            path,
            expected_raw_sidecar_sha256=artifact.raw_sidecar_sha256,
        )


def test_verified_sidecar_rejects_schema_order_and_type_changes() -> None:
    source = _long_sidecar()
    reordered = source.loc[:, list(reversed(PIT_LONG_SIDECAR_COLUMNS))]
    with pytest.raises(ContractError, match="exact sealed column order"):
        _verified_sidecar(reordered)
    wrong_revision = source.copy()
    wrong_revision["revision_id"] = "not-an-integer"
    with pytest.raises(ContractError, match="revision_id"):
        _verified_sidecar(wrong_revision)
    wrong_mask = source.copy()
    wrong_mask["is_missing"] = "not-a-boolean"
    with pytest.raises(ContractError, match="is_missing"):
        _verified_sidecar(wrong_mask)


def test_long_pit_sidecar_requires_explicit_missing_mask(
    canonical_150: pd.DataFrame,
    observed_feature: FeatureMetadata,
) -> None:
    prepared = prepare_model_input(canonical_150, [observed_feature])
    feature = _sidecar_feature(observed_feature)
    source = _long_sidecar().iloc[[0]].copy()
    source.loc[source.index[0], "is_missing"] = True
    source.loc[source.index[0], "value"] = np.inf
    cutoffs = pd.Series(
        [f"{date:%Y-%m-%d}T12:30:00+00:00" for date in canonical_150["date"]],
        index=prepared.features.index,
    )
    result = prepare_pit_feature_sidecar_asof(
        prepared,
        _verified_sidecar(source),
        [feature],
        decision_cutoffs=cutoffs,
        cutoff_policy_id=CUTOFF_POLICY_ID,
        entity_ids="market",
    )
    assert result.prepared.features["synthetic_rate"].isna().all()


def test_truth_merge_happens_after_prediction_by_identity_date_and_cutoff() -> None:
    predictions = pd.DataFrame(
        {
            "seed": [1, 1],
            "date": ["2014-12-31", "2015-01-02"],
            "model_id": ["a", "a"],
            "prediction": [9.0, 10.0],
        }
    )
    truth = pd.DataFrame(
        {
            "seed": [1, 1],
            "date": ["2014-12-31", "2015-01-02"],
            "true_fair_pe": [9.0, 11.0],
        }
    )
    merged = merge_evaluation_truth(predictions, truth)
    assert merged["date"].tolist() == [pd.Timestamp("2015-01-02")]
    assert merged["true_fair_pe"].tolist() == [11.0]
    with pytest.raises(ContractError, match="before evaluation truth"):
        merge_evaluation_truth(merged, truth)


def test_truth_merge_rejects_missing_or_duplicate_truth() -> None:
    predictions = pd.DataFrame(
        {"seed": [1], "date": ["2015-01-02"], "model_id": ["a"], "prediction": [10.0]}
    )
    with pytest.raises(ContractError, match="missing for"):
        merge_evaluation_truth(
            predictions,
            pd.DataFrame({"seed": [2], "date": ["2015-01-02"], "true_fair_pe": [10.0]}),
        )
    duplicated = pd.DataFrame(
        {
            "seed": [1, 1],
            "date": ["2015-01-02", "2015-01-02"],
            "true_fair_pe": [10.0, 10.0],
        }
    )
    with pytest.raises(ContractError, match="unique"):
        merge_evaluation_truth(predictions, duplicated)


def test_identical_common_mask_uses_exact_same_rows(prediction_frame: pd.DataFrame) -> None:
    frame = prediction_frame.copy()
    frame.loc[
        (frame["model_id"] == "model_a") & (frame["date"] == frame["date"].min()), "prediction"
    ] = np.nan
    common = apply_identical_common_mask(frame, required_model_ids=["model_a", "model_b"])
    counts = common.groupby("model_id").size()
    assert counts.to_dict() == {"model_a": 3, "model_b": 3}
    assert common.groupby("model_id")["date"].apply(tuple).nunique() == 1


def test_identical_common_mask_rejects_duplicate_or_missing_model(
    prediction_frame: pd.DataFrame,
) -> None:
    with pytest.raises(ContractError, match="every required model"):
        apply_identical_common_mask(prediction_frame, required_model_ids=["model_a", "missing"])
    duplicate = pd.concat([prediction_frame, prediction_frame.iloc[[0]]], ignore_index=True)
    with pytest.raises(ContractError, match="unique"):
        apply_identical_common_mask(duplicate, required_model_ids=["model_a", "model_b"])
    unequal = prediction_frame.drop(
        prediction_frame.loc[prediction_frame["model_id"].eq("model_b")].index[0]
    )
    with pytest.raises(ContractError, match="identical pre-mask identity sets"):
        apply_identical_common_mask(unequal, required_model_ids=["model_a", "model_b"])
    mismatch = prediction_frame.copy()
    mismatch.loc[mismatch["model_id"].eq("model_b").idxmax(), "true_fair_pe"] *= 1.01
    with pytest.raises(ContractError, match="truth must be identical"):
        apply_identical_common_mask(mismatch, required_model_ids=["model_a", "model_b"])
