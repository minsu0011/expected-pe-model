from __future__ import annotations

import hashlib
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    BCE_VALUE_COLUMNS as UPSTREAM_BCE_VALUE_COLUMNS,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    GLOBAL_HOFS_LOG_SHRINK as UPSTREAM_GLOBAL_HOFS_LOG_SHRINK,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    HOFS_VALUE_COLUMNS as UPSTREAM_HOFS_VALUE_COLUMNS,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    MODEL_IDS as UPSTREAM_MODEL_IDS,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.prediction import (
    build_task_prediction_rows as upstream_build_task_prediction_rows,
)
from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.artifacts import (
    seal_payload,
    semantic_sha256,
)
from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.binding import (
    snapshot_record,
    validate_binding_payload,
)
from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.combine import (
    build_qualification_five_model_rows,
    build_task_five_model_rows,
)
from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1.contracts import (
    BINDING_SCHEMA,
    BINDING_STATUS,
    C1_C3_BINDING_FILES,
    C1_C3_PREDICTION_FILES,
    C4_ID,
    C4_SURFACE_FILES,
    DGP_IDS,
    GLOBAL_HOFS_LOG_SHRINK,
    HOFS_TASK_SURFACE_COLUMNS,
    IDENTITY_COLUMNS,
    MODEL_IDS,
    OUTPUT_FILES,
    PREDICTION_ROW_COUNT,
    PREFIX_MODEL_IDS,
    PREFIX_ROW_COUNT,
    ROWS_PER_TASK,
    SEED_ALIASES,
    SOURCE_CLOSURE_RELATIVES,
    TASK_COUNT,
    FiveModelCombinerError,
)


def _versions() -> dict[str, str]:
    return {
        model_id: f"sha256:{ordinal + 1:064x}"
        for ordinal, model_id in enumerate(MODEL_IDS)
    }


def _identity(seed_alias: str = "qualification_seed_01", dgp: str = "A") -> pd.DataFrame:
    positions = np.arange(504, 1800, dtype=np.int64)
    starts = tuple(range(504, 1800, 21))
    sizes = np.asarray([min(1800, start + 21) - start for start in starts])
    test_starts = np.repeat(starts, sizes).astype(np.int64)
    folds = np.repeat(
        [f"fold_{12 + ordinal:03d}" for ordinal in range(len(starts))], sizes
    )
    return pd.DataFrame(
        {
            "seed_alias": seed_alias,
            "dgp_id": dgp,
            "session_position": positions,
            "date": pd.bdate_range("2020-01-02", periods=ROWS_PER_TASK).strftime(
                "%Y-%m-%d"
            ),
            "symbol": "SYNTH",
            "fold_id": folds,
            "train_end_position": test_starts - 1,
            "test_start_position": test_starts,
        }
    )


def _merged_surface(
    seed_alias: str = "qualification_seed_01", dgp: str = "A"
) -> pd.DataFrame:
    identity = _identity(seed_alias, dgp)
    phase = np.linspace(0.0, 8.0 * np.pi, ROWS_PER_TASK)
    champion = 18.0 + 0.25 * np.sin(phase)
    correction_a = 0.08 * np.sin(phase / 3.0) + 0.01
    correction_b = 0.06 * np.sin(phase / 3.0) + 0.015
    bce = {
        "v04_expected_pe": champion,
        "lgbm_full_state_expected_pe": champion * np.exp(correction_a),
        "histgb_full_state_expected_pe": champion * np.exp(correction_b),
        "ofs_v1_eps_confidence_01": np.full(ROWS_PER_TASK, 0.8),
        "ofs_v1_eps_staleness_log1p": np.full(ROWS_PER_TASK, 1.2),
        "ofs_v1_regime_entropy": np.full(ROWS_PER_TASK, 0.25),
        "ofs_v1_regime_confidence": np.full(ROWS_PER_TASK, 0.75),
        "ofs_v1_state_abs_innovation_lag1": np.full(ROWS_PER_TASK, 0.12),
    }
    hofs = {
        "hofs_r2_expected_log_pe": np.log(champion) + 0.07 * np.cos(phase / 2.0),
        "hofs_v7_tail_guard_weight": np.linspace(0.2, 0.9, ROWS_PER_TASK),
        "hofs_v7_log_scale": np.log(np.linspace(0.08, 0.22, ROWS_PER_TASK)),
    }
    return pd.concat(
        [identity, pd.DataFrame(bce), pd.DataFrame(hofs)], axis=1
    )


def _prefix_and_c4(
    seed_alias: str = "qualification_seed_01", dgp: str = "A"
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    surface = _merged_surface(seed_alias, dgp)
    upstream = upstream_build_task_prediction_rows(
        surface,
        source_model_versions=_versions(),
    )
    prefix = upstream.loc[
        upstream["pe_model_id"].isin(PREFIX_MODEL_IDS)
    ].reset_index(drop=True)
    c4 = surface.loc[:, list(HOFS_TASK_SURFACE_COLUMNS)].reset_index(drop=True)
    return prefix, c4, upstream


def _fake_record(relative: str, ordinal: int) -> dict[str, object]:
    return {
        "relative_path": relative,
        "raw_sha256": f"{ordinal + 1:064x}",
        "size_bytes": ordinal + 1,
        "volume_serial_number": "0000000000000001",
        "file_id_128": f"{ordinal + 1:032x}",
    }


def _fake_artifact(
    role: str, root_relative: str, files: tuple[str, ...], start: int
) -> dict[str, object]:
    return {
        "role": role,
        "root_relative": root_relative,
        "root_identity": {
            "volume_serial_number": "0000000000000001",
            "file_id_128": f"{start + 1:032x}",
        },
        "files": [
            _fake_record(relative, start + index)
            for index, relative in enumerate(files)
        ],
    }


def _synthetic_binding() -> dict[str, object]:
    source_records = [
        _fake_record(relative, 100 + index)
        for index, relative in enumerate(SOURCE_CLOSURE_RELATIVES)
    ]
    unsigned = {
        "schema_version": BINDING_SCHEMA,
        "status": BINDING_STATUS,
        "c1_c3_binding_artifact": _fake_artifact(
            "c1_c3_binding",
            "outputs/c1_c3_binding_artifact",
            C1_C3_BINDING_FILES,
            10,
        ),
        "c1_c3_prediction_artifact": _fake_artifact(
            "c1_c3_predictions",
            "outputs/c1_c3_predictions_artifact",
            C1_C3_PREDICTION_FILES,
            20,
        ),
        "c4_surface_artifact": _fake_artifact(
            "c4_surfaces",
            "outputs/hofs_c4_qualification_artifact",
            C4_SURFACE_FILES,
            30,
        ),
        "source_records": source_records,
        "source_records_semantic_sha256": semantic_sha256(source_records),
        "source_model_versions": [
            {"model_id": model_id, "source_model_version": version}
            for model_id, version in _versions().items()
        ],
        "prediction_output_relative": "outputs/five_model_qualification_predictions_v1",
        "activation_marker_relative": (
            "outputs/five_model_qualification_predictions_v1_activation"
        ),
    }
    return seal_payload(unsigned, "binding_semantic_sha256")


def test_contract_geometry_and_upstream_schema_are_exact() -> None:
    assert MODEL_IDS == tuple(UPSTREAM_MODEL_IDS)
    assert GLOBAL_HOFS_LOG_SHRINK == UPSTREAM_GLOBAL_HOFS_LOG_SHRINK == 0.50
    assert PREFIX_ROW_COUNT == 259_200
    assert PREDICTION_ROW_COUNT == 324_000
    assert TASK_COUNT == 50
    assert ROWS_PER_TASK == 1_296
    assert tuple(HOFS_TASK_SURFACE_COLUMNS[8:]) == tuple(UPSTREAM_HOFS_VALUE_COLUMNS)
    assert len(UPSTREAM_BCE_VALUE_COLUMNS) == 8
    assert set(OUTPUT_FILES) == {
        "CHECKSUMS.sha256",
        "COMBINATION_RECEIPT.json",
        "INPUT_BINDING.json",
        "INPUT_CUSTODY_RECEIPT.json",
        "PREDICTIONS.csv",
        "PREDICTION_MANIFEST.json",
        "RUNTIME_RECEIPT.json",
        "SOURCE_MANIFEST.json",
    }
    assert all(
        not path.startswith(
            "research/model_zoo/observable_state_bce_dgp_tournament"
        )
        for path in SOURCE_CLOSURE_RELATIVES
    )


def test_one_task_is_byte_equivalent_to_frozen_upstream_five_model_formula() -> None:
    prefix, c4, upstream = _prefix_and_c4()
    actual = build_task_five_model_rows(
        prefix,
        c4,
        source_model_versions=_versions(),
    )
    pd.testing.assert_frame_equal(
        actual,
        upstream,
        check_dtype=True,
        check_exact=True,
        check_names=True,
    )
    assert actual["pe_model_id"].tolist()[:5] == list(MODEL_IDS)
    assert actual.loc[actual["pe_model_id"].eq(C4_ID), "applied_alpha"].eq(0.5).all()


def test_identity_mismatch_fails_closed_without_sort_or_join() -> None:
    prefix, c4, _ = _prefix_and_c4()
    attacked = c4.copy()
    attacked.loc[10, "date"] = "2099-12-31"
    with pytest.raises(FiveModelCombinerError, match="identities differ|dates"):
        build_task_five_model_rows(
            prefix,
            attacked,
            source_model_versions=_versions(),
        )


def test_full_50_task_synthetic_geometry_is_exact_and_adjacent() -> None:
    prefix_template, c4_template, _ = _prefix_and_c4()
    prefixes: list[pd.DataFrame] = []
    surfaces: list[pd.DataFrame] = []
    for seed_alias in SEED_ALIASES:
        for dgp in DGP_IDS:
            prefix = prefix_template.copy()
            surface = c4_template.copy()
            prefix["seed_alias"] = seed_alias
            prefix["dgp_id"] = dgp
            surface["seed_alias"] = seed_alias
            surface["dgp_id"] = dgp
            prefixes.append(prefix)
            surfaces.append(surface)
    output = build_qualification_five_model_rows(
        pd.concat(prefixes, ignore_index=True),
        pd.concat(surfaces, ignore_index=True),
        source_model_versions=_versions(),
    )
    assert len(output) == PREDICTION_ROW_COUNT
    assert output["pe_model_id"].to_numpy(dtype=object).reshape(-1, 5)[0].tolist() == list(
        MODEL_IDS
    )
    assert not output.duplicated([*IDENTITY_COLUMNS, "pe_model_id"]).any()


def test_parameterized_binding_requires_exact_roles_files_sources_and_self_seal() -> None:
    binding = _synthetic_binding()
    assert validate_binding_payload(binding) == binding
    attacked = dict(binding)
    attacked["prediction_output_relative"] = "outputs/truth_five_model_predictions"
    attacked.pop("binding_semantic_sha256")
    attacked = seal_payload(attacked, "binding_semantic_sha256")
    with pytest.raises(FiveModelCombinerError, match="safe final outputs child"):
        validate_binding_payload(attacked)
    unsealed = dict(binding)
    unsealed["status"] = "ATTACKED"
    with pytest.raises(FiveModelCombinerError, match="self-seal"):
        validate_binding_payload(unsealed)


@pytest.mark.skipif(os.name != "nt", reason="Win32 FileId contract")
def test_synthetic_file_snapshot_uses_raw_hash_size_and_file_id(tmp_path: Path) -> None:
    path = tmp_path / "spent_synthetic.txt"
    raw = b"spent synthetic public bytes\n"
    path.write_bytes(raw)
    record = snapshot_record(path, relative_path="spent_synthetic.txt")
    assert record["raw_sha256"] == hashlib.sha256(raw).hexdigest()
    assert record["size_bytes"] == len(raw)
    assert len(str(record["file_id_128"])) == 32
    assert len(str(record["volume_serial_number"])) == 16
