from __future__ import annotations

import copy
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.artifacts import (
    canonical_json_bytes,
    checksum_bytes,
    seal_payload,
    semantic_sha256,
    sha256_bytes,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.contracts import (
    AUDIT_EVIDENCE_FILENAMES,
    BCE_TASK_SURFACE_COLUMNS,
    BINDING_SCHEMA,
    BINDING_STATUS,
    C1_ID,
    C2_ID,
    C3_ID,
    FROZEN_NUMERIC_SOURCE_RECORDS,
    GENERATION_EVIDENCE_FILENAMES,
    IDENTITY_COLUMNS,
    MODEL_IDS,
    POSTGEN_AUDIT_SCHEMA,
    POSTGEN_GO,
    PREDICTION_COLUMNS,
    PREDICTION_ROW_COUNT,
    QUALIFICATION_SEEDS,
    RESOURCE_POLICY,
    SEED_ALIASES,
    SOURCE_CLOSURE_RELATIVES,
    C1C3PredictionError,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.custody import (
    _verify_postgen_audit,
    validate_binding_payload,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.prediction import (
    build_task_prediction_rows,
    validate_task_prediction_rows,
)
from research.model_zoo.pe_c1_c3_fresh_qualification_prediction_v1.publisher import (
    run_prediction_once,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.contracts import (
    C4_ID,
    FOLD_GEOMETRY,
    HOFS_TASK_SURFACE_COLUMNS,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.prediction import (
    build_task_prediction_rows as build_v2_task_prediction_rows,
)
from research.model_zoo.pe_c1_c4_fresh_qualification_prediction_v2.prediction import (
    merge_bound_task_surfaces,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {
    MODEL_IDS[0]: "sha256:" + "a" * 64,
    C1_ID: "sha256:" + "b" * 64,
    C2_ID: "sha256:" + "c" * 64,
    C3_ID: "sha256:" + "d" * 64,
}


def _surface() -> pd.DataFrame:
    positions = np.arange(504, 1800, dtype=np.int64)
    sizes = np.asarray(
        [
            FOLD_GEOMETRY.test_end_exclusive(start) - start
            for start in FOLD_GEOMETRY.test_starts
        ]
    )
    starts = np.repeat(FOLD_GEOMETRY.test_starts, sizes)
    champion = 9.0 + positions / 100_000.0
    return pd.DataFrame(
        {
            "seed_alias": "qualification_seed_01",
            "dgp_id": "A",
            "session_position": positions,
            "date": pd.date_range("2025-01-01", periods=len(positions), freq="D").strftime(
                "%Y-%m-%d"
            ),
            "symbol": "SYNTHETIC_ISSUER",
            "fold_id": np.repeat(
                [FOLD_GEOMETRY.fold_id(start) for start in FOLD_GEOMETRY.test_starts],
                sizes,
            ),
            "train_end_position": starts - 1,
            "test_start_position": starts,
            "v04_expected_pe": champion,
            "lgbm_full_state_expected_pe": champion
            * np.exp(0.04 + 0.005 * np.sin(positions / 13.0)),
            "histgb_full_state_expected_pe": champion
            * np.exp(0.05 + 0.005 * np.cos(positions / 17.0)),
            "ofs_v1_eps_confidence_01": np.linspace(0.2, 0.9, len(positions)),
            "ofs_v1_eps_staleness_log1p": np.linspace(
                0.0, np.log1p(252.0), len(positions)
            ),
            "ofs_v1_regime_entropy": np.linspace(0.8, 0.1, len(positions)),
            "ofs_v1_regime_confidence": np.linspace(
                1.0 / 3.0, 0.95, len(positions)
            ),
            "ofs_v1_state_abs_innovation_lag1": np.linspace(
                0.0, 2.0, len(positions)
            ),
        }
    ).loc[:, list(BCE_TASK_SURFACE_COLUMNS)]


def _file_record(relative: str, *, digest: str = "1" * 64, size: int = 1) -> dict[str, object]:
    return {
        "relative_path": relative,
        "size_bytes": size,
        "raw_sha256": digest,
        "volume_serial_number": "0000000000000001",
        "file_id_128": "2" * 32,
    }


def _syntactic_binding() -> dict[str, object]:
    pinned = {relative: (digest, size) for relative, digest, size in FROZEN_NUMERIC_SOURCE_RECORDS}
    sources = []
    for relative in SOURCE_CLOSURE_RELATIVES:
        digest, size = pinned.get(relative, (hashlib.sha256(relative.encode()).hexdigest(), 7))
        sources.append(_file_record(relative, digest=digest, size=size))
    source_semantic = semantic_sha256(sources)
    tree = "a" * 64
    tasks = []
    task_index = 0
    for seed_alias, seed in zip(SEED_ALIASES, QUALIFICATION_SEEDS, strict=True):
        for dgp in "ABCDEFGHIJ":
            prefix = f"replays/pass_1/seed_{seed}/dgp_{dgp}"
            tasks.append(
                {
                    "task_index": task_index,
                    "seed_alias": seed_alias,
                    "estimator_seed": seed,
                    "dgp_id": dgp,
                    "canonical": _file_record(f"{prefix}/canonical150.csv"),
                    "overlay": _file_record(f"{prefix}/v04_overlay.csv"),
                }
            )
            task_index += 1
    output = "outputs/model_zoo_pe_c1_c3_fresh_qualification_predictions_r1_20260824"
    unsigned = {
        "schema_version": BINDING_SCHEMA,
        "status": BINDING_STATUS,
        "public_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_r14_"
            "qualification_generation_20260824T000005"
        ),
        "public_root_identity": {
            "volume_serial_number": "0000000000000001",
            "file_id_128": "3" * 32,
        },
        "public_tree_sha256": tree,
        "generation_evidence": {
            name: _file_record(name) for name in GENERATION_EVIDENCE_FILENAMES
        },
        "tasks": tasks,
        "audit_root_relative": "outputs/model_zoo_r8_r14_post_generation_audit_20260824",
        "audit_root_identity": {
            "volume_serial_number": "0000000000000001",
            "file_id_128": "4" * 32,
        },
        "audit_evidence": {
            name: _file_record(name) for name in AUDIT_EVIDENCE_FILENAMES
        },
        "source_records": sources,
        "source_records_semantic_sha256": source_semantic,
        "source_model_versions": [
            {"model_id": MODEL_IDS[0], "source_model_version": f"sha256:{tree}"},
            *[
                {
                    "model_id": model_id,
                    "source_model_version": f"sha256:{source_semantic}",
                }
                for model_id in MODEL_IDS[1:]
            ],
        ],
        "prediction_output_relative": output,
        "activation_marker_relative": f"{output}_activation",
    }
    return seal_payload(unsigned, "binding_semantic_sha256")


def test_geometry_and_resources_are_exact_four_model_259200() -> None:
    assert MODEL_IDS == (
        "v04_expected_pe",
        C1_ID,
        C2_ID,
        C3_ID,
    )
    assert PREDICTION_ROW_COUNT == 50 * 1_296 * 4 == 259_200
    assert RESOURCE_POLICY == {
        "outer_backend": "exact_16_spawned_workers",
        "outer_workers": 16,
        "logical_cpu_count": 32,
        "logical_cpu_affinity_per_worker": 2,
        "inner_threads": 1,
        "gpu_enabled": False,
        "cuda_visible_devices": "-1",
    }


def test_adapter_is_bit_exact_v2_champion_c1_c2_c3_prefix() -> None:
    surface = _surface()
    actual = build_task_prediction_rows(surface, source_model_versions=VERSIONS)
    champion = surface["v04_expected_pe"].to_numpy(dtype=np.float64)
    hofs = surface.loc[:, list(IDENTITY_COLUMNS)].copy()
    hofs["hofs_r2_expected_log_pe"] = np.log(champion)
    hofs["hofs_v7_tail_guard_weight"] = 0.5
    hofs["hofs_v7_log_scale"] = 0.0
    hofs = hofs.loc[:, list(HOFS_TASK_SURFACE_COLUMNS)]
    upstream = build_v2_task_prediction_rows(
        merge_bound_task_surfaces(surface, hofs),
        source_model_versions={
            **VERSIONS,
            C4_ID: "sha256:" + "e" * 64,
        },
    )
    expected = upstream.loc[upstream["pe_model_id"].isin(MODEL_IDS)].reset_index(
        drop=True
    )
    pd.testing.assert_frame_equal(actual, expected, check_exact=True)
    assert tuple(actual.columns) == PREDICTION_COLUMNS
    assert actual["pe_model_id"].tolist()[:8] == [*MODEL_IDS, *MODEL_IDS]
    assert np.array_equal(
        actual.loc[actual["pe_model_id"].eq(MODEL_IDS[0]), "expected_pe"].to_numpy(),
        champion,
    )
    c3 = actual.loc[actual["pe_model_id"].eq(C3_ID)]
    assert np.allclose(c3["applied_alpha"], 0.4, rtol=0.0, atol=0.0)


def test_validation_recomputes_formula_and_rejects_tampering() -> None:
    surface = _surface()
    rows = build_task_prediction_rows(surface, source_model_versions=VERSIONS)
    attacked = rows.copy(deep=True)
    selected = attacked["pe_model_id"].eq(C2_ID)
    attacked.loc[selected, "expected_pe"] *= np.exp(0.01)
    attacked.loc[selected, "expected_log_pe"] = np.log(
        attacked.loc[selected, "expected_pe"].to_numpy(dtype=np.float64)
    )
    with pytest.raises(C1C3PredictionError, match="frozen source formula"):
        validate_task_prediction_rows(
            attacked,
            source_surface=surface,
            source_model_versions=VERSIONS,
        )


def test_binding_is_fully_explicit_and_source_pins_fail_closed() -> None:
    binding = _syntactic_binding()
    assert validate_binding_payload(binding) == binding
    attacked = copy.deepcopy(binding)
    attacked["source_records"][-1]["raw_sha256"] = "f" * 64
    attacked["source_records_semantic_sha256"] = semantic_sha256(
        attacked["source_records"]
    )
    attacked["source_model_versions"] = [
        attacked["source_model_versions"][0],
        *[
            {"model_id": model_id, "source_model_version": "sha256:" + "f" * 64}
            for model_id in MODEL_IDS[1:]
        ],
    ]
    attacked.pop("binding_semantic_sha256")
    attacked = seal_payload(attacked, "binding_semantic_sha256")
    with pytest.raises(C1C3PredictionError, match="frozen numeric source pin"):
        validate_binding_payload(attacked)


def test_binding_rejects_task_reorder_and_restricted_path_before_io() -> None:
    attacked = _syntactic_binding()
    attacked["tasks"][0], attacked["tasks"][1] = (
        attacked["tasks"][1],
        attacked["tasks"][0],
    )
    attacked.pop("binding_semantic_sha256")
    attacked = seal_payload(attacked, "binding_semantic_sha256")
    with pytest.raises(C1C3PredictionError, match="task binding order"):
        validate_binding_payload(attacked)

    attacked = _syntactic_binding()
    attacked["public_root_relative"] = "outputs/truth_vault"
    attacked.pop("binding_semantic_sha256")
    attacked = seal_payload(attacked, "binding_semantic_sha256")
    with pytest.raises(C1C3PredictionError, match="public boundary"):
        validate_binding_payload(attacked)

    attacked = _syntactic_binding()
    attacked["public_root_identity"]["volume_serial_number"] = 1
    attacked.pop("binding_semantic_sha256")
    attacked = seal_payload(attacked, "binding_semantic_sha256")
    with pytest.raises(C1C3PredictionError, match="FileId identity is invalid"):
        validate_binding_payload(attacked)


def test_final_postgen_auditor_schema_and_target_digest_are_exact() -> None:
    binding = _syntactic_binding()
    generation = binding["generation_evidence"]
    identity = binding["public_root_identity"]
    target = {
        "public_root_name": Path(binding["public_root_relative"]).name,
        "manifest_raw_sha256": generation["MANIFEST.json"]["raw_sha256"],
        "checksums_raw_sha256": generation["CHECKSUMS.sha256"]["raw_sha256"],
        "expected_tree_semantic_sha256": binding["public_tree_sha256"],
        "observed_tree_semantic_sha256": binding["public_tree_sha256"],
        "target_root_file_count": 1_209,
        "root_identity": {
            "identity_source": "GetFileInformationByHandleEx.FileIdInfo",
            "volume_serial_number": identity["volume_serial_number"],
            "file_id_128": identity["file_id_128"],
        },
    }
    audit = {
        "schema_version": POSTGEN_AUDIT_SCHEMA,
        "status": POSTGEN_GO,
        "verdict": POSTGEN_GO,
        "severity_counts": {"P0": 0, "P1": 0, "P2": 0},
        "access": {
            "truth_open_count": 0,
            "score_open_count": 0,
            "heldout_open_count": 0,
            "protected_namespace_open_count": 0,
        },
        "audited_public_root_name": target["public_root_name"],
        "public_manifest_raw_sha256": target["manifest_raw_sha256"],
        "public_checksums_raw_sha256": target["checksums_raw_sha256"],
        "expected_public_tree_semantic_sha256": binding["public_tree_sha256"],
        "public_tree_semantic_sha256": binding["public_tree_sha256"],
        "public_root_volume_serial_number": identity["volume_serial_number"],
        "public_root_file_id_128": identity["file_id_128"],
        "target_root_file_count": 1_209,
        "target_binding": target,
        "target_binding_sha256": semantic_sha256(target),
    }
    audit_raw = canonical_json_bytes(audit)
    audit_record = binding["audit_evidence"]["POSTGEN_AUDIT.json"]
    audit_record["raw_sha256"] = sha256_bytes(audit_raw)
    audit_record["size_bytes"] = len(audit_raw)
    seal = {
        "schema_version": "expected_pe.r8.r14.post_generation_audit_seal.v1",
        "status": "SEALED_GO_POSTGEN_PUBLIC_ROOT_P0_0_P1_0_P2_0",
        "postgen_audit_raw_sha256": audit_record["raw_sha256"],
        "postgen_audit_size_bytes": audit_record["size_bytes"],
        "postgen_audit_volume_serial_number": audit_record["volume_serial_number"],
        "postgen_audit_file_id_128": audit_record["file_id_128"],
    }
    seal_raw = canonical_json_bytes(seal)
    binding["audit_evidence"]["AUDIT_SEAL.json"]["raw_sha256"] = sha256_bytes(
        seal_raw
    )
    checksums_raw = checksum_bytes(
        {
            "AUDIT_SEAL.json": sha256_bytes(seal_raw),
            "POSTGEN_AUDIT.json": sha256_bytes(audit_raw),
        }
    )
    _verify_postgen_audit(
        binding,
        {
            "POSTGEN_AUDIT.json": audit_raw,
            "AUDIT_SEAL.json": seal_raw,
            "CHECKSUMS.sha256": checksums_raw,
        },
    )


def test_wrong_activation_fails_before_project_or_input_path_access(tmp_path: Path) -> None:
    with pytest.raises(C1C3PredictionError, match="activation literal"):
        run_prediction_once(
            project_root=tmp_path / "does-not-exist",
            binding={},
            activation="WRONG",
        )


def test_measured_numeric_source_closure_is_still_byte_exact() -> None:
    for relative, expected_sha, expected_size in FROZEN_NUMERIC_SOURCE_RECORDS:
        path = PROJECT_ROOT / relative
        raw = path.read_bytes()
        assert len(raw) == expected_size
        assert hashlib.sha256(raw).hexdigest() == expected_sha


def test_publisher_import_boundary_keeps_numerical_stack_cold() -> None:
    raw = (
        PROJECT_ROOT
        / "research/model_zoo/pe_c1_c3_fresh_qualification_prediction_v1/publisher.py"
    ).read_text(encoding="utf-8")
    prefix = raw.split("run_injected_batch(injected, max_workers=16)", 1)[0]
    assert "import numpy" not in prefix
    assert "import pandas" not in prefix
    assert "from .prediction import" not in prefix
