from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.artifacts import (
    make_preserved_staging,
    parse_checksum_bytes,
    seal_payload,
    verify_sealed_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.bindings import (
    EXPECTED_R8_GENERATION_ROOT,
    FUTURE_FINAL_FREEZE,
    FUTURE_R5_POST_GENERATION_AUDIT,
    FUTURE_R8_GENERATION,
    FutureFinalFreezeBinding,
    FutureR5PostGenerationAuditBinding,
    FutureR8GenerationBinding,
    null_future_binding_payload,
    require_all_future_authority_exact,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.contracts import (
    BCE_B_ID,
    BCE_D_ID,
    CANDIDATE_IDS,
    CHAMPION_ID,
    CONSTITUENT_MODEL_IDS,
    DGP_IDS,
    EXPECTED_CONSTITUENT_FITS,
    EXPECTED_FOLD_BLOCKS,
    EXPECTED_IDENTITIES,
    EXPECTED_MODEL_IDENTITY_ROWS,
    EXPECTED_TASK_COUNT,
    FIXED_040_ID,
    FOLD_GEOMETRY,
    FORBIDDEN_PREDICTION_FIELD_TOKENS,
    IDENTITY_COLUMNS,
    MODEL_IDS,
    MODEL_ORDINALS,
    PREDICTION_COLUMNS,
    PREDICTION_LAUNCH_ALLOWED,
    RESOURCE_POLICY,
    SEED_ALIASES,
    TASK_SURFACE_COLUMNS,
    FreshQualificationContractError,
    contract_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.custody import (
    bind_future_inputs,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.design import (
    design_preview_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.diagnostics import (
    validate_task_fold_diagnostics,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.precommit import (
    VerificationEvidence,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.prediction import (
    build_task_prediction_rows,
    compute_frozen_candidates,
    validate_task_prediction_rows,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.runner import (
    PREDICTION_ACTIVATION_LITERAL,
    run_prediction_only,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.source_audit import (
    SOURCE_RELATIVE_PATHS,
    audit_source_boundary,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _task_surface() -> pd.DataFrame:
    positions = np.arange(
        FOLD_GEOMETRY.first_prediction_position,
        FOLD_GEOMETRY.final_prediction_position + 1,
        dtype=np.int64,
    )
    sizes = np.asarray(
        [
            FOLD_GEOMETRY.test_end_exclusive(start) - start
            for start in FOLD_GEOMETRY.test_starts
        ],
        dtype=np.int64,
    )
    test_starts = np.repeat(FOLD_GEOMETRY.test_starts, sizes)
    correction_a = 0.03 + 0.005 * np.sin(np.arange(len(positions)) / 17.0)
    correction_b = 0.05 + 0.005 * np.cos(np.arange(len(positions)) / 19.0)
    champion = 10.0 + 0.001 * np.arange(len(positions))
    frame = pd.DataFrame(
        {
            "seed_alias": SEED_ALIASES[0],
            "dgp_id": DGP_IDS[0],
            "date": pd.date_range("2022-01-01", periods=len(positions), freq="D").strftime(
                "%Y-%m-%d"
            ),
            "symbol": "SYNTHETIC_ISSUER",
            "session_position": positions,
            "fold_id": np.repeat(
                [FOLD_GEOMETRY.fold_id(start) for start in FOLD_GEOMETRY.test_starts],
                sizes,
            ),
            "train_end_position": test_starts - 1,
            "test_start_position": test_starts,
            "champion_expected_pe": champion,
            "constituent_a_expected_pe": champion * np.exp(correction_a),
            "constituent_b_expected_pe": champion * np.exp(correction_b),
            "observable_state_confidence": np.linspace(0.2, 0.8, len(positions)),
        }
    )
    return frame.loc[:, list(TASK_SURFACE_COLUMNS)]


def _fold_diagnostics() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for start in FOLD_GEOMETRY.test_starts:
        rows.append(
            {
                "seed_alias": SEED_ALIASES[0],
                "dgp_id": DGP_IDS[0],
                "fold_id": FOLD_GEOMETRY.fold_id(start),
                "test_start_position": start,
                "test_end_exclusive_position": FOLD_GEOMETRY.test_end_exclusive(start),
                "train_end_position": start - 1,
                "train_rows": start,
                "train_positions_sha256": "a" * 64,
                "state_feature_sha256": "b" * 64,
                "models": [
                    {"model_id": model_id, "inner_threads": 1}
                    for model_id in CONSTITUENT_MODEL_IDS
                ],
                "fitted_state_challengers": 2,
                "within_fold_refit_count": 0,
            }
        )
    return rows


def _exact_future_bindings() -> tuple[
    FutureR8GenerationBinding,
    FutureR5PostGenerationAuditBinding,
    FutureFinalFreezeBinding,
]:
    generation = FutureR8GenerationBinding(
        generation_design_raw_sha256="1" * 64,
        generation_manifest_raw_sha256="2" * 64,
        freeze_receipt_raw_sha256="3" * 64,
        checksums_raw_sha256="4" * 64,
    )
    audit = FutureR5PostGenerationAuditBinding(
        access_ledger_raw_sha256="5" * 64,
        audit_raw_sha256="6" * 64,
        audit_semantic_sha256="7" * 64,
        audit_sha256_file_raw_sha256="8" * 64,
        seal_receipt_raw_sha256="9" * 64,
        checksums_raw_sha256="a" * 64,
    )
    final = FutureFinalFreezeBinding(
        design_lock_raw_sha256="b" * 64,
        design_lock_semantic_sha256="c" * 64,
        checksums_raw_sha256="d" * 64,
    )
    return generation, audit, final


def test_exact_model_universe_geometry_and_resource_contract() -> None:
    assert MODEL_IDS == (CHAMPION_ID, BCE_B_ID, BCE_D_ID, FIXED_040_ID)
    assert CANDIDATE_IDS == MODEL_IDS[1:]
    assert MODEL_ORDINALS == dict(zip(MODEL_IDS, range(4), strict=True))
    assert CHAMPION_ID == "v04_expected_pe"
    assert CONSTITUENT_MODEL_IDS == (
        "lgbm__ofs_v1_full_with_regime",
        "histgb__ofs_v1_full_with_regime",
    )
    assert EXPECTED_TASK_COUNT == 5 * 10 == 50
    assert FOLD_GEOMETRY.fold_count == 62
    assert FOLD_GEOMETRY.prediction_rows_per_task == 1296
    assert EXPECTED_IDENTITIES == 5 * 10 * 1296 == 64800
    assert EXPECTED_MODEL_IDENTITY_ROWS == EXPECTED_IDENTITIES * 4 == 259200
    assert EXPECTED_FOLD_BLOCKS == 3100
    assert EXPECTED_CONSTITUENT_FITS == 6200
    assert RESOURCE_POLICY.outer_backend == "spawn_process_pool"
    assert RESOURCE_POLICY.outer_workers == 32
    assert RESOURCE_POLICY.inner_threads == 1
    assert RESOURCE_POLICY.failed_staging_policy == "PRESERVE_WITH_FAILURE_RECEIPT"
    assert RESOURCE_POLICY.environment["OMP_NUM_THREADS"] == "1"
    assert RESOURCE_POLICY.gpu_enabled is False
    assert PREDICTION_LAUNCH_ALLOWED is False
    contract = contract_payload()
    assert contract["parameter_tuning_allowed"] is False
    assert contract["model_addition_substitution_or_retry_allowed"] is False
    assert contract["constituent_gate_or_rank_use_allowed"] is False


def test_prediction_schema_has_no_restricted_fields() -> None:
    assert tuple(PREDICTION_COLUMNS) == tuple(dict.fromkeys(PREDICTION_COLUMNS))
    assert not [
        column
        for column in PREDICTION_COLUMNS
        if any(token in column.casefold() for token in FORBIDDEN_PREDICTION_FIELD_TOKENS)
    ]
    assert "expected_pe" in PREDICTION_COLUMNS
    assert "expected_log_pe" in PREDICTION_COLUMNS
    assert "observable_state_confidence" in PREDICTION_COLUMNS
    assert "disagreement" in PREDICTION_COLUMNS


def test_all_R8_R5_and_final_hashes_are_null_and_fail_closed() -> None:
    payload = null_future_binding_payload()
    assert set(payload) == {
        "r8_generation",
        "r5_post_generation_audit",
        "final_execution_freeze",
    }
    assert all(
        value is None
        for binding in payload.values()
        for key, value in binding.items()
        if key.endswith("_sha256")
    )
    assert FUTURE_R8_GENERATION.is_exact is False
    assert FUTURE_R5_POST_GENERATION_AUDIT.is_exact is False
    assert FUTURE_FINAL_FREEZE.is_exact is False
    with pytest.raises(FreshQualificationContractError, match="not exact"):
        require_all_future_authority_exact()


def test_partial_malformed_and_path_attacks_cannot_become_exact() -> None:
    partial = FutureR8GenerationBinding(generation_design_raw_sha256="a" * 64)
    malformed = replace(
        partial,
        generation_manifest_raw_sha256="g" * 64,
        freeze_receipt_raw_sha256="b" * 63,
        checksums_raw_sha256="c" * 64,
    )
    escaped = FutureR8GenerationBinding(
        relative_root="outputs/../forbidden",
        generation_design_raw_sha256="a" * 64,
        generation_manifest_raw_sha256="b" * 64,
        freeze_receipt_raw_sha256="c" * 64,
        checksums_raw_sha256="d" * 64,
    )
    staging = replace(
        escaped,
        relative_root=f"{EXPECTED_R8_GENERATION_ROOT}.staging.attack",
    )
    for binding in (partial, malformed, escaped, staging):
        assert binding.is_exact is False
        with pytest.raises(FreshQualificationContractError, match="not exact"):
            binding.require_exact()


def test_exact_hash_mismatch_fails_on_synthetic_future_root(tmp_path: Path) -> None:
    generation, audit, final = _exact_future_bindings()
    generation_root = tmp_path / EXPECTED_R8_GENERATION_ROOT
    generation_root.mkdir(parents=True)
    (generation_root / "DESIGN_LOCK.json").write_bytes(b"synthetic design\n")
    with pytest.raises(FreshQualificationContractError, match="raw hash differs"):
        bind_future_inputs(
            project_root=tmp_path,
            design_preview_sha256="e" * 64,
            generation=generation,
            audit=audit,
            final_freeze=final,
        )


def test_checksum_duplicate_and_traversal_attacks_fail() -> None:
    duplicate = (f"{'a' * 64}  safe.txt\n" f"{'b' * 64}  safe.txt\n").encode("ascii")
    traversal = f"{'a' * 64}  ../escape.txt\n".encode("ascii")
    with pytest.raises(FreshQualificationContractError, match="invalid"):
        parse_checksum_bytes(duplicate)
    with pytest.raises(FreshQualificationContractError, match="unsafe"):
        parse_checksum_bytes(traversal)


def test_seal_detects_semantic_hash_attack() -> None:
    sealed = seal_payload({"status": "PASS", "value": 1}, "semantic_sha256")
    verify_sealed_payload(sealed, "semantic_sha256")
    attacked = dict(sealed)
    attacked["value"] = 2
    with pytest.raises(FreshQualificationContractError, match="differs"):
        verify_sealed_payload(attacked, "semantic_sha256")


def test_frozen_candidate_formulas_are_causal_under_future_perturbation() -> None:
    rows = 120
    champion = np.full(rows, 10.0)
    a = champion * np.exp(np.linspace(0.01, 0.08, rows))
    b = champion * np.exp(np.linspace(0.02, 0.09, rows))
    dates = pd.date_range("2025-01-01", periods=rows, freq="D")
    confidence = np.linspace(0.1, 0.9, rows)
    original = compute_frozen_candidates(
        champion_expected_pe=champion,
        constituent_a_expected_pe=a,
        constituent_b_expected_pe=b,
        group_codes=np.zeros(rows, dtype=np.int64),
        dates=dates,
        observable_state_confidence=confidence,
    )
    attacked_a = a.copy()
    attacked_b = b.copy()
    attacked_confidence = confidence.copy()
    attacked_a[70:] *= 100.0
    attacked_b[70:] *= 0.01
    attacked_confidence[70:] = 1.0 - attacked_confidence[70:]
    attacked = compute_frozen_candidates(
        champion_expected_pe=champion,
        constituent_a_expected_pe=attacked_a,
        constituent_b_expected_pe=attacked_b,
        group_codes=np.zeros(rows, dtype=np.int64),
        dates=dates,
        observable_state_confidence=attacked_confidence,
    )
    assert tuple(original) == CANDIDATE_IDS
    for model_id in CANDIDATE_IDS:
        assert np.array_equal(original[model_id].expected_pe[:70], attacked[model_id].expected_pe[:70])
        assert np.array_equal(original[model_id].alpha[:70], attacked[model_id].alpha[:70])


def test_standard_rows_use_actual_champion_and_fixed_identity_model_order() -> None:
    surface = _task_surface()
    first = build_task_prediction_rows(surface)
    second = build_task_prediction_rows(surface.copy(deep=True))
    pd.testing.assert_frame_equal(first, second, check_exact=True)
    assert len(first) == 1296 * 4
    assert first["model_id"].tolist()[:8] == [*MODEL_IDS, *MODEL_IDS]
    champion_rows = first["model_id"].eq(CHAMPION_ID)
    assert np.array_equal(
        first.loc[champion_rows, "expected_pe"].to_numpy(dtype=np.float64),
        surface["champion_expected_pe"].to_numpy(dtype=np.float64),
    )
    assert np.array_equal(
        first.loc[champion_rows, "applied_log_correction"].to_numpy(dtype=np.float64),
        np.zeros(1296),
    )
    assert first.loc[:, list(IDENTITY_COLUMNS)].drop_duplicates().shape[0] == 1296


def test_surface_schema_restricted_injection_duplicate_and_reorder_attacks_fail() -> None:
    surface = _task_surface()
    injected = surface.copy()
    injected["true_fair_pe"] = 10.0
    with pytest.raises(FreshQualificationContractError, match="restricted namespace"):
        build_task_prediction_rows(injected)
    reordered = surface.loc[:, list(reversed(TASK_SURFACE_COLUMNS))]
    with pytest.raises(FreshQualificationContractError, match="schema or column order"):
        build_task_prediction_rows(reordered)
    duplicate = surface.copy()
    duplicate.columns = [*TASK_SURFACE_COLUMNS[:-1], TASK_SURFACE_COLUMNS[-2]]
    with pytest.raises(FreshQualificationContractError, match="duplicated"):
        build_task_prediction_rows(duplicate)
    identity_reorder = surface.copy()
    identity_reorder.iloc[[0, 1]] = identity_reorder.iloc[[1, 0]].to_numpy()
    with pytest.raises(FreshQualificationContractError, match="gap or reorder"):
        build_task_prediction_rows(identity_reorder)


def test_output_duplicate_model_reorder_and_schema_attacks_fail() -> None:
    rows = build_task_prediction_rows(_task_surface())
    duplicate = rows.copy()
    duplicate.loc[5, list(IDENTITY_COLUMNS)] = duplicate.loc[
        1, list(IDENTITY_COLUMNS)
    ].to_numpy()
    with pytest.raises(FreshQualificationContractError, match="duplicated"):
        validate_task_prediction_rows(duplicate)
    reordered = rows.copy()
    reordered.iloc[[0, 1]] = reordered.iloc[[1, 0]].to_numpy()
    with pytest.raises(FreshQualificationContractError, match="model universe"):
        validate_task_prediction_rows(reordered)
    substituted = rows.copy()
    substituted.loc[0, "model_id"] = "unfrozen_substitute"
    with pytest.raises(FreshQualificationContractError, match="model universe"):
        validate_task_prediction_rows(substituted)
    injected = rows.copy()
    injected["score"] = 0.0
    with pytest.raises(FreshQualificationContractError, match="schema"):
        validate_task_prediction_rows(injected)


def test_constituent_diagnostics_are_exact_and_restricted_key_attack_fails() -> None:
    diagnostics = _fold_diagnostics()
    validate_task_fold_diagnostics(
        diagnostics,
        seed_alias=SEED_ALIASES[0],
        dgp_id=DGP_IDS[0],
    )
    attacked = [dict(row) for row in diagnostics]
    attacked[0]["score"] = 0.0
    with pytest.raises(FreshQualificationContractError, match="restricted namespace"):
        validate_task_fold_diagnostics(
            attacked,
            seed_alias=SEED_ALIASES[0],
            dgp_id=DGP_IDS[0],
        )


def test_default_launch_fails_before_any_path_or_worker_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    touched = {"path": 0, "read": 0, "worker": 0}

    def forbidden_path(*args: object, **kwargs: object) -> Path:
        touched["path"] += 1
        raise AssertionError("path access occurred before exact binding")

    def forbidden_read(*args: object, **kwargs: object) -> pd.DataFrame:
        touched["read"] += 1
        raise AssertionError("payload read occurred before exact binding")

    def forbidden_worker(*args: object, **kwargs: object) -> object:
        touched["worker"] += 1
        raise AssertionError("worker execution occurred before exact binding")

    import research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.runner as runner_module

    monkeypatch.setattr(Path, "resolve", forbidden_path)
    monkeypatch.setattr(pd, "read_csv", forbidden_read)
    monkeypatch.setattr(runner_module, "_run_parallel", forbidden_worker)
    with pytest.raises(FreshQualificationContractError, match="not exact"):
        run_prediction_only(
            project_root=Path("must_not_be_touched"),
            activation=PREDICTION_ACTIVATION_LITERAL,
        )
    assert touched == {"path": 0, "read": 0, "worker": 0}


def test_failed_staging_is_preserved_without_cleanup(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    staging = make_preserved_staging(outputs, "synthetic_destination")
    marker = staging / "partial.bin"
    marker.write_bytes(b"synthetic partial bytes")
    assert staging.is_dir()
    assert marker.read_bytes() == b"synthetic partial bytes"


def test_design_preview_predates_generation_and_has_source_hash_provenance() -> None:
    preview = design_preview_payload(_repo_root())
    assert preview["definitions_timing"] == {
        "definitions_frozen_before_R8_generation": True,
        "definitions_frozen_before_R5_post_generation_audit": True,
        "R8_generation_observed": False,
        "R5_post_generation_audit_observed": False,
        "actual_seed_ids_observed": False,
        "prediction_payload_observed": False,
        "assessment_payload_observed": False,
    }
    assert preview["model_ids_in_fixed_order"] == list(MODEL_IDS)
    assert preview["future_bindings"] == null_future_binding_payload()
    assert preview["final_execution_design_frozen"] is False
    assert preview["prediction_launch_allowed"] is False
    assert preview["upstream_source_provenance"]
    assert all(
        len(record["raw_sha256"]) == 64
        for record in preview["upstream_source_provenance"].values()
    )


def test_source_audit_is_clean_and_reads_only_exact_source_paths() -> None:
    audit = audit_source_boundary(_repo_root())
    assert audit["status"] == "PASS_CLEAN_PREGENERATION_SOURCE_BOUNDARY"
    assert audit["audited_files"] == list(SOURCE_RELATIVE_PATHS)
    assert audit["findings"] == []
    assert audit["old_v2_package_imported"] is False
    assert audit["directory_enumeration_present"] is False
    assert audit["failed_staging_deletion_present"] is False
    assert audit["static_access_ledger"] == {
        "output_directories_enumerated": 0,
        "output_payload_files_opened": 0,
        "restricted_payload_paths_resolved": 0,
        "restricted_payload_bytes_read": 0,
        "actual_model_fit_calls": 0,
        "actual_prediction_calls": 0,
        "assessment_calls": 0,
    }


def test_verification_evidence_rejects_any_actual_execution_claim() -> None:
    clean = VerificationEvidence(
        pytest_command=("python", "-m", "pytest", "synthetic_test.py"),
        pytest_returncode=0,
        pytest_summary="18 passed",
        ruff_command=("python", "-m", "ruff", "check", "exact.py"),
        ruff_returncode=0,
        ruff_summary="All checks passed!",
    )
    clean.require_clean()
    for field in (
        "repository_output_payload_reads",
        "restricted_payload_path_resolutions",
        "actual_model_fit_calls",
        "actual_prediction_calls",
        "assessment_calls",
    ):
        attacked = replace(clean, **{field: 1})
        with pytest.raises(FreshQualificationContractError, match="clean passing"):
            attacked.require_clean()
