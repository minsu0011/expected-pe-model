from __future__ import annotations

from dataclasses import asdict
import hashlib
import inspect
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.bounded_consensus_v1.contracts import DIRECTION_EPSILON
from research.model_zoo.observable_state_bce_dgp_tournament_v1.candidates import (
    compute_fixed_alpha_040,
    compute_tournament_candidates,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.contracts import (
    BCE_B_ID,
    BCE_D_ID,
    DGP_IDS,
    DGP_SOURCE_MODE,
    EXPECTED_COMMON_IDENTITIES,
    EXPECTED_FITTED_CHALLENGERS_PER_FOLD,
    EXPECTED_FOLD_BLOCKS,
    EXPECTED_STATE_MODEL_FITS,
    EXPECTED_TASK_COUNT,
    EXTREME_ABS_LOG_ERROR_THRESHOLD,
    FINAL_DESIGN_FROZEN,
    FIXED_040_ID,
    FIXED_DIRECTIONAL_ALPHA,
    FOLD_GEOMETRY,
    LEGACY_FORMAL_DGP_ALLOWED,
    PREDICTION_LAUNCH_ALLOWED,
    RANKING_RULE,
    RESOURCE_POLICY,
    SEED_ALIASES,
    TOURNAMENT_CANDIDATE_IDS,
    TOURNAMENT_GATE,
    TournamentContractError,
    canonical_json_bytes,
    design_preview_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.custody import (
    FUTURE_INDEPENDENT_AUDIT_PLACEHOLDER,
    FUTURE_PUBLIC_INPUT_PLACEHOLDER,
    FutureIndependentAuditBinding,
    FuturePublicInputBinding,
    PublicInputClosure,
    PublicTaskBinding,
    bind_independent_audit,
    bind_public_inputs,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.evaluator import (
    FutureEvaluationAuthorization,
    evaluate_tournament,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.lineage import (
    verify_static_lineage,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.prediction import (
    PreparedTask,
    fit_one_fold,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.runner import (
    FUTURE_FINAL_DESIGN_PLACEHOLDER,
    build_final_design_payload,
    build_execution_plan,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v1.source_audit import (
    audit_source_boundary,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_exact_candidate_universe_and_no_alpha_sweep() -> None:
    assert TOURNAMENT_CANDIDATE_IDS == (BCE_B_ID, BCE_D_ID, FIXED_040_ID)
    assert FIXED_DIRECTIONAL_ALPHA == 0.4
    assert "alpha" not in inspect.signature(compute_fixed_alpha_040).parameters
    preview = design_preview_payload()
    assert preview["tournament_candidates"] == list(TOURNAMENT_CANDIDATE_IDS)
    assert preview["fixed_alpha_candidate"]["sweep_allowed"] is False
    assert preview["constituent_scores_used_for_gate_or_rank"] is False
    assert preview["no_parameter_sweep"] is True
    assert EXTREME_ABS_LOG_ERROR_THRESHOLD == pytest.approx(np.log(1.10), abs=1e-15)
    assert preview["tail_definition"] == {
        "absolute_log_error_extreme_threshold": EXTREME_ABS_LOG_ERROR_THRESHOLD,
        "extreme_comparison": "greater_than_or_equal",
        "pooled_tail_quantile": 0.95,
    }


def test_fixed_alpha_formula_and_exact_disagreement_zero() -> None:
    base = np.array([10.0, 10.0, 10.0, 10.0])
    challenger_a = 10.0 * np.exp(np.array([0.2, -0.2, 0.2, DIRECTION_EPSILON / 2]))
    challenger_b = 10.0 * np.exp(np.array([0.4, -0.4, -0.1, 0.1]))
    result = compute_fixed_alpha_040(
        base_prediction=base,
        challenger_a_prediction=challenger_a,
        challenger_b_prediction=challenger_b,
    )
    expected_agreement = np.array([True, True, False, False])
    expected_raw = np.array([0.3, -0.3, 0.0, 0.0])
    expected_applied = np.array([0.12, -0.12, 0.0, 0.0])
    assert np.array_equal(result.directional_agreement, expected_agreement)
    assert np.allclose(result.raw_log_correction, expected_raw, rtol=0, atol=1e-15)
    assert np.array_equal(result.alpha, np.array([0.4, 0.4, 0.0, 0.0]))
    assert np.allclose(result.applied_log_correction, expected_applied, rtol=0, atol=1e-15)
    assert np.allclose(result.prediction[:2], np.exp(np.log(10.0) + expected_applied[:2]))
    assert np.array_equal(result.prediction[2:], base[2:])


def test_b_and_d_reuse_frozen_formulas_and_share_raw_consensus() -> None:
    rows = 24
    base = np.full(rows, 10.0)
    correction_a = np.linspace(0.01, 0.12, rows)
    correction_b = np.linspace(0.02, 0.13, rows)
    confidence = np.linspace(0.1, 0.9, rows)
    result = compute_tournament_candidates(
        base_prediction=base,
        challenger_a_prediction=base * np.exp(correction_a),
        challenger_b_prediction=base * np.exp(correction_b),
        group_codes=np.zeros(rows, dtype=np.int64),
        dates=pd.date_range("2024-01-01", periods=rows, freq="D"),
        observable_state_confidence=confidence,
    )
    assert tuple(result) == TOURNAMENT_CANDIDATE_IDS
    expected_raw = 0.5 * (correction_a + correction_b)
    for computation in result.values():
        assert np.allclose(computation.raw_log_correction, expected_raw, rtol=0, atol=1e-15)
    expected_budget_at_10 = np.sqrt(
        np.mean(0.5 * (correction_a[:10] ** 2 + correction_b[:10] ** 2))
    )
    expected_b_alpha_at_10 = min(1.0, expected_budget_at_10 / abs(expected_raw[10]))
    assert np.array_equal(result[BCE_B_ID].alpha[:10], np.zeros(10))
    assert result[BCE_B_ID].alpha[10] == pytest.approx(expected_b_alpha_at_10)
    assert np.allclose(result[BCE_D_ID].alpha, confidence, rtol=0, atol=0)
    assert np.array_equal(result[FIXED_040_ID].alpha, np.full(rows, FIXED_DIRECTIONAL_ALPHA))


def test_candidate_construction_is_invariant_to_future_surface_perturbation() -> None:
    rows = 90
    base = np.full(rows, 10.0)
    a = base * np.exp(np.linspace(0.01, 0.09, rows))
    b = base * np.exp(np.linspace(0.02, 0.10, rows))
    dates = pd.date_range("2025-01-01", periods=rows, freq="D")
    confidence = np.linspace(0.2, 0.8, rows)
    original = compute_tournament_candidates(
        base_prediction=base,
        challenger_a_prediction=a,
        challenger_b_prediction=b,
        group_codes=np.zeros(rows, dtype=np.int64),
        dates=dates,
        observable_state_confidence=confidence,
    )
    perturbed_a = a.copy()
    perturbed_b = b.copy()
    perturbed_a[60:] *= 25.0
    perturbed_b[60:] *= 0.05
    perturbed = compute_tournament_candidates(
        base_prediction=base,
        challenger_a_prediction=perturbed_a,
        challenger_b_prediction=perturbed_b,
        group_codes=np.zeros(rows, dtype=np.int64),
        dates=dates,
        observable_state_confidence=confidence,
    )
    for candidate_id in TOURNAMENT_CANDIDATE_IDS:
        assert np.array_equal(
            original[candidate_id].prediction[:60],
            perturbed[candidate_id].prediction[:60],
        )
        assert np.array_equal(original[candidate_id].alpha[:60], perturbed[candidate_id].alpha[:60])


def test_state_model_fold_uses_strict_prefix_target_only(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = FOLD_GEOMETRY.canonical_rows_per_task
    target = np.linspace(1.0, 2.0, rows)
    common = {
        "seed_alias": SEED_ALIASES[0],
        "dgp_id": DGP_IDS[0],
        "model_seed": 17,
        "dates": pd.date_range("2020-01-01", periods=rows, freq="D")
        .strftime("%Y-%m-%d")
        .to_numpy(),
        "symbols": np.full(rows, "DGP_ISSUER", dtype=object),
        "sample_weights": np.ones(rows),
        "reference_prediction": np.full(rows, 10.0),
        "lgbm_features": pd.DataFrame({"x": np.arange(rows, dtype=float)}),
        "histgb_features": pd.DataFrame({"x": np.arange(rows, dtype=float)}),
        "observable_state_confidence": np.full(rows, 0.5),
        "state_feature_sha256": "a" * 64,
    }

    def fake_fit(
        model_id: str,
        features: pd.DataFrame,
        all_targets: np.ndarray,
        weights: np.ndarray,
        train_positions: np.ndarray,
        test_positions: np.ndarray,
        *,
        fold_seed: int,
    ) -> tuple[np.ndarray, dict[str, object]]:
        assert int(train_positions.max()) < FOLD_GEOMETRY.first_test_position
        assert int(test_positions.min()) == FOLD_GEOMETRY.first_test_position
        value = float(np.mean(all_targets[train_positions]))
        return np.full(len(test_positions), np.exp(value)), {
            "model_id": model_id,
            "fold_seed": fold_seed,
        }

    import research.model_zoo.observable_state_bce_dgp_tournament_v1.prediction as module

    monkeypatch.setattr(module, "_fit_model", fake_fit)
    original = PreparedTask(target_log_observed_pe=target.copy(), **common)
    perturbed_target = target.copy()
    perturbed_target[FOLD_GEOMETRY.first_test_position :] += 1000.0
    perturbed = PreparedTask(target_log_observed_pe=perturbed_target, **common)
    first = fit_one_fold(original, FOLD_GEOMETRY.first_test_position).frame
    second = fit_one_fold(perturbed, FOLD_GEOMETRY.first_test_position).frame
    assert np.array_equal(
        first["challenger__lgbm_full_state"].to_numpy(),
        second["challenger__lgbm_full_state"].to_numpy(),
    )
    assert np.array_equal(
        first["challenger__histgb_full_state"].to_numpy(),
        second["challenger__histgb_full_state"].to_numpy(),
    )


def test_fold_identity_and_full_resource_geometry() -> None:
    assert len(FOLD_GEOMETRY.test_positions) == 62
    sizes = [
        FOLD_GEOMETRY.test_end_exclusive(start) - start for start in FOLD_GEOMETRY.test_positions
    ]
    assert sizes == [21] * 61 + [15]
    assert sum(sizes) == 1296
    assert EXPECTED_TASK_COUNT == 5 * 10
    assert EXPECTED_FOLD_BLOCKS == 5 * 10 * 62 == 3100
    assert EXPECTED_COMMON_IDENTITIES == 5 * 10 * 1296 == 64800
    assert EXPECTED_FITTED_CHALLENGERS_PER_FOLD == 2
    assert EXPECTED_STATE_MODEL_FITS == 6200
    assert RESOURCE_POLICY.cpu_ids == tuple(range(32))
    assert RESOURCE_POLICY.affinity_mask == 0xFFFFFFFF
    assert RESOURCE_POLICY.maximum_outer_workers == 32
    assert RESOURCE_POLICY.inner_threads == 1
    assert RESOURCE_POLICY.gpu_enabled is False
    assert RESOURCE_POLICY.environment["CUDA_VISIBLE_DEVICES"] == "-1"
    assert RESOURCE_POLICY.environment["NVIDIA_VISIBLE_DEVICES"] == "void"


def test_generic_execution_plan_has_all_3100_fold_blocks_without_path_access() -> None:
    tasks = tuple(
        PublicTaskBinding(
            seed_alias=seed_alias,
            model_seed=seed_index + 1,
            dgp_id=dgp_id,
            canonical_csv=Path(f"unused/{seed_alias}/{dgp_id}/canonical.csv"),
            overlay_csv=Path(f"unused/{seed_alias}/{dgp_id}/overlay.csv"),
            geometry_json=Path(f"unused/{seed_alias}/{dgp_id}/geometry.json"),
        )
        for seed_index, seed_alias in enumerate(SEED_ALIASES)
        for dgp_id in DGP_IDS
    )
    closure = PublicInputClosure(
        root=Path("unused"),
        freeze_receipt_raw_sha256="a" * 64,
        checksums_raw_sha256="b" * 64,
        tasks=tasks,
        score_start_inclusive=504,
        score_end_exclusive=1800,
    )
    plan = build_execution_plan(closure)
    assert len(plan) == EXPECTED_FOLD_BLOCKS
    assert len({(item.seed_alias, item.dgp_id) for item in plan}) == EXPECTED_TASK_COUNT
    counts = pd.Series([(item.seed_alias, item.dgp_id) for item in plan]).value_counts()
    assert counts.eq(FOLD_GEOMETRY.fold_count).all()


def test_preview_and_all_default_bindings_fail_closed(tmp_path: Path) -> None:
    assert FINAL_DESIGN_FROZEN is False
    assert PREDICTION_LAUNCH_ALLOWED is False
    assert FUTURE_PUBLIC_INPUT_PLACEHOLDER.is_exact is False
    assert FUTURE_INDEPENDENT_AUDIT_PLACEHOLDER.is_exact is False
    assert FUTURE_FINAL_DESIGN_PLACEHOLDER.is_exact is False
    with pytest.raises(TournamentContractError, match="not exact-bound"):
        bind_public_inputs(tmp_path)
    with pytest.raises(TournamentContractError, match="not exact-bound"):
        bind_independent_audit(tmp_path)
    with pytest.raises(TournamentContractError, match="not exact-bound"):
        build_final_design_payload(project_root=tmp_path)
    preview_text = json.dumps(design_preview_payload(), sort_keys=True)
    assert "2026082001" not in preview_text
    assert design_preview_payload()["public_input_binding"]["freeze_receipt_raw_sha256"] is None


def test_independent_audit_binding_is_exact_and_fail_closed(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    audit_root = (
        outputs
        / "model_zoo_dgp_state_tournament_v1_inputs_r4_clean_independent_audit_20260821"
    )
    audit_root.mkdir(parents=True)
    public = FuturePublicInputBinding(
        freeze_receipt_raw_sha256="a" * 64,
        checksums_raw_sha256="b" * 64,
    )
    access = {
        "score_computed": False,
        "truth_join_executed": False,
        "truth_payload_opened": False,
        "truth_values_read": False,
        "vault_payload_bytes_read": 0,
        "vault_payload_directory_enumerated": False,
        "vault_payload_files_opened": 0,
        "vault_payload_paths_resolved_or_stat_called": False,
    }
    access_raw = canonical_json_bytes(access) + b"\n"
    (audit_root / "ACCESS_LEDGER.json").write_bytes(access_raw)
    unsigned_audit = {
        "access_ledger": access,
        "checks": [{"check_id": "SYNTHETIC.EXACT", "status": "PASS"}],
        "custody": {
            "candidate_or_survivor_fits_executed": 0,
            "registry_or_champion_mutations": 0,
            "scores_computed": 0,
            "seeds_selected_or_reserved": 0,
            "survivor_selected": False,
            "truth_join_executed": False,
            "truth_payload_files_opened": 0,
            "truth_payload_opened": False,
            "truth_values_read": False,
        },
        "decision": {
            "fresh_or_heldout_authority": False,
            "overall": "GO_R4_PUBLIC_INPUT_BUNDLE_LAUNCH_AUTHORITATIVE_RESEARCH_ONLY",
            "promotion_authority": False,
            "public_bundle_use": (
                "GO_ONE_EXTERNALLY_PREDECLARED_SCORE_BLIND_PREDICTION_STAGE"
            ),
            "truth_or_score_authority": False,
        },
        "failed_checks": [],
        "pins": {
            "actual": {
                "public_checksums": public.checksums_raw_sha256,
                "public_freeze": public.freeze_receipt_raw_sha256,
            }
        },
        "public_bundle": {"relative_path": public.relative_root},
        "severity_counts": {"P0": 0, "P1": 0, "P2": 0},
    }
    audit_semantic = hashlib.sha256(canonical_json_bytes(unsigned_audit)).hexdigest()
    audit = dict(unsigned_audit)
    audit["self_seal"] = {"audit_semantic_sha256": audit_semantic}
    audit_raw = canonical_json_bytes(audit) + b"\n"
    (audit_root / "AUDIT.json").write_bytes(audit_raw)
    audit_raw_sha = hashlib.sha256(audit_raw).hexdigest()
    audit_sha_raw = f"{audit_raw_sha}  AUDIT.json\n".encode("ascii")
    (audit_root / "AUDIT.sha256").write_bytes(audit_sha_raw)
    script_raw = b"# clean independent audit source\n"
    (audit_root / "AUDIT_SCRIPT.py").write_bytes(script_raw)
    report_raw = b"# Independent audit\n"
    (audit_root / "REPORT.md").write_bytes(report_raw)
    seal = {
        "audit_raw_sha256": audit_raw_sha,
        "audit_semantic_sha256": audit_semantic,
        "audit_sha256_file_raw_sha256": hashlib.sha256(audit_sha_raw).hexdigest(),
        "public_checksums_raw_sha256": public.checksums_raw_sha256,
        "public_freeze_receipt_raw_sha256": public.freeze_receipt_raw_sha256,
        "score_computed": False,
        "status": "PASS_AUDIT_SEALED",
        "truth_payload_opened": False,
    }
    seal_raw = canonical_json_bytes(seal)
    (audit_root / "SEAL_RECEIPT.json").write_bytes(seal_raw)
    artifact_hashes = {
        "ACCESS_LEDGER.json": hashlib.sha256(access_raw).hexdigest(),
        "AUDIT.json": audit_raw_sha,
        "AUDIT.sha256": hashlib.sha256(audit_sha_raw).hexdigest(),
        "AUDIT_SCRIPT.py": hashlib.sha256(script_raw).hexdigest(),
        "REPORT.md": hashlib.sha256(report_raw).hexdigest(),
        "SEAL_RECEIPT.json": hashlib.sha256(seal_raw).hexdigest(),
    }
    checksums_raw = (
        "\n".join(f"{artifact_hashes[name]}  {name}" for name in sorted(artifact_hashes))
        + "\n"
    ).encode("ascii")
    (audit_root / "CHECKSUMS.sha256").write_bytes(checksums_raw)
    binding = FutureIndependentAuditBinding(
        relative_root=str(audit_root.relative_to(tmp_path)).replace("\\", "/"),
        audit_raw_sha256=artifact_hashes["AUDIT.json"],
        audit_semantic_sha256=audit_semantic,
        audit_sha256_file_raw_sha256=artifact_hashes["AUDIT.sha256"],
        seal_receipt_raw_sha256=artifact_hashes["SEAL_RECEIPT.json"],
        checksums_raw_sha256=hashlib.sha256(checksums_raw).hexdigest(),
    )
    closure = bind_independent_audit(
        tmp_path,
        public_binding=public,
        audit_binding=binding,
    )
    assert closure.status == "PASS_AUDIT_SEALED"
    assert closure.overall_verdict == audit["decision"]["overall"]
    assert closure.audit_semantic_sha256 == audit_semantic

    bad_public = FuturePublicInputBinding(
        freeze_receipt_raw_sha256="c" * 64,
        checksums_raw_sha256="b" * 64,
    )
    with pytest.raises(TournamentContractError, match="public hashes differ"):
        bind_independent_audit(
            tmp_path,
            public_binding=bad_public,
            audit_binding=binding,
        )


def test_static_lineage_is_opaque_and_legacy_formal_dgp_is_forbidden() -> None:
    assert DGP_SOURCE_MODE == "FROZEN_V3_RESEARCH_PUBLIC_REPLAY_BUNDLE_ONLY"
    assert LEGACY_FORMAL_DGP_ALLOWED is False
    lineage = verify_static_lineage(_repo_root())
    assert lineage["status"] == "PASS_STATIC_OPAQUE_LINEAGE"
    assert lineage["structured_state_prediction_or_audit_content_read"] is False
    assert lineage["score_artifact_opened"] is False
    assert lineage["final_validation_artifact_opened"] is False
    assert lineage["registry_artifact_opened"] is False
    assert lineage["dgp_input_seed_value_opened"] is False
    assert lineage["legacy_formal_dgp_opened"] is False


def _synthetic_full_tournament() -> tuple[pd.DataFrame, pd.DataFrame]:
    positions = np.arange(
        FOLD_GEOMETRY.first_test_position,
        FOLD_GEOMETRY.final_test_position + 1,
        dtype=np.int64,
    )
    sizes = np.array(
        [FOLD_GEOMETRY.test_end_exclusive(start) - start for start in FOLD_GEOMETRY.test_positions],
        dtype=np.int64,
    )
    fold_ids = np.repeat(
        [FOLD_GEOMETRY.fold_id(start) for start in FOLD_GEOMETRY.test_positions], sizes
    )
    test_starts = np.repeat(FOLD_GEOMETRY.test_positions, sizes)
    dates = pd.date_range("2021-01-01", periods=len(positions), freq="D").strftime("%Y-%m-%d")
    target_value = 10.0
    frames: list[pd.DataFrame] = []
    targets: list[pd.DataFrame] = []
    for seed_alias in SEED_ALIASES:
        for dgp_id in DGP_IDS:
            identity = {
                "seed_alias": seed_alias,
                "dgp_id": dgp_id,
                "date": dates,
                "session_position": positions,
            }
            frame = pd.DataFrame(identity)
            frame["fold_id"] = fold_ids
            frame["test_start_position"] = test_starts
            frame["train_end_position"] = test_starts - 1
            frame["incumbent__v04_expected_pe"] = target_value * np.exp(0.10)
            frame["challenger__lgbm_full_state"] = target_value * np.exp(0.07)
            frame["challenger__histgb_full_state"] = target_value * np.exp(0.06)
            frame["candidate__bce_b"] = target_value * np.exp(0.09)
            frame["candidate__bce_d"] = target_value * np.exp(0.08)
            frame["candidate__fixed_alpha_040"] = target_value * np.exp(0.095)
            frames.append(frame)
            target = pd.DataFrame(identity)
            target["synthetic_target"] = target_value
            targets.append(target)
    return pd.concat(frames, ignore_index=True), pd.concat(targets, ignore_index=True)


def test_detached_evaluator_gates_and_lexicographic_ranking_are_exact() -> None:
    predictions, target = _synthetic_full_tournament()
    authorization = FutureEvaluationAuthorization(
        prediction_manifest_raw_sha256="a" * 64,
        prediction_checksums_raw_sha256="b" * 64,
        evaluator_receipt_raw_sha256="c" * 64,
        evaluator_checksums_raw_sha256="d" * 64,
    )
    result = evaluate_tournament(
        predictions,
        target,
        target_column="synthetic_target",
        authorization=authorization,
    )
    assert len(result.pooled_metrics) == 3
    assert len(result.seed_dgp_metrics) == 3 * 50
    assert len(result.dgp_mean_metrics) == 3 * 10
    assert result.decisions["gate_pass"].all()
    assert result.decisions["seed_dgp_wins"].eq(50).all()
    assert result.decisions["dgp_mean_wins"].eq(10).all()
    assert result.decisions["worst_dgp_mean_harm"].eq(0.0).all()
    assert result.decisions["worst_seed_dgp_harm"].eq(0.0).all()
    assert result.ranking["candidate_id"].tolist() == [BCE_D_ID, BCE_B_ID, FIXED_040_ID]
    assert result.ranking["ranking_rule"].eq("|".join(RANKING_RULE)).all()
    assert result.constituent_diagnostics["diagnostic_only"].all()
    assert not result.constituent_diagnostics["gate_used"].any()
    assert not result.constituent_diagnostics["rank_used"].any()
    assert asdict(TOURNAMENT_GATE) == {
        "pooled_mae_relative_gain_min": 0.005,
        "pooled_rmse_relative_gain_min": 0.0,
        "seed_dgp_wins_min": 30,
        "seed_dgp_total": 50,
        "dgp_mean_wins_min": 6,
        "dgp_total": 10,
        "worst_dgp_mean_harm_max": 0.03,
        "worst_seed_dgp_harm_max": 0.05,
        "pooled_p95_non_worse": True,
        "pooled_extreme_frequency_non_worse": True,
    }


def test_evaluator_default_and_source_boundaries_are_fail_closed() -> None:
    with pytest.raises(TournamentContractError, match="custody hashes"):
        evaluate_tournament(pd.DataFrame(), pd.DataFrame(), target_column="unused")
    audit = audit_source_boundary()
    assert audit["status"] == "PASS_AUDIT_READY_SOURCE_WAITING_EXACT_PUBLIC_BINDING"
    assert audit["outcome_artifacts_opened"] is False
    assert audit["dgp_input_seed_values_opened"] is False
    assert audit["final_design_emitted"] is False
    assert audit["tournament_executed"] is False
    assert audit["findings"] == []
