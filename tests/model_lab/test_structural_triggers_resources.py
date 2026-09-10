from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from pe_regime_v04.model_lab.structural.contracts import (
    STRUCTURAL_DESIGN_SHA256,
    StructuralContractError,
    seal_payload,
    verify_payload_seal,
    verify_structural_design,
)
from pe_regime_v04.model_lab.structural.dispatcher import StructuralDispatcher
from pe_regime_v04.model_lab.structural.authorization import (
    EXPECTED_PAIR,
    StructuralExecutionAuthorization,
    _verify_snapshot,
)
from pe_regime_v04.model_lab.structural.authorization_v6 import (
    load_structural_execution_authorization_v6,
)
from pe_regime_v04.model_lab.structural.resources import (
    THREAD_ENVIRONMENT,
    apply_native_thread_environment,
    require_worker_hash_parity,
    resolve_process_backend_policy,
)
from pe_regime_v04.model_lab.structural.triggers import (
    FINAL_AUDIT_MANIFEST_FILE_SHA256,
    FINAL_AUDIT_REPORT_FILE_SHA256,
    FINAL_TERMINAL_FILE_SHA256,
    FINAL_TRIGGER_INPUT_FILE_SHA256,
    VerifiedWave1TerminalEvidence,
    load_authorized_final_wave1_evidence,
    resolve_structural_triggers,
)


ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "outputs/model_zoo_structural_wave_design_20260819/DESIGN.json"
TERMINAL = ROOT / "outputs/model_zoo_wave1_screen_20260819/TERMINAL_MANIFEST.json"
AUDIT_DIR = ROOT / "outputs/model_zoo_wave1_terminal_audit_20260819"
SCREEN_DIR = ROOT / "outputs/model_zoo_structural_wave_screen_20260819"
V6_REVOKED_AUTHORITY_POLICY_SHA256 = (
    "63e82420c08249261f3c9d635b7f74d35f382c59ec561cdb0750aecd84a9baea"
)


def test_final_trigger_authority_binds_exact_four_files_and_resolves_five_candidates() -> None:
    assert (
        verify_structural_design(DESIGN)["design_id"] == "model_zoo_structural_wave_design_20260819"
    )
    evidence = load_authorized_final_wave1_evidence(
        terminal_path=TERMINAL,
        audit_manifest_path=AUDIT_DIR / "AUDIT_MANIFEST.json",
        audit_report_path=AUDIT_DIR / "REPORT.json",
        trigger_inputs_path=AUDIT_DIR / "STRUCTURAL_TRIGGER_INPUTS.json",
    )
    assert dict(evidence.bound_artifact_sha256s) == {
        "wave1_terminal_manifest": FINAL_TERMINAL_FILE_SHA256,
        "independent_audit_manifest": FINAL_AUDIT_MANIFEST_FILE_SHA256,
        "independent_audit_report": FINAL_AUDIT_REPORT_FILE_SHA256,
        "structural_trigger_inputs": FINAL_TRIGGER_INPUT_FILE_SHA256,
    }
    resolution = resolve_structural_triggers(evidence)
    assert dict(resolution.triggers) == {
        "T_A_TRACK_GAP": True,
        "T_DIRECT_PLATEAU_OR_TAIL": True,
        "T_COMPLEMENTARITY": True,
        "T_STABLE_BIAS": False,
        "T_SERIAL_RESIDUAL": True,
    }
    assert resolution.enabled_candidates == (
        "decomp_block_ridge_ar1_lag1",
        "decomp_block_ridge_ar1_current",
        "residual_ar1_nested_oof",
        "stack_geometric_equal_pair",
        "stack_simplex_pair_frozen",
    )
    assert resolution.disabled_candidates == ("residual_huber_nested_oof",)
    assert resolution.selected_pair == ("xgboost_cpu_common", "spline_ridge_common")
    assert resolution.selected_residual_base_model_id == "v04_expected_pe"


def test_final_trigger_authority_rejects_any_file_byte_tamper(tmp_path) -> None:
    tampered = tmp_path / "STRUCTURAL_TRIGGER_INPUTS.json"
    tampered.write_bytes((AUDIT_DIR / "STRUCTURAL_TRIGGER_INPUTS.json").read_bytes() + b" ")
    with pytest.raises(StructuralContractError, match="file SHA-256"):
        load_authorized_final_wave1_evidence(
            terminal_path=TERMINAL,
            audit_manifest_path=AUDIT_DIR / "AUDIT_MANIFEST.json",
            audit_report_path=AUDIT_DIR / "REPORT.json",
            trigger_inputs_path=tampered,
        )
    with pytest.raises(StructuralContractError, match="only be created"):
        VerifiedWave1TerminalEvidence(
            token=object(),
            inputs=None,  # type: ignore[arg-type]
            terminal_file_sha256="0" * 64,
            terminal_manifest_sha256="0" * 64,
            audit_file_sha256="0" * 64,
            audit_manifest_sha256="0" * 64,
            trigger_inputs_sha256="0" * 64,
            bound_artifact_sha256s=(),
        )


def test_sealed_trigger_decision_is_score_free_and_exact() -> None:
    decision_path = SCREEN_DIR / "TRIGGER_DECISION.json"
    payload = json.loads(decision_path.read_text(encoding="utf-8"))
    verify_payload_seal(payload)
    assert payload["structural_design"]["sha256"] == STRUCTURAL_DESIGN_SHA256
    assert payload["enabled_candidate_count"] == 5
    assert payload["disabled_candidates"] == ["residual_huber_nested_oof"]
    assert payload["attestations"] == {
        "candidate_predictions_generated": False,
        "candidate_scores_computed": False,
        "candidate_models_run": False,
        "fresh_seed_selected_or_reserved": False,
        "heldout_opened": False,
        "registry_modified": False,
        "phase1_wave1_or_dgp_source_modified": False,
        "oracle_pair_used_as_model_feature_or_weight_target": False,
    }
    names = {path.name.casefold() for path in SCREEN_DIR.rglob("*") if path.is_file()}
    forbidden = {
        name
        for name in names
        if ("prediction" in name or "score" in name or "seed_reservation" in name)
        and "no_score" not in name
    }
    assert forbidden == set()


def test_process_backend_resolves_32_workers_without_benchmark_or_gpu() -> None:
    policy = resolve_process_backend_policy(
        logical_cpu_count=32,
        available_physical_bytes=96 * 1024**3,
    )
    assert policy.backend == "process"
    assert policy.start_method == "spawn"
    assert policy.outer_workers == 32
    assert policy.estimator_inner_threads == 1
    assert policy.blas_openmp_threads == 1
    assert policy.gpu_enabled is False
    assert policy.benchmark_performed is False
    child_environment = apply_native_thread_environment({"PATH": "fixture"})
    assert child_environment["PATH"] == "fixture"
    assert all(child_environment[key] == value for key, value in THREAD_ENVIRONMENT.items())
    hashes = ("a" * 64, "b" * 64)
    require_worker_hash_parity(hashes, hashes, reference_worker_count=8, candidate_worker_count=32)
    with pytest.raises(StructuralContractError, match="parity failed"):
        require_worker_hash_parity(
            hashes,
            ("a" * 64, "c" * 64),
            reference_worker_count=8,
            candidate_worker_count=32,
        )


def test_execution_authorization_is_factory_only_exact_and_spent_fail_closed() -> None:
    with pytest.raises(StructuralContractError, match="factory-only"):
        StructuralExecutionAuthorization()  # type: ignore[call-arg]
    authorization = load_structural_execution_authorization_v6(
        ROOT,
        external_policy_sha256=V6_REVOKED_AUTHORITY_POLICY_SHA256,
        scope="SYNTHETIC_NO_SCORE",
    )
    authorization.verify()
    assert authorization.enabled_candidates == (
        "decomp_block_ridge_ar1_lag1",
        "decomp_block_ridge_ar1_current",
        "residual_ar1_nested_oof",
        "stack_geometric_equal_pair",
        "stack_simplex_pair_frozen",
    )
    assert authorization.residual_base.model_id == "v04_expected_pe"
    assert tuple(item.model_id for item in authorization.pair) == EXPECTED_PAIR
    assert authorization.pair[0].config_sha256 == (
        "9fc0dbf42109c7545ab8d6db2b8b83d6a7a015f1e74ee26cbe6f7f2764c622a6"
    )
    assert authorization.pair[1].config_sha256 == (
        "f441aeb7bbe376fe1c16942ad6075d58eb4e263fdb2cacf538d8db2ac49c3c0e"
    )
    assert authorization.base_binding_lock_sha256 == (
        "b60ca510b4cad411c29dded212df934e327b948c24f0a932060e1bdff26a81a4"
    )
    assert authorization.execution_snapshot_sha256 == (
        "b1996943814339ca3b9b9aa4b1d92c13bfe569783e9a174b9440bff54705dec2"
    )
    assert authorization.audit_activation_sha256 == (
        "b443eb4f6a490f0807ef88f5118a5be10d0fda811596747df176b221ee7c6a55"
    )
    assert authorization.spent_execution_authorized is False
    with pytest.raises(StructuralContractError, match="blocked pending independent audit GO"):
        load_structural_execution_authorization_v6(
            ROOT,
            external_policy_sha256=V6_REVOKED_AUTHORITY_POLICY_SHA256,
            scope="FORMAL_SPENT",
        )


def test_revoked_v6_authority_rejects_caller_resealed_policy_without_external_pin() -> None:
    with pytest.raises(StructuralContractError, match="external audit pin"):
        load_structural_execution_authorization_v6(
            ROOT,
            external_policy_sha256="0" * 64,
        )


def test_authorization_and_dispatcher_reject_capability_or_disabled_candidate_tamper() -> None:
    authorization = load_structural_execution_authorization_v6(
        ROOT,
        external_policy_sha256=V6_REVOKED_AUTHORITY_POLICY_SHA256,
        scope="SYNTHETIC_NO_SCORE",
    )
    with pytest.raises(StructuralContractError, match="factory-only"):
        StructuralDispatcher()  # type: ignore[call-arg]
    dispatcher = StructuralDispatcher.from_authorization(authorization)
    assert dispatcher.candidate_ids == authorization.enabled_candidates
    assert (
        dispatcher.decomposition_binding(
            candidate_id="decomp_block_ridge_ar1_lag1", fold_sha256="a" * 64
        ).track
        == "A"
    )
    assert (
        dispatcher.decomposition_binding(
            candidate_id="decomp_block_ridge_ar1_current", fold_sha256="b" * 64
        ).track
        == "C"
    )
    with pytest.raises(StructuralContractError, match="disabled Huber"):
        dispatcher.fit_huber()
    tampered = copy.deepcopy(authorization)
    object.__setattr__(tampered, "enabled_candidates", (*authorization.enabled_candidates, "x"))
    with pytest.raises(StructuralContractError, match="authorization content"):
        tampered.verify()


def test_data_bound_audit_and_spawn_benchmark_evidence_are_complete() -> None:
    track_a = json.loads((SCREEN_DIR / "TRACK_A_DATA_BOUND_AUDIT.json").read_text())
    verify_payload_seal(track_a)
    assert track_a["surface_count"] == 5
    assert track_a["all_5_surfaces_all_6_audits_pass"] is True
    assert track_a["combined_group_boundary_isolation"] is True
    assert all(row["all_six_pass"] for row in track_a["surfaces"])
    assert all(len(row["six_audits"]) == 6 for row in track_a["surfaces"])

    benchmark = json.loads((SCREEN_DIR / "NO_SCORE_BACKEND_BENCHMARK.json").read_text())
    verify_payload_seal(benchmark)
    assert benchmark["worker_grid"] == [8, 16, 24, 32]
    assert benchmark["selected_worker_count"] in benchmark["worker_grid"]
    assert benchmark["parity"]["all_8_16_24_32_repeats_exact"] is True
    assert benchmark["warning_failure_ledger"] == {"warnings": [], "failures": []}
    assert all(record["all_resource_guards_pass"] for record in benchmark["records"])


def test_v3_execution_snapshot_is_narrow_and_rejects_dependency_drift() -> None:
    snapshot = json.loads((SCREEN_DIR / "EXECUTION_SNAPSHOT_V3.json").read_text())
    verify_payload_seal(snapshot)
    paths = {row["path"] for row in snapshot["source_inventory"]}
    assert snapshot["dependency_scope"] == ("TRANSITIVE_STRUCTURAL_V04_PHASE1_WAVE1_RUNTIME_ONLY")
    assert not any("dgp_suite" in path for path in paths)
    assert not any(path.startswith("tests/") for path in paths)
    assert not any(path.startswith("scripts/") for path in paths)
    assert "src/pe_regime_v04/model_lab/structural/replay.py" in paths
    tampered = copy.deepcopy(snapshot)
    target = next(
        row
        for row in tampered["source_inventory"]
        if row["path"] == "src/pe_regime_v04/model_lab/structural/replay.py"
    )
    target["sha256"] = "0" * 64
    tampered = seal_payload(tampered)
    with pytest.raises(StructuralContractError, match="snapshotted source changed"):
        _verify_snapshot(tampered, ROOT)
