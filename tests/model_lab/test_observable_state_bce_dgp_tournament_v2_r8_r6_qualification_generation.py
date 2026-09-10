from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation import (
    binding_freeze,
    immediate_issuance,
    signer_supervisor,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.contracts import (
    DGPS,
    HELDOUT_SEEDS,
    QUALIFICATION_SEEDS,
    SIGNER_BINDING_RELATIVE,
    SIGNER_BINDING_ROOT_RELATIVE,
    SIGNER_TELEMETRY_RELATIVE,
    R8QualificationGenerationError,
    child_capability_id,
    expected_child_capability_ids,
    expected_tasks,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.paths import (
    plan_paths,
    validate_initial_plan,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.scheduler import (
    admit_scheduler,
    canonical_task_specs,
    run_deterministic_bounded,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_qualification_generation.supervision import (
    BINDING_SCHEMA,
    LifecycleState,
    SignerTelemetry,
    TELEMETRY_SCHEMA,
    static_supervision_contract,
    validate_binding,
    validate_static_audit_go,
    validate_supplemental_audit_go,
    validate_telemetry,
    validate_transition,
)


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _telemetry(now: datetime) -> SignerTelemetry:
    return SignerTelemetry(
        schema_version=TELEMETRY_SCHEMA,
        state="READY",
        supervisor_pid=100,
        signer_pid=101,
        started_at_utc=_utc(now - timedelta(seconds=10)),
        last_heartbeat_utc=_utc(now - timedelta(seconds=1)),
        observed_at_utc=_utc(now - timedelta(milliseconds=500)),
        heartbeat_sequence=10,
        exit_status=None,
        error_code=None,
        request_count=0,
        signature_count=0,
        private_key_persisted=False,
        detached_process=False,
        parent_supervised=True,
        foreground_supervised=True,
    )


def _binding(now: datetime) -> dict[str, object]:
    public_key = bytes.fromhex("11" * 32)
    key_id = hashlib.sha256(public_key).hexdigest()
    digest = "a" * 64
    return {
        "schema_version": BINDING_SCHEMA,
        "binding_root_relative": SIGNER_BINDING_ROOT_RELATIVE,
        "binding_relative": SIGNER_BINDING_RELATIVE,
        "telemetry_relative": SIGNER_TELEMETRY_RELATIVE,
        "design_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
            "r8_qualification_generation_static_design_r6_20260822"
        ),
        "design_checksums_raw_sha256": digest,
        "external_anchor_raw_sha256": "9" * 64,
        "static_audit_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
            "independent_static_pre_generation_audit_r6_20260822"
        ),
        "static_audit_json_raw_sha256": "b" * 64,
        "static_audit_seal_raw_sha256": "c" * 64,
        "service_source_relative": (
            "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
            "r8_r6_qualification_generation/signer_service.py"
        ),
        "service_source_raw_sha256": "d" * 64,
        "service_executable_raw_sha256": "e" * 64,
        "public_key_hex": public_key.hex(),
        "key_id": key_id,
        "readiness_raw_sha256": "f" * 64,
        "endpoint": rf"\\.\pipe\expected_pe_r8_r6_{key_id[:40]}",
        "launch_nonce_sha256": "1" * 64,
        "signer_pid": 101,
        "supervisor_pid": 100,
        "launched_at_utc": _utc(now),
        "expires_at_utc": _utc(now + timedelta(seconds=900)),
        "heartbeat_interval_seconds": 1,
        "maximum_heartbeat_age_seconds": 5,
        "maximum_lifetime_seconds": 900,
        "private_key_persisted": False,
        "foreground_supervised": True,
        "parent_supervised": True,
        "detached_process": False,
        "maximum_signature_count": 1,
        "maximum_generation_count": 1,
    }


def test_exact_geometry_is_qualification_only() -> None:
    assert QUALIFICATION_SEEDS == (7573, 7577, 7583, 7589, 7591)
    assert HELDOUT_SEEDS == (7603, 7607, 7621, 7639, 7643)
    assert DGPS == tuple("ABCDEFGHIJ")
    assert len(expected_tasks()) == 100
    assert len(expected_child_capability_ids()) == 202
    assert all(seed not in HELDOUT_SEEDS for seed, _dgp, _pass in expected_tasks())


def test_capability_identity_rejects_heldout() -> None:
    with pytest.raises(R8QualificationGenerationError):
        child_capability_id(
            "PROTECTED_GENERATE", seed=HELDOUT_SEEDS[0], dgp="A", replay_pass=1
        )


def test_r6_path_plan_is_new_and_four_way_distinct(tmp_path: Path) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    plan = plan_paths("20260822T120000", outputs_root=outputs)
    validate_initial_plan(plan)
    assert len({path.name.casefold() for path in plan.four_roots}) == 4
    assert "r8_r6" in plan.public_final.name
    assert "r8_r6" in plan.vault_final.name
    assert all(path.parent == outputs.resolve() for path in (*plan.four_roots, plan.journal))


@pytest.mark.parametrize(
    "run_id", ["20260822", "19991231T235959", "20260230T120000", "../escape"]
)
def test_path_plan_rejects_noncanonical_run_id(tmp_path: Path, run_id: str) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    with pytest.raises(R8QualificationGenerationError):
        plan_paths(run_id, outputs_root=outputs)


def test_scheduler_admits_7950x3d_geometry_at_16x1() -> None:
    admission = admit_scheduler(
        logical_cpu_count=32,
        total_physical_gib=95.5,
        available_physical_gib=80.0,
        benchmark_worker_cap=16,
    )
    assert admission.admitted_workers == 16
    assert admission.inner_threads == 1
    assert len({cpu for part in admission.partitions for cpu in part.cpu_ids}) == 32


def test_scheduler_preserves_canonical_result_order() -> None:
    admission = admit_scheduler(
        logical_cpu_count=32,
        total_physical_gib=95.5,
        available_physical_gib=80.0,
        benchmark_worker_cap=16,
    )
    tasks = canonical_task_specs()[:32]
    result = run_deterministic_bounded(
        admission,
        lambda task, partition: (task.ordinal, partition.worker_index),
        tasks=tasks,
    )
    assert [row[0] for row in result] == list(range(32))


def test_static_contract_contains_no_phase1_authority() -> None:
    contract = static_supervision_contract()
    assert contract["phase_1"] == {
        "signer_launch": False,
        "key_generation": False,
        "authority_issuance": False,
        "qualification_generation": False,
        "truth_access": False,
        "heldout_access": False,
    }
    assert contract["process_model"]["foreground_supervised"] is True
    assert contract["process_model"]["parent_supervised"] is True
    assert contract["process_model"]["detached_process"] is False


def test_lifecycle_allows_only_two_phase_order() -> None:
    chain = (
        LifecycleState.STATIC_FROZEN,
        LifecycleState.STATIC_AUDIT_GO,
        LifecycleState.SIGNER_FOREGROUND_READY,
        LifecycleState.BINDING_FROZEN,
        LifecycleState.SUPPLEMENTAL_AUDIT_GO,
        LifecycleState.ALIVE_RECHECK_GO,
        LifecycleState.AUTHORITY_ISSUED,
        LifecycleState.GENERATION_RUNNING,
        LifecycleState.GENERATION_COMMITTED,
    )
    for previous, current in zip(chain, chain[1:]):
        validate_transition(previous, current)
    with pytest.raises(R8QualificationGenerationError):
        validate_transition(
            LifecycleState.STATIC_FROZEN, LifecycleState.SIGNER_FOREGROUND_READY
        )


def test_live_unused_telemetry_passes() -> None:
    now = datetime(2026, 8, 22, 12, tzinfo=timezone.utc)
    result = validate_telemetry(_telemetry(now).as_mapping(), now=now, require_unused=True)
    assert result.signer_pid == 101
    assert result.request_count == result.signature_count == 0


@pytest.mark.parametrize(
    "mutation",
    [
        {"last_heartbeat_utc": "2026-08-22T11:59:00+00:00"},
        {"request_count": 1},
        {"private_key_persisted": True},
        {"detached_process": True},
        {"exit_status": 0},
    ],
)
def test_telemetry_fails_closed(mutation: dict[str, object]) -> None:
    now = datetime(2026, 8, 22, 12, tzinfo=timezone.utc)
    telemetry = replace(_telemetry(now), **mutation)
    with pytest.raises(R8QualificationGenerationError):
        validate_telemetry(telemetry.as_mapping(), now=now, require_unused=True)


def test_binding_validation_is_late_bound_public_only() -> None:
    now = datetime(2026, 8, 22, 12, tzinfo=timezone.utc)
    payload = _binding(now)
    result = validate_binding(payload, design_checksums_raw_sha256="a" * 64)
    assert result["private_key_persisted"] is False
    assert not any("seed" in key or "activation_token" in key for key in result)


def test_binding_rejects_key_substitution() -> None:
    now = datetime(2026, 8, 22, 12, tzinfo=timezone.utc)
    payload = _binding(now)
    payload["key_id"] = "2" * 64
    with pytest.raises(R8QualificationGenerationError):
        validate_binding(payload, design_checksums_raw_sha256="a" * 64)


def test_static_audit_can_authorize_only_phase2_launch() -> None:
    payload = {
        "schema_version": "expected_pe.r8.r6.independent_static_audit.v1",
        "verdict": "GO",
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "audit_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
            "independent_static_pre_generation_audit_r6_20260822"
        ),
        "design_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
            "r8_qualification_generation_static_design_r6_20260822"
        ),
        "design_checksums_raw_sha256": "a" * 64,
        "external_anchor_raw_sha256": "9" * 64,
        "signer_launch_authorized": True,
        "qualification_generation_authorized": False,
        "heldout_generation_authorized": False,
        "truth_access_count": 0,
        "generation_count": 0,
        "signature_count": 0,
    }
    validate_static_audit_go(payload, design_checksums_raw_sha256="a" * 64)
    payload["qualification_generation_authorized"] = True
    with pytest.raises(R8QualificationGenerationError):
        validate_static_audit_go(payload, design_checksums_raw_sha256="a" * 64)


def test_supplemental_audit_is_binding_specific() -> None:
    payload = {
        "schema_version": (
            "expected_pe.r8.r6.independent_signer_binding_supplemental_audit.v1"
        ),
        "verdict": "GO",
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "audit_root_relative": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
            "independent_signer_binding_supplemental_audit_r6_20260822"
        ),
        "design_checksums_raw_sha256": "a" * 64,
        "binding_raw_sha256": "b" * 64,
        "alive_recheck_authorized": True,
        "qualification_authority_issuance_authorized": True,
        "heldout_generation_authorized": False,
        "model_fit_prediction_score_authorized": False,
        "truth_access_count": 0,
        "generation_count": 0,
        "request_count": 0,
        "signature_count": 0,
    }
    validate_supplemental_audit_go(
        payload,
        design_checksums_raw_sha256="a" * 64,
        binding_raw_sha256="b" * 64,
    )


def test_phase2_sources_are_static_and_not_invoked() -> None:
    supervisor_source = Path(signer_supervisor.__file__).read_text(encoding="utf-8")
    freezer_source = Path(binding_freeze.__file__).read_text(encoding="utf-8")
    issuance_source = Path(immediate_issuance.__file__).read_text(encoding="utf-8")
    assert "secrets.token_bytes(32)" in supervisor_source
    assert "child.stdin.write(seed)" in supervisor_source
    assert "_zeroize(seed)" in supervisor_source
    assert "child.wait" in supervisor_source
    assert "Start-Process" not in supervisor_source
    assert "subprocess.Popen" in supervisor_source
    assert "freeze_live_binding" in freezer_source
    assert issuance_source.index("    _alive_recheck(binding=") < issuance_source.index(
        "activation_token = secrets.token_hex(32)"
    )
    assert "authority_persisted" in issuance_source
