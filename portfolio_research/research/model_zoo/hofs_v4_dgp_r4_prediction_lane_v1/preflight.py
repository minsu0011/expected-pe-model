"""Cross-bound integration preflight builder with no model execution surface."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import platform
import sys
from typing import Any, Mapping

from .contracts import (
    BLOCKING_FINDINGS,
    EXACT_V4_RESOURCE_POLICY,
    GEOMETRY,
    NO_RUN_FLAGS,
    PINNED_PYTHON_EXECUTABLE,
    PINNED_PYTHON_EXECUTABLE_SHA256,
    PINNED_PYTHON_VERSION,
    PUBLIC_INPUT_CHECKSUMS_RAW_SHA256,
    PUBLIC_INPUT_FREEZE_RAW_SHA256,
    PUBLIC_INPUT_ROOT,
    REQUESTED_RESOURCE_POLICY,
    SCHEMA_VERSION,
    STATUS,
    V4_AUDIT_CHECKSUMS_RAW_SHA256,
    V4_AUDIT_RAW_SHA256,
    V4_AUDIT_ROOT,
    V4_AUDIT_SEAL_RAW_SHA256,
    V4_AUDIT_SEAL_SEMANTIC_SHA256,
    V4_AUDIT_SEMANTIC_SHA256,
    V4_AUDIT_VERDICT,
    V4_DESIGN_CHECKSUMS_RAW_SHA256,
    V4_DESIGN_CONTRACT_SHA256,
    V4_DESIGN_LOCK_RAW_SHA256,
    V4_DESIGN_ROOT,
    V4_RUNTIME_SOURCE_SHA256,
    V4_SOURCE_CLOSURE_RAW_SHA256,
    V4_SOURCE_CLOSURE_SEMANTIC_SHA256,
    IntegrationContractError,
    canonical_json_bytes,
    design_payload,
    sealed_payload,
    semantic_sha256,
)
from .custody import (
    InputClosureResult,
    build_public_input_closure,
    load_json_object,
    sha256_file,
    verify_self_seal,
)
from .source_audit import build_source_closure


V4_DESIGN_LOCK_SEMANTIC_SHA256 = (
    "8b980332bd6ffd46b3a453b0d7e72675afdd98055ba04d929956617d99cb82ec"
)


@dataclass(frozen=True)
class DraftPreflightArtifacts:
    input_closure: dict[str, Any]
    input_closure_bytes: bytes
    decision_identities_bytes: bytes
    fold_plan_bytes: bytes
    source_closure: dict[str, Any]
    source_closure_bytes: bytes
    design: dict[str, Any]
    design_bytes: bytes
    preflight: dict[str, Any]
    preflight_bytes: bytes

    def __post_init__(self) -> None:
        mappings = (
            self.input_closure,
            self.source_closure,
            self.design,
            self.preflight,
        )
        byte_values = (
            self.input_closure_bytes,
            self.decision_identities_bytes,
            self.fold_plan_bytes,
            self.source_closure_bytes,
            self.design_bytes,
            self.preflight_bytes,
        )
        if any(type(value) is not dict for value in mappings):
            raise IntegrationContractError("draft artifact payload type differs")
        if any(type(value) is not bytes or not value for value in byte_values):
            raise IntegrationContractError("draft artifact bytes are absent")


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(payload) + b"\n"


def _verify_pinned_runtime() -> dict[str, Any]:
    executable = Path(sys.executable).resolve(strict=True)
    expected = Path(PINNED_PYTHON_EXECUTABLE).resolve(strict=True)
    if executable != expected:
        raise IntegrationContractError("preflight did not use the exact pinned Python")
    if platform.python_version() != PINNED_PYTHON_VERSION:
        raise IntegrationContractError("pinned Python version differs")
    executable_sha256 = sha256_file(executable)
    if executable_sha256 != PINNED_PYTHON_EXECUTABLE_SHA256:
        raise IntegrationContractError("pinned Python executable hash differs")
    if (os.cpu_count() or 0) < 32:
        raise IntegrationContractError("host cannot expose requested CPU0-31 topology")
    return {
        "python_version": platform.python_version(),
        "python_executable": executable.as_posix(),
        "python_executable_raw_sha256": executable_sha256,
        "logical_cpu_count": os.cpu_count(),
        "cpu0_through_31_available": True,
        "model_runtime_entered": False,
    }


def _verify_v4_binding(project_root: Path) -> dict[str, Any]:
    design_root = project_root / V4_DESIGN_ROOT
    audit_root = project_root / V4_AUDIT_ROOT
    files = {
        "design_checksums": (
            design_root / "CHECKSUMS.sha256",
            V4_DESIGN_CHECKSUMS_RAW_SHA256,
        ),
        "design_lock": (design_root / "DESIGN_LOCK.json", V4_DESIGN_LOCK_RAW_SHA256),
        "source_closure": (
            design_root / "SOURCE_CLOSURE.json",
            V4_SOURCE_CLOSURE_RAW_SHA256,
        ),
        "audit": (audit_root / "AUDIT.json", V4_AUDIT_RAW_SHA256),
        "audit_seal": (audit_root / "SEAL_RECEIPT.json", V4_AUDIT_SEAL_RAW_SHA256),
        "audit_checksums": (
            audit_root / "CHECKSUMS.sha256",
            V4_AUDIT_CHECKSUMS_RAW_SHA256,
        ),
    }
    for label, (path, expected_hash) in files.items():
        if not path.is_file() or path.is_symlink() or sha256_file(path) != expected_hash:
            raise IntegrationContractError(f"exact V4 binding differs: {label}")

    design = load_json_object(files["design_lock"][0])
    verify_self_seal(design, V4_DESIGN_LOCK_SEMANTIC_SHA256)
    if design.get("design_contract_sha256") != V4_DESIGN_CONTRACT_SHA256:
        raise IntegrationContractError("V4 design contract binding differs")
    contract = design.get("design_contract")
    if type(contract) is not dict or semantic_sha256(contract) != V4_DESIGN_CONTRACT_SHA256:
        raise IntegrationContractError("embedded V4 design contract differs")
    runtime = contract.get("runtime_plan")
    fixed = contract.get("fixed_hyperparameters")
    if (
        type(runtime) is not dict
        or runtime.get("max_outer_workers") != 10
        or runtime.get("inner_threads") != 1
        or runtime.get("gpu_usage") is not False
        or runtime.get("cpu_ids") != list(range(32))
        or type(fixed) is not dict
        or fixed.get("minimum_training_rows") != 504
        or fixed.get("regime_fallback_max_count") != 8
        or fixed.get("regime_fallback_max_fraction") != 0.02
    ):
        raise IntegrationContractError("V4 runtime/training compatibility facts differ")

    source_closure = load_json_object(files["source_closure"][0])
    verify_self_seal(source_closure, V4_SOURCE_CLOSURE_SEMANTIC_SHA256)
    source_records = dict(source_closure["source_audit"]["source_sha256"])
    if any(source_records.get(path) != digest for path, digest in V4_RUNTIME_SOURCE_SHA256.items()):
        raise IntegrationContractError("V4 runtime source closure differs")
    for relative_path, expected_hash in V4_RUNTIME_SOURCE_SHA256.items():
        path = project_root / relative_path
        if not path.is_file() or path.is_symlink() or sha256_file(path) != expected_hash:
            raise IntegrationContractError("live exact V4 runtime source differs")

    audit = load_json_object(files["audit"][0])
    verify_self_seal(audit, V4_AUDIT_SEMANTIC_SHA256)
    if (
        audit.get("overall_verdict") != V4_AUDIT_VERDICT
        or audit.get("severity_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or audit.get("decision", {}).get("real_fit_or_prediction_executed") is not False
    ):
        raise IntegrationContractError("V4 clean audit verdict/scope differs")
    audit_seal = load_json_object(files["audit_seal"][0])
    verify_self_seal(audit_seal, V4_AUDIT_SEAL_SEMANTIC_SHA256)
    if (
        audit_seal.get("verdict") != V4_AUDIT_VERDICT
        or audit_seal.get("authority", {}).get("real_fit") is not False
        or audit_seal.get("authority", {}).get("real_prediction") is not False
    ):
        raise IntegrationContractError("V4 audit seal scope differs")
    return {
        "status": "PASS_EXACT_FROZEN_V4_AND_CLEAN_AUDIT_BOUND",
        "design_root": V4_DESIGN_ROOT,
        "design_lock_raw_sha256": V4_DESIGN_LOCK_RAW_SHA256,
        "design_contract_sha256": V4_DESIGN_CONTRACT_SHA256,
        "design_checksums_raw_sha256": V4_DESIGN_CHECKSUMS_RAW_SHA256,
        "source_closure_raw_sha256": V4_SOURCE_CLOSURE_RAW_SHA256,
        "source_closure_semantic_sha256": V4_SOURCE_CLOSURE_SEMANTIC_SHA256,
        "audit_root": V4_AUDIT_ROOT,
        "audit_raw_sha256": V4_AUDIT_RAW_SHA256,
        "audit_semantic_sha256": V4_AUDIT_SEMANTIC_SHA256,
        "audit_seal_raw_sha256": V4_AUDIT_SEAL_RAW_SHA256,
        "audit_seal_semantic_sha256": V4_AUDIT_SEAL_SEMANTIC_SHA256,
        "audit_checksums_raw_sha256": V4_AUDIT_CHECKSUMS_RAW_SHA256,
        "audit_verdict": V4_AUDIT_VERDICT,
        "audit_scope_extended": False,
    }


def _verify_input_compatibility_facts(input_result: InputClosureResult) -> None:
    payload = input_result.payload
    records = payload.get("task_records")
    if type(records) is not list or len(records) != 50:
        raise IntegrationContractError("input compatibility task records differ")
    if (
        payload.get("fold_count") != 3100
        or payload.get("decision_identity_count") != 64800
        or payload.get("public_input_freeze_receipt_raw_sha256")
        != PUBLIC_INPUT_FREEZE_RAW_SHA256
        or payload.get("public_input_checksums_raw_sha256")
        != PUBLIC_INPUT_CHECKSUMS_RAW_SHA256
    ):
        raise IntegrationContractError("input closure cross-binding differs")
    for record in records:
        if (
            record.get("entity_count") != 1
            or record.get("fold_count") != 62
            or record.get("decision_identity_count") != 1296
            or record.get("first_fold_warm_fit_row_count") != 503
            or record.get("invalid_regime_row_count") != 199
            or record.get("expected_regime_warmup_source_row_count") != 199
            or record.get("first_fold_fit_regime_fallback_count") != 198
            or record.get("unexpected_malformed_regime_row_count") != 0
            or record.get("decision_window_invalid_regime_row_count") != 0
            or record.get("folds_passing_exact_v4_fit_fallback_gate") != 0
        ):
            raise IntegrationContractError("public/V4 compatibility fact differs")


def _validate_quality_evidence(quality: Mapping[str, Any]) -> dict[str, Any]:
    output = dict(quality)
    required = {
        "status": "PASS_TESTS_RUFF_SMOKE_NO_MODEL_RUN",
        "pytest_exit_code": 0,
        "ruff_exit_code": 0,
        "smoke_task_count": 50,
        "smoke_fold_count": 3100,
        "smoke_decision_identity_count": 64800,
        "model_fit_executed": False,
        "model_prediction_executed": False,
    }
    for field, expected in required.items():
        if output.get(field) != expected:
            raise IntegrationContractError(f"quality evidence differs: {field}")
    return output


def build_draft_preflight(
    project_root: Path,
    *,
    quality_evidence: Mapping[str, Any],
) -> DraftPreflightArtifacts:
    """Build immutable bytes for a non-authoritative NO_GO draft only."""

    root = project_root.resolve(strict=True)
    runtime = _verify_pinned_runtime()
    v4_binding = _verify_v4_binding(root)
    input_result = build_public_input_closure(root)
    _verify_input_compatibility_facts(input_result)
    quality = _validate_quality_evidence(quality_evidence)
    source_closure = build_source_closure(root)

    input_bytes = _json_bytes(input_result.payload)
    source_bytes = _json_bytes(source_closure)
    identity_sha256 = hashlib.sha256(input_result.decision_identities_csv).hexdigest()
    fold_sha256 = hashlib.sha256(input_result.fold_plan_csv).hexdigest()
    input_sha256 = hashlib.sha256(input_bytes).hexdigest()
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    design = design_payload(
        input_closure_raw_sha256=input_sha256,
        input_closure_semantic_sha256=input_result.payload["manifest_sha256"],
        decision_identities_raw_sha256=identity_sha256,
        fold_plan_raw_sha256=fold_sha256,
        source_closure_raw_sha256=source_sha256,
        source_closure_semantic_sha256=source_closure["manifest_sha256"],
    )
    design_bytes = _json_bytes(design)
    design_sha256 = hashlib.sha256(design_bytes).hexdigest()
    preflight = sealed_payload(
        {
            "schema_version": f"{SCHEMA_VERSION}.preflight.v1",
            "status": STATUS,
            "verdict": "NO_GO_EXACT_V4_R4_PREDICTION_LANE_CONTRACT_MAINTENANCE_REQUIRED",
            "authoritative_freeze": False,
            "superseded_draft": True,
            "current_worker_clean_room_eligible": False,
            "fresh_fork_turns_none_revalidation_required": True,
            "public_input_binding": {
                "relative_root": PUBLIC_INPUT_ROOT,
                "freeze_receipt_raw_sha256": PUBLIC_INPUT_FREEZE_RAW_SHA256,
                "checksums_raw_sha256": PUBLIC_INPUT_CHECKSUMS_RAW_SHA256,
            },
            "v4_binding": v4_binding,
            "artifact_bindings": {
                "input_closure_raw_sha256": input_sha256,
                "input_closure_semantic_sha256": input_result.payload[
                    "manifest_sha256"
                ],
                "decision_identities_raw_sha256": identity_sha256,
                "fold_plan_raw_sha256": fold_sha256,
                "source_closure_raw_sha256": source_sha256,
                "source_closure_semantic_sha256": source_closure["manifest_sha256"],
                "design_lock_raw_sha256": design_sha256,
                "design_lock_semantic_sha256": design["manifest_sha256"],
            },
            "geometry": {
                "task_count": GEOMETRY.task_count,
                "fold_count": GEOMETRY.total_fold_count,
                "requested_fit_count": GEOMETRY.requested_fit_count,
                "decision_identity_count": GEOMETRY.total_decision_count,
                "exact_v4_native_decision_capacity": (
                    GEOMETRY.exact_v4_native_decision_capacity
                ),
                "exact_v4_uncovered_decision_count": (
                    GEOMETRY.exact_v4_uncovered_decision_count
                ),
            },
            "requested_resource_policy": dict(REQUESTED_RESOURCE_POLICY),
            "exact_v4_resource_policy": dict(EXACT_V4_RESOURCE_POLICY),
            "runtime_receipt": runtime,
            "quality_evidence": quality,
            "blocking_findings": [dict(item) for item in BLOCKING_FINDINGS],
            "severity_counts": {"P0": 4, "P1": 0, "P2": 0},
            "authority": dict(NO_RUN_FLAGS),
            "real_data_accessed": False,
            "public_synthetic_dgp_inputs_only": True,
        }
    )
    preflight_bytes = _json_bytes(preflight)
    return DraftPreflightArtifacts(
        input_closure=input_result.payload,
        input_closure_bytes=input_bytes,
        decision_identities_bytes=input_result.decision_identities_csv,
        fold_plan_bytes=input_result.fold_plan_csv,
        source_closure=source_closure,
        source_closure_bytes=source_bytes,
        design=design,
        design_bytes=design_bytes,
        preflight=preflight,
        preflight_bytes=preflight_bytes,
    )


__all__ = ["DraftPreflightArtifacts", "build_draft_preflight"]
