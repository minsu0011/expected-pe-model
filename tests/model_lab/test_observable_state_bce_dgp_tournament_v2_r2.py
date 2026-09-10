from __future__ import annotations

import copy
from pathlib import Path
import shutil
from typing import Any

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2.artifacts import (
    canonical_json_bytes,
    read_json_object,
    seal_payload,
    semantic_sha256,
    sha256_file,
    write_checksums_exclusive,
    write_json_exclusive,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2 import seed_ledger
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2.authority import (
    PRECOMMIT_SEMANTIC_FIELDS,
    verify_independent_audit_bundle,
    verify_root_reservation_approval_bundle,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2.contracts import (
    APPROVAL_KEYS,
    AUDIT_FILENAMES,
    AUDIT_KEYS,
    EXPECTED_APPROVAL_AUTHORITY,
    EXPECTED_APPROVAL_RESERVATION_SCOPE,
    EXPECTED_AUDIT_AUTHORITY,
    EXPECTED_EXECUTION_STATE_ZERO,
    EXPECTED_FORBIDDEN_ACCESS_ZERO,
    EXPECTED_PROBE_SIDE_EFFECTS_ZERO,
    EXPECTED_SEVERITY_ZERO,
    METADATA_ACCESS_KEYS,
    PINNED_PYTHON_EXECUTABLE_RAW_SHA256,
    PINNED_PYTHON_VERSION,
    PRECOMMIT_FILENAMES,
    PROBE_KEYS,
    REQUIRED_AUDIT_CHECK_IDS,
    RESERVATION_ACTIVATION_LITERAL,
    R1_NO_GO_AUDIT_ROOT,
    R2_ACCESS_SCHEMA_VERSION,
    R2_ACCESS_STATUS,
    R2_APPROVAL_ACTION,
    R2_APPROVAL_DECISION,
    R2_APPROVAL_OUTPUT_PREFIX,
    R2_APPROVAL_SCHEMA_VERSION,
    R2_APPROVAL_STATUS,
    R2_AUDIT_OUTPUT_PREFIX,
    R2_AUDIT_SCHEMA_VERSION,
    R2_AUDIT_SEAL_SCHEMA_VERSION,
    R2_AUDIT_STATUS,
    R2_AUDIT_VERDICT,
    R2_PRECOMMIT_OUTPUT_PREFIX,
    R2_PROBE_SCHEMA_VERSION,
    R2_PROBE_STATUS,
    R2_QUALITY_SCHEMA_VERSION,
    R2_QUALITY_STATUS,
    R2_RESOURCE_SCHEMA_VERSION,
    R2_RESOURCE_STATUS,
    R2_SEAL_STATUS,
    V2R2ContractError,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2.lineage import (
    verify_complete_lineage,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r2.precommit import (
    source_manifest_payload,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64


def _fixture_roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    precommit = outputs / f"{R2_PRECOMMIT_OUTPUT_PREFIX}fixture"
    precommit.mkdir()
    audit = outputs / f"{R2_AUDIT_OUTPUT_PREFIX}fixture"
    audit.mkdir()
    return project, precommit, audit


def _context(project: Path, precommit: Path) -> dict[str, Any]:
    unsigned = {
        "precommit_root": precommit.relative_to(project).as_posix(),
        "precommit_raw_sha256": {
            name: HEX_A for name in sorted(PRECOMMIT_FILENAMES)
        },
        "precommit_semantic_sha256": {
            name: HEX_B for name in sorted(PRECOMMIT_SEMANTIC_FIELDS)
        },
        "smoke_root": (
            "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
            "schema_smoke_r1_20260821"
        ),
        "smoke_raw_sha256": {
            "CHECKSUMS.sha256": HEX_A,
            "SMOKE_RECEIPT.json": HEX_B,
        },
        "smoke_semantic_sha256": HEX_C,
        "registry": {
            "relative_path": "outputs/v04_spent_seed_registry.json",
            "raw_sha256": HEX_A,
            "self_sha256": HEX_B,
            "entry_count": 9,
        },
        "v2_r1_no_go_audit": {
            "relative_root": R1_NO_GO_AUDIT_ROOT,
            "audit_raw_sha256": HEX_A,
            "audit_semantic_sha256": HEX_B,
            "seal_raw_sha256": HEX_C,
            "checksums_raw_sha256": "d" * 64,
            "verdict": "NO_GO_V2_FRESH_5_PLUS_5_RESERVATION",
            "severity_counts": {"P0": 2, "P1": 0, "P2": 0},
        },
    }
    return {**unsigned, "authority_context_semantic_sha256": semantic_sha256(unsigned)}


def _write_sealed(path: Path, payload: dict[str, Any], field: str) -> None:
    write_json_exclusive(path, seal_payload(payload, field))


def _replace_sealed(path: Path, payload: dict[str, Any], field: str) -> None:
    path.unlink()
    _write_sealed(path, payload, field)


def _refresh_audit_seal(audit: Path, context: dict[str, Any]) -> None:
    (audit / "SEAL_RECEIPT.json").unlink(missing_ok=True)
    (audit / "CHECKSUMS.sha256").unlink(missing_ok=True)
    fields = {
        "ACCESS_RECEIPT.json": "access_semantic_sha256",
        "AUDIT.json": "audit_semantic_sha256",
        "PROBE_RECEIPT.json": "probe_semantic_sha256",
        "QUALITY_RECEIPT.json": "quality_semantic_sha256",
        "RESOURCE_RECEIPT.json": "resource_semantic_sha256",
    }
    payloads = {name: read_json_object(audit / name) for name in fields}
    raw = {name: sha256_file(audit / name) for name in sorted(fields)}
    semantic = {name: payloads[name][field] for name, field in fields.items()}
    _write_sealed(
        audit / "SEAL_RECEIPT.json",
        {
            "schema_version": R2_AUDIT_SEAL_SCHEMA_VERSION,
            "status": R2_SEAL_STATUS,
            "decision": R2_AUDIT_VERDICT,
            "severity_counts": EXPECTED_SEVERITY_ZERO,
            "artifact_raw_sha256": raw,
            "artifact_semantic_sha256": semantic,
            "authority_context_semantic_sha256": context[
                "authority_context_semantic_sha256"
            ],
            "registry_raw_before": context["registry"]["raw_sha256"],
            "registry_raw_expected_after": context["registry"]["raw_sha256"],
            "required_go_issued": True,
            "root_approval_created": False,
            "seed_derivation_or_reservation_performed": False,
        },
        "seal_semantic_sha256",
    )
    write_checksums_exclusive(audit)


def _build_valid_audit(audit: Path, context: dict[str, Any]) -> None:
    _write_sealed(
        audit / "ACCESS_RECEIPT.json",
        {
            "schema_version": R2_ACCESS_SCHEMA_VERSION,
            "status": R2_ACCESS_STATUS,
            "forbidden_access": EXPECTED_FORBIDDEN_ACCESS_ZERO,
            "metadata_access": {key: True for key in METADATA_ACCESS_KEYS},
        },
        "access_semantic_sha256",
    )
    _write_sealed(
        audit / "PROBE_RECEIPT.json",
        {
            "schema_version": R2_PROBE_SCHEMA_VERSION,
            "status": R2_PROBE_STATUS,
            "probes": {key: True for key in PROBE_KEYS},
            "side_effects": EXPECTED_PROBE_SIDE_EFFECTS_ZERO,
        },
        "probe_semantic_sha256",
    )
    _write_sealed(
        audit / "QUALITY_RECEIPT.json",
        {
            "schema_version": R2_QUALITY_SCHEMA_VERSION,
            "status": R2_QUALITY_STATUS,
            "pytest_returncode": 0,
            "pytest_passed_count": len(PROBE_KEYS),
            "ruff_returncode": 0,
            "verifier_returncode": 0,
            "source_closure_exact": True,
        },
        "quality_semantic_sha256",
    )
    _write_sealed(
        audit / "RESOURCE_RECEIPT.json",
        {
            "schema_version": R2_RESOURCE_SCHEMA_VERSION,
            "status": R2_RESOURCE_STATUS,
            "python_version": PINNED_PYTHON_VERSION,
            "python_executable_raw_sha256": PINNED_PYTHON_EXECUTABLE_RAW_SHA256,
            "logical_cpu_count": 32,
            "gpu_queried": False,
            "model_execution_resource_policy_exercised": False,
        },
        "resource_semantic_sha256",
    )
    _write_sealed(
        audit / "AUDIT.json",
        {
            "schema_version": R2_AUDIT_SCHEMA_VERSION,
            "audit_revision": "R2",
            "generated_at_utc": "2026-08-21T00:00:00+00:00",
            "status": R2_AUDIT_STATUS,
            "verdict": R2_AUDIT_VERDICT,
            "severity_counts": EXPECTED_SEVERITY_ZERO,
            "bindings": context,
            "access_state": EXPECTED_FORBIDDEN_ACCESS_ZERO,
            "execution_state": EXPECTED_EXECUTION_STATE_ZERO,
            "checks": {key: "PASS" for key in REQUIRED_AUDIT_CHECK_IDS},
            "findings": [],
            "authorization_boundary": EXPECTED_AUDIT_AUTHORITY,
        },
        "audit_semantic_sha256",
    )
    _refresh_audit_seal(audit, context)


def _verify_audit(
    project: Path, precommit: Path, audit: Path, context: dict[str, Any]
) -> dict[str, Any]:
    return verify_independent_audit_bundle(
        project_root=project,
        precommit_root=precommit,
        audit_root=audit,
        expected_context=context,
    )


def _build_valid_approval(
    project: Path,
    precommit: Path,
    audit: Path,
    context: dict[str, Any],
) -> Path:
    audit_result = _verify_audit(project, precommit, audit, context)
    approval = project / "outputs" / f"{R2_APPROVAL_OUTPUT_PREFIX}fixture"
    approval.mkdir()
    bindings = {
        "precommit_root": context["precommit_root"],
        "precommit_raw_sha256": context["precommit_raw_sha256"],
        "precommit_semantic_sha256": context["precommit_semantic_sha256"],
        "audit_root": audit_result["audit_root"],
        "audit_raw_sha256": audit_result["audit_raw_sha256"],
        "audit_semantic_sha256": audit_result["audit_semantic_sha256"],
        "audit_seal_raw_sha256": audit_result["audit_seal_raw_sha256"],
        "audit_checksums_raw_sha256": audit_result["audit_checksums_raw_sha256"],
        "registry": context["registry"],
        "authority_context_semantic_sha256": context[
            "authority_context_semantic_sha256"
        ],
    }
    _write_sealed(
        approval / "ROOT_APPROVAL.json",
        {
            "schema_version": R2_APPROVAL_SCHEMA_VERSION,
            "created_at_utc": "2026-08-21T00:01:00+00:00",
            "status": R2_APPROVAL_STATUS,
            "action": R2_APPROVAL_ACTION,
            "decision": R2_APPROVAL_DECISION,
            "root_approver_id": "independent-root-fixture",
            "bindings": bindings,
            "reservation_scope": EXPECTED_APPROVAL_RESERVATION_SCOPE,
            "authority_boundary": EXPECTED_APPROVAL_AUTHORITY,
        },
        "approval_semantic_sha256",
    )
    write_checksums_exclusive(approval)
    return approval


def test_both_historical_audit_series_and_terminal_no_go_are_exact() -> None:
    lineage = verify_complete_lineage(PROJECT_ROOT)
    prediction = lineage["prediction_pre_evaluation_chain"]
    pre_score = lineage["detached_evaluation_pre_score_chain"]
    assert [item["file_raw_sha256"]["AUDIT.json"] for item in prediction] == [
        "64589b3b965d43ad9406f771a5e6996b158c7de8189005c1a764214ca01ff267",
        "5c66ad3a00bcfbb6a590c150a66af0564972fd974674c8a108cba84d33e53e29",
        "8a6119b74cb0243f6b54cdd5bce7d5412bc4ffa8e8f1a7532963022951ac688d",
    ]
    assert [item["file_raw_sha256"]["AUDIT.json"] for item in pre_score] == [
        "2dcb4292de52f1ce666d24b1109b1c37c59b9677f183b0f66432abcf269fca16",
        "b81dc87db7d225c4a4c3e3773f4e136ef1803300c360df1b0ac70ff316bd073c",
        "a234090e84d2fd98f5db520c87f1290d42fceb8f49005510cca62a63f5a0008c",
    ]
    assert lineage["series_are_distinct"] is True
    assert lineage["v2_r1_no_go"]["severity_counts"] == {"P0": 2, "P1": 0, "P2": 0}
    assert lineage["old_truth_or_latent_payload_opened"] is False
    assert lineage["historical_prediction_payload_opened"] is False
    assert lineage["historical_score_payload_opened"] is False


def test_r2_source_manifest_has_no_payload_or_seed_inventory() -> None:
    manifest = source_manifest_payload(PROJECT_ROOT)
    assert manifest["old_vault_payload_files_in_inventory"] == 0
    assert manifest["historical_prediction_payload_files_in_inventory"] == 0
    assert manifest["historical_score_payload_files_in_inventory"] == 0
    assert manifest["fresh_truth_payload_files_in_inventory"] == 0
    assert all("PREDICTIONS.csv" not in key for key in manifest["dependencies"])


def test_valid_audit_is_exact_but_non_authorizing(tmp_path: Path) -> None:
    project, precommit, audit = _fixture_roots(tmp_path)
    context = _context(project, precommit)
    _build_valid_audit(audit, context)
    result = _verify_audit(project, precommit, audit, context)
    assert result["reservation_authorized_by_audit_alone"] is False
    assert set(path.name for path in audit.iterdir()) == set(AUDIT_FILENAMES)


@pytest.mark.parametrize("mode", ["minimal", "extra", "missing", "wrong_self_hash"])
def test_adversarial_audit_schema_and_self_seal_rejected(
    tmp_path: Path, mode: str
) -> None:
    project, precommit, audit = _fixture_roots(tmp_path)
    context = _context(project, precommit)
    _build_valid_audit(audit, context)
    original = read_json_object(audit / "AUDIT.json")
    if mode == "minimal":
        payload = {
            "schema_version": R2_AUDIT_SCHEMA_VERSION,
            "verdict": R2_AUDIT_VERDICT,
            "reservation_authorized_by_audit_alone": False,
            "score_computed": False,
        }
        _replace_sealed(audit / "AUDIT.json", payload, "audit_semantic_sha256")
    elif mode == "extra":
        unsigned = dict(original)
        unsigned.pop("audit_semantic_sha256")
        unsigned["unexpected"] = False
        _replace_sealed(audit / "AUDIT.json", unsigned, "audit_semantic_sha256")
    elif mode == "missing":
        unsigned = dict(original)
        unsigned.pop("audit_semantic_sha256")
        unsigned.pop("findings")
        _replace_sealed(audit / "AUDIT.json", unsigned, "audit_semantic_sha256")
    else:
        original["audit_semantic_sha256"] = "0" * 64
        (audit / "AUDIT.json").write_bytes(canonical_json_bytes(original))
    _refresh_audit_seal(audit, context)
    with pytest.raises(V2R2ContractError):
        _verify_audit(project, precommit, audit, context)


@pytest.mark.parametrize("binding", ["precommit", "smoke", "registry", "unbound"])
def test_adversarial_audit_context_hashes_rejected(
    tmp_path: Path, binding: str
) -> None:
    project, precommit, audit = _fixture_roots(tmp_path)
    context = _context(project, precommit)
    _build_valid_audit(audit, context)
    payload = read_json_object(audit / "AUDIT.json")
    payload.pop("audit_semantic_sha256")
    bindings = copy.deepcopy(payload["bindings"])
    if binding == "precommit":
        bindings["precommit_raw_sha256"]["DESIGN_LOCK.json"] = "0" * 64
    elif binding == "smoke":
        bindings["smoke_semantic_sha256"] = "0" * 64
    elif binding == "registry":
        bindings["registry"]["raw_sha256"] = "0" * 64
    else:
        bindings = {
            "precommit_root": context["precommit_root"],
            "authority_context_semantic_sha256": context[
                "authority_context_semantic_sha256"
            ],
        }
    payload["bindings"] = bindings
    _replace_sealed(audit / "AUDIT.json", payload, "audit_semantic_sha256")
    _refresh_audit_seal(audit, context)
    with pytest.raises(V2R2ContractError):
        _verify_audit(project, precommit, audit, context)


def test_non_direct_child_and_extra_file_universes_rejected(tmp_path: Path) -> None:
    project, precommit, audit = _fixture_roots(tmp_path)
    context = _context(project, precommit)
    _build_valid_audit(audit, context)
    (audit / "EXTRA.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(V2R2ContractError, match="file universe"):
        _verify_audit(project, precommit, audit, context)
    (audit / "EXTRA.json").unlink()
    nested_parent = project / "outputs" / "nested"
    nested_parent.mkdir()
    nested = nested_parent / f"{R2_AUDIT_OUTPUT_PREFIX}nested"
    shutil.copytree(audit, nested)
    with pytest.raises(V2R2ContractError, match="direct outputs child"):
        _verify_audit(project, precommit, nested, context)


def test_valid_separate_root_approval_authorizes_reservation_only(tmp_path: Path) -> None:
    project, precommit, audit = _fixture_roots(tmp_path)
    context = _context(project, precommit)
    _build_valid_audit(audit, context)
    approval = _build_valid_approval(project, precommit, audit, context)
    result = verify_root_reservation_approval_bundle(
        project_root=project,
        precommit_root=precommit,
        audit_root=audit,
        approval_root=approval,
        expected_context=context,
    )
    assert result["reservation_authorized"] is True
    assert result["generation_prediction_truth_or_score_authorized"] is False


@pytest.mark.parametrize(
    "mode", ["minimal", "extra", "missing", "wrong_audit_hash", "wrong_registry_hash"]
)
def test_adversarial_root_approval_rejected(tmp_path: Path, mode: str) -> None:
    project, precommit, audit = _fixture_roots(tmp_path)
    context = _context(project, precommit)
    _build_valid_audit(audit, context)
    approval = _build_valid_approval(project, precommit, audit, context)
    path = approval / "ROOT_APPROVAL.json"
    original = read_json_object(path)
    if mode == "minimal":
        payload = {
            "schema_version": R2_APPROVAL_SCHEMA_VERSION,
            "action": R2_APPROVAL_ACTION,
            "decision": R2_APPROVAL_DECISION,
            "root_approver_id": "fixture",
        }
    else:
        payload = dict(original)
        payload.pop("approval_semantic_sha256")
        if mode == "extra":
            payload["unexpected"] = True
        elif mode == "missing":
            payload.pop("reservation_scope")
        elif mode == "wrong_audit_hash":
            payload["bindings"] = copy.deepcopy(payload["bindings"])
            payload["bindings"]["audit_raw_sha256"] = "0" * 64
        else:
            payload["bindings"] = copy.deepcopy(payload["bindings"])
            payload["bindings"]["registry"] = copy.deepcopy(
                payload["bindings"]["registry"]
            )
            payload["bindings"]["registry"]["raw_sha256"] = "0" * 64
    _replace_sealed(path, payload, "approval_semantic_sha256")
    (approval / "CHECKSUMS.sha256").unlink()
    write_checksums_exclusive(approval)
    with pytest.raises(V2R2ContractError):
        verify_root_reservation_approval_bundle(
            project_root=project,
            precommit_root=precommit,
            audit_root=audit,
            approval_root=approval,
            expected_context=context,
        )


def test_wrong_activation_literal_rejects_before_ledger_or_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden() -> tuple[object, ...]:
        raise AssertionError("ledger API must not be imported")

    monkeypatch.setattr(seed_ledger, "_ledger_api", forbidden)
    with pytest.raises(V2R2ContractError, match="activation literal"):
        seed_ledger.reserve_fresh_5_plus_5(
            project_root=PROJECT_ROOT,
            precommit_root=PROJECT_ROOT / "absent",
            independent_audit_root=PROJECT_ROOT / "absent-audit",
            root_approval_root=PROJECT_ROOT / "absent-approval",
            activation_literal=RESERVATION_ACTIVATION_LITERAL + "_WRONG",
        )


def test_closed_top_level_field_universes_include_semantic_seals() -> None:
    assert "audit_semantic_sha256" in AUDIT_KEYS
    assert "approval_semantic_sha256" in APPROVAL_KEYS
    assert "bindings" in AUDIT_KEYS & APPROVAL_KEYS
