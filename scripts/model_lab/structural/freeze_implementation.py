"""Freeze the score-free Structural Wave V4 implementation and re-audit request."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.authorization import (  # noqa: E402
    EXPECTED_ENABLED,
    load_structural_execution_authorization,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    STRUCTURAL_DESIGN_SHA256,
    StructuralContractError,
    canonical_json_bytes,
    seal_payload,
    sha256_file,
    verify_payload_seal,
    verify_structural_design,
)
from pe_regime_v04.model_lab.structural.derived_registry import (  # noqa: E402
    track_a_derived_feature_definitions,
)
from pe_regime_v04.model_lab.structural.nested import (  # noqa: E402
    FORMAL_OUTER_COVERAGE_SHA256,
    FORMAL_OUTER_FOLD_COUNT,
    FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
    FORMAL_OUTER_STARTS,
)


OUTPUT = ROOT / "outputs/model_zoo_structural_wave_screen_20260819"
DESIGN = ROOT / "outputs/model_zoo_structural_wave_design_20260819/DESIGN.json"
TRIGGER = OUTPUT / "TRIGGER_DECISION.json"
BASE_LOCK = OUTPUT / "BASE_BINDING_LOCK_V4.json"
TRACK_A_AUDIT = OUTPUT / "TRACK_A_DATA_BOUND_AUDIT.json"
BENCHMARK = OUTPUT / "NO_SCORE_BACKEND_BENCHMARK.json"
SNAPSHOT = OUTPUT / "EXECUTION_SNAPSHOT_V4.json"
AUTHORITY_POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v4.py"
AUTHORITY_POLICY_SHA256 = "ca874545c461d60cdfd71569472c743943e0f74db5080aeb8e1443e6d41aef2e"
AUDIT_NO_GO_V3 = (
    ROOT / "outputs/model_zoo_structural_wave_third_independent_audit_20260819/AUDIT.json"
)
REGISTRY_V4 = OUTPUT / "TRACK_A_DERIVED_FEATURE_REGISTRY_V4.json"
MANIFEST_V4 = OUTPUT / "IMPLEMENTATION_MANIFEST_V4.json"
AUDIT_REQUEST_V4 = OUTPUT / "INDEPENDENT_REAUDIT_REQUEST_V4.json"
CHECKSUMS_V4 = OUTPUT / "CHECKSUMS_V4.sha256"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON object required: {path}")
    return value


def _record(path: Path) -> dict[str, Any]:
    path = path.resolve(strict=True)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def _write_immutable(path: Path, value: bytes) -> None:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite immutable V4 file: {path}")
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    verify_structural_design(DESIGN)
    artifacts = {
        "trigger_decision": TRIGGER,
        "base_binding_lock_v4": BASE_LOCK,
        "track_a_data_bound_audit": TRACK_A_AUDIT,
        "no_score_backend_benchmark": BENCHMARK,
        "execution_snapshot_v4": SNAPSHOT,
    }
    payloads = {name: _read(path) for name, path in artifacts.items()}
    for payload in payloads.values():
        verify_payload_seal(payload)
    if sha256_file(TRIGGER) != "45b6dee894ed72809c49902f4f78ff058a465db6ebfe8903a21c659883504765":
        raise RuntimeError("trigger decision changed")
    if payloads["track_a_data_bound_audit"]["all_5_surfaces_all_6_audits_pass"] is not True:
        raise RuntimeError("Track-A data-bound audit is not complete")
    benchmark = payloads["no_score_backend_benchmark"]
    if benchmark["parity"]["all_8_16_24_32_repeats_exact"] is not True:
        raise RuntimeError("worker-count parity is not complete")
    snapshot = payloads["execution_snapshot_v4"]
    if snapshot["spent_execution_authorized"] is not False:
        raise RuntimeError("pre-audit V4 snapshot cannot authorize spent execution")
    inventory_paths = {row["path"] for row in snapshot["source_inventory"]}
    if any("dgp_suite" in path for path in inventory_paths):
        raise RuntimeError("unrelated DGP state is present in V4 execution inventory")
    if any(path.startswith(("scripts/", "tests/")) for path in inventory_paths):
        raise RuntimeError("runtime snapshot includes non-runtime scripts/tests")
    if sha256_file(AUTHORITY_POLICY) != AUTHORITY_POLICY_SHA256:
        raise RuntimeError("V4 externally pinned authority policy changed")
    authorization = load_structural_execution_authorization(
        ROOT, external_policy_sha256=AUTHORITY_POLICY_SHA256
    )
    authorization.verify()
    if authorization.enabled_candidates != EXPECTED_ENABLED:
        raise RuntimeError("V4 authorization candidate universe changed")
    try:
        load_structural_execution_authorization(
            ROOT,
            external_policy_sha256=AUTHORITY_POLICY_SHA256,
            scope="FORMAL_SPENT",
        )
    except StructuralContractError as exc:
        if "repeat independent audit GO" not in str(exc):
            raise
    else:
        raise RuntimeError("FORMAL_SPENT unexpectedly opened before independent re-audit")

    source_paths = sorted((ROOT / "src/pe_regime_v04/model_lab/structural").glob("*.py"))
    script_paths = sorted((ROOT / "scripts/model_lab/structural").glob("*.py"))
    test_paths = sorted((ROOT / "tests/model_lab").glob("test_structural_*.py"))
    if any(path.name == "__init__.py" for path in (*source_paths, *script_paths)):
        raise RuntimeError("isolated structural paths must not create/edit __init__.py")

    registry_payload = seal_payload(
        {
            "format_version": 4,
            "mode": "structural_track_a_derived_feature_registry_isolated",
            "design_sha256": STRUCTURAL_DESIGN_SHA256,
            "data_bound_audit": _record(TRACK_A_AUDIT),
            "data_bound_audit_logical_sha256": payloads["track_a_data_bound_audit"][
                "manifest_sha256"
            ],
            "frozen_canonical_feature_registry_modified": False,
            "definition_count": 27,
            "execution_status": "DATA_BOUND_SIX_AUDITS_PASS_5_OF_5_PRESERVED_V4",
            "definitions": [
                definition.as_dict() for definition in track_a_derived_feature_definitions()
            ],
        }
    )
    _write_immutable(REGISTRY_V4, canonical_json_bytes(registry_payload) + b"\n")

    no_go = _read(AUDIT_NO_GO_V3)
    manifest = seal_payload(
        {
            "format_version": 4,
            "mode": "model_zoo_structural_wave_score_free_implementation_v4",
            "state": "V4_AUDIT_READY_FORMAL_SPENT_STILL_FAIL_CLOSED",
            "design": _record(DESIGN),
            "authority_and_execution_artifacts": {
                name: {
                    **_record(path),
                    "logical_sha256": payloads[name]["manifest_sha256"],
                }
                for name, path in artifacts.items()
            },
            "external_authority_policy": {
                **_record(AUTHORITY_POLICY),
                "logical_sha256": authorization.authority_policy_logical_sha256,
                "pin_delivery": "INDEPENDENT_AUDITOR_OR_FORMAL_CALLER_MUST_SUPPLY_EXACT_RAW_SHA256",
                "excluded_from_recursive_snapshot_to_avoid_self_reference": True,
            },
            "audit_activation": {
                **_record(AUDIT_NO_GO_V3),
                "logical_sha256": no_go["manifest_sha256"],
                "formal_spent_activated": False,
            },
            "track_a_derived_registry_v4": _record(REGISTRY_V4),
            "supersedes_v3_no_go": {
                **_record(AUDIT_NO_GO_V3),
                "logical_sha256": no_go["manifest_sha256"],
                "decision": no_go["decision"],
                "v3_files_modified_or_deleted": False,
            },
            "isolated_source_files": [_record(path) for path in source_paths],
            "isolated_script_files": [_record(path) for path in script_paths],
            "isolated_test_files": [_record(path) for path in test_paths],
            "repair_closure": {
                "P0-01": {
                    "status": "CLOSED_AWAITING_INDEPENDENT_REAUDIT",
                    "controls": [
                        "generated executable policy code-owns exact raw and logical trigger/base-lock/snapshot/audit hashes",
                        "policy raw bytes require an external SHA-256 pin before any artifact is trusted",
                        "acyclic snapshot excludes only the generated policy while policy binds snapshot and its current 62-entry source closure",
                        "authorization verify reopens policy, audit activation, every artifact seal, and every current source byte",
                        "coordinated base-lock or snapshot self-reseal cannot satisfy the externally pinned policy",
                    ],
                },
                "P0-02": {
                    "status": "CLOSED_AWAITING_INDEPENDENT_REAUDIT",
                    "controls": [
                        "formal factory accepts only one canonical fold_id and no caller frames/cutoff",
                        "code-owned range(252,1800,21) has exactly 74 folds and terminal length 15",
                        "full train/test membership schedule and coverage hashes are literal constants",
                        "formal factory reconstructs all 74 folds and complete 252:1800 coverage before selecting one fold",
                        "off-grid test start 601 is rejected",
                    ],
                },
            },
            "formal_outer_schedule": {
                "fold_count": FORMAL_OUTER_FOLD_COUNT,
                "starts": list(FORMAL_OUTER_STARTS),
                "terminal_test_sessions": 15,
                "position_schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
                "coverage_sha256": FORMAL_OUTER_COVERAGE_SHA256,
                "coverage": "range(252,1800)",
            },
            "preserved_controls": {
                "trigger_tuple": [True, True, True, False, True],
                "enabled_candidates": list(EXPECTED_ENABLED),
                "disabled_candidate": "residual_huber_nested_oof",
                "track_a_surfaces": 5,
                "track_a_audits_per_surface": 6,
                "backend_worker_grid": [8, 16, 24, 32],
                "backend_selected_workers": benchmark["selected_worker_count"],
                "backend_exact_parity": True,
            },
            "test_evidence": {
                "pytest_command": "PYTHONPATH=src python -m pytest -q tests/model_lab -k structural",
                "passed": 26,
                "failed": 0,
                "ruff_check": "PASS",
                "ruff_format_check": "PASS",
                "formal_spent_executor_run": False,
                "adversarial_regressions_added": [
                    "wrong_external_policy_pin_rejected_before_authorization",
                    "formal_outer_start_601_rejected_as_off_grid",
                ],
            },
            "next_gate": {
                "independent_v4_score_free_reaudit_required": True,
                "spent_seed_screen_authorized_now": False,
                "formal_authorizer_is_fail_closed": True,
                "requested_decision": "EXPLICIT_GO_OR_NO_GO_WITH_P0_P1_COUNTS",
            },
            "attestations": {
                "structural_candidate_predictions_written": False,
                "structural_candidate_scores_computed": False,
                "formal_exact_base_replay_executed": False,
                "spent_structural_candidate_execution_performed": False,
                "fresh_seed_selected_or_reserved": False,
                "heldout_opened": False,
                "registry_modified": False,
                "frozen_phase1_wave1_or_dgp_source_modified": False,
            },
        }
    )
    _write_immutable(MANIFEST_V4, canonical_json_bytes(manifest) + b"\n")

    request = seal_payload(
        {
            "format_version": 4,
            "mode": "structural_wave_v4_independent_score_free_reaudit_request",
            "implementation_manifest_v4": _record(MANIFEST_V4),
            "implementation_manifest_v4_logical_sha256": manifest["manifest_sha256"],
            "execution_snapshot_v4": _record(SNAPSHOT),
            "execution_snapshot_v4_logical_sha256": snapshot["manifest_sha256"],
            "base_binding_lock_v4": _record(BASE_LOCK),
            "base_binding_lock_v4_logical_sha256": payloads["base_binding_lock_v4"][
                "manifest_sha256"
            ],
            "external_authority_policy": _record(AUTHORITY_POLICY),
            "external_authority_policy_logical_sha256": (
                authorization.authority_policy_logical_sha256
            ),
            "requested_checks": [
                "reproduce V3 P0-01 coordinated self-reseal against external policy pin",
                "reproduce V3 P0-02 off-grid 601 intervention against formal fold resolver",
                "verify exact 74-fold full-membership and terminal-15 hashes",
                "re-run exact 26-test structural selection and Ruff",
                "verify no project prediction/score/seed action occurred",
                "issue explicit spent-screen GO or NO-GO with P0/P1 counts",
            ],
            "formal_spent_execution_authorized": False,
            "candidate_prediction_or_score_authorized": False,
        }
    )
    _write_immutable(AUDIT_REQUEST_V4, canonical_json_bytes(request) + b"\n")

    checksum_paths = sorted(
        (
            *artifacts.values(),
            AUTHORITY_POLICY,
            AUDIT_NO_GO_V3,
            REGISTRY_V4,
            MANIFEST_V4,
            AUDIT_REQUEST_V4,
        ),
        key=lambda path: path.name,
    )
    checksums = "".join(
        f"{sha256_file(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in checksum_paths
    )
    _write_immutable(CHECKSUMS_V4, checksums.encode("utf-8"))
    print(
        json.dumps(
            {
                "manifest": _record(MANIFEST_V4),
                "manifest_logical_sha256": manifest["manifest_sha256"],
                "audit_request": _record(AUDIT_REQUEST_V4),
                "registry": _record(REGISTRY_V4),
                "authority_policy": _record(AUTHORITY_POLICY),
                "checksums": _record(CHECKSUMS_V4),
                "spent_execution_authorized": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
