"""Freeze the blocked Structural V6 package for a fresh independent audit."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.authorization_v6 import (  # noqa: E402
    load_structural_execution_authorization_v6,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    StructuralContractError,
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)


V6 = ROOT / "outputs/model_zoo_structural_wave_spent_screen_v6_20260819"
POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v6.py"
POLICY_RAW = "63e82420c08249261f3c9d635b7f74d35f382c59ec561cdb0750aecd84a9baea"
POLICY_LOGICAL = "f513ce0bb3dceb9a3db52fadcd6d82d4cdcc93d135df3a957e30aa1c2564bd92"
EXTERNAL_PIN = V6 / "EXTERNAL_POLICY_PIN_CANDIDATE_V6.json"
PREFLIGHT = V6 / "POLICY_PREFLIGHT_V6.json"
MANIFEST = V6 / "IMPLEMENTATION_MANIFEST_V6.json"
REQUEST = V6 / "INDEPENDENT_AUDIT_REQUEST_V6.json"
CHECKSUMS = V6 / "CHECKSUMS_V6.sha256"
FILES = (
    "src/pe_regime_v04/model_lab/structural/authorization_v6.py",
    "src/pe_regime_v04/model_lab/structural/authority_policy_v6.py",
    "scripts/model_lab/structural/run_spent_predictions_v6.py",
    "scripts/model_lab/structural/run_spent_predictions_v5.py",
    "scripts/model_lab/structural/run_spent_predictions_v4.py",
    "scripts/model_lab/structural/prepare_v6_runtime_environment.py",
    "tests/model_lab/test_structural_v6_runner.py",
    "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/RUNTIME_ENVIRONMENT_V6.json",
    "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/V6_TEST_EVIDENCE.json",
    "outputs/model_zoo_structural_wave_spent_screen_v6_20260819/ACTIVATION_CANDIDATE_V6.json",
    "outputs/model_zoo_structural_wave_fifth_independent_audit_20260819/AUDIT.json",
    "outputs/model_zoo_structural_wave_fifth_independent_audit_20260819/REPORT.md",
    "outputs/model_zoo_structural_wave_fifth_independent_audit_20260819/CHECKSUMS.sha256",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/IMPLEMENTATION_MANIFEST_V5.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/INDEPENDENT_AUDIT_REQUEST_V5.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/CHECKSUMS_V5.sha256",
    "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/V4_FAILED_ATTEMPT_ADDENDUM_V2.json",
    "outputs/model_zoo_structural_wave_screen_20260819/EXECUTION_SNAPSHOT_V4.json",
    "outputs/model_zoo_structural_wave_screen_20260819/BASE_BINDING_LOCK_V4.json",
    "outputs/model_zoo_structural_wave_screen_20260819/TRIGGER_DECISION.json",
    "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json",
    "outputs/model_zoo_structural_wave_design_20260819/DESIGN.json",
)


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"object required: {path}")
    verify_payload_seal(value)
    return value


def _record(path: Path, *, logical: bool = False) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "raw_sha256": sha256_file(path),
    }
    if logical:
        row["logical_sha256"] = _read(path)["manifest_sha256"]
    return row


def _write_atomic_bytes(path: Path, content: bytes) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _write_atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    _write_atomic_bytes(path, canonical_json_bytes(payload) + b"\n")


def main() -> int:
    activation = _read(V6 / "ACTIVATION_CANDIDATE_V6.json")
    if activation["decision"]["structural_prediction_or_scoring_authorized"] is not False:
        raise RuntimeError("V6 activation candidate is not blocked")
    if any((V6 / name).exists() for name in ("prediction", "structural_predictions.csv")):
        raise RuntimeError("V6 prediction custody is not empty")

    external_pin = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v6_external_candidate_policy_pin",
            "authority_policy": {
                **_record(POLICY),
                "logical_sha256": POLICY_LOGICAL,
            },
            "activation_candidate": _record(V6 / "ACTIVATION_CANDIDATE_V6.json", logical=True),
            "formal_spent_activated": False,
            "independent_audit_required": True,
        }
    )
    _write_atomic_json(EXTERNAL_PIN, external_pin)

    synthetic = load_structural_execution_authorization_v6(
        ROOT, external_policy_sha256=POLICY_RAW, scope="SYNTHETIC_NO_SCORE"
    )
    if synthetic.spent_execution_authorized:
        raise RuntimeError("V6 blocked policy unexpectedly authorizes spent execution")
    formal_error = ""
    try:
        load_structural_execution_authorization_v6(
            ROOT, external_policy_sha256=POLICY_RAW, scope="FORMAL_SPENT"
        )
    except StructuralContractError as exc:
        formal_error = str(exc)
    if "blocked pending independent audit GO" not in formal_error:
        raise RuntimeError("V6 formal gate did not fail closed")
    preflight = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v6_blocked_policy_preflight",
            "authority_policy": {
                **_record(POLICY),
                "logical_sha256": POLICY_LOGICAL,
            },
            "external_candidate_policy_pin": _record(EXTERNAL_PIN, logical=True),
            "synthetic_no_score_authorization_sha256": synthetic.authorization_sha256,
            "synthetic_no_score_authorized": True,
            "formal_spent_authorized": False,
            "formal_spent_error": formal_error,
            "prediction_artifact_count": 0,
            "truth_opened": False,
            "scores_computed": False,
        }
    )
    _write_atomic_json(PREFLIGHT, preflight)

    records = [
        _record(
            ROOT / relative,
            logical=relative.endswith(".json") and not relative.endswith("/DESIGN.json"),
        )
        for relative in FILES
    ]
    records.extend(
        [
            _record(EXTERNAL_PIN, logical=True),
            _record(PREFLIGHT, logical=True),
        ]
    )
    manifest = seal_payload(
        {
            "format_version": 6,
            "mode": "structural_v6_repair_implementation_manifest",
            "source_and_evidence_inventory": records,
            "inventory_sha256": sha256_bytes(canonical_json_bytes(records)),
            "repairs": {
                "P0_complete_runtime_dependency_enforcement": (
                    "implementation closed; fresh independent verification pending"
                ),
                "P1_exact_worker_future_failure_attribution": (
                    "implementation closed; fresh independent verification pending"
                ),
            },
            "complete_runtime_contract": {
                "installed_package_count": 38,
                "pip_freeze_all_bound": True,
                "freeze_stdout_raw_bytes_bound": True,
                "complete_package_map_and_hash_bound": True,
                "parent_and_every_task_worker_verification": True,
                "lightgbm": "4.6.0",
                "pyyaml": "6.0.2",
                "exact_launcher_process_image_version_prefix_stdlib": True,
            },
            "failure_contract": {
                "worker_first_observation_receipt": True,
                "parent_future_map_identity_receipt": True,
                "payload_seed_candidate_fold_ids_exact_positions": True,
                "worker_pid_environment_trace": True,
                "fail_fast_cancel_terminate_shutdown_receipt": True,
                "immutable_formal_failure_artifact": "FAILURE_RECEIPT_V6.json",
            },
            "candidate_parameters_changed": False,
            "candidate_universe": list(
                (
                    "decomp_block_ridge_ar1_lag1",
                    "decomp_block_ridge_ar1_current",
                    "residual_ar1_nested_oof",
                    "stack_geometric_equal_pair",
                    "stack_simplex_pair_frozen",
                )
            ),
            "formal_identity": {
                "seeds": [6301, 6421, 6521, 6607, 6701],
                "fold_ids": [f"fold_{index:03d}" for index in range(12, 74)],
                "rows_per_seed_candidate": 1296,
                "total_future_prediction_rows": 32400,
            },
            "runtime_estimate": {
                "expected_wall_minutes": [25, 35],
                "workers": 8,
                "task_count": 200,
                "additional_runtime_verification_overhead": "one exact freeze/map check per worker",
            },
            "state": "NO_GO_PENDING_INDEPENDENT_V6_AUDIT",
            "formal_spent_authorized": False,
            "predictions_generated": False,
            "truth_opened": False,
            "scores_computed": False,
            "seeds_reserved": False,
        }
    )
    _write_atomic_json(MANIFEST, manifest)

    request = seal_payload(
        {
            "format_version": 6,
            "mode": "structural_v6_independent_audit_request",
            "implementation_manifest": _record(MANIFEST, logical=True),
            "activation_candidate": _record(V6 / "ACTIVATION_CANDIDATE_V6.json", logical=True),
            "external_candidate_policy_pin": _record(EXTERNAL_PIN, logical=True),
            "required_independent_reproductions": [
                "recompute exact launcher/process-image/version/prefix/stdlib hashes",
                "recompute raw pip freeze --all bytes and canonical complete freeze hash",
                "recompute all 38 installed distribution name/version pairs and map hash",
                "verify exact LightGBM 4.6.0 and PyYAML 6.0.2 in parent and every worker",
                "adversarially remove/mutate LightGBM, PyYAML, one transitive package, freeze bytes and map hash",
                "reproduce pinned CPython acceptance and base CPython 3.13 pre-import rejection",
                "run the live synthetic spawn failure and verify sealed worker first-observation receipt",
                "verify parent future_map identity exactly matches payload/seed/candidate/fold IDs and positions",
                "verify worker pid, executable, package hashes, environment and original traceback are present",
                "verify pending cancellation, process termination, wait=False and no live worker after poll",
                "verify failure path can publish only immutable FAILURE_RECEIPT_V6 and no predictions",
                "verify unchanged V5 scheduling/eligibility/candidate/fold/seed contracts",
                "verify FORMAL_SPENT stays blocked and no truth, score, prediction, seed or registry mutation",
            ],
            "post_go_execution_activation_exact_binding_names": [
                "physical_prediction_runner_v6",
                "frozen_runner_v5_dependency",
                "frozen_runner_v4_transitive_dependency",
                "authorization_v5_transitive_dependency",
                "authorization_v6",
                "runtime_environment_v6",
                "v5_independent_no_go_audit",
                "v4_failed_attempt",
            ],
            "required_decision": {
                "open_p0": 0,
                "open_p1": 0,
                "spent_seed_screen": "GO only if every reproduction passes",
                "structural_prediction_or_scoring_authorized": (
                    "true only for the exact V6 runner after atomic post-audit activation"
                ),
            },
            "post_go_sequence": [
                "bind exact independent V6 AUDIT raw/logical hash in new execution activation",
                "bind unchanged V6 runner/runtime/auth and frozen V5/V4 dependency bytes",
                "publish superseding formal V6 policy and external execution pin",
                "verify with exact pinned absolute CPython command",
                "wait for explicit CPU release before any spent candidate execution",
            ],
            "current_state": "NO_GO_NO_PREDICTIONS_NO_TRUTH_NO_SCORES",
        }
    )
    _write_atomic_json(REQUEST, request)

    checksum_paths = [ROOT / relative for relative in FILES] + [
        EXTERNAL_PIN,
        PREFLIGHT,
        MANIFEST,
        REQUEST,
    ]
    lines = [f"{sha256_file(path)}  {path.relative_to(ROOT).as_posix()}" for path in checksum_paths]
    _write_atomic_bytes(CHECKSUMS, ("\n".join(lines) + "\n").encode("utf-8"))
    print(
        json.dumps(
            {
                "policy_raw_sha256": POLICY_RAW,
                "external_pin_raw_sha256": sha256_file(EXTERNAL_PIN),
                "preflight_raw_sha256": sha256_file(PREFLIGHT),
                "manifest_raw_sha256": sha256_file(MANIFEST),
                "manifest_logical_sha256": manifest["manifest_sha256"],
                "request_raw_sha256": sha256_file(REQUEST),
                "request_logical_sha256": request["manifest_sha256"],
                "checksums_raw_sha256": sha256_file(CHECKSUMS),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
