"""Freeze the blocked Structural V5 repair for independent re-audit."""

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

from pe_regime_v04.model_lab.structural.authorization_v5 import (  # noqa: E402
    load_structural_execution_authorization_v5,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    StructuralContractError,
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)


V5 = ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819"
POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v5.py"
POLICY_RAW = "6708312a42fb815817d9e46e32ddecc02ade854863873771a16f40370373324d"
POLICY_LOGICAL = "0b74ada45b7798ab4b2ca6af544755ee403ad07788f0bcc71fda80589dbfbaad"
PREFLIGHT = V5 / "POLICY_PREFLIGHT_V5.json"
MANIFEST = V5 / "IMPLEMENTATION_MANIFEST_V5.json"
REQUEST = V5 / "INDEPENDENT_AUDIT_REQUEST_V5.json"
CHECKSUMS = V5 / "CHECKSUMS_V5.sha256"
FILES = (
    "src/pe_regime_v04/model_lab/structural/authorization_v5.py",
    "src/pe_regime_v04/model_lab/structural/authority_policy_v5.py",
    "scripts/model_lab/structural/run_spent_predictions_v5.py",
    "scripts/model_lab/structural/run_spent_predictions_v4.py",
    "tests/model_lab/test_structural_v5_runner.py",
    "scripts/model_lab/structural/benchmark_v5_scheduling_no_score.py",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/RUNTIME_ENVIRONMENT_V5.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/NO_SCORE_SCHEDULING_PARITY_V5.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/V5_TEST_EVIDENCE.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/ACTIVATION_CANDIDATE_V5.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/EXTERNAL_POLICY_PIN_CANDIDATE_V5.json",
    "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/V4_FAILED_ATTEMPT_ADDENDUM_V2.json",
    "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json",
    "outputs/model_zoo_structural_wave_terminal_failure_independent_audit_20260819/AUDIT.json",
    "outputs/model_zoo_structural_wave_terminal_failure_independent_audit_20260819/REPORT.md",
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


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(path)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    activation = _read(V5 / "ACTIVATION_CANDIDATE_V5.json")
    if activation["decision"]["structural_prediction_or_scoring_authorized"] is not False:
        raise RuntimeError("V5 activation candidate is not blocked")
    synthetic = load_structural_execution_authorization_v5(
        ROOT, external_policy_sha256=POLICY_RAW, scope="SYNTHETIC_NO_SCORE"
    )
    if synthetic.spent_execution_authorized:
        raise RuntimeError("V5 pre-audit policy unexpectedly authorizes spent execution")
    formal_error = ""
    try:
        load_structural_execution_authorization_v5(
            ROOT, external_policy_sha256=POLICY_RAW, scope="FORMAL_SPENT"
        )
    except StructuralContractError as exc:
        formal_error = str(exc)
    if "blocked pending independent audit GO" not in formal_error:
        raise RuntimeError("V5 formal gate did not fail closed")
    if (V5 / "prediction").exists():
        raise RuntimeError("V5 prediction directory exists before independent audit")

    preflight = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v5_blocked_policy_preflight",
            "authority_policy": {
                "path": POLICY.relative_to(ROOT).as_posix(),
                "bytes": POLICY.stat().st_size,
                "raw_sha256": POLICY_RAW,
                "logical_sha256": POLICY_LOGICAL,
            },
            "synthetic_no_score_authorization_sha256": synthetic.authorization_sha256,
            "synthetic_no_score_authorized": True,
            "formal_spent_authorized": False,
            "formal_spent_error": formal_error,
            "prediction_directory_exists": False,
            "scores_computed": False,
            "truth_opened": False,
        }
    )
    _write_atomic(PREFLIGHT, preflight)

    records = [
        _record(
            ROOT / relative,
            logical=relative.endswith(".json") and not relative.endswith("/DESIGN.json"),
        )
        for relative in FILES
    ]
    manifest = seal_payload(
        {
            "format_version": 5,
            "mode": "structural_v5_repair_implementation_manifest",
            "source_and_evidence_inventory": records,
            "inventory_sha256": sha256_bytes(canonical_json_bytes(records)),
            "policy_preflight": _record(PREFLIGHT, logical=True),
            "candidate_universe": [
                "decomp_block_ridge_ar1_lag1",
                "decomp_block_ridge_ar1_current",
                "residual_ar1_nested_oof",
                "stack_geometric_equal_pair",
                "stack_simplex_pair_frozen",
            ],
            "candidate_parameters_changed": False,
            "formal_identity": {
                "seeds": [6301, 6421, 6521, 6607, 6701],
                "fold_ids": [f"fold_{index:03d}" for index in range(12, 74)],
                "rows_per_seed_candidate": 1296,
                "total_future_prediction_rows": 32400,
            },
            "repairs": {
                "P0_runtime": "closed in implementation; independent verification pending",
                "P1_target_eligibility": "closed in implementation; independent verification pending",
                "P1_fail_fast_and_scheduling": (
                    "closed in implementation; independent verification pending"
                ),
            },
            "runtime_estimate": {
                "v4_observed_wall_minutes": 60.55,
                "v4_observed_aggregate_cpu_minutes": 176.7,
                "v5_expected_wall_minutes": [25, 35],
                "basis": (
                    "same work divided into 200 parity-checked chunks on ProcessPool8; "
                    "includes repeated per-chunk input/authorization overhead"
                ),
            },
            "state": "NO_GO_PENDING_INDEPENDENT_V5_AUDIT",
            "predictions_generated": False,
            "scores_computed": False,
            "truth_opened": False,
            "seeds_reserved": False,
        }
    )
    _write_atomic(MANIFEST, manifest)

    request = seal_payload(
        {
            "format_version": 5,
            "mode": "structural_v5_independent_audit_request",
            "implementation_manifest": _record(MANIFEST, logical=True),
            "activation_candidate": _record(V5 / "ACTIVATION_CANDIDATE_V5.json", logical=True),
            "external_policy_pin": _record(
                V5 / "EXTERNAL_POLICY_PIN_CANDIDATE_V5.json", logical=True
            ),
            "required_independent_reproductions": [
                "verify V4 failure custody is empty and bind corrected folds 012..036",
                "run exact invalid-target audit on all five spent surfaces without predictions",
                "verify fold012 filters positions 0/1 to 502 and fold037 filters none",
                "verify feature NaNs are train-only imputed and never target-row filtered",
                "verify zero eligible and interior target gaps fail closed",
                "verify base Python 3.13 rejects before numerical import",
                "verify pinned launcher/process-image/version/package freeze in parent and workers",
                "reproduce real Windows spawn parity for 8/16/24/32 and 200 tasks",
                "verify chunked and monolithic synthetic canonical row bytes are identical",
                "adversarially force one future failure and prove pending cancellation/termination",
                "verify V4 snapshot/base/trigger/predict inputs and all new source bytes are exact",
                "verify policy FORMAL_SPENT remains blocked before independent GO",
                "verify no project predictions, scores, truth access, seeds, or registry mutation",
            ],
            "required_decision": {
                "open_p0": "integer",
                "open_p1": "integer",
                "spent_seed_screen": "GO only if P0=0 and P1=0",
                "structural_prediction_or_scoring_authorized": (
                    "true only for exact V5 runner after atomic post-audit activation"
                ),
            },
            "post_go_sequence": [
                "bind exact independent AUDIT raw/logical hash in new execution activation",
                "bind unchanged V5 runner/runtime/source/input/fold bytes",
                "publish superseding formal V5 policy and external raw pin",
                "verify exact pinned absolute launch command",
                "only then execute five candidates on five already-spent seeds",
            ],
            "current_state": "NO_GO_NO_PREDICTIONS_NO_SCORES",
        }
    )
    _write_atomic(REQUEST, request)

    checksum_paths = [ROOT / relative for relative in FILES] + [
        PREFLIGHT,
        MANIFEST,
        REQUEST,
    ]
    lines = [f"{sha256_file(path)}  {path.relative_to(ROOT).as_posix()}" for path in checksum_paths]
    CHECKSUMS.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(
        json.dumps(
            {
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
