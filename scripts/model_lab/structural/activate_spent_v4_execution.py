"""Seal the superseding Structural V4 execution activation around final runner bytes."""

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

from pe_regime_v04.model_lab.structural.authorization import (  # noqa: E402
    _load_authority_policy,
    _verify_snapshot,
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_file,
    verify_payload_seal,
)


SCREEN = ROOT / "outputs/model_zoo_structural_wave_screen_20260819"
SPENT = ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819"
OUTPUT = SPENT / "ACTIVATION_BINDING_EXECUTION.json"
PREVIOUS_ACTIVATION = SPENT / "ACTIVATION_BINDING.json"
PREVIOUS_PIN = SPENT / "EXTERNAL_POLICY_PIN.json"
CURRENT_POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v4.py"
RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v4.py"

PREVIOUS_ACTIVATION_RAW = "4166124875e1ec074ca0d6facdaf63c7a940327a23574de7ca39190e9e2ef750"
PREVIOUS_ACTIVATION_LOGICAL = "5626f2b9c9f8f21d9c8282b87641e5b9b8df697bf9df9d05838583e15c219bc9"
PREVIOUS_PIN_RAW = "9e190c46aa10af9f948e13046646d3f24bccce2f7f08ac08e4e2ae290b18fd52"
PREVIOUS_PIN_LOGICAL = "395651521e04d34c84f719cc070f01b3b5c9e5c597a04167e2aa9aada77a6829"
INTERMEDIATE_POLICY_RAW = "694171fdba5c051d7ad55685c9d8e7a4856ccaf9e21a6a4d83e848175251727d"
INTERMEDIATE_POLICY_LOGICAL = "cbf4c0c8f8806b0657b31e4c07e7940debdc59c8d5d6ac6c153d50fc314a0c7a"
AUDITED_POLICY_RAW = "ca874545c461d60cdfd71569472c743943e0f74db5080aeb8e1443e6d41aef2e"
RUNNER_RAW = "cc5c3345baf6319a2e1f5612ba9735b0cbd86943810a9219c3c9f87502e398f0"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON object required: {path}")
    verify_payload_seal(value)
    return value


def _record(path: Path, *, raw: str, logical: str | None = None) -> dict[str, Any]:
    resolved = path.resolve(strict=True)
    if sha256_file(resolved) != raw:
        raise RuntimeError(f"raw binding mismatch: {resolved}")
    output: dict[str, Any] = {
        "path": resolved.relative_to(ROOT).as_posix(),
        "bytes": resolved.stat().st_size,
        "raw_sha256": raw,
    }
    if logical is not None:
        value = _read(resolved)
        if value["manifest_sha256"] != logical:
            raise RuntimeError(f"logical binding mismatch: {resolved}")
        output["logical_sha256"] = logical
    return output


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable execution activation already exists: {path}")
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    encoded = canonical_json_bytes(payload) + b"\n"
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    previous = _read(PREVIOUS_ACTIVATION)
    if (
        sha256_file(PREVIOUS_ACTIVATION) != PREVIOUS_ACTIVATION_RAW
        or previous["manifest_sha256"] != PREVIOUS_ACTIVATION_LOGICAL
    ):
        raise RuntimeError("predecessor activation bytes changed")
    previous_pin = _read(PREVIOUS_PIN)
    if (
        sha256_file(PREVIOUS_PIN) != PREVIOUS_PIN_RAW
        or previous_pin["manifest_sha256"] != PREVIOUS_PIN_LOGICAL
    ):
        raise RuntimeError("predecessor external pin bytes changed")
    if previous_pin.get("activation_binding", {}).get("raw_sha256") != PREVIOUS_ACTIVATION_RAW:
        raise RuntimeError("predecessor activation/pin chain changed")

    if sha256_file(CURRENT_POLICY) == AUDITED_POLICY_RAW:
        raise RuntimeError("predecessor activation unexpectedly remained executable")
    policy = _load_authority_policy(CURRENT_POLICY, expected_raw_sha256=INTERMEDIATE_POLICY_RAW)
    if policy.get("manifest_sha256") != INTERMEDIATE_POLICY_LOGICAL:
        raise RuntimeError("intermediate authority policy changed")
    if previous_pin.get("authority_policy", {}).get("raw_sha256") != INTERMEDIATE_POLICY_RAW:
        raise RuntimeError("intermediate authority policy was not externally pinned")

    # Every V4 audited file must remain exact except the explicitly superseded policy.
    for line in (SCREEN / "CHECKSUMS_V4.sha256").read_text(encoding="utf-8").splitlines():
        expected, relative = line.split("  ", 1)
        if relative == "src/pe_regime_v04/model_lab/structural/authority_policy_v4.py":
            if expected != AUDITED_POLICY_RAW:
                raise RuntimeError("audited policy checksum record changed")
            continue
        if sha256_file(ROOT / relative) != expected:
            raise RuntimeError(f"V4 audited dependency drift: {relative}")

    snapshot = _read(SCREEN / "EXECUTION_SNAPSHOT_V4.json")
    _verify_snapshot(snapshot, ROOT)
    runner_record = _record(RUNNER, raw=RUNNER_RAW)
    if runner_record["bytes"] != 30612:
        raise RuntimeError("physical runner byte length changed")
    if (SPENT / "prediction").exists():
        raise RuntimeError("prediction output exists before execution activation")

    bindings = dict(previous["exact_bindings"])
    bindings["predecessor_activation"] = _record(
        PREVIOUS_ACTIVATION,
        raw=PREVIOUS_ACTIVATION_RAW,
        logical=PREVIOUS_ACTIVATION_LOGICAL,
    )
    bindings["predecessor_external_policy_pin"] = _record(
        PREVIOUS_PIN, raw=PREVIOUS_PIN_RAW, logical=PREVIOUS_PIN_LOGICAL
    )
    bindings["superseded_intermediate_authority_policy"] = {
        **_record(CURRENT_POLICY, raw=INTERMEDIATE_POLICY_RAW),
        "logical_sha256": INTERMEDIATE_POLICY_LOGICAL,
    }
    bindings["physical_prediction_runner"] = runner_record
    payload = seal_payload(
        {
            "format_version": 2,
            "mode": "structural_v4_atomic_spent_execution_activation",
            "state": "ACTIVE_EXACT_SPENT_SCREEN_ONLY",
            "supersedes": {
                "activation_raw_sha256": PREVIOUS_ACTIVATION_RAW,
                "reason": "PREDECESSOR_DID_NOT_BIND_FINAL_PHYSICAL_RUNNER_BYTES",
                "predecessor_is_executable": False,
                "predecessor_policy_path_changed": True,
            },
            "exact_bindings": bindings,
            "source_closure": {
                **dict(previous["source_closure"]),
                "physical_runner_in_execution_closure": True,
                "physical_runner_raw_sha256": RUNNER_RAW,
                "previously_bound_nonpolicy_files_reverified": True,
                "audited_policy_transition_explicitly_bound": True,
            },
            "fold_contract": dict(previous["fold_contract"]),
            "execution_contract": dict(previous["execution_contract"]),
            "decision": dict(previous["decision"]),
            "attestations": {
                **dict(previous["attestations"]),
                "prediction_started_before_this_activation": False,
                "final_physical_runner_frozen_before_this_activation": True,
            },
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "path": OUTPUT.relative_to(ROOT).as_posix(),
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
                "runner_raw_sha256": RUNNER_RAW,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
