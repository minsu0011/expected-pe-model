"""Publish the immutable external pin for the runner-bound Structural V4 authority."""

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
)
from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_file,
    verify_payload_seal,
)


SPENT = ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819"
OUTPUT = SPENT / "EXTERNAL_POLICY_PIN_EXECUTION.json"
ACTIVATION = SPENT / "ACTIVATION_BINDING_EXECUTION.json"
POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v4.py"
RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v4.py"
ACTIVATION_RAW = "ed469d17308afbaaec23558ee31230912c9daca9936b765046f335b74b4da467"
ACTIVATION_LOGICAL = "8d3d314ffa73b86cc5543e7eb636cd7050625511cc5aa4403aefcdf9f0fe280a"
POLICY_RAW = "2c1c27fbe315746fe21a4c1a4d24734a8c05b8c370fc1fec08059a3f447b1a71"
POLICY_LOGICAL = "e7af154af059038d210f779a4e1c0d94de5dff87bc4de78a505b7b0064030511"
RUNNER_RAW = "cc5c3345baf6319a2e1f5612ba9735b0cbd86943810a9219c3c9f87502e398f0"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON object required: {path}")
    verify_payload_seal(value)
    return value


def _record(path: Path, *, raw: str, logical: str | None = None) -> dict[str, Any]:
    if sha256_file(path) != raw:
        raise RuntimeError(f"raw binding mismatch: {path}")
    row: dict[str, Any] = {
        "path": path.relative_to(ROOT).as_posix(),
        "bytes": path.stat().st_size,
        "raw_sha256": raw,
    }
    if logical is not None:
        value = _read(path)
        if value["manifest_sha256"] != logical:
            raise RuntimeError(f"logical binding mismatch: {path}")
        row["logical_sha256"] = logical
    return row


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"immutable execution policy pin already exists: {path}")
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
    activation = _read(ACTIVATION)
    if activation["manifest_sha256"] != ACTIVATION_LOGICAL:
        raise RuntimeError("execution activation logical binding changed")
    policy = _load_authority_policy(POLICY, expected_raw_sha256=POLICY_RAW)
    if policy["manifest_sha256"] != POLICY_LOGICAL:
        raise RuntimeError("execution authority logical binding changed")
    runner = _record(RUNNER, raw=RUNNER_RAW)
    if activation.get("exact_bindings", {}).get("physical_prediction_runner") != runner:
        raise RuntimeError("activation does not bind final runner verbatim")

    payload = seal_payload(
        {
            "format_version": 2,
            "mode": "structural_v4_external_spent_execution_policy_pin",
            "authority_policy": {
                **_record(POLICY, raw=POLICY_RAW),
                "logical_sha256": POLICY_LOGICAL,
            },
            "activation_binding": _record(
                ACTIVATION, raw=ACTIVATION_RAW, logical=ACTIVATION_LOGICAL
            ),
            "physical_prediction_runner": runner,
            "independent_go_audit": {
                "raw_sha256": ("d59656aeea97a568f52fb17c95d114a4a28a0ac15d23208fe98aa9e90dfba5c9"),
                "logical_sha256": (
                    "efe869aa58ac89b7c5c5a82f86ff8533f2d66f551ef1f9620abb05664ad9102f"
                ),
            },
            "predecessor_activation_superseded": True,
            "formal_spent_activated": True,
            "external_pin_must_be_supplied_verbatim": True,
        }
    )
    _write_atomic(OUTPUT, payload)
    print(
        json.dumps(
            {
                "path": OUTPUT.relative_to(ROOT).as_posix(),
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
