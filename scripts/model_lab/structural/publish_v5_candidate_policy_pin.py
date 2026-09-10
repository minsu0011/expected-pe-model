"""Publish the external raw pin for blocked Structural V5 audit review."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


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


V5 = ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819"
POLICY = ROOT / "src/pe_regime_v04/model_lab/structural/authority_policy_v5.py"
ACTIVATION = V5 / "ACTIVATION_CANDIDATE_V5.json"
OUTPUT = V5 / "EXTERNAL_POLICY_PIN_CANDIDATE_V5.json"
POLICY_RAW = "6708312a42fb815817d9e46e32ddecc02ade854863873771a16f40370373324d"
POLICY_LOGICAL = "0b74ada45b7798ab4b2ca6af544755ee403ad07788f0bcc71fda80589dbfbaad"
ACTIVATION_RAW = "81de379e7f165724589474fff727af47b2de9032b784129138a028410484632d"
ACTIVATION_LOGICAL = "20ec7e8111817cc3f365fd08a6dfa8f8ea432eac8c122a6dc5ce2bf6ce09b1db"


def main() -> int:
    policy = _load_authority_policy(POLICY, expected_raw_sha256=POLICY_RAW)
    if policy["manifest_sha256"] != POLICY_LOGICAL or policy["formal_spent_activated"] is not False:
        raise RuntimeError("V5 candidate authority is not exact and blocked")
    activation = json.loads(ACTIVATION.read_text(encoding="utf-8"))
    verify_payload_seal(activation)
    if (
        sha256_file(ACTIVATION) != ACTIVATION_RAW
        or activation["manifest_sha256"] != ACTIVATION_LOGICAL
    ):
        raise RuntimeError("V5 activation candidate changed")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v5_external_candidate_policy_pin",
            "authority_policy": {
                "path": POLICY.relative_to(ROOT).as_posix(),
                "bytes": POLICY.stat().st_size,
                "raw_sha256": POLICY_RAW,
                "logical_sha256": POLICY_LOGICAL,
            },
            "activation_candidate": {
                "path": ACTIVATION.relative_to(ROOT).as_posix(),
                "bytes": ACTIVATION.stat().st_size,
                "raw_sha256": ACTIVATION_RAW,
                "logical_sha256": ACTIVATION_LOGICAL,
            },
            "formal_spent_activated": False,
            "independent_audit_required": True,
        }
    )
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    temporary = OUTPUT.with_name(f".{OUTPUT.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, OUTPUT)
    finally:
        temporary.unlink(missing_ok=True)
    print(
        json.dumps(
            {
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
