"""Exercise recovery V5 under an already active native DACL window.

This audit never calls ``main``, creates the V5 supervisor claim, creates the
child pycache prefix, or executes the freezer.  The consumed V3 claim is not a
V4 governed identity and is deliberately ignored.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay")
SUPERVISOR = PROJECT_ROOT / (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r8_r8_"
    "preimport_source_supervisor_v3/trusted_supervisor_v5.py"
)
EXPECTED_SHA256 = "2166d35962260d0efaaf8a77845f4531d5393f74bcfe5cbcba1194f84b3de6ba"
EXPECTED_SIZE = 100422
CLAIM = PROJECT_ROOT / "build/pc_r8r8_preimport_source_supervisor_v5_recovery_once_20260823"
CHILD_PREFIX = PROJECT_ROOT / "build/pc_r8r8_static_freeze_actual_once_20260822"
DESIGN_OUTPUT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)


def main() -> int:
    governed = (CLAIM, CHILD_PREFIX, DESIGN_OUTPUT)
    before = tuple(path.exists() for path in governed)
    if before != (False, False, False):
        raise RuntimeError("V5 one-shot identity or output existed before handshake audit")
    raw = SUPERVISOR.read_bytes()
    if len(raw) != EXPECTED_SIZE or hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError("V5 supervisor bytes drifted before handshake audit")
    namespace: dict[str, Any] = {
        "__builtins__": __builtins__,
        "__file__": str(SUPERVISOR),
        "__name__": "r8r8_v5_external_native_handshake_audit",
    }
    exec(compile(raw, str(SUPERVISOR), "exec", dont_inherit=True, optimize=2), namespace)
    owners = namespace["_CheckedOwners"]()
    primary: BaseException | None = None
    try:
        sources, source_receipt = namespace["_hold_fixed_closure"](owners)
        files, executable, directories, runtime_receipt = namespace["_hold_runtime_closure"](
            owners
        )
        active = [directory.verify() for directory in directories]
        if (
            len(sources) != 119
            or len(files) != 2265
            or len(directories) != 129
            or executable.path != namespace["PINNED_VENV_PYTHON"]
            or any(row["external_native_protection"] is not True for row in active)
        ):
            raise RuntimeError("external V5 custody universe drifted")
        delegated = [directory.restore() for directory in directories]
        if any(
            row.get("dacl_restore_delegated_to_native_launcher") is not True
            for row in delegated
        ):
            raise RuntimeError("external V5 DACL restoration was not delegated")
        after = tuple(path.exists() for path in governed)
        if after != before:
            raise RuntimeError("handshake audit consumed a V5 one-shot identity or output")
        print(
            json.dumps(
                {
                    "authority_generation_fresh_truth_heldout_signer_counts": {
                        "authority": 0,
                        "fresh": 0,
                        "generation": 0,
                        "heldout": 0,
                        "signer": 0,
                        "truth": 0,
                    },
                    "external_native_protection_count": len(active),
                    "file_record_count": len(files),
                    "one_shot_identity_before_after_absent": True,
                    "restore_delegation_count": len(delegated),
                    "runtime_status": runtime_receipt["status"],
                    "source_record_count": len(sources),
                    "source_status": source_receipt["status"],
                    "status": "PASS_FULL_V5_EXTERNAL_NATIVE_HANDSHAKE_NO_EXECUTION_NO_IDENTITY",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except BaseException as exc:
        primary = exc
    owners.close(primary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
