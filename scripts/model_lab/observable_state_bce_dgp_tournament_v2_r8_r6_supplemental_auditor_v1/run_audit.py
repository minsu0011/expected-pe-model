"""Production-only entry point for the independent R8-r6 supplemental audit.

This command must not be run before a live public binding has been frozen.  It
has no path overrides and cannot launch or contact the signer endpoint.
"""

from __future__ import annotations

import sys

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1 import (
    AuditPaths,
    AuditPolicy,
    WindowsProcessProbe,
    run_supplemental_audit,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r6_supplemental_auditor_v1.contracts import (
    canonical_json_bytes,
)


def main() -> int:
    if sys.argv != [sys.argv[0], "--audit-live-public-binding-after-phase1-go"]:
        return 64
    result = run_supplemental_audit(
        paths=AuditPaths.production(),
        policy=AuditPolicy.production(),
        process_probe=WindowsProcessProbe(),
    )
    sys.stdout.buffer.write(canonical_json_bytes(dict(result.as_mapping())) + b"\n")
    return 0 if result.verdict == "GO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
