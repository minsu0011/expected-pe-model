"""Build and verify the score-free H-OFS V2 design/preflight payload in memory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
from typing import Any

from research.model_zoo.hierarchical_observable_fair_value_state_v2 import (
    PARENT_RUNTIME_SOURCE_SHA256,
    V1_INDEPENDENT_AUDIT_BINDING,
    contract_payload,
    contract_sha256,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v2.contracts import (
    RUNTIME_PLAN,
    canonical_json_bytes,
)
from research.model_zoo.hierarchical_observable_fair_value_state_v2.source_audit import (
    run_source_audit_v2,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def build_preflight_payload(project_root: Path = PROJECT_ROOT) -> dict[str, Any]:
    """Return the deterministic, no-fit/no-prediction preflight record."""

    source_audit = run_source_audit_v2(project_root)
    if not source_audit.passed:
        raise RuntimeError("H-OFS V2 source isolation failed")
    executable = Path(sys.executable).resolve()
    return {
        "schema_version": "expected_pe.hofs_v2.score_free_preflight.v1",
        "status": "PASS_SCORE_FREE_R2_CAPABILITY_PREFLIGHT_NO_MODEL_LAUNCH",
        "design_contract_sha256": contract_sha256(),
        "design_contract": contract_payload(),
        "v1_independent_audit_binding": dict(V1_INDEPENDENT_AUDIT_BINDING),
        "source_audit": source_audit.payload(),
        "parent_runtime_source_sha256": dict(PARENT_RUNTIME_SOURCE_SHA256),
        "resource": {
            "python_version": platform.python_version(),
            "python_executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
            "logical_cpu_count": int(os.cpu_count() or 1),
            "runtime_plan": dict(RUNTIME_PLAN),
        },
        "authority": {
            "real_fit": False,
            "real_prediction": False,
            "truth_or_vault": False,
            "score": False,
            "registry_or_champion": False,
            "promotion": False,
        },
    }


def preflight_sha256(project_root: Path = PROJECT_ROOT) -> str:
    return hashlib.sha256(canonical_json_bytes(build_preflight_payload(project_root))).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", required=True)
    args = parser.parse_args()
    if not args.check:
        return 2
    payload = build_preflight_payload()
    print(
        json.dumps(
            {
                "status": payload["status"],
                "design_contract_sha256": payload["design_contract_sha256"],
                "preflight_sha256": hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
                "source_file_count": len(payload["source_audit"]["source_sha256"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
