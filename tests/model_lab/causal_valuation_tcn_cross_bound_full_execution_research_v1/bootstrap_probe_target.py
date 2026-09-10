"""Disposable same-PID bootstrap finalization target used only by tests."""

from __future__ import annotations

import argparse
from pathlib import Path

from research.model_zoo.causal_valuation_tcn_cross_bound_full_execution_research_v1.pycache_guard import (
    write_bootstrap_finalization_request,
    write_runtime_isolation_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--isolation-receipt", required=True)
    arguments = parser.parse_args()
    artifact = Path(arguments.artifact)
    artifact.write_bytes(b"same-pid-bootstrap-probe\n")
    isolation = Path(arguments.isolation_receipt)
    write_runtime_isolation_receipt(
        isolation,
        label="same_pid_bootstrap_negative_probe",
    )
    write_bootstrap_finalization_request(
        label="same_pid_bootstrap_negative_probe",
        bind_files={
            "artifact": artifact,
            "pycache_isolation_receipt": isolation,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
