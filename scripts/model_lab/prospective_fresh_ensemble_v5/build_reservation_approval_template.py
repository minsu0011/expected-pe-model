"""Emit an exact V5 root reservation approval template; grants no authority."""

from __future__ import annotations

from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.prospective_fresh_ensemble_v5.contracts import (  # noqa: E402
    sha256_file,
    write_json_exclusive,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.reservation_authority import (  # noqa: E402
    APPROVAL_NAME,
    build_root_reservation_approval,
)


TEMPLATE_ROOT = (
    PROJECT_ROOT
    / "outputs"
    / "model_zoo_prospective_fresh_ensemble_v5_reservation_approval_template_20260820"
)


def main() -> int:
    payload = build_root_reservation_approval(PROJECT_ROOT)
    TEMPLATE_ROOT.mkdir(parents=True, exist_ok=False)
    path = TEMPLATE_ROOT / f"{APPROVAL_NAME}.template"
    write_json_exclusive(path, payload)
    print(f"TEMPLATE {path.resolve()}")
    print(f"RAW_SHA256 {sha256_file(path)}")
    print(f"SELF_SHA256 {payload['approval_sha256']}")
    print("AUTHORITY_GRANTED False")
    print("SEED_RESOLUTION_OR_RESERVATION False")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
