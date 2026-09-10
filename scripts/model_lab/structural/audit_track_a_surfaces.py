"""Seal the score-free Track-A six-audit evidence for all five input surfaces."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "outputs/model_zoo_structural_wave_screen_20260819/TRACK_A_DATA_BOUND_AUDIT.json"
        ),
    )
    args = parser.parse_args()
    root = _project_root()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.structural.contracts import canonical_json_bytes
    from pe_regime_v04.model_lab.structural.track_a_audit import (
        audit_five_track_a_surfaces,
    )

    output = (root / args.output).resolve() if not args.output.is_absolute() else args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite sealed Track-A audit: {output}")
    payload = audit_five_track_a_surfaces(root)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_bytes(canonical_json_bytes(payload) + b"\n")
    temporary.replace(output)
    print(
        json.dumps(
            {
                "path": output.relative_to(root).as_posix(),
                "manifest_sha256": payload["manifest_sha256"],
                "surface_count": payload["surface_count"],
                "all_pass": payload["all_5_surfaces_all_6_audits_pass"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
