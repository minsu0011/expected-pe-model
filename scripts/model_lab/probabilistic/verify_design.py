from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify exact probabilistic design bytes")
    parser.add_argument("--repo-root", type=Path, default=_root())
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.binding import (
        LOCKED_FEATURE_SIDECAR_SHA256,
        feature_sidecar,
        verify_implementation_binding,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
    )

    design = root / "outputs/model_zoo_probabilistic_wave_design_20260819/DESIGN.json"
    verify_implementation_binding(design_path=design, sidecar=feature_sidecar())
    print(
        json.dumps(
            {
                "status": "PASS",
                "design_sha256": PROBABILISTIC_DESIGN_SHA256,
                "feature_sidecar_sha256": LOCKED_FEATURE_SIDECAR_SHA256,
                "score_free": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
