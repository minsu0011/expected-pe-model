"""Run the dependency-frozen Structural V7 V2 no-fit preflight."""

# ruff: noqa: E402 -- dependency verification precedes resource/numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


OUTPUT = ROOT / "outputs/model_zoo_structural_v7_preflight_v2_20260820"
EXPECTED_OUTER_SCHEDULE_SHA256 = (
    "fe6f8038ded6f880cb885489278e02be484caf0a5f113df6e903fb3a1dcd111a"
)


def main() -> int:
    from research.model_zoo.structural_v7.post_freeze_pins_v2 import (
        DESIGN_LOCK_V2_RAW_SHA256,
        load_design_lock_v2,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.resources import seal_battleground_process

    resource_receipt = seal_battleground_process(outer_workers=1)
    load_design_lock_v2(ROOT)
    from research.model_zoo.structural_v7.contracts import seal_payload, sha256_file
    from research.model_zoo.structural_v7.preflight import run_no_fit_preflight

    report = run_no_fit_preflight(
        ROOT, v7_design_lock_raw_sha256=DESIGN_LOCK_V2_RAW_SHA256
    )
    base = dict(report.payload)
    base.pop("manifest_sha256", None)
    if (
        base.get("hard_failure_count") != 0
        or base.get("base_fit_call_count") != 740
        or base.get("candidate_outer_consumer_edge_count") != 3100
        or base.get("outer_schedule_sha256") != EXPECTED_OUTER_SCHEDULE_SHA256
        or base.get("minimum_meta_usable_label_rows") != 252
        or base.get("minimum_structural_usable_label_rows") != 502
    ):
        raise RuntimeError("Structural V7 V2 exact no-fit preflight identity changed")
    base.update(
        {
            "format_version": 2,
            "mode": "structural_v7_dependency_frozen_all_calls_no_fit_preflight_v2",
            "status": "GO_V2_NO_FIT_DEPENDENCY_FROZEN_HEAVY_LAUNCH_BLOCKED",
            "dependency_manifest_raw_sha256": (
                dependency_receipt.manifest_raw_sha256
            ),
            "dependency_verification_receipt": dependency_receipt.as_dict(),
            "resource_receipt": resource_receipt.as_dict(),
            "evaluation_identity_contract": {
                "seed_count": 5,
                "rows_per_seed_model": 1296,
                "outer_schedule_sha256": EXPECTED_OUTER_SCHEDULE_SHA256,
                "must_pass_before_truth_open": True,
            },
            "minimum_train_rationale_v2": {
                "hard_min_role": "exploration executability floor only",
                "spline_expansion": (
                    "cubic four-knot SplineTransformer materially expands dimensions; "
                    "Ridge alpha=10 regularizes the expanded design"
                ),
                "empirical_usable_base_meta_structural": [250, 252, 502],
                "margin_below_empirical_minimum": 50,
                "parameter_sample_sufficiency_claim": False,
            },
        }
    )
    payload = seal_payload(base)
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V7 V2 preflight exists: {OUTPUT}")
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "PREFLIGHT_V2.json"
    path.write_bytes(raw)
    text = (
        "# Structural V7 V2 Dependency-Frozen No-Fit Preflight\n\n"
        f"- Status: `{payload['status']}`\n"
        "- Base calls / candidate-outer edges: 740 / 3,100.\n"
        "- Minimum usable base/meta/structural: 250 / 252 / 502.\n"
        "- Hard failures: 0; preferred-min exceptions: 10.\n"
        "- Fit/prediction/truth/score: 0 / 0 / 0 / 0.\n"
        "- Exact evaluator outer schedule hash is bound; heavy launch remains blocked.\n"
    )
    (OUTPUT / "REPORT.md").write_text(text, encoding="utf-8", newline="\n")
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
