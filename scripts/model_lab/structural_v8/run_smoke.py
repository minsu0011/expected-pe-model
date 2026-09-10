"""Cheap score-free synthetic executability smoke for Structural V8."""

# ruff: noqa: E402 -- dependency verification precedes numerical imports.

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
for _path in (ROOT, SRC):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

OUTPUT = ROOT / "outputs/model_zoo_structural_v8_smoke_20260820"


def main() -> int:
    from research.model_zoo.structural_v8.post_freeze_pins import (
        DEPENDENCY_MANIFEST_RAW_SHA256,
        DESIGN_LOCK_RAW_SHA256,
        PREFLIGHT_RAW_SHA256,
        load_design_lock,
        load_preflight,
        verify_dependency_freeze,
    )

    dependency_receipt = verify_dependency_freeze(ROOT)
    from research.model_zoo.aggressive_lab.full_load_resources import (
        seal_full_load_process,
    )

    resource_receipt = seal_full_load_process(outer_workers=1)
    design = load_design_lock(ROOT)
    preflight = load_preflight(ROOT)
    import numpy as np
    import pandas as pd

    from research.model_zoo.structural_v8.contracts import (
        COMMON_FEATURE_COLUMNS,
        CURRENT_REGIME_PROBABILITY_COLUMNS,
        REGIME_PROBABILITY_COLUMNS,
        seal_payload,
        sha256_file,
    )
    from research.model_zoo.structural_v8.models import (
        fit_predict_hierarchical_regime_ridge,
        fit_predict_local_linear_analogue,
        fit_predict_rbf_nystroem_residual,
        fixed_causal_regime_gated_residual_blend,
    )

    row_count = 260
    test_count = 8
    index = np.arange(row_count + test_count, dtype=np.float64)
    columns = sorted(
        set(COMMON_FEATURE_COLUMNS)
        | set(REGIME_PROBABILITY_COLUMNS)
        | set(CURRENT_REGIME_PROBABILITY_COLUMNS)
    )
    values = {
        column: np.sin(index / (7.0 + (column_index % 11)))
        + 0.01 * column_index * np.cos(index / 19.0)
        for column_index, column in enumerate(columns)
    }
    frame = pd.DataFrame(values)
    phase = (index.astype(int) // 40) % 3
    probabilities = np.full((len(index), 3), 0.1, dtype=np.float64)
    probabilities[np.arange(len(index)), phase] = 0.8
    for column_index, column in enumerate(REGIME_PROBABILITY_COLUMNS):
        frame[column] = probabilities[:, column_index]
    for column_index, column in enumerate(CURRENT_REGIME_PROBABILITY_COLUMNS):
        frame[column] = probabilities[:, column_index]
    train = frame.iloc[:row_count].reset_index(drop=True)
    test = frame.iloc[row_count:].reset_index(drop=True)
    train_incumbent = 20.0 + 0.15 * np.sin(index[:row_count] / 13.0)
    observed = train_incumbent * np.exp(
        0.02 * np.sin(index[:row_count] / 17.0)
        + 0.01 * (phase[:row_count] - 1)
    )
    test_incumbent = 20.0 + 0.15 * np.sin(index[row_count:] / 13.0)
    outputs = {}
    outputs["local_analogue"], local_receipt = fit_predict_local_linear_analogue(
        train,
        observed,
        train_incumbent,
        test,
        test_incumbent,
        feature_columns=COMMON_FEATURE_COLUMNS,
    )
    outputs["hierarchical"], hierarchical_receipt = (
        fit_predict_hierarchical_regime_ridge(
            train,
            observed,
            test,
            test_incumbent,
            feature_columns=COMMON_FEATURE_COLUMNS,
        )
    )
    outputs["rbf"], rbf_receipt = fit_predict_rbf_nystroem_residual(
        train,
        observed,
        train_incumbent,
        test,
        test_incumbent,
        feature_columns=COMMON_FEATURE_COLUMNS,
        random_state=8068,
    )
    common_component = test_incumbent * np.exp(0.01)
    regime_component = test_incumbent * np.exp(-0.01)
    outputs["fixed_gate"], gate_receipt = fixed_causal_regime_gated_residual_blend(
        test,
        test_incumbent,
        common_component,
        regime_component,
    )
    if any(
        len(output) != test_count
        or not (np.isfinite(output) & (output > 0.0)).all()
        for output in outputs.values()
    ):
        raise RuntimeError("Structural V8 synthetic smoke output is invalid")
    if OUTPUT.exists():
        raise FileExistsError(f"immutable Structural V8 smoke exists: {OUTPUT}")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v8_score_free_synthetic_smoke",
            "status": "PASS_SCORE_FREE_SYNTHETIC_ONLY",
            "design_lock_raw_sha256": DESIGN_LOCK_RAW_SHA256,
            "dependency_manifest_raw_sha256": DEPENDENCY_MANIFEST_RAW_SHA256,
            "preflight_raw_sha256": PREFLIGHT_RAW_SHA256,
            "design_manifest_sha256": design["manifest_sha256"],
            "preflight_manifest_sha256": preflight["manifest_sha256"],
            "synthetic_train_rows": row_count,
            "synthetic_test_rows": test_count,
            "family_receipts": {
                "local_analogue": local_receipt.detail,
                "hierarchical": hierarchical_receipt.detail,
                "rbf": rbf_receipt.detail,
                "fixed_gate": gate_receipt.detail,
            },
            "output_finite_positive": {name: True for name in outputs},
            "real_spent_fit_calls_executed": 0,
            "real_prediction_rows_generated": 0,
            "evaluation_truth_opened": False,
            "scores_computed": False,
            "resource_receipt": resource_receipt.as_dict(),
            "dependency_receipt": dependency_receipt.as_dict(),
        }
    )
    OUTPUT.mkdir(parents=True)
    raw = json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False).encode(
        "utf-8"
    ) + b"\n"
    path = OUTPUT / "SMOKE.json"
    path.write_bytes(raw)
    (OUTPUT / "REPORT.md").write_text(
        "# Structural V8 Synthetic Smoke\n\n"
        "All four locked family paths returned finite positive outputs on a small "
        "synthetic surface. No spent-data fit, truth access, or score occurred.\n",
        encoding="utf-8",
        newline="\n",
    )
    print(sha256_file(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
