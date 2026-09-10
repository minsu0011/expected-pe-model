from __future__ import annotations

import argparse
import io
import os
from pathlib import Path
import pickle
import sys
import time


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run score-free adapter serialization replay")
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--include-ngboost", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for key, value in {
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
        "CUDA_VISIBLE_DEVICES": "",
    }.items():
        os.environ[key] = value
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    import numpy as np
    import pandas as pd

    from pe_regime_v04.model_lab.contracts import FitContext, PredictContext
    from pe_regime_v04.model_lab.probabilistic.adapters import create_adapter
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.contracts import sha256_bytes
    from pe_regime_v04.model_lab.probabilistic.spec import FEATURE_COLUMNS, feature_metadata

    rng = np.random.default_rng(20260819)
    x = pd.DataFrame(rng.normal(size=(336, len(FEATURE_COLUMNS))), columns=FEATURE_COLUMNS)
    y = pd.Series(
        np.exp(2.7 + 0.05 * x[FEATURE_COLUMNS[0]].to_numpy() + rng.normal(0.0, 0.12, len(x))),
        name="observed_pe",
    )
    fit_context = FitContext(
        experiment_id="score-free-serialization-replay",
        fold_id="synthetic_fold",
        seed=0,
        train_end=pd.Timestamp("2020-12-31"),
        target_name="observed_pe",
        feature_metadata=feature_metadata(),
    )
    predict_context = PredictContext(
        experiment_id="score-free-serialization-replay",
        fold_id="synthetic_fold",
        seed=0,
        prediction_start=pd.Timestamp("2021-01-01"),
        prediction_end=pd.Timestamp("2021-02-05"),
        feature_metadata=feature_metadata(),
    )
    model_ids = ["qlinear_l1_with_regime_v1", "qhistgb_with_regime_v1"]
    if args.include_ngboost:
        model_ids.append("ngboost_normal_crps_with_regime_v1")
    records = []
    for model_id in model_ids:
        started = time.monotonic()
        model = create_adapter(model_id).fit(x.iloc[:300], y.iloc[:300], context=fit_context)
        first = model.predict(x.iloc[300:], context=predict_context)
        buffer = io.BytesIO()
        pickle.dump(model, buffer, protocol=5)
        serialized = buffer.getvalue()
        restored = pickle.loads(serialized)
        second = restored.predict(x.iloc[300:], context=predict_context)
        first_bytes = b"".join(
            [
                first.raw_log_quantiles.tobytes(),
                first.repaired_log_quantiles.tobytes(),
                first.pe_quantiles.tobytes(),
            ]
        )
        second_bytes = b"".join(
            [
                second.raw_log_quantiles.tobytes(),
                second.repaired_log_quantiles.tobytes(),
                second.pe_quantiles.tobytes(),
            ]
        )
        if first_bytes != second_bytes:
            raise RuntimeError(f"serialization replay changed predictions: {model_id}")
        records.append(
            {
                "model_id": model_id,
                "fit_attempts": model.fit_attempts,
                "serialized_model_sha256": sha256_bytes(serialized),
                "prediction_sha256_before": sha256_bytes(first_bytes),
                "prediction_sha256_after": sha256_bytes(second_bytes),
                "rows": len(x) - 300,
                "wall_seconds": time.monotonic() - started,
                "warnings": [],
                "solver_status": "PASS_ONE_ATTEMPT_NO_RETRY",
            }
        )
    payload = {
        "schema_version": "expected_pe_model_zoo.probabilistic_serialization_replay.v2",
        "status": "PASS",
        "synthetic_only": True,
        "project_predictions_generated": False,
        "project_scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
        "records": records,
    }
    output = args.output if args.output.is_absolute() else root / args.output
    immutable_write_json(output, payload)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
