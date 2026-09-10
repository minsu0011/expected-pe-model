"""Create a fresh dual-format registry containing only the plumbing baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from pe_regime_v04.model_lab import (  # noqa: E402
    ModelRegistration,
    RegistryPaths,
    write_model_registry,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    registration = ModelRegistration(
        model_id="historical_geometric_mean_pe",
        family="baseline",
        variant="expanding_geometric_mean",
        version="1",
        registry_revision=0,
        track="B",
        estimand="historical geometric mean of positive finite PIT observed P/E",
        external_reference=False,
        paper=None,
        repository=None,
        package=None,
        license=None,
        target="observed_pe",
        feature_set="constant_no_features",
        uses_same_row_price=False,
        uses_same_row_observed_pe=False,
        causal=False,
        pit_safe=True,
        train_window="expanding_all_available",
        refit_frequency="each_pit_fold",
        hyperparameters={},
        tuning_status="UNTESTED",
        locked_status="UNTESTED",
        heldout_status="NOT_OPENED",
        fair_log_mae=None,
        fair_log_rmse=None,
        worst_seed=None,
        compute_time=None,
        status="UNTESTED",
        notes="Plumbing baseline only; not promotion eligible.",
        entrypoint="pe_regime_v04.model_lab.baselines:HistoricalGeometricMeanPE",
        feature_ids=(),
        prediction_name="expected_pe",
        output_semantics="constant geometric mean of positive finite PIT observed P/E",
        deterministic=True,
        description="Dependency-light plumbing baseline; not eligible for production promotion",
        parameters_sha256=("44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    )
    paths = RegistryPaths(
        args.output_directory / "model_registry.csv",
        args.output_directory / "model_registry.json",
    )
    snapshot = write_model_registry(paths, [registration])
    print(
        json.dumps(
            {
                "status": "PASS",
                "record_count": snapshot.record_count,
                "logical_sha256": snapshot.logical_sha256,
                "csv_sha256": snapshot.csv_sha256,
                "json_sha256": snapshot.json_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
