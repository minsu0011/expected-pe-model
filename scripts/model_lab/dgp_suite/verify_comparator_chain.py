"""Run one score-free exact v0.3->v0.4 comparator-chain integration."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

import pandas as pd

from research.model_zoo.dgp_suite import (
    FIXTURE_MASTER_SEED,
    DGPContractError,
    ExactComparatorPipeline,
    FixtureSeed,
    align_primary_comparators,
    generate_dgp,
    prepare_primary_candidate_surface,
    validate_canonical150_output,
    write_dgp_artifacts,
)
from research.model_zoo.dgp_suite.primary_surface import _transform_canonical_components


def _verify_interventions(canonical: pd.DataFrame) -> None:
    baseline = _transform_canonical_components(canonical)
    row = 600

    changed_market = canonical.copy()
    changed_market.loc[row, "close"] = float(canonical.loc[row, "close"]) * 10.0
    market_surface = _transform_canonical_components(changed_market)
    if (
        market_surface.features.loc[row, "close__pit_lag1"]
        != baseline.features.loc[row, "close__pit_lag1"]
    ):
        raise RuntimeError("same-session close entered the primary candidate surface")
    if market_surface.features.loc[row + 1, "close__pit_lag1"] != changed_market.loc[row, "close"]:
        raise RuntimeError("prior-session close was not exposed on the next session")

    changed_observed = canonical.copy()
    changed_observed.loc[row, "observed_pe"] = float(canonical.loc[row, "observed_pe"]) * 10.0
    observed_surface = _transform_canonical_components(changed_observed)
    if (
        observed_surface.features.loc[row, "observed_pe__pit_lag1"]
        != baseline.features.loc[row, "observed_pe__pit_lag1"]
    ):
        raise RuntimeError("same-session observed P/E entered candidate features")

    future_filing = canonical.copy()
    date = pd.Timestamp(future_filing.loc[row, "date"]).tz_localize("UTC")
    future_filing.loc[row, "available_at"] = (
        date + pd.Timedelta(hours=12, minutes=30, seconds=1)
    ).isoformat()
    try:
        _transform_canonical_components(future_filing)
    except DGPContractError:
        pass
    else:
        raise RuntimeError("post-cutoff filing was accepted by the primary surface")


def main() -> int:
    seed = FixtureSeed(FIXTURE_MASTER_SEED)
    with tempfile.TemporaryDirectory(prefix="pe_dgp_comparator_chain_") as temporary:
        generated = generate_dgp("B", fixture_seed=seed)
        artifact_root = Path(temporary) / "DGP_B"
        write_dgp_artifacts(generated, artifact_root)
        comparator = ExactComparatorPipeline().produce(
            artifact_root,
            master_seed=FIXTURE_MASTER_SEED,
            dgp_id="B",
        )
        validate_canonical150_output(comparator)
        aligned = align_primary_comparators(comparator)
        if (
            tuple(aligned.columns)
            != (
                "seed",
                "dgp_id",
                "date",
                "v03_prediction",
                "v04_prediction",
            )
            or len(aligned) != 1800
        ):
            raise RuntimeError("exact comparator alignment schema/coverage mismatch")
        surface = prepare_primary_candidate_surface(comparator)
        if "close" in surface.features or "observed_pe" in surface.features:
            raise RuntimeError("unlagged market data entered the primary surface")
        _verify_interventions(comparator.canonical_frame())
        try:
            align_primary_comparators(
                pd.DataFrame(
                    {
                        "date": ["2015-01-02"],
                        "ml_expected_pe": [999.0],
                        "v04_expected_pe": [777.0],
                    }
                )
            )
        except DGPContractError:
            pass
        else:
            raise RuntimeError("name-only comparator DataFrame crossed the exact boundary")
        output = {
            "candidate_score_computed": False,
            "comparator_receipt_sha256": comparator.receipt_sha256,
            "dgp_id": comparator.dgp_id,
            "master_seed": comparator.master_seed,
            "model_lab_candidate_executed": False,
            "primary_surface_content_sha256": surface.surface_content_sha256,
            "primary_transformation_sha256": surface.transformation_sha256,
            "receipt": comparator.receipt,
            "truth_read_or_merged": False,
        }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
