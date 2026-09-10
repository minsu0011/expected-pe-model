"""Score-blind two-process smoke on the already-spent 2026082001:A task."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import json
import multiprocessing
from pathlib import Path


ACTIVATION_LITERAL = "SMOKE_DGP_STATE_TOURNAMENT_V1_SPENT_A_PUBLIC_ONLY"
DEFAULT_OUTPUT = Path("outputs/model_zoo_dgp_state_tournament_v1_smoke_20260820")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--activation", required=True)
    args = parser.parse_args()
    if args.activation != ACTIVATION_LITERAL:
        raise RuntimeError("exact score-blind smoke activation literal is absent")

    from research.model_zoo.dgp_state_tournament_v1.resources import (
        seal_input_freeze_process,
    )

    launch_resource = seal_input_freeze_process(outer_workers=1)

    import numpy as np
    import pandas as pd

    from research.model_zoo.dgp_state_tournament_v1.artifacts import (
        canonical_json_bytes,
        canonical_value_sha256,
        sha256_bytes,
        write_checksums_new,
        write_json_new,
    )
    from research.model_zoo.dgp_state_tournament_v1.contracts import (
        EVIDENCE_CLASS,
        PUBLIC_NAMES,
        V3_PREDICTIONS_RELATIVE_PATH,
    )
    from research.model_zoo.dgp_state_tournament_v1.precommit import (
        load_and_verify_v3_bindings,
        repository_root,
    )
    from research.model_zoo.dgp_state_tournament_v1.runner import _produce_task

    root = repository_root()
    output = (root / args.output).resolve()
    if (
        output.parent != (root / "outputs").resolve()
        or not output.name.startswith("model_zoo_dgp_state_tournament_v1_smoke_")
    ):
        raise RuntimeError("smoke output escaped its exact isolated namespace")
    if output.exists():
        raise RuntimeError("immutable smoke output already exists")
    lock, receipt = load_and_verify_v3_bindings(root)
    expected_public = receipt["generation_public_hash_by_task"]["2026082001:A"]
    arguments = {
        "seed": 2026082001,
        "dgp_id": "A",
        "outer_workers": 1,
        "expected_public_logical_sha256": expected_public,
        "replay_inventory": lock["replay_inventory"],
        "expected_child_runtime": lock["child_runtime_reference"],
    }
    passes = []
    for _ in (1, 2):
        with ProcessPoolExecutor(
            max_workers=1,
            mp_context=multiprocessing.get_context("spawn"),
        ) as executor:
            passes.append(executor.submit(_produce_task, **arguments).result())
    first, second = passes
    comparisons = {
        f"public/{name}.csv": first["public_raw"][name] == second["public_raw"][name]
        for name in PUBLIC_NAMES
    }
    comparisons.update(
        {
            "canonical150.csv": first["canonical_raw"] == second["canonical_raw"],
            "v04_overlay.csv": first["overlay_raw"] == second["overlay_raw"],
            "comparator_diagnostics.csv": (
                first["diagnostics_raw"] == second["diagnostics_raw"]
            ),
            "normalized_replay_receipt": (
                first["replay_receipt_raw"] == second["replay_receipt_raw"]
            ),
            "geometry": canonical_json_bytes(first["geometry"])
            == canonical_json_bytes(second["geometry"]),
        }
    )
    if not all(comparisons.values()):
        raise RuntimeError("score-blind smoke replay bytes differ")

    diagnostics = pd.read_csv(
        pd.io.common.BytesIO(first["diagnostics_raw"]),
        float_precision="round_trip",
    )
    predictions = pd.read_csv(
        root / V3_PREDICTIONS_RELATIVE_PATH,
        float_precision="round_trip",
    )
    predictions = predictions.loc[
        predictions["seed"].eq(2026082001)
        & predictions["dgp"].eq("A")
        & predictions["model_id"].isin(("ml_expected_pe", "v04_expected_pe"))
    ].copy()
    anchor_results = {}
    for model_id, column in (
        ("ml_expected_pe", "ml_expected_pe_lag1_incumbent"),
        ("v04_expected_pe", "v04_expected_pe_lag1_incumbent"),
    ):
        expected = predictions.loc[predictions["model_id"].eq(model_id)]
        merged = expected.merge(
            diagnostics.loc[:, ["date", "row_position", column]],
            on=["date", "row_position"],
            how="inner",
            validate="one_to_one",
        )
        left = merged["prediction"].to_numpy(dtype=np.float64)
        right = merged[column].to_numpy(dtype=np.float64)
        if len(merged) != 378 or not np.array_equal(left.view(np.uint64), right.view(np.uint64)):
            raise RuntimeError(f"smoke {model_id} V3 anchor parity differs")
        anchor_results[model_id] = {
            "rows": len(merged),
            "bitwise_equal": True,
            "max_absolute_difference": float(np.max(np.abs(left - right))),
        }
    output.mkdir(parents=True, exist_ok=False)
    smoke_receipt = {
        "schema_version": "expected_pe_dgp_state_tournament_v1.smoke.v1",
        "status": "PASS_SCORE_BLIND_DOUBLE_REPLAY_SPENT_2026082001_A",
        "evidence_class": EVIDENCE_CLASS,
        "production_authority": False,
        "fresh_or_heldout_authority": False,
        "seed": 2026082001,
        "dgp": "A",
        "passes": 2,
        "fresh_process_pool_lifetimes": 2,
        "comparator_child_stages": 4,
        "public_expected_logical_sha256": expected_public,
        "public_expected_semantic_sha256": canonical_value_sha256(expected_public),
        "byte_exact_comparisons": comparisons,
        "canonical150_raw_sha256": sha256_bytes(first["canonical_raw"]),
        "v04_overlay_raw_sha256": sha256_bytes(first["overlay_raw"]),
        "comparator_diagnostics_raw_sha256": sha256_bytes(first["diagnostics_raw"]),
        "normalized_replay_receipt_raw_sha256": sha256_bytes(
            first["replay_receipt_raw"]
        ),
        "geometry": first["geometry"],
        "v3_incumbent_anchor_parity": anchor_results,
        "launch_resource": launch_resource.as_dict(),
        "pass_resource": {
            "pass_1": {
                "before": first["resource_before"],
                "after": first["resource_after"],
            },
            "pass_2": {
                "before": second["resource_before"],
                "after": second["resource_after"],
            },
        },
        "simulator_public_and_evaluator_namespaces_constructed": 2,
        "evaluator_mapping_accessed": False,
        "truth_file_read": False,
        "truth_value_selected": False,
        "score_computed": False,
        "candidate_or_survivor_fit_executed": False,
        "legacy_formal_execution_used": False,
        "old_production_implementation_status": "NO_GO_NOT_RESEALED",
    }
    receipt_sha = write_json_new(output / "SMOKE_RECEIPT.json", smoke_receipt)
    checksums_sha = write_checksums_new(output)
    print(
        json.dumps(
            {
                "status": smoke_receipt["status"],
                "smoke_receipt_raw_sha256": receipt_sha,
                "checksums_raw_sha256": checksums_sha,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
