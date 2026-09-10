"""One score-free new-input comparator-chain integration smoke."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from research.model_zoo.aggressive_lab.resources import seal_battleground_process


SMOKE_SEED = 2026082099


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--design-lock-sha256", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/model_zoo_dgp_exploration_v2_comparator_smoke_20260820"),
    )
    args = parser.parse_args()
    resource = seal_battleground_process(outer_workers=1)

    # Import model/runtime libraries only after affinity, threads, and GPU are sealed.
    import numpy as np
    import pandas as pd

    from research.model_zoo.dgp_exploration_v2.artifacts import (
        canonical_csv_bytes,
        require_isolated_output,
        sha256_bytes,
        write_checksums,
        write_json,
    )
    from research.model_zoo.dgp_exploration_v2.generator import generate_dgp
    from research.model_zoo.dgp_exploration_v2.incumbent import (
        CHILD_RESOURCE_ENVIRONMENT,
        run_research_comparator_chain,
    )
    from research.model_zoo.dgp_exploration_v2.runner import repository_root, verify_precommit

    verify_precommit(args.design_lock_sha256)
    output = require_isolated_output(args.output, repository_root=repository_root())
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("smoke output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    generated = generate_dgp("A", master_seed=SMOKE_SEED)
    public = generated.public
    legacy_hash = str(generated.generation_audit["legacy_generator_combined_sha256"])
    public_hashes = dict(generated.generation_audit["public_logical_sha256"])
    # The simulator constructed evaluator-only frames, but this adapter is given
    # only the public mapping and a non-truth generator code hash.
    del generated
    comparators, comparator_receipt = run_research_comparator_chain(
        public,
        legacy_generator_combined_sha256=legacy_hash,
    )
    verify_precommit(args.design_lock_sha256)
    window = comparators.iloc[504:]
    for column in ("ml_expected_pe", "v04_expected_pe"):
        values = pd.to_numeric(window[column], errors="coerce").to_numpy(dtype=np.float64)
        if not (np.isfinite(values).all() and (values > 0.0).all()):
            raise RuntimeError(f"score-free comparator smoke lacks coverage: {column}")
    prediction_raw = canonical_csv_bytes(comparators)
    receipt = {
        "schema_version": "expected_pe_dgp_exploration_v2.comparator_smoke.v1",
        "status": "PASS_SCORE_FREE_NEW_INPUT_COMPARATOR_CHAIN",
        "labels": ["EXPLORATION_ONLY", "NOT_PROMOTION_EVIDENCE"],
        "design_lock_raw_sha256": args.design_lock_sha256,
        "dgp": "A",
        "seed": SMOKE_SEED,
        "rows": len(comparators),
        "score_window_rows": len(window),
        "prediction_raw_sha256": sha256_bytes(prediction_raw),
        "public_logical_sha256": public_hashes,
        "child_environment_expected": CHILD_RESOURCE_ENVIRONMENT,
        "child_environment_probe": comparator_receipt["child_environment_probe"],
        "all_five_thread_variables_one": comparator_receipt[
            "all_five_thread_variables_one"
        ],
        "both_gpu_variables_sealed": comparator_receipt["both_gpu_variables_sealed"],
        "simulator_constructed_evaluator_namespace": True,
        "prediction_adapter_received_public_mapping_only": True,
        "truth_frame_accessed_by_smoke": False,
        "truth_score_computed": False,
        "candidate_fit_executed": False,
        "physical_production_custody_claimed": False,
        "old_sealed_dgp_implementation_status": "NO_GO_NOT_RESEALED",
        "resource_receipt": resource.as_dict(),
        "elapsed_seconds": time.perf_counter() - started,
        "comparator_receipt": comparator_receipt,
    }
    write_json(output / "SMOKE_RECEIPT.json", receipt)
    checksums = write_checksums(output)
    print(json.dumps({**receipt, "checksums_raw_sha256": checksums}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
