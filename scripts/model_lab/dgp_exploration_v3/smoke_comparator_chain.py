"""Score-free DGP-A smoke for the isolated V3 comparator replay adapter."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from research.model_zoo.aggressive_lab.full_load_resources import seal_full_load_process


SMOKE_SEED = 2026082099


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--common-full-load-lock-sha256", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs/model_zoo_dgp_exploration_v3_comparator_smoke_20260820"),
    )
    args = parser.parse_args()
    resource = seal_full_load_process(outer_workers=1)

    # Numerical/model imports occur only after the common full-load seal.
    from research.model_zoo.dgp_exploration_v2.generator import generate_dgp
    from research.model_zoo.dgp_exploration_v3.artifacts import (
        require_isolated_output,
        write_checksums,
        write_json,
    )
    from research.model_zoo.dgp_exploration_v3.precommit import (
        load_common_full_load_lock,
        repository_root,
    )
    from research.model_zoo.dgp_exploration_v3.replay_adapter import (
        capture_replay_inventory,
        run_research_comparator_replay,
    )

    root = repository_root()
    load_common_full_load_lock(
        root=root,
        expected_raw_sha256=args.common_full_load_lock_sha256,
    )
    output = require_isolated_output(args.output, repository_root=root)
    if output.exists() and any(output.iterdir()):
        raise RuntimeError("V3 smoke output must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    expected_inventory = capture_replay_inventory(root=root)
    generated = generate_dgp("A", master_seed=SMOKE_SEED)
    public = generated.public
    public_hashes = dict(generated.generation_audit["public_logical_sha256"])
    # The simulator constructs evaluator-only frames, but this smoke discards
    # the container and passes only the public mapping to the adapter.
    del generated
    comparators, comparator_receipt = run_research_comparator_replay(
        public,
        expected_inventory=expected_inventory,
        outer_workers=1,
    )
    load_common_full_load_lock(
        root=root,
        expected_raw_sha256=args.common_full_load_lock_sha256,
    )
    receipt = {
        "schema_version": "expected_pe_dgp_exploration_v3.comparator_smoke.v1",
        "status": "PASS_SCORE_FREE_DGP_A_RESEARCH_COMPARATOR_REPLAY",
        "labels": ["EXPLORATION_ONLY", "NOT_PROMOTION_EVIDENCE"],
        "production_authority": False,
        "common_full_load_lock_raw_sha256": args.common_full_load_lock_sha256,
        "dgp": "A",
        "seed": SMOKE_SEED,
        "rows": len(comparators),
        "public_logical_sha256": public_hashes,
        "replay_inventory_combined_sha256": expected_inventory["combined_sha256"],
        "simulator_constructed_evaluator_namespace": True,
        "prediction_adapter_received_public_mapping_only": True,
        "truth_frame_accessed_by_smoke": False,
        "truth_score_computed": False,
        "candidate_fit_executed": False,
        "physical_production_custody_claimed": False,
        "production_attestation_used": False,
        "production_registry_modified": False,
        "production_champion_modified": False,
        "fresh_or_heldout_authority": False,
        "old_production_implementation_status": "NO_GO_NOT_RESEALED",
        "parent_full_load_resource": resource.as_dict(),
        "comparator_backend": "CPU",
        "comparator_gpu_selected": False,
        "comparator_child_gpu_sealed_off": True,
        "elapsed_seconds": time.perf_counter() - started,
        "comparator_receipt": comparator_receipt,
    }
    write_json(output / "SMOKE_RECEIPT.json", receipt)
    checksums = write_checksums(output)
    print(json.dumps({**receipt, "checksums_raw_sha256": checksums}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
