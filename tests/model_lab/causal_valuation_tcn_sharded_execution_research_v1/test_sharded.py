from __future__ import annotations

import ast

from research.model_zoo.causal_valuation_tcn_sharded_execution_research_v1 import (
    contracts,
)


PACKAGE = (
    contracts.project_root()
    / "research/model_zoo/causal_valuation_tcn_sharded_execution_research_v1"
)


def test_frozen_v1_source_closure_and_research_authority() -> None:
    payload = contracts.contract_payload()
    assert payload["v1_source_closure"]["contract_sha256"] == (
        "7d0dc4a4d6892619d82368f4000dac5d8c105e3358c2ef5687112ff66ee48db8"
    )
    assert payload["v1_source_closure"][
        "runtime_source_manifest_semantic_sha256"
    ] == "302e75e9b39911310576b43a24bad4484da143ce19d756abd6d68b03899e7824"
    assert payload["selected_batch_size"] == 64
    assert payload["formal_v8_identity_created_or_consumed"] is False
    assert payload["authority"] == {
        "research_only": True,
        "truth": False,
        "score": False,
        "fresh": False,
        "heldout": False,
        "promotion": False,
        "full_predictions": False,
    }


def test_smoke_and_full_fold_ownership_are_exact_and_disjoint() -> None:
    smoke = contracts.SMOKE_SHARD_ASSIGNMENTS
    smoke_folds = [fold for values in smoke.values() for fold in values]
    assert smoke_folds == ["fold_012", "fold_043", "fold_073"]
    assert len(smoke_folds) == len(set(smoke_folds))
    full = contracts.full_cost_balanced_shard_map()
    fold_ids = [fold for values in full["shards"].values() for fold in values]
    assert len(fold_ids) == 62
    assert len(set(fold_ids)) == 62
    assert sorted(fold_ids) == [f"fold_{number:03d}" for number in range(12, 74)]
    totals = [
        item["numerator"] / item["denominator"] for item in full["cost_totals"]
    ]
    assert max(totals) / min(totals) < 1.01


def test_design_lock_is_fail_closed_before_smoke() -> None:
    lock = contracts.design_lock_payload()
    assert lock["status"] == "LOCKED_BEFORE_EQUIVALENCE_SMOKE"
    assert lock["reference_aggregate_digest_sha256"] == (
        "f3720533e491bc6eb55d6ebf197811f62fe88353c87c18a0499b3904a8e1e769"
    )
    assert lock["acceptance_policy"]["aggregate_digest_exact"] is True
    assert lock["acceptance_policy"][
        "each_fold_deterministic_metrics_exact"
    ] is True
    assert lock["acceptance_policy"]["all_resource_caps_pass"] is True
    assert lock["failure_policy"]["full_run_allowed"] is False
    assert lock["success_policy"]["full_run_allowed"] is False
    merged = lock["merged_artifact_contract"]
    assert merged["expected_rows"] == 64_800
    assert merged["canonical_merge_order"] == [
        "seed",
        "dgp_id",
        "session_position",
    ]
    assert merged["identity_overlap"] == 0
    assert merged["identity_gaps"] == 0


def test_public_parent_surface_never_imports_torch_or_private_workers() -> None:
    for name in ("__init__.py", "contracts.py", "ipc.py", "runner.py"):
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert not any(value == "torch" or value.startswith("torch.") for value in imports)
        assert not any("_private_worker" in value for value in imports)
        assert not any("_private_shard_worker" in value for value in imports)


def test_private_shard_has_no_state_serialization_or_truth_surface() -> None:
    source = (PACKAGE / "_private_shard_worker.py").read_text(encoding="utf-8")
    assert "core._fit_private_model" in source
    assert "core._predict_rows" in source
    assert '"serialized_model_state_files": 0' in source
    assert '"truth_accessed": False' in source
    assert '"score_computed": False' in source
    assert "torch.save" not in source
    assert "state_dict" not in source
    assert ".pt\"" not in source


def test_runner_has_guard_and_no_full_command() -> None:
    source = (PACKAGE / "runner.py").read_text(encoding="utf-8")
    assert 'subparsers.add_parser("prepare-equivalence")' in source
    assert 'subparsers.add_parser("equivalence-smoke")' in source
    assert "--acknowledge-three-concurrent-private-cuda-children" in source
    assert 'add_parser("full")' not in source
