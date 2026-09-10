from __future__ import annotations

import ast
import math

import numpy as np

from research.model_zoo.causal_valuation_tcn_private_process_research_v1 import (
    contracts,
)
from research.model_zoo.causal_valuation_tcn_private_process_research_v1.public_adapter import (
    _load_one_task,
    strict_lag1_proxy,
    validate_public_root,
)


PACKAGE = (
    contracts.project_root()
    / "research/model_zoo/causal_valuation_tcn_private_process_research_v1"
)


def test_global_fold_geometry_is_62_pooled_fits() -> None:
    folds = contracts.fold_definitions()
    assert len(folds) == 62
    assert sum(item.test_rows for item in folds) == 1_296
    assert folds[0].test_start_position == 504
    assert folds[-1].test_end_exclusive == 1_800
    assert folds[-1].test_rows == 15
    for fold in folds:
        assert fold.purge_end_position - fold.purge_start_position + 1 == 127
        assert fold.embargo_end_position - fold.embargo_start_position + 1 == 5
        assert fold.train_end_position < fold.purge_start_position
        assert fold.embargo_end_position < fold.test_start_position
    payload = contracts.contract_payload()
    assert payload["architecture"]["cross_entity_pooling"].startswith("50_opaque")
    assert payload["architecture"][
        "seed_or_dgp_as_model_input_router_embedding_or_loss"
    ] is False
    assert payload["fallback_policy"] == {
        "scope": "exact_global_pooled_prefix_across_opaque_entities",
        "minimum_eligible_proxy_rows": 756,
        "entity_specific_threshold": False,
        "action": "UNCHANGED_V04_CHAMPION",
    }
    optimization = payload["bounded_batch_optimization"]
    assert (
        optimization["status"]
        == "FROZEN_BATCH64_AFTER_INDEPENDENT_EXACT_SELECTED_POLICY_REPEAT"
    )
    assert optimization["full_policy_batch_size_until_qualified"] == 64
    assert optimization["provisional_throughput_batch_size"] == 1024
    assert optimization["candidates"] == [64, 256, 512, 1024]
    assert optimization["representative_global_folds"] == [
        "fold_012",
        "fold_043",
        "fold_073",
    ]
    assert optimization["epochs_per_fold"] == 2
    assert optimization["truth_or_score_access"] is False
    assert optimization["batch_64_role"] == "MEASURED_BASELINE"
    evidence = optimization["resource_evidence"]
    assert len(evidence["runs"]) == 2
    assert evidence["provisional_throughput_batch_size"] == 1024
    assert evidence["maximum_vram_bytes_by_batch"]["1024"] == 723_072_000
    assert (
        evidence["bitwise_prediction_digest_sha256_by_batch"]["1024"]
        == "ebb5847033933cda9934cd18c13f87085acb2f82069c408852039eba0769594a"
    )
    safety = optimization["convergence_safety_required_before_final_selection"]
    assert safety["candidates"] == [64, 1024]
    assert safety["epochs_max"] == 80
    assert safety["early_stopping_patience"] == 12
    assert safety["independent_exact_repeat_required"] is True
    assert safety["required_independent_runs"] == 2
    assert safety["maximum_weighted_mean_relative_huber_degradation"] == 0.01
    assert safety["maximum_any_fold_relative_huber_degradation"] == 0.03
    assert payload["training_policy"]["batch_entities"] == 64
    r1 = optimization["convergence_safety_r1_evidence"]
    assert r1["checksums_raw_sha256"] == (
        "48f656057a91e44fb820c45a76ef87d4409cfa64cf98c11e2327bbb06d511bf7"
    )
    assert r1["pinned_batch64_baseline"][
        "deterministic_result_digest_sha256"
    ] == "f3720533e491bc6eb55d6ebf197811f62fe88353c87c18a0499b3904a8e1e769"
    assert r1["pinned_rejected_batch1024"][
        "within_predeclared_quality_limits"
    ] is False
    expansion = optimization["expansion_r2_lock_policy"]
    assert expansion["candidate_batch_sizes"] == [256, 512]
    assert expansion["selection"] == "shortest_total_fit_seconds_then_larger_batch"
    assert expansion["no_eligible_fallback_batch_size"] == 64
    expansion_r2 = optimization["expansion_r2_evidence"]
    assert expansion_r2["candidate_eligibility"] == {
        "256": False,
        "512": False,
    }
    assert expansion_r2["fallback_to_pinned_batch64"] is True
    selected = optimization["selected_policy_repeat"]
    assert selected["selected_batch_size"] == 64
    assert selected["exact_r1_deterministic_repeat_required"] is True
    assert selected["full_predictions_blocked_until_accepted"] is True
    assert selected["accepted"] is True
    assert selected["evidence"]["repeat_accepted"] is True
    assert selected["evidence"]["mismatch_count"] == 0
    assert selected["evidence"]["selected_policy_repeat_raw_sha256"] == (
        "ba332a1b8259bb701993b11c9ef4b2caa832bad40b7221b12ce22f64ac7190c7"
    )
    assert selected["full_entrypoint_preparation_allowed"] is True
    assert selected["full_execution_still_requires_explicit_parent_approval"] is True
    assert payload["private_full_panel_window_cache"]["expected_resident_bytes"] == (
        5_333_760_000
    )
    assert payload["private_full_panel_window_cache"]["serialized_files"] == 0


def test_synthetic_proxy_is_strictly_earlier_and_future_invariant() -> None:
    observed = np.asarray([10.0, 11.0, np.nan, 12.0, -1.0, 13.0])
    proxy, source = strict_lag1_proxy(observed)
    assert np.isnan(proxy[0]) and source[0] == -1
    assert proxy[1] == np.float32(math.log(10.0)) and source[1] == 0
    assert proxy[2] == np.float32(math.log(11.0)) and source[2] == 1
    assert np.isnan(proxy[3]) and source[3] == -1
    assert proxy[4] == np.float32(math.log(12.0)) and source[4] == 3
    assert np.isnan(proxy[5]) and source[5] == -1
    changed = observed.copy()
    changed[4:] = [1_000.0, 2_000.0]
    changed_proxy, changed_source = strict_lag1_proxy(changed)
    np.testing.assert_array_equal(proxy[:5], changed_proxy[:5])
    np.testing.assert_array_equal(source[:5], changed_source[:5])
    finite = np.flatnonzero(np.isfinite(proxy))
    assert np.all(source[finite] == finite - 1)
    assert np.all(source[finite] < finite)


def test_exact_spent_public_task_adapter_has_no_target_leakage() -> None:
    root = validate_public_root()
    task = _load_one_task(root, 2026082001, "A")
    features = task["features"]
    proxy = task["proxy_log_pe"]
    sources = task["proxy_source_positions"]
    assert features.shape == (1_800, 42)
    assert proxy.shape == (1_800,)
    assert int(np.isfinite(proxy).sum()) == 1_797
    finite = np.flatnonzero(np.isfinite(proxy))
    np.testing.assert_array_equal(sources[finite], finite.astype(np.int32) - 1)
    assert not np.isinf(features).any()


def test_public_parent_modules_do_not_import_torch_or_private_worker() -> None:
    public_names = ("__init__.py", "contracts.py", "public_adapter.py", "ipc.py", "runner.py")
    for name in public_names:
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert not any(value == "torch" or value.startswith("torch.") for value in imports)
        assert not any("_private_worker" in value for value in imports)


def test_seed_and_dgp_are_not_used_in_private_training_surface() -> None:
    source = (PACKAGE / "_private_worker.py").read_text(encoding="utf-8")
    training = source.split("def _fit_private_model(", 1)[1].split(
        "def _predict_rows(", 1
    )[0]
    assert "panel.seeds" not in training
    assert "panel.dgps" not in training
    assert "DGP_IDS.index" not in training
    assert "nn.Embedding" not in training
    assert "nuisance" not in training.lower()


def test_private_cache_is_built_once_and_cached_batches_do_not_rebuild_windows() -> None:
    source = (PACKAGE / "_private_worker.py").read_text(encoding="utf-8")
    cached_builder = source.split("def _build_full_panel_window_cache(", 1)[1].split(
        "def _build_windows(", 1
    )[0]
    cached_batch = source.split("def _build_windows(", 1)[1].split(
        "def _to_device_batch(", 1
    )[0]
    prediction_runner = source.split("def _prediction_records(", 1)[1].split(
        "def _run_bounded_batch_microbenchmark(", 1
    )[0]
    assert "_build_windows_uncached" in cached_builder
    assert "require_valid_baseline=False" in cached_builder
    assert "np.maximum.accumulate" not in cached_batch
    assert "cache.values[task_indices, row_positions]" in cached_batch
    assert prediction_runner.count("_build_full_panel_window_cache(panel)") == 1


def test_convergence_safety_surface_is_full_policy_and_non_scoreable() -> None:
    worker = (PACKAGE / "_private_worker.py").read_text(encoding="utf-8")
    benchmark = worker.split("def _run_convergence_safety_benchmark(", 1)[1].split(
        "def _atomic_write(", 1
    )[0]
    assert "CONVERGENCE_BENCHMARK_CANDIDATES" in benchmark
    assert "FULL_TRAINING_POLICY" in benchmark
    assert '"best_proxy_huber"' in benchmark
    assert '"best_epoch"' in benchmark
    assert '"optimizer_steps"' in benchmark
    assert '"optimizer_training_samples"' in benchmark
    assert '"truth_accessed": False' in benchmark
    assert '"score_computed": False' in benchmark
    assert '"model_prediction_artifact_created": False' in benchmark
    assert "_write_predictions" not in benchmark
    runner = (PACKAGE / "runner.py").read_text(encoding="utf-8")
    assert 'subparsers.add_parser("prepare-convergence")' in runner
    assert 'subparsers.add_parser("benchmark-convergence")' in runner
    assert "--acknowledge-heavy-convergence-benchmark" in runner


def test_expansion_lock_is_predeclared_and_pins_r1_without_truth() -> None:
    lock = contracts.expansion_lock_payload()
    assert lock["status"] == "LOCKED_BEFORE_TRAINING"
    assert lock["candidate_batch_sizes"] == [256, 512]
    assert lock["fold_ids"] == ["fold_012", "fold_043", "fold_073"]
    assert lock["training_policy"]["epochs_max"] == 80
    assert lock["training_policy"]["early_stopping_patience"] == 12
    assert lock["eligibility_policy"] == {
        "maximum_weighted_mean_relative_huber_degradation": 0.01,
        "maximum_any_fold_relative_huber_degradation": 0.03,
        "vram_hard_limit_bytes": 13 * 1024**3,
        "same_or_future_target_rows": 0,
        "serialized_model_state_files": 0,
    }
    assert lock["selection_policy"]["no_eligible_fallback_batch_size"] == 64
    assert lock["authority"]["truth"] is False
    assert lock["authority"]["score"] is False
    worker = (PACKAGE / "_private_worker.py").read_text(encoding="utf-8")
    expansion = worker.split(
        "def _run_convergence_expansion_benchmark(", 1
    )[1].split("def _atomic_write(", 1)[0]
    assert "EXPANSION_BENCHMARK_CANDIDATES" in expansion
    assert "CONVERGENCE_R1_EVIDENCE" in expansion
    assert '"eligible": eligible' in expansion
    assert "_write_predictions" not in expansion
    runner = (PACKAGE / "runner.py").read_text(encoding="utf-8")
    assert 'subparsers.add_parser("prepare-expansion")' in runner
    assert 'subparsers.add_parser("benchmark-expansion")' in runner
    assert "--acknowledge-heavy-expansion-benchmark" in runner


def test_selected_repeat_lock_has_exact_acceptance_and_mismatch_rules() -> None:
    lock = contracts.selected_repeat_lock_payload()
    assert lock["status"] == "LOCKED_BEFORE_TRAINING"
    assert lock["selected_batch_size"] == 64
    assert lock["fold_ids"] == ["fold_012", "fold_043", "fold_073"]
    assert lock["training_policy"]["epochs_max"] == 80
    assert lock["training_policy"]["early_stopping_patience"] == 12
    assert lock["cache_contract"]["resident_bytes"] == 5_333_760_000
    assert lock["pinned_r1_reference"]["private_worker_raw_sha256"] == (
        "d834a7c9a444b7d148020a438d2539a6579a3064f23af801e2cb48660b9f976d"
    )
    assert lock["pinned_expansion_r2_fallback"][
        "fallback_to_pinned_batch64"
    ] is True
    assert lock["acceptance_policy"]["deterministic_result_digest_exact"] is True
    assert lock["mismatch_policy"]["status"] == (
        "REJECT_SELECTED_POLICY_REPEAT_MISMATCH"
    )
    assert lock["mismatch_policy"]["full_predictions_allowed"] is False
    assert lock["match_policy"]["full_predictions_allowed"] is False
    worker = (PACKAGE / "_private_worker.py").read_text(encoding="utf-8")
    repeat = worker.split("def _run_selected_policy_repeat(", 1)[1].split(
        "def _atomic_write(", 1
    )[0]
    assert "SELECTED_POLICY_BATCH_SIZE" in repeat
    assert "CONVERGENCE_R1_EVIDENCE" in repeat
    assert "REJECT_SELECTED_POLICY_REPEAT_MISMATCH" in repeat
    assert '"full_predictions_allowed": False' in repeat
    assert "_write_predictions" not in repeat
    runner = (PACKAGE / "runner.py").read_text(encoding="utf-8")
    assert '"prepare-selected-repeat"' in runner
    assert 'subparsers.add_parser("selected-repeat")' in runner
    assert "--acknowledge-heavy-selected-policy-repeat" in runner


def test_research_authority_and_prediction_schema_are_fail_closed() -> None:
    payload = contracts.contract_payload()
    assert payload["formal_v8_identity_created_or_consumed"] is False
    assert payload["authority"] == {
        "research_only": True,
        "fresh": False,
        "heldout": False,
        "certification": False,
        "promotion": False,
        "registry_mutation": False,
    }
    assert contracts.EXPECTED_FULL_PREDICTION_ROWS == 64_800
    required_standard = {
        "date",
        "ticker",
        "pe_model_id",
        "expected_pe",
        "expected_log_pe",
        "uncertainty",
        "confidence",
        "regime_state",
        "specialist_tags",
        "prediction_valid",
        "pit_valid",
        "source_model_version",
    }
    assert required_standard.issubset(contracts.PREDICTION_COLUMNS)
    assert not any(token in contracts.PUBLIC_ROOT.lower() for token in ("heldout", "qualification"))
