from __future__ import annotations

import ast
from datetime import date, timedelta
import hashlib
import importlib.util
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "model_lab"
    / "pe_four_model_heldout_r3_post_generation_audit.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("r3_post_generation_audit", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _authority(module, *, run_id: str = "r3_synthetic"):
    aliases = [f"heldout_seed_{index:02d}" for index in range(1, 6)]
    seeds = list(range(101, 106))
    tasks = [
        {
            "data_seed": seed,
            "dgp_id": dgp,
            "estimator_rng_alias": alias,
            "estimator_rng_seed": seed,
            "seed_alias": alias,
            "task_ordinal": seed_index * 10 + dgp_index,
        }
        for seed_index, (alias, seed) in enumerate(zip(aliases, seeds, strict=True))
        for dgp_index, dgp in enumerate(module.DGPS)
    ]
    adapter_records = [
        {
            "relative_path": f"research/synthetic/adapter_{index:03d}.py",
            "raw_sha256": f"{index + 1:064x}",
            "size_bytes": index + 1,
        }
        for index in range(74)
    ]
    c2_c3_records = [
        {
            "relative_path": f"research/synthetic/c2_c3_{index:03d}.py",
            "raw_sha256": f"{index + 101:064x}",
            "size_bytes": index + 101,
        }
        for index in range(26)
    ]
    c4_tree_records = [
        {
            "relative_path": f"research/synthetic/c4_tree_{index:03d}.py",
            "raw_sha256": f"{index + 201:064x}",
            "size_bytes": index + 201,
        }
        for index in range(34)
    ]
    c4_file_records = [
        {
            "relative_path": f"research/synthetic/c4_file_{index:03d}.py",
            "raw_sha256": f"{index + 301:064x}",
            "size_bytes": index + 301,
        }
        for index in range(3)
    ]
    plan = {
        "schema_version": "expected_pe.four_model.heldout_generation_plan.v1",
        "status": "AUTHORIZED_FIXED_HELDOUT_GENERATION_PRETRUTH",
        "qualification_result_raw_sha256": "a" * 64,
        "heldout_seed_aliases_in_order": aliases,
        "heldout_seeds_in_order": seeds,
        "estimator_rng_aliases_in_order": aliases,
        "estimator_rng_seeds_in_order": seeds,
        "estimator_rng_is_mechanical_heldout_data_seed": True,
        "fold_rng_formula": "fold_seed=heldout_data_seed+test_start_position",
        "estimator_rng_is_feature_router_weight_or_formula_parameter": False,
        "dgp_ids_in_order": list(module.DGPS),
        "task_count": 50,
        "task_order": "heldout_data_seed_major_then_dgp_A_to_J",
        "tasks": tasks,
        "identity_count": 64800,
        "prediction_row_count": 259200,
        "source_rows_per_task": 1800,
        "truth_open_count": 0,
        "heldout_content_open_count_at_authority": 0,
        "prediction_must_be_frozen_before_truth": True,
        "protected_generator": {
            "imports_generator": True,
            "may_write_truth_and_latent_to_private_vault": True,
            "may_emit_public_frames_one_way": True,
            "may_fit_or_predict": False,
            "may_score": False,
        },
        "public_replay": {
            "imports_generator": False,
            "accepts_public_frames_only": True,
            "may_open_private_vault": False,
            "may_fit_or_predict": False,
            "may_score": False,
        },
        "public_predictor": {
            "imports_generator": False,
            "accepts_public_replay_only": True,
            "uses_bound_generation_seed_as_constituent_rng_only": True,
            "may_open_private_vault": False,
            "may_open_truth_or_latent": False,
            "may_score": False,
        },
        "c4_numeric_lineage_is_seed_free": True,
        "adapter_source_bindings": {
            key: "d" * 64 for key in module.ADAPTER_SOURCE_BINDING_FIELDS
        },
        "c2_c3_frozen_numeric_source_records": c2_c3_records,
        "c4_source_model_version": "sha256:synthetic",
        "c4_source_tree_relatives": [
            record["relative_path"] for record in c4_tree_records
        ],
        "c4_source_file_relatives": [
            record["relative_path"] for record in c4_file_records
        ],
        "c4_runtime_must_recompute_full_source_closure": True,
    }
    plan["plan_semantic_sha256"] = module.semantic_sha256(plan)
    formula = {
        "bce_v1_d_observable_state_confidence_shrinkage": {
            "direction_epsilon": 1.0e-12,
            "alpha": "synthetic",
            "log_formula": "synthetic",
        },
        "bce_tournament_v1_fixed_alpha_040_directional_consensus": {
            "direction_epsilon": 1.0e-12,
            "fixed_alpha": 0.40,
            "log_formula": "synthetic",
        },
        "hofs_v4_expected_pe": {
            "global_log_shrink": 0.50,
            "log_formula": "synthetic",
            "numeric_lineage_is_seed_free": True,
        },
    }
    qualification_ref = {
        "relative_path": "outputs/synthetic/QUALIFICATION_RESULT.json",
        "raw_sha256": "a" * 64,
        "size_bytes": 1,
        "volume_serial_number": 1,
        "file_id_128": "1" * 32,
    }
    survivor = {
        "schema_version": "expected_pe.four_model.heldout_survivor_freeze.v1",
        "status": "FROZEN_FROM_QUALIFICATION_RESULT_NO_POST_RESULT_TUNING",
        "qualification_result_ref": qualification_ref,
        "qualification_result_raw_sha256": "a" * 64,
        "qualification_result_schema_version": "synthetic",
        "qualification_result_status": "synthetic",
        "qualification_run_id": "synthetic",
        "champion_id": "v04_expected_pe",
        "survivor_ids_in_qualification_rank_order": ["c4", "c2", "c3"],
        "model_ids_in_order": ["v04", "c4", "c2", "c3"],
        "research_only_ids_excluded": ["c1"],
        "excluded_c1_prediction_row_count": 0,
        "source_model_versions": [
            {"model_id": model_id, "source_model_version": "sha256:synthetic"}
            for model_id in ("v04", "c4", "c2", "c3")
        ],
        "formula_lock": formula,
        "heldout_seeds_in_order": seeds,
        "estimator_rng_seeds_in_order": seeds,
        "estimator_rng_is_bound_generation_seed": True,
        "estimator_rng_is_feature_router_weight_or_formula_parameter": False,
        "dgp_ids_in_order": list(module.DGPS),
        "task_count": 50,
        "identity_count": 64800,
        "prediction_row_count": 259200,
        "candidate_tuning_allowed": False,
        "prediction_before_truth": True,
        "truth_open_count": 0,
        "heldout_content_open_count": 0,
        "score_open_count": 0,
    }
    survivor["survivor_freeze_semantic_sha256"] = module.semantic_sha256(survivor)
    runtime = {key: "synthetic" for key in module.RUNTIME_VERSION_FIELDS}
    flattened = [
        *adapter_records,
        *c2_c3_records,
        *c4_tree_records,
        *c4_file_records,
    ]
    source_manifest = {
        "schema_version": "expected_pe.four_model.heldout_prediction_source_manifest.v1",
        "status": "FROZEN_EXECUTED_NUMERIC_SOURCE_CLOSURE_PRETRUTH",
        "qualification_result_raw_sha256": "a" * 64,
        "public_replay_design_lock_raw_sha256": "b" * 64,
        "adapter_source_records": adapter_records,
        "c2_c3_frozen_numeric_source_records": c2_c3_records,
        "c4_source_model_version": "sha256:synthetic",
        "c4_source_tree_records": c4_tree_records,
        "c4_source_file_records": c4_file_records,
        "runtime_versions": runtime,
        "runtime_semantic_sha256": module.semantic_sha256(runtime),
        "source_record_count": 137,
        "source_records_semantic_sha256": module.semantic_sha256(flattened),
    }
    source_manifest["source_manifest_semantic_sha256"] = module.semantic_sha256(
        source_manifest
    )
    protocol_binding = {
        "r1_terminal_failure": {"relative_path": "outputs/r1.json", "raw_sha256": "1" * 64},
        "replacement_seed_precommit": {
            "relative_path": "build/precommit.json",
            "raw_sha256": "2" * 64,
        },
        "final_nonreserved_preflight": {
            "relative_path": "build/preflight.json",
            "raw_sha256": "3" * 64,
            "status": "PASS",
            "reserved_generator_invocation_count": 0,
            "truth_leakage_count": 0,
            "heldout_access_count": 0,
            "score_open_count": 0,
            "registry_mutation_count": 0,
        },
        "quarantine_seeds_never_generate_or_score": [],
        "heldout_seeds_in_order": seeds,
        "heldout_seed_commitment_sha256": "4" * 64,
        "reservation_contract": {
            "format_version": 1,
            "registry_id": "synthetic",
            "owner_output_root": "outputs/synthetic",
            "source_config_sha256": "5" * 64,
            "candidates_sha256": "6" * 64,
            "policy_config_sha256": "7" * 64,
            "tuning_seeds": [],
            "locked_seeds": seeds,
            "reserved_seeds": seeds,
        },
        "spent_seed_reservation": {
            "format_version": 1,
            "registry_id": "synthetic",
            "registry_path": "outputs/registry.json",
            "genesis_sha256": "8" * 64,
            "reservation_id": "9" * 64,
            "reservation_sequence": 1,
            "reservation_entry_sha256": "a" * 64,
        },
        "registry_transition": {
            "registry_relative_path": "outputs/registry.json",
            "registry_before_raw_sha256": "b" * 64,
            "registry_after_raw_sha256": "c" * 64,
            "entry_count_before": 0,
            "entry_count_after": 1,
            "append_count": 1,
            "previous_entry_sha256": "d" * 64,
            "reservation_entry_sha256": "a" * 64,
            "reservation_created_at_utc": "synthetic",
        },
        "overlap_audit": {key: 0 for key in module.OVERLAP_FIELDS},
        "candidate_performance_consulted": False,
        "heldout_truth_consulted": False,
        "retry_allowed": False,
        "additional_recovery_reservation_allowed": False,
        "candidate_tuning_allowed": False,
        "truth_open_count_at_lock": 0,
        "score_open_count_at_lock": 0,
        "heldout_content_open_count_at_lock": 0,
    }
    protocol = {
        "schema_version": "expected_pe.four_model.r2_protocol_lock.v1",
        "status": "synthetic",
        "run_id": run_id,
        "r2_protocol_binding": protocol_binding,
        "r2_protocol_binding_semantic_sha256": module.semantic_sha256(protocol_binding),
        "policy_lock_sha256": "e" * 64,
    }
    authority = {
        "schema_version": "expected_pe.four_model.heldout_execution_authority.v1",
        "status": "FROZEN_PRETRUTH_SOURCE_PLAN_AND_SURVIVOR_AUTHORITY",
        "run_id": run_id,
        "source_frozen_before_generation": True,
        "candidate_tuning_allowed": False,
        "retry_allowed": False,
        "heldout_content_open_count": 0,
        "truth_open_count": 0,
        "score_open_count": 0,
        "generation_plan": plan,
        "generation_plan_semantic_sha256": plan["plan_semantic_sha256"],
        "survivor_freeze": survivor,
        "qualification_survivor_freeze_semantic_sha256": survivor[
            "survivor_freeze_semantic_sha256"
        ],
        "formula_lock_semantic_sha256": module.semantic_sha256(formula),
        "source_manifest": source_manifest,
        "source_manifest_semantic_sha256": source_manifest[
            "source_manifest_semantic_sha256"
        ],
        "source_records_semantic_sha256": source_manifest[
            "source_records_semantic_sha256"
        ],
        "runtime_semantic_sha256": source_manifest["runtime_semantic_sha256"],
        "r2_protocol_lock_relative_path": "outputs/synthetic/promotion_policy.lock.json",
        "r2_protocol_lock_raw_sha256": module.sha256(module.pretty_bytes(protocol)),
        "r2_protocol_binding_semantic_sha256": protocol[
            "r2_protocol_binding_semantic_sha256"
        ],
        "r2_protocol_lock": protocol,
    }
    authority["execution_authority_semantic_sha256"] = module.semantic_sha256(
        authority
    )
    return authority


def _upstream(module):
    distributions = {
        name: {"version": "synthetic", "record_raw_sha256": "1" * 64}
        for name in module.CHILD_RUNTIME_DISTRIBUTIONS
    }
    runtime = {
        "python_version": "synthetic",
        "python_executable": "C:/synthetic/python.exe",
        "python_executable_raw_sha256": "2" * 64,
        "python_base_executable": "C:/synthetic/python.exe",
        "python_base_executable_raw_sha256": "2" * 64,
        "distributions": distributions,
        "combined_sha256": "3" * 64,
    }
    environment = {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }

    def attestation(stage: str):
        return {
            "stage": stage,
            "output_csv": f"$REPLAY_ROOT/{stage}_output/result.csv",
            "resource_probe": {
                "cpu_ids": list(range(32)),
                "affinity_mask_hex": "0xFFFFFFFF",
                "environment": environment,
                "all_five_thread_variables_one": True,
                "both_gpu_variables_sealed": True,
                "isolated_python": True,
            },
            "runtime_before": runtime,
            "runtime_after": runtime,
            "threadpool_probe": [],
            "staged_project_tree_sha256_before": "4" * 64,
            "staged_project_tree_sha256_after": "4" * 64,
        }

    return {
        "schema_version": "expected_pe.r7.qualification.public_replay_receipt.v1",
        "status": "PASS_SCORE_FREE_PUBLIC_CANONICAL_OVERLAY_REPLAY",
        "stage": "QUALIFICATION",
        "truth_namespace_accessed": False,
        "protected_path_received": False,
        "score_fit_prediction_evaluation": False,
        "public_inputs_used": ["benchmark", "eps_events", "price"],
        "public_input_raw_sha256": {
            "benchmark": "5" * 64,
            "eps_events": "6" * 64,
            "price": "7" * 64,
        },
        "canonical150_raw_sha256": "8" * 64,
        "canonical150_logical_sha256": "9" * 64,
        "canonical150_header_semantic_sha256": "a" * 64,
        "canonical150_header_raw_sha256": "b" * 64,
        "canonical150_rows": 1800,
        "canonical150_columns": 150,
        "v04_overlay_raw_sha256": "c" * 64,
        "v04_overlay_logical_sha256": "d" * 64,
        "v04_overlay_header_raw_sha256": "e" * 64,
        "v04_overlay_rows": 1800,
        "v04_overlay_columns": 254,
        "identity_sha256": "f" * 64,
        "replay_inventory_combined_sha256": "1" * 64,
        "normalized_invocations": {
            stage: [
                "python",
                "-I",
                "-B",
                "-X",
                "pycache_prefix=C:/synthetic",
                "$REPLAY_ROOT/child.py",
                "--stage",
                stage,
                "--spec",
                f"$REPLAY_ROOT/{stage}_spec.json",
            ]
            for stage in ("v03", "v04")
        },
        "child_attestation": {
            stage: attestation(stage) for stage in ("v03", "v04")
        },
    }


def _artifact_ref(module, path: Path, project: Path) -> dict[str, object]:
    raw = path.read_bytes()
    info = path.stat()
    return {
        "file_id_128": int(info.st_ino).to_bytes(16, "little").hex(),
        "raw_sha256": module.sha256(raw),
        "relative_path": path.relative_to(project).as_posix(),
        "size_bytes": len(raw),
        "volume_serial_number": info.st_dev,
    }


def _csv_bytes(columns: int) -> bytes:
    header = ["date", *(f"c{index:03d}" for index in range(1, columns))]
    start = date(2000, 1, 1)
    rows = [
        [str(start + timedelta(days=index)), *("" for _ in range(columns - 1))]
        for index in range(1800)
    ]
    return (
        "\n".join(",".join(row) for row in [header, *rows]) + "\n"
    ).encode("ascii")


def _write_full_synthetic_tree(tmp_path: Path, module):
    run_id = "r3_e2e"
    project = tmp_path / "p"
    build = project / "build"
    outputs = project / "outputs"
    build.mkdir(parents=True)
    outputs.mkdir()

    authority = _authority(module, run_id=run_id)
    authority_raw = module.pretty_bytes(authority)
    authority_path = (
        build / f"pe_four_model_heldout_execution_authority_{run_id}.json"
    )
    authority_path.write_bytes(authority_raw)

    public_root = (
        outputs / f"model_zoo_pe_four_model_heldout_public_replay_{run_id}"
    )
    public_root.mkdir()
    vault_root = outputs / f".model_zoo_pe_four_model_heldout_vault_{run_id}"
    vault_root.mkdir()
    vault_relative = vault_root.relative_to(project).as_posix()

    canonical_raw = _csv_bytes(150)
    overlay_raw = _csv_bytes(254)
    canonical_header_sha = module.sha256(canonical_raw.split(b"\n", 1)[0])
    overlay_header_sha = module.sha256(overlay_raw.split(b"\n", 1)[0])
    embedded_receipts = []
    design_lock = authority["source_manifest"][
        "public_replay_design_lock_raw_sha256"
    ]
    for task in authority["generation_plan"]["tasks"]:
        task_root = (
            public_root / task["seed_alias"] / f"dgp_{task['dgp_id']}"
        )
        task_root.mkdir(parents=True)
        canonical_path = task_root / "canonical150.csv"
        overlay_path = task_root / "v04_overlay.csv"
        canonical_path.write_bytes(canonical_raw)
        overlay_path.write_bytes(overlay_raw)
        canonical_ref = _artifact_ref(module, canonical_path, project)
        overlay_ref = _artifact_ref(module, overlay_path, project)
        geometry = module.expected_geometry(task["dgp_id"])
        public_hashes = {
            key: module.sha256(
                f"{task['task_ordinal']}:{key}".encode("ascii")
            )
            for key in module.PUBLIC_FRAME_KEYS
        }
        upstream = _upstream(module)
        upstream.update(
            {
                "canonical150_raw_sha256": module.sha256(canonical_raw),
                "canonical150_header_raw_sha256": canonical_header_sha,
                "v04_overlay_raw_sha256": module.sha256(overlay_raw),
                "v04_overlay_header_raw_sha256": overlay_header_sha,
            }
        )
        pass_1 = {
            "schema_version": (
                "expected_pe.four_model.heldout_public_replay_receipt.v1"
            ),
            "status": "PASS_PUBLIC_ONLY_REPLAY_PRETRUTH",
            "task_ordinal": task["task_ordinal"],
            "data_seed": task["data_seed"],
            "seed_alias": task["seed_alias"],
            "dgp_id": task["dgp_id"],
            "replay_pass": 1,
            "rows": 1800,
            "protected_generator_imported": False,
            "protected_path_received": False,
            "protected_value_received": False,
            "truth_open_count": 0,
            "score_open_count": 0,
            "public_frame_raw_sha256": public_hashes,
            "public_frame_rows": geometry,
            "upstream_replay_receipt": upstream,
        }
        pass_2 = {**pass_1, "replay_pass": 2}
        manifest = {
            "schema_version": (
                "expected_pe.four_model.heldout_public_task_manifest.v1"
            ),
            "status": "PASS_TWO_PUBLIC_REPLAYS_FROZEN_PRETRUTH",
            "task": task,
            "public_replay_design_lock_raw_sha256": design_lock,
            "canonical_ref": canonical_ref,
            "overlay_ref": overlay_ref,
            "public_frame_raw_sha256": public_hashes,
            "public_frame_rows": geometry,
            "public_frame_raw_hashes_equal": True,
            "public_frame_rows_equal": True,
            "canonical_replay_bytes_equal": True,
            "overlay_replay_bytes_equal": True,
            "protected_generator_imported": False,
            "truth_open_count": 0,
            "score_open_count": 0,
        }
        manifest["task_manifest_semantic_sha256"] = module.semantic_sha256(
            manifest
        )
        manifest_path = task_root / "PUBLIC_TASK_MANIFEST.json"
        manifest_path.write_bytes(module.pretty_bytes(manifest))
        receipt = {
            **pass_1,
            "status": "PASS_TWO_PUBLIC_PASSES_BYTE_EXACT_PRETRUTH",
            "public_frame_raw_hashes_equal": True,
            "public_frame_rows_equal": True,
            "canonical_replay_bytes_equal": True,
            "overlay_replay_bytes_equal": True,
            "pass_1_replay_receipt": pass_1,
            "pass_2_replay_receipt": pass_2,
            "public_replay_design_lock_raw_sha256": design_lock,
            "canonical_ref": canonical_ref,
            "overlay_ref": overlay_ref,
            "task_manifest_ref": _artifact_ref(
                module, manifest_path, project
            ),
            "task_manifest_semantic_sha256": manifest[
                "task_manifest_semantic_sha256"
            ],
        }
        receipt_path = task_root / "PUBLIC_REPLAY_RECEIPT.json"
        receipt_path.write_bytes(module.pretty_bytes(receipt))
        embedded_receipts.append(receipt)

    generation = {
        "schema_version": "expected_pe.four_model.heldout_generation_execution.v1",
        "status": "PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH",
        "run_id": run_id,
        "execution_authority_semantic_sha256": authority[
            "execution_authority_semantic_sha256"
        ],
        "source_frozen_before_generation": True,
        "task_count": 50,
        "outer_workers": 16,
        "inner_blas_threads": 1,
        "cpu_affinity": "CPU0-31",
        "gpu_enabled": False,
        "protected_public_process_separation": True,
        "anonymous_one_way_pipe_used": True,
        "public_pass_1_pass_2_byte_exact": True,
        "public_task_receipts": embedded_receipts,
        "truth_ref_inventory_received_by_public_process": False,
        "truth_open_count_by_controller": 0,
        "truth_open_count_by_public_process": 0,
        "score_open_count": 0,
    }
    (public_root / "GENERATION_EXECUTION_RECEIPT.json").write_bytes(
        module.compact_file_bytes(generation)
    )

    truth_refs = [
        {
            "file_id_128": f"{index + 1:032x}",
            "raw_sha256": f"{index + 1:064x}",
            "relative_path": (
                f"{vault_relative}/pass_1/seed_{task['data_seed']}/"
                f"dgp_{task['dgp_id']}/truth.csv"
            ),
            "size_bytes": index + 1,
            "volume_serial_number": 1,
        }
        for index, task in enumerate(
            authority["generation_plan"]["tasks"]
        )
    ]
    vault_manifest = {
        "schema_version": "expected_pe.four_model.heldout_vault_manifest.v1",
        "status": "FROZEN_PROTECTED_TRUTH_REFS_NO_OUTER_TRUTH_CONTENT_OPEN",
        "vault_relative_path": vault_relative,
        "qualification_result_raw_sha256": authority["generation_plan"][
            "qualification_result_raw_sha256"
        ],
        "generation_plan_semantic_sha256": authority[
            "generation_plan_semantic_sha256"
        ],
        "truth_refs": truth_refs,
        "truth_ref_count": 50,
        "protected_task_metadata_count": 100,
        "task_order": "heldout_data_seed_major_then_dgp_A_to_J",
        "metadata_read_count": 100,
        "pass_1_pass_2_protected_hashes_equal": True,
        "pass_1_pass_2_public_hashes_equal": True,
        "truth_content_open_count": 0,
        "truth_attribute_open_count_by_manifest_builder": 0,
        "truth_attribute_open_count_at_protected_write_time": 100,
        "pass_2_truth_ref_export_count": 0,
        "latent_ref_export_count": 0,
        "truth_refs_origin": "protected_write_time_FILE_READ_ATTRIBUTES_only",
        "outer_truth_content_open_count": 0,
        "evaluator_pre_marker_truth_content_open_count": 0,
    }
    vault_manifest["vault_manifest_semantic_sha256"] = module.semantic_sha256(
        vault_manifest
    )
    vault_manifest_path = vault_root / "VAULT_MANIFEST.json"
    vault_manifest_path.write_bytes(module.compact_file_bytes(vault_manifest))
    return {
        "authority": authority,
        "authority_path": authority_path,
        "authority_raw": authority_raw,
        "project": project,
        "public_root": public_root,
        "run_id": run_id,
        "vault_manifest_path": vault_manifest_path,
    }


def test_auditor_is_stdlib_only_and_contains_no_future_seed_constants() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported <= {
        "__future__",
        "argparse",
        "csv",
        "hashlib",
        "io",
        "json",
        "os",
        "pathlib",
        "re",
        "stat",
        "typing",
    }
    assert "research.model_zoo" not in source
    assert "SEEDS =" not in source
    truth_loop = source[source.index("for task, ref in zip") : source.index("def run_audit")]
    assert ".read_bytes()" not in truth_loop
    assert "os.stat" not in truth_loop
    assert "os.lstat" not in truth_loop


def test_authority_derives_and_checks_exact_50_task_order(tmp_path: Path) -> None:
    module = _module()
    authority = _authority(module)
    raw = module.pretty_bytes(authority)
    path = tmp_path / "AUTHORITY.json"
    path.write_bytes(raw)
    expected_semantic = authority["execution_authority_semantic_sha256"]
    parsed, observed_raw, tasks = module.validate_authority(
        path,
        run_id="r3_synthetic",
        expected_semantic_sha256=expected_semantic,
        expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
        state=module.State(),
    )
    assert observed_raw == raw
    assert parsed["generation_plan"]["heldout_seeds_in_order"] == list(
        range(101, 106)
    )
    assert len(tasks) == 50
    assert [task["task_ordinal"] for task in tasks] == list(range(50))


def test_authority_rejects_reordered_tasks_even_when_resealed(tmp_path: Path) -> None:
    module = _module()
    authority = _authority(module)
    plan = authority["generation_plan"]
    plan["tasks"][0], plan["tasks"][1] = plan["tasks"][1], plan["tasks"][0]
    plan.pop("plan_semantic_sha256")
    plan["plan_semantic_sha256"] = module.semantic_sha256(plan)
    authority["generation_plan_semantic_sha256"] = plan[
        "plan_semantic_sha256"
    ]
    authority.pop("execution_authority_semantic_sha256")
    authority["execution_authority_semantic_sha256"] = module.semantic_sha256(
        authority
    )
    raw = module.pretty_bytes(authority)
    path = tmp_path / "AUTHORITY.json"
    path.write_bytes(raw)
    with pytest.raises(module.AuditFailure, match="task identities/order") as caught:
        module.validate_authority(
            path,
            run_id="r3_synthetic",
            expected_semantic_sha256=authority[
                "execution_authority_semantic_sha256"
            ],
            expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
            state=module.State(),
        )
    assert caught.value.code == "AUTHORITY_TASK_ORDER"


def test_authority_rejects_resealed_extra_top_or_plan_key(tmp_path: Path) -> None:
    module = _module()
    for layer in ("authority", "plan"):
        authority = _authority(module)
        if layer == "authority":
            authority["resealed_extra"] = True
        else:
            plan = authority["generation_plan"]
            plan["resealed_extra"] = True
            plan.pop("plan_semantic_sha256")
            plan["plan_semantic_sha256"] = module.semantic_sha256(plan)
            authority["generation_plan_semantic_sha256"] = plan[
                "plan_semantic_sha256"
            ]
        authority.pop("execution_authority_semantic_sha256")
        authority["execution_authority_semantic_sha256"] = module.semantic_sha256(
            authority
        )
        raw = module.pretty_bytes(authority)
        path = tmp_path / f"AUTHORITY_{layer}.json"
        path.write_bytes(raw)
        with pytest.raises(module.AuditFailure) as caught:
            module.validate_authority(
                path,
                run_id="r3_synthetic",
                expected_semantic_sha256=authority[
                    "execution_authority_semantic_sha256"
                ],
                expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
                state=module.State(),
            )
        assert caught.value.code == (
            "AUTHORITY_KEY_UNIVERSE"
            if layer == "authority"
            else "AUTHORITY_PLAN_KEY_UNIVERSE"
        )


def test_generation_and_public_layers_reject_extra_keys() -> None:
    module = _module()
    generation = {key: None for key in module.GENERATION_RECEIPT_FIELDS}
    generation.update(
        {
            "schema_version": "expected_pe.four_model.heldout_generation_execution.v1",
            "status": "PASS_50_PROTECTED_PUBLIC_TWO_PASS_TASKS_PRETRUTH",
            "run_id": "r3_synthetic",
            "execution_authority_semantic_sha256": "a" * 64,
            "source_frozen_before_generation": True,
            "task_count": 50,
            "outer_workers": 16,
            "inner_blas_threads": 1,
            "cpu_affinity": "CPU0-31",
            "gpu_enabled": False,
            "protected_public_process_separation": True,
            "anonymous_one_way_pipe_used": True,
            "public_pass_1_pass_2_byte_exact": True,
            "public_task_receipts": [{} for _ in range(50)],
            "truth_ref_inventory_received_by_public_process": False,
            "truth_open_count_by_controller": 0,
            "truth_open_count_by_public_process": 0,
            "score_open_count": 0,
        }
    )
    assert len(
        module.validate_generation_receipt(
            generation,
            run_id="r3_synthetic",
            authority_semantic_sha256="a" * 64,
            state=module.State(),
        )
    ) == 50
    attacked_generation = {**generation, "resealed_extra": True}
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_generation_receipt(
            attacked_generation,
            run_id="r3_synthetic",
            authority_semantic_sha256="a" * 64,
            state=module.State(),
        )
    assert caught.value.code == "GENERATION_KEY_UNIVERSE"

    manifest = {key: None for key in module.PUBLIC_TASK_MANIFEST_FIELDS}
    manifest["task"] = {key: None for key in module.TASK_FIELDS}
    receipt = {key: None for key in module.PUBLIC_REPLAY_RECEIPT_FIELDS}
    receipt["pass_1_replay_receipt"] = {
        key: None for key in module.PUBLIC_PASS_RECEIPT_FIELDS
    }
    receipt["pass_2_replay_receipt"] = {
        key: None for key in module.PUBLIC_PASS_RECEIPT_FIELDS
    }
    module.validate_public_json_key_universes(
        manifest, receipt, state=module.State()
    )
    attacked_receipt = {**receipt, "resealed_extra": True}
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_public_json_key_universes(
            manifest, attacked_receipt, state=module.State()
        )
    assert caught.value.code == "PUBLIC_RECEIPT_KEY_UNIVERSE"
    nested_receipt = dict(receipt)
    nested_receipt["pass_1_replay_receipt"] = {
        **receipt["pass_1_replay_receipt"],
        "resealed_extra": True,
    }
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_public_json_key_universes(
            manifest, nested_receipt, state=module.State()
        )
    assert caught.value.code == "PASS_RECEIPT_KEY_UNIVERSE"


def test_upstream_rejects_extra_top_and_nested_keys() -> None:
    module = _module()
    upstream = _upstream(module)
    kwargs = {
        "canonical_sha": "8" * 64,
        "overlay_sha": "c" * 64,
        "canonical_header_sha": "b" * 64,
        "overlay_header_sha": "e" * 64,
    }
    module.validate_upstream(upstream, **kwargs, state=module.State())
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_upstream(
            {**upstream, "resealed_extra": True},
            **kwargs,
            state=module.State(),
        )
    assert caught.value.code == "UPSTREAM_KEY_UNIVERSE"
    attacked = dict(upstream)
    attacked_attestations = dict(upstream["child_attestation"])
    attacked_attestations["v03"] = {
        **attacked_attestations["v03"],
        "resealed_extra": True,
    }
    attacked["child_attestation"] = attacked_attestations
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_upstream(attacked, **kwargs, state=module.State())
    assert caught.value.code == "CHILD_ATTESTATION_KEY_UNIVERSE"


def test_vault_manifest_validation_is_metadata_only(tmp_path: Path) -> None:
    module = _module()
    authority = _authority(module)
    tasks = authority["generation_plan"]["tasks"]
    vault_relative = "outputs/.synthetic_vault_r3"
    refs = [
        {
            "file_id_128": f"{index + 1:032x}",
            "raw_sha256": f"{index + 1:064x}",
            "relative_path": (
                f"{vault_relative}/pass_1/seed_{task['data_seed']}/"
                f"dgp_{task['dgp_id']}/truth.csv"
            ),
            "size_bytes": index + 1,
            "volume_serial_number": 1,
        }
        for index, task in enumerate(tasks)
    ]
    manifest = {
        "schema_version": "expected_pe.four_model.heldout_vault_manifest.v1",
        "status": "FROZEN_PROTECTED_TRUTH_REFS_NO_OUTER_TRUTH_CONTENT_OPEN",
        "vault_relative_path": vault_relative,
        "qualification_result_raw_sha256": "a" * 64,
        "generation_plan_semantic_sha256": authority[
            "generation_plan_semantic_sha256"
        ],
        "truth_ref_count": 50,
        "protected_task_metadata_count": 100,
        "task_order": "heldout_data_seed_major_then_dgp_A_to_J",
        "metadata_read_count": 100,
        "pass_1_pass_2_protected_hashes_equal": True,
        "pass_1_pass_2_public_hashes_equal": True,
        "truth_content_open_count": 0,
        "truth_attribute_open_count_by_manifest_builder": 0,
        "truth_attribute_open_count_at_protected_write_time": 100,
        "pass_2_truth_ref_export_count": 0,
        "latent_ref_export_count": 0,
        "truth_refs_origin": "protected_write_time_FILE_READ_ATTRIBUTES_only",
        "outer_truth_content_open_count": 0,
        "evaluator_pre_marker_truth_content_open_count": 0,
        "truth_refs": refs,
    }
    manifest["vault_manifest_semantic_sha256"] = module.semantic_sha256(manifest)
    module.validate_vault_manifest(
        module.compact_file_bytes(manifest),
        project=tmp_path,
        vault_relative=vault_relative,
        tasks=tasks,
        qualification_raw_sha256="a" * 64,
        generation_plan_semantic_sha256=authority[
            "generation_plan_semantic_sha256"
        ],
        state=module.State(),
    )
    assert not (tmp_path / "outputs").exists()
    attacked = dict(manifest)
    attacked.pop("vault_manifest_semantic_sha256")
    attacked["resealed_extra"] = True
    attacked["vault_manifest_semantic_sha256"] = module.semantic_sha256(attacked)
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_vault_manifest(
            module.compact_file_bytes(attacked),
            project=tmp_path,
            vault_relative=vault_relative,
            tasks=tasks,
            qualification_raw_sha256="a" * 64,
            generation_plan_semantic_sha256=authority[
                "generation_plan_semantic_sha256"
            ],
            state=module.State(),
        )
    assert caught.value.code == "VAULT_KEY_UNIVERSE"


def test_public_guard_and_create_new_publication(tmp_path: Path) -> None:
    module = _module()
    for payload in (
        {"truth_open_count": 1},
        {"protected_value_received": True},
        {"nested": ["outputs/.synthetic_vault_r3/pass_1"]},
    ):
        with pytest.raises(module.AuditFailure):
            module.scan_public_protection(payload, state=module.State())

    project = tmp_path / "project"
    (project / "build").mkdir(parents=True)
    report = {"status": "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0"}
    output_root = project / "build" / "new_audit"
    raw_hash = module.publish(report, project=project, output_root=output_root)
    output = output_root / module.REPORT_NAME
    assert raw_hash == hashlib.sha256(output.read_bytes()).hexdigest()
    with pytest.raises(module.AuditFailure) as caught:
        module.publish(report, project=project, output_root=output_root)
    assert caught.value.code == "OUTPUT_EXISTS"


def test_cli_requires_all_external_bindings() -> None:
    module = _module()
    parser = module._parser()
    destinations = {action.dest for action in parser._actions}
    assert {
        "project_root",
        "run_id",
        "execution_authority",
        "execution_authority_semantic_sha256",
        "execution_authority_raw_sha256",
        "public_replay_root",
        "vault_manifest",
        "output_root",
    } <= destinations
    raw_action = next(
        action
        for action in parser._actions
        if action.dest == "execution_authority_raw_sha256"
    )
    assert raw_action.required is True


def test_r3_run_identity_binds_all_formal_paths() -> None:
    module = _module()
    run_id = "r3_synthetic"
    kwargs = {
        "run_id": run_id,
        "authority_relative": (
            f"build/pe_four_model_heldout_execution_authority_{run_id}.json"
        ),
        "public_relative": (
            f"outputs/model_zoo_pe_four_model_heldout_public_replay_{run_id}"
        ),
        "vault_relative": (
            f"outputs/.model_zoo_pe_four_model_heldout_vault_{run_id}"
        ),
        "vault_manifest_leaf": "VAULT_MANIFEST.json",
    }
    module.validate_r3_run_paths(**kwargs, state=module.State())
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_r3_run_paths(
            **{**kwargs, "public_relative": "outputs/wrong"},
            state=module.State(),
        )
    assert caught.value.code == "R3_PATH_BINDING"
    with pytest.raises(module.AuditFailure) as caught:
        module.validate_r3_run_paths(
            **{**kwargs, "run_id": "r2_synthetic"},
            state=module.State(),
        )
    assert caught.value.code == "R3_RUN_ID"


def test_full_synthetic_50_task_tree_run_audit_go(tmp_path: Path) -> None:
    module = _module()
    tree = _write_full_synthetic_tree(tmp_path, module)
    report = module.run_audit(
        tree["project"],
        run_id=tree["run_id"],
        execution_authority=tree["authority_path"],
        authority_semantic_sha256=tree["authority"][
            "execution_authority_semantic_sha256"
        ],
        authority_raw_sha256=module.sha256(tree["authority_raw"]),
        public_replay_root=tree["public_root"],
        vault_manifest_path=tree["vault_manifest_path"],
    )
    assert report["status"] == "GO_R3_POST_GENERATION_P0_0_P1_0_P2_0"
    assert report["finding_counts"] == {"P0": 0, "P1": 0, "P2": 0}
    assert report["public_evidence"]["task_count"] == 50
    assert report["public_evidence"]["public_file_count"] == 201
    assert report["vault_metadata_evidence"]["truth_ref_count"] == 50
    assert report["vault_metadata_evidence"]["payload_leaves_opened"] == 0
