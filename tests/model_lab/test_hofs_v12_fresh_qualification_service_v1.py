from __future__ import annotations

from dataclasses import replace
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
from typing import Callable

import numpy as np
import pandas as pd
import pytest

import research.model_zoo.hofs_v12_fresh_qualification_service_v1 as hofs_service_package
from research.model_zoo.hierarchical_observable_fair_value_state_v7.dgp_r4 import (
    R4_CANONICAL_COLUMNS,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v1 import (
    ACTUAL_COMMON_PATH_BINDING_STATUS,
    HOFS_TASK_SURFACE_COLUMNS,
    ExternalTaskBinding,
    HofsV12QualificationServiceError,
    SPENT_RESEARCH_ONLY_SEED_ALIAS,
    V7DecisionBlockResult,
    V7_RUNTIME_ENVELOPE_CONFLICT_ID,
    build_isolated_c4_runtime_prebinding,
    build_qualification_fold_plan,
    build_source_model_version,
    build_task_worker_assignments,
    build_worker_slot_plan,
    compute_task_artifact,
    compute_task_surface,
    compute_spent_research_only_task_artifact,
    contract_payload,
    expected_process_exit_records,
    run_native_16_worker_resource_preflight,
    validate_current_worker_envelope,
    validate_exact_task_universe,
    validate_inherited_gpu_off_environment,
    validate_injected_task,
    validate_task_surface,
    validate_live_resource_values,
    validate_spent_evidence_receipts,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v1 import service
from research.model_zoo.hofs_v12_fresh_qualification_service_v1 import publisher
from research.model_zoo.hofs_v12_fresh_qualification_service_v1.contracts import (
    CANONICAL_HEADER_SHA256,
    CANONICAL_COLUMNS,
    DGP_IDS,
    GPU_OFF_ENVIRONMENT,
    OUTER_WORKERS,
    PREDICTION_ROWS_PER_TASK,
    QUALIFICATION_SEEDS,
    RUNTIME_PREBINDING_FIELDS,
    SEED_ALIASES,
    SPENT_EVIDENCE_OUTPUT_ROOT,
    SPENT_EVIDENCE_STAGING_ROOT,
    SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256,
    SOURCE_ROWS_PER_TASK,
    TASK_COUNT,
    TASK_MANIFEST_FIELDS,
    TASK_MANIFEST_SCHEMA_VERSION,
    TASK_MANIFEST_STATUS,
    UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE,
    WORKER_AFFINITY_MASK,
    canonical_json_bytes as service_canonical_json_bytes,
    validate_exact_json_primitives,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.contract import (
    CANDIDATE_IDS,
    QualificationEvaluatorError,
    canonical_json_bytes as evaluator_canonical_json_bytes,
    validate_runtime_bindings,
)


@pytest.fixture(scope="module")
def canonical_fixture() -> tuple[pd.DataFrame, bytes, ExternalTaskBinding]:
    header = CANONICAL_COLUMNS
    matrix = np.zeros((SOURCE_ROWS_PER_TASK, len(header)), dtype=np.float64)
    frame = pd.DataFrame(matrix, columns=header)
    frame["date"] = pd.bdate_range("2010-01-04", periods=SOURCE_ROWS_PER_TASK).strftime(
        "%Y-%m-%d"
    )
    frame["symbol"] = "DGP_ISSUER"
    raw = frame.to_csv(
        index=False,
        lineterminator="\n",
        float_format="%.17g",
        na_rep="",
    ).encode("utf-8")
    parsed = service._parse_exact_canonical_csv(raw)
    binding = _binding(
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        semantic_sha256=service._logical_frame_sha256(parsed),
    )
    return parsed, raw, binding


def _binding(
    *,
    task_ordinal: int = 0,
    raw_sha256: str = "1" * 64,
    semantic_sha256: str = "2" * 64,
    **overrides: object,
) -> ExternalTaskBinding:
    seed_index, dgp_index = divmod(task_ordinal, len(DGP_IDS))
    alias = SEED_ALIASES[seed_index]
    payload: dict[str, object] = {
        "schema_version": TASK_MANIFEST_SCHEMA_VERSION,
        "status": TASK_MANIFEST_STATUS,
        "task_ordinal": task_ordinal,
        "qualification_seed": QUALIFICATION_SEEDS[seed_index],
        "seed_alias": alias,
        "dgp_id": DGP_IDS[dgp_index],
        "canonical_raw_sha256": raw_sha256,
        "canonical_semantic_sha256": semantic_sha256,
        "canonical_header_sha256": CANONICAL_HEADER_SHA256,
        "canonical_rows": SOURCE_ROWS_PER_TASK,
        "canonical_columns": 150,
        "common_task_manifest_raw_sha256": "3" * 64,
        "common_task_manifest_semantic_sha256": "4" * 64,
        "common_task_manifest_volume_serial_number": 17,
        "common_task_manifest_file_id_128": "5" * 32,
        "actual_common_path_binding_status": ACTUAL_COMMON_PATH_BINDING_STATUS,
    }
    payload.update(overrides)
    return ExternalTaskBinding.from_mapping(payload)


def _fake_backend(
    capture: dict[str, object] | None = None,
) -> Callable[[pd.DataFrame, tuple[object, ...]], tuple[V7DecisionBlockResult, ...]]:
    def run(
        numeric_source: pd.DataFrame,
        plan: tuple[object, ...],
    ) -> tuple[V7DecisionBlockResult, ...]:
        if capture is not None:
            capture["columns"] = tuple(numeric_source.columns)
            capture["shape"] = numeric_source.shape
            capture["args"] = 2
        blocks = []
        for untyped_spec in plan:
            spec = untyped_spec
            positions = tuple(
                range(
                    spec.decision_block_start_inclusive,
                    spec.decision_block_end_exclusive,
                )
            )
            blocks.append(
                V7DecisionBlockResult(
                    fold_ordinal=spec.fold_ordinal,
                    source_row_positions=positions,
                    entity_ids=("DGP_ISSUER",) * len(positions),
                    decision_dates=tuple(str(numeric_source.loc[pos, "date"]) for pos in positions),
                    expected_pe=tuple(float(10.0 + pos / 1_000.0) for pos in positions),
                    pe_p10=tuple(float(9.0 + pos / 1_000.0) for pos in positions),
                    pe_p90=tuple(float(11.0 + pos / 1_000.0) for pos in positions),
                    log_scale=tuple(float(-0.1 + spec.fold_ordinal / 1_000.0) for _ in positions),
                    tail_guard_weight=tuple(
                        float(0.25 + spec.fold_ordinal / 1_000.0) for _ in positions
                    ),
                    fit_prefix_end_exclusive=spec.fit_prefix_end_exclusive,
                    within_block_parameter_update_count=0,
                    parameter_sha256=f"{spec.fold_ordinal:064x}",
                    fit_receipt_sha256=f"{spec.fold_ordinal + 1:064x}",
                    decision_block_ordered_membership_sha256=(
                        f"{spec.fold_ordinal + 2:064x}"
                    ),
                    decision_block_set_membership_sha256=(
                        f"{spec.fold_ordinal + 3:064x}"
                    ),
                    decision_source_positions_sha256=f"{spec.fold_ordinal + 4:064x}",
                    output_manifest_sha256=f"{spec.fold_ordinal + 100:064x}",
                )
            )
        return tuple(blocks)

    return run


def _validated(canonical_fixture) -> service.ValidatedTaskInput:
    frame, _, binding = canonical_fixture
    return validate_injected_task(frame, external_binding=binding)


def test_direct_fold_geometry_is_exact_and_seed_free() -> None:
    plan = build_qualification_fold_plan()
    assert len(plan) == 62
    assert tuple(item.fold_id for item in plan) == tuple(
        f"fold_{number:03d}" for number in range(12, 74)
    )
    assert tuple(item.decision_row_count for item in plan) == (21,) * 61 + (15,)
    assert sum(item.decision_row_count for item in plan) == 1_296
    assert plan[0].fit_prefix_end_exclusive == 504
    assert plan[-1].decision_block_start_inclusive == 1_785
    assert plan[-1].decision_block_end_exclusive == 1_800
    assert all(item.within_block_parameter_update_count == 0 for item in plan)
    assert all("seed" not in item.payload() and "dgp" not in item.payload() for item in plan)


def test_contract_declares_full32_resolution_and_no_qualification_authority() -> None:
    payload = contract_payload()
    assert payload["runtime_conflict"] == {
        "id": V7_RUNTIME_ENVELOPE_CONFLICT_ID,
        "status": "RESOLVED_BY_FULL_MACHINE_AFFINITY_WITH_EXACT_LIVE_GATE",
        "v7_required_affinity_mask": "0xFFFFFFFF",
        "v7_required_logical_cpu_count": 32,
        "v7_required_outer_workers": 32,
        "numeric_entry_gate_status": "PASS_EXACT_LIVE_FULL_AFFINITY_ENVIRONMENT",
        "resource_resolution_lock_relative": (
            "research/model_zoo/portfolio_governance_v1/"
            "HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json"
        ),
        "resource_resolution_lock_raw_sha256": (
            "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c"
        ),
    }
    assert payload["authority"]["actual_numeric_launch"] is False
    assert payload["authority"]["publication"] is False
    assert payload["authority"]["score_or_truth_input"] is False
    assert payload["authority"]["spent_public_equivalence_smoke"] is True
    assert payload["resources"]["outer_workers"] == 16
    assert payload["resources"]["logical_cpus_per_worker"] == 32
    assert payload["resources"]["worker_affinity_mask_hex"] == "0xFFFFFFFF"
    assert payload["resources"]["v7_resource_receipt_outer_workers_field"] == 32
    assert (
        payload["task_contract"]["actual_common_path_binding_status"]
        == ACTUAL_COMMON_PATH_BINDING_STATUS
    )


def test_external_manifest_exact_identity_and_no_paths() -> None:
    binding = _binding(task_ordinal=49)
    assert binding.seed_alias == "qualification_seed_05"
    assert binding.qualification_seed == 7591
    assert binding.dgp_id == "J"
    assert tuple(binding.payload()) == TASK_MANIFEST_FIELDS
    assert not any("path" in field for field in TASK_MANIFEST_FIELDS if field != "actual_common_path_binding_status")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "wrong"),
        ("status", "PENDING"),
        ("qualification_seed", 7577),
        ("seed_alias", "qualification_seed_02"),
        ("dgp_id", "J"),
        ("canonical_raw_sha256", "A" * 64),
        ("canonical_header_sha256", "0" * 64),
        ("canonical_rows", 1_799),
        ("canonical_columns", 149),
        ("common_task_manifest_file_id_128", "f" * 31),
        ("actual_common_path_binding_status", "BOUND"),
    ],
)
def test_external_manifest_attacks_fail_closed(field: str, value: object) -> None:
    with pytest.raises(HofsV12QualificationServiceError):
        _binding(**{field: value})


def test_external_manifest_extra_field_fails_closed() -> None:
    payload = _binding().payload()
    payload["caller_path"] = "forbidden"
    with pytest.raises(HofsV12QualificationServiceError):
        ExternalTaskBinding.from_mapping(payload)


def test_injected_bytes_and_dataframe_bindings(canonical_fixture) -> None:
    frame, raw, binding = canonical_fixture
    by_bytes = validate_injected_task(raw, external_binding=binding)
    by_frame = validate_injected_task(frame, external_binding=binding.payload())
    assert by_bytes.receipt.raw_bytes_reverified is True
    assert by_frame.receipt.raw_bytes_reverified is False
    assert by_bytes.receipt.canonical_semantic_sha256 == binding.canonical_semantic_sha256
    assert by_frame.receipt.source_kind == "INJECTED_DATAFRAME_EXTERNAL_RAW_BINDING_ONLY"
    assert by_frame.canonical.equals(frame)


def test_injected_input_hash_schema_date_symbol_and_type_attacks(canonical_fixture) -> None:
    frame, raw, binding = canonical_fixture
    with pytest.raises(HofsV12QualificationServiceError, match="raw hash"):
        validate_injected_task(raw + b"\n", external_binding=binding)
    with pytest.raises(HofsV12QualificationServiceError, match="semantic hash"):
        validate_injected_task(frame, external_binding=replace(binding, canonical_semantic_sha256="a" * 64))
    for mutation in ("truth_value", "latent_state", "heldout_value", "qualification_score"):
        attacked = frame.copy()
        attacked = attacked.rename(columns={attacked.columns[-1]: mutation})
        with pytest.raises(HofsV12QualificationServiceError, match="canonical150"):
            validate_injected_task(attacked, external_binding=binding)
    attacked = frame.copy()
    attacked.loc[1, "date"] = attacked.loc[0, "date"]
    with pytest.raises(HofsV12QualificationServiceError, match="dates"):
        validate_injected_task(attacked, external_binding=binding)
    attacked = frame.copy()
    attacked.loc[0, "symbol"] = "OTHER"
    with pytest.raises(HofsV12QualificationServiceError, match="symbol"):
        validate_injected_task(attacked, external_binding=binding)
    with pytest.raises(HofsV12QualificationServiceError, match="bytes or pandas"):
        validate_injected_task(bytearray(raw), external_binding=binding)  # type: ignore[arg-type]


def test_sealed_score_named_column_is_allowed_but_excluded_from_numeric(canonical_fixture) -> None:
    validated = _validated(canonical_fixture)
    capture: dict[str, object] = {}
    surface = service._compute_surface_with_backend_for_test(validated, _fake_backend(capture))
    assert UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE in validated.canonical
    assert capture["columns"] == R4_CANONICAL_COLUMNS
    assert UPSTREAM_SCORE_NAMED_COLUMN_EXCLUDED_FROM_NUMERIC_LINEAGE not in capture["columns"]
    assert capture["shape"] == (1_800, 22)
    assert len(surface) == 1_296


def test_synthetic_backend_returns_exact_11_column_surface(canonical_fixture) -> None:
    validated = _validated(canonical_fixture)
    surface = service._compute_surface_with_backend_for_test(validated, _fake_backend())
    assert tuple(surface.columns) == HOFS_TASK_SURFACE_COLUMNS
    assert surface.shape == (PREDICTION_ROWS_PER_TASK, 11)
    assert surface["session_position"].tolist() == list(range(504, 1_800))
    assert surface["fold_id"].iloc[:21].eq("fold_012").all()
    assert surface["fold_id"].iloc[-15:].eq("fold_073").all()
    assert surface["train_end_position"].iloc[0] == 503
    assert surface["test_start_position"].iloc[-1] == 1_785
    expected = np.log(10.0 + surface["session_position"].to_numpy(dtype=float) / 1_000.0)
    np.testing.assert_array_equal(surface["hofs_r2_expected_log_pe"].to_numpy(), expected)
    validate_task_surface(surface)


def test_actual_seed_and_dgp_never_reach_numeric_backend(canonical_fixture) -> None:
    validated = _validated(canonical_fixture)
    captured: dict[str, object] = {}
    service._compute_surface_with_backend_for_test(validated, _fake_backend(captured))
    assert captured["args"] == 2
    assert "seed" not in captured
    assert "dgp" not in captured
    assert "qualification_seed" not in captured["columns"]
    assert "dgp_id" not in captured["columns"]
    assert 7573 not in captured.values()


def test_surface_rejects_partial_reordered_and_invalid_blocks(canonical_fixture) -> None:
    validated = _validated(canonical_fixture)
    blocks = _fake_backend()(service._select_v7_numeric_source(validated.canonical), build_qualification_fold_plan())
    with pytest.raises(HofsV12QualificationServiceError, match="partial"):
        service._assemble_task_surface(validated, blocks[:-1])
    with pytest.raises(HofsV12QualificationServiceError, match="duplicated or reordered"):
        service._assemble_task_surface(validated, (blocks[1], blocks[0], *blocks[2:]))
    with pytest.raises(HofsV12QualificationServiceError, match="expected P/E"):
        replace(blocks[0], expected_pe=(-1.0, *blocks[0].expected_pe[1:]))
    with pytest.raises(HofsV12QualificationServiceError, match="strict-prefix"):
        replace(blocks[0], within_block_parameter_update_count=1)


def test_surface_validator_rejects_reorder_nan_and_fold_mutation(canonical_fixture) -> None:
    surface = service._compute_surface_with_backend_for_test(
        _validated(canonical_fixture), _fake_backend()
    )
    attacked = pd.concat([surface.iloc[[1]], surface.iloc[[0]], surface.iloc[2:]], ignore_index=True)
    with pytest.raises(HofsV12QualificationServiceError, match="positions"):
        validate_task_surface(attacked)
    attacked = surface.copy()
    attacked.loc[0, "hofs_v7_tail_guard_weight"] = np.nan
    with pytest.raises(HofsV12QualificationServiceError, match="numeric"):
        validate_task_surface(attacked)
    attacked = surface.copy()
    attacked.loc[0, "fold_id"] = "fold_013"
    with pytest.raises(HofsV12QualificationServiceError, match="fold identity"):
        validate_task_surface(attacked)
    attacked = surface.astype(
        {
            "session_position": "float64",
            "test_start_position": "float64",
            "train_end_position": "float64",
        }
    )
    attacked.loc[0, "session_position"] = 504.1
    attacked.loc[0, "test_start_position"] = 504.1
    attacked.loc[0, "train_end_position"] = 503.1
    with pytest.raises(HofsV12QualificationServiceError, match="exact dtype"):
        validate_task_surface(attacked)
    attacked = surface.copy()
    attacked["session_position"] = attacked["session_position"].astype("Int64")
    with pytest.raises(HofsV12QualificationServiceError, match="exact dtype"):
        validate_task_surface(attacked)
    attacked = surface.copy()
    attacked["hofs_v7_log_scale"] = attacked["hofs_v7_log_scale"].astype(str)
    with pytest.raises(HofsV12QualificationServiceError, match="exact dtype"):
        validate_task_surface(attacked)


def test_public_numeric_entry_rejects_pending_binding_before_resource_or_backend(
    monkeypatch, canonical_fixture
) -> None:
    _, raw, binding = canonical_fixture
    order: list[str] = []

    def gate(worker_ordinal):
        order.append("gate")
        return {"status": "PASS_EXACT_LIVE_FULL_AFFINITY_ENVIRONMENT"}

    def backend(numeric_source, plan, *, capability):
        order.append("backend")
        return _fake_backend()(numeric_source, plan)

    monkeypatch.setattr(
        service,
        "verify_numeric_source_closure",
        lambda: order.append("source_closure"),
    )
    monkeypatch.setattr(service, "assert_actual_numeric_launch_allowed", gate)
    monkeypatch.setattr(service, "_execute_audited_v7_numeric_lineage", backend)
    with pytest.raises(HofsV12QualificationServiceError, match="production numeric entry"):
        compute_task_artifact(raw, external_binding=binding)
    assert order == []
    assert compute_task_surface.__name__ == "compute_task_surface"


def test_fixed_spent_research_entry_is_separate_and_zero_access(
    monkeypatch, canonical_fixture
) -> None:
    assert SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256 == (
        "aa6bb2f3e63b4423c79a578c3ed2fb8353050dd5ed7dc2d117931abfde1bb384"
    )
    _, raw, _ = canonical_fixture
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    monkeypatch.setattr(service, "SPENT_RESEARCH_ONLY_CANONICAL_RAW_SHA256", raw_sha256)
    order: list[str] = []

    monkeypatch.setattr(
        service,
        "verify_numeric_source_closure",
        lambda: order.append("source_closure"),
    )
    monkeypatch.setattr(
        service,
        "assert_actual_numeric_launch_allowed",
        lambda ordinal: order.append(f"gate:{ordinal}") or {"status": "PASS"},
    )
    monkeypatch.setattr(
        service,
        "_execute_audited_v7_numeric_lineage",
        lambda numeric_source, plan, *, capability: (
            order.append("backend") or _fake_backend()(numeric_source, plan)
        ),
    )
    artifact = compute_spent_research_only_task_artifact(raw)
    assert order == ["source_closure", "gate:0", "backend"]
    assert artifact.input_receipt.seed_alias == SPENT_RESEARCH_ONLY_SEED_ALIAS
    assert artifact.input_receipt.external_manifest_file_id_held_by_wrapper is False
    assert all(
        type(value) is int and value == 0
        for value in (
            artifact.input_receipt.qualification_access_count,
            artifact.input_receipt.fresh_access_count,
            artifact.input_receipt.truth_access_count,
            artifact.input_receipt.heldout_access_count,
            artifact.input_receipt.score_access_count,
        )
    )
    with pytest.raises(HofsV12QualificationServiceError, match="raw pin"):
        compute_spent_research_only_task_artifact(raw + b"\n")


def test_public_numeric_entry_rejects_caller_parsed_dataframe(canonical_fixture) -> None:
    frame, _, binding = canonical_fixture
    with pytest.raises(HofsV12QualificationServiceError, match="production numeric entry"):
        compute_task_artifact(frame, external_binding=binding)


def test_worker_slots_assignments_and_environment_are_exact(monkeypatch) -> None:
    slots = build_worker_slot_plan()
    assert len(slots) == OUTER_WORKERS
    assert all(slot.logical_cpu_ids == tuple(range(32)) for slot in slots)
    assert all(slot.affinity_mask == WORKER_AFFINITY_MASK for slot in slots)
    assert all(slot.inner_threads == 1 for slot in slots)
    assignments = build_task_worker_assignments()
    assert len(assignments) == TASK_COUNT
    assert tuple(item.worker_ordinal for item in assignments[:18]) == tuple(range(16)) + (0, 1)
    for name, value in GPU_OFF_ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("UNRELATED", "preserved")
    assert validate_inherited_gpu_off_environment() == GPU_OFF_ENVIRONMENT
    monkeypatch.setenv("CUDA_VISIBLE_DEVICES", "0")
    with pytest.raises(HofsV12QualificationServiceError, match="GPU-off"):
        validate_inherited_gpu_off_environment()


def test_live_resource_value_attacks_fail_closed() -> None:
    expected_environment = dict(GPU_OFF_ENVIRONMENT)
    receipt = validate_live_resource_values(
        logical_cpu_count=32,
        affinity_mask=0xFFFFFFFF,
        cpu_ids=tuple(range(32)),
        environment=expected_environment,
    )
    assert receipt["status"] == "PASS_EXACT_LIVE_FULL_AFFINITY_ENVIRONMENT"
    for attack in (
        {"logical_cpu_count": 31},
        {"affinity_mask": 0x00000003},
        {"cpu_ids": (0, 1)},
        {"environment": {**expected_environment, "CUDA_VISIBLE_DEVICES": ""}},
    ):
        values = {
            "logical_cpu_count": 32,
            "affinity_mask": 0xFFFFFFFF,
            "cpu_ids": tuple(range(32)),
            "environment": expected_environment,
            **attack,
        }
        with pytest.raises(HofsV12QualificationServiceError, match="full32"):
            validate_live_resource_values(**values)


@pytest.mark.skipif(os.name != "nt", reason="exact native resource gate is Windows-only")
def test_native_controller_and_16_spawned_workers_full_affinity() -> None:
    assert validate_current_worker_envelope(0)["affinity_mask"] == "0xFFFFFFFF"
    receipt = run_native_16_worker_resource_preflight()
    assert receipt["status"] == (
        "PASS_NATIVE_16_SPAWNED_FULL_AFFINITY_RESOURCE_PREFLIGHT"
    )
    assert receipt["actual_controller_worker_count"] == 16
    assert receipt["simultaneous_ready_worker_count"] == 16
    assert len(receipt["worker_observations"]) == 16
    assert len({row["pid"] for row in receipt["worker_observations"]}) == 16
    assert receipt["process_exit_records"] == list(expected_process_exit_records())
    assert all(row["affinity_mask"] == "0xFFFFFFFF" for row in receipt["worker_observations"])
    assert all(row["logical_cpu_ids"] == list(range(32)) for row in receipt["worker_observations"])


def _self_hashed_receipt(payload: dict[str, object]) -> dict[str, object]:
    return {
        **payload,
        "receipt_raw_sha256": hashlib.sha256(service_canonical_json_bytes(payload)).hexdigest(),
    }


def _synthetic_resource_observation(
    *, worker_ordinal: int, pid: int, memory: bool
) -> dict[str, object]:
    observation: dict[str, object] = {
        "logical_cpu_count": 32,
        "logical_cpu_ids": list(range(32)),
        "affinity_mask": "0xFFFFFFFF",
        "affinity_policy": "EVERY_WORKER_SEES_THE_SAME_FULL_MACHINE_MASK",
        "inner_threads": 1,
        "environment": dict(GPU_OFF_ENVIRONMENT),
        "process_start_method": "spawn",
        "status": "PASS_EXACT_LIVE_FULL_AFFINITY_ENVIRONMENT",
        "worker_ordinal": worker_ordinal,
        "pid": pid,
    }
    if memory:
        observation["memory"] = {
            "rss_bytes": 1_000 + worker_ordinal,
            "peak_rss_bytes": 2_000 + worker_ordinal,
            "private_bytes": 900 + worker_ordinal,
            "peak_pagefile_bytes": 2_500 + worker_ordinal,
        }
    return observation


def _synthetic_spent_evidence_pair() -> tuple[dict[str, object], dict[str, object]]:
    controller = _synthetic_resource_observation(
        worker_ordinal=0, pid=9_999, memory=True
    )
    controller["process_role"] = "controller"
    workers = [
        _synthetic_resource_observation(
            worker_ordinal=ordinal,
            pid=10_000 + ordinal,
            memory=True,
        )
        for ordinal in range(16)
    ]
    worker_peaks = [row["memory"]["peak_rss_bytes"] for row in workers]  # type: ignore[index]
    resource = _self_hashed_receipt(
        {
            "schema_version": "expected_pe.hofs_v12.resource_preflight.v1",
            "status": "PASS_NATIVE_16_SPAWNED_FULL_AFFINITY_RESOURCE_PREFLIGHT",
            "resource_resolution_lock_raw_sha256": (
                "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c"
            ),
            "process_start_method": "spawn",
            "actual_controller_worker_count": 16,
            "simultaneous_ready_worker_count": 16,
            "controller_observation": controller,
            "worker_observations": workers,
            "process_exit_records": list(expected_process_exit_records()),
            "elapsed_ns": 1_000,
            "worker_peak_rss_max_bytes": max(worker_peaks),
            "worker_peak_rss_sum_bytes": sum(worker_peaks),
            "qualification_access_count": 0,
            "fresh_access_count": 0,
            "truth_access_count": 0,
            "heldout_access_count": 0,
            "score_access_count": 0,
            "publication_count": 0,
        }
    )
    spent = _self_hashed_receipt(
        {
            "schema_version": "expected_pe.hofs_v12.spent_public_equivalence_smoke.v1",
            "status": "PASS_SPENT_PUBLIC_ONE_TASK_62_FOLD_BITWISE_EQUIVALENCE",
            "resource_resolution_lock_raw_sha256": (
                "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c"
            ),
            "spent_seed": 2_026_082_001,
            "spent_dgp": "A",
            "fold_count": 62,
            "prediction_row_count": 1_296,
            "bitwise_numeric_comparison_count": 6_480,
            "bitwise_numeric_mismatch_count": 0,
            "identity_or_hash_mismatch_count": 0,
            "surface_log_bitwise_mismatch_count": 0,
            "current_prediction_rows_sha256": (
                "b9ddd3fc9b397a825da4ae3a5abb35370df19f3db64b5a89c61b4e0f40edb58e"
            ),
            "frozen_r2_prediction_rows_sha256": (
                "b9ddd3fc9b397a825da4ae3a5abb35370df19f3db64b5a89c61b4e0f40edb58e"
            ),
            "resource_envelope": _synthetic_resource_observation(
                worker_ordinal=0,
                pid=30_000,
                memory=False,
            ),
            "fixed_file_records": {
                relative: {
                    "raw_sha256": raw_sha256,
                    "size_bytes": 1 + ordinal,
                    "volume_serial_number": 17,
                    "file_id_128": f"{ordinal + 1:032x}",
                }
                for ordinal, (relative, raw_sha256) in enumerate(
                    publisher._SPENT_FIXED_FILE_RAW_SHA256.items()
                )
            },
            "elapsed_ns": 2_000,
            "peak_process_rss_bytes": 4_000,
            "qualification_access_count": 0,
            "fresh_access_count": 0,
            "truth_artifact_access_count": 0,
            "heldout_access_count": 0,
            "score_artifact_access_count": 0,
            "upstream_score_named_numeric_use_count": 0,
            "publication_count": 0,
        }
    )
    return resource, spent


def test_spent_evidence_publisher_validator_is_exact_and_fail_closed() -> None:
    resource, spent = _synthetic_spent_evidence_pair()
    assert validate_spent_evidence_receipts(resource, spent) == (resource, spent)
    spent_payload = {key: value for key, value in spent.items() if key != "receipt_raw_sha256"}
    resource_payload = {
        key: value for key, value in resource.items() if key != "receipt_raw_sha256"
    }
    attacks: list[tuple[dict[str, object], dict[str, object]]] = []
    extra = dict(spent_payload)
    extra["caller_extra"] = 0
    attacks.append((resource, _self_hashed_receipt(extra)))
    float_count = dict(spent_payload)
    float_count["fold_count"] = 62.0
    attacks.append((resource, _self_hashed_receipt(float_count)))
    bool_counter = dict(spent_payload)
    bool_counter["publication_count"] = False
    attacks.append((resource, _self_hashed_receipt(bool_counter)))
    string_pid = dict(resource_payload)
    observations = [dict(row) for row in resource["worker_observations"]]
    observations[0]["pid"] = "not-a-pid"
    string_pid["worker_observations"] = observations
    attacks.append((_self_hashed_receipt(string_pid), spent))
    duplicate_pid = dict(resource_payload)
    observations = [dict(row) for row in resource["worker_observations"]]
    observations[1]["pid"] = observations[0]["pid"]
    duplicate_pid["worker_observations"] = observations
    attacks.append((_self_hashed_receipt(duplicate_pid), spent))
    for resource_attack, spent_attack in attacks:
        with pytest.raises(HofsV12QualificationServiceError):
            validate_spent_evidence_receipts(resource_attack, spent_attack)


def test_spent_evidence_publisher_is_private_root_only_and_unconsumed() -> None:
    root = Path(__file__).resolve().parents[2]
    assert not (root / SPENT_EVIDENCE_OUTPUT_ROOT).exists()
    assert not (root / SPENT_EVIDENCE_STAGING_ROOT).exists()
    assert not hasattr(hofs_service_package, "publish_spent_evidence")
    assert not hasattr(
        hofs_service_package, "SpentEvidencePublicationApprovalCapability"
    )
    assert "publish_spent_evidence" not in hofs_service_package.__all__
    assert publisher.__all__ == ["validate_spent_evidence_receipts"]
    assert not hasattr(publisher, "publish_spent_evidence")
    assert tuple(
        inspect.signature(
            publisher._publish_spent_evidence_from_fixed_root_approval_record
        ).parameters
    ) == (
        "resource_receipt",
        "spent_receipt",
    )
    resource, spent = _synthetic_spent_evidence_pair()
    with pytest.raises(HofsV12QualificationServiceError, match="approval record"):
        publisher._publish_spent_evidence_from_fixed_root_approval_record(
            resource_receipt=resource,
            spent_receipt=spent,
        )
    with pytest.raises(HofsV12QualificationServiceError, match="only be minted"):
        publisher._SpentEvidencePublicationApprovalCapability(
            approval_record_raw_sha256="a" * 64,
            approval_record_size_bytes=1,
            approval_record_volume_serial_number=1,
            approval_record_file_id_128="b" * 32,
            _mint_token=object(),
        )


def test_publisher_source_closure_pins_all_imported_trust_dependencies() -> None:
    root = Path(__file__).resolve().parents[2]
    required = {
        "research/model_zoo/hofs_research_adapter_v1/inputs.py": (
            "627ac3a73fcfee88b10b6229b1043b79cc98c8b5425e693b108d844126586551"
        ),
        "research/model_zoo/portfolio_governance_v1/"
        "HOFS_V12_RESOURCE_RESOLUTION_LOCK_V1.json": (
            "768ba5718fbb6e73f5d2ad06c65c64e0ac37dab481b2c94dfedbc55a9e1fe53c"
        ),
        "research/model_zoo/pe_c1_c4_fresh_qualification_prediction_v2/contracts.py": (
            "ab5d80a58236472f9536dfe4cce73084e8d47f97e6da3490aa5d99b0e0099d32"
        ),
    }
    assert set(required).issubset(publisher._SOURCE_RELATIVES)
    assert publisher._PINNED_DEPENDENCY_RAW_SHA256 == required
    records = {row["relative"]: row for row in publisher._source_records(root)}
    for relative, expected in required.items():
        assert records[relative]["raw_sha256"] == expected


def test_runtime_prebinding_is_canonical_but_cannot_claim_evaluator_receipt() -> None:
    artifact = build_isolated_c4_runtime_prebinding(
        started_perf_counter_ns=1_000,
        ended_perf_counter_ns=2_500,
        sample_count=15,
        sample_interval_max_ms=99.5,
        peak_process_tree_rss_bytes=123_456,
        peak_vram_bytes=0,
        gpu_process_observation_count=0,
        process_exit_records=expected_process_exit_records(),
    )
    assert set(artifact.receipt) == set(RUNTIME_PREBINDING_FIELDS)
    assert artifact.raw_bytes == evaluator_canonical_json_bytes(artifact.receipt)
    assert artifact.raw_bytes.endswith(b"\n") and b"\r" not in artifact.raw_bytes
    compact = json.dumps(
        artifact.receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert hashlib.sha256(compact).hexdigest() != artifact.raw_sha256

    shared = dict(artifact.receipt)
    shared["candidate_ids"] = list(CANDIDATE_IDS[:3])
    shared["lane_id"] = "shared_c1_c3"
    shared_raw = evaluator_canonical_json_bytes(shared)
    bindings = [
        {
            "raw_sha256": hashlib.sha256(shared_raw).hexdigest(),
            "file_id": {"volume_serial_number": 1, "file_id_128": "a" * 32},
            "receipt": shared,
        },
        {
            "raw_sha256": artifact.raw_sha256,
            "file_id": {"volume_serial_number": 1, "file_id_128": "b" * 32},
            "receipt": artifact.receipt,
        },
    ]
    with pytest.raises(QualificationEvaluatorError):
        validate_runtime_bindings(bindings)


@pytest.mark.parametrize("attack", ["gpu", "exit", "missing", "sample_interval"])
def test_runtime_prebinding_attacks_fail_closed(attack: str) -> None:
    exits = list(expected_process_exit_records())
    kwargs: dict[str, object] = {
        "started_perf_counter_ns": 1,
        "ended_perf_counter_ns": 2,
        "sample_count": 1,
        "sample_interval_max_ms": 1.0,
        "peak_process_tree_rss_bytes": 1,
        "peak_vram_bytes": 0,
        "gpu_process_observation_count": 0,
        "process_exit_records": exits,
    }
    if attack == "gpu":
        kwargs["peak_vram_bytes"] = 1
    elif attack == "exit":
        exits[-1] = {"process_role": "worker", "worker_ordinal": 15, "exit_code": 1}
    elif attack == "missing":
        kwargs["process_exit_records"] = exits[:-1]
    else:
        kwargs["sample_interval_max_ms"] = 100.1
    with pytest.raises(HofsV12QualificationServiceError):
        build_isolated_c4_runtime_prebinding(**kwargs)  # type: ignore[arg-type]


def test_exact_50_task_universe_and_duplicate_attacks() -> None:
    bindings = [
        _binding(
            task_ordinal=ordinal,
            raw_sha256=hashlib.sha256(f"raw-{ordinal}".encode()).hexdigest(),
            semantic_sha256=hashlib.sha256(f"semantic-{ordinal}".encode()).hexdigest(),
        )
        for ordinal in range(TASK_COUNT)
    ]
    assert validate_exact_task_universe(bindings) == tuple(bindings)
    with pytest.raises(HofsV12QualificationServiceError, match="reordered"):
        validate_exact_task_universe([bindings[1], bindings[0], *bindings[2:]])
    duplicated = list(bindings)
    duplicated[1] = replace(
        duplicated[1], canonical_raw_sha256=duplicated[0].canonical_raw_sha256
    )
    with pytest.raises(HofsV12QualificationServiceError, match="raw bindings"):
        validate_exact_task_universe(duplicated)


def test_source_model_version_requires_final_hash() -> None:
    digest = "a" * 64
    assert build_source_model_version(digest) == (
        "hofs_v12_fresh_qualification_service_v1__source_closure_sha256_"
        f"{digest}__frozen_v7_r2_numeric_lineage"
    )
    with pytest.raises(HofsV12QualificationServiceError):
        build_source_model_version("PENDING")


def test_no_spent_plan_runtime_patch_path_or_publication_surface() -> None:
    package_root = Path(service.__file__).resolve().parent
    sources = "\n".join(
        (package_root / name).read_text(encoding="utf-8")
        for name in ("contracts.py", "runtime.py", "service.py")
    )
    assert "build_" + "r4_fold_plan_v7" not in sources
    assert "monkey" + "patch" not in sources
    assert "research.model_zoo.dgp_suite" not in sources
    assert "os.replace" not in sources
    assert ".write_bytes(" not in sources
    assert ".write_text(" not in sources
    assert "Path(" not in sources
    signature = inspect.signature(compute_task_surface)
    assert tuple(signature.parameters) == ("canonical_input", "external_binding")
    assert all("path" not in name and "affinity" not in name for name in signature.parameters)
    spent_signature = inspect.signature(compute_spent_research_only_task_artifact)
    assert tuple(spent_signature.parameters) == ("canonical_input",)
    assert "compute_spent_research_only" not in inspect.getsource(compute_task_artifact)


def test_v7_numeric_source_closure_remains_exact() -> None:
    receipt = service.verify_numeric_source_closure()
    assert receipt["file_count"] == 12
    assert receipt["status"] == "PASS_EXACT_AUDITED_V7_NUMERIC_SOURCE_CLOSURE"


def test_raw_csv_frozen_r2_default_parser_fixture_is_exact(canonical_fixture) -> None:
    frame, raw, binding = canonical_fixture
    reparsed = pd.read_csv(io.BytesIO(raw))
    assert tuple(reparsed.columns) == CANONICAL_COLUMNS
    assert service._logical_frame_sha256(reparsed) == binding.canonical_semantic_sha256
    assert frame.equals(reparsed)
    assert "float_precision" not in inspect.getsource(service._parse_exact_canonical_csv)


def test_frozen_r2_parser_does_not_forward_a_precision_override(
    monkeypatch, canonical_fixture
) -> None:
    frame, raw, _ = canonical_fixture
    observed_kwargs: dict[str, object] = {}

    def capture_read_csv(stream, **kwargs):
        assert stream.read() == raw
        observed_kwargs.update(kwargs)
        return frame.copy(deep=True)

    monkeypatch.setattr(service.pd, "read_csv", capture_read_csv)
    assert service._parse_exact_canonical_csv(raw).equals(frame)
    assert observed_kwargs == {}


def test_receipt_json_boundary_rejects_numpy_pandas_and_nonfinite_scalars() -> None:
    valid = {
        "elapsed_ns": 1,
        "memory": {"peak_rss_bytes": 2},
        "files": [{"size_bytes": 3}],
        "counter": 0,
        "ratio": 0.0,
    }
    validate_exact_json_primitives(valid)
    assert service_canonical_json_bytes(valid).endswith(b"\n")
    for attacked in (
        {**valid, "counter": np.int32(0)},
        {**valid, "ratio": np.float64(0.0)},
        {**valid, "ratio": float("nan")},
        {**valid, "files": ({"size_bytes": 3},)},
    ):
        with pytest.raises(HofsV12QualificationServiceError):
            validate_exact_json_primitives(attacked)
