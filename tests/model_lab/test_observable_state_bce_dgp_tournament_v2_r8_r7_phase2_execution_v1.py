from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation import (  # noqa: E501
    contracts as r7_contracts,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1 import (  # noqa: E501
    archive_entry,
    backend,
    contracts,
    generation,
    generation_closure,
    import_closure,
    resource_smoke,
    supervision,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r7_phase2_execution_v1.canonical import (  # noqa: E501
    Phase2DesignError,
    canonical_json_bytes,
    sha256_bytes,
)


PROJECT = Path(__file__).resolve().parents[2]
BUILDER_PATH = (
    PROJECT
    / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r7_phase2_execution_v1/freeze_execution.py"
)
ZERO_SHA = "0" * 64


def _digest(label: str) -> str:
    return sha256_bytes(label.encode("ascii"))


def _concrete(module: str, token: str) -> dict[str, Any]:
    return {
        "module": module,
        "origin_class": "FROZEN_EXECUTION_ARCHIVE_MEMBER",
        "origin_identity": f"phase2_execution/{module.replace('.', '/')}.py",
        "content_raw_sha256": _digest(f"content:{token}"),
        "content_size_bytes": len(token),
        "held_container_relative": "fixed/EXECUTION.pyz",
        "held_container_raw_sha256": _digest("execution archive"),
        "held_container_size_bytes": 4096,
        "held_container_volume_serial_number": 17,
        "held_container_file_id_128": "17" * 16,
    }


def _snapshot(stage: str, records: list[dict[str, Any]]) -> dict[str, Any]:
    concrete = sorted(records, key=lambda row: row["module"])
    combined = [
        {"kind": "CONCRETE", **record}
        for record in concrete
    ]
    return {
        "schema_version": "expected_pe.r8.r7.phase2.loaded_origin_snapshot.v1",
        "status": "PASS_NO_MUTABLE_WORKSPACE_OR_UNHELD_MODULE_ORIGIN",
        "stage": stage,
        "concrete_records": concrete,
        "namespace_records": [],
        "concrete_record_count": len(concrete),
        "namespace_record_count": 0,
        "records_semantic_sha256": sha256_bytes(canonical_json_bytes(combined)),
        "mutable_workspace_origin_count": 0,
        "unheld_origin_count": 0,
        "base_parent_search_count": 0,
    }


def _refresh_receipt(receipt: dict[str, Any]) -> None:
    pre_modules = {
        record["module"] for record in receipt["pre_import_snapshot"]["concrete_records"]
    }
    concrete = [
        record
        for record in receipt["post_import_snapshot"]["concrete_records"]
        if record["module"] not in pre_modules
    ]
    combined = [{"kind": "CONCRETE", **record} for record in concrete]
    receipt["newly_loaded_concrete_records"] = concrete
    receipt["newly_loaded_namespace_records"] = []
    receipt["newly_loaded_record_count"] = len(combined)
    receipt["newly_loaded_records_semantic_sha256"] = sha256_bytes(
        canonical_json_bytes(combined)
    )
    semantic = {
        key: receipt[key]
        for key in sorted(import_closure.IMPORT_CLOSURE_KEYS - {"semantic_sha256"})
    }
    receipt["semantic_sha256"] = sha256_bytes(canonical_json_bytes(semantic))


def _receipt() -> dict[str, Any]:
    pre = _snapshot(
        "PRE_GENERATION_IMPORT", [_concrete("preexisting.module", "pre")]
    )
    entrypoint_modules = [
        import_closure.ENTRYPOINTS[0],
        import_closure.ENTRYPOINTS[1],
        import_closure.ENTRYPOINTS[2].split(":", 1)[0],
    ]
    post = _snapshot(
        "POST_GENERATION_IMPORT",
        [
            deepcopy(pre["concrete_records"][0]),
            *(
                _concrete(module, f"entrypoint-{index}")
                for index, module in enumerate(entrypoint_modules)
            ),
        ],
    )
    receipt: dict[str, Any] = {
        "schema_version": (
            "expected_pe.r8.r7.phase2.generation_import_closure_receipt.v1"
        ),
        "status": (
            "PASS_FROZEN_ARCHIVE_NARROW_IMPORT_SPENT_DRY_RUN_UNHELD_ZERO"
        ),
        "execution_archive_raw_sha256": _digest("execution archive"),
        "execution_source_identity_raw_sha256": _digest("source identity"),
        "generation_external_input_closure_raw_sha256": _digest(
            "generation closure"
        ),
        "entrypoints": list(import_closure.ENTRYPOINTS),
        "pre_import_snapshot": pre,
        "post_import_snapshot": post,
        "newly_loaded_concrete_records": [],
        "newly_loaded_namespace_records": [],
        "newly_loaded_record_count": 0,
        "newly_loaded_records_semantic_sha256": ZERO_SHA,
        "runtime_distribution_names": sorted(
            generation_closure.EXPECTED_RUNTIME_DISTRIBUTIONS
        ),
        "runtime_distribution_count": len(
            generation_closure.EXPECTED_RUNTIME_DISTRIBUTIONS
        ),
        "runtime_distributions_semantic_sha256": _digest("runtime distributions"),
        "python_runtime_records_semantic_sha256": (
            generation_closure.PYTHON_RUNTIME_RECORDS_SEMANTIC_SHA256
        ),
        "expected_worker_resource_contract_semantic_sha256": _digest(
            "worker resource contract"
        ),
        "mutable_workspace_import_count": 0,
        "unheld_origin_count": 0,
        "generator_invocation_count": 0,
        "comparator_invocation_count": 0,
        "qualification_generation_count": 0,
        "actual_process_launch_count": 0,
        "fresh_access_count": 0,
        "heldout_access_count": 0,
        "truth_access_count": 0,
        "score_access_count": 0,
        "semantic_sha256": ZERO_SHA,
    }
    _refresh_receipt(receipt)
    return receipt


def _load_builder() -> Any:
    spec = importlib.util.spec_from_file_location("phase2_execution_builder", BUILDER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _resource_receipt(
    ordinal: int,
    *,
    resource_hash: str,
    closure_hash: str,
    import_hash: str,
) -> dict[str, Any]:
    observations = [
        {
            "role": role,
            "pid": 10_000 + ordinal * 3 + index,
            "creation_time_100ns": 20_000_000 + ordinal * 3 + index,
            "cpu_ids": list(range(32)),
            "affinity_mask_hex": "0xFFFFFFFF",
            "environment": dict(generation.INNER_THREAD_ENVIRONMENT),
            "inner_thread_count": 1,
            "gpu_enabled": False,
        }
        for index, role in enumerate(generation.RESOURCE_PROCESS_ROLES)
    ]
    row: dict[str, Any] = {
        "schema_version": "expected_pe.r8.r7.phase2.worker_resource_receipt.v1",
        "status": (
            "PASS_EXACT_R7_FULL32_INNER1_GPU_OFF_WORKER_CHILD_GRANDCHILD"
        ),
        "invocation_ordinal": ordinal,
        "logical_task_ordinal": ordinal % 50,
        "replay_pass": ordinal // 50,
        "worker_slot": ordinal % 16,
        "expected_worker_resource_contract_semantic_sha256": resource_hash,
        "generation_external_input_closure_raw_sha256": closure_hash,
        "import_closure_receipt_semantic_sha256": import_hash,
        "process_observations": observations,
        "process_observation_count": 3,
        "caller_supplied_resource_claim_count": 0,
        "semantic_sha256": ZERO_SHA,
    }
    semantic = {
        key: row[key]
        for key in sorted(
            generation.WORKER_RESOURCE_RECEIPT_KEYS - {"semantic_sha256"}
        )
    }
    row["semantic_sha256"] = sha256_bytes(canonical_json_bytes(semantic))
    return row


def test_import_closure_positive_exact_synthetic_receipt() -> None:
    expected = _receipt()
    assert import_closure.validate_import_closure_receipt(expected) == expected


def test_import_closure_rejects_preexisting_module_origin_swap() -> None:
    receipt = _receipt()
    post = receipt["post_import_snapshot"]
    preexisting = next(
        record
        for record in post["concrete_records"]
        if record["module"] == "preexisting.module"
    )
    preexisting["content_raw_sha256"] = _digest("swapped")
    post["records_semantic_sha256"] = sha256_bytes(
        canonical_json_bytes(
            [
                {"kind": "CONCRETE", **record}
                for record in post["concrete_records"]
            ]
        )
    )
    _refresh_receipt(receipt)
    with pytest.raises(Phase2DesignError, match="preexisting module origin"):
        import_closure.validate_import_closure_receipt(receipt)


def test_import_closure_rejects_staged_origin_class() -> None:
    receipt = _receipt()
    receipt["post_import_snapshot"]["concrete_records"][1][
        "origin_class"
    ] = "HELD_V04_STAGED_PROJECT_FILE"
    with pytest.raises(Phase2DesignError, match="concrete loaded-origin record"):
        import_closure.validate_import_closure_receipt(receipt)


def test_import_closure_requires_all_three_concrete_entrypoints() -> None:
    receipt = _receipt()
    missing = import_closure.ENTRYPOINTS[1]
    post_records = receipt["post_import_snapshot"]["concrete_records"]
    receipt["post_import_snapshot"] = _snapshot(
        "POST_GENERATION_IMPORT",
        [record for record in post_records if record["module"] != missing],
    )
    _refresh_receipt(receipt)
    with pytest.raises(Phase2DesignError, match="receipt drifted"):
        import_closure.validate_import_closure_receipt(receipt)


def test_import_closure_requires_at_least_one_new_module() -> None:
    receipt = _receipt()
    receipt["post_import_snapshot"] = _snapshot(
        "POST_GENERATION_IMPORT",
        deepcopy(receipt["pre_import_snapshot"]["concrete_records"]),
    )
    _refresh_receipt(receipt)
    with pytest.raises(Phase2DesignError, match="receipt drifted"):
        import_closure.validate_import_closure_receipt(receipt)


def test_final_and_staging_replay_emit_identical_canonical_bytes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive = tmp_path / "EXECUTION.pyz"
    archive.write_bytes(b"synthetic")
    expected = _receipt()

    class FakeCustody:
        def __enter__(self) -> "FakeCustody":
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def assert_all_reopen_exact(self) -> None:
            return None

    monkeypatch.setattr(
        generation_closure.GenerationExternalInputCustody,
        "for_frozen_import_smoke",
        classmethod(lambda _cls: FakeCustody()),
    )
    monkeypatch.setattr(
        generation_closure.GenerationExternalInputCustody,
        "for_final_import_replay",
        classmethod(lambda _cls: FakeCustody()),
    )
    monkeypatch.setattr(
        import_closure,
        "capture_frozen_import_closure_receipt",
        lambda **_kwargs: expected,
    )
    monkeypatch.setattr(sys, "argv", [str(archive)])
    assert import_closure.frozen_import_smoke_main() == 0
    staging_raw = capsys.readouterr().out.encode("ascii")
    assert import_closure.final_import_replay_main() == 0
    final_raw = capsys.readouterr().out.encode("ascii")
    assert final_raw == staging_raw == canonical_json_bytes(expected) + b"\n"


def test_archive_entry_dispatches_only_exact_final_replay_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        import_closure, "final_import_replay_main", lambda: 23
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["EXECUTION.pyz", archive_entry.IMPORT_CLOSURE_FINAL_REPLAY_FLAG],
    )
    assert archive_entry.main() == 23
    monkeypatch.setattr(sys, "argv", ["EXECUTION.pyz", "--similar-but-unbound"])
    assert archive_entry.main() == archive_entry.USAGE_EXIT_CODE


def test_command_lock_pins_both_import_modes() -> None:
    builder = _load_builder()
    command = json.loads(builder._command_lock())
    assert set(command) == archive_entry.COMMAND_LOCK_KEYS
    assert command["import_closure_argv_suffix"] == [
        archive_entry.IMPORT_CLOSURE_FLAG
    ]
    assert command["import_closure_final_replay_argv_suffix"] == [
        archive_entry.IMPORT_CLOSURE_FINAL_REPLAY_FLAG
    ]
    assert command["resource_smoke_staging_argv_suffix"] == [
        archive_entry.RESOURCE_SMOKE_STAGING_FLAG
    ]
    assert command["resource_smoke_final_replay_argv_suffix"] == [
        archive_entry.RESOURCE_SMOKE_FINAL_REPLAY_FLAG
    ]
    assert command["resource_smoke_child_argv_suffix"] == [
        archive_entry.RESOURCE_SMOKE_CHILD_FLAG
    ]


def test_builder_source_universe_covers_every_execution_module() -> None:
    builder = _load_builder()
    actual = {
        path.name
        for path in (PROJECT / builder.PACKAGE_RELATIVE).glob("*.py")
    }
    assert set(builder.PACKAGE_FILES) == actual
    assert all(
        (PROJECT / relative).is_file()
        for relative in builder.LOCAL_SOURCE_RELATIVES
    )


def test_builder_is_fail_closed_while_known_p0s_remain() -> None:
    builder = _load_builder()
    assert builder.FREEZE_BLOCKERS == (
        "QUALIFICATION_POLICY_V2_STILL_PINS_SUPERSEDED_ARCHITECTURE_V2",
        "V3_NO_FRESH_NATIVE_RESOURCE_IMPORT_AND_ROLE_DISPATCH_SMOKE_NOT_YET_PASS",
        "LIVE_ROLE_DISPATCH_AND_BOUNDED_CHOREOGRAPHY_INCOMPLETE",
        "ACTUAL_100_INVOCATION_RESOURCE_AND_REPLAY_AGGREGATE_INCOMPLETE",
    )


def test_v3_phase2_resource_contract_matches_frozen_r7() -> None:
    assert r7_contracts.CPU_IDS == tuple(range(32))
    assert r7_contracts.CPU_AFFINITY_MASK == 0xFFFFFFFF
    assert r7_contracts.EXACT_ENVIRONMENT["CUDA_VISIBLE_DEVICES"] == "-1"
    assert generation.LOGICAL_CPU_AFFINITY_PER_WORKER == 32
    assert generation.worker_affinity_mask(0) == 0xFFFFFFFF
    assert generation.INNER_THREAD_ENVIRONMENT == r7_contracts.EXACT_ENVIRONMENT
    assert generation_closure.WORKER_RESOURCE_CONTRACT_KEYS
    assert _load_builder().FREEZE_BLOCKERS


def test_v3_architecture_is_exact_and_v2_remains_immutable() -> None:
    v3_path = PROJECT.joinpath(*contracts.ARCHITECTURE_LOCK_RELATIVE.split("/"))
    v3_raw = v3_path.read_bytes()
    lock = contracts.parse_architecture_lock(v3_raw)
    assert sha256_bytes(v3_raw) == (
        "eed9bfce67408bd6adaffc9a9b1c4f21e8be9066bed406527c4110e2a0a1db3f"
    )
    assert lock["common_generation"]["outer_worker_count"] == 16
    assert lock["common_generation"]["logical_cpu_affinity_per_worker"] == 32
    assert lock["r7_resource_contract"]["exact_environment"] == (
        r7_contracts.EXACT_ENVIRONMENT
    )
    v2 = (
        PROJECT
        / "research/model_zoo/portfolio_governance_v1/"
        "PHASE2_R8_R7_EXECUTION_ARCHITECTURE_LOCK_V2.json"
    ).read_bytes()
    assert sha256_bytes(v2) == (
        "62fa37b06e1a5df1588e36bdba40dcf6b2dcc95513272ecad5245868d7ca13c7"
    )


def test_v3_phase2_plan_is_deterministic_but_not_freeze_ready() -> None:
    first = generation.deterministic_generation_plan()
    second = generation.deterministic_generation_plan()
    assert first == second
    assert len(first) == 100
    assert {row["worker_slot"] for row in first} == set(range(16))
    assert all(row["logical_cpu_affinity"] == list(range(32)) for row in first)


def test_runtime_distribution_minimum_is_exact_fourteen() -> None:
    assert set(generation_closure.EXPECTED_RUNTIME_DISTRIBUTIONS) == {
        "joblib",
        "lightgbm",
        "numpy",
        "pandas",
        "pyarrow",
        "python-dateutil",
        "pyyaml",
        "pytz",
        "scikit-learn",
        "scipy",
        "setuptools",
        "six",
        "statsmodels",
        "threadpoolctl",
    }


def test_resource_smoke_child_argv_has_no_caller_controlled_fields() -> None:
    staging = supervision.fixed_child_argv(
        supervision.ChildRole.NO_FRESH_RESOURCE_SMOKE_STAGING
    )
    final = supervision.fixed_child_argv(
        supervision.ChildRole.NO_FRESH_RESOURCE_SMOKE_FINAL
    )
    assert staging[-2:] == (
        supervision.EXECUTION_STAGING_ARCHIVE,
        archive_entry.RESOURCE_SMOKE_CHILD_FLAG,
    )
    assert final[-2:] == (
        supervision.EXECUTION_ARCHIVE,
        archive_entry.RESOURCE_SMOKE_CHILD_FLAG,
    )
    assert "pycache_prefix=" + supervision.RESOURCE_SMOKE_STAGING_PYCACHE_PREFIX in staging
    assert "pycache_prefix=" + supervision.RESOURCE_SMOKE_FINAL_PYCACHE_PREFIX in final


def test_resource_smoke_child_dispatch_executes_exact_resource_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    def observe(ordinal: int) -> dict[str, Any]:
        calls.append(ordinal)
        return {
            "cpu_ids": list(range(32)),
            "affinity_mask_hex": "0xFFFFFFFF",
            "gpu_enabled": False,
        }

    monkeypatch.setattr(resource_smoke, "validate_current_worker_resources", observe)
    monkeypatch.setattr(
        sys,
        "argv",
        ["EXECUTION.pyz", archive_entry.RESOURCE_SMOKE_CHILD_FLAG],
    )
    assert archive_entry.main() == 0
    assert calls == [0]


def test_pinned_sodium_randombytes_is_exact_c_buffer_and_zeroized() -> None:
    with backend.BackendClosureCustody() as custody:
        _ffi, _lib, receipt = backend.load_validated_sodium(custody=custody)
        api = receipt["native_api_closure"]
        assert api["randombytes_binding_name"] == "randombytes"
        assert api["randombytes_buffer_write_nonzero_proved"] is True
        assert api["randombytes_exact_two_argument_call"] is True
        assert api["randombytes_wrong_arity_rejected"] is True
        assert api["randombytes_probe_sodium_memzero_proved"] is True
        assert api["python_returning_random_api_used"] is False
        assert api["ctypes_symbol_bypass_used"] is False


def test_sodium_api_closure_rejects_missing_and_wrong_arity_swaps() -> None:
    with backend.BackendClosureCustody() as custody:
        ffi, lib, _receipt = backend.load_validated_sodium(custody=custody)

        class MissingRandombytes:
            def __getattr__(self, name: str) -> Any:
                if name == "randombytes":
                    raise AttributeError(name)
                return getattr(lib, name)

        class PermissiveRandombytes:
            def __getattr__(self, name: str) -> Any:
                return getattr(lib, name)

            def randombytes(self, *args: Any) -> Any:
                if len(args) == 1:
                    return lib.randombytes(args[0], 32)
                return lib.randombytes(*args)

        with pytest.raises(Phase2DesignError, match="API closure drifted"):
            backend.validate_sodium_api_closure(ffi, MissingRandombytes())
        with pytest.raises(Phase2DesignError, match="wrong arity"):
            backend.validate_sodium_api_closure(ffi, PermissiveRandombytes())


def test_two_pass_results_require_exact_100_resource_lineages() -> None:
    resource_hash = _digest("resource contract")
    closure_hash = _digest("generation closure")
    import_hash = _digest("import receipt")
    results = []
    for ordinal in range(100):
        receipt = _resource_receipt(
            ordinal,
            resource_hash=resource_hash,
            closure_hash=closure_hash,
            import_hash=import_hash,
        )
        results.append(
            {
                "schema_version": "expected_pe.r8.r7.phase2.worker_result.v1",
                "invocation_ordinal": ordinal,
                "logical_task_ordinal": ordinal % 50,
                "replay_pass": ordinal // 50,
                "result_raw_sha256": _digest(f"task:{ordinal % 50}"),
                "worker_resource_receipt": receipt,
                "worker_resource_receipt_semantic_sha256": receipt[
                    "semantic_sha256"
                ],
                "heldout_access_count": 0,
                "truth_access_count": 0,
                "score_access_count": 0,
                "error_count": 0,
            }
        )
    verified = generation.validate_two_pass_results(
        results,
        expected_worker_resource_contract_semantic_sha256=resource_hash,
        generation_external_input_closure_raw_sha256=closure_hash,
        import_closure_receipt_semantic_sha256=import_hash,
    )
    assert verified["worker_resource_receipt_count"] == 100
    assert verified["logical_cpu_affinity_per_worker"] == 32


def test_two_pass_results_reject_one_descendant_resource_drift() -> None:
    resource_hash = _digest("resource contract")
    closure_hash = _digest("generation closure")
    import_hash = _digest("import receipt")
    receipt = _resource_receipt(
        0,
        resource_hash=resource_hash,
        closure_hash=closure_hash,
        import_hash=import_hash,
    )
    receipt["process_observations"][2]["affinity_mask_hex"] = "0x00000003"
    with pytest.raises(Phase2DesignError, match="process observation drifted"):
        generation.validate_worker_resource_receipt(
            receipt,
            invocation_ordinal=0,
            expected_worker_resource_contract_semantic_sha256=resource_hash,
            generation_external_input_closure_raw_sha256=closure_hash,
            import_closure_receipt_semantic_sha256=import_hash,
        )
