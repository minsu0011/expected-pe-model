from __future__ import annotations

import ast
import csv
import importlib
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
from types import SimpleNamespace

import pytest

from research.model_zoo.causal_valuation_tcn_cross_bound_full_execution_research_v1 import (
    authority,
    boundary_smoke,
    contracts,
    ipc,
    path_guards,
    prelaunch,
    publication,
    runner,
)
from research.model_zoo.causal_valuation_tcn_cross_bound_full_execution_research_v1 import (
    _clean_cache_bootstrap as clean_bootstrap,
)
from research.model_zoo.causal_valuation_tcn_cross_bound_full_execution_research_v1 import (
    pycache_guard,
)
from research.model_zoo.causal_valuation_tcn_cross_bound_full_execution_research_v1._win_job import (
    CREATE_SUSPENDED,
    WindowsKillOnCloseJob,
    resume_suspended_process,
)


PACKAGE = Path(contracts.__file__).resolve().parent
PARENT_MODULES = (
    "__init__.py",
    "_clean_cache_bootstrap.py",
    "contracts.py",
    "path_guards.py",
    "prelaunch.py",
    "authority.py",
    "boundary_smoke.py",
    "_win_job.py",
    "ipc.py",
    "publication.py",
    "runner.py",
    "pycache_guard.py",
)


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_bytes(contracts.canonical_json_bytes(payload))


def test_exact_clipped_shard_geometry() -> None:
    assert contracts.derive_shard_rows() == {
        "shard_00": 21_750,
        "shard_01": 22_050,
        "shard_02": 21_000,
    }
    assert sum(contracts.derive_shard_rows().values()) == 64_800
    assert contracts.fold_test_rows()["fold_073"] == 15
    contracts.validate_geometry()


def test_uniform_rows_formula_is_explicitly_forbidden() -> None:
    false_rows = len(contracts.SHARD_ASSIGNMENTS["shard_00"]) * 1_050
    assert false_rows == 22_050
    assert false_rows != contracts.EXPECTED_SHARD_ROWS["shard_00"]
    assert contracts.FALSE_FIXED_ROWS_FORMULA_ALLOWED is False


def test_fold_partition_is_exact_and_disjoint() -> None:
    folds = [
        fold_id
        for values in contracts.SHARD_ASSIGNMENTS.values()
        for fold_id in values
    ]
    assert len(folds) == len(set(folds)) == 62
    assert "fold_073" in contracts.SHARD_ASSIGNMENTS["shard_00"]
    assert set(folds) == set(contracts.fold_test_rows())


def test_authority_is_research_only_and_fail_closed() -> None:
    assert contracts.AUTHORITY_FLAGS == {
        "research_only": True,
        "spent_public_r4_only": True,
        "truth_allowed": False,
        "score_allowed": False,
        "fresh_allowed": False,
        "heldout_allowed": False,
        "latent_allowed": False,
        "formal_v8_identity_created_or_consumed": False,
        "model_state_serialization_allowed": False,
    }
    assert contracts.BROKEN_ADAPTER_V1["status"] == "FORBIDDEN_BROKEN_PREDECESSOR"
    assert contracts.BROKEN_ADAPTER_V1["launch_authority"] is False


def test_authority_remains_blocked_without_boundary_pass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_missing_smoke() -> dict[str, object]:
        raise contracts.CrossBoundContractError("boundary smoke PASS is absent")

    monkeypatch.setattr(boundary_smoke, "binding_for_authority", reject_missing_smoke)
    with pytest.raises(contracts.CrossBoundContractError, match="smoke PASS"):
        authority.build_authority_payload()
    readiness = prelaunch.static_readiness()
    assert readiness["unresolved_placeholders"] == []
    assert readiness["full_run_launched"] is False


def test_parent_module_closure_has_no_torch_import() -> None:
    for name in PARENT_MODULES:
        imports = _imports(PACKAGE / name)
        assert not any(value == "torch" or value.startswith("torch.") for value in imports)


def test_only_private_worker_imports_torch_and_training_core() -> None:
    worker_imports = _imports(PACKAGE / "_private_full_shard_worker.py")
    assert "torch" in worker_imports
    assert any("causal_valuation_tcn_private_process_research_v1" in value for value in worker_imports)
    for name in PARENT_MODULES:
        imports = _imports(PACKAGE / name)
        assert not any("._private_worker" in value for value in imports)


def test_runtime_source_closure_is_exact_and_cache_free() -> None:
    manifest = contracts.runtime_source_manifest()
    assert tuple(manifest) == contracts.RUNTIME_SOURCE_FILES
    assert all(contracts.is_concrete_sha256(value) for value in manifest.values())
    assert not list(PACKAGE.rglob("__pycache__"))
    assert not list(PACKAGE.rglob("*.pyc"))


def test_cache_guard_rejects_bytecode(tmp_path: Path) -> None:
    (tmp_path / "__pycache__").mkdir()
    with pytest.raises(contracts.CrossBoundContractError, match="cache"):
        contracts.reject_cache_paths(tmp_path)


def test_broken_adapter_and_rejection_audit_live_pins() -> None:
    audit = prelaunch.verify_broken_adapter_v1(contracts.project_root())
    assert audit["status"].startswith("REJECT_FROZEN_R1_ADAPTER")
    assert audit["exact_geometry"]["shards"]["shard_00"]["exact_prediction_rows"] == 21_750
    assert audit["exact_geometry"]["false_uniform_overstatement_rows"] == 300


def test_upstream_training_sharded_and_prepare_evidence_live() -> None:
    root = contracts.project_root()
    prelaunch.verify_training_source(root)
    prelaunch.verify_sharded_source(root)
    equivalence = prelaunch.verify_equivalence_v2(root)
    prepare = prelaunch.verify_prepare_only_v2(root)
    assert equivalence["accepted"] is True
    assert prepare["full_run_allowed"] is False


def test_corrected_adapter_has_exact_live_binding() -> None:
    assert contracts.placeholder_paths(contracts.CORRECTED_ADAPTER_V2_PINS) == []
    design = prelaunch.verify_corrected_adapter_v2(contracts.project_root())
    assert design["shard_row_geometry"]["pinned_prediction_rows"] == {
        "shard_00": 21_750,
        "shard_01": 22_050,
        "shard_02": 21_000,
    }


def test_corrected_adapter_hash_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drifted = dict(contracts.CORRECTED_ADAPTER_V2_PINS)
    drifted["design_lock_raw_sha256"] = "0" * 64
    monkeypatch.setattr(prelaunch, "CORRECTED_ADAPTER_V2_PINS", drifted)
    with pytest.raises(contracts.CrossBoundContractError, match="pinned artifact drifted"):
        prelaunch.verify_corrected_adapter_v2(contracts.project_root())


def test_training_source_pin_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drifted = dict(contracts.TRAINING_V1_SOURCE_MANIFEST)
    drifted["contracts.py"] = "0" * 64
    monkeypatch.setattr(prelaunch, "TRAINING_V1_SOURCE_MANIFEST", drifted)
    with pytest.raises(contracts.CrossBoundContractError, match="source closure drifted"):
        prelaunch.verify_training_source(contracts.project_root())


def test_output_path_guard_rejects_escape_and_forbidden_namespace(tmp_path: Path) -> None:
    (tmp_path / "outputs").mkdir()
    with pytest.raises(contracts.CrossBoundContractError):
        path_guards.resolve_output_path("../escape", root=tmp_path)
    with pytest.raises(contracts.CrossBoundContractError, match="forbidden"):
        path_guards.resolve_output_path("outputs/fresh_candidate", root=tmp_path)


def test_incomplete_predecessor_is_exact_and_nonauthoritative() -> None:
    actual = path_guards.verify_incomplete_predecessor()
    assert actual == contracts.INCOMPLETE_SINGLE_CHILD_FILES
    assert not any("PREDICTIONS" in name or "RECEIPT" in name for name in actual)


def test_attempt_marker_consumes_identity_before_panel(tmp_path: Path) -> None:
    authority_path = tmp_path / "AUTHORITY.json"
    payload = {"authority_semantic_sha256": "a" * 64}
    _write_json(authority_path, payload)
    work = tmp_path / "work"
    marker = ipc.create_attempt_workspace(
        work,
        authority_path=authority_path,
        authority=payload,
    )
    assert marker.is_file()
    assert not (work / "public_input").exists()
    with pytest.raises(contracts.CrossBoundContractError, match="already consumed"):
        ipc.create_attempt_workspace(
            work,
            authority_path=authority_path,
            authority=payload,
        )


def test_failure_receipt_is_external_single_write_and_forbids_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    marker = work / ipc.ATTEMPT_MARKER_FILE
    marker.write_bytes(b"marker")
    authority_path = tmp_path / "AUTHORITY.json"
    authority_path.write_bytes(b"{}\n")
    failure = tmp_path / "FAILURE.json"

    def fake_resolve(relative: str) -> Path:
        if relative == contracts.FAILURE_RECEIPT_PATH:
            return failure
        return tmp_path / Path(relative).name

    monkeypatch.setattr(runner, "resolve_output_path", fake_resolve)
    monkeypatch.setattr(runner, "project_root", lambda: tmp_path)
    first = runner._write_failure_receipt_once(
        error=RuntimeError("synthetic failure"),
        authority_path=authority_path,
        work_root=work,
        staging_root=tmp_path / "staging",
    )
    assert first == failure
    receipt = json.loads(failure.read_text(encoding="utf-8"))
    assert receipt["retry_allowed"] is False
    assert receipt["in_place_retry_allowed"] is False
    before = failure.read_bytes()
    second = runner._write_failure_receipt_once(
        error=RuntimeError("must not overwrite"),
        authority_path=authority_path,
        work_root=work,
        staging_root=tmp_path / "staging",
    )
    assert second == failure
    assert failure.read_bytes() == before


def test_full_request_rows_are_exact_not_fold_count_formula(tmp_path: Path) -> None:
    authority_path = tmp_path / "AUTHORITY.json"
    authority_payload = {
        "authority_semantic_sha256": "b" * 64,
        "boundary_fold_073_integration_smoke": {
            "private_child_loaded_source_manifest_semantic_sha256": "c" * 64,
        },
    }
    _write_json(authority_path, authority_payload)
    work = tmp_path / "work"
    ipc.create_attempt_workspace(
        work,
        authority_path=authority_path,
        authority=authority_payload,
    )
    panel = tmp_path / "panel.npz"
    panel.write_bytes(b"panel")
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"{}\n")
    requests = ipc.build_shard_requests(
        work_root=work,
        authority_path=authority_path,
        authority=authority_payload,
        panel_path=panel,
        panel_manifest_path=manifest,
        task_count=50,
    )
    observed = {
        json.loads(path.read_text(encoding="utf-8"))["shard_id"]: json.loads(
            path.read_text(encoding="utf-8")
        )["expected_prediction_rows"]
        for path in requests
    }
    assert observed == contracts.EXPECTED_SHARD_ROWS


def test_boundary_request_uses_separate_marker_and_750_rows(tmp_path: Path) -> None:
    work = tmp_path / "smoke_work"
    work.mkdir()
    marker = {"status": "SMOKE"}
    _write_json(work / "SMOKE_ATTEMPT_MARKER.json", marker)
    design_path = tmp_path / "SMOKE_DESIGN_LOCK.json"
    design = {"smoke_design_semantic_sha256": "c" * 64}
    _write_json(design_path, design)
    panel = tmp_path / "panel.npz"
    panel.write_bytes(b"panel")
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(b"{}\n")
    request_path = ipc.build_boundary_smoke_request(
        work_root=work,
        design_path=design_path,
        design=design,
        panel_path=panel,
        panel_manifest_path=manifest,
        task_count=50,
    )
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert request["assigned_fold_ids"] == ["fold_073"]
    assert request["expected_prediction_rows"] == 750
    assert request["uniform_1050_per_fold_allowed"] is False
    assert request["execution_class"] == contracts.BOUNDARY_SMOKE_EXECUTION_CLASS


def test_child_csv_validator_rejects_uniform_shard_00_count(tmp_path: Path) -> None:
    path = tmp_path / "SHARD_PREDICTIONS.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(contracts.PREDICTION_COLUMNS))
        writer.writeheader()
    with pytest.raises(contracts.CrossBoundContractError, match="row count"):
        publication._read_and_validate_child_rows(path, shard_id="shard_00")


def test_artifact_field_schemas_have_semantic_tail() -> None:
    assert contracts.DESIGN_LOCK_FIELDS[-1] == "design_lock_semantic_sha256"
    assert contracts.SHARD_PLAN_FIELDS[-1] == "plan_semantic_sha256"
    assert contracts.PREDICTION_MANIFEST_FIELDS[-1] == "manifest_semantic_sha256"
    assert contracts.RUN_RECEIPT_FIELDS[-1] == "run_receipt_semantic_sha256"
    assert contracts.CHILD_RECEIPT_FIELDS[-1] == "receipt_semantic_sha256"
    assert "PYCACHE_ISOLATION_RECEIPT.json" in authority.AUTHORITY_ROOT_FILES
    schema = authority.expected_prelaunch_schema_payload()
    assert schema["full_final_schema_allows_process_tree_support_fields"] is False
    assert schema["bootstrap_terminal_requires_no_late_project_import"] is True


def test_boundary_reference_bytes_are_pinned_to_sealed_v2_fold() -> None:
    sealed = (
        contracts.project_root()
        / "outputs/model_zoo_causal_valuation_tcn_sharded_execution_research_v2_"
        "equivalence_smoke_r1_20260822/shards/shard_02/FOLD_OUTPUT.f64"
    )
    assert contracts.sha256_file(sealed) == contracts.BOUNDARY_SMOKE_F64_RAW_SHA256
    result = json.loads(
        (sealed.parent / "SHARD_RESULT.json").read_text(encoding="utf-8")
    )
    assert result["fold_segment_digest_sha256"] == contracts.BOUNDARY_SMOKE_FOLD_SEGMENT_SHA256
    assert result["fold_output_rows"] == 750


def test_atomic_mini_publication_renames_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    predictions = source / "SHARD_PREDICTIONS.csv"
    predictions.write_text(",".join(contracts.PREDICTION_COLUMNS) + "\n", encoding="utf-8")
    receipt_path = source / "SHARD_RECEIPT.json"
    fold = dict(contracts.BOUNDARY_SMOKE_REFERENCE_FOLD)
    receipt = {
        "fold_receipts": [fold],
        "peak_working_set_bytes": 1,
        "maximum_vram_bytes": 1,
    }
    _write_json(receipt_path, receipt)
    design_path = tmp_path / "SMOKE_DESIGN_LOCK.json"
    design = {"smoke_design_semantic_sha256": "d" * 64}
    _write_json(design_path, design)
    containment_path = tmp_path / "PROCESS_TREE_CONTAINMENT_RECEIPT.json"
    containment = {
        "status": "PASS_PROCESS_TREE_CONTAINMENT_NORMAL_EXIT_ZERO_SURVIVORS",
        "process_bindings": [{"shard_id": "boundary_fold_073"}],
        "zero_surviving_wrapper_or_worker_pids": True,
    }
    containment["process_tree_receipt_semantic_sha256"] = contracts.semantic_sha256(
        containment
    )
    _write_json(containment_path, containment)
    parent_pycache_path = tmp_path / "PARENT_PYCACHE.json"
    child_pycache_path = tmp_path / "CHILD_PYCACHE.json"
    child_terminal_path = tmp_path / "CHILD_BOOTSTRAP_TERMINAL.json"
    parent_pycache_path.write_bytes(b"parent-pycache")
    child_pycache_path.write_bytes(b"child-pycache")
    child_terminal_path.write_bytes(b"child-terminal")

    def fake_isolation(
        path: Path,
        *,
        expected_label: str | None = None,
        expected_loaded_source_semantic_sha256: str | None = None,
    ) -> dict[str, object]:
        del path, expected_loaded_source_semantic_sha256
        return {
            "pycache_prefix": "fresh-prefix",
            "bootstrap_nonce": "nonce",
            "loaded_project_source_manifest_semantic_sha256": (
                "a" * 64 if expected_label == "boundary_smoke_public_parent" else "b" * 64
            ),
        }

    monkeypatch.setattr(
        boundary_smoke,
        "load_and_validate_isolation_receipt",
        fake_isolation,
    )
    monkeypatch.setattr(
        boundary_smoke,
        "load_and_validate_bootstrap_terminal_receipt",
        lambda *args, **kwargs: {},
    )
    staging = tmp_path / "staging"
    final = tmp_path / "final"
    result = boundary_smoke._publish_mini(
        staging=staging,
        final=final,
        design_path=design_path,
        predictions_path=predictions,
        receipt_path=receipt_path,
        receipt=receipt,
        f64_digest=contracts.BOUNDARY_SMOKE_F64_RAW_SHA256,
        segment_digest=contracts.BOUNDARY_SMOKE_FOLD_SEGMENT_SHA256,
        telemetry={
            "maximum_sampled_total_device_memory_bytes": 1,
            "wall_seconds": 1.0,
            "child_launch_count": 1,
            "child_retry_count": 0,
            "process_bindings": containment["process_bindings"],
            "zero_surviving_wrapper_or_worker_pids": True,
        },
        parent_pycache_path=parent_pycache_path,
        child_pycache_path=child_pycache_path,
        child_bootstrap_terminal_path=child_terminal_path,
        containment_path=containment_path,
    )
    assert result["status"] == contracts.BOUNDARY_SMOKE_STATUS
    assert final.is_dir()
    assert not staging.exists()
    assert {path.name for path in final.iterdir()} == set(boundary_smoke.SMOKE_FINAL_FILES)
    published_result = json.loads((final / "SMOKE_RESULT.json").read_text(encoding="utf-8"))
    published_receipt = json.loads(
        (final / "SMOKE_RUN_RECEIPT.json").read_text(encoding="utf-8")
    )
    assert published_result["process_tree_containment_receipt_raw_sha256"] == (
        contracts.sha256_file(containment_path)
    )
    assert published_result["process_bindings"] == containment["process_bindings"]
    assert published_receipt["zero_surviving_wrapper_or_worker_pids"] is True


def test_wrapper_worker_parent_binding_drift_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "shards" / "boundary_fold_073"
    directory.mkdir(parents=True)
    request = directory / "IPC_REQUEST.json"
    _write_json(
        request,
        {
            "shard_id": "boundary_fold_073",
            "execution_class": contracts.BOUNDARY_SMOKE_EXECUTION_CLASS,
        },
    )
    receipt = {
        "pid": 303,
        "parent_pid": 202,
        "declared_parent_pid": os.getpid(),
    }
    _write_json(directory / "SHARD_RECEIPT.json", receipt)
    (directory / contracts.CHILD_PYCACHE_RECEIPT_FILE).write_bytes(b"pycache")
    (directory / "BOOTSTRAP_TERMINAL_RECEIPT.json").write_bytes(b"terminal")
    monkeypatch.setattr(
        ipc,
        "load_and_validate_isolation_receipt",
        lambda *args, **kwargs: {
            "loaded_project_source_manifest_semantic_sha256": "d" * 64,
        },
    )
    monkeypatch.setattr(
        ipc,
        "load_and_validate_bootstrap_terminal_receipt",
        lambda *args, **kwargs: {},
    )
    wrapper = SimpleNamespace(pid=202)
    bindings = ipc._receipt_process_bindings([request], [wrapper])
    assert bindings[0]["worker_parent_pid"] == wrapper.pid
    receipt["parent_pid"] = 999
    _write_json(directory / "SHARD_RECEIPT.json", receipt)
    with pytest.raises(contracts.CrossBoundContractError, match="PID binding drifted"):
        ipc._receipt_process_bindings([request], [wrapper])


def test_terminal_checksum_ledger_rejects_member_and_universe_drift(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sealed"
    root.mkdir()
    member = root / "A.json"
    member.write_bytes(b"{}\n")
    ledger = root / "CHECKSUMS.sha256"
    ledger.write_text(
        f"{contracts.sha256_file(member)}  A.json\n",
        encoding="ascii",
    )
    records, observed = prelaunch.verify_checksum_ledger(root)
    assert records == {"A.json": contracts.sha256_file(member)}
    assert observed == contracts.sha256_file(ledger)
    member.write_bytes(b'{"drift":true}\n')
    with pytest.raises(contracts.CrossBoundContractError, match="member drifted"):
        prelaunch.verify_checksum_ledger(root)
    member.write_bytes(b"{}\n")
    (root / "UNLISTED.txt").write_text("drift", encoding="ascii")
    with pytest.raises(contracts.CrossBoundContractError, match="universe drifted"):
        prelaunch.verify_checksum_ledger(root)


def test_expected_commands_keep_parent_torch_free_and_child_private() -> None:
    commands = authority.expected_commands_payload()
    full = commands["future_full_command_after_independent_root_authorization"]
    assert full.startswith(contracts.PINNED_PARENT_PYTHON)
    assert contracts.PINNED_PARENT_PYTHON != contracts.PINNED_TORCH_PYTHON
    assert contracts.FUTURE_AUTHORITY_BUNDLE_PATH in full
    assert " -I -B " in full
    assert contracts.BOOTSTRAP_RELATIVE_PATH in full
    assert contracts.FULL_FINALIZATION_REQUEST_PATH in full
    assert contracts.FULL_BOOTSTRAP_TERMINAL_PATH in full
    smoke_commands = boundary_smoke.expected_smoke_commands_payload()
    assert smoke_commands["smoke_command"].startswith(contracts.PINNED_PARENT_PYTHON)
    assert smoke_commands["scoped_test_command"] == contracts.SCOPED_TEST_COMMAND
    assert smoke_commands["scoped_test_count"] == contracts.SCOPED_TEST_COUNT
    assert smoke_commands["reserved_full_command_allowed"] is False
    assert " -I -B " in smoke_commands["design_freeze_command"]
    assert contracts.BOUNDARY_SMOKE_DESIGN_FINALIZATION_REQUEST_PATH in (
        smoke_commands["design_freeze_command"]
    )
    assert authority.expected_authority_freeze_command() == (
        authority.expected_commands_payload()[
            "authority_freeze_command_used_for_this_bundle"
        ]
    )
    bootstrap_imports = _imports(PACKAGE / "_clean_cache_bootstrap.py")
    assert "subprocess" not in bootstrap_imports


def test_authority_payload_schema_or_authority_drift_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = {
        "status": contracts.BOUNDARY_SMOKE_STATUS,
        "process_tree_containment_receipt_raw_sha256": "e" * 64,
        "zero_surviving_wrapper_or_worker_pids": True,
    }
    monkeypatch.setattr(boundary_smoke, "binding_for_authority", lambda: binding)
    payload = authority.build_authority_payload()
    assert payload["partition"]["expected_shard_rows"] == contracts.EXPECTED_SHARD_ROWS
    payload["partition"]["expected_shard_rows"]["shard_00"] = 22_050
    with pytest.raises(contracts.CrossBoundContractError, match="differs"):
        prelaunch.validate_authority_payload(payload)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object contract")
def test_windows_job_terminates_real_redirector_descendant_tree() -> None:
    """Non-CUDA real-process negative test for race-free tree containment."""

    code = (
        "import os,subprocess,sys,time;"
        "p=subprocess.Popen([sys.executable,'-B','-c','import time;time.sleep(60)']);"
        "print(str(os.getpid())+' '+str(p.pid),flush=True);time.sleep(60)"
    )
    job = WindowsKillOnCloseJob(f"ExpectedPE_Test_{os.getpid()}")
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            [contracts.PINNED_TORCH_PYTHON, "-B", "-c", code],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=CREATE_SUSPENDED,
        )
        job.assign_process_handle(int(process._handle))
        thread_id = resume_suspended_process(process.pid)
        assert thread_id > 0
        assert process.stdout is not None
        actual_pid, grandchild_pid = [int(value) for value in process.stdout.readline().split()]
        observed = set(job.process_ids())
        assert process.pid in observed
        assert actual_pid in observed
        assert grandchild_pid in observed
        job.terminate()
        assert job.wait_empty(timeout_seconds=20.0) == []
        process.wait(timeout=20)
        assert process.poll() is not None
    finally:
        if process is not None and process.poll() is None:
            job.terminate()
            job.wait_empty(timeout_seconds=20.0)
            process.wait(timeout=20)
        job.close()


def test_current_python_parent_has_not_imported_torch() -> None:
    assert "torch" not in sys.modules


def test_same_pid_bootstrap_terminal_probe() -> None:
    project = contracts.project_root()
    relative_directory = (
        "outputs/"
        f"_tcn_cross_bound_same_pid_bootstrap_test_{os.getpid()}"
    )
    directory = project / relative_directory
    directory.mkdir(exist_ok=False)
    artifact = directory / "ARTIFACT.txt"
    isolation = directory / "PYCACHE_ISOLATION_RECEIPT.json"
    request = directory / "FINALIZATION_REQUEST.json"
    terminal = directory / "BOOTSTRAP_TERMINAL_RECEIPT.json"
    target = (
        "tests/model_lab/"
        "causal_valuation_tcn_cross_bound_full_execution_research_v1/"
        "bootstrap_probe_target.py"
    )
    try:
        completed = subprocess.run(
            [
                contracts.PINNED_PARENT_PYTHON,
                "-I",
                "-B",
                contracts.BOOTSTRAP_RELATIVE_PATH,
                "--finalization-request",
                request.relative_to(project).as_posix(),
                "--terminal-receipt",
                terminal.relative_to(project).as_posix(),
                "--script",
                target,
                "--",
                "--artifact",
                artifact.relative_to(project).as_posix(),
                "--isolation-receipt",
                isolation.relative_to(project).as_posix(),
            ],
            cwd=project,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        assert completed.returncode == 0, completed.stderr
        pycache_guard.load_and_validate_isolation_receipt(
            isolation,
            expected_label="same_pid_bootstrap_negative_probe",
        )
        terminal_payload = pycache_guard.load_and_validate_bootstrap_terminal_receipt(
            terminal,
            expected_label="same_pid_bootstrap_negative_probe",
            expected_owned_prefix=True,
            expected_bind_files={
                "artifact": artifact,
                "pycache_isolation_receipt": isolation,
            },
        )
        assert terminal_payload["target_source_matches_late_receipt"] is True
        assert terminal_payload["new_project_import_after_last_late_receipt"] is False
        assert terminal_payload["prefix_removed_after_final_check"] is True
    finally:
        for path in (artifact, isolation, request, terminal):
            if path.is_file() and not path.is_symlink():
                path.unlink()
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()


def test_adjacent_unchecked_pyc_is_ignored_by_same_pid_prefix(tmp_path: Path) -> None:
    payload = pycache_guard.runtime_isolation_payload(label="pytest_adjacent_pyc_probe")
    assert payload["same_pid_bootstrap"] is True
    assert payload["adjacent_pyc_files_detected_and_ignored"]
    module_name = f"tcn_adjacent_pyc_probe_{os.getpid()}"
    source = tmp_path / f"{module_name}.py"
    adjacent = tmp_path / "__pycache__" / f"{module_name}.cpython-310.pyc"
    adjacent.parent.mkdir()
    source.write_text("VALUE = 'adjacent-pyc'\n", encoding="utf-8")
    py_compile.compile(
        str(source),
        cfile=str(adjacent),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    source.write_text("VALUE = 'reviewed-source'\n", encoding="utf-8")
    sys.path.insert(0, str(tmp_path))
    importlib.invalidate_caches()
    try:
        module = importlib.import_module(module_name)
        assert module.VALUE == "reviewed-source"
        cached = Path(module.__cached__).resolve(strict=False)
        prefix = Path(str(sys.pycache_prefix)).resolve(strict=True)
        assert cached.is_relative_to(prefix)
        assert not cached.exists()
        assert adjacent.is_file()
    finally:
        sys.modules.pop(module_name, None)
        sys.path.remove(str(tmp_path))


@pytest.mark.parametrize(
    "unsafe",
    [
        "../escape.json",
        "/absolute.json",
        "C:drive-relative.json",
        "C:/absolute.json",
        "//server/share.json",
        r"outputs\backslash.json",
        "outputs/colon:name.json",
        "outputs/CON/file.json",
        "outputs/LPT1.txt",
        "outputs/CLOCK$/file.json",
        "outputs/CONIN$.txt",
        "outputs/CONOUT$/file.json",
        "outputs/COM¹.json",
        "outputs/LPT³.txt",
        "outputs/trailing./file.json",
        "outputs/trailing /file.json",
        "outputs//duplicate.json",
    ],
)
def test_bootstrap_finalization_path_rejects_windows_aliases(unsafe: str) -> None:
    with pytest.raises(clean_bootstrap.CleanCacheBootstrapError):
        clean_bootstrap._safe_project_path(contracts.project_root(), unsafe)
