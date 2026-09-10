from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.channel import (
    read_message,
    validate_check_message,
    validate_generation_header,
    write_check_message,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.contracts import (
    DGPS,
    FULL_IDENTITIES_HEADER_RAW_SHA256,
    FULL_IDENTITY_COUNT,
    HELDOUT_SEEDS,
    PUBLIC_SOURCE_NAMES,
    PUBLIC_TASK_FILE_UNIVERSE,
    QUALIFICATION_SEEDS,
    R6_UNSEALED_DIRECT_FILES,
    R6_UNSEALED_TRANSITIVE_FILES,
    R7QualificationGenerationError,
    REGISTRY_AFTER,
    ROWS_PER_TASK,
    TASK_COUNT,
    TRUTH_COLUMNS,
    TRUTH_HEADER_RAW_SHA256,
    expected_tasks,
    require_registry_snapshot,
    require_stage_authority,
    sha256_bytes,
    task_relative,
    validate_public_request,
    validate_task_records,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.controller import (
    finalize_public_staging,
    validate_planned_public_path,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.one_shot import (
    OneShotCustody,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r7_qualification_generation.preflight import (
    validate_source_lock_structure,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = (
    PROJECT_ROOT
    / "research/model_zoo/observable_state_bce_dgp_tournament_v2_r7_qualification_generation"
)
SCRIPT = (
    PROJECT_ROOT
    / "scripts/model_lab/observable_state_bce_dgp_tournament_v2_r7_qualification_generation"
)
TOKEN = "a" * 64
TOKEN_SHA256 = hashlib.sha256(TOKEN.encode("ascii")).hexdigest()
DESIGN_SHA256 = "b" * 64


def _request() -> dict[str, object]:
    return {
        "activation_token": TOKEN,
        "design_checksums_raw_sha256": DESIGN_SHA256,
        "dgp": "A",
        "public_run_id": "20260821T120000",
        "replay_pass": 1,
        "schema_version": (
            "expected_pe.observable_state_bce_dgp_tournament.v2.r7.qualification_public_request.v1"
        ),
        "seed": 7573,
        "stage": "QUALIFICATION",
        "task_relative": "replays/pass_1/seed_7573/dgp_A",
    }


def _validate(request: dict[str, object]) -> None:
    validate_public_request(
        request,
        activation_token_sha256=TOKEN_SHA256,
        design_checksums_raw_sha256=DESIGN_SHA256,
    )


def _task_records() -> list[dict[str, object]]:
    return [
        {
            "seed": seed,
            "dgp": dgp,
            "task_relative": f"seed_{seed}/dgp_{dgp}",
            "identity_sha256": "c" * 64,
            "artifact_raw_sha256": {name: "d" * 64 for name in PUBLIC_TASK_FILE_UNIVERSE},
        }
        for seed, dgp in expected_tasks()
    ]


def _load_bootstrap_module() -> object:
    path = SCRIPT / "trusted_bootstrap.py"
    spec = importlib.util.spec_from_file_location("r7_test_bootstrap", path)
    if spec is None or spec.loader is None:
        raise AssertionError("bootstrap import spec is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exact_qualification_and_heldout_geometry() -> None:
    assert QUALIFICATION_SEEDS == (7573, 7577, 7583, 7589, 7591)
    assert HELDOUT_SEEDS == (7603, 7607, 7621, 7639, 7643)
    assert set(QUALIFICATION_SEEDS).isdisjoint(HELDOUT_SEEDS)
    assert DGPS == tuple("ABCDEFGHIJ")
    assert TASK_COUNT == 50
    assert ROWS_PER_TASK == 1_800
    assert FULL_IDENTITY_COUNT == 90_000


def test_exact_truth_and_full_identity_headers() -> None:
    assert len(TRUTH_COLUMNS) == 7
    assert sha256_bytes((",".join(TRUTH_COLUMNS) + "\n").encode("ascii")) == (
        TRUTH_HEADER_RAW_SHA256
    )
    assert sha256_bytes(b"seed,dgp,row_position,date\n") == FULL_IDENTITIES_HEADER_RAW_SHA256


def test_r6_omission_repair_universes_are_exact() -> None:
    assert len(R6_UNSEALED_DIRECT_FILES) == 10
    assert len(R6_UNSEALED_TRANSITIVE_FILES) == 27
    assert set(R6_UNSEALED_DIRECT_FILES).issubset(R6_UNSEALED_TRANSITIVE_FILES)


def test_r7_execution_sources_do_not_import_legacy_runner_or_seed_constants() -> None:
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert "research.model_zoo.dgp_state_tournament_v1.runner" not in imports
        assert not any(name.endswith("dgp_state_tournament_v1.contracts") for name in imports)


def test_public_execution_sources_do_not_import_generator_or_protected_role() -> None:
    for name in ("controller.py", "public_adapter.py", "public_role.py", "replay.py"):
        tree = ast.parse((PACKAGE / name).read_text(encoding="utf-8"))
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
        assert all("protected_role" not in item for item in imports)
        assert all("dgp_exploration_v2" not in item for item in imports)
        assert all("dgp_suite" not in item for item in imports)


def test_protected_role_is_the_only_r7_generator_import() -> None:
    importers = []
    for path in PACKAGE.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(
            isinstance(node, ast.ImportFrom)
            and node.module == "research.model_zoo.dgp_exploration_v2.generator"
            for node in ast.walk(tree)
        ):
            importers.append(path.name)
    assert importers == ["protected_role.py"]


def test_check_channel_round_trip_has_zero_payload() -> None:
    stream = io.BytesIO()
    nonce = "e" * 64
    write_check_message(stream, nonce=nonce)
    validate_check_message(stream.getvalue(), nonce=nonce)
    header, frames = read_message(io.BytesIO(stream.getvalue()))
    assert header["generator_invoked"] is False
    assert header["payload_rows"] == 0
    assert tuple(frames) == PUBLIC_SOURCE_NAMES
    assert all(value == b"" for value in frames.values())


def test_check_channel_wrong_nonce_fails_closed() -> None:
    stream = io.BytesIO()
    write_check_message(stream, nonce="e" * 64)
    with pytest.raises(R7QualificationGenerationError):
        validate_check_message(stream.getvalue(), nonce="f" * 64)


def test_generation_header_wrong_geometry_fails_closed() -> None:
    header = {
        "schema_version": (
            "expected_pe.observable_state_bce_dgp_tournament.v2.r7.qualification_public_channel.v1"
        ),
        "stage": "QUALIFICATION",
        "seed": 7573,
        "dgp": "A",
        "replay_pass": 1,
        "rows": 1_799,
        "protected_path_included": False,
        "protected_value_included": False,
    }
    with pytest.raises(R7QualificationGenerationError):
        validate_generation_header(header, seed=7573, dgp="A", replay_pass=1)


def test_valid_public_request_passes() -> None:
    _validate(_request())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("stage", "HELDOUT"),
        ("seed", 7603),
        ("seed", 2026082001),
        ("dgp", "K"),
        ("replay_pass", 3),
        ("schema_version", "expected_pe.r6.legacy"),
        ("task_relative", "replays/pass_1/seed_7573/dgp_B"),
        ("design_checksums_raw_sha256", "f" * 64),
        ("activation_token", "0" * 64),
    ],
)
def test_wrong_public_request_fields_fail_closed(field: str, value: object) -> None:
    request = _request()
    request[field] = value
    with pytest.raises(R7QualificationGenerationError):
        _validate(request)


def test_extra_public_request_field_fails_closed() -> None:
    request = _request()
    request["marker_state"] = "CLAIMED_EXCLUSIVE"
    with pytest.raises(R7QualificationGenerationError):
        _validate(request)


def test_premature_heldout_authority_fails_closed() -> None:
    with pytest.raises(R7QualificationGenerationError):
        require_stage_authority(
            stage="HELDOUT",
            authority={
                "qualification_activation_authorized": True,
                "heldout_activation_authorized": False,
                "model_fit_prediction_score_evaluation_authorized": False,
                "activation_token_sha256": TOKEN_SHA256,
                "independent_audit_seal_raw_sha256": "1" * 64,
                "audit_finding_counts": {"P0": 0, "P1": 0, "P2": 0},
            },
        )


def test_nonzero_audit_findings_block_qualification_authority() -> None:
    with pytest.raises(R7QualificationGenerationError):
        require_stage_authority(
            stage="QUALIFICATION",
            authority={
                "qualification_activation_authorized": True,
                "heldout_activation_authorized": False,
                "model_fit_prediction_score_evaluation_authorized": False,
                "activation_token_sha256": TOKEN_SHA256,
                "independent_audit_seal_raw_sha256": "1" * 64,
                "audit_finding_counts": {"P0": 0, "P1": 1, "P2": 0},
            },
        )


def test_registry_drift_fails_closed() -> None:
    require_registry_snapshot(REGISTRY_AFTER)
    drifted = dict(REGISTRY_AFTER)
    drifted["entry_count"] = 11
    with pytest.raises(R7QualificationGenerationError):
        require_registry_snapshot(drifted)


def test_task_record_requires_exact_artifact_universe() -> None:
    records = _task_records()
    validate_task_records(records)
    corrupted = copy.deepcopy(records)
    del corrupted[0]["artifact_raw_sha256"]["canonical150.csv"]  # type: ignore[index]
    with pytest.raises(R7QualificationGenerationError):
        validate_task_records(corrupted)


def test_receipt_only_parity_has_no_public_api() -> None:
    signature = ast.parse((PACKAGE / "controller.py").read_text(encoding="utf-8"))
    finalizer = next(
        node
        for node in signature.body
        if isinstance(node, ast.FunctionDef) and node.name == "finalize_public_staging"
    )
    argument_names = [argument.arg for argument in finalizer.args.kwonlyargs]
    assert "staging" in argument_names
    assert "first_receipts" not in argument_names
    assert "second_receipts" not in argument_names
    source = ast.get_source_segment(
        (PACKAGE / "controller.py").read_text(encoding="utf-8"), finalizer
    )
    assert source is not None
    assert "_task_bytes" in source
    assert "first != second" in source


def test_public_finalizer_rejects_absent_artifact_tree(tmp_path: Path) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    metadata = {
        "aggregate_metadata_sha256": "1" * 64,
        "artifact_count": 200,
        "byte_hash_parity": True,
        "dgp_ids_sha256": "2" * 64,
        "generator_invocations": 100,
        "schema_version": "expected_pe.r7.qualification.protected_metadata_receipt.v1",
        "seed_ids_sha256": "3" * 64,
        "stage": "QUALIFICATION",
        "status": "PASS_OPAQUE_METADATA_ONLY_SEPARATE_PROCESS_TWO_PASS",
        "task_count": 50,
        "truth_header_raw_sha256": TRUTH_HEADER_RAW_SHA256,
    }
    with pytest.raises(R7QualificationGenerationError):
        finalize_public_staging(
            staging=staging,
            protected_metadata=metadata,
            design_checksums_raw_sha256="4" * 64,
            source_lock_raw_sha256="5" * 64,
            runtime_lock_semantic_sha256="6" * 64,
        )


def test_one_shot_complete_consume_and_duplicate_rejection(tmp_path: Path) -> None:
    custody = OneShotCustody(tmp_path / "activation", governed_parent=tmp_path)
    assert custody.inspect().state == "ABSENT"
    custody.claim(
        activation_token_sha256="1" * 64,
        design_checksums_raw_sha256="2" * 64,
        independent_audit_seal_raw_sha256="3" * 64,
        public_output_name="public",
        vault_capability_sha256="4" * 64,
    )
    assert custody.inspect().state == "CLAIMED_EXCLUSIVE"
    with pytest.raises(R7QualificationGenerationError):
        custody.claim(
            activation_token_sha256="1" * 64,
            design_checksums_raw_sha256="2" * 64,
            independent_audit_seal_raw_sha256="3" * 64,
            public_output_name="public",
            vault_capability_sha256="4" * 64,
        )
    custody.complete(public_tree_sha256="5" * 64, protected_metadata_sha256="6" * 64)
    custody.consume(published_output_raw_sha256="7" * 64)
    state = custody.inspect()
    assert state.state == "CONSUMED"
    assert state.retry_allowed is False


def test_one_shot_crash_abort_blocks_resume(tmp_path: Path) -> None:
    custody = OneShotCustody(tmp_path / "activation", governed_parent=tmp_path)
    custody.claim(
        activation_token_sha256="1" * 64,
        design_checksums_raw_sha256="2" * 64,
        independent_audit_seal_raw_sha256="3" * 64,
        public_output_name="public",
        vault_capability_sha256="4" * 64,
    )
    custody.abort(failure_class="SyntheticCrash")
    state = custody.inspect()
    assert state.state == "ABORTED_NO_REUSE"
    assert state.recovery_action == "PRESERVE_FOR_AUDIT"
    with pytest.raises(R7QualificationGenerationError):
        custody.complete(public_tree_sha256="5" * 64, protected_metadata_sha256="6" * 64)


def test_one_shot_extra_marker_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "activation"
    root.mkdir()
    (root / "unexpected.json").write_text("{}", encoding="ascii")
    with pytest.raises(R7QualificationGenerationError):
        OneShotCustody(root, governed_parent=tmp_path).inspect()


def test_planned_public_path_requires_absent_direct_output_child(tmp_path: Path) -> None:
    valid = tmp_path / (
        "model_zoo_observable_state_bce_dgp_tournament_v2_r7_qualification_generation_probe"
    )
    receipt = validate_planned_public_path(valid, outputs_root=tmp_path)
    assert receipt["absolute_path_returned"] is False
    nested = tmp_path / "nested" / valid.name
    with pytest.raises(R7QualificationGenerationError):
        validate_planned_public_path(nested, outputs_root=tmp_path)


def test_public_filesystem_guard_denies_other_output_root() -> None:
    bootstrap = _load_bootstrap_module()
    public_root = (
        PROJECT_ROOT
        / "outputs"
        / (
            "model_zoo_observable_state_bce_dgp_tournament_v2_"
            "r7_qualification_generation_guard_probe"
        )
    )
    guard = bootstrap.PublicFilesystemGuard(public_root=public_root)  # type: ignore[attr-defined]
    fake_private = PROJECT_ROOT / "outputs" / ".r7_private_guard_probe" / "truth.csv"
    with pytest.raises(PermissionError):
        guard("open", (str(fake_private), "rb", 0))


def test_source_lock_rejects_caller_maps_by_construction() -> None:
    source = (SCRIPT / "trusted_bootstrap.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    parser_function = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "parser"
    )
    parser_source = ast.get_source_segment(source, parser_function)
    assert parser_source is not None
    assert "source-map" not in parser_source
    assert "source-hash" not in parser_source


def test_source_lock_structure_rejects_missing_and_extra_dependencies() -> None:
    locked = json.loads((SCRIPT / "SOURCE_LOCK.json").read_bytes())
    validate_source_lock_structure(locked)
    missing = copy.deepcopy(locked)
    missing["execution_transitive_local_files"].pop()
    with pytest.raises(R7QualificationGenerationError):
        validate_source_lock_structure(missing)
    extra = copy.deepcopy(locked)
    extra["execution_transitive_local_files"].append("research/model_zoo/untrusted.py")
    with pytest.raises(R7QualificationGenerationError):
        validate_source_lock_structure(extra)


def test_exact_task_relative_rejects_heldout() -> None:
    assert task_relative(replay_pass=2, seed=7573, dgp="J") == ("replays/pass_2/seed_7573/dgp_J")
    with pytest.raises(R7QualificationGenerationError):
        task_relative(replay_pass=1, seed=7603, dgp="A")


def test_real_check_only_spawns_roles_without_generation() -> None:
    command = [
        str(Path(sys.executable).resolve()),
        "-I",
        "-S",
        "-B",
        "-E",
        str(SCRIPT / "trusted_bootstrap.py"),
        "check-only-preflight",
    ]
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper()
        in {
            "ALLUSERSPROFILE",
            "APPDATA",
            "COMSPEC",
            "HOMEDRIVE",
            "HOMEPATH",
            "LOCALAPPDATA",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "PATHEXT",
            "PROCESSOR_ARCHITECTURE",
            "PROCESSOR_IDENTIFIER",
            "PROGRAMDATA",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "PROGRAMW6432",
            "SYSTEMDRIVE",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "USERDOMAIN",
            "USERNAME",
            "USERPROFILE",
            "WINDIR",
        }
    }
    environment.update(
        {
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_NUM_THREADS": "1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "NUMEXPR_NUM_THREADS": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
        }
    )
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        env=environment,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", errors="replace")
    receipt = json.loads(completed.stdout)
    assert receipt["generator_invocation_count"] == 0
    assert receipt["replay_invocation_count"] == 0
    assert receipt["pipeline"]["anonymous_one_way_pipe_used"] is True
    assert receipt["pipeline"]["public_command_contains_protected_path"] is False
    assert receipt["pipeline"]["public_receipt"]["forbidden_module_count"] == 0
    assert receipt["pipeline"]["public_finalizer_returncode"] == 0
    assert receipt["pipeline"]["public_finalizer_receipt"]["artifact_open_count"] == 0
