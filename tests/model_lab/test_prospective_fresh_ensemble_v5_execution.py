from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from research.model_zoo.prospective_fresh_ensemble_v5.execution import pid_handshake
from research.model_zoo.prospective_fresh_ensemble_v5.execution.contracts import (
    DEFAULT_OUTPUT_NAME,
    HELDOUT_SEED_COMMITMENT_SHA256,
    QUALIFICATION_SEEDS,
    V5_RESERVATION_RAW_SHA256,
    V5_RESERVATION_SELF_SHA256,
    ProspectiveContractError,
    sha256_file,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.precommit import (
    verify_generator_smoke_evidence,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.generator_contract import (
    build_generator_plan,
    run_generator_smoke,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.heldout_authority import (
    require_heldout_live_authority,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.precommit_guard import (
    verify_precommit_root,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.process_runner import (
    spawn_actual_child_worker,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.qualification_authority import (
    require_qualification_parent_authority,
)
from research.model_zoo.prospective_fresh_ensemble_v5.execution.qualification_process import (
    spawn_qualification_worker,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_ROOT = PROJECT_ROOT / "outputs" / DEFAULT_OUTPUT_NAME


def test_exact_fresh_reservation_is_bound_without_exposing_heldout_ids() -> None:
    state = verify_precommit_root(OUTPUT_ROOT)
    receipt = state["seed_receipt"]

    assert sha256_file(OUTPUT_ROOT / "SEED_RESERVATION.json") == V5_RESERVATION_RAW_SHA256
    assert receipt["receipt_sha256"] == V5_RESERVATION_SELF_SHA256
    assert receipt["qualification_seeds"] == list(QUALIFICATION_SEEDS)
    assert receipt["heldout_seed_commitment_sha256"] == HELDOUT_SEED_COMMITMENT_SHA256
    assert receipt["heldout_identifiers_exposed_in_receipt"] is False
    assert "locked_seeds" not in receipt


def test_qualification_guard_has_no_transitive_seed_registry_resolver() -> None:
    paths = (
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v5/execution/precommit_guard.py",
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v5/execution/qualification_authority.py",
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v5/execution/qualification_process.py",
    )
    forbidden = (
        "seed_ledger",
        "read_registry",
        "locked_seeds",
        "reservation_contract_from_entry",
        "planned_seed_groups",
        ".precommit import",
    )

    for path in paths:
        source = path.read_text(encoding="utf-8").lower()
        assert not [token for token in forbidden if token in source], path


def test_descriptors_are_authority_files_outside_runtime_roots() -> None:
    state = verify_precommit_root(OUTPUT_ROOT)
    qualification = state["qualification_descriptor"]
    qualification_path = OUTPUT_ROOT / "QUALIFICATION_STAGE_DESCRIPTOR.json"
    heldout_path = OUTPUT_ROOT / "HELDOUT_STAGE_DESCRIPTOR.json"

    assert Path(qualification["runtime_root"]) == OUTPUT_ROOT / "runtime" / "qualification"
    assert qualification_path.parent != Path(qualification["runtime_root"])
    assert state["design"]["artifact_custody"]["descriptor_and_caller_path_seal"] == {
        "qualification_descriptor_relative": "QUALIFICATION_STAGE_DESCRIPTOR.json",
        "heldout_descriptor_relative": "HELDOUT_STAGE_DESCRIPTOR.json",
        "heldout_runtime_relative": "runtime/heldout",
        "heldout_descriptor_outside_runtime_root": True,
        "project_root_caller_argument_allowed": False,
        "worker_script_caller_argument_allowed": False,
        "child_extra_arguments_allowed": False,
        "worker_script_exact_by_stage_and_kind": True,
        "worker_command_template_exact_by_stage_and_kind": True,
    }
    assert not heldout_path.exists()
    assert not (OUTPUT_ROOT / "runtime").exists()


def test_parent_launch_apis_expose_no_caller_project_or_script_path() -> None:
    assert list(inspect.signature(spawn_qualification_worker).parameters) == [
        "output_root",
        "kind",
    ]
    assert list(inspect.signature(spawn_actual_child_worker).parameters) == [
        "precommit_root",
        "stage",
        "kind",
    ]
    assert "spawn_actual_child_bound_worker" not in pid_handshake.__all__
    assert list(
        inspect.signature(pid_handshake._spawn_actual_child_bound_worker).parameters
    ) == [
        "descriptor_path",
        "stage",
        "kind",
        "bound_inputs_factory",
        "ready_timeout_seconds",
    ]
    policy = verify_precommit_root(OUTPUT_ROOT)["qualification_descriptor"][
        "capability_policy"
    ]
    assert policy["caller_path_arguments_allowed"] is False
    assert set(policy["worker_scripts"]) == {"generate", "predict", "evaluate"}
    assert set(policy["worker_command_templates"]) == {
        "generate",
        "predict",
        "evaluate",
    }


def test_heldout_live_authority_rechecks_pass_and_approvals_without_seed_resolution() -> None:
    source = inspect.getsource(require_heldout_live_authority)
    assert "_verify_passing_qualification" in source
    assert source.count("_verify_approval") == 2
    assert "verify_stage_descriptor" in source
    assert "qualification_report_binding" in source
    assert "read_registry" not in source
    assert "reservation_contract_from_entry" not in source
    for relative in (
        "research/model_zoo/prospective_fresh_ensemble_v5/execution/heldout_process.py",
        "research/model_zoo/prospective_fresh_ensemble_v5/execution/process_runner.py",
        "research/model_zoo/prospective_fresh_ensemble_v5/execution/custody.py",
    ):
        assert "require_heldout_live_authority" in (PROJECT_ROOT / relative).read_text(
            encoding="utf-8"
        )


def test_inherited_v4_smoke_is_read_only_and_no_new_v5_smoke_exists() -> None:
    smoke = verify_generator_smoke_evidence(PROJECT_ROOT)

    assert smoke["inherited_from_lane"] == "prospective_fresh_ensemble_v4"
    assert smoke["new_v5_smoke_data_generated"] is False
    assert len(smoke["leaf_artifacts"]) == 16
    assert not (PROJECT_ROOT / "outputs" / "_p4g_v5").exists()
    with pytest.raises(ProspectiveContractError, match="not authorized"):
        run_generator_smoke(PROJECT_ROOT)
    with pytest.raises(ProspectiveContractError, match="not authorized"):
        build_generator_plan(
            PROJECT_ROOT,
            stage="smoke",
            invocation_id="0" * 32,
            seed=7417,
            runtime_boundary_record={},
        )


def test_launch_stays_blocked_without_two_new_qualification_approvals() -> None:
    assert not (OUTPUT_ROOT / "V5_PRELAUNCH_INDEPENDENT_AUDIT_GO.json").exists()
    assert not (OUTPUT_ROOT / "V5_QUALIFICATION_ROOT_LAUNCH_APPROVAL.json").exists()
    with pytest.raises((FileNotFoundError, ProspectiveContractError)):
        require_qualification_parent_authority(OUTPUT_ROOT)


def test_precommit_contains_no_model_or_truth_runtime_artifacts() -> None:
    state = verify_precommit_root(OUTPUT_ROOT)

    assert state["manifest"]["qualification_or_heldout_data_generated"] is False
    assert state["manifest"]["v5_candidate_fit_calls"] == 0
    assert state["manifest"]["v5_candidate_prediction_rows_generated"] == 0
    assert state["manifest"]["v5_candidate_scores_computed"] is False
    assert state["manifest"]["new_v5_smoke_data_generated"] is False
    assert not (OUTPUT_ROOT / "runtime").exists()
