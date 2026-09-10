from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any

import pytest

from research.model_zoo.prospective_fresh_ensemble_v1.artifacts import (
    file_record,
    write_bytes_exclusive,
    write_json_exclusive,
)
from research.model_zoo.prospective_fresh_ensemble_v4.contracts import (
    CANDIDATE_ID,
    GENERATOR_CONTRACT,
    LANE_ID,
    QUALIFICATION_GATES,
    QUALIFICATION_SEEDS,
    ProspectiveContractError,
    absolute_contract_paths,
    absolute_seed_paths,
    seal_payload,
)
from research.model_zoo.prospective_fresh_ensemble_v4.custody import (
    VerifiedCapability,
    assert_case_pair,
    verify_file_record_exact,
    verify_prediction_inputs,
    verify_prediction_results,
    verify_truth_index,
)
from research.model_zoo.prospective_fresh_ensemble_v4.evaluation import (
    _verify_locked_evaluation_surface,
    write_heldout_report_and_terminal,
    write_qualification_report_and_terminal,
)
from research.model_zoo.prospective_fresh_ensemble_v4.generation import run_generation
from research.model_zoo.prospective_fresh_ensemble_v4.heldout_authority import (
    _verify_passing_qualification,
)
from research.model_zoo.prospective_fresh_ensemble_v4.pid_handshake import VerifiedReadyClaim
from research.model_zoo.prospective_fresh_ensemble_v4.prediction import run_predictions
from research.model_zoo.prospective_fresh_ensemble_v4.process_runner import (
    initialize_actual_child_worker,
)
from research.model_zoo.prospective_fresh_ensemble_v4.precommit import (
    build_source_dependency_closure,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEEDS = list(QUALIFICATION_SEEDS)


def _write_sealed(path: Path, payload: dict[str, Any], field: str) -> dict[str, Any]:
    sealed = seal_payload(payload, field)
    write_json_exclusive(path, sealed)
    return sealed


def _root(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    root = (tmp_path / "v4").resolve()
    root.mkdir()
    descriptor = {
        "lane_id": LANE_ID,
        "stage": "qualification",
        "precommit_root": str(root),
        "runtime_root": str(root / "runtime" / "qualification"),
        "seeds": SEEDS,
        "descriptor_sha256": "a" * 64,
    }
    return root, descriptor


def _capability(
    root: Path,
    descriptor: dict[str, Any],
    *,
    kind: str,
    bound_inputs: dict[str, Any],
) -> VerifiedCapability:
    path = (root / "runtime" / "qualification" / "capabilities" / kind / ("0" * 32 + ".json"))
    ready_path = (
        root / "runtime" / "qualification" / "ready_claims" / kind / ("0" * 32 + ".json")
    )
    payload = {
        "stage": "qualification",
        "kind": kind,
        "bound_inputs": bound_inputs,
        "authorized_pid": 123,
        "launcher_pid": 122,
        "invocation_id": "0" * 32,
        "capability_sha256": "b" * 64,
    }
    ready = VerifiedReadyClaim(
        path=ready_path,
        payload={"ready_claim_sha256": "c" * 64},
        descriptor=descriptor,
    )
    return VerifiedCapability(path=path, payload=payload, descriptor=descriptor, ready_claim=ready)


def _identity(seed: int, stage: str = "qualification") -> dict[str, Any]:
    return {
        "lane_id": LANE_ID,
        "stage": stage,
        "seed": seed,
        "rows": 1800,
        "symbol": "DEMO",
        "date_index_sha256": "c" * 64,
        "generator_version": GENERATOR_CONTRACT["generator_version"],
        "generation_identity_sha256": "d" * 64,
    }


def test_public_execution_apis_accept_capability_only() -> None:
    assert tuple(inspect.signature(run_generation).parameters) == ("capability",)
    assert tuple(inspect.signature(run_predictions).parameters) == ("capability",)
    assert tuple(inspect.signature(write_qualification_report_and_terminal).parameters) == (
        "capability",
    )
    assert tuple(inspect.signature(write_heldout_report_and_terminal).parameters) == (
        "capability",
    )


def test_alternate_canonical_path_is_rejected(tmp_path: Path) -> None:
    root, descriptor = _root(tmp_path)
    alternate = root / "attacker" / "canonical.csv"
    write_bytes_exclusive(alternate, b"schema-valid substitute")
    manifest_path = absolute_contract_paths(root, "qualification")[
        "prediction_inputs_manifest"
    ]
    _write_sealed(
        manifest_path,
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "stage_descriptor_sha256": descriptor["descriptor_sha256"],
            "evaluation_data_excluded": True,
            "generator_contract": dict(GENERATOR_CONTRACT),
            "seeds": [
                {
                    "seed": seed,
                    "canonical_csv": file_record(alternate),
                    "generation_identity": _identity(seed),
                }
                for seed in SEEDS
            ],
        },
        "manifest_sha256",
    )
    capability = _capability(
        root,
        descriptor,
        kind="predict",
        bound_inputs={"prediction_inputs_manifest": file_record(manifest_path)},
    )
    with pytest.raises(ProspectiveContractError, match="path substitution"):
        verify_prediction_inputs(capability)


def test_alternate_prediction_path_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, descriptor = _root(tmp_path)
    paths = absolute_contract_paths(root, "qualification")
    alternate = root / "attacker" / "predictions.csv"
    write_bytes_exclusive(alternate, b"substitute")
    inputs = []
    for seed in SEEDS:
        canonical = absolute_seed_paths(root, "qualification", seed)["canonical"]
        write_bytes_exclusive(canonical, b"canonical")
        inputs.append(
            {
                "seed": seed,
                "canonical_csv": file_record(canonical),
                "generation_identity": _identity(seed),
            }
        )
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.custody.inspect_canonical_identity",
        lambda _path, *, stage, seed: _identity(seed, stage),
    )
    _write_sealed(
        paths["prediction_inputs_manifest"],
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "stage_descriptor_sha256": descriptor["descriptor_sha256"],
            "evaluation_data_excluded": True,
            "generator_contract": dict(GENERATOR_CONTRACT),
            "seeds": inputs,
        },
        "manifest_sha256",
    )
    _write_sealed(
        paths["prediction_results_manifest"],
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "candidate_id": CANDIDATE_ID,
            "candidate_set_size": 1,
            "stage_descriptor_sha256": descriptor["descriptor_sha256"],
            "prediction_inputs_manifest": file_record(paths["prediction_inputs_manifest"]),
            "seeds": [
                {
                    "seed": seed,
                    "prediction_csv": file_record(alternate),
                    "prediction_diagnostics": {
                        "path": str(
                            absolute_seed_paths(root, "qualification", seed)[
                                "prediction_diagnostics"
                            ]
                        ),
                        "bytes": 1,
                        "sha256": "e" * 64,
                    },
                    "canonical_csv": inputs[index]["canonical_csv"],
                    "generation_identity": _identity(seed),
                }
                for index, seed in enumerate(SEEDS)
            ],
        },
        "manifest_sha256",
    )
    write_bytes_exclusive(paths["truth_index"], b"bound but unopened")
    capability = _capability(
        root,
        descriptor,
        kind="evaluate",
        bound_inputs={
            "prediction_results_manifest": file_record(paths["prediction_results_manifest"]),
            "truth_index": file_record(paths["truth_index"]),
        },
    )
    with pytest.raises(ProspectiveContractError, match="path substitution"):
        verify_prediction_results(capability)


def test_alternate_truth_path_is_rejected(tmp_path: Path) -> None:
    root, descriptor = _root(tmp_path)
    paths = absolute_contract_paths(root, "qualification")
    alternate = root / "attacker" / "truth.csv"
    write_bytes_exclusive(alternate, b"schema-valid substitute")
    _write_sealed(
        paths["truth_index"],
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "stage_descriptor_sha256": descriptor["descriptor_sha256"],
            "prediction_worker_access": False,
            "seeds": [
                {
                    "seed": seed,
                    "truth_csv": file_record(alternate),
                    "generation_identity": _identity(seed),
                }
                for seed in SEEDS
            ],
        },
        "manifest_sha256",
    )
    write_bytes_exclusive(paths["prediction_results_manifest"], b"bound but unopened")
    capability = _capability(
        root,
        descriptor,
        kind="evaluate",
        bound_inputs={
            "prediction_results_manifest": file_record(paths["prediction_results_manifest"]),
            "truth_index": file_record(paths["truth_index"]),
        },
    )
    with pytest.raises(ProspectiveContractError, match="path substitution"):
        verify_truth_index(capability)


def test_cross_seed_and_wrong_stage_pairing_are_rejected() -> None:
    prediction = {"seed": SEEDS[0], "generation_identity": _identity(SEEDS[0])}
    cross_seed = {"seed": SEEDS[1], "generation_identity": _identity(SEEDS[1])}
    with pytest.raises(ProspectiveContractError, match="cross-seed"):
        assert_case_pair(
            prediction, cross_seed, expected_stage="qualification", expected_seed=SEEDS[0]
        )
    wrong_stage = {
        "seed": SEEDS[0],
        "generation_identity": _identity(SEEDS[0], "heldout"),
    }
    with pytest.raises(ProspectiveContractError, match="cross-seed"):
        assert_case_pair(
            prediction, wrong_stage, expected_stage="qualification", expected_seed=SEEDS[0]
        )


def test_same_bytes_at_wrong_path_are_rejected(tmp_path: Path) -> None:
    expected = tmp_path / "expected.bin"
    alternate = tmp_path / "alternate.bin"
    write_bytes_exclusive(expected, b"same")
    write_bytes_exclusive(alternate, b"same")
    with pytest.raises(ProspectiveContractError, match="path substitution"):
        verify_file_record_exact(file_record(alternate), expected)


def test_malformed_passing_qualification_terminal_is_rejected(tmp_path: Path) -> None:
    root, descriptor = _root(tmp_path)
    paths = absolute_contract_paths(root, "qualification")
    _write_sealed(
        paths["qualification_report"],
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "candidate_id": CANDIDATE_ID,
            "qualification_gate_pass": True,
        },
        "report_sha256",
    )
    _write_sealed(
        paths["qualification_terminal"],
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "state": "QUALIFICATION_PASS_AWAITING_HELDOUT_UNLOCK",
        },
        "terminal_sha256",
    )
    state = {
        "root": root,
        "qualification_descriptor": descriptor,
        "design": {"qualification_gates": dict(QUALIFICATION_GATES)},
    }
    with pytest.raises(ProspectiveContractError, match="exact passing"):
        _verify_passing_qualification(state)


def test_direct_child_rechecks_authority_before_ready_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = (tmp_path / "precommit").resolve()
    descriptor_path = root / "QUALIFICATION_STAGE_DESCRIPTOR.json"
    write_bytes_exclusive(descriptor_path, b"placeholder")
    descriptor = {
        "descriptor_sha256": "a" * 64,
        "capability_policy": {"ready_claim_timeout_seconds": 20.0},
    }
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.process_runner.verify_stage_descriptor",
        lambda *_args, **_kwargs: descriptor,
    )

    def reject_authority(_root: Path) -> dict[str, Any]:
        raise ProspectiveContractError("missing V4 approval")

    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.qualification_authority.require_qualification_parent_authority",
        reject_authority,
    )
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v4.process_runner.publish_child_ready_claim",
        lambda **_kwargs: pytest.fail("ready claim published before child authority check"),
    )
    with pytest.raises(ProspectiveContractError, match="missing V4 approval"):
        initialize_actual_child_worker(
            descriptor_path=descriptor_path,
            invocation_id="0" * 32,
            expected_precommit_root=root,
            expected_stage="qualification",
            expected_kind="generate",
        )


def _locked_surface_frame():
    import pandas as pd

    from research.model_zoo.structural_v7.folds import build_outer_folds

    dates = pd.bdate_range("2013-01-02", periods=1800)
    rows = []
    for fold in build_outer_folds(dates):
        for position in fold.test_positions:
            rows.append(
                {
                    "session_position": position,
                    "fold_id": fold.fold_id,
                    "train_end_position": fold.train_end_position,
                    "test_start_position": fold.test_start_position,
                    "cheap_secondary_mask": fold.fold_id
                    in {
                        "fold_012",
                        "fold_017",
                        "fold_022",
                        "fold_027",
                        "fold_032",
                        "fold_037",
                        "fold_042",
                        "fold_047",
                        "fold_052",
                        "fold_059",
                        "fold_066",
                        "fold_073",
                    },
                }
            )
    return pd.DataFrame(rows), pd.Series(dates)


def test_wrong_full_and_cheap_surfaces_are_rejected() -> None:
    frame, dates = _locked_surface_frame()
    positions, cheap = _verify_locked_evaluation_surface(frame, dates)
    assert len(positions) == 1296
    assert int(cheap.sum()) == 246
    shifted = frame.copy()
    shifted.loc[0, "session_position"] += 1
    with pytest.raises(ProspectiveContractError, match="locked full62"):
        _verify_locked_evaluation_surface(shifted, dates)
    wrong_cheap = frame.copy()
    wrong_cheap.loc[0, "cheap_secondary_mask"] = not bool(
        wrong_cheap.loc[0, "cheap_secondary_mask"]
    )
    with pytest.raises(ProspectiveContractError, match="locked full62"):
        _verify_locked_evaluation_surface(wrong_cheap, dates)


def test_qualification_modules_have_no_heldout_resolver() -> None:
    paths = (
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v4/qualification_authority.py",
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v4/qualification_process.py",
        PROJECT_ROOT
        / "scripts/model_lab/prospective_fresh_ensemble_v4/run_qualification_stage.py",
        PROJECT_ROOT
        / "scripts/model_lab/prospective_fresh_ensemble_v4/evaluate_qualification.py",
    )
    forbidden = ("seed_ledger", "locked_seeds", "registry_path", "heldout_authority")
    for path in paths:
        source = path.read_text(encoding="utf-8").lower()
        assert all(token not in source for token in forbidden), path


def test_v4_stage_clis_do_not_accept_caller_artifact_paths() -> None:
    paths = (
        PROJECT_ROOT / "scripts/model_lab/prospective_fresh_ensemble_v4/run_qualification_stage.py",
        PROJECT_ROOT / "scripts/model_lab/prospective_fresh_ensemble_v4/evaluate_qualification.py",
        PROJECT_ROOT / "scripts/model_lab/prospective_fresh_ensemble_v4/run_heldout_stage.py",
        PROJECT_ROOT / "scripts/model_lab/prospective_fresh_ensemble_v4/evaluate_heldout.py",
    )
    for path in paths:
        source = path.read_text(encoding="utf-8")
        assert "--capability" not in source
        assert "--canonical" not in source
        assert "--prediction" not in source
        assert "--truth" not in source
        assert "--seed" not in source


def test_precommit_closure_refuses_to_start_before_sealed_generator_smoke() -> None:
    with pytest.raises(ProspectiveContractError, match="generator smoke receipt"):
        build_source_dependency_closure(PROJECT_ROOT)
