from __future__ import annotations

import inspect
import os
from pathlib import Path
from typing import Any

import pytest

from research.model_zoo.prospective_fresh_ensemble_v1.artifacts import (
    file_record,
    write_bytes_exclusive,
    write_json_exclusive,
)
from research.model_zoo.prospective_fresh_ensemble_v2.contracts import (
    CANDIDATE_ID,
    GENERATOR_CONTRACT,
    LANE_ID,
    QUALIFICATION_GATES,
    ProspectiveContractError,
    absolute_contract_paths,
    absolute_seed_paths,
    seal_payload,
    sha256_file,
)
from research.model_zoo.prospective_fresh_ensemble_v2.custody import (
    VerifiedCapability,
    assert_case_pair,
    load_stage_capability,
    verify_file_record_exact,
    verify_prediction_inputs,
    verify_prediction_results,
    verify_truth_index,
)
from research.model_zoo.prospective_fresh_ensemble_v2.evaluation import (
    _verify_locked_evaluation_surface,
    write_heldout_report_and_terminal,
    write_qualification_report_and_terminal,
)
from research.model_zoo.prospective_fresh_ensemble_v2.generation import run_generation
from research.model_zoo.prospective_fresh_ensemble_v2.prediction import run_predictions
from research.model_zoo.prospective_fresh_ensemble_v2.heldout_authority import (
    _verify_passing_qualification,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SEEDS = [7211, 7213, 7219, 7229, 7237]


def _write_sealed(path: Path, payload: dict[str, Any], field: str) -> dict[str, Any]:
    sealed = seal_payload(payload, field)
    write_json_exclusive(path, sealed)
    return sealed


def _stage_root(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    root = (tmp_path / "v2").resolve()
    root.mkdir()
    closure_path = root / "SOURCE_DEPENDENCY_CLOSURE.json"
    v03_root = (PROJECT_ROOT.parent / GENERATOR_CONTRACT["engine_root_name"]).resolve(
        strict=True
    )
    v03_python = (v03_root / ".venv" / "Scripts" / "python.exe").resolve(strict=True)
    worker_python = Path(os.sys.executable).resolve(strict=True)
    _write_sealed(
        closure_path,
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "project_root": str(PROJECT_ROOT),
            "v03_root": str(v03_root),
            "files": {},
            "interpreters": {
                "precommit_python": {
                    "path": str(worker_python),
                    "sha256": sha256_file(worker_python),
                },
                "v03_python": {
                    "path": str(v03_python),
                    "sha256": sha256_file(v03_python),
                },
            },
        },
        "closure_sha256",
    )
    _write_sealed(
        root / "RESERVATION_BINDING.json",
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "qualification_seeds": SEEDS,
            "heldout_seed_commitment_sha256": "e" * 64,
        },
        "binding_sha256",
    )
    _write_sealed(
        root / "DESIGN_LOCK.json",
        {"format_version": 1, "lane_id": LANE_ID},
        "design_sha256",
    )
    descriptor = _write_sealed(
        root / "QUALIFICATION_STAGE_DESCRIPTOR.json",
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "precommit_root": str(root),
            "runtime_root": str((root / "runtime" / "qualification").resolve()),
            "seeds": SEEDS,
            "seed_count": 5,
            "source_closure": file_record(closure_path),
            "design_lock_raw_sha256": sha256_file(root / "DESIGN_LOCK.json"),
            "reservation_binding_raw_sha256": sha256_file(
                root / "RESERVATION_BINDING.json"
            ),
            "allowed_paths": {
                name: str(path)
                for name, path in absolute_contract_paths(root, "qualification").items()
            },
            "capability_policy": {
                "single_stage": "qualification",
                "authorized_pid_exact": True,
                "caller_path_arguments_allowed": False,
                "worker_python": str(worker_python),
                "project_root": str(PROJECT_ROOT),
                "v03_root": str(v03_root),
                "v03_python": str(v03_python),
                "v03_config": str(
                    (v03_root / GENERATOR_CONTRACT["config_relative"]).resolve(strict=True)
                ),
            },
        },
        "descriptor_sha256",
    )
    return root, descriptor


def _capability(
    root: Path,
    descriptor: dict[str, Any],
    *,
    kind: str,
    bound_inputs: dict[str, Any],
    pid: int | None = None,
) -> tuple[Path, VerifiedCapability]:
    path = root / "runtime" / "qualification" / "capabilities" / kind / "probe.json"
    payload = _write_sealed(
        path,
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "kind": kind,
            "authorized_pid": os.getpid() if pid is None else pid,
            "invocation_id": "probe",
            "issued_at_utc": "2026-08-20T00:00:00+00:00",
            "stage_descriptor": file_record(root / "QUALIFICATION_STAGE_DESCRIPTOR.json"),
            "bound_inputs": bound_inputs,
            "capability_path": str(path.resolve()),
        },
        "capability_sha256",
    )
    return path, VerifiedCapability(path=path.resolve(), payload=payload, descriptor=descriptor)


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
    root, descriptor = _stage_root(tmp_path)
    alternate = root / "attacker" / "canonical.csv"
    write_bytes_exclusive(alternate, b"schema-valid substitute")
    expected_manifest = absolute_contract_paths(root, "qualification")[
        "prediction_inputs_manifest"
    ]
    entries = [
        {
            "seed": seed,
            "canonical_csv": file_record(alternate),
            "generation_identity": _identity(seed),
        }
        for seed in SEEDS
    ]
    _write_sealed(
        expected_manifest,
        {
            "format_version": 1,
            "lane_id": LANE_ID,
            "stage": "qualification",
            "stage_descriptor_sha256": descriptor["descriptor_sha256"],
            "evaluation_data_excluded": True,
            "generator_contract": dict(GENERATOR_CONTRACT),
            "seeds": entries,
        },
        "manifest_sha256",
    )
    _path, capability = _capability(
        root,
        descriptor,
        kind="predict",
        bound_inputs={"prediction_inputs_manifest": file_record(expected_manifest)},
    )
    with pytest.raises(ProspectiveContractError, match="path substitution"):
        verify_prediction_inputs(capability)


def test_alternate_prediction_path_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, descriptor = _stage_root(tmp_path)
    paths = absolute_contract_paths(root, "qualification")
    alternate = root / "attacker" / "predictions.csv"
    write_bytes_exclusive(alternate, b"substitute")
    input_entries = []
    for seed in SEEDS:
        canonical = absolute_seed_paths(root, "qualification", seed)["canonical"]
        write_bytes_exclusive(canonical, b"canonical fixture")
        input_entries.append(
            {
                "seed": seed,
                "canonical_csv": file_record(canonical),
                "generation_identity": _identity(seed),
            }
        )
    monkeypatch.setattr(
        "research.model_zoo.prospective_fresh_ensemble_v2.custody.inspect_canonical_identity",
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
            "seeds": input_entries,
        },
        "manifest_sha256",
    )
    result_entries = [
        {
            "seed": seed,
            "prediction_csv": file_record(alternate),
            "prediction_diagnostics": {
                "path": str(
                    absolute_seed_paths(root, "qualification", seed)["prediction_diagnostics"]
                ),
                "bytes": 1,
                "sha256": "b" * 64,
            },
            "canonical_csv": input_entries[index]["canonical_csv"],
            "generation_identity": _identity(seed),
        }
        for index, seed in enumerate(SEEDS)
    ]
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
            "seeds": result_entries,
        },
        "manifest_sha256",
    )
    write_bytes_exclusive(paths["truth_index"], b"bound but unopened")
    _path, capability = _capability(
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
    root, descriptor = _stage_root(tmp_path)
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
                {"seed": seed, "truth_csv": file_record(alternate), "generation_identity": _identity(seed)}
                for seed in SEEDS
            ],
        },
        "manifest_sha256",
    )
    write_bytes_exclusive(paths["prediction_results_manifest"], b"bound but unopened")
    _path, capability = _capability(
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
    prediction = {"seed": 7211, "generation_identity": _identity(7211)}
    cross_seed = {"seed": 7213, "generation_identity": _identity(7213)}
    with pytest.raises(ProspectiveContractError, match="cross-seed"):
        assert_case_pair(
            prediction, cross_seed, expected_stage="qualification", expected_seed=7211
        )
    wrong_stage = {"seed": 7211, "generation_identity": _identity(7211, "heldout")}
    with pytest.raises(ProspectiveContractError, match="cross-seed"):
        assert_case_pair(
            prediction, wrong_stage, expected_stage="qualification", expected_seed=7211
        )


def test_wrong_pid_and_wrong_stage_capabilities_are_rejected(tmp_path: Path) -> None:
    root, descriptor = _stage_root(tmp_path)
    path, _cap = _capability(
        root,
        descriptor,
        kind="generate",
        bound_inputs={},
        pid=os.getpid(),
    )
    with pytest.raises(ProspectiveContractError, match="PID"):
        load_stage_capability(
            path,
            expected_precommit_root=root,
            expected_stage="qualification",
            expected_kind="generate",
            expected_pid=os.getpid() + 1,
        )
    with pytest.raises((ProspectiveContractError, FileNotFoundError, OSError)):
        load_stage_capability(
            path,
            expected_precommit_root=root,
            expected_stage="heldout",
            expected_kind="generate",
            expected_pid=os.getpid(),
        )


def test_qualification_modules_have_no_heldout_resolver() -> None:
    paths = (
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v2/qualification_authority.py",
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v2/qualification_process.py",
        PROJECT_ROOT
        / "scripts/model_lab/prospective_fresh_ensemble_v2/run_qualification_stage.py",
        PROJECT_ROOT
        / "scripts/model_lab/prospective_fresh_ensemble_v2/evaluate_qualification.py",
    )
    forbidden = ("seed_ledger", "locked_seeds", "registry_path", "heldout_authority")
    for path in paths:
        source = path.read_text(encoding="utf-8").lower()
        assert all(token not in source for token in forbidden), path


def test_same_bytes_at_wrong_path_are_still_rejected(tmp_path: Path) -> None:
    expected = tmp_path / "expected.bin"
    alternate = tmp_path / "alternate.bin"
    write_bytes_exclusive(expected, b"same")
    write_bytes_exclusive(alternate, b"same")
    with pytest.raises(ProspectiveContractError, match="path substitution"):
        verify_file_record_exact(file_record(alternate), expected)


def test_direct_execution_rechecks_missing_qualification_authority(tmp_path: Path) -> None:
    root, descriptor = _stage_root(tmp_path)
    _path, capability = _capability(root, descriptor, kind="generate", bound_inputs={})
    with pytest.raises(ProspectiveContractError, match="cannot read JSON artifact"):
        run_generation(capability)


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


def test_malformed_passing_qualification_report_is_rejected(tmp_path: Path) -> None:
    root, descriptor = _stage_root(tmp_path)
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


def test_heldout_descriptor_source_contains_complete_runtime_policy() -> None:
    source = (
        PROJECT_ROOT
        / "research/model_zoo/prospective_fresh_ensemble_v2/heldout_authority.py"
    ).read_text(encoding="utf-8")
    for key in ("worker_python", "project_root", "v03_root", "v03_python", "v03_config"):
        assert f'"{key}"' in source
