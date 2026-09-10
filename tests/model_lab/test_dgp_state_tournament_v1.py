from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.dgp_exploration_v2.generator import (
    _logical_frame_sha256 as v2_logical_frame_sha256,
)
from research.model_zoo.dgp_state_tournament_v1.artifacts import (
    canonical_json_bytes,
    canonical_value_sha256,
    require_isolated_output,
)
from research.model_zoo.dgp_state_tournament_v1.contracts import (
    ACTIVATION_LITERAL,
    CANONICAL_HEADER_SHA256,
    DGPS,
    EXACT_ENVIRONMENT,
    IDENTITY_COLUMNS,
    OBSERVABLE_STATE_CONTRACT_SHA256,
    PUBLIC_NAMES,
    ROWS,
    SEEDS,
    V3_PUBLIC_LEDGER_SEMANTIC_SHA256,
    InputFreezeContractError,
    task_keys,
)
from research.model_zoo.dgp_state_tournament_v1.precommit import (
    load_and_verify_v3_bindings,
    load_truth_vault_binding,
    repository_root,
)
from research.model_zoo.dgp_state_tournament_v1 import precommit as tournament_precommit
from research.model_zoo.dgp_state_tournament_v1.replay import _normalize_work_paths
from research.model_zoo.dgp_state_tournament_v1.runner import (
    _comparator_diagnostics,
    _logical_public_frame_sha256,
    _task_relative_directory,
)
from research.model_zoo.dgp_state_tournament_v1.source_audit import (
    audit_score_blind_source_boundary,
)
from research.model_zoo.dgp_suite.boundary import sealed_canonical_header
from research.model_zoo.observable_fair_value_state_v1.contracts import (
    REQUIRED_SOURCE_COLUMNS,
    contract_sha256 as observable_state_contract_sha256,
)


def test_exact_spent_task_and_resource_geometry() -> None:
    assert SEEDS == (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
    assert DGPS == tuple("ABCDEFGHIJ")
    assert len(task_keys()) == 50
    assert len(set(task_keys())) == 50
    assert ROWS == 1800
    assert IDENTITY_COLUMNS == ("seed", "dgp", "row_position", "date")
    assert EXACT_ENVIRONMENT == {
        "CUDA_VISIBLE_DEVICES": "-1",
        "MKL_NUM_THREADS": "1",
        "NVIDIA_VISIBLE_DEVICES": "void",
        "NUMEXPR_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }


def test_v3_lock_and_all_250_public_hashes_are_exact() -> None:
    root = repository_root()
    lock, receipt = load_and_verify_v3_bindings(root)
    assert lock["production_authority"] is False
    ledger = receipt["generation_public_hash_by_task"]
    assert set(ledger) == set(task_keys())
    assert sum(len(value) for value in ledger.values()) == 250
    assert all(set(value) == set(PUBLIC_NAMES) for value in ledger.values())
    assert canonical_value_sha256(ledger) == V3_PUBLIC_LEDGER_SEMANTIC_SHA256


def test_public_logical_digest_independently_matches_v2_algorithm() -> None:
    frame = pd.DataFrame(
        {
            "date": ["2026-01-02", "2026-01-05"],
            "value": np.asarray([1.25, np.nan], dtype=np.float64),
            "available_at": [pd.Timestamp("2026-01-02T12:30:00Z"), pd.NaT],
        }
    )
    assert _logical_public_frame_sha256(frame) == v2_logical_frame_sha256(frame)


def test_canonical_header_and_observable_state_contract_are_exact() -> None:
    header = sealed_canonical_header()
    assert len(header) == 150
    assert canonical_value_sha256(list(header)) == CANONICAL_HEADER_SHA256
    assert set(REQUIRED_SOURCE_COLUMNS).issubset(header)
    assert observable_state_contract_sha256() == OBSERVABLE_STATE_CONTRACT_SHA256


def test_receipt_normalization_changes_only_work_root_paths(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    payload = {
        "output_csv": str(root / "v03_output" / "canonical.csv"),
        "runtime": {"python_executable": "C:/exact/python.exe", "hash": "a" * 64},
        "invocation": [str(root / "child.py"), "--stage", "v03"],
        "identity": "2015-01-02",
    }
    normalized = _normalize_work_paths(payload, work_root=root)
    assert normalized == {
        "output_csv": "$REPLAY_ROOT/v03_output/canonical.csv",
        "runtime": {"python_executable": "C:/exact/python.exe", "hash": "a" * 64},
        "invocation": ["$REPLAY_ROOT/child.py", "--stage", "v03"],
        "identity": "2015-01-02",
    }


def test_full_row_comparator_diagnostics_apply_exact_lag_one() -> None:
    canonical = pd.DataFrame(
        {"date": ["2026-01-02", "2026-01-05"], "ml_expected_pe": [10.0, 11.0]}
    )
    overlay = pd.DataFrame({"v04_expected_pe": [20.0, 21.0]})
    diagnostic = _comparator_diagnostics(canonical, overlay)
    assert diagnostic["row_position"].tolist() == [0, 1]
    assert np.isnan(diagnostic.loc[0, "ml_expected_pe_lag1_incumbent"])
    assert diagnostic.loc[1, "ml_expected_pe_lag1_incumbent"] == 10.0
    assert np.isnan(diagnostic.loc[0, "v04_expected_pe_lag1_incumbent"])
    assert diagnostic.loc[1, "v04_expected_pe_lag1_incumbent"] == 20.0


def test_output_and_task_paths_are_fail_closed(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    (root / "outputs").mkdir()
    accepted = root / "outputs/model_zoo_dgp_state_tournament_v1_inputs_unit"
    assert require_isolated_output(accepted, repository_root=root) == accepted
    with pytest.raises(InputFreezeContractError):
        require_isolated_output(root / "elsewhere/output", repository_root=root)
    with pytest.raises(InputFreezeContractError):
        _task_relative_directory(SEEDS[0], "A", pass_id="pass_3")
    with pytest.raises(InputFreezeContractError):
        _task_relative_directory(123, "A")


def test_source_boundary_has_no_formal_evaluator_scoring_or_model_calls() -> None:
    audit = audit_score_blind_source_boundary()
    assert audit["status"] == "PASS_SCORE_BLIND_SOURCE_BOUNDARY"
    assert audit["findings"] == []


def test_run_entrypoint_activation_check_precedes_resource_and_path_use() -> None:
    path = (
        repository_root()
        / "scripts/model_lab/dgp_state_tournament_v1/run_tournament.py"
    )
    tree = ast.parse(path.read_text("utf-8"))
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "main")
    activation_guard_line = min(
        node.lineno
        for node in ast.walk(main)
        if isinstance(node, ast.Compare)
        and any(
            isinstance(comparator, ast.Name) and comparator.id == "ACTIVATION_LITERAL"
            for comparator in node.comparators
        )
    )
    resource_import_line = min(
        node.lineno
        for node in ast.walk(main)
        if isinstance(node, ast.ImportFrom)
        and str(node.module).endswith("resources")
    )
    assert ACTIVATION_LITERAL in path.read_text("utf-8")
    assert activation_guard_line < resource_import_line


def test_canonical_json_is_lf_sorted_and_hashable() -> None:
    raw = canonical_json_bytes({"b": 2, "a": 1})
    assert raw == b'{"a":1,"b":2}\n'
    assert hashlib.sha256(raw).hexdigest() == hashlib.sha256(b'{"a":1,"b":2}\n').hexdigest()
    assert json.loads(raw) == {"a": 1, "b": 2}


def test_truth_vault_checksum_order_matches_windows_path_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    relative_root = Path("outputs/vault")
    monkeypatch.setattr(
        tournament_precommit,
        "DEFAULT_TRUTH_VAULT_OUTPUT_RELATIVE_PATH",
        relative_root.as_posix(),
    )
    vault_root = tmp_path / relative_root
    vault_root.mkdir(parents=True)
    artifact_hash = "a" * 64
    artifacts_by_task = {
        task_key: {
            name: {
                "bytes": 1,
                "raw_sha256": artifact_hash,
                "relative_path": (
                    f"vault/seed_{task_key.split(':', 1)[0]}/"
                    f"dgp_{task_key.split(':', 1)[1]}/{name}.csv"
                ),
                "rows": 1800,
            }
            for name in ("truth", "latent_events")
        }
        for task_key in task_keys()
    }
    design_hash = "b" * 64
    receipt = {
        "status": "PASS_IMMUTABLE_DETACHED_TRUTH_VAULT_SCORING_LOCKED",
        "design_lock_raw_sha256": design_hash,
        "task_count": 50,
        "artifact_count": 100,
        "artifact_metadata_policy": "PATH_BYTES_SHA256_ROW_COUNT_ONLY",
        "complete_evaluator_frames_serialized_without_column_or_row_selection": True,
        "truth_file_reopened_after_write_for_raw_hash_verification": True,
        "truth_file_parsed_after_write": False,
        "truth_value_selected": False,
        "truth_identity_selected": False,
        "truth_join_executed": False,
        "score_computed": False,
        "candidate_or_survivor_fit_executed": False,
        "prediction_worker_received_vault_path": False,
        "scoring_activation_present": False,
        "future_scoring_requires_separate_capability_and_activation": True,
        "artifacts_by_task": artifacts_by_task,
    }
    receipt_raw = canonical_json_bytes(receipt)
    receipt_hash = hashlib.sha256(receipt_raw).hexdigest()
    (vault_root / "VAULT_RECEIPT.json").write_bytes(receipt_raw)
    manifest_lines = [
        f"{metadata['raw_sha256']}  {metadata['relative_path']}"
        for artifacts in artifacts_by_task.values()
        for metadata in artifacts.values()
    ]
    manifest_lines.append(f"{receipt_hash}  VAULT_RECEIPT.json")
    manifest_raw = (
        "\n".join(
            sorted(
                manifest_lines,
                key=lambda line: line.split("  ", 1)[1].casefold(),
            )
        )
        + "\n"
    ).encode("ascii")
    assert manifest_raw.rstrip().splitlines()[-1].endswith(b"VAULT_RECEIPT.json")
    (vault_root / "CHECKSUMS.sha256").write_bytes(manifest_raw)
    loaded, checksum_hash = load_truth_vault_binding(
        root=tmp_path,
        expected_receipt_raw_sha256=receipt_hash,
        expected_design_lock_raw_sha256=design_hash,
    )
    assert loaded == receipt
    assert checksum_hash == hashlib.sha256(manifest_raw).hexdigest()
