from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    PROJECT_ROOT
    / "scripts/model_lab/pe_four_model_heldout_r2_publish_prediction_terminal.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("r2_prediction_terminal", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_terminal_contract_is_non_recovery_and_non_certifying() -> None:
    module = _module()
    assert module.FAILURE_CODES == (
        "R2_PREDICTION_PUBLICATION_FILESHARE_SEQUENCE_DENIAL",
        "R2_PREDICTION_AUDITOR_BCE_RESOURCE_ENVIRONMENT_MISMATCH",
    )
    assert module.PARTIAL_LEAVES == (
        "HELDOUT_PREDICTION_FREEZE_RECEIPT.json",
        "PREDICTION_MANIFEST.json",
        "PREDICTIONS.csv",
        "SOURCE_MANIFEST.json",
    )
    assert module.TERMINAL_LEAF == "TERMINAL_FAILURE.json"
    assert module.BCE_NUMERIC_ENVIRONMENT == {
        **module.BASE_NUMERIC_ENVIRONMENT,
        "HIP_VISIBLE_DEVICES": "-1",
        "ROCR_VISIBLE_DEVICES": "-1",
    }
    assert len(module.BASE_NUMERIC_ENVIRONMENT) == 7
    assert len(module.BCE_NUMERIC_ENVIRONMENT) == 9


def test_apply_requires_a_prior_dry_run_hash() -> None:
    module = _module()
    parser = module.parser()
    dry = parser.parse_args(["--dry-run"])
    apply = parser.parse_args(["--apply"])
    assert dry.dry_run and not dry.apply
    assert apply.apply and apply.expected_terminal_raw_sha256 is None
    with pytest.raises(SystemExit):
        parser.parse_args([])
    with pytest.raises(SystemExit):
        parser.parse_args(["--dry-run", "--apply"])


def test_source_has_no_numeric_recovery_activation_scoring_or_destructive_calls() -> None:
    raw = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(raw)
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not ({"unlink", "rmdir", "replace", "rename"} & called_attributes)
    assert not (
        {
            "run_prediction_execution",
            "publish_prediction_freeze",
            "mint_heldout_activation",
            "run_evaluation",
            "score_predictions",
        }
        & called_names
    )
    assert "recovery_allowed\": False" in raw
    assert "numeric_predictions_rerun\": False" in raw
    assert "heldout_scorer_invoked\": False" in raw


def test_secure_apply_can_publish_only_one_new_terminal_leaf() -> None:
    raw = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(raw)
    publish_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "publish_leaf"
    ]
    claim_calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "claim_output_root"
    ]
    assert len(publish_calls) == 1
    assert len(claim_calls) == 1
    keywords = {item.arg: item.value for item in publish_calls[0].keywords}
    assert isinstance(keywords["final_leaf"], ast.Name)
    assert keywords["final_leaf"].id == "TERMINAL_LEAF"
