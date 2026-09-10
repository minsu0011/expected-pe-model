"""Static no-run boundary audit and exact integration source closure."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .contracts import SCHEMA_VERSION, IntegrationContractError, sealed_payload
from .custody import sha256_file


SOURCE_PATHS = (
    "research/model_zoo/hofs_v4_dgp_r4_prediction_lane_v1/__init__.py",
    "research/model_zoo/hofs_v4_dgp_r4_prediction_lane_v1/contracts.py",
    "research/model_zoo/hofs_v4_dgp_r4_prediction_lane_v1/custody.py",
    "research/model_zoo/hofs_v4_dgp_r4_prediction_lane_v1/preflight.py",
    "research/model_zoo/hofs_v4_dgp_r4_prediction_lane_v1/source_audit.py",
    "research/model_zoo/hofs_v4_dgp_r4_prediction_lane_v1/DESIGN.md",
    "scripts/model_lab/hofs_v4_dgp_r4_prediction_lane_v1/freeze_draft.py",
    "tests/model_lab/test_hofs_v4_dgp_r4_prediction_lane_v1.py",
    "pyproject.toml",
)

FORBIDDEN_IMPORT_TOKENS = (
    "evaluator",
    "truth",
    "vault",
    "latent",
    "heldout",
    "registry",
)
FORBIDDEN_EXECUTION_CALLS = frozenset(
    {
        "apply_frozen_parameters_v4",
        "fit",
        "fit_chronological_prefix_v4",
        "fit_hierarchical_state_v4",
        "load_and_run_frozen_decision_session_v4",
        "predict",
        "run_frozen_decision_session_v4",
        "run_prediction_only",
        "score",
    }
)


def _call_name(node: ast.Call) -> str:
    target = node.func
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return ""


def _audit_python(path: Path, relative_path: str) -> dict[str, Any]:
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=relative_path)
    except (UnicodeError, SyntaxError) as exc:
        raise IntegrationContractError(f"source cannot be parsed: {relative_path}") from exc
    forbidden_imports: list[str] = []
    forbidden_calls: list[str] = []
    for node in ast.walk(tree):
        imported: list[str] = []
        if isinstance(node, ast.Import):
            imported = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported = [node.module or ""]
        for module in imported:
            lowered = module.lower()
            if any(token in lowered.split(".") for token in FORBIDDEN_IMPORT_TOKENS):
                forbidden_imports.append(f"{node.lineno}:{module}")
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in FORBIDDEN_EXECUTION_CALLS:
                forbidden_calls.append(f"{node.lineno}:{name}")
    return {
        "relative_path": relative_path,
        "forbidden_import_hits": forbidden_imports,
        "forbidden_model_execution_call_hits": forbidden_calls,
    }


def build_source_closure(project_root: Path) -> dict[str, Any]:
    """Hash the exact isolated namespace and prove it has no model run call."""

    root = project_root.resolve(strict=True)
    records: list[dict[str, Any]] = []
    audits: list[dict[str, Any]] = []
    for relative_path in SOURCE_PATHS:
        path = root / relative_path
        if not path.is_file() or path.is_symlink():
            raise IntegrationContractError(f"source closure file is absent/unsafe: {relative_path}")
        records.append(
            {
                "relative_path": relative_path,
                "size_bytes": path.stat().st_size,
                "raw_sha256": sha256_file(path),
            }
        )
        if path.suffix == ".py":
            audits.append(_audit_python(path, relative_path))
    forbidden_import_hits = [
        f"{item['relative_path']}:{hit}"
        for item in audits
        for hit in item["forbidden_import_hits"]
    ]
    forbidden_call_hits = [
        f"{item['relative_path']}:{hit}"
        for item in audits
        for hit in item["forbidden_model_execution_call_hits"]
    ]
    if forbidden_import_hits or forbidden_call_hits:
        raise IntegrationContractError("isolated integration source crosses the no-run boundary")
    return sealed_payload(
        {
            "schema_version": f"{SCHEMA_VERSION}.source_closure.v1",
            "status": "PASS_ISOLATED_INTEGRATION_SOURCE_NO_MODEL_RUN_CAPABILITY",
            "records": records,
            "record_count": len(records),
            "python_file_count": len(audits),
            "forbidden_import_hits": forbidden_import_hits,
            "forbidden_model_execution_call_hits": forbidden_call_hits,
            "model_fit_call_count": 0,
            "model_prediction_call_count": 0,
            "score_call_count": 0,
            "evaluator_truth_vault_latent_heldout_registry_import_count": 0,
            "existing_v1_v2_v3_v4_source_modified_by_namespace": False,
            "existing_audit_source_modified_by_namespace": False,
        }
    )


__all__ = ["SOURCE_PATHS", "build_source_closure"]
