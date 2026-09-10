"""Run final no-score checks and seal the exact Wave1 audit-candidate tree."""

# ruff: noqa: E402 -- resource controls must precede numerical project imports.

from __future__ import annotations

import os

for _name in (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
    "VECLIB_MAXIMUM_THREADS",
):
    os.environ[_name] = "1"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

import argparse
import base64
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Sequence


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    load_sealed_json,
    seal_payload,
    sha256_file,
    write_immutable_json,
)
from pe_regime_v04.model_lab.models.wave1.audit import audit_inventory_sha256
from pe_regime_v04.model_lab.models.wave1.binding import (
    RUNTIME_DEPENDENCY_RELATIVE_PATHS,
    collect_mg1_execution_inputs,
)
from pe_regime_v04.model_lab.models.wave1.registration import (
    planned_feature_registrations,
    planned_model_registrations,
)
from pe_regime_v04.model_lab.models.wave1.spec import (
    DESIGN_LOCK_SHA256,
    EVIDENCE_SEEDS,
)
from pe_regime_v04.model_lab.registry import (
    RegistryPaths,
    load_feature_registry,
    load_model_registry,
)


RESULT_RELATIVE = (
    "outputs/mg1/artifacts/tuning/seed_{seed}/v04/"
    "causal_matured_forward_median_regularized_promotion_v1/result.json"
)


def _run_check(name: str, arguments: Sequence[str]) -> dict[str, object]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(SRC)
    completed = subprocess.run(
        list(arguments),
        cwd=ROOT,
        env=environment,
        capture_output=True,
        check=False,
    )
    stdout = completed.stdout
    stderr = completed.stderr
    if completed.returncode != 0:
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        raise RuntimeError(f"final audit check failed: {name}")
    return {
        "name": name,
        "command": subprocess.list2cmdline(list(arguments)),
        "exit_code": completed.returncode,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_base64": base64.b64encode(stdout).decode("ascii"),
        "stderr_base64": base64.b64encode(stderr).decode("ascii"),
        "stdout_tail": stdout.decode("utf-8", errors="replace")[-4000:],
        "stderr_tail": stderr.decode("utf-8", errors="replace")[-4000:],
        "summary": "PASS",
    }


def _inventory(paths: Sequence[Path]) -> list[dict[str, object]]:
    records = []
    seen: set[str] = set()
    for path in sorted((item.resolve(strict=True) for item in paths), key=str):
        relative = path.relative_to(ROOT).as_posix()
        if relative in seen:
            continue
        seen.add(relative)
        records.append(
            {
                "relative_path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return sorted(records, key=lambda item: str(item["relative_path"]))


def _assert_wave1_registries_unmodified() -> None:
    registry_root = ROOT / "research/model_zoo"
    feature_paths = RegistryPaths(
        registry_root / "feature_registry.csv",
        registry_root / "feature_registry.json",
    )
    model_paths = RegistryPaths(
        registry_root / "model_registry.csv",
        registry_root / "model_registry.json",
    )
    existing_feature_ids = {item.feature_id for item in load_feature_registry(feature_paths)}
    existing_model_ids = {item.model_id for item in load_model_registry(model_paths)}
    planned_feature_ids = {item.feature_id for item in planned_feature_registrations()}
    planned_model_ids = {item.model_id for item in planned_model_registrations()}
    if existing_feature_ids.intersection(planned_feature_ids):
        raise RuntimeError("Wave1 feature definitions were written before independent audit")
    if existing_model_ids.intersection(planned_model_ids):
        raise RuntimeError("Wave1 model definitions were written before independent audit")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal final no-score Wave1 audit evidence")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resource-probe", type=Path, required=True)
    parser.add_argument("--no-score-dry-run", type=Path, required=True)
    parser.add_argument("--resolved-model-parameters", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        raise FileExistsError(f"immutable audit candidate exists: {args.output}")
    prohibited = (
        "EXECUTION_BINDING.json",
        "EXECUTION_PRECOMMIT.json",
        "PREDICT_INPUTS.json",
        "EVALUATE_INPUTS.json",
        "PREDICTION_MANIFEST.json",
        "EVALUATION_MANIFEST.json",
    )
    if any((args.output.parent / name).exists() for name in prohibited):
        raise RuntimeError("execution or prediction artifacts exist before the audit freeze")
    _assert_wave1_registries_unmodified()

    probe = load_sealed_json(
        args.resource_probe, expected_mode="wave1_fresh_process_resource_probe"
    )
    dry = load_sealed_json(
        args.no_score_dry_run, expected_mode="wave1_synthetic_no_score_dry_run"
    )
    resolved = load_sealed_json(
        args.resolved_model_parameters,
        expected_mode="wave1_synthetic_resolved_model_parameters",
    )
    if (
        probe.get("project_data_read") is not False
        or probe.get("candidate_scores_computed") is not False
        or dry.get("project_data_read") is not False
        or dry.get("candidate_scores_computed") is not False
        or resolved.get("project_data_read") is not False
        or resolved.get("candidate_scores_computed") is not False
    ):
        raise RuntimeError("final synthetic/resource evidence claims project scoring or data access")

    python = str(Path(sys.executable).resolve(strict=True))
    ruff = shutil.which("ruff")
    if ruff is None:
        raise RuntimeError("ruff executable is unavailable for the final audit")
    compile_paths = sorted(
        {
            str((ROOT / relative).resolve(strict=True))
            for relative in RUNTIME_DEPENDENCY_RELATIVE_PATHS
            if relative.endswith(".py")
        }
    )
    checks = [
        _run_check(
            "wave1_targeted_pytest",
            (
                python,
                "-m",
                "pytest",
                "-o",
                "addopts=--strict-markers",
                "-q",
                "tests/model_lab",
                "-k",
                "wave1",
            ),
        ),
        _run_check(
            "full_pytest",
            (
                python,
                "-m",
                "pytest",
                "-o",
                "addopts=--strict-markers",
                "-q",
            ),
        ),
        _run_check(
            "ruff",
            (
                ruff,
                "check",
                "src/pe_regime_v04/model_lab/models",
                "scripts/model_lab/wave1",
                *sorted(
                    str(path.relative_to(ROOT))
                    for path in (ROOT / "tests/model_lab").glob("test_wave1_*.py")
                ),
            ),
        ),
        _run_check("py_compile", (python, "-m", "py_compile", *compile_paths)),
    ]

    result_paths = {
        seed: ROOT / RESULT_RELATIVE.format(seed=seed) for seed in EVIDENCE_SEEDS
    }
    predict, evaluate, opaque, fold_bindings = collect_mg1_execution_inputs(result_paths)
    mg1 = {
        "status": "PASS",
        "seeds": list(EVIDENCE_SEEDS),
        "predict_entries_verified": len(predict),
        "evaluation_entries_verified": len(evaluate),
        "opaque_artifact_digests": opaque,
        "per_seed_rows": [
            {"seed": int(item["seed"]), "rows": int(item["expected_rows"])}
            for item in predict
        ],
        "fold_bindings": fold_bindings,
        "candidate_predictions_run": False,
        "candidate_scores_seen": False,
        "fresh_or_heldout_opened": False,
    }

    dependency_paths = [
        ROOT / relative for relative in RUNTIME_DEPENDENCY_RELATIVE_PATHS
    ]
    evidence_paths = [
        path
        for path in args.output.parent.glob("*")
        if path.is_file() and path.resolve() != args.output.resolve()
    ]
    inventory = _inventory([*dependency_paths, *evidence_paths])
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_audit_candidate",
            "design_lock_sha256": DESIGN_LOCK_SHA256,
            "audit_scope": "WAVE1_NO_SCORE_PRE_EXECUTION",
            "runtime_inventory": inventory,
            "runtime_inventory_sha256": audit_inventory_sha256(inventory),
            "checks": checks,
            "mg1_schema_check": mg1,
            "candidate_scores_seen": False,
            "candidate_predictions_run": False,
            "fresh_or_heldout_opened": False,
            "execution_binding_written": False,
            "execution_precommit_written": False,
            "registries_mutated": False,
        }
    )
    write_immutable_json(args.output, payload)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
