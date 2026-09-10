"""Create the V3.2 pre-probe and final replay closures without opening score truth."""

from __future__ import annotations

import argparse
from importlib import metadata as importlib_metadata
import json
from pathlib import Path
import platform
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.model_zoo.probabilistic_exploration_v2.contracts import (  # noqa: E402
    ExplorationContractError,
    sha256_bytes,
    sha256_file,
)
from research.model_zoo.probabilistic_exploration_v3.closure import (  # noqa: E402
    CLOSURE_SCHEMA,
    file_record,
)
from research.model_zoo.probabilistic_exploration_v3.design import (  # noqa: E402
    COMMON_FULL_LOAD_LOCK_PATH,
    COMMON_FULL_LOAD_LOCK_RAW_SHA256,
    LANE_LABELS,
    PARENT_AGGRESSIVE_DESIGN_RAW_SHA256,
    RESOURCE_POLICY,
    design_payload,
    verify_design_file,
)
from research.model_zoo.probabilistic_exploration_v3.governance import (  # noqa: E402
    INVENTORY_SCHEMA,
    load_v3_inventory,
)
from research.model_zoo.probabilistic_exploration_v3.resources import (  # noqa: E402
    gpu_inventory,
)


DEFAULT_OUTPUT = (
    ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_design_20260820"
)
DEFAULT_PROBE_OUTPUT = (
    ROOT / "outputs" / "model_zoo_probabilistic_exploration_v3_2_gpu_probe_20260820"
)
DEFAULT_PROBE_APPROVAL = (
    ROOT
    / "outputs"
    / "model_zoo_probabilistic_exploration_v3_2_gpu_probe_approval_20260820"
    / "APPROVAL.json"
)
CREATED_AT = "2026-08-20T07:40:00+09:00"
PACKAGE_DISTRIBUTIONS = (
    "PyYAML",
    "catboost",
    "graphviz",
    "joblib",
    "lightgbm",
    "matplotlib",
    "numpy",
    "pandas",
    "plotly",
    "pyarrow",
    "scikit-learn",
    "scipy",
    "threadpoolctl",
)


def _json_raw(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
    ).encode("utf-8")


def _write_new(path: Path, raw: bytes) -> None:
    path = Path(path)
    if path.exists():
        raise ExplorationContractError(f"refusing to overwrite frozen artifact: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _checked_record(relative: str) -> dict[str, Any]:
    return file_record(ROOT / relative, root=ROOT)


def _inventory_payload() -> dict[str, Any]:
    artifact_paths = {
        "parent_aggressive_design": (
            "outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json"
        ),
        "common_full_load_lock": COMMON_FULL_LOAD_LOCK_PATH,
        "v2_design_lock": (
            "outputs/model_zoo_probabilistic_exploration_v2_design_20260820/"
            "DESIGN_LOCK.json"
        ),
        "v2_input_inventory": (
            "outputs/model_zoo_probabilistic_exploration_v2_design_20260820/"
            "INPUT_INVENTORY.json"
        ),
        "v2_checksums": (
            "outputs/model_zoo_probabilistic_exploration_v2_design_20260820/"
            "CHECKSUMS.sha256"
        ),
        "v2_independent_audit": (
            "outputs/model_zoo_probabilistic_exploration_v2_independent_audit_20260820/"
            "AUDIT.json"
        ),
        "immutable_survivor_score_manifest": (
            "outputs/model_zoo_probabilistic_exploration_v2_survivor_score_20260820/"
            "MANIFEST.json"
        ),
        "immutable_survivor_p50_bridge": (
            "outputs/model_zoo_probabilistic_exploration_v2_survivor_score_20260820/"
            "CENTRAL_P50_BRIDGE.csv"
        ),
        "immutable_survivor_metrics": (
            "outputs/model_zoo_probabilistic_exploration_v2_survivor_score_20260820/"
            "SURVIVOR_METRICS.json"
        ),
        "failed_v3_design": (
            "outputs/model_zoo_probabilistic_exploration_v3_design_20260820/"
            "DESIGN_LOCK.json"
        ),
        "failed_v3_inventory": (
            "outputs/model_zoo_probabilistic_exploration_v3_design_20260820/"
            "INPUT_INVENTORY.json"
        ),
        "failed_v3_runtime_closure": (
            "outputs/model_zoo_probabilistic_exploration_v3_design_20260820/"
            "RUNTIME_CLOSURE.json"
        ),
        "failed_v3_heavy_approval": (
            "outputs/model_zoo_probabilistic_exploration_v3_heavy_approval_20260820/"
            "APPROVAL.json"
        ),
        "failed_v3_stderr": (
            "outputs/model_zoo_probabilistic_exploration_v3_full_load_stderr_20260820.log"
        ),
        "failed_v3_stdout": (
            "outputs/model_zoo_probabilistic_exploration_v3_full_load_stdout_20260820.log"
        ),
        "failed_v3_1_design": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_design_20260820/"
            "DESIGN_LOCK.json"
        ),
        "failed_v3_1_inventory": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_design_20260820/"
            "INPUT_INVENTORY.json"
        ),
        "failed_v3_1_preprobe_runtime_closure": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_design_20260820/"
            "PREPROBE_RUNTIME_CLOSURE.json"
        ),
        "failed_v3_1_preprobe_runtime_closure_sidecar": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_design_20260820/"
            "PREPROBE_RUNTIME_CLOSURE.sha256"
        ),
        "failed_v3_1_gpu_probe_approval": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_gpu_probe_approval_20260820/"
            "APPROVAL.json"
        ),
        "failed_v3_1_gpu_probe_failure": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_gpu_probe_failure_20260820/"
            "FAILURE.json"
        ),
        "failed_v3_1_gpu_probe_failure_manifest": (
            "outputs/model_zoo_probabilistic_exploration_v3_1_gpu_probe_failure_20260820/"
            "MANIFEST.json"
        ),
    }
    artifacts = {
        name: _checked_record(relative) for name, relative in artifact_paths.items()
    }
    return {
        "schema_version": INVENTORY_SCHEMA,
        "created_at": CREATED_AT,
        "lane_labels": list(LANE_LABELS),
        "state": "V3_2_FULL_LOAD_REFREEZE_PRE_SCORE_PRE_FIT",
        "parent_design_lock_raw_sha256": PARENT_AGGRESSIVE_DESIGN_RAW_SHA256,
        "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        "truth_opened": False,
        "score_computed": False,
        "heavy_fit_started": False,
        "fresh_or_heldout_opened": False,
        "registry_mutated": False,
        "artifacts": artifacts,
        "failed_v3_attempt": {
            "failure": "locked feature entirely missing in eligible training prefix",
            "cpu_phase_started": True,
            "gpu_phase_started": False,
            "prediction_publication_created": False,
            "truth_opened": False,
            "score_computed": False,
            "immutable": True,
        },
        "failed_v3_1_gpu_probe": {
            "failed_candidate_id": (
                "catboost_multiquantile_with_regime_exploration_v1"
            ),
            "failure": "installed CatBoost GPU MultiQuantile unsupported",
            "lightgbm_probe_stage_completed": True,
            "conformal_probe_stage_started": False,
            "heavy_prediction_started": False,
            "truth_opened": False,
            "score_or_evaluator_called": False,
            "fallback_applied": False,
            "immutable": True,
        },
        "feature_intervention": {
            "selection_input": "eligible training X only",
            "test_values_inspected_for_selection": False,
            "target_values_inspected_for_selection": False,
            "imputation": False,
            "same_subset_for_test": True,
            "actual_seed_fold_preflight_count": 60,
            "status": "PASS",
        },
        "gpu_backend_preflight": {
            "scope": "SCORE_FREE_ONE_FOLD_GPU_BACKEND_COMPATIBILITY_ONLY",
            "seed": 6301,
            "fold_id": "fold_012",
            "truth_opened": False,
            "score_or_evaluator_called": False,
            "required_before_final_runtime_closure": True,
            "output_path": DEFAULT_PROBE_OUTPUT.relative_to(ROOT).as_posix(),
        },
        "runtime_closure": {
            "preprobe_path": (
                "outputs/model_zoo_probabilistic_exploration_v3_2_design_20260820/"
                "PREPROBE_RUNTIME_CLOSURE.json"
            ),
            "preprobe_raw_pin_sidecar": (
                "outputs/model_zoo_probabilistic_exploration_v3_2_design_20260820/"
                "PREPROBE_RUNTIME_CLOSURE.sha256"
            ),
            "final_path": (
                "outputs/model_zoo_probabilistic_exploration_v3_2_design_20260820/"
                "RUNTIME_CLOSURE.json"
            ),
            "final_raw_pin_sidecar": (
                "outputs/model_zoo_probabilistic_exploration_v3_2_design_20260820/"
                "RUNTIME_CLOSURE.sha256"
            ),
            "generated_after_source_and_inventory_freeze": True,
        },
        "governance": {
            "gpu_backend_preflight": "ROOT_SEALED_SCORE_FREE_APPROVAL_REQUIRED",
            "heavy_candidate_fit": "BLOCKED_UNTIL_NEW_SEALED_ROOT_APPROVAL",
            "future_candidate_spent_score": (
                "BLOCKED_UNTIL_PREDICTION_FREEZE_AND_SEALED_ROOT_APPROVAL"
            ),
            "immutable_survivor_central_tournament": (
                "BLOCKED_UNTIL_SEALED_ROOT_APPROVAL"
            ),
            "fresh_or_heldout": "FORBIDDEN",
            "registry_or_production_mutation": "FORBIDDEN",
        },
    }


def _source_records() -> list[dict[str, Any]]:
    paths: set[Path] = set()
    for directory in (
        ROOT / "research" / "model_zoo" / "aggressive_lab",
        ROOT / "research" / "model_zoo" / "probabilistic_exploration_v2",
        ROOT / "research" / "model_zoo" / "probabilistic_exploration_v3",
        ROOT / "scripts" / "model_lab" / "probabilistic_exploration_v3",
        ROOT / "src" / "pe_regime_v04" / "model_lab",
    ):
        paths.update(path for path in directory.rglob("*.py") if path.is_file())
    paths.add(ROOT / "src" / "pe_regime_v04" / "__init__.py")
    return [file_record(path, root=ROOT) for path in sorted(paths)]


def _walk_file_records(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        if set(value) == {"path", "bytes", "sha256"}:
            yield dict(value)
        else:
            for child in value.values():
                yield from _walk_file_records(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_file_records(child)


def _deduplicated_checked_records(
    records: Iterable[Mapping[str, Any]], *, excluded_paths: set[str]
) -> list[dict[str, Any]]:
    by_path: dict[str, dict[str, Any]] = {}
    for record in records:
        relative = str(record["path"])
        if relative in excluded_paths:
            continue
        actual = _checked_record(relative)
        if (
            int(record["bytes"]) != actual["bytes"]
            or str(record["sha256"]) != actual["sha256"]
        ):
            raise ExplorationContractError(f"upstream artifact drift: {relative}")
        by_path[relative] = actual
    return [by_path[path] for path in sorted(by_path)]


def _runtime_payload() -> dict[str, Any]:
    executable = Path(sys.executable).resolve()
    return {
        "packages": {
            distribution: importlib_metadata.version(distribution)
            for distribution in PACKAGE_DISTRIBUTIONS
        },
        "platform_machine": platform.machine(),
        "platform_system": platform.system(),
        "python_executable": {
            "path": str(executable),
            "bytes": executable.stat().st_size,
            "sha256": sha256_file(executable),
        },
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
    }


def _closure_payload(
    *,
    design_path: Path,
    inventory_path: Path,
    phase: str,
    extra_records: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    _, inventory, v2_inventory = load_v3_inventory(ROOT, inventory_path)
    common_record = _checked_record(COMMON_FULL_LOAD_LOCK_PATH)
    upstream_records = [
        *_walk_file_records(inventory["artifacts"]),
        *_walk_file_records(v2_inventory["artifacts"]),
        *extra_records,
    ]
    artifact_records = _deduplicated_checked_records(
        [
            file_record(design_path, root=ROOT),
            file_record(inventory_path, root=ROOT),
            *upstream_records,
        ],
        excluded_paths={COMMON_FULL_LOAD_LOCK_PATH},
    )
    return {
        "schema_version": CLOSURE_SCHEMA,
        "created_at": CREATED_AT,
        "phase": phase,
        "lane_labels": list(LANE_LABELS),
        "parent_design_lock_raw_sha256": PARENT_AGGRESSIVE_DESIGN_RAW_SHA256,
        "common_full_load_lock_raw_sha256": COMMON_FULL_LOAD_LOCK_RAW_SHA256,
        "common_full_load_lock": common_record,
        "source_records": _source_records(),
        "artifact_records": artifact_records,
        "runtime": _runtime_payload(),
        "hardware": {"gpu": gpu_inventory()},
        "resource_contract": {
            "cpu_ids": RESOURCE_POLICY["logical_cpu_ids"],
            "maximum_outer_workers": RESOURCE_POLICY["maximum_outer_workers"],
            "inner_threads": RESOURCE_POLICY["estimator_inner_threads"],
            "aggregate_rss_soft_limit_bytes": RESOURCE_POLICY[
                "aggregate_rss_limit_bytes"
            ],
            "minimum_free_ram_bytes": RESOURCE_POLICY["minimum_free_ram_bytes"],
            "gpu_candidate_concurrency": RESOURCE_POLICY["gpu"][
                "maximum_concurrent_gpu_tasks"
            ],
        },
        "training_label_bytes_in_closure": True,
        "evaluation_truth_bytes_in_closure": False,
        "truth_open_requires_post_prediction_approval": True,
        "fresh_or_heldout_authority": False,
        "production_promotion_authority": False,
    }


def freeze_preprobe(output: Path) -> dict[str, str]:
    output = Path(output).resolve()
    design_path = output / "DESIGN_LOCK.json"
    inventory_path = output / "INPUT_INVENTORY.json"
    closure_path = output / "PREPROBE_RUNTIME_CLOSURE.json"
    design_raw = _json_raw(design_payload())
    _write_new(design_path, design_raw)
    inventory_raw = _json_raw(_inventory_payload())
    _write_new(inventory_path, inventory_raw)
    closure_raw = _json_raw(
        _closure_payload(
            design_path=design_path,
            inventory_path=inventory_path,
            phase="PRE_SCORE_FREE_GPU_BACKEND_PROBE",
        )
    )
    _write_new(closure_path, closure_raw)
    closure_sha = sha256_bytes(closure_raw)
    _write_new(output / "PREPROBE_RUNTIME_CLOSURE.sha256", (closure_sha + "\n").encode())
    return {
        "design_raw_sha256": sha256_bytes(design_raw),
        "inventory_raw_sha256": sha256_bytes(inventory_raw),
        "preprobe_runtime_closure_raw_sha256": closure_sha,
    }


def freeze_final(
    output: Path, *, probe_output: Path, probe_approval: Path
) -> dict[str, str]:
    output = Path(output).resolve()
    design_path = output / "DESIGN_LOCK.json"
    inventory_path = output / "INPUT_INVENTORY.json"
    verify_design_file(design_path)
    load_v3_inventory(ROOT, inventory_path)
    preprobe_path = output / "PREPROBE_RUNTIME_CLOSURE.json"
    preprobe_sidecar = output / "PREPROBE_RUNTIME_CLOSURE.sha256"
    expected_preprobe = preprobe_sidecar.read_text(encoding="ascii").strip()
    if sha256_file(preprobe_path) != expected_preprobe:
        raise ExplorationContractError("preprobe closure sidecar differs")
    probe_output = Path(probe_output).resolve()
    probe_approval = Path(probe_approval).resolve()
    extra_paths = (
        preprobe_path,
        preprobe_sidecar,
        probe_approval,
        probe_output / "GPU_BACKEND_PREFLIGHT.json",
        probe_output / "MANIFEST.json",
    )
    closure = _closure_payload(
        design_path=design_path,
        inventory_path=inventory_path,
        phase="FINAL_POST_GPU_PROBE_PRE_HEAVY_APPROVAL",
        extra_records=(file_record(path, root=ROOT) for path in extra_paths),
    )
    closure["preprobe_runtime_closure_raw_sha256"] = expected_preprobe
    closure["gpu_probe_manifest_raw_sha256"] = sha256_file(
        probe_output / "MANIFEST.json"
    )
    closure["gpu_probe_result_raw_sha256"] = sha256_file(
        probe_output / "GPU_BACKEND_PREFLIGHT.json"
    )
    closure_path = output / "RUNTIME_CLOSURE.json"
    closure_raw = _json_raw(closure)
    _write_new(closure_path, closure_raw)
    closure_sha = sha256_bytes(closure_raw)
    _write_new(output / "RUNTIME_CLOSURE.sha256", (closure_sha + "\n").encode())
    return {
        "design_raw_sha256": sha256_file(design_path),
        "inventory_raw_sha256": sha256_file(inventory_path),
        "runtime_closure_raw_sha256": closure_sha,
        "gpu_probe_manifest_raw_sha256": closure[
            "gpu_probe_manifest_raw_sha256"
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("preprobe", "final"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--probe-output", type=Path, default=DEFAULT_PROBE_OUTPUT)
    parser.add_argument("--probe-approval", type=Path, default=DEFAULT_PROBE_APPROVAL)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.phase == "preprobe":
        result = freeze_preprobe(args.output)
    else:
        result = freeze_final(
            args.output,
            probe_output=args.probe_output,
            probe_approval=args.probe_approval,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
