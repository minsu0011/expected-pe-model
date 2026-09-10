"""Fail-closed, resumable multi-seed validation for the v0.4 overlay.

The public workflow is intentionally split into three invocations::

    python scripts/run_v04_multiseed_validation.py tune ...
    python scripts/run_v04_multiseed_validation.py lock ...
    python scripts/run_v04_multiseed_validation.py holdout ...

There is no ``all`` shortcut.  Held-out synthetic seeds may only be generated after
the tuning result and candidate configuration have been sealed in ``candidate.lock``.
The harness is deliberately outside ``src``: it evaluates a frozen source/config
snapshot and must never become part of the production calculation path.
"""

from __future__ import annotations

import argparse
import ast
import copy
import ctypes
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


EXECUTION_LOGICAL_CPU_IDS = (
    tuple(range(int(os.cpu_count() or 1)))
    if os.name == "nt"
    else tuple(sorted(int(value) for value in os.sched_getaffinity(0)))
    if hasattr(os, "sched_getaffinity")
    else tuple(range(int(os.cpu_count() or 1)))
)
EXECUTION_AFFINITY_MASK = sum(1 << cpu_id for cpu_id in EXECUTION_LOGICAL_CPU_IDS)
EXECUTION_MAXIMUM_CPU_THREADS = len(EXECUTION_LOGICAL_CPU_IDS)
EXECUTION_THREAD_ENVIRONMENT = (
    "OMP_NUM_THREADS",
    "MKL_NUM_THREADS",
    "OPENBLAS_NUM_THREADS",
    "NUMEXPR_NUM_THREADS",
)
EXECUTION_GPU_ENVIRONMENT = {
    "CUDA_VISIBLE_DEVICES": "-1",
    "NVIDIA_VISIBLE_DEVICES": "void",
    "HIP_VISIBLE_DEVICES": "-1",
    "ROCR_VISIBLE_DEVICES": "-1",
}


def _execution_policy_runtime(*, apply: bool) -> dict[str, Any]:
    """Apply/verify the full-host CPU and GPU-off execution boundary.

    This function is deliberately defined and first called before NumPy is
    imported.  Overlay workers inherit the exact affinity and retain the
    stricter one-thread environment supplied by the parent process.
    """

    for name in EXECUTION_THREAD_ENVIRONMENT:
        raw = os.environ.get(name, "")
        try:
            requested = int(raw)
        except ValueError:
            requested = EXECUTION_MAXIMUM_CPU_THREADS
        if apply:
            if not 1 <= requested <= EXECUTION_MAXIMUM_CPU_THREADS:
                requested = EXECUTION_MAXIMUM_CPU_THREADS
            os.environ[name] = str(requested)
        if not 1 <= requested <= EXECUTION_MAXIMUM_CPU_THREADS:
            raise RuntimeError(f"{name} must stay within 1..{EXECUTION_MAXIMUM_CPU_THREADS}")

    for name, expected in EXECUTION_GPU_ENVIRONMENT.items():
        if apply:
            os.environ[name] = expected
        if os.environ.get(name) != expected:
            raise RuntimeError(f"GPU-off environment changed: {name}")

    expected_mask = int(EXECUTION_AFFINITY_MASK)
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.argtypes = []
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.SetProcessAffinityMask.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel32.SetProcessAffinityMask.restype = ctypes.c_int
        kernel32.GetProcessAffinityMask.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        kernel32.GetProcessAffinityMask.restype = ctypes.c_int
        process = kernel32.GetCurrentProcess()
        if apply and not kernel32.SetProcessAffinityMask(process, ctypes.c_size_t(expected_mask)):
            raise RuntimeError(
                "cannot apply full-load CPU affinity mask "
                f"0x{expected_mask:08X}: winerror={ctypes.get_last_error()}"
            )
        process_mask = ctypes.c_size_t()
        system_mask = ctypes.c_size_t()
        if not kernel32.GetProcessAffinityMask(
            process,
            ctypes.byref(process_mask),
            ctypes.byref(system_mask),
        ):
            raise RuntimeError(
                f"cannot verify full-load CPU affinity: winerror={ctypes.get_last_error()}"
            )
        observed_ids = tuple(
            cpu_id for cpu_id in range(64) if int(process_mask.value) & (1 << cpu_id)
        )
        observed_mask = int(process_mask.value)
    elif hasattr(os, "sched_getaffinity") and hasattr(os, "sched_setaffinity"):
        desired = set(EXECUTION_LOGICAL_CPU_IDS)
        if apply:
            available = set(os.sched_getaffinity(0))
            if not desired.issubset(available):
                raise RuntimeError(
                    "full-load logical CPU set is unavailable; "
                    f"required={sorted(desired)}, available={sorted(available)}"
                )
            os.sched_setaffinity(0, desired)
        observed_ids = tuple(sorted(int(value) for value in os.sched_getaffinity(0)))
        observed_mask = sum(1 << cpu_id for cpu_id in observed_ids)
    else:
        raise RuntimeError("this platform cannot enforce the required CPU affinity")

    if observed_ids != EXECUTION_LOGICAL_CPU_IDS or observed_mask != expected_mask:
        raise RuntimeError(
            "full-load CPU affinity differs: "
            f"expected={EXECUTION_LOGICAL_CPU_IDS}, observed={observed_ids}"
        )
    return {
        "logical_cpu_ids": list(observed_ids),
        "affinity_mask_hex": f"0x{observed_mask:08X}",
        "thread_environment": {
            name: int(os.environ[name]) for name in EXECUTION_THREAD_ENVIRONMENT
        },
        "gpu_environment": dict(EXECUTION_GPU_ENVIRONMENT),
    }


_EXECUTION_IMPORT_RUNTIME = _execution_policy_runtime(apply=True)

import numpy as np  # noqa: E402 - execution policy must precede numerical imports
import pandas as pd  # noqa: E402 - execution policy must precede numerical imports


HARNESS_VERSION = "2.6"
MANIFEST_FORMAT_VERSION = 4
CHECKPOINT_FORMAT_VERSION = 4
ARTIFACT_FORMAT_VERSION = 3
ARTIFACT_LAYOUT_VERSION = 3
PATH_POLICY_VERSION = 2
RESULT_FORMAT_VERSION = 3
LOCK_FORMAT_VERSION = 3
REPORT_FORMAT_VERSION = 3
WINDOWS_CLASSIC_FILE_PATH_CHARS = 259
WINDOWS_CLASSIC_DIRECTORY_PATH_CHARS = 248
WINDOWS_MAX_PID = 4_294_967_295
DEFAULT_TUNING_SEEDS = (2309, 2411, 2503, 2609, 2707)
DEFAULT_LOCKED_SEEDS = (2801, 2903, 3001, 3109, 3203)
DETERMINISM_SERIAL_OUTER_JOBS = 1
DETERMINISM_PARALLEL_OUTER_JOBS = 32
CANONICAL_V03_COLUMNS = 150
ROWS = 1800
CAUSAL_PREFIX_ROWS = 1500
GENERATION_START = "2013-01-02"
PRODUCTION_EVALUATION_START = "2015-01-02"
EXPECTED_LAST_DATE = "2020-02-26"
EXPECTED_DATE_INDEX_SHA256 = "62a428e4dbd37fbf72cdab78b3209073e2916ff3b8c2d41bdad5504726bfa9d5"
REGIMES = ("BEAR", "SIDEWAYS", "BULL")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
INVARIANCE_CONFIG_SECTIONS = (
    "regime_stacker",
    "expected_pe",
    "fundamental_vintage",
    "lagged_market_conditioned",
    "ml_incumbent_weekly_median_shrinkage",
    "matured_proxy_gate",
)
PROMOTION_METRICS = ("fair_log_mae", "fair_log_rmse")
DIAGNOSTIC_ONLY_METRICS = ("observed_log_mae", "observed_log_rmse")
ALL_PAIRED_METRICS = PROMOTION_METRICS + DIAGNOSTIC_ONLY_METRICS

PROMOTION_POLICY_ID = "v04-dual-comparator-promotion-stat-v2"
PROMOTION_POLICY_FORMAT_VERSION = 2
PROMOTION_MINIMUM_TUNING_SEEDS = 5
PROMOTION_MINIMUM_LOCKED_SEEDS = 5
PROMOTION_MINIMUM_COMMON_ROWS = 1260
PROMOTION_JOINT_WIN_FRACTION = 0.80
PROMOTION_WORST_SEED_DEGRADATION_CAP = 0.005
PROMOTION_PRACTICAL_GAIN = 0.005
PROMOTION_BOOTSTRAP_ITERATIONS = 49_999
PROMOTION_BOOTSTRAP_METHODS = ("moving_block", "stationary")
PROMOTION_BOOTSTRAP_BLOCK_LENGTHS = (21, 42, 63)
PROMOTION_FAMILY_ALPHA = 0.05
PROMOTION_COMPARATOR_METRIC_ALPHA = 0.0125
PROMOTION_BOOTSTRAP_MASTER_SEED = 2_026_081_801
PROMOTION_BOOTSTRAP_RNG = "PCG64DXSM"
PROMOTION_BOOTSTRAP_QUANTILE_METHOD = "inverted_cdf"
PROMOTION_BOOTSTRAP_CHUNK_SIZE = 128
SPENT_SEED_REGISTRY_FORMAT_VERSION = 1
SPENT_SEED_REGISTRY_ID = "v04-prospective-spent-seeds-v1"

# Every seed whose result was inspected or whose locked commitment was consumed
# before the prospective v1 policy.  It may remain useful as historical evidence,
# but it can never enter a new prospective tuning or heldout set.
SPENT_EVIDENCE_SEEDS = (
    11,
    23,
    37,
    101,
    149,
    211,
    307,
    401,
    503,
    607,
    709,
    811,
    907,
    1009,
    1103,
    1201,
    1301,
    1409,
    1511,
    1601,
    1709,
    1801,
    1901,
    2003,
    2111,
    2203,
)

PROMOTION_DAILY_EVIDENCE_COLUMNS = (
    "seed",
    "date",
    "true_fair_pe",
    "observed_pe",
    "primary_v04_expected_pe",
    "anti_ml_expected_pe",
    "challenger_pe",
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EPS_ROOT = PROJECT_ROOT.parent
DEFAULT_V03_ROOT = EPS_ROOT / "PE_Regime_Engine_v0.2.0"
DEFAULT_V03_PYTHON = DEFAULT_V03_ROOT / ".venv" / "Scripts" / "python.exe"
DEFAULT_V03_CONFIG = DEFAULT_V03_ROOT / "config" / "high_accuracy.yaml"
DEFAULT_V04_CONFIG = PROJECT_ROOT / "config" / "v04_bottleneck.yaml"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "outputs" / "v04_multiseed_validation"
SPENT_SEED_REGISTRY_PATH = PROJECT_ROOT / "outputs" / "v04_spent_seed_registry.json"

DEFAULT_CANDIDATES: dict[str, dict[str, Any]] = {
    "current": {
        "selection_column": "v04_expected_pe",
        "overrides": {},
    }
}

EXPECTED_PE_COLUMNS = (
    "statistical_expected_pe",
    "ml_expected_pe",
    "expected_pe",
    "v04_global_statistical_expected_pe",
    "v04_guarded_statistical_expected_pe",
    "v04_ml_expected_pe_no_regime",
    "v04_market_conditioned_kalman_diagnostic_expected_pe",
    "v04_fundamental_vintage_expected_pe",
    "v04_lagged_market_conditioned_raw_expected_pe",
    "v04_gated_lagged_market_conditioned_expected_pe",
    "v04_ml_weekly_median_shrinkage_expected_pe",
    "v04_matured_proxy_regularized_expected_pe",
    "v04_ml_expected_pe_with_regime",
    "v04_matched_best_ml_expected_pe",
    "v04_guarded_ml_expected_pe",
    "v04_dynamic_blend_expected_pe",
    "v04_expected_pe",
)

# These research surfaces have an explicit ``enabled`` switch and remain in the
# public schema while disabled.  They are still audited when enabled; only a
# non-selected, configured-off surface that is wholly missing in the evaluation
# scope may be recorded as unavailable instead of aborting primary analysis.
OPTIONAL_EXPECTED_PE_CONFIG_SECTIONS = {
    "v04_fundamental_vintage_expected_pe": "fundamental_vintage",
    "v04_lagged_market_conditioned_raw_expected_pe": "lagged_market_conditioned",
    "v04_gated_lagged_market_conditioned_expected_pe": "lagged_market_conditioned",
    "v04_ml_weekly_median_shrinkage_expected_pe": ("ml_incumbent_weekly_median_shrinkage"),
    "v04_matured_proxy_regularized_expected_pe": "matured_proxy_gate",
}

# Promotion semantics are code-owned, not candidate-JSON-owned.  Every challenger
# must clear both the current product and the raw-ML anti-gaming reference on the
# exact same daily rows.  Candidate JSON cannot name, replace, or weaken either
# comparator.  Adding a comparator or promotion surface is therefore a harness
# code review rather than a data-file edit.
PROMOTION_COMPARATORS: dict[str, str] = {
    "primary_product": "v04_expected_pe",
    "anti_gaming": "ml_expected_pe",
}
PROMOTION_PRIMARY_COMPARATOR = "primary_product"
PROMOTION_ANTI_GAMING_COMPARATOR = "anti_gaming"
PROMOTION_PRIMARY_COMPARATOR_COLUMN = PROMOTION_COMPARATORS[PROMOTION_PRIMARY_COMPARATOR]
PROMOTION_ANTI_GAMING_COMPARATOR_COLUMN = PROMOTION_COMPARATORS[PROMOTION_ANTI_GAMING_COMPARATOR]
PROMOTION_SELECTION_COLUMNS = frozenset(
    {
        "v04_expected_pe",
        "v04_ml_no_regime_shrinkage_expected_pe",
        "v04_market_conditioned_kalman_diagnostic_expected_pe",
        "v04_fundamental_vintage_expected_pe",
        "v04_gated_lagged_market_conditioned_expected_pe",
        "v04_ml_weekly_median_shrinkage_expected_pe",
        "v04_matured_proxy_regularized_expected_pe",
    }
)

PAIR_DEFINITIONS = {
    "matched_no_regime_vs_with_regime": (
        "v04_ml_expected_pe_no_regime",
        "v04_ml_expected_pe_with_regime",
    ),
    "v03_ml_vs_matched_best": (
        "ml_expected_pe",
        "v04_matched_best_ml_expected_pe",
    ),
    "guarded_ml_vs_guarded_stat": (
        "v04_guarded_ml_expected_pe",
        "v04_guarded_statistical_expected_pe",
    ),
    "v03_ml_vs_v04_final": ("ml_expected_pe", "v04_expected_pe"),
}

# prefix: (baseline, challenger, blended, config section)
GATE_DEFINITIONS = {
    "v04_stat_regime": (
        "v04_global_baseline_expected_pe",
        "statistical_expected_pe",
        "v04_stat_regime_blended",
        "statistical_gate",
    ),
    "v04_ml_matched_regime": (
        "v04_ml_expected_pe_no_regime",
        "v04_ml_expected_pe_with_regime",
        "v04_ml_matched_regime_blended",
        "ml_matched_regime_gate",
    ),
    "v04_ml_no_regime": (
        "v04_ml_incumbent_expected_pe",
        "v04_ml_expected_pe_no_regime",
        "v04_ml_no_regime_blended",
        "ml_no_regime_gate",
    ),
    "v04_ml_incumbent": (
        "v04_ml_incumbent_expected_pe",
        "v04_matched_best_ml_expected_pe",
        "v04_ml_incumbent_blended",
        "ml_incumbent_gate",
    ),
    "v04_final_stat_challenger": (
        "v04_guarded_ml_expected_pe",
        "v04_guarded_statistical_expected_pe",
        "v04_final_stat_challenger_blended",
        "final_guard",
    ),
}


class ValidationError(RuntimeError):
    """A validation contract failed and the run must stop closed."""


@dataclass(frozen=True)
class PlannedArtifactPath:
    label: str
    path: Path
    is_directory: bool = False


def _atomic_temp_path(path: Path, pid: int) -> Path:
    return path.with_name(f".{path.name}.{int(pid)}.tmp")


def _read_v03_demo_generator_version(v03_root: Path) -> str:
    """Read the v0.3 path component without importing or spawning v0.3."""

    source_path = Path(v03_root) / "src" / "pe_regime_engine" / "demo.py"
    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    except (OSError, SyntaxError) as exc:
        raise ValidationError(
            f"cannot read v0.3 DEMO_GENERATOR_VERSION before path preflight: {source_path}"
        ) from exc

    version: Any = None
    for node in tree.body:
        targets: list[ast.expr] = []
        value_node: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
            value_node = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value_node = node.value
        if value_node is None or not any(
            isinstance(target, ast.Name) and target.id == "DEMO_GENERATOR_VERSION"
            for target in targets
        ):
            continue
        try:
            version = ast.literal_eval(value_node)
        except (TypeError, ValueError) as exc:
            raise ValidationError("v0.3 DEMO_GENERATOR_VERSION must be a string literal") from exc
        break

    if (
        not isinstance(version, str)
        or not version
        or len(version) > 128
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", version)
    ):
        raise ValidationError("v0.3 DEMO_GENERATOR_VERSION is missing or unsafe")
    return version


def _runtime_platform_name() -> str:
    return os.name


def _windows_long_paths_enabled() -> bool:
    """Return the machine policy; unreadable policy fails closed as disabled."""

    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
        ) as key:
            value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
    except (ImportError, OSError):
        return False
    return int(value) == 1


def _planned_artifact_paths(
    args: argparse.Namespace,
    candidates: Mapping[str, Mapping[str, Any]],
    demo_generator_version: str,
) -> tuple[PlannedArtifactPath, ...]:
    """Enumerate the sealed v3 artifact layout before output or subprocess work."""

    _require_determinism_parallel_outer_jobs(args.outer_jobs)
    root = args.output_root
    files: dict[str, PlannedArtifactPath] = {}
    directories: dict[str, PlannedArtifactPath] = {}

    def add_directory(label: str, path: Path) -> None:
        directories.setdefault(str(path), PlannedArtifactPath(label, path, True))

    def add_parent_directories(label: str, path: Path) -> None:
        parent = path.parent
        while True:
            try:
                parent.relative_to(root)
            except ValueError:
                break
            add_directory(f"{label}:parent", parent)
            if parent == root:
                break
            parent = parent.parent

    def add_file(label: str, path: Path, *, atomic_json: bool = False) -> None:
        files.setdefault(str(path), PlannedArtifactPath(label, path))
        add_parent_directories(label, path)
        if atomic_json:
            temporary = _atomic_temp_path(path, WINDOWS_MAX_PID)
            files.setdefault(
                str(temporary),
                PlannedArtifactPath(f"{label}:atomic_temp_max_pid", temporary),
            )
            add_parent_directories(label, temporary)

    add_directory("output_root", root)
    for filename in (
        "promotion_policy.lock.json",
        "run_manifest.json",
        "checkpoint.json",
        "tuning_common_metrics.json",
        "candidate.lock.json",
        "lock_rejected.json",
        "heldout_report.json",
    ):
        add_file(f"root:{filename}", root / filename, atomic_json=True)

    representatives = {
        str(group["representative_candidate"]) for group in args.invariance_plan["groups"].values()
    }
    stage_seeds = {
        "tuning": tuple(int(seed) for seed in args.tuning_seeds),
        "heldout": tuple(int(seed) for seed in args.locked_seeds),
    }
    v03_stem = "DEMO_PE_Regime_DEMO_BENCH"
    for stage, seeds in stage_seeds.items():
        for seed in seeds:
            seed_root = root / "artifacts" / stage / f"seed_{seed}"
            v03_output = seed_root / "v03_high"
            add_directory(f"{stage}:{seed}:v03_output", v03_output)
            add_file(f"{stage}:{seed}:v03_cli_log", seed_root / "v03_high_cli.log")

            run_identity = f"{demo_generator_version}_seed_{seed}_rows_{ROWS}"
            demo_input = v03_output / "demo_inputs" / run_identity
            add_directory(f"{stage}:{seed}:demo_input", demo_input)
            for filename in (
                "DEMO_price.csv",
                "DEMO_price_split_adjusted.csv",
                "DEMO_benchmark.csv",
                "DEMO_eps.csv",
                "DEMO_truth.csv",
            ):
                add_file(f"{stage}:{seed}:v03_demo:{filename}", demo_input / filename)
            for filename in (
                f"{v03_stem}.csv",
                f"{v03_stem}_summary.json",
                f"{v03_stem}_diagnostics.json",
                f"{v03_stem}_validation.json",
                f"{v03_stem}_{run_identity}_truth.csv",
            ):
                add_file(f"{stage}:{seed}:v03_result:{filename}", v03_output / filename)
            intermediate = v03_output / "intermediate"
            for filename in (
                "DEMO_pit_eps_events.csv",
                "DEMO_BENCH_benchmark_features.csv",
                "DEMO_BENCH_regime_probabilities.csv",
            ):
                add_file(
                    f"{stage}:{seed}:v03_intermediate:{filename}",
                    intermediate / filename,
                )

            for name in sorted(candidates):
                candidate_root = seed_root / "v04" / name
                add_directory(f"{stage}:{seed}:{name}:candidate_root", candidate_root)
                add_file(
                    f"{stage}:{seed}:{name}:overrides",
                    candidate_root / "candidate_overrides.json",
                    atomic_json=True,
                )
                add_file(
                    f"{stage}:{seed}:{name}:parallel_csv",
                    candidate_root / f"parallel{args.outer_jobs}.csv",
                )
                add_file(
                    f"{stage}:{seed}:{name}:parallel_diagnostics",
                    candidate_root / f"parallel{args.outer_jobs}_diagnostics.json",
                    atomic_json=True,
                )
                add_file(
                    f"{stage}:{seed}:{name}:parallel_log",
                    candidate_root / f"parallel{args.outer_jobs}.log",
                )
                add_file(
                    f"{stage}:{seed}:{name}:result",
                    candidate_root / "result.json",
                    atomic_json=True,
                )
                add_file(
                    f"{stage}:{seed}:{name}:promotion_daily_evidence",
                    candidate_root / "promotion_daily_evidence.csv",
                )

                if args.overlay_adapter in {"auto", "cli"}:
                    cli_adapter = candidate_root / "cli_adapter"
                    add_file(
                        f"{stage}:{seed}:{name}:cli_adapter_csv",
                        cli_adapter / f"{v03_stem}_v04_bottleneck.csv",
                    )
                    add_file(
                        f"{stage}:{seed}:{name}:cli_adapter_report",
                        cli_adapter / f"{v03_stem}_v04_bottleneck_report.json",
                    )

                requires_invariance = (
                    stage == "tuning"
                    and seed == int(args.tuning_seeds[0])
                    and name in representatives
                )
                if not requires_invariance:
                    continue
                add_file(
                    f"{stage}:{seed}:{name}:serial_csv",
                    candidate_root / "serial1.csv",
                )
                add_file(
                    f"{stage}:{seed}:{name}:serial_diagnostics",
                    candidate_root / "serial1_diagnostics.json",
                    atomic_json=True,
                )
                add_file(
                    f"{stage}:{seed}:{name}:serial_log",
                    candidate_root / "serial1.log",
                )
                add_file(
                    f"{stage}:{seed}:{name}:prefix_input",
                    candidate_root / f"causal_prefix_input_{CAUSAL_PREFIX_ROWS}.csv",
                )
                add_file(
                    f"{stage}:{seed}:{name}:prefix_output",
                    candidate_root / f"causal_prefix_output_{CAUSAL_PREFIX_ROWS}.csv",
                )
                add_file(
                    f"{stage}:{seed}:{name}:prefix_diagnostics",
                    candidate_root / "causal_prefix_diagnostics.json",
                    atomic_json=True,
                )
                add_file(
                    f"{stage}:{seed}:{name}:prefix_log",
                    candidate_root / "causal_prefix.log",
                )

    records = [*files.values(), *directories.values()]
    return tuple(sorted(records, key=lambda item: (str(item.path).lower(), item.label)))


def _planned_path_policy(
    args: argparse.Namespace,
    candidates: Mapping[str, Mapping[str, Any]],
    demo_generator_version: str,
    *,
    platform_name: str | None = None,
    long_paths_enabled: bool | None = None,
) -> dict[str, Any]:
    platform = _runtime_platform_name() if platform_name is None else platform_name
    windows = platform == "nt"
    if windows and str(args.output_root).startswith("\\\\?\\"):
        raise ValidationError("extended-length \\\\?\\ output roots are not supported")
    if windows and long_paths_enabled is None:
        long_paths_enabled = _windows_long_paths_enabled()
    if not windows:
        long_paths_enabled = None

    records = _planned_artifact_paths(args, candidates, demo_generator_version)
    file_records = [record for record in records if not record.is_directory]
    directory_records = [record for record in records if record.is_directory]
    longest = max(records, key=lambda item: (len(str(item.path)), str(item.path)))
    longest_file = max(file_records, key=lambda item: (len(str(item.path)), str(item.path)))
    longest_directory = max(
        directory_records,
        key=lambda item: (len(str(item.path)), str(item.path)),
    )
    return {
        "version": PATH_POLICY_VERSION,
        "artifact_layout_version": ARTIFACT_LAYOUT_VERSION,
        "output_root": str(args.output_root),
        "output_root_chars": len(str(args.output_root)),
        "platform": platform,
        "mode": (
            "windows_long_paths_enabled"
            if windows and long_paths_enabled
            else "windows_classic_max_path"
            if windows
            else "platform_native"
        ),
        "long_paths_enabled": long_paths_enabled,
        "classic_safe_file_path_chars": WINDOWS_CLASSIC_FILE_PATH_CHARS,
        "classic_safe_directory_path_chars": WINDOWS_CLASSIC_DIRECTORY_PATH_CHARS,
        "classic_limits_enforced": bool(windows and not long_paths_enabled),
        "planned_path_count": len(records),
        "longest_planned_path_chars": len(str(longest.path)),
        "longest_planned_path": str(longest.path),
        "longest_planned_path_label": longest.label,
        "longest_planned_file_chars": len(str(longest_file.path)),
        "longest_planned_file": str(longest_file.path),
        "longest_planned_directory_chars": len(str(longest_directory.path)),
        "longest_planned_directory": str(longest_directory.path),
        "atomic_temp_pid_envelope": WINDOWS_MAX_PID,
        "v03_demo_generator_version": demo_generator_version,
        "scope": "all_tuning_and_heldout_seeds_x_all_committed_candidates",
    }


def _enforce_planned_path_policy(policy: Mapping[str, Any]) -> None:
    if policy.get("classic_limits_enforced") is not True:
        return
    file_overflow = max(
        0,
        int(policy["longest_planned_file_chars"]) - WINDOWS_CLASSIC_FILE_PATH_CHARS,
    )
    directory_overflow = max(
        0,
        int(policy["longest_planned_directory_chars"]) - WINDOWS_CLASSIC_DIRECTORY_PATH_CHARS,
    )
    required_reduction = max(file_overflow, directory_overflow)
    if required_reduction == 0:
        return
    raise ValidationError(
        "Windows planned artifact path exceeds the conservative MAX_PATH policy "
        "before any output write or subprocess: "
        f"long_paths_enabled={policy['long_paths_enabled']}; "
        f"safe_file_path_chars={WINDOWS_CLASSIC_FILE_PATH_CHARS}; "
        f"safe_directory_path_chars={WINDOWS_CLASSIC_DIRECTORY_PATH_CHARS}; "
        f"longest_planned_path_chars={policy['longest_planned_path_chars']}; "
        f"longest_planned_path={policy['longest_planned_path']}; "
        f"longest_planned_directory_chars={policy['longest_planned_directory_chars']}; "
        f"required_output_root_reduction_chars={required_reduction}"
    )


def _preflight_planned_paths(
    args: argparse.Namespace,
    candidates: Mapping[str, Mapping[str, Any]],
    demo_generator_version: str,
) -> dict[str, Any]:
    policy = _planned_path_policy(args, candidates, demo_generator_version)
    _enforce_planned_path_policy(policy)
    return policy


def _verify_manifest_storage_contract(
    manifest: Mapping[str, Any], expected_path_policy: Mapping[str, Any]
) -> None:
    if manifest.get("format_version") != MANIFEST_FORMAT_VERSION:
        raise ValidationError("run manifest format is incompatible; use a new output directory")
    if manifest.get("harness_version") != HARNESS_VERSION:
        raise ValidationError(
            "run manifest harness version is incompatible; use a new output directory"
        )
    if manifest.get("artifact_layout_version") != ARTIFACT_LAYOUT_VERSION:
        raise ValidationError(
            "run manifest artifact layout is incompatible; use a new output directory"
        )
    if manifest.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION:
        raise ValidationError(
            "run manifest artifact format is incompatible; use a new output directory"
        )
    if manifest.get("promotion_comparators") != PROMOTION_COMPARATORS:
        raise ValidationError("run manifest promotion comparators are missing or invalid")
    if manifest.get("path_policy") != expected_path_policy:
        raise ValidationError("run manifest path policy differs; use a new output directory")
    _verify_promotion_policy_config(manifest.get("promotion_policy_config"), context="run manifest")
    policy_artifact = manifest.get("promotion_policy_lock")
    if not isinstance(policy_artifact, Mapping):
        raise ValidationError("run manifest has no prospective policy-lock artifact")
    policy_path = _verify_artifact(policy_artifact, context="promotion policy lock")
    policy_lock = _read_json(policy_path)
    _verify_sealed(policy_lock, "policy_lock_sha256", context="promotion policy lock")
    if policy_lock.get("policy_lock_sha256") != manifest.get("promotion_policy_lock_sha256"):
        raise ValidationError("run manifest promotion policy-lock hash differs")
    receipt = manifest.get("spent_seed_reservation")
    _verify_spent_seed_reservation_receipt(receipt)
    if policy_lock.get("spent_seed_reservation") != receipt:
        raise ValidationError("manifest/policy spent-seed reservation differs")


def _metric_roles_contract() -> dict[str, Any]:
    return {
        "promotion": {
            "target": "synthetic_true_fair_pe",
            "comparators": copy.deepcopy(PROMOTION_COMPARATORS),
            "both_comparators_must_pass": True,
            "common_daily_mask": [
                "true_fair_pe",
                *PROMOTION_COMPARATORS.values(),
                "challenger_pe",
            ],
            "metrics": list(PROMOTION_METRICS),
            "decision_use": [
                "material_harm_cap",
                "practical_margin",
                "joint_seed_wins",
                "leave_one_seed_out",
                "paired_seed_cluster_time_block_bootstrap",
                "candidate_eligibility",
                "candidate_ranking",
                "holdout_promotion",
            ],
        },
        "diagnostic_only": {
            "target": "pit_observed_pe_reconstruction",
            "metrics": list(DIAGNOSTIC_ONLY_METRICS),
            "decision_use": [],
        },
    }


def _verify_metric_roles(payload: Any, *, context: str) -> None:
    if payload != _metric_roles_contract():
        raise ValidationError(f"{context} metric roles are missing or invalid")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, np.generic):
        value = value.item()
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        _jsonable(payload),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _payload_sha256(payload: Mapping[str, Any], seal_key: str) -> str:
    unsigned = {key: value for key, value in payload.items() if key != seal_key}
    return hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()


def _seal_payload(payload: Mapping[str, Any], seal_key: str) -> dict[str, Any]:
    sealed = copy.deepcopy(dict(payload))
    sealed[seal_key] = _payload_sha256(sealed, seal_key)
    return sealed


def _verify_sealed(payload: Mapping[str, Any], seal_key: str, *, context: str) -> None:
    recorded = payload.get(seal_key)
    expected = _payload_sha256(payload, seal_key)
    if not isinstance(recorded, str) or recorded != expected:
        raise ValidationError(f"{context} hash is missing or invalid")


def _promotion_policy_config() -> dict[str, Any]:
    """Return the immutable, code-owned prospective promotion contract."""

    _execution_policy_runtime(apply=False)
    if not hasattr(np.random, PROMOTION_BOOTSTRAP_RNG):
        raise ValidationError(f"NumPy lacks required RNG {PROMOTION_BOOTSTRAP_RNG}")
    payload = {
        "format_version": PROMOTION_POLICY_FORMAT_VERSION,
        "policy_id": PROMOTION_POLICY_ID,
        "metric_roles": _metric_roles_contract(),
        "minimum_tuning_seeds": PROMOTION_MINIMUM_TUNING_SEEDS,
        "minimum_locked_seeds": PROMOTION_MINIMUM_LOCKED_SEEDS,
        "minimum_common_rows_per_seed": PROMOTION_MINIMUM_COMMON_ROWS,
        "joint_win_fraction": PROMOTION_JOINT_WIN_FRACTION,
        "worst_seed_degradation_cap": PROMOTION_WORST_SEED_DEGRADATION_CAP,
        "pooled_practical_gain": {metric: PROMOTION_PRACTICAL_GAIN for metric in PROMOTION_METRICS},
        "leave_one_seed_out_gain_strictly_positive": True,
        "full_natural_coverage_required": 1.0,
        "promotion_comparators": copy.deepcopy(PROMOTION_COMPARATORS),
        "both_comparators_must_pass": True,
        "candidate_may_choose_comparator": False,
        "candidate_rank": "maximize_worst_relative_pooled_gain_across_2x2_comparator_metrics",
        "daily_evidence_columns": list(PROMOTION_DAILY_EVIDENCE_COLUMNS),
        "common_daily_mask": [
            "true_fair_pe",
            *PROMOTION_COMPARATORS.values(),
            "challenger_pe",
        ],
        "bootstrap": {
            "iterations": PROMOTION_BOOTSTRAP_ITERATIONS,
            "methods": list(PROMOTION_BOOTSTRAP_METHODS),
            "block_lengths": list(PROMOTION_BOOTSTRAP_BLOCK_LENGTHS),
            "family_alpha_one_sided": PROMOTION_FAMILY_ALPHA,
            "comparator_metric_hypotheses": (len(PROMOTION_COMPARATORS) * len(PROMOTION_METRICS)),
            "comparator_metric_alpha_bonferroni": PROMOTION_COMPARATOR_METRIC_ALPHA,
            "master_seed": PROMOTION_BOOTSTRAP_MASTER_SEED,
            "rng": PROMOTION_BOOTSTRAP_RNG,
            "stream_key": "SHA-256(policy_id|master_seed|method|block_length)",
            "quantile_method": PROMOTION_BOOTSTRAP_QUANTILE_METHOD,
            "chunk_size": PROMOTION_BOOTSTRAP_CHUNK_SIZE,
            "seed_clusters_resampled": True,
            "time_indices_synchronized_across_seed_clusters": True,
            "resamples_synchronized_across_comparators_and_metrics": True,
        },
        "software": {
            "numpy_version": np.__version__,
            "float_dtype": "float64",
            "integer_dtype": "int64",
        },
        "execution": {
            "maximum_cpu_workers": EXECUTION_MAXIMUM_CPU_THREADS,
            "logical_cpu_ids": list(EXECUTION_LOGICAL_CPU_IDS),
            "affinity_mask_hex": f"0x{EXECUTION_AFFINITY_MASK:08X}",
            "affinity_enforced_before_numpy_import": True,
            "thread_environment_variables": list(EXECUTION_THREAD_ENVIRONMENT),
            "thread_environment_minimum": 1,
            "thread_environment_maximum": EXECUTION_MAXIMUM_CPU_THREADS,
            "gpu": "sealed_off",
            "gpu_environment": dict(EXECUTION_GPU_ENVIRONMENT),
            "determinism_comparison": {
                "name": (f"serial-vs-{DETERMINISM_PARALLEL_OUTER_JOBS}"),
                "serial_outer_jobs": DETERMINISM_SERIAL_OUTER_JOBS,
                "parallel_outer_jobs": DETERMINISM_PARALLEL_OUTER_JOBS,
                "bit_exact_required": True,
            },
        },
    }
    return _seal_payload(payload, "policy_config_sha256")


def _verify_promotion_policy_config(payload: Any, *, context: str) -> None:
    if not isinstance(payload, Mapping):
        raise ValidationError(f"{context} prospective promotion policy is missing")
    _verify_sealed(payload, "policy_config_sha256", context=f"{context} policy config")
    if dict(payload) != _promotion_policy_config():
        raise ValidationError(
            f"{context} prospective promotion policy differs; use a new output directory"
        )


def _promotion_policy_lock_contract(
    args: argparse.Namespace,
    candidates: Mapping[str, Mapping[str, Any]],
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    spent = list(SPENT_EVIDENCE_SEEDS)
    reservation_contract = _spent_seed_reservation_contract(args, candidates, snapshot)
    reservation_receipt = getattr(args, "spent_seed_reservation", None)
    _verify_spent_seed_reservation_receipt(
        reservation_receipt,
        expected_contract=reservation_contract,
    )
    return {
        "format_version": PROMOTION_POLICY_FORMAT_VERSION,
        "harness_version": HARNESS_VERSION,
        "created_at_utc": _utc_now(),
        "prospective_only": True,
        "retroactive_reclassification_forbidden": True,
        "policy_config": _promotion_policy_config(),
        "source_config_sha256": snapshot["combined_sha256"],
        "candidates_sha256": hashlib.sha256(_canonical_json_bytes(candidates)).hexdigest(),
        "tuning_seeds": list(args.tuning_seeds),
        "locked_seeds": list(args.locked_seeds),
        "tuning_seed_commitment_sha256": hashlib.sha256(
            _canonical_json_bytes({"tuning_seeds": list(args.tuning_seeds)})
        ).hexdigest(),
        "locked_seed_commitment_sha256": hashlib.sha256(
            _canonical_json_bytes({"locked_seeds": list(args.locked_seeds)})
        ).hexdigest(),
        "spent_evidence_seeds": spent,
        "spent_evidence_seed_registry_sha256": hashlib.sha256(
            _canonical_json_bytes({"spent_evidence_seeds": spent})
        ).hexdigest(),
        "spent_seed_reservation": copy.deepcopy(dict(reservation_receipt)),
    }


def _policy_lock_comparable(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in {"created_at_utc", "policy_lock_sha256"}
    }


def _load_or_create_promotion_policy_lock(
    path: Path,
    contract: Mapping[str, Any],
    *,
    allow_create: bool,
) -> dict[str, Any]:
    if path.exists():
        policy_lock = _read_json(path)
        _verify_sealed(policy_lock, "policy_lock_sha256", context="promotion policy lock")
        if (
            policy_lock.get("format_version") != PROMOTION_POLICY_FORMAT_VERSION
            or policy_lock.get("harness_version") != HARNESS_VERSION
            or _policy_lock_comparable(policy_lock) != _policy_lock_comparable(contract)
        ):
            raise ValidationError(
                "promotion policy lock is incompatible; use a new output directory"
            )
        _verify_promotion_policy_config(
            policy_lock.get("policy_config"), context="promotion policy lock"
        )
        return policy_lock
    if not allow_create:
        raise ValidationError("tune must create promotion_policy.lock.json before lock/holdout")
    if path.parent.exists() and any(path.parent.iterdir()):
        raise ValidationError(
            "prospective policy requires a new empty output directory; existing artifacts "
            "cannot be reclassified"
        )
    sealed = _seal_payload(contract, "policy_lock_sha256")
    _atomic_write_json(path, sealed)
    return sealed


def _atomic_write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = _atomic_temp_path(path, os.getpid())
    temporary.write_text(
        json.dumps(_jsonable(payload), ensure_ascii=False, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationError(f"JSON object required: {path}")
    return payload


def _spent_registry_genesis_payload() -> dict[str, Any]:
    baseline = list(SPENT_EVIDENCE_SEEDS)
    return {
        "format_version": SPENT_SEED_REGISTRY_FORMAT_VERSION,
        "registry_id": SPENT_SEED_REGISTRY_ID,
        "baseline_spent_evidence_seeds": baseline,
        "baseline_spent_evidence_seed_sha256": hashlib.sha256(
            _canonical_json_bytes({"spent_evidence_seeds": baseline})
        ).hexdigest(),
    }


def _spent_registry_genesis_sha256() -> str:
    return hashlib.sha256(_canonical_json_bytes(_spent_registry_genesis_payload())).hexdigest()


def _new_spent_seed_registry() -> dict[str, Any]:
    payload = {
        **_spent_registry_genesis_payload(),
        "genesis_sha256": _spent_registry_genesis_sha256(),
        "entries": [],
        "updated_at_utc": _utc_now(),
    }
    return _seal_payload(payload, "registry_sha256")


_RESERVATION_CONTRACT_KEYS = (
    "format_version",
    "registry_id",
    "owner_output_root",
    "source_config_sha256",
    "candidates_sha256",
    "policy_config_sha256",
    "tuning_seeds",
    "locked_seeds",
    "reserved_seeds",
)


def _reservation_contract_from_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {key: copy.deepcopy(entry[key]) for key in _RESERVATION_CONTRACT_KEYS}
    except KeyError as exc:
        raise ValidationError("spent-seed registry entry lacks its reservation contract") from exc


def _reservation_id(contract: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json_bytes(dict(contract))).hexdigest()


def _canonical_output_root(path: Path) -> str:
    return os.path.normcase(str(Path(path).resolve()))


def _require_managed_output_root(path: Path) -> Path:
    """Confine prospective evidence to the repository-wide anchor search tree.

    The spent-seed ledger is fail-closed after accidental deletion only when every
    surviving policy lock is discoverable below ``PROJECT_ROOT/outputs``.  Resolve
    both sides first so ``..`` traversal and symlink/junction escapes cannot place
    a committed run outside that tree.
    """

    managed_root = (PROJECT_ROOT / "outputs").resolve()
    output_root = Path(path).resolve()
    if output_root == managed_root:
        raise ValidationError(
            "prospective output_root must be a dedicated directory below "
            f"{managed_root}, not the managed outputs directory itself"
        )
    try:
        output_root.relative_to(managed_root)
    except ValueError as exc:
        raise ValidationError(
            "prospective output_root must resolve below the repository-managed "
            f"anchor tree {managed_root}; got {output_root}"
        ) from exc

    ledger_path = (managed_root / SPENT_SEED_REGISTRY_PATH.name).resolve()
    if output_root == ledger_path or ledger_path in output_root.parents:
        raise ValidationError(
            "prospective output_root cannot be the reserved spent-seed ledger path "
            f"or one of its descendants: {ledger_path}"
        )

    if os.path.lexists(managed_root) and not managed_root.is_dir():
        raise ValidationError(
            f"prospective managed outputs anchor is not a directory: {managed_root}"
        )
    cursor = output_root
    while cursor != managed_root:
        if os.path.lexists(cursor) and not cursor.is_dir():
            raise ValidationError(
                "prospective output_root contains an existing non-directory path "
                f"component: {cursor}"
            )
        cursor = cursor.parent
    return output_root


def _spent_seed_reservation_contract(
    args: argparse.Namespace,
    candidates: Mapping[str, Mapping[str, Any]],
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    tuning = [int(seed) for seed in args.tuning_seeds]
    locked = [int(seed) for seed in args.locked_seeds]
    return {
        "format_version": SPENT_SEED_REGISTRY_FORMAT_VERSION,
        "registry_id": SPENT_SEED_REGISTRY_ID,
        "owner_output_root": _canonical_output_root(Path(args.output_root)),
        "source_config_sha256": str(snapshot["combined_sha256"]),
        "candidates_sha256": hashlib.sha256(_canonical_json_bytes(candidates)).hexdigest(),
        "policy_config_sha256": _promotion_policy_config()["policy_config_sha256"],
        "tuning_seeds": tuning,
        "locked_seeds": locked,
        "reserved_seeds": sorted(set(tuning).union(locked)),
    }


def _verify_reservation_contract(contract: Mapping[str, Any]) -> None:
    if set(contract) != set(_RESERVATION_CONTRACT_KEYS):
        raise ValidationError("spent-seed reservation contract schema is invalid")
    if (
        contract.get("format_version") != SPENT_SEED_REGISTRY_FORMAT_VERSION
        or contract.get("registry_id") != SPENT_SEED_REGISTRY_ID
        or not isinstance(contract.get("owner_output_root"), str)
        or not contract.get("owner_output_root")
    ):
        raise ValidationError("spent-seed reservation identity is invalid")
    for name in ("source_config_sha256", "candidates_sha256", "policy_config_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(contract.get(name, ""))):
            raise ValidationError(f"spent-seed reservation {name} is invalid")
    try:
        tuning = tuple(int(seed) for seed in contract["tuning_seeds"])
        locked = tuple(int(seed) for seed in contract["locked_seeds"])
        reserved = [int(seed) for seed in contract["reserved_seeds"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("spent-seed reservation seed lists are invalid") from exc
    validate_seed_design(tuning, locked)
    if reserved != sorted(set(tuning).union(locked)):
        raise ValidationError("spent-seed reservation union is invalid")


def _verify_spent_seed_registry(payload: Mapping[str, Any]) -> None:
    expected_keys = {
        *set(_spent_registry_genesis_payload()),
        "genesis_sha256",
        "entries",
        "updated_at_utc",
        "registry_sha256",
    }
    if set(payload) != expected_keys:
        raise ValidationError("spent-seed registry schema is invalid")
    _verify_sealed(payload, "registry_sha256", context="spent-seed registry")
    genesis = _spent_registry_genesis_payload()
    if any(payload.get(key) != value for key, value in genesis.items()):
        raise ValidationError("spent-seed registry genesis differs from code-owned history")
    expected_previous = _spent_registry_genesis_sha256()
    if payload.get("genesis_sha256") != expected_previous:
        raise ValidationError("spent-seed registry genesis hash is invalid")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise ValidationError("spent-seed registry entries must be a list")
    seen = set(SPENT_EVIDENCE_SEEDS)
    owners: set[str] = set()
    reservation_ids: set[str] = set()
    expected_entry_keys = {
        *_RESERVATION_CONTRACT_KEYS,
        "sequence",
        "previous_entry_sha256",
        "reservation_id",
        "created_at_utc",
        "entry_sha256",
    }
    for sequence, entry in enumerate(entries, start=1):
        if not isinstance(entry, Mapping) or set(entry) != expected_entry_keys:
            raise ValidationError("spent-seed registry entry schema is invalid")
        _verify_sealed(entry, "entry_sha256", context="spent-seed registry entry")
        contract = _reservation_contract_from_entry(entry)
        _verify_reservation_contract(contract)
        reservation_id = _reservation_id(contract)
        owner = str(contract["owner_output_root"])
        reserved = set(int(seed) for seed in contract["reserved_seeds"])
        if (
            int(entry.get("sequence", -1)) != sequence
            or entry.get("previous_entry_sha256") != expected_previous
            or entry.get("reservation_id") != reservation_id
            or not isinstance(entry.get("created_at_utc"), str)
            or not entry.get("created_at_utc")
        ):
            raise ValidationError("spent-seed registry hash chain is invalid")
        if owner in owners or reservation_id in reservation_ids:
            raise ValidationError("spent-seed registry contains a duplicate owner/reservation")
        overlap = sorted(seen.intersection(reserved))
        if overlap:
            raise ValidationError(f"spent-seed registry reuses prior evidence: {overlap}")
        owners.add(owner)
        reservation_ids.add(reservation_id)
        seen.update(reserved)
        expected_previous = str(entry["entry_sha256"])


def _read_spent_seed_registry(path: Path) -> dict[str, Any]:
    try:
        payload = _read_json(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValidationError(f"spent-seed registry is unreadable: {path}") from exc
    _verify_spent_seed_registry(payload)
    return payload


def _spent_registry_has_external_anchor(path: Path) -> bool:
    outputs = PROJECT_ROOT / "outputs"
    if not outputs.is_dir():
        return False
    target = _canonical_output_root(path)
    for policy_path in outputs.rglob("promotion_policy.lock.json"):
        try:
            payload = json.loads(policy_path.read_text(encoding="utf-8"))
            receipt = payload.get("spent_seed_reservation", {})
        except (OSError, ValueError, AttributeError):
            continue
        if (
            isinstance(receipt, Mapping)
            and os.path.normcase(str(receipt.get("registry_path", ""))) == target
        ):
            return True
    return False


def _acquire_spent_registry_lock(path: Path) -> tuple[int, Path]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f"{path.name}.lock")
    try:
        descriptor = os.open(
            lock_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise ValidationError(
            f"spent-seed registry is locked; fail closed until audited: {lock_path}"
        ) from exc
    try:
        os.write(descriptor, f"pid={os.getpid()} utc={_utc_now()}\n".encode("utf-8"))
        os.fsync(descriptor)
    except Exception:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)
        raise
    return descriptor, lock_path


def _release_spent_registry_lock(descriptor: int, lock_path: Path) -> None:
    os.close(descriptor)
    lock_path.unlink(missing_ok=True)


def _spent_seed_reservation_receipt(path: Path, entry: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "format_version": SPENT_SEED_REGISTRY_FORMAT_VERSION,
        "registry_id": SPENT_SEED_REGISTRY_ID,
        "registry_path": str(path.resolve()),
        "genesis_sha256": _spent_registry_genesis_sha256(),
        "reservation_id": str(entry["reservation_id"]),
        "reservation_sequence": int(entry["sequence"]),
        "reservation_entry_sha256": str(entry["entry_sha256"]),
    }


def _reserve_or_verify_spent_seeds(
    path: Path,
    contract: Mapping[str, Any],
    *,
    allow_create: bool,
) -> dict[str, Any]:
    path = Path(path).resolve()
    contract = copy.deepcopy(dict(contract))
    _verify_reservation_contract(contract)
    wanted_id = _reservation_id(contract)
    descriptor, lock_path = _acquire_spent_registry_lock(path)
    try:
        if path.exists():
            registry = _read_spent_seed_registry(path)
        else:
            if not allow_create:
                raise ValidationError("tune must reserve seeds before lock/holdout")
            if _spent_registry_has_external_anchor(path):
                raise ValidationError(
                    "spent-seed registry is missing despite an existing policy anchor"
                )
            registry = _new_spent_seed_registry()

        for entry in registry["entries"]:
            existing_contract = _reservation_contract_from_entry(entry)
            if entry["reservation_id"] == wanted_id:
                if existing_contract != contract:
                    raise ValidationError("spent-seed reservation hash collision")
                return _spent_seed_reservation_receipt(path, entry)
            if existing_contract["owner_output_root"] == contract["owner_output_root"]:
                raise ValidationError("output root already owns a different spent-seed reservation")

        if not allow_create:
            raise ValidationError("this run has no spent-seed reservation")
        spent = set(SPENT_EVIDENCE_SEEDS)
        for entry in registry["entries"]:
            spent.update(int(seed) for seed in entry["reserved_seeds"])
        overlap = sorted(spent.intersection(int(seed) for seed in contract["reserved_seeds"]))
        if overlap:
            raise ValidationError(
                f"prospective seeds are already reserved/spent in another run: {overlap}"
            )
        previous = (
            registry["entries"][-1]["entry_sha256"]
            if registry["entries"]
            else registry["genesis_sha256"]
        )
        entry = _seal_payload(
            {
                **contract,
                "sequence": len(registry["entries"]) + 1,
                "previous_entry_sha256": previous,
                "reservation_id": wanted_id,
                "created_at_utc": _utc_now(),
            },
            "entry_sha256",
        )
        updated = copy.deepcopy(registry)
        updated["entries"].append(entry)
        updated["updated_at_utc"] = _utc_now()
        updated = _seal_payload(updated, "registry_sha256")
        _verify_spent_seed_registry(updated)
        _atomic_write_json(path, updated)
        reloaded = _read_spent_seed_registry(path)
        if reloaded != updated:
            raise ValidationError("spent-seed registry changed on atomic round-trip")
        return _spent_seed_reservation_receipt(path, entry)
    finally:
        _release_spent_registry_lock(descriptor, lock_path)


def _verify_spent_seed_reservation_receipt(
    receipt: Any,
    *,
    expected_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "format_version",
        "registry_id",
        "registry_path",
        "genesis_sha256",
        "reservation_id",
        "reservation_sequence",
        "reservation_entry_sha256",
    }
    if not isinstance(receipt, Mapping) or set(receipt) != expected_keys:
        raise ValidationError("spent-seed reservation receipt is missing or invalid")
    if (
        receipt.get("format_version") != SPENT_SEED_REGISTRY_FORMAT_VERSION
        or receipt.get("registry_id") != SPENT_SEED_REGISTRY_ID
        or receipt.get("genesis_sha256") != _spent_registry_genesis_sha256()
    ):
        raise ValidationError("spent-seed reservation receipt version/genesis differs")
    path = Path(str(receipt["registry_path"])).resolve()
    registry = _read_spent_seed_registry(path)
    matches = [
        entry
        for entry in registry["entries"]
        if entry["reservation_id"] == receipt["reservation_id"]
    ]
    if len(matches) != 1:
        raise ValidationError("spent-seed reservation is absent from the global registry")
    entry = matches[0]
    if (
        int(receipt["reservation_sequence"]) != int(entry["sequence"])
        or receipt["reservation_entry_sha256"] != entry["entry_sha256"]
    ):
        raise ValidationError("spent-seed reservation receipt differs from the registry")
    actual_contract = _reservation_contract_from_entry(entry)
    if expected_contract is not None and actual_contract != dict(expected_contract):
        raise ValidationError("spent-seed reservation differs from this invocation")
    return actual_contract


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValidationError(f"artifact is missing: {path}")
    return {
        "format_version": ARTIFACT_FORMAT_VERSION,
        "path": str(path.resolve()),
        "bytes": int(path.stat().st_size),
        "sha256": _file_sha256(path),
    }


def _verify_artifact(record: Mapping[str, Any], *, context: str) -> Path:
    if not isinstance(record, Mapping):
        raise ValidationError(f"{context} artifact record is malformed")
    if record.get("format_version") != ARTIFACT_FORMAT_VERSION:
        raise ValidationError(f"{context} artifact format is incompatible")
    if set(record) != {"format_version", "path", "bytes", "sha256"}:
        raise ValidationError(f"{context} artifact schema differs")
    path = Path(str(record.get("path", "")))
    if not path.is_file():
        raise ValidationError(f"{context} artifact is missing: {path}")
    if int(record.get("bytes", -1)) != path.stat().st_size:
        raise ValidationError(f"{context} artifact size changed: {path}")
    if record.get("sha256") != _file_sha256(path):
        raise ValidationError(f"{context} artifact hash changed: {path}")
    return path


def _source_tree_record(root: Path) -> dict[str, Any]:
    root = root.resolve()
    candidates: list[Path] = []
    for directory in (root / "src", root / "config"):
        if directory.is_dir():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt"):
        path = root / name
        if path.is_file():
            candidates.append(path)
    files: dict[str, dict[str, Any]] = {}
    for path in sorted(set(candidates), key=lambda item: item.as_posix().lower()):
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        files[relative] = {
            "bytes": int(path.stat().st_size),
            "sha256": _file_sha256(path),
        }
    if not files:
        raise ValidationError(f"no source/config files found below {root}")
    digest = hashlib.sha256(_canonical_json_bytes(files)).hexdigest()
    return {"root": str(root), "files": files, "sha256": digest}


def source_snapshot(v03_root: Path, v04_root: Path) -> dict[str, Any]:
    snapshot = {
        "v03": _source_tree_record(v03_root),
        "v04": _source_tree_record(v04_root),
        "harness": _artifact(Path(__file__).resolve()),
    }
    snapshot["combined_sha256"] = hashlib.sha256(_canonical_json_bytes(snapshot)).hexdigest()
    return snapshot


def assert_source_snapshot(start: Mapping[str, Any]) -> None:
    current = source_snapshot(
        Path(str(start["v03"]["root"])),
        Path(str(start["v04"]["root"])),
    )
    if current != start:
        raise ValidationError(
            "source/config snapshot changed during or between validation stages; "
            "start a new output directory"
        )


def parse_seeds(text: str | Sequence[int]) -> tuple[int, ...]:
    raw = text.split(",") if isinstance(text, str) else list(text)
    try:
        seeds = tuple(int(value) for value in raw)
    except (TypeError, ValueError) as exc:
        raise ValidationError("seeds must be comma-separated integers") from exc
    if len(seeds) != len(set(seeds)):
        raise ValidationError("seed lists may not contain duplicates")
    if any(seed < 0 for seed in seeds):
        raise ValidationError("seeds must be non-negative")
    return seeds


def validate_seed_design(tuning_seeds: Sequence[int], locked_seeds: Sequence[int]) -> None:
    if len(tuning_seeds) != len(set(tuning_seeds)) or len(locked_seeds) != len(set(locked_seeds)):
        raise ValidationError("tuning and locked seed lists may not contain duplicates")
    if (
        len(tuning_seeds) < PROMOTION_MINIMUM_TUNING_SEEDS
        or len(locked_seeds) < PROMOTION_MINIMUM_LOCKED_SEEDS
    ):
        raise ValidationError(
            "prospective promotion requires at least five tuning and five locked seeds"
        )
    overlap = sorted(set(tuning_seeds).intersection(locked_seeds))
    if overlap:
        raise ValidationError(f"tuning and locked seeds overlap: {overlap}")
    spent = sorted(set(tuning_seeds).union(locked_seeds).intersection(SPENT_EVIDENCE_SEEDS))
    if spent:
        raise ValidationError(
            f"prospective tuning/locked seeds contain spent historical evidence: {spent}"
        )


def _deep_merge(base: Mapping[str, Any], overrides: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(dict(base))
    for key, value in overrides.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def load_candidates(path: Path | None) -> dict[str, dict[str, Any]]:
    payload: Any = copy.deepcopy(DEFAULT_CANDIDATES) if path is None else _read_json(path)
    if "candidates" in payload:
        payload = payload["candidates"]
    if not isinstance(payload, dict) or not payload:
        raise ValidationError("candidate JSON must contain a non-empty object")
    normalized: dict[str, dict[str, Any]] = {}
    for name, raw_spec in payload.items():
        if not isinstance(name, str) or not SAFE_NAME.fullmatch(name):
            raise ValidationError(f"unsafe candidate name: {name!r}")
        if not isinstance(raw_spec, Mapping):
            raise ValidationError(f"candidate {name!r} must be an object")
        unknown = set(raw_spec).difference({"overrides", "selection_column"})
        if unknown:
            if "incumbent_column" in unknown:
                raise ValidationError(
                    f"candidate {name!r} cannot choose incumbent_column; "
                    "both promotion comparators are code-owned"
                )
            raise ValidationError(f"candidate {name!r} has unknown keys: {sorted(unknown)}")
        overrides = raw_spec.get("overrides", {})
        if not isinstance(overrides, Mapping):
            raise ValidationError(f"candidate {name!r} overrides must be an object")
        selection = str(raw_spec.get("selection_column", "v04_expected_pe"))
        if not SAFE_NAME.fullmatch(selection):
            raise ValidationError(f"candidate {name!r} has unsafe column: {selection!r}")
        if selection not in PROMOTION_SELECTION_COLUMNS:
            raise ValidationError(
                f"candidate {name!r} selection_column is not a code-owned promotion "
                f"surface: {selection!r}"
            )
        normalized[name] = {
            "selection_column": selection,
            "overrides": copy.deepcopy(dict(overrides)),
        }
    return dict(sorted(normalized.items()))


def _positive_finite(series: pd.Series) -> np.ndarray:
    values = pd.to_numeric(series, errors="coerce").to_numpy(dtype=float)
    return np.isfinite(values) & (values > 0.0)


def _require_fair_truth(
    fair: pd.Series,
    *,
    scope_mask: np.ndarray | None = None,
    context: str,
) -> np.ndarray:
    available = _positive_finite(fair)
    if scope_mask is not None:
        scope = np.asarray(scope_mask, dtype=bool)
        if scope.shape != available.shape:
            raise ValidationError(f"{context} fair-truth scope has the wrong shape")
        available &= scope
    if not available.any():
        raise ValidationError(f"{context} synthetic true_fair_pe is unavailable")
    return available


def _fractional_degradation(baseline_loss: np.ndarray, challenger_loss: np.ndarray) -> np.ndarray:
    denominator = np.maximum(np.asarray(baseline_loss, dtype=float), 1e-15)
    return (np.asarray(challenger_loss, dtype=float) - baseline_loss) / denominator


def _mask_sha(mask: np.ndarray, dates: pd.Series) -> str:
    selected = pd.to_datetime(dates, errors="raise").astype("int64").to_numpy()[mask]
    digest = hashlib.sha256()
    digest.update(np.packbits(mask.astype(np.uint8)).tobytes())
    digest.update(selected.astype("<i8", copy=False).tobytes())
    return digest.hexdigest()


def paired_log_metrics(
    baseline: pd.Series,
    challenger: pd.Series,
    observed: pd.Series,
    fair: pd.Series,
    dates: pd.Series,
    *,
    forced_mask: np.ndarray | None = None,
) -> dict[str, Any]:
    """Evaluate fair promotion and observed diagnostics on explicit paired masks."""

    size = len(baseline)
    if not all(len(item) == size for item in (challenger, observed, fair, dates)):
        raise ValidationError("paired metric inputs have different lengths")
    base_values = pd.to_numeric(baseline, errors="coerce").to_numpy(dtype=float)
    challenger_values = pd.to_numeric(challenger, errors="coerce").to_numpy(dtype=float)
    observed_values = pd.to_numeric(observed, errors="coerce").to_numpy(dtype=float)
    fair_values = pd.to_numeric(fair, errors="coerce").to_numpy(dtype=float)
    prediction_valid = (
        np.isfinite(base_values)
        & (base_values > 0.0)
        & np.isfinite(challenger_values)
        & (challenger_values > 0.0)
    )
    scope = np.ones(size, dtype=bool)
    if forced_mask is not None:
        scope = np.asarray(forced_mask, dtype=bool)
        if scope.shape != prediction_valid.shape:
            raise ValidationError("forced paired mask has the wrong shape")
    fair_available = scope & np.isfinite(fair_values) & (fair_values > 0.0)
    if not fair_available.any():
        raise ValidationError("paired metric synthetic true_fair_pe is unavailable")
    common = prediction_valid & fair_available
    common_rows = int(common.sum())
    if common_rows == 0:
        raise ValidationError("paired finite-positive fair mask is empty")
    observed_common = common & np.isfinite(observed_values) & (observed_values > 0.0)
    if not observed_common.any():
        raise ValidationError("paired finite-positive observed diagnostic mask is empty")

    def losses(prediction: np.ndarray) -> dict[str, float]:
        fair_error = np.log(prediction[common] / fair_values[common])
        observed_error = np.log(prediction[observed_common] / observed_values[observed_common])
        return {
            "fair_log_mae": float(np.mean(np.abs(fair_error))),
            "fair_log_rmse": float(np.sqrt(np.mean(np.square(fair_error)))),
            "observed_log_mae": float(np.mean(np.abs(observed_error))),
            "observed_log_rmse": float(np.sqrt(np.mean(np.square(observed_error)))),
        }

    base_loss = losses(base_values)
    challenger_loss = losses(challenger_values)
    selected_dates = pd.to_datetime(dates, errors="raise").loc[common]
    return {
        "total_rows": int(size),
        "evaluation_scope_rows": int(scope.sum()),
        "common_rows": common_rows,
        "coverage": float(common_rows / scope.sum()) if scope.any() else 0.0,
        "mask_sha256": _mask_sha(common, dates),
        "promotion_mask_sha256": _mask_sha(common, dates),
        "diagnostic_common_rows": int(observed_common.sum()),
        "diagnostic_coverage": float(observed_common.sum() / scope.sum()) if scope.any() else 0.0,
        "diagnostic_mask_sha256": _mask_sha(observed_common, dates),
        "first_date": selected_dates.iloc[0].isoformat(),
        "last_date": selected_dates.iloc[-1].isoformat(),
        "baseline": base_loss,
        "challenger": challenger_loss,
        "gain": {key: float(base_loss[key] - challenger_loss[key]) for key in base_loss},
    }


def _date_index_sha256(dates: pd.Series) -> str:
    parsed = pd.to_datetime(dates, errors="raise")
    values = parsed.astype("int64").to_numpy(dtype="<i8", copy=False)
    return hashlib.sha256(values.tobytes()).hexdigest()


def _validate_promotion_daily_evidence_frame(
    frame: pd.DataFrame,
    *,
    expected_seed: int,
    minimum_rows: int = PROMOTION_MINIMUM_COMMON_ROWS,
) -> dict[str, Any]:
    if tuple(frame.columns) != PROMOTION_DAILY_EVIDENCE_COLUMNS:
        raise ValidationError("promotion daily paired evidence schema is invalid")
    if len(frame) < int(minimum_rows):
        raise ValidationError(
            "promotion daily paired evidence has too few common rows: "
            f"{len(frame)} < {int(minimum_rows)}"
        )
    seeds = pd.to_numeric(frame["seed"], errors="coerce").to_numpy(dtype=float)
    if not np.isfinite(seeds).all() or not np.equal(seeds, float(expected_seed)).all():
        raise ValidationError("promotion daily paired evidence seed is mismatched")
    dates = pd.to_datetime(frame["date"], errors="raise")
    if dates.duplicated().any() or not dates.is_monotonic_increasing:
        raise ValidationError("promotion daily paired evidence dates must be unique/increasing")
    for column in (
        "true_fair_pe",
        "primary_v04_expected_pe",
        "anti_ml_expected_pe",
        "challenger_pe",
    ):
        values = pd.to_numeric(frame[column], errors="coerce").to_numpy(dtype=float)
        if not np.isfinite(values).all() or np.any(values <= 0.0):
            raise ValidationError(
                f"promotion daily paired evidence {column} must be finite and positive"
            )
    observed_source = frame["observed_pe"]
    observed = pd.to_numeric(observed_source, errors="coerce").to_numpy(dtype=float)
    observed_valid = np.isfinite(observed) & (observed > 0.0)
    if (
        (observed_source.notna().to_numpy(dtype=bool) & np.isnan(observed)).any()
        or np.any(np.isfinite(observed) & (observed <= 0.0))
        or np.isinf(observed).any()
    ):
        raise ValidationError(
            "promotion daily paired evidence observed_pe must be positive or missing"
        )
    if not observed_valid.any():
        raise ValidationError("promotion daily paired evidence has no observed diagnostics")
    return {
        "format_version": ARTIFACT_FORMAT_VERSION,
        "seed": int(expected_seed),
        "rows": int(len(frame)),
        "coverage": 1.0,
        "observed_diagnostic_rows": int(observed_valid.sum()),
        "first_date": dates.iloc[0].isoformat(),
        "last_date": dates.iloc[-1].isoformat(),
        "date_index_sha256": _date_index_sha256(frame["date"]),
        "columns": list(PROMOTION_DAILY_EVIDENCE_COLUMNS),
        "columns_sha256": hashlib.sha256(
            _canonical_json_bytes({"columns": list(PROMOTION_DAILY_EVIDENCE_COLUMNS)})
        ).hexdigest(),
    }


def _write_promotion_daily_evidence(
    *,
    output_path: Path,
    truth_path: Path,
    candidate: Mapping[str, Any],
    seed: int,
    evidence_path: Path,
) -> dict[str, Any]:
    output = _read_csv(output_path)
    truth = _read_csv(truth_path)
    aligned = _align_truth(output, truth)
    dates = pd.to_datetime(output["date"], errors="raise")
    scope = dates.ge(PRODUCTION_EVALUATION_START).to_numpy(dtype=bool)
    if not scope.any():
        raise ValidationError("promotion daily paired evidence scope is empty")
    selection = str(candidate["selection_column"])
    required_columns = {selection, *PROMOTION_COMPARATORS.values()}
    missing = required_columns.difference(output.columns)
    if missing:
        raise ValidationError(f"promotion evidence misses columns: {sorted(missing)}")
    fair_values = pd.to_numeric(aligned["true_fair_pe"], errors="coerce")
    common = scope & _positive_finite(fair_values)
    for column in (*PROMOTION_COMPARATORS.values(), selection):
        common &= _positive_finite(output[column])
    if not np.array_equal(common, scope):
        missing_rows = int(scope.sum() - common.sum())
        raise ValidationError(
            "promotion dual-comparator common mask lacks full natural daily coverage: "
            f"{missing_rows} row(s)"
        )
    evidence = pd.DataFrame(
        {
            "seed": np.full(int(common.sum()), int(seed), dtype=np.int64),
            "date": dates.loc[common].dt.strftime("%Y-%m-%d").to_numpy(),
            "true_fair_pe": fair_values.loc[common].to_numpy(dtype=float),
            "observed_pe": pd.to_numeric(
                output.loc[common, "observed_pe"], errors="coerce"
            ).to_numpy(dtype=float),
            "primary_v04_expected_pe": pd.to_numeric(
                output.loc[common, PROMOTION_PRIMARY_COMPARATOR_COLUMN], errors="coerce"
            ).to_numpy(dtype=float),
            "anti_ml_expected_pe": pd.to_numeric(
                output.loc[common, PROMOTION_ANTI_GAMING_COMPARATOR_COLUMN], errors="coerce"
            ).to_numpy(dtype=float),
            "challenger_pe": pd.to_numeric(output.loc[common, selection], errors="coerce").to_numpy(
                dtype=float
            ),
        },
        columns=list(PROMOTION_DAILY_EVIDENCE_COLUMNS),
    )
    metadata = _validate_promotion_daily_evidence_frame(
        evidence,
        expected_seed=int(seed),
    )
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence.to_csv(
        evidence_path,
        index=False,
        encoding="utf-8",
        float_format="%.17g",
        lineterminator="\n",
    )
    reloaded = _read_csv(evidence_path)
    reloaded_metadata = _validate_promotion_daily_evidence_frame(
        reloaded,
        expected_seed=int(seed),
    )
    if reloaded_metadata != metadata:
        raise ValidationError("promotion daily paired evidence changed on CSV round-trip")
    return {
        **metadata,
        "comparator_columns": copy.deepcopy(PROMOTION_COMPARATORS),
        "challenger_column": selection,
        "artifact": _artifact(evidence_path),
    }


def _load_promotion_daily_evidence(
    record: Mapping[str, Any],
    *,
    expected_seed: int,
    expected_challenger_column: str | None = None,
    minimum_rows: int = PROMOTION_MINIMUM_COMMON_ROWS,
) -> pd.DataFrame:
    if not isinstance(record, Mapping):
        raise ValidationError("candidate result is missing daily paired evidence")
    artifact = record.get("artifact")
    if not isinstance(artifact, Mapping):
        raise ValidationError("daily paired evidence artifact is missing")
    path = _verify_artifact(artifact, context="promotion daily paired evidence")
    frame = _read_csv(path)
    actual = _validate_promotion_daily_evidence_frame(
        frame,
        expected_seed=int(expected_seed),
        minimum_rows=int(minimum_rows),
    )
    expected_metadata = {
        **actual,
        "comparator_columns": copy.deepcopy(PROMOTION_COMPARATORS),
        "challenger_column": record.get("challenger_column"),
    }
    recorded = {key: value for key, value in record.items() if key != "artifact"}
    if recorded != expected_metadata:
        raise ValidationError("promotion daily paired evidence metadata differs")
    challenger_column = record.get("challenger_column")
    if (
        not isinstance(challenger_column, str)
        or challenger_column not in PROMOTION_SELECTION_COLUMNS
        or (
            expected_challenger_column is not None
            and challenger_column != expected_challenger_column
        )
    ):
        raise ValidationError("promotion daily paired evidence challenger column differs")
    return frame


def _aggregate_paired_seed_metrics(
    rows: Sequence[Mapping[str, Any]],
    *,
    tolerance_fraction: float,
) -> dict[str, Any]:
    """Aggregate all metrics while allowing only fair-truth metrics to decide."""

    if not rows:
        raise ValidationError("paired metric aggregation requires at least one seed")
    tolerance = float(tolerance_fraction)
    if not math.isfinite(tolerance) or tolerance < 0.0:
        raise ValidationError("paired metric tolerance must be finite and non-negative")
    aggregate: dict[str, Any] = {}
    worst_by_role: dict[str, float | None] = {
        "promotion": -math.inf,
        "diagnostic_only": -math.inf,
    }
    for metric in ALL_PAIRED_METRICS:
        try:
            baseline = np.asarray([row["baseline"][metric] for row in rows], dtype=float)
            challenger = np.asarray([row["challenger"][metric] for row in rows], dtype=float)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"paired metric {metric!r} is unavailable") from exc
        role = "promotion" if metric in PROMOTION_METRICS else "diagnostic_only"
        if (
            baseline.size != len(rows)
            or challenger.size != len(rows)
            or not np.isfinite(baseline).all()
            or not np.isfinite(challenger).all()
            or np.any(baseline < 0.0)
            or np.any(challenger < 0.0)
            or (role == "promotion" and np.any(baseline == 0.0))
        ):
            raise ValidationError(f"paired metric {metric!r} is invalid")
        baseline_mean = float(baseline.mean())
        challenger_mean = float(challenger.mean())
        absolute_gain = baseline_mean - challenger_mean
        relative_available = bool(np.all(baseline > 0.0))
        if relative_available:
            degradation = _fractional_degradation(baseline, challenger)
            relative_mean_gain: float | None = absolute_gain / baseline_mean
            metric_worst: float | None = float(degradation.max())
            per_seed_relative_gain: list[float] | None = [float(value) for value in -degradation]
        else:
            relative_mean_gain = None
            metric_worst = None
            per_seed_relative_gain = None
        aggregate[metric] = {
            "role": role,
            "baseline_mean": baseline_mean,
            "challenger_mean": challenger_mean,
            "mean_gain": absolute_gain,
            "relative_mean_gain": relative_mean_gain,
            "strict_seed_wins": int(np.sum(challenger < baseline)),
            "seed_wins_or_ties": int(np.sum(challenger <= baseline + 1e-15)),
            "worst_seed_degradation_fraction": metric_worst,
            "per_seed_relative_gain": per_seed_relative_gain,
        }
        if metric_worst is None:
            worst_by_role[role] = None
        elif worst_by_role[role] is not None:
            worst_by_role[role] = max(worst_by_role[role], metric_worst)
    promotion_worst = float(worst_by_role["promotion"])
    diagnostic_worst = worst_by_role["diagnostic_only"]
    return {
        "aggregate": aggregate,
        "empirical_no_harm_pass": promotion_worst <= tolerance + 1e-15,
        "worst_degradation_fraction_across_promotion_metrics": promotion_worst,
        "worst_degradation_fraction_across_diagnostic_only_metrics": (
            None if diagnostic_worst is None else float(diagnostic_worst)
        ),
    }


def _prospective_deterministic_gates(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if len(rows) < PROMOTION_MINIMUM_LOCKED_SEEDS:
        raise ValidationError("prospective promotion gates require at least five seeds")
    metric_arrays: dict[str, tuple[np.ndarray, np.ndarray]] = {}
    for metric in PROMOTION_METRICS:
        try:
            baseline = np.asarray([row["baseline"][metric] for row in rows], dtype=float)
            challenger = np.asarray([row["challenger"][metric] for row in rows], dtype=float)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"prospective metric {metric!r} is unavailable") from exc
        if (
            baseline.size != len(rows)
            or challenger.size != len(rows)
            or not np.isfinite(baseline).all()
            or not np.isfinite(challenger).all()
            or np.any(baseline <= 0.0)
            or np.any(challenger < 0.0)
        ):
            raise ValidationError(f"prospective metric {metric!r} is invalid")
        metric_arrays[metric] = baseline, challenger

    joint = np.ones(len(rows), dtype=bool)
    per_metric: dict[str, Any] = {}
    leave_one_out: list[dict[str, Any]] = []
    for metric, (baseline, challenger) in metric_arrays.items():
        relative_gain = (baseline - challenger) / baseline
        joint &= relative_gain > 0.0
        pooled_gain = float((baseline.mean() - challenger.mean()) / baseline.mean())
        worst_degradation = float(np.max(-relative_gain))
        per_metric[metric] = {
            "relative_pooled_gain": pooled_gain,
            "strict_seed_wins": int(np.sum(relative_gain > 0.0)),
            "worst_seed_degradation_fraction": worst_degradation,
            "practical_margin": PROMOTION_PRACTICAL_GAIN,
            "practical_margin_pass": pooled_gain >= PROMOTION_PRACTICAL_GAIN,
            "material_harm_cap": PROMOTION_WORST_SEED_DEGRADATION_CAP,
            "material_harm_cap_pass": (worst_degradation <= PROMOTION_WORST_SEED_DEGRADATION_CAP),
        }

    for omitted in range(len(rows)):
        keep = np.ones(len(rows), dtype=bool)
        keep[omitted] = False
        gains: dict[str, float] = {}
        for metric, (baseline, challenger) in metric_arrays.items():
            gains[metric] = float(
                (baseline[keep].mean() - challenger[keep].mean()) / baseline[keep].mean()
            )
        try:
            omitted_seed = int(rows[omitted]["seed"])
        except (KeyError, TypeError, ValueError):
            omitted_seed = omitted
        leave_one_out.append(
            {
                "omitted_seed": omitted_seed,
                "relative_gain": gains,
                "pass": all(value > 0.0 for value in gains.values()),
            }
        )

    required_joint_wins = int(math.ceil(PROMOTION_JOINT_WIN_FRACTION * len(rows)))
    joint_wins = int(joint.sum())
    joint_pass = joint_wins >= required_joint_wins
    cap_pass = all(item["material_harm_cap_pass"] for item in per_metric.values())
    practical_pass = all(item["practical_margin_pass"] for item in per_metric.values())
    loo_pass = all(item["pass"] for item in leave_one_out)
    return {
        "seed_count": int(len(rows)),
        "joint_seed_wins": joint_wins,
        "required_joint_seed_wins": required_joint_wins,
        "joint_seed_win_pass": joint_pass,
        "per_metric": per_metric,
        "worst_seed_material_harm_pass": cap_pass,
        "pooled_practical_margin_pass": practical_pass,
        "leave_one_seed_out": leave_one_out,
        "leave_one_seed_out_pass": loo_pass,
        "pass": joint_pass and cap_pass and practical_pass and loo_pass,
    }


def _prepare_bootstrap_evidence(
    evidence_by_seed: Mapping[int, pd.DataFrame],
    *,
    minimum_rows: int = PROMOTION_MINIMUM_COMMON_ROWS,
) -> dict[str, Any]:
    if len(evidence_by_seed) < PROMOTION_MINIMUM_LOCKED_SEEDS:
        raise ValidationError("block bootstrap requires at least five seed clusters")
    seed_ids = tuple(sorted(int(seed) for seed in evidence_by_seed))
    date_values: np.ndarray | None = None
    fair_rows: list[np.ndarray] = []
    comparator_rows: dict[str, list[np.ndarray]] = {name: [] for name in PROMOTION_COMPARATORS}
    challenger_rows: list[np.ndarray] = []
    evidence_columns = {
        PROMOTION_PRIMARY_COMPARATOR: "primary_v04_expected_pe",
        PROMOTION_ANTI_GAMING_COMPARATOR: "anti_ml_expected_pe",
    }
    for seed in seed_ids:
        frame = evidence_by_seed[seed]
        _validate_promotion_daily_evidence_frame(
            frame,
            expected_seed=seed,
            minimum_rows=minimum_rows,
        )
        current_dates = pd.to_datetime(frame["date"], errors="raise").astype("int64").to_numpy()
        if date_values is None:
            date_values = current_dates
        elif not np.array_equal(date_values, current_dates):
            raise ValidationError("daily paired evidence date indexes differ across seed clusters")
        fair_rows.append(pd.to_numeric(frame["true_fair_pe"]).to_numpy(dtype=float))
        for comparator_name, evidence_column in evidence_columns.items():
            comparator_rows[comparator_name].append(
                pd.to_numeric(frame[evidence_column]).to_numpy(dtype=float)
            )
        challenger_rows.append(pd.to_numeric(frame["challenger_pe"]).to_numpy(dtype=float))
    assert date_values is not None
    fair = np.stack(fair_rows)
    challenger = np.stack(challenger_rows)
    challenger_error = np.log(challenger / fair)
    arrays: dict[str, dict[str, np.ndarray]] = {}
    for comparator_name in PROMOTION_COMPARATORS:
        comparator = np.stack(comparator_rows[comparator_name])
        comparator_error = np.log(comparator / fair)
        arrays[comparator_name] = {
            "mae_baseline": np.abs(comparator_error),
            "mae_challenger": np.abs(challenger_error),
            "rmse_baseline": np.square(comparator_error),
            "rmse_challenger": np.square(challenger_error),
        }
    if any(
        not np.isfinite(values).all()
        for comparator_arrays in arrays.values()
        for values in comparator_arrays.values()
    ):
        raise ValidationError("daily paired evidence produced non-finite losses")
    return {
        "seed_ids": seed_ids,
        "rows_per_seed": int(fair.shape[1]),
        "date_index_sha256": hashlib.sha256(
            date_values.astype("<i8", copy=False).tobytes()
        ).hexdigest(),
        "arrays": arrays,
    }


def _bootstrap_time_indices(
    rng: np.random.Generator,
    *,
    method: str,
    block_length: int,
    sample_count: int,
    rows: int,
) -> np.ndarray:
    if block_length <= 0 or rows < block_length:
        raise ValidationError("bootstrap block length is invalid for the evidence rows")
    if method == "moving_block":
        blocks = int(math.ceil(rows / block_length))
        starts = rng.integers(
            0,
            rows - block_length + 1,
            size=(sample_count, blocks),
            dtype=np.int64,
        )
        offsets = np.arange(block_length, dtype=np.int64)
        return (starts[:, :, None] + offsets).reshape(sample_count, -1)[:, :rows]
    if method == "stationary":
        restart = rng.random((sample_count, rows)) < (1.0 / block_length)
        restart[:, 0] = True
        fresh = rng.integers(0, rows, size=(sample_count, rows), dtype=np.int64)
        positions = np.arange(rows, dtype=np.int64)[None, :]
        last_restart = np.maximum.accumulate(
            np.where(restart, positions, 0),
            axis=1,
        )
        starts = np.take_along_axis(fresh, last_restart, axis=1)
        return (starts + positions - last_restart) % rows
    raise ValidationError(f"unknown bootstrap method: {method!r}")


def _bootstrap_cell_relative_gains(
    arrays: Mapping[str, Mapping[str, np.ndarray]],
    *,
    method: str,
    block_length: int,
    iterations: int,
    stream_seed: int,
    chunk_size: int,
) -> dict[str, dict[str, np.ndarray]]:
    if iterations <= 0 or chunk_size <= 0:
        raise ValidationError("bootstrap iterations/chunk size must be positive")
    if set(arrays) != set(PROMOTION_COMPARATORS):
        raise ValidationError("bootstrap evidence comparator set differs")
    mae_baseline = np.asarray(arrays[PROMOTION_PRIMARY_COMPARATOR]["mae_baseline"], dtype=float)
    shape = mae_baseline.shape
    if len(shape) != 2 or shape[0] < PROMOTION_MINIMUM_LOCKED_SEEDS:
        raise ValidationError("bootstrap evidence matrix has an invalid shape")
    for comparator_name, comparator_arrays in arrays.items():
        expected_names = {
            "mae_baseline",
            "mae_challenger",
            "rmse_baseline",
            "rmse_challenger",
        }
        if set(comparator_arrays) != expected_names:
            raise ValidationError(
                f"bootstrap evidence arrays differ for comparator {comparator_name!r}"
            )
        for name, values in comparator_arrays.items():
            if np.asarray(values).shape != shape:
                raise ValidationError(
                    f"bootstrap evidence array {comparator_name!r}/{name!r} shape differs"
                )
    seed_clusters, rows = shape
    rng = np.random.Generator(np.random.PCG64DXSM(stream_seed))
    result = {
        comparator_name: {
            metric: np.empty(iterations, dtype=np.float64) for metric in PROMOTION_METRICS
        }
        for comparator_name in PROMOTION_COMPARATORS
    }

    def sampled_loss(
        values: np.ndarray,
        cluster_indices: np.ndarray,
        time_indices: np.ndarray,
        *,
        root: bool,
    ) -> np.ndarray:
        selected = values[cluster_indices[:, :, None], time_indices[:, None, :]]
        per_cluster = selected.mean(axis=2)
        if root:
            per_cluster = np.sqrt(per_cluster)
        return per_cluster.mean(axis=1)

    for start in range(0, iterations, chunk_size):
        stop = min(start + chunk_size, iterations)
        count = stop - start
        cluster_indices = rng.integers(
            0,
            seed_clusters,
            size=(count, seed_clusters),
            dtype=np.int64,
        )
        time_indices = _bootstrap_time_indices(
            rng,
            method=method,
            block_length=block_length,
            sample_count=count,
            rows=rows,
        )
        for comparator_name, comparator_arrays in arrays.items():
            for metric, root in (("fair_log_mae", False), ("fair_log_rmse", True)):
                prefix = "mae" if metric == "fair_log_mae" else "rmse"
                baseline_loss = sampled_loss(
                    np.asarray(comparator_arrays[f"{prefix}_baseline"]),
                    cluster_indices,
                    time_indices,
                    root=root,
                )
                challenger_loss = sampled_loss(
                    np.asarray(comparator_arrays[f"{prefix}_challenger"]),
                    cluster_indices,
                    time_indices,
                    root=root,
                )
                if np.any(baseline_loss <= 0.0):
                    raise ValidationError(
                        f"bootstrap {comparator_name} baseline loss is non-positive"
                    )
                result[comparator_name][metric][start:stop] = (
                    baseline_loss - challenger_loss
                ) / baseline_loss
    if any(
        not np.isfinite(values).all()
        for comparator_gains in result.values()
        for values in comparator_gains.values()
    ):
        raise ValidationError("bootstrap produced non-finite relative gains")
    return result


def _promotion_block_bootstrap(
    evidence_by_seed: Mapping[int, pd.DataFrame],
    *,
    policy_config: Mapping[str, Any],
) -> dict[str, Any]:
    _verify_promotion_policy_config(policy_config, context="block bootstrap")
    evidence = _prepare_bootstrap_evidence(evidence_by_seed)
    bootstrap = policy_config["bootstrap"]
    iterations = int(bootstrap["iterations"])
    chunk_size = int(bootstrap["chunk_size"])
    alpha = float(bootstrap["comparator_metric_alpha_bonferroni"])
    quantile_probabilities = (0.01, alpha, 0.025, 0.05, 0.5, 0.95, 0.975, 0.99)
    cells: list[dict[str, Any]] = []
    minimum_lcb = {
        comparator_name: {metric: math.inf for metric in PROMOTION_METRICS}
        for comparator_name in PROMOTION_COMPARATORS
    }
    all_pass = True
    for method in bootstrap["methods"]:
        for block_length_raw in bootstrap["block_lengths"]:
            block_length = int(block_length_raw)
            stream_text = (
                f"{PROMOTION_POLICY_ID}|{int(bootstrap['master_seed'])}|{method}|{block_length}"
            )
            stream_digest = hashlib.sha256(stream_text.encode("utf-8")).digest()
            stream_seed = int.from_bytes(stream_digest[:16], "little", signed=False)
            gains = _bootstrap_cell_relative_gains(
                evidence["arrays"],
                method=str(method),
                block_length=block_length,
                iterations=iterations,
                stream_seed=stream_seed,
                chunk_size=chunk_size,
            )
            for comparator_name, comparator_column in PROMOTION_COMPARATORS.items():
                for metric in PROMOTION_METRICS:
                    values = gains[comparator_name][metric]
                    quantiles = np.quantile(
                        values,
                        quantile_probabilities,
                        method=PROMOTION_BOOTSTRAP_QUANTILE_METHOD,
                    )
                    lcb = float(quantiles[1])
                    passed = lcb > 0.0
                    all_pass = all_pass and passed
                    minimum_lcb[comparator_name][metric] = min(
                        minimum_lcb[comparator_name][metric], lcb
                    )
                    cells.append(
                        {
                            "comparator": comparator_name,
                            "comparator_column": comparator_column,
                            "method": str(method),
                            "block_length": block_length,
                            "metric": metric,
                            "iterations": iterations,
                            "comparator_metric_alpha_bonferroni": alpha,
                            "stream_key_sha256": stream_digest.hex(),
                            "replicate_sha256": hashlib.sha256(
                                values.astype("<f8", copy=False).tobytes()
                            ).hexdigest(),
                            "quantiles": {
                                "q01": float(quantiles[0]),
                                "q0125": lcb,
                                "q025": float(quantiles[2]),
                                "q05": float(quantiles[3]),
                                "q50": float(quantiles[4]),
                                "q95": float(quantiles[5]),
                                "q975": float(quantiles[6]),
                                "q99": float(quantiles[7]),
                            },
                            "simultaneous_lcb": lcb,
                            "lcb_pass": passed,
                        }
                    )
    expected_cells = (
        len(PROMOTION_COMPARATORS)
        * len(PROMOTION_METRICS)
        * len(PROMOTION_BOOTSTRAP_METHODS)
        * len(PROMOTION_BOOTSTRAP_BLOCK_LENGTHS)
    )
    if len(cells) != expected_cells:
        raise ValidationError("block bootstrap cell count is incomplete")
    config_sha256 = str(policy_config["policy_config_sha256"])
    payload = {
        "format_version": REPORT_FORMAT_VERSION,
        "policy_config_sha256": config_sha256,
        "comparators": copy.deepcopy(PROMOTION_COMPARATORS),
        "seed_ids": list(evidence["seed_ids"]),
        "seed_clusters": int(len(evidence["seed_ids"])),
        "rows_per_seed": int(evidence["rows_per_seed"]),
        "date_index_sha256": evidence["date_index_sha256"],
        "iterations_per_cell": iterations,
        "expected_cells": expected_cells,
        "cells": cells,
        "minimum_simultaneous_lcb": minimum_lcb,
        "pass": bool(all_pass),
    }
    payload["cells_sha256"] = hashlib.sha256(_canonical_json_bytes({"cells": cells})).hexdigest()
    return _seal_payload(payload, "bootstrap_sha256")


def _verify_promotion_block_bootstrap_summary(
    payload: Any,
    *,
    policy_config: Mapping[str, Any],
    context: str,
) -> None:
    _verify_promotion_policy_config(policy_config, context=context)
    if not isinstance(payload, Mapping):
        raise ValidationError(f"{context} block-bootstrap summary is missing")
    _verify_sealed(payload, "bootstrap_sha256", context=f"{context} block-bootstrap summary")
    expected_payload_keys = {
        "format_version",
        "policy_config_sha256",
        "comparators",
        "seed_ids",
        "seed_clusters",
        "rows_per_seed",
        "date_index_sha256",
        "iterations_per_cell",
        "expected_cells",
        "cells",
        "minimum_simultaneous_lcb",
        "pass",
        "cells_sha256",
        "bootstrap_sha256",
    }
    if set(payload) != expected_payload_keys:
        raise ValidationError(f"{context} block-bootstrap summary schema differs")
    bootstrap = policy_config["bootstrap"]
    expected_combinations = {
        (comparator, str(method), int(block_length), metric)
        for comparator in PROMOTION_COMPARATORS
        for method in bootstrap["methods"]
        for block_length in bootstrap["block_lengths"]
        for metric in PROMOTION_METRICS
    }
    cells = payload.get("cells")
    if not isinstance(cells, list) or len(cells) != len(expected_combinations):
        raise ValidationError(f"{context} must contain all 24 bootstrap LCB cells")
    expected_cells_sha256 = hashlib.sha256(_canonical_json_bytes({"cells": cells})).hexdigest()
    if payload.get("cells_sha256") != expected_cells_sha256:
        raise ValidationError(f"{context} bootstrap cell hash differs")
    actual_combinations: set[tuple[str, str, int, str]] = set()
    cell_passes: list[bool] = []
    recomputed_minimum = {
        comparator_name: {metric: math.inf for metric in PROMOTION_METRICS}
        for comparator_name in PROMOTION_COMPARATORS
    }
    for cell in cells:
        if not isinstance(cell, Mapping):
            raise ValidationError(f"{context} contains a malformed bootstrap cell")
        if set(cell) != {
            "comparator",
            "comparator_column",
            "method",
            "block_length",
            "metric",
            "iterations",
            "comparator_metric_alpha_bonferroni",
            "stream_key_sha256",
            "replicate_sha256",
            "quantiles",
            "simultaneous_lcb",
            "lcb_pass",
        }:
            raise ValidationError(f"{context} bootstrap cell schema differs")
        try:
            combination = (
                str(cell["comparator"]),
                str(cell["method"]),
                int(cell["block_length"]),
                str(cell["metric"]),
            )
            iterations = int(cell["iterations"])
            alpha = float(cell["comparator_metric_alpha_bonferroni"])
            lcb = float(cell["simultaneous_lcb"])
            quantiles = cell["quantiles"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError(f"{context} contains an invalid bootstrap cell") from exc
        if combination in actual_combinations:
            raise ValidationError(f"{context} contains a duplicate bootstrap cell")
        actual_combinations.add(combination)
        expected_stream_text = (
            f"{PROMOTION_POLICY_ID}|{int(bootstrap['master_seed'])}|"
            f"{combination[1]}|{combination[2]}"
        )
        expected_stream_sha256 = hashlib.sha256(expected_stream_text.encode("utf-8")).hexdigest()
        if not isinstance(quantiles, Mapping) or set(quantiles) != {
            "q01",
            "q0125",
            "q025",
            "q05",
            "q50",
            "q95",
            "q975",
            "q99",
        }:
            raise ValidationError(f"{context} bootstrap quantile contract differs")
        try:
            quantile_values = {name: float(value) for name, value in quantiles.items()}
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"{context} bootstrap quantiles are invalid") from exc
        if (
            iterations != int(bootstrap["iterations"])
            or alpha != float(bootstrap["comparator_metric_alpha_bonferroni"])
            or cell.get("comparator_column") != PROMOTION_COMPARATORS.get(combination[0])
            or not math.isfinite(lcb)
            or not all(math.isfinite(value) for value in quantile_values.values())
            or [
                quantile_values[name]
                for name in ("q01", "q0125", "q025", "q05", "q50", "q95", "q975", "q99")
            ]
            != sorted(quantile_values.values())
            or quantile_values["q0125"] != lcb
            or cell.get("lcb_pass") is not (lcb > 0.0)
            or not re.fullmatch(r"[0-9a-f]{64}", str(cell.get("replicate_sha256", "")))
            or cell.get("stream_key_sha256") != expected_stream_sha256
        ):
            raise ValidationError(f"{context} bootstrap cell contract differs")
        cell_passes.append(lcb > 0.0)
        recomputed_minimum[combination[0]][combination[3]] = min(
            recomputed_minimum[combination[0]][combination[3]], lcb
        )
    if actual_combinations != expected_combinations:
        raise ValidationError(f"{context} bootstrap cell set differs from policy")
    seed_ids = payload.get("seed_ids")
    if (
        payload.get("format_version") != REPORT_FORMAT_VERSION
        or payload.get("policy_config_sha256") != policy_config["policy_config_sha256"]
        or payload.get("comparators") != PROMOTION_COMPARATORS
        or payload.get("minimum_simultaneous_lcb") != recomputed_minimum
        or int(payload.get("iterations_per_cell", -1)) != int(bootstrap["iterations"])
        or int(payload.get("expected_cells", -1)) != len(expected_combinations)
        or int(payload.get("seed_clusters", -1)) < PROMOTION_MINIMUM_LOCKED_SEEDS
        or int(payload.get("rows_per_seed", -1)) < PROMOTION_MINIMUM_COMMON_ROWS
        or not isinstance(seed_ids, list)
        or len(seed_ids) != int(payload.get("seed_clusters", -1))
        or len(set(seed_ids)) != len(seed_ids)
        or seed_ids != sorted(seed_ids)
        or not all(
            isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0 for seed in seed_ids
        )
        or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("date_index_sha256", "")))
        or payload.get("pass") is not all(cell_passes)
    ):
        raise ValidationError(f"{context} block-bootstrap summary contract differs")


def _summarize_tuning_candidate(
    rows: Sequence[Mapping[str, Any]],
    *,
    tolerance_fraction: float,
    invariance_assignment: Mapping[str, Any],
    daily_evidence_by_seed: Mapping[int, pd.DataFrame],
    policy_config: Mapping[str, Any],
) -> dict[str, Any]:
    if float(tolerance_fraction) != PROMOTION_WORST_SEED_DEGRADATION_CAP:
        raise ValidationError("prospective material-harm cap is immutable at 0.005")
    _verify_promotion_policy_config(policy_config, context="tuning summary")
    row_seeds: list[int] = []
    for row in rows:
        try:
            row_seeds.append(int(row["seed"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("tuning metric row is missing its seed") from exc
    if set(row_seeds) != set(daily_evidence_by_seed) or len(row_seeds) != len(
        daily_evidence_by_seed
    ):
        raise ValidationError("tuning daily evidence seed set differs from metric rows")
    evidence = _prepare_bootstrap_evidence(daily_evidence_by_seed)
    seed_position = {seed: index for index, seed in enumerate(evidence["seed_ids"])}
    rows_by_comparator: dict[str, list[dict[str, Any]]] = {
        name: [] for name in PROMOTION_COMPARATORS
    }
    for row in rows:
        seed = int(row["seed"])
        position = seed_position[seed]
        comparator_rows = row.get("comparators")
        if not isinstance(comparator_rows, Mapping) or set(comparator_rows) != set(
            PROMOTION_COMPARATORS
        ):
            raise ValidationError(f"seed {seed} dual-comparator metric set differs")
        mask_hashes: set[str] = set()
        for comparator_name in PROMOTION_COMPARATORS:
            raw_metric = comparator_rows[comparator_name]
            if not isinstance(raw_metric, Mapping):
                raise ValidationError(f"seed {seed}/{comparator_name} metric row is malformed")
            metric_row = copy.deepcopy(dict(raw_metric))
            metric_row["seed"] = seed
            if (
                int(metric_row.get("evaluation_scope_rows", -1)) != int(evidence["rows_per_seed"])
                or int(metric_row.get("common_rows", -1)) != int(evidence["rows_per_seed"])
                or float(metric_row.get("coverage", -1.0)) != 1.0
            ):
                raise ValidationError(
                    f"seed {seed}/{comparator_name} does not have full natural daily paired coverage"
                )
            mask_hashes.add(str(metric_row.get("promotion_mask_sha256", "")))
            arrays = evidence["arrays"][comparator_name]
            recomputed = {
                "fair_log_mae": {
                    "baseline": float(arrays["mae_baseline"][position].mean()),
                    "challenger": float(arrays["mae_challenger"][position].mean()),
                },
                "fair_log_rmse": {
                    "baseline": float(np.sqrt(arrays["rmse_baseline"][position].mean())),
                    "challenger": float(np.sqrt(arrays["rmse_challenger"][position].mean())),
                },
            }
            for promotion_metric in PROMOTION_METRICS:
                for side in ("baseline", "challenger"):
                    try:
                        recorded = float(metric_row[side][promotion_metric])
                    except (KeyError, TypeError, ValueError) as exc:
                        raise ValidationError(
                            f"seed {seed}/{comparator_name} lacks {promotion_metric}/{side}"
                        ) from exc
                    if not math.isclose(
                        recorded,
                        recomputed[promotion_metric][side],
                        rel_tol=1e-13,
                        abs_tol=1e-15,
                    ):
                        raise ValidationError(
                            "daily evidence differs from "
                            f"{comparator_name}/{promotion_metric}/{side} for seed {seed}"
                        )
            rows_by_comparator[comparator_name].append(metric_row)
        if len(mask_hashes) != 1:
            raise ValidationError(f"seed {seed} comparator promotion masks differ")
    bootstrap = _promotion_block_bootstrap(
        daily_evidence_by_seed,
        policy_config=policy_config,
    )
    _verify_promotion_block_bootstrap_summary(
        bootstrap,
        policy_config=policy_config,
        context="tuning/heldout summary",
    )
    try:
        structural = all(row["structural_no_harm_pass"] is True for row in rows)
        deterministic = all(row["determinism_pass"] is True for row in rows)
        prefix_invariant = all(row["causal_prefix_invariance_pass"] is True for row in rows)
    except (KeyError, TypeError) as exc:
        raise ValidationError("tuning candidate structural evidence is incomplete") from exc
    comparator_summaries: dict[str, Any] = {}
    all_deterministic = True
    all_no_harm = True
    worst_promotion_degradation = -math.inf
    diagnostic_degradations: list[float] = []
    rank_gains: list[float] = []
    for comparator_name, comparator_column in PROMOTION_COMPARATORS.items():
        comparator_rows = rows_by_comparator[comparator_name]
        paired_summary = _aggregate_paired_seed_metrics(
            comparator_rows,
            tolerance_fraction=tolerance_fraction,
        )
        deterministic_gates = _prospective_deterministic_gates(comparator_rows)
        comparator_summaries[comparator_name] = {
            "comparator_column": comparator_column,
            "per_seed": comparator_rows,
            **paired_summary,
            "prospective_deterministic_gates": deterministic_gates,
        }
        all_deterministic = all_deterministic and deterministic_gates["pass"] is True
        all_no_harm = all_no_harm and paired_summary["empirical_no_harm_pass"] is True
        worst_promotion_degradation = max(
            worst_promotion_degradation,
            float(paired_summary["worst_degradation_fraction_across_promotion_metrics"]),
        )
        diagnostic = paired_summary["worst_degradation_fraction_across_diagnostic_only_metrics"]
        if diagnostic is not None:
            diagnostic_degradations.append(float(diagnostic))
        for promotion_metric in PROMOTION_METRICS:
            relative_gain = paired_summary["aggregate"][promotion_metric]["relative_mean_gain"]
            if relative_gain is None or not math.isfinite(float(relative_gain)):
                raise ValidationError(
                    f"{comparator_name}/{promotion_metric} has no finite relative pooled gain"
                )
            rank_gains.append(float(relative_gain))
    deterministic_contract = {
        "comparators": {
            name: comparator_summaries[name]["prospective_deterministic_gates"]
            for name in PROMOTION_COMPARATORS
        },
        "both_comparators_required": True,
        "pass": bool(all_deterministic),
    }
    prospective = all_deterministic and bootstrap["pass"] is True
    return {
        "invariance_assignment": copy.deepcopy(dict(invariance_assignment)),
        "seeds": len(rows),
        "per_seed": list(rows),
        "comparators": comparator_summaries,
        "worst_relative_pooled_gain_across_comparator_metrics": min(rank_gains),
        "worst_degradation_fraction_across_promotion_metrics": (worst_promotion_degradation),
        "worst_degradation_fraction_across_diagnostic_only_metrics": (
            max(diagnostic_degradations) if diagnostic_degradations else None
        ),
        "structural_no_harm_pass": structural,
        "serial_parallel_determinism_pass": deterministic,
        "causal_prefix_invariance_pass": prefix_invariant,
        "both_comparators_no_harm_pass": bool(all_no_harm),
        "prospective_deterministic_gates": deterministic_contract,
        "prospective_block_bootstrap": bootstrap,
        "eligible_for_lock": (
            structural and deterministic and prefix_invariant and all_no_harm and prospective
        ),
    }


def _verify_dual_candidate_summary(
    payload: Any,
    *,
    policy_config: Mapping[str, Any],
    context: str,
) -> None:
    """Recompute all deterministic summary gates before lock/resume/holdout."""

    _verify_promotion_policy_config(policy_config, context=context)
    if not isinstance(payload, Mapping):
        raise ValidationError(f"{context} dual-comparator summary is missing")
    if set(payload) != {
        "invariance_assignment",
        "seeds",
        "per_seed",
        "comparators",
        "worst_relative_pooled_gain_across_comparator_metrics",
        "worst_degradation_fraction_across_promotion_metrics",
        "worst_degradation_fraction_across_diagnostic_only_metrics",
        "structural_no_harm_pass",
        "serial_parallel_determinism_pass",
        "causal_prefix_invariance_pass",
        "both_comparators_no_harm_pass",
        "prospective_deterministic_gates",
        "prospective_block_bootstrap",
        "eligible_for_lock",
    }:
        raise ValidationError(f"{context} dual-comparator summary schema differs")
    comparator_summaries = payload.get("comparators")
    if not isinstance(comparator_summaries, Mapping) or set(comparator_summaries) != set(
        PROMOTION_COMPARATORS
    ):
        raise ValidationError(f"{context} comparator summary set differs")
    top_per_seed = payload.get("per_seed")
    if not isinstance(top_per_seed, list) or len(top_per_seed) < PROMOTION_MINIMUM_LOCKED_SEEDS:
        raise ValidationError(f"{context} top-level per-seed evidence is missing")
    try:
        raw_top_seed_ids = [row["seed"] for row in top_per_seed]
    except (KeyError, TypeError) as exc:
        raise ValidationError(f"{context} top-level seed identity is malformed") from exc
    if not all(
        isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0
        for seed in raw_top_seed_ids
    ):
        raise ValidationError(f"{context} top-level seed identity is malformed")
    top_seed_ids = list(raw_top_seed_ids)
    if len(set(top_seed_ids)) != len(top_seed_ids) or payload.get("seeds") != len(top_seed_ids):
        raise ValidationError(f"{context} top-level seed set differs")
    structural = all(row.get("structural_no_harm_pass") is True for row in top_per_seed)
    deterministic = all(row.get("determinism_pass") is True for row in top_per_seed)
    prefix_invariant = all(row.get("causal_prefix_invariance_pass") is True for row in top_per_seed)
    if (
        payload.get("structural_no_harm_pass") is not structural
        or payload.get("serial_parallel_determinism_pass") is not deterministic
        or payload.get("causal_prefix_invariance_pass") is not prefix_invariant
    ):
        raise ValidationError(f"{context} top-level structural gates differ")
    rank_gains: list[float] = []
    deterministic_by_comparator: dict[str, Any] = {}
    all_no_harm = True
    promotion_degradations: list[float] = []
    diagnostic_degradations: list[float] = []
    for comparator_name, comparator_column in PROMOTION_COMPARATORS.items():
        comparator_summary = comparator_summaries[comparator_name]
        if (
            not isinstance(comparator_summary, Mapping)
            or comparator_summary.get("comparator_column") != comparator_column
        ):
            raise ValidationError(f"{context} comparator identity differs")
        if set(comparator_summary) != {
            "comparator_column",
            "per_seed",
            "aggregate",
            "empirical_no_harm_pass",
            "worst_degradation_fraction_across_promotion_metrics",
            "worst_degradation_fraction_across_diagnostic_only_metrics",
            "prospective_deterministic_gates",
        }:
            raise ValidationError(f"{context} comparator summary schema differs")
        per_seed = comparator_summary.get("per_seed")
        if not isinstance(per_seed, list):
            raise ValidationError(f"{context} comparator per-seed rows are missing")
        try:
            raw_comparator_seed_ids = [row["seed"] for row in per_seed]
        except (KeyError, TypeError) as exc:
            raise ValidationError(f"{context} comparator seed identity is malformed") from exc
        if not all(
            isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0
            for seed in raw_comparator_seed_ids
        ):
            raise ValidationError(f"{context} comparator seed identity is malformed")
        comparator_seed_ids = list(raw_comparator_seed_ids)
        if comparator_seed_ids != top_seed_ids:
            raise ValidationError(f"{context} comparator seed set/order differs")
        for top_row, comparator_row in zip(top_per_seed, per_seed, strict=True):
            if not isinstance(comparator_row, Mapping):
                raise ValidationError(f"{context} comparator per-seed row is malformed")
            top_comparators = top_row.get("comparators")
            if not isinstance(top_comparators, Mapping) or set(top_comparators) != set(
                PROMOTION_COMPARATORS
            ):
                raise ValidationError(f"{context} top-level comparator row differs")
            comparator_without_seed = {
                key: value for key, value in comparator_row.items() if key != "seed"
            }
            if top_comparators[comparator_name] != comparator_without_seed:
                raise ValidationError(f"{context} {comparator_name} per-seed evidence differs")
        recomputed_paired = _aggregate_paired_seed_metrics(
            per_seed,
            tolerance_fraction=PROMOTION_WORST_SEED_DEGRADATION_CAP,
        )
        for key, value in recomputed_paired.items():
            if comparator_summary.get(key) != value:
                raise ValidationError(f"{context} {comparator_name} aggregate summary differs")
        recomputed_gates = _prospective_deterministic_gates(per_seed)
        if comparator_summary.get("prospective_deterministic_gates") != recomputed_gates:
            raise ValidationError(f"{context} {comparator_name} deterministic gates differ")
        deterministic_by_comparator[comparator_name] = recomputed_gates
        all_no_harm = all_no_harm and recomputed_paired["empirical_no_harm_pass"] is True
        promotion_degradations.append(
            float(recomputed_paired["worst_degradation_fraction_across_promotion_metrics"])
        )
        diagnostic_degradation = recomputed_paired[
            "worst_degradation_fraction_across_diagnostic_only_metrics"
        ]
        if diagnostic_degradation is not None:
            diagnostic_degradations.append(float(diagnostic_degradation))
        for metric in PROMOTION_METRICS:
            gain = recomputed_paired["aggregate"][metric]["relative_mean_gain"]
            if gain is None or not math.isfinite(float(gain)):
                raise ValidationError(f"{context} comparator relative gain is invalid")
            rank_gains.append(float(gain))
    deterministic_contract = payload.get("prospective_deterministic_gates")
    expected_deterministic_contract = {
        "comparators": deterministic_by_comparator,
        "both_comparators_required": True,
        "pass": all(item["pass"] is True for item in deterministic_by_comparator.values()),
    }
    if deterministic_contract != expected_deterministic_contract:
        raise ValidationError(f"{context} dual-comparator deterministic contract differs")
    if payload.get("both_comparators_no_harm_pass") is not all_no_harm:
        raise ValidationError(f"{context} dual-comparator no-harm contract differs")
    worst_gain = min(rank_gains)
    if payload.get("worst_relative_pooled_gain_across_comparator_metrics") != worst_gain:
        raise ValidationError(f"{context} worst-of-four rank gain differs")
    if payload.get("worst_degradation_fraction_across_promotion_metrics") != max(
        promotion_degradations
    ) or payload.get("worst_degradation_fraction_across_diagnostic_only_metrics") != (
        max(diagnostic_degradations) if diagnostic_degradations else None
    ):
        raise ValidationError(f"{context} cross-comparator degradation summary differs")
    bootstrap = payload.get("prospective_block_bootstrap")
    _verify_promotion_block_bootstrap_summary(
        bootstrap,
        policy_config=policy_config,
        context=context,
    )
    if bootstrap.get("seed_ids") != sorted(top_seed_ids):
        raise ValidationError(f"{context} bootstrap seed set differs from summary")
    expected_eligible = (
        structural
        and deterministic
        and prefix_invariant
        and all_no_harm
        and expected_deterministic_contract["pass"] is True
        and bootstrap.get("pass") is True
    )
    if payload.get("eligible_for_lock") is not expected_eligible:
        raise ValidationError(f"{context} eligibility differs from dual-comparator gates")


def _regime_metrics(
    probabilities: pd.DataFrame,
    truth: pd.Series,
    *,
    scope_mask: np.ndarray | None = None,
) -> dict[str, Any]:
    mapping = {name: index for index, name in enumerate(REGIMES)}
    labels = truth.astype("string").str.upper().map(mapping).to_numpy(dtype=float, na_value=np.nan)
    values = probabilities.apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    finite = np.isfinite(values).all(axis=1)
    in_range = ((values >= 0.0) & (values <= 1.0)).all(axis=1)
    sums = np.where(finite[:, None], values, 0.0).sum(axis=1)
    scope = (
        np.ones(len(labels), dtype=bool)
        if scope_mask is None
        else np.asarray(scope_mask, dtype=bool)
    )
    if scope.shape != labels.shape:
        raise ValidationError("regime metric scope has the wrong shape")
    valid = scope & np.isfinite(labels) & finite & in_range & (sums > 0.0)
    if not valid.any():
        return {"evaluated_rows": 0, "coverage": 0.0}
    p = values[valid] / sums[valid, None]
    y = labels[valid].astype(int)
    hard = np.argmax(p, axis=1)
    recalls: dict[str, float | None] = {}
    for index, name in enumerate(REGIMES):
        class_rows = y == index
        recalls[name] = float(np.mean(hard[class_rows] == index)) if class_rows.any() else None
    confidence = np.max(p, axis=1)
    correct = hard == y
    ece = 0.0
    for lower, upper in zip(np.linspace(0.0, 0.9, 10), np.linspace(0.1, 1.0, 10)):
        bucket = (confidence >= lower) & (
            (confidence <= upper) if upper == 1.0 else (confidence < upper)
        )
        if bucket.any():
            ece += float(bucket.mean()) * abs(
                float(correct[bucket].mean()) - float(confidence[bucket].mean())
            )
    chosen = np.clip(p[np.arange(len(y)), y], 1e-15, 1.0)
    one_hot = np.eye(3, dtype=float)[y]
    available_recalls = [value for value in recalls.values() if value is not None]
    return {
        "evaluated_rows": int(valid.sum()),
        "coverage": float(valid.sum() / scope.sum()) if scope.any() else 0.0,
        "accuracy": float(correct.mean()),
        "balanced_accuracy": float(np.mean(available_recalls)),
        "log_loss": float(-np.log(chosen).mean()),
        "brier": float(np.square(p - one_hot).sum(axis=1).mean()),
        "ece_10_bin": float(ece),
        "class_recall": recalls,
    }


def _forward_return_proxy(
    benchmark_close: pd.Series,
    *,
    horizon: int,
    bull_threshold: float,
    bear_threshold: float,
) -> pd.Series:
    close = pd.to_numeric(benchmark_close, errors="coerce")
    forward = close.shift(-horizon) / close - 1.0
    labels = pd.Series(pd.NA, index=close.index, dtype="string")
    valid = np.isfinite(forward.to_numpy(dtype=float)) & _positive_finite(close)
    labels.loc[valid & forward.le(bear_threshold)] = "BEAR"
    labels.loc[valid & forward.ge(bull_threshold)] = "BULL"
    labels.loc[valid & forward.gt(bear_threshold) & forward.lt(bull_threshold)] = "SIDEWAYS"
    return labels


def _bool_values(series: pd.Series) -> np.ndarray:
    if pd.api.types.is_bool_dtype(series):
        return series.fillna(False).to_numpy(dtype=bool)
    text = series.astype("string").str.strip().str.lower()
    invalid = text.notna() & ~text.isin(["true", "false", "1", "0"])
    if invalid.any():
        raise ValidationError(f"invalid boolean gate values: {sorted(text[invalid].unique())}")
    return text.isin(["true", "1"]).to_numpy(dtype=bool)


def validate_no_harm_gates(
    frame: pd.DataFrame,
    config: Mapping[str, Any],
    *,
    atol: float = 1e-12,
) -> dict[str, Any]:
    """Assert that rejected/non-improving challengers cannot affect a blend."""

    reports: dict[str, Any] = {}
    failures = 0
    for prefix, (baseline_col, challenger_col, blended_col, section) in GATE_DEFINITIONS.items():
        required = {
            baseline_col,
            challenger_col,
            blended_col,
            f"{prefix}_oos_gain",
            f"{prefix}_challenger_weight",
            f"{prefix}_accepted",
        }
        if not required.issubset(frame.columns):
            continue
        baseline = pd.to_numeric(frame[baseline_col], errors="coerce").to_numpy(dtype=float)
        challenger = pd.to_numeric(frame[challenger_col], errors="coerce").to_numpy(dtype=float)
        blended = pd.to_numeric(frame[blended_col], errors="coerce").to_numpy(dtype=float)
        gain = pd.to_numeric(frame[f"{prefix}_oos_gain"], errors="coerce").to_numpy(dtype=float)
        weight = pd.to_numeric(frame[f"{prefix}_challenger_weight"], errors="coerce").to_numpy(
            dtype=float
        )
        accepted = _bool_values(frame[f"{prefix}_accepted"])
        margin = float(config.get(section, {}).get("improvement_margin", 0.0))
        pair = (
            np.isfinite(baseline) & (baseline > 0.0) & np.isfinite(challenger) & (challenger > 0.0)
        )
        positive_weight = np.isfinite(weight) & (weight > atol)
        invalid_weight = ~np.isfinite(weight) | (weight < -atol) | (weight > 1.0 + atol)
        bad_acceptance = accepted != positive_weight
        bad_evidence = pair & positive_weight & (~np.isfinite(gain) | (gain <= margin))
        rejected_pair = pair & ~positive_weight
        tolerance = atol * np.maximum(1.0, np.abs(baseline))
        bad_rejected_blend = rejected_pair & (
            ~np.isfinite(blended) | (np.abs(blended - baseline) > tolerance)
        )
        count = int(invalid_weight.sum() + bad_acceptance.sum() + bad_evidence.sum())
        count += int(bad_rejected_blend.sum())
        failures += count
        reports[prefix] = {
            "checked_rows": int(len(frame)),
            "paired_rows": int(pair.sum()),
            "positive_weight_rows": int(positive_weight.sum()),
            "invalid_weight_rows": int(invalid_weight.sum()),
            "acceptance_weight_mismatch_rows": int(bad_acceptance.sum()),
            "weight_without_decisive_gain_rows": int(bad_evidence.sum()),
            "rejected_blend_changed_rows": int(bad_rejected_blend.sum()),
            "pass": count == 0,
        }
    if not reports:
        raise ValidationError("no auditable candidate-gate columns were found")
    return {"pass": failures == 0, "failure_count": failures, "gates": reports}


def _frame_exact_sha256(frame: pd.DataFrame) -> str:
    digest = hashlib.sha256()
    digest.update(_canonical_json_bytes({"columns": list(frame.columns)}))
    digest.update(_canonical_json_bytes({"dtypes": [str(value) for value in frame.dtypes]}))
    for column in frame.columns:
        hashes = pd.util.hash_pandas_object(frame[column], index=True, categorize=False)
        digest.update(hashes.to_numpy(dtype="uint64").astype("<u8", copy=False).tobytes())
    return digest.hexdigest()


def _validate_append_contract(
    original: pd.DataFrame,
    output: pd.DataFrame,
    append_columns: Sequence[str],
) -> dict[str, Any]:
    if len(original.columns) != CANONICAL_V03_COLUMNS:
        raise ValidationError(
            f"v0.3 input must have exactly {CANONICAL_V03_COLUMNS} columns; "
            f"got {len(original.columns)}"
        )
    prefix = list(output.columns[: len(original.columns)])
    if prefix != list(original.columns):
        raise ValidationError("v0.3 150-column prefix names/order changed")
    pd.testing.assert_frame_equal(
        output.iloc[:, : len(original.columns)],
        original,
        check_dtype=True,
        check_exact=True,
        check_names=True,
        check_like=False,
    )
    appended = list(output.columns[len(original.columns) :])
    if appended != list(append_columns):
        raise ValidationError(
            f"v0.4 append schema mismatch: expected {len(append_columns)}, got {len(appended)}"
        )
    if len(appended) != len(set(appended)) or any(
        not column.startswith("v04_") for column in appended
    ):
        raise ValidationError("appended columns must be unique and v04_-prefixed")

    numeric = output[appended].select_dtypes(include=[np.number])
    infinite: dict[str, int] = {}
    for column in numeric.columns:
        count = int(np.isinf(numeric[column].to_numpy(dtype=float)).sum())
        if count:
            infinite[column] = count
    if infinite:
        raise ValidationError(f"v0.4 numeric columns contain infinity: {infinite}")
    nan_counts = {
        column: int(numeric[column].isna().sum())
        for column in numeric.columns
        if numeric[column].isna().any()
    }
    for column in [item for item in appended if "expected_pe" in item]:
        values = pd.to_numeric(output[column], errors="coerce").to_numpy(dtype=float)
        bad = np.isfinite(values) & (values <= 0.0)
        if bad.any():
            raise ValidationError(f"{column} contains non-positive finite values")
    return {
        "v03_prefix_columns": len(original.columns),
        "v04_append_columns": len(appended),
        "v03_frozen_parity_exact": True,
        "append_schema_exact": True,
        "infinite_numeric_values": 0,
        "numeric_nan_counts": nan_counts,
        "frame_exact_sha256": _frame_exact_sha256(output),
    }


def _normalize_apply_result(result: Any) -> tuple[pd.DataFrame, dict[str, Any]]:
    """The only compatibility shim for the integration agent's evolving API."""

    if isinstance(result, pd.DataFrame):
        return result, {}
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], pd.DataFrame):
        metadata = result[1] if isinstance(result[1], Mapping) else {"raw": str(result[1])}
        return result[0], dict(metadata)
    if isinstance(result, Mapping):
        for key in ("frame", "output", "data"):
            if isinstance(result.get(key), pd.DataFrame):
                metadata = {name: value for name, value in result.items() if name != key}
                return result[key], metadata
    raise ValidationError(
        "apply_v04_layers must return DataFrame, (DataFrame, metadata), or a mapping "
        "containing frame/output/data"
    )


def _load_yaml_config(config_path: Path) -> dict[str, Any]:
    source = PROJECT_ROOT / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    from pe_regime_v04.config import load_config

    return load_config(config_path)


def _force_parallelism(config: Mapping[str, Any], outer_jobs: int) -> dict[str, Any]:
    forced = copy.deepcopy(dict(config))
    for section in ("regime_stacker", "expected_pe"):
        values = forced.setdefault(section, {})
        values["outer_n_jobs"] = int(outer_jobs)
        values["parallel_backend"] = (
            "serial" if outer_jobs == DETERMINISM_SERIAL_OUTER_JOBS else "thread"
        )
        values["n_jobs"] = 1
    return forced


def _require_determinism_parallel_outer_jobs(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise ValidationError(
            "the production determinism comparison is fixed at serial vs "
            f"{DETERMINISM_PARALLEL_OUTER_JOBS}"
        )
    outer_jobs = int(value)
    if outer_jobs != DETERMINISM_PARALLEL_OUTER_JOBS:
        raise ValidationError(
            "the production determinism comparison is fixed at serial vs "
            f"{DETERMINISM_PARALLEL_OUTER_JOBS}"
        )
    return outer_jobs


def _validate_effective_mapping(config: Mapping[str, Any]) -> None:
    source = PROJECT_ROOT / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    from pe_regime_v04.config import validate_config

    validate_config(config)


def _validated_effective_config(
    config_path: Path,
    overrides: Mapping[str, Any],
    *,
    model_seed: int,
    outer_jobs: int,
) -> dict[str, Any]:
    """Merge a candidate, apply harness-owned fields, then validate the result."""

    if not isinstance(overrides, Mapping):
        raise ValidationError("candidate overrides must be a mapping")
    effective = _deep_merge(_load_yaml_config(config_path), overrides)
    effective.setdefault("project", {})["random_seed"] = int(model_seed)
    effective = _force_parallelism(effective, int(outer_jobs))
    _validate_effective_mapping(effective)
    return effective


def _invariance_model_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return the validated model sections that define invariance compatibility."""

    missing = [section for section in INVARIANCE_CONFIG_SECTIONS if section not in config]
    if missing:
        raise ValidationError(f"effective model config misses invariance sections: {missing}")
    payload: dict[str, Any] = {}
    for section in INVARIANCE_CONFIG_SECTIONS:
        values = config[section]
        if not isinstance(values, Mapping):
            raise ValidationError(f"effective model section {section!r} must be a mapping")
        payload[section] = copy.deepcopy(dict(values))
    return payload


def _build_invariance_plan(
    effective_configs: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    """Group candidates only when their validated effective model configs match."""

    if not effective_configs:
        raise ValidationError("cannot build an invariance plan without candidates")
    grouped: dict[str, dict[str, Any]] = {}
    for name in sorted(effective_configs):
        model_config = _invariance_model_config(effective_configs[name])
        signature = hashlib.sha256(_canonical_json_bytes(model_config)).hexdigest()
        group = grouped.setdefault(
            signature,
            {
                "signature_sha256": signature,
                "effective_model_config": model_config,
                "candidates": [],
            },
        )
        if group["effective_model_config"] != model_config:
            raise ValidationError("invariance model-config signature collision")
        group["candidates"].append(name)

    groups: dict[str, Any] = {}
    assignments: dict[str, Any] = {}
    for signature in sorted(grouped):
        group_id = f"model_config_{signature}"
        members = sorted(grouped[signature]["candidates"])
        representative = members[0]
        record = {
            "group_id": group_id,
            "signature_sha256": signature,
            "representative_candidate": representative,
            "candidates": members,
            "effective_model_config": grouped[signature]["effective_model_config"],
        }
        groups[group_id] = record
        for name in members:
            assignments[name] = {
                "group_id": group_id,
                "signature_sha256": signature,
                "representative_candidate": representative,
            }
    plan = {
        "format_version": 1,
        "signature_sections": list(INVARIANCE_CONFIG_SECTIONS),
        "groups": groups,
        "candidate_assignments": dict(sorted(assignments.items())),
    }
    sealed = _seal_payload(plan, "invariance_plan_sha256")
    _verify_invariance_plan(sealed, candidate_names=effective_configs)
    return sealed


def _verify_invariance_plan(
    plan: Mapping[str, Any],
    *,
    candidate_names: Sequence[str] | Mapping[str, Any] | None = None,
) -> None:
    """Fail closed on incomplete, ambiguous, or internally inconsistent grouping."""

    _verify_sealed(plan, "invariance_plan_sha256", context="invariance plan")
    if plan.get("signature_sections") != list(INVARIANCE_CONFIG_SECTIONS):
        raise ValidationError("invariance plan signature sections changed")
    groups = plan.get("groups")
    assignments = plan.get("candidate_assignments")
    if not isinstance(groups, Mapping) or not groups:
        raise ValidationError("invariance plan groups are missing")
    if not isinstance(assignments, Mapping) or not assignments:
        raise ValidationError("invariance plan candidate assignments are missing")

    seen: set[str] = set()
    for group_id, raw_group in groups.items():
        if not isinstance(group_id, str) or not isinstance(raw_group, Mapping):
            raise ValidationError("invariance plan contains an invalid group")
        signature = raw_group.get("signature_sha256")
        model_config = raw_group.get("effective_model_config")
        members = raw_group.get("candidates")
        representative = raw_group.get("representative_candidate")
        if raw_group.get("group_id") != group_id:
            raise ValidationError(f"invariance group ID mismatch: {group_id}")
        if not isinstance(model_config, Mapping):
            raise ValidationError(f"invariance group {group_id} has no model config")
        expected_signature = hashlib.sha256(_canonical_json_bytes(model_config)).hexdigest()
        if signature != expected_signature or group_id != f"model_config_{expected_signature}":
            raise ValidationError(f"invariance group {group_id} signature is invalid")
        if not isinstance(members, list) or not members or members != sorted(set(members)):
            raise ValidationError(f"invariance group {group_id} members are invalid")
        if representative != members[0]:
            raise ValidationError(
                f"invariance group {group_id} representative is not deterministic"
            )
        for name in members:
            if name in seen:
                raise ValidationError(f"candidate {name!r} belongs to multiple invariance groups")
            seen.add(name)
            expected_assignment = {
                "group_id": group_id,
                "signature_sha256": expected_signature,
                "representative_candidate": representative,
            }
            if assignments.get(name) != expected_assignment:
                raise ValidationError(f"candidate {name!r} has an invalid invariance assignment")
    if set(assignments) != seen:
        raise ValidationError("invariance plan has orphan candidate assignments")
    if candidate_names is not None and set(candidate_names) != seen:
        raise ValidationError("invariance plan does not cover the candidate set exactly")


def _invariance_assignment(args: argparse.Namespace, name: str) -> dict[str, Any]:
    plan = getattr(args, "invariance_plan", None)
    if not isinstance(plan, Mapping):
        raise ValidationError("invariance plan is missing from the run")
    _verify_invariance_plan(plan)
    assignment = plan["candidate_assignments"].get(name)
    if not isinstance(assignment, Mapping):
        raise ValidationError(f"candidate {name!r} has no invariance assignment")
    return copy.deepcopy(dict(assignment))


def _overlay_worker(args: argparse.Namespace) -> int:
    source = PROJECT_ROOT / "src"
    if str(source) not in sys.path:
        sys.path.insert(0, str(source))
    from pe_regime_v04 import pipeline

    input_path = Path(args.input_csv).resolve()
    output_path = Path(args.output_csv).resolve()
    diagnostics_path = Path(args.diagnostics_json).resolve()
    candidate_overrides = _read_json(Path(args.overrides_json).resolve())
    config = _validated_effective_config(
        Path(args.config).resolve(),
        candidate_overrides,
        model_seed=int(args.model_seed),
        outer_jobs=int(args.outer_jobs),
    )
    original = pd.read_csv(input_path, float_precision="round_trip")
    before = original.copy(deep=True)

    adapter = args.adapter
    apply_function = getattr(pipeline, "apply_v04_layers", None)
    if adapter in {"auto", "in-memory"} and callable(apply_function):
        output, metadata = _normalize_apply_result(apply_function(original, config))
        adapter_used = "apply_v04_layers"
    elif adapter == "in-memory":
        raise ValidationError("apply_v04_layers is unavailable")
    else:
        # Compatibility fallback.  It intentionally remains here, in one small
        # adapter boundary, so the validation/evaluation code never depends on the
        # file-oriented overlay API.
        run_overlay = getattr(pipeline, "run_overlay", None)
        if not callable(run_overlay):
            raise ValidationError("neither apply_v04_layers nor run_overlay is available")
        temporary_dir = output_path.parent / "cli_adapter"
        temporary_dir.mkdir(parents=True, exist_ok=True)
        result = run_overlay(input_path, temporary_dir, config)
        generated = Path(result["output_csv"])
        output = pd.read_csv(generated, float_precision="round_trip")
        metadata = {"run_overlay_report": result.get("report", {})}
        adapter_used = "run_overlay_cli_boundary"

    pd.testing.assert_frame_equal(
        original,
        before,
        check_dtype=True,
        check_exact=True,
        check_names=True,
    )
    append_columns = tuple(getattr(pipeline, "V04_APPEND_COLUMNS"))
    contract = _validate_append_contract(before, output, append_columns)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output.to_csv(output_path, index=False, encoding="utf-8-sig")
    diagnostics = {
        "adapter_used": adapter_used,
        "outer_jobs": int(args.outer_jobs),
        "model_seed": int(args.model_seed),
        "input_frame_sha256": _frame_exact_sha256(before),
        "output_contract": contract,
        "prefix_frame_sha256": {
            str(CAUSAL_PREFIX_ROWS): _frame_exact_sha256(output.iloc[:CAUSAL_PREFIX_ROWS])
        }
        if len(output) >= CAUSAL_PREFIX_ROWS
        else {},
        "pipeline_metadata": _jsonable(metadata),
    }
    _atomic_write_json(diagnostics_path, diagnostics)
    return 0


def _process_rss_bytes(pid: int) -> int | None:
    if os.name == "nt":

        class ProcessMemoryCounters(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        psapi.GetProcessMemoryInfo.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessMemoryCounters),
            ctypes.c_ulong,
        ]
        query_information = 0x0400
        vm_read = 0x0010
        handle = kernel32.OpenProcess(query_information | vm_read, False, int(pid))
        if not handle:
            return None
        try:
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(counters)
            ok = psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)
            return int(counters.WorkingSetSize) if ok else None
        finally:
            kernel32.CloseHandle(handle)
    status = Path(f"/proc/{pid}/status")
    try:
        for line in status.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (FileNotFoundError, PermissionError, ValueError):
        return None
    return None


def _process_tree_pids(root_pid: int) -> set[int]:
    if os.name == "nt":

        class ProcessEntry(ctypes.Structure):
            _fields_ = [
                ("dwSize", ctypes.c_ulong),
                ("cntUsage", ctypes.c_ulong),
                ("th32ProcessID", ctypes.c_ulong),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", ctypes.c_ulong),
                ("cntThreads", ctypes.c_ulong),
                ("th32ParentProcessID", ctypes.c_ulong),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", ctypes.c_ulong),
                ("szExeFile", ctypes.c_wchar * 260),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        kernel32.Process32FirstW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessEntry),
        ]
        kernel32.Process32NextW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ProcessEntry),
        ]
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            return {int(root_pid)}
        parents: dict[int, int] = {}
        try:
            entry = ProcessEntry()
            entry.dwSize = ctypes.sizeof(entry)
            success = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            while success:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                success = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)
    else:
        parents = {}
        for status in Path("/proc").glob("[0-9]*/status"):
            try:
                values = {}
                for line in status.read_text(encoding="utf-8").splitlines():
                    if line.startswith(("Pid:", "PPid:")):
                        key, value = line.split(":", 1)
                        values[key] = int(value.strip())
                parents[values["Pid"]] = values["PPid"]
            except (FileNotFoundError, PermissionError, KeyError, ValueError):
                continue
    tree = {int(root_pid)}
    changed = True
    while changed:
        changed = False
        for pid, parent in parents.items():
            if parent in tree and pid not in tree:
                tree.add(pid)
                changed = True
    return tree


def _process_tree_rss_bytes(root_pid: int) -> int | None:
    values = [
        value
        for pid in _process_tree_pids(root_pid)
        if (value := _process_rss_bytes(pid)) is not None
    ]
    return int(sum(values)) if values else None


@dataclass
class CommandMeasurement:
    wall_seconds: float
    peak_rss_bytes: int | None
    rss_scope: str = "process_tree_sum_sampled_50ms"


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    log_path: Path,
    env: Mapping[str, str] | None = None,
) -> CommandMeasurement:
    _execution_policy_runtime(apply=False)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    peak: int | None = None
    with log_path.open("w", encoding="utf-8", errors="replace") as stream:
        process = subprocess.Popen(
            list(command),
            cwd=str(cwd),
            stdout=stream,
            stderr=subprocess.STDOUT,
            text=True,
            env=dict(env) if env is not None else None,
        )
        while process.poll() is None:
            rss = _process_tree_rss_bytes(process.pid)
            if rss is not None:
                peak = rss if peak is None else max(peak, rss)
            time.sleep(0.05)
        return_code = process.wait()
    wall = time.perf_counter() - started
    if return_code != 0:
        tail = log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-30:]
        raise ValidationError(f"command failed ({return_code}); see {log_path}\n" + "\n".join(tail))
    return CommandMeasurement(wall_seconds=float(wall), peak_rss_bytes=peak)


def _subprocess_environment(v03_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    path_entries = [str(PROJECT_ROOT / "src"), str(v03_root / "src")]
    existing = env.get("PYTHONPATH")
    if existing:
        path_entries.append(existing)
    env.update(
        {
            "PYTHONPATH": os.pathsep.join(path_entries),
            "PYTHONHASHSEED": "0",
            "OMP_NUM_THREADS": "1",
            "MKL_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "NUMEXPR_NUM_THREADS": "1",
            "CUDA_VISIBLE_DEVICES": "-1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "HIP_VISIBLE_DEVICES": "-1",
            "ROCR_VISIBLE_DEVICES": "-1",
        }
    )
    return env


def _probe_python310(python: Path, v03_root: Path) -> dict[str, Any]:
    if not python.is_file():
        raise ValidationError(f"v0.3 Python is missing: {python}")
    command = [
        str(python),
        "-c",
        (
            "import json,platform,sys; "
            "from pe_regime_engine.demo import DEMO_GENERATOR_VERSION; "
            "print(json.dumps({"
            "'version':[sys.version_info.major,sys.version_info.minor,sys.version_info.micro],"
            "'executable':sys.executable,'platform':platform.platform(),"
            "'demo_generator_version':DEMO_GENERATOR_VERSION}))"
        ),
    ]
    completed = subprocess.run(
        command,
        cwd=str(v03_root),
        check=True,
        capture_output=True,
        text=True,
        env=_subprocess_environment(v03_root),
    )
    payload = json.loads(completed.stdout.strip())
    if payload["version"][:2] != [3, 10]:
        raise ValidationError(f"v0.3 validation requires CPython 3.10; got {payload}")
    return payload


def _read_csv(path: Path) -> pd.DataFrame:
    return pd.read_csv(path, float_precision="round_trip")


def _validate_v03_pair(canonical_path: Path, truth_path: Path) -> dict[str, Any]:
    frame = _read_csv(canonical_path)
    truth = _read_csv(truth_path)
    if len(frame.columns) != CANONICAL_V03_COLUMNS:
        raise ValidationError(f"v0.3 CLI output is not canonical150: {len(frame.columns)} columns")
    required = {
        "date",
        "observed_pe",
        "benchmark_close",
        "p_bear",
        "p_sideways",
        "p_bull",
        "market_regime",
        "ml_expected_pe",
    }
    missing = required.difference(frame.columns)
    if missing:
        raise ValidationError(f"canonical v0.3 output misses {sorted(missing)}")
    truth_required = {"date", "true_fair_pe", "true_observed_pe", "true_regime"}
    truth_missing = truth_required.difference(truth.columns)
    if truth_missing:
        raise ValidationError(f"truth output misses {sorted(truth_missing)}")
    dates = pd.to_datetime(frame["date"], errors="raise")
    truth_dates = pd.to_datetime(truth["date"], errors="raise")
    if dates.duplicated().any() or not dates.is_monotonic_increasing:
        raise ValidationError("canonical v0.3 dates must be unique/increasing")
    if truth_dates.duplicated().any():
        raise ValidationError("truth dates must be unique")
    if len(frame) != ROWS or len(truth) != ROWS:
        raise ValidationError(
            f"warm-up contract requires {ROWS} canonical and truth rows; "
            f"got {len(frame)} and {len(truth)}"
        )
    if not dates.reset_index(drop=True).equals(truth_dates.reset_index(drop=True)):
        raise ValidationError("canonical and truth date indexes differ")
    production_scope = dates.ge(PRODUCTION_EVALUATION_START).to_numpy(dtype=bool)
    fair_available = _require_fair_truth(
        truth["true_fair_pe"],
        scope_mask=production_scope,
        context="canonical v0.3 truth",
    )
    first_date = dates.iloc[0].strftime("%Y-%m-%d")
    last_date = dates.iloc[-1].strftime("%Y-%m-%d")
    date_bytes = dates.astype("int64").to_numpy().astype("<i8", copy=False).tobytes()
    date_sha = hashlib.sha256(date_bytes).hexdigest()
    if (
        first_date != GENERATION_START
        or last_date != EXPECTED_LAST_DATE
        or date_sha != EXPECTED_DATE_INDEX_SHA256
    ):
        raise ValidationError(
            "canonical warm-up date contract changed: "
            f"first={first_date}, last={last_date}, sha256={date_sha}"
        )
    versions = (
        sorted(str(value) for value in truth["demo_generator_version"].dropna().unique())
        if "demo_generator_version" in truth.columns
        else []
    )
    observed = pd.to_numeric(frame["observed_pe"], errors="coerce").to_numpy(dtype=float)
    true_observed = pd.to_numeric(truth["true_observed_pe"], errors="coerce").to_numpy(dtype=float)
    observed_common = np.isfinite(observed) & np.isfinite(true_observed)
    if not observed_common.any():
        raise ValidationError("no finite PIT observed-P/E truth rows")
    observed_error = np.abs(observed[observed_common] - true_observed[observed_common])
    observed_scale = np.maximum(np.abs(true_observed[observed_common]), 1.0)
    if np.any(observed_error > 1e-10 * observed_scale):
        raise ValidationError("canonical observed_pe does not match independent PIT truth")
    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "first_date": dates.iloc[0].isoformat(),
        "last_date": dates.iloc[-1].isoformat(),
        "date_index_sha256": date_sha,
        "full_1800_warmup_before_production_filter": True,
        "production_evaluation_start": PRODUCTION_EVALUATION_START,
        "truth_rows": int(len(truth)),
        "truth_versions": versions,
        "production_fair_truth_rows": int(fair_available.sum()),
        "observed_pe_truth_rows": int(observed_common.sum()),
        "observed_pe_truth_max_abs_error": float(observed_error.max()),
    }


def _new_checkpoint(manifest_sha256: str) -> dict[str, Any]:
    return _seal_payload(
        {
            "format_version": CHECKPOINT_FORMAT_VERSION,
            "artifact_format_version": ARTIFACT_FORMAT_VERSION,
            "artifact_layout_version": ARTIFACT_LAYOUT_VERSION,
            "manifest_sha256": manifest_sha256,
            "previous_checkpoint_sha256": None,
            "updated_at_utc": _utc_now(),
            "inputs": {"tuning": {}, "heldout": {}},
            "runs": {"tuning": {}, "heldout": {}},
            "stage_completions": {},
        },
        "checkpoint_sha256",
    )


def _load_checkpoint(path: Path, manifest_sha256: str) -> dict[str, Any]:
    if not path.exists():
        return _new_checkpoint(manifest_sha256)
    checkpoint = _read_json(path)
    _verify_sealed(checkpoint, "checkpoint_sha256", context="checkpoint")
    if (
        checkpoint.get("format_version") != CHECKPOINT_FORMAT_VERSION
        or checkpoint.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION
        or checkpoint.get("artifact_layout_version") != ARTIFACT_LAYOUT_VERSION
    ):
        raise ValidationError(
            "checkpoint format/layout is incompatible; use a new output directory"
        )
    if checkpoint.get("manifest_sha256") != manifest_sha256:
        raise ValidationError("checkpoint belongs to a different run manifest")
    return checkpoint


def _write_checkpoint(path: Path, checkpoint: Mapping[str, Any]) -> dict[str, Any]:
    previous = checkpoint.get("checkpoint_sha256")
    updated = copy.deepcopy(dict(checkpoint))
    updated["previous_checkpoint_sha256"] = previous
    updated["updated_at_utc"] = _utc_now()
    sealed = _seal_payload(updated, "checkpoint_sha256")
    _atomic_write_json(path, sealed)
    return sealed


def _contract_from_args(
    args: argparse.Namespace,
    candidates: Mapping[str, Any],
    snapshot: Mapping[str, Any],
    python_info: Mapping[str, Any],
) -> dict[str, Any]:
    parallel_outer_jobs = _require_determinism_parallel_outer_jobs(args.outer_jobs)
    policy_lock = args.promotion_policy_lock
    _verify_sealed(policy_lock, "policy_lock_sha256", context="promotion policy lock")
    _verify_promotion_policy_config(
        policy_lock.get("policy_config"), context="promotion policy lock"
    )
    return {
        "format_version": MANIFEST_FORMAT_VERSION,
        "harness_version": HARNESS_VERSION,
        "artifact_format_version": ARTIFACT_FORMAT_VERSION,
        "artifact_layout_version": ARTIFACT_LAYOUT_VERSION,
        "path_policy": copy.deepcopy(args.path_policy),
        "created_at_utc": _utc_now(),
        "v03_root": str(Path(args.v03_root).resolve()),
        "v04_root": str(PROJECT_ROOT.resolve()),
        "v03_python": str(Path(args.v03_python).resolve()),
        "v03_config": _artifact(Path(args.v03_config).resolve()),
        "v04_config": _artifact(Path(args.v04_config).resolve()),
        "python_info": python_info,
        "rows": ROWS,
        "generation_start": args.generation_start,
        "production_evaluation_start": args.evaluation_start,
        "tuning_seeds": list(args.tuning_seeds),
        "locked_seeds": list(args.locked_seeds),
        "candidates": candidates,
        "candidates_sha256": hashlib.sha256(_canonical_json_bytes(candidates)).hexdigest(),
        "source_snapshot": snapshot,
        "source_config_sha256_at_start": snapshot["combined_sha256"],
        "overlay_adapter": args.overlay_adapter,
        "parallel_outer_jobs": parallel_outer_jobs,
        "serial_determinism": True,
        "determinism_comparison": {
            "name": f"serial-vs-{parallel_outer_jobs}",
            "serial_outer_jobs": DETERMINISM_SERIAL_OUTER_JOBS,
            "parallel_outer_jobs": parallel_outer_jobs,
            "bit_exact_required": True,
        },
        "invariance_plan": args.invariance_plan,
        "metric_roles": _metric_roles_contract(),
        "promotion_comparators": copy.deepcopy(PROMOTION_COMPARATORS),
        "promotion_policy_config": copy.deepcopy(policy_lock["policy_config"]),
        "promotion_policy_lock": _artifact(args.promotion_policy_path),
        "promotion_policy_lock_sha256": policy_lock["policy_lock_sha256"],
        "spent_seed_reservation": copy.deepcopy(args.spent_seed_reservation),
        "material_harm_cap_fraction": PROMOTION_WORST_SEED_DEGRADATION_CAP,
        "heldout_open_policy": "candidate.lock must exist before any heldout input/run",
    }


def _manifest_comparable(payload: Mapping[str, Any]) -> dict[str, Any]:
    ignored = {"created_at_utc", "manifest_sha256"}
    return {key: value for key, value in payload.items() if key not in ignored}


def _load_or_create_manifest(
    path: Path,
    contract: Mapping[str, Any],
    *,
    allow_create: bool,
) -> dict[str, Any]:
    if path.exists():
        manifest = _read_json(path)
        _verify_sealed(manifest, "manifest_sha256", context="run manifest")
        if (
            manifest.get("format_version") != MANIFEST_FORMAT_VERSION
            or manifest.get("harness_version") != HARNESS_VERSION
            or manifest.get("artifact_format_version") != ARTIFACT_FORMAT_VERSION
            or manifest.get("artifact_layout_version") != ARTIFACT_LAYOUT_VERSION
            or manifest.get("promotion_comparators") != PROMOTION_COMPARATORS
        ):
            raise ValidationError(
                "run manifest format/harness/layout is incompatible; use a new output directory"
            )
        if _manifest_comparable(manifest) != _manifest_comparable(contract):
            raise ValidationError(
                "invocation differs from the sealed run manifest; use a new output directory"
            )
        return manifest
    if not allow_create:
        raise ValidationError("tune must create the run manifest before lock/holdout")
    sealed = _seal_payload(contract, "manifest_sha256")
    _atomic_write_json(path, sealed)
    return sealed


def _ensure_v03_input(
    *,
    stage: str,
    seed: int,
    args: argparse.Namespace,
    checkpoint: dict[str, Any],
    checkpoint_path: Path,
) -> tuple[Path, Path, dict[str, Any], dict[str, Any]]:
    bucket = checkpoint["inputs"][stage]
    existing = bucket.get(str(seed))
    if existing is not None:
        if not isinstance(existing, Mapping):
            raise ValidationError(f"{stage} seed {seed} input checkpoint is malformed")
        canonical = _verify_artifact(existing["canonical_csv"], context="canonical v0.3")
        truth = _verify_artifact(existing["truth_csv"], context="synthetic truth")
        _verify_artifact(existing["cli_log"], context="v0.3 CLI log")
        validation = _validate_v03_pair(canonical, truth)
        if (
            existing.get("seed") != int(seed)
            or existing.get("generator_rows") != ROWS
            or existing.get("validation") != validation
        ):
            raise ValidationError(
                f"{stage} seed {seed} input checkpoint identity differs from its bucket"
            )
        return canonical, truth, existing, checkpoint

    seed_root = Path(args.output_root).resolve() / "artifacts" / stage / f"seed_{seed}"
    v03_output = seed_root / "v03_high"
    log_path = seed_root / "v03_high_cli.log"
    command = [
        str(Path(args.v03_python).resolve()),
        "-m",
        "pe_regime_engine",
        "demo",
        "--config",
        str(Path(args.v03_config).resolve()),
        "--output-dir",
        str(v03_output),
        "--start",
        args.generation_start,
        "--seed",
        str(seed),
        "--rows",
        str(ROWS),
        "--no-chart",
    ]
    measurement = _run_command(
        command,
        cwd=Path(args.v03_root).resolve(),
        log_path=log_path,
        env=_subprocess_environment(Path(args.v03_root).resolve()),
    )
    canonical_matches = sorted(v03_output.glob("DEMO_PE_Regime_DEMO_BENCH.csv"))
    truth_matches = sorted(v03_output.glob("DEMO_PE_Regime_DEMO_BENCH_*_truth.csv"))
    if len(canonical_matches) != 1 or len(truth_matches) != 1:
        raise ValidationError(
            f"v0.3 CLI did not produce one canonical/truth pair below {v03_output}"
        )
    validation = _validate_v03_pair(canonical_matches[0], truth_matches[0])
    record = {
        "seed": int(seed),
        "generator_rows": ROWS,
        "canonical_csv": _artifact(canonical_matches[0]),
        "truth_csv": _artifact(truth_matches[0]),
        "cli_log": _artifact(log_path),
        "runtime": {
            "wall_seconds": measurement.wall_seconds,
            "peak_rss_bytes": measurement.peak_rss_bytes,
            "rss_scope": measurement.rss_scope,
        },
        "validation": validation,
    }
    bucket[str(seed)] = record
    checkpoint = _write_checkpoint(checkpoint_path, checkpoint)
    return canonical_matches[0], truth_matches[0], record, checkpoint


def _run_v04_adapter(
    *,
    input_csv: Path,
    output_csv: Path,
    diagnostics_json: Path,
    overrides_json: Path,
    model_seed: int,
    outer_jobs: int,
    args: argparse.Namespace,
    log_path: Path,
) -> CommandMeasurement:
    """Small subprocess boundary around the evolving in-memory/CLI integration API."""

    command = [
        str(Path(args.v03_python).resolve()),
        str(Path(__file__).resolve()),
        "_overlay-worker",
        "--input-csv",
        str(input_csv),
        "--output-csv",
        str(output_csv),
        "--diagnostics-json",
        str(diagnostics_json),
        "--overrides-json",
        str(overrides_json),
        "--config",
        str(Path(args.v04_config).resolve()),
        "--model-seed",
        str(model_seed),
        "--outer-jobs",
        str(outer_jobs),
        "--adapter",
        args.overlay_adapter,
    ]
    return _run_command(
        command,
        cwd=PROJECT_ROOT,
        log_path=log_path,
        env=_subprocess_environment(Path(args.v03_root).resolve()),
    )


def _compare_prefix_diagnostics(
    full: Mapping[str, Any],
    prefix: Mapping[str, Any],
    *,
    rows: int = CAUSAL_PREFIX_ROWS,
) -> dict[str, Any]:
    expected = full.get("prefix_frame_sha256", {}).get(str(rows))
    actual = prefix.get("output_contract", {}).get("frame_exact_sha256")
    passed = isinstance(expected, str) and expected == actual
    return {
        "required": True,
        "rows": int(rows),
        "full_output_prefix_sha256": expected,
        "truncated_input_output_sha256": actual,
        "pass": passed,
    }


def _align_truth(frame: pd.DataFrame, truth: pd.DataFrame) -> pd.DataFrame:
    dates = pd.to_datetime(frame["date"], errors="raise")
    if dates.duplicated().any() or not dates.is_monotonic_increasing:
        raise ValidationError("overlay dates must be unique and increasing")
    truth_frame = truth.copy()
    if "true_fair_pe" not in truth_frame.columns:
        raise ValidationError("synthetic true_fair_pe is missing from truth")
    truth_frame["date"] = pd.to_datetime(truth_frame["date"], errors="raise")
    if truth_frame["date"].duplicated().any():
        raise ValidationError("truth dates must be unique")
    aligned = pd.DataFrame({"date": dates}).merge(
        truth_frame, on="date", how="left", validate="one_to_one"
    )
    if aligned["true_fair_pe"].notna().sum() == 0:
        raise ValidationError("truth did not align to overlay output")
    _require_fair_truth(aligned["true_fair_pe"], context="aligned overlay truth")
    return aligned


def _probability_sets(frame: pd.DataFrame, choices: Mapping[str, Sequence[str]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, columns in choices.items():
        if all(column in frame.columns for column in columns):
            subset = frame[list(columns)].copy()
            subset.columns = list(REGIMES)
            result[name] = subset
    return result


def _optional_expected_pe_metrics(
    *,
    column: str,
    baseline: pd.Series,
    challenger: pd.Series,
    observed: pd.Series,
    fair: pd.Series,
    dates: pd.Series,
    production_scope: np.ndarray,
    effective_config: Mapping[str, Any],
) -> dict[str, Any]:
    """Audit an optional non-selected surface without weakening enabled checks."""

    section_name = OPTIONAL_EXPECTED_PE_CONFIG_SECTIONS[column]
    section = effective_config.get(section_name)
    if not isinstance(section, Mapping) or not isinstance(section.get("enabled"), bool):
        raise ValidationError(
            f"optional expected-P/E surface {column!r} has no boolean "
            f"{section_name}.enabled contract"
        )
    enabled = bool(section["enabled"])
    scope = np.asarray(production_scope, dtype=bool)
    if scope.shape != (len(challenger),):
        raise ValidationError("optional expected-P/E scope has the wrong shape")
    present = challenger.notna().to_numpy(dtype=bool)

    if not enabled:
        if np.any(scope & present):
            raise ValidationError(
                f"disabled optional expected-P/E surface {column!r} emitted values "
                "in the production scope"
            )
        empty_mask = np.zeros(len(challenger), dtype=bool)
        empty_mask_sha256 = _mask_sha(empty_mask, dates)
        return {
            "status": "unavailable",
            "reason": "configured_disabled_and_all_values_missing",
            "optional_surface": True,
            "surface_column": column,
            "config_section": section_name,
            "configured_enabled": False,
            "total_rows": int(len(challenger)),
            "evaluation_scope_rows": int(scope.sum()),
            "common_rows": 0,
            "coverage": 0.0,
            "mask_sha256": empty_mask_sha256,
            "promotion_mask_sha256": empty_mask_sha256,
            "diagnostic_common_rows": 0,
            "diagnostic_coverage": 0.0,
            "diagnostic_mask_sha256": empty_mask_sha256,
            "first_date": None,
            "last_date": None,
            "baseline": None,
            "challenger": None,
            "gain": None,
        }

    metrics = paired_log_metrics(
        baseline,
        challenger,
        observed,
        fair,
        dates,
        forced_mask=scope,
    )
    return {
        "status": "available",
        "optional_surface": True,
        "surface_column": column,
        "config_section": section_name,
        "configured_enabled": True,
        **metrics,
    }


def analyze_overlay_output(
    canonical_path: Path,
    truth_path: Path,
    output_path: Path,
    candidate: Mapping[str, Any],
    effective_config: Mapping[str, Any],
) -> dict[str, Any]:
    _validate_effective_mapping(effective_config)
    canonical = _read_csv(canonical_path)
    truth = _read_csv(truth_path)
    output = _read_csv(output_path)
    if len(output) != len(canonical):
        raise ValidationError("overlay changed the v0.3 row count")
    if list(output.columns[:CANONICAL_V03_COLUMNS]) != list(canonical.columns):
        raise ValidationError("overlay CSV does not retain the canonical150 prefix")
    aligned = _align_truth(output, truth)
    fair = aligned["true_fair_pe"]
    observed = output["observed_pe"]
    selection_column = str(candidate["selection_column"])
    required_promotion_columns = {selection_column, *PROMOTION_COMPARATORS.values()}
    missing = required_promotion_columns.difference(output.columns)
    if missing:
        raise ValidationError(f"dual-comparator columns missing from overlay: {sorted(missing)}")
    output_dates = pd.to_datetime(output["date"], errors="raise")
    production_scope = output_dates.ge(PRODUCTION_EVALUATION_START).to_numpy(dtype=bool)
    if not production_scope.any():
        raise ValidationError("production evaluation scope is empty")
    fair_available = _require_fair_truth(
        fair,
        scope_mask=production_scope,
        context="overlay production evaluation",
    )
    promotion_common = (
        production_scope & fair_available & _positive_finite(output[selection_column])
    )
    for comparator_column in PROMOTION_COMPARATORS.values():
        promotion_common &= _positive_finite(output[comparator_column])
    if not np.array_equal(promotion_common, production_scope):
        missing_rows = int(production_scope.sum() - promotion_common.sum())
        raise ValidationError(
            "dual-comparator promotion requires full natural daily coverage; "
            f"{missing_rows} row(s) are unavailable"
        )
    comparator_metrics = {
        comparator_name: paired_log_metrics(
            output[comparator_column],
            output[selection_column],
            observed,
            fair,
            output["date"],
            forced_mask=promotion_common,
        )
        for comparator_name, comparator_column in PROMOTION_COMPARATORS.items()
    }
    comparator_mask_hashes = {
        metric["promotion_mask_sha256"] for metric in comparator_metrics.values()
    }
    if len(comparator_mask_hashes) != 1:
        raise ValidationError("dual-comparator promotion masks differ")
    candidate_pairs: dict[str, Any] = {}
    for name, (baseline, challenger) in PAIR_DEFINITIONS.items():
        if baseline in output.columns and challenger in output.columns:
            candidate_pairs[name] = paired_log_metrics(
                output[baseline],
                output[challenger],
                observed,
                fair,
                output["date"],
                forced_mask=production_scope,
            )
    versus_anti_gaming: dict[str, Any] = {}
    anti_gaming_column = PROMOTION_ANTI_GAMING_COMPARATOR_COLUMN
    for column in EXPECTED_PE_COLUMNS:
        if column in output.columns:
            if column in OPTIONAL_EXPECTED_PE_CONFIG_SECTIONS and column not in {
                selection_column,
                *PROMOTION_COMPARATORS.values(),
            }:
                versus_anti_gaming[column] = _optional_expected_pe_metrics(
                    column=column,
                    baseline=output[anti_gaming_column],
                    challenger=output[column],
                    observed=observed,
                    fair=fair,
                    dates=output["date"],
                    production_scope=production_scope,
                    effective_config=effective_config,
                )
            else:
                versus_anti_gaming[column] = paired_log_metrics(
                    output[anti_gaming_column],
                    output[column],
                    observed,
                    fair,
                    output["date"],
                    forced_mask=production_scope,
                )

    current_truth = aligned["true_regime"]
    current_sets = _probability_sets(
        output,
        {
            "v03_current_ensemble": ("p_bear", "p_sideways", "p_bull"),
            "v04_current_passthrough": (
                "v04_current_p_bear",
                "v04_current_p_sideways",
                "v04_current_p_bull",
            ),
        },
    )
    current_metrics = {
        name: _regime_metrics(probabilities, current_truth, scope_mask=production_scope)
        for name, probabilities in current_sets.items()
    }
    stacker_config = effective_config.get("regime_stacker", {})
    horizon = int(stacker_config.get("horizon", 21))
    proxy = _forward_return_proxy(
        output["benchmark_close"],
        horizon=horizon,
        bull_threshold=float(stacker_config.get("bull_return_threshold", 0.03)),
        bear_threshold=float(stacker_config.get("bear_return_threshold", -0.03)),
    )
    forecast_sets = _probability_sets(
        output,
        {
            "v04_h21_forward_return": (
                "v04_return_forecast_p_bear",
                "v04_return_forecast_p_sideways",
                "v04_return_forecast_p_bull",
            ),
            "v04_h21_forward_return_legacy": (
                "v04_forecast_p_bear",
                "v04_forecast_p_sideways",
                "v04_forecast_p_bull",
            ),
        },
    )
    forecast_metrics = {
        name: _regime_metrics(probabilities, proxy, scope_mask=production_scope)
        for name, probabilities in forecast_sets.items()
    }
    if not current_metrics:
        raise ValidationError("current-state probabilities are unavailable")
    if not forecast_metrics:
        raise ValidationError("horizon-21 forward-return probabilities are unavailable")

    gate_report = validate_no_harm_gates(output, effective_config)
    if not gate_report["pass"]:
        raise ValidationError(f"no-harm structural gate failed: {gate_report}")
    return {
        "selection_column": selection_column,
        "promotion_comparators": copy.deepcopy(PROMOTION_COMPARATORS),
        "warmup_contract": {
            "overlay_input_rows": int(len(output)),
            "generation_start": GENERATION_START,
            "production_evaluation_start": PRODUCTION_EVALUATION_START,
            "production_scope_rows": int(production_scope.sum()),
            "models_computed_before_evaluation_filter": True,
        },
        "dual_comparator_paired": comparator_metrics,
        "promotion_common_mask": {
            "rows": int(promotion_common.sum()),
            "coverage": float(promotion_common.sum() / production_scope.sum()),
            "sha256": next(iter(comparator_mask_hashes)),
        },
        "candidate_pairs": candidate_pairs,
        "candidate_suite_vs_anti_gaming": versus_anti_gaming,
        "no_harm_gate": gate_report,
        "current_state_truth_metrics": current_metrics,
        "h21_forward_return_proxy_metrics": forecast_metrics,
        "regime_metric_semantics_separated": True,
    }


def _requires_expensive_invariance_check(
    *, stage: str, seed: int, name: str, args: argparse.Namespace
) -> bool:
    assignment = _invariance_assignment(args, name)
    return (
        stage == "tuning"
        and seed == args.tuning_seeds[0]
        and name == assignment["representative_candidate"]
    )


def _run_one_candidate(
    *,
    stage: str,
    seed: int,
    name: str,
    candidate: Mapping[str, Any],
    canonical: Path,
    truth: Path,
    args: argparse.Namespace,
    snapshot: Mapping[str, Any],
) -> dict[str, Any]:
    assert_source_snapshot(snapshot)
    parallel_outer_jobs = _require_determinism_parallel_outer_jobs(args.outer_jobs)
    # Validate in the parent before creating a model subprocess.  The worker
    # repeats this validation to fail closed if its serialized override is altered.
    effective = _validated_effective_config(
        Path(args.v04_config),
        candidate["overrides"],
        model_seed=seed + 500_000,
        outer_jobs=parallel_outer_jobs,
    )
    root = Path(args.output_root).resolve() / "artifacts" / stage / f"seed_{seed}" / "v04" / name
    root.mkdir(parents=True, exist_ok=True)
    overrides_path = root / "candidate_overrides.json"
    _atomic_write_json(overrides_path, candidate["overrides"])
    parallel_csv = root / f"parallel{parallel_outer_jobs}.csv"
    parallel_diagnostics = root / f"parallel{parallel_outer_jobs}_diagnostics.json"
    parallel_log = root / f"parallel{parallel_outer_jobs}.log"
    measurement = _run_v04_adapter(
        input_csv=canonical,
        output_csv=parallel_csv,
        diagnostics_json=parallel_diagnostics,
        overrides_json=overrides_path,
        model_seed=seed + 500_000,
        outer_jobs=parallel_outer_jobs,
        args=args,
        log_path=parallel_log,
    )
    diagnostics = _read_json(parallel_diagnostics)
    evaluation = analyze_overlay_output(canonical, truth, parallel_csv, candidate, effective)
    promotion_evidence = _write_promotion_daily_evidence(
        output_path=parallel_csv,
        truth_path=truth,
        candidate=candidate,
        seed=int(seed),
        evidence_path=root / "promotion_daily_evidence.csv",
    )

    assignment = _invariance_assignment(args, name)
    inherited = str(assignment["representative_candidate"])
    determinism: dict[str, Any] = {
        "required": False,
        "inherited_from": inherited,
        "evidence_seed": int(args.tuning_seeds[0]),
        "comparison": f"serial-vs-{parallel_outer_jobs}",
        "serial_outer_jobs": DETERMINISM_SERIAL_OUTER_JOBS,
        "parallel_outer_jobs": parallel_outer_jobs,
        **assignment,
        "pass": None,
    }
    prefix_invariance: dict[str, Any] = {
        "required": False,
        "inherited_from": inherited,
        "evidence_seed": int(args.tuning_seeds[0]),
        "parallel_outer_jobs": parallel_outer_jobs,
        **assignment,
        "pass": None,
    }
    if _requires_expensive_invariance_check(stage=stage, seed=seed, name=name, args=args):
        serial_csv = root / "serial1.csv"
        serial_diagnostics = root / "serial1_diagnostics.json"
        serial_log = root / "serial1.log"
        serial_measurement = _run_v04_adapter(
            input_csv=canonical,
            output_csv=serial_csv,
            diagnostics_json=serial_diagnostics,
            overrides_json=overrides_path,
            model_seed=seed + 500_000,
            outer_jobs=DETERMINISM_SERIAL_OUTER_JOBS,
            args=args,
            log_path=serial_log,
        )
        serial_diag = _read_json(serial_diagnostics)
        parallel_sha = diagnostics["output_contract"]["frame_exact_sha256"]
        serial_sha = serial_diag["output_contract"]["frame_exact_sha256"]
        determinism = {
            "required": True,
            "representative_candidate": name,
            "evidence_seed": int(seed),
            "comparison": f"serial-vs-{parallel_outer_jobs}",
            "serial_outer_jobs": DETERMINISM_SERIAL_OUTER_JOBS,
            "parallel_outer_jobs": parallel_outer_jobs,
            **assignment,
            "pass": parallel_sha == serial_sha,
            "parallel_frame_sha256": parallel_sha,
            "serial_frame_sha256": serial_sha,
            "parallel_csv_sha256": _file_sha256(parallel_csv),
            "serial_csv_sha256": _file_sha256(serial_csv),
            "serial_runtime": {
                "wall_seconds": serial_measurement.wall_seconds,
                "peak_rss_bytes": serial_measurement.peak_rss_bytes,
                "rss_scope": serial_measurement.rss_scope,
            },
            "serial_csv": _artifact(serial_csv),
            "serial_diagnostics": _artifact(serial_diagnostics),
            "serial_log": _artifact(serial_log),
        }
        if not determinism["pass"]:
            raise ValidationError(
                f"serial-vs-{parallel_outer_jobs} in-memory output is not bit deterministic"
            )

        canonical_frame = _read_csv(canonical)
        prefix_input = root / f"causal_prefix_input_{CAUSAL_PREFIX_ROWS}.csv"
        canonical_prefix = canonical_frame.iloc[:CAUSAL_PREFIX_ROWS].copy()
        canonical_prefix.to_csv(prefix_input, index=False, encoding="utf-8-sig")
        pd.testing.assert_frame_equal(
            _read_csv(prefix_input),
            canonical_prefix,
            check_dtype=True,
            check_exact=True,
            check_names=True,
        )
        prefix_output = root / f"causal_prefix_output_{CAUSAL_PREFIX_ROWS}.csv"
        prefix_diagnostics_path = root / "causal_prefix_diagnostics.json"
        prefix_log = root / "causal_prefix.log"
        prefix_measurement = _run_v04_adapter(
            input_csv=prefix_input,
            output_csv=prefix_output,
            diagnostics_json=prefix_diagnostics_path,
            overrides_json=overrides_path,
            model_seed=seed + 500_000,
            outer_jobs=parallel_outer_jobs,
            args=args,
            log_path=prefix_log,
        )
        prefix_diagnostics = _read_json(prefix_diagnostics_path)
        prefix_invariance = {
            **_compare_prefix_diagnostics(diagnostics, prefix_diagnostics),
            "required": True,
            "representative_candidate": name,
            "evidence_seed": int(seed),
            "parallel_outer_jobs": parallel_outer_jobs,
            **assignment,
            "runtime": {
                "wall_seconds": prefix_measurement.wall_seconds,
                "peak_rss_bytes": prefix_measurement.peak_rss_bytes,
                "rss_scope": prefix_measurement.rss_scope,
            },
            "prefix_input": _artifact(prefix_input),
            "prefix_output": _artifact(prefix_output),
            "prefix_diagnostics": _artifact(prefix_diagnostics_path),
            "prefix_log": _artifact(prefix_log),
        }
        if not prefix_invariance["pass"]:
            raise ValidationError(f"future rows changed the first {CAUSAL_PREFIX_ROWS} output rows")

    assert_source_snapshot(snapshot)
    result = {
        "format_version": RESULT_FORMAT_VERSION,
        "stage": stage,
        "seed": int(seed),
        "candidate": name,
        "candidate_sha256": hashlib.sha256(_canonical_json_bytes(candidate)).hexdigest(),
        "invariance_assignment": assignment,
        "source_config_sha256_at_start_and_end": snapshot["combined_sha256"],
        "promotion_policy_config_sha256": _promotion_policy_config()["policy_config_sha256"],
        "artifacts": {
            "canonical_csv": _artifact(canonical),
            "truth_csv": _artifact(truth),
            "output_csv": _artifact(parallel_csv),
            "diagnostics_json": _artifact(parallel_diagnostics),
            "log": _artifact(parallel_log),
            "overrides_json": _artifact(overrides_path),
        },
        "runtime": {
            "wall_seconds": measurement.wall_seconds,
            "peak_rss_bytes": measurement.peak_rss_bytes,
            "rss_scope": measurement.rss_scope,
        },
        "integration_contract": diagnostics,
        "serial_vs_parallel_determinism": determinism,
        "causal_prefix_invariance": prefix_invariance,
        "promotion_daily_evidence": promotion_evidence,
        "evaluation": evaluation,
        "completed_at_utc": _utc_now(),
    }
    result = _seal_payload(result, "result_sha256")
    result_path = root / "result.json"
    _atomic_write_json(result_path, result)
    result["result_artifact"] = _artifact(result_path)
    return result


def _verify_result_record(
    record: Mapping[str, Any],
    *,
    expected_stage: str | None = None,
    expected_seed: int | None = None,
    expected_candidate: str | None = None,
    expected_candidate_spec: Mapping[str, Any] | None = None,
    expected_source_config_sha256: str | None = None,
    expected_invariance_assignment: Mapping[str, Any] | None = None,
) -> None:
    stored = dict(record)
    result_artifact = stored.pop("result_artifact", None)
    _verify_sealed(stored, "result_sha256", context="candidate result")
    if stored.get("format_version") != RESULT_FORMAT_VERSION:
        raise ValidationError(
            "candidate result predates the prospective policy; use a new output directory"
        )
    if (
        stored.get("promotion_policy_config_sha256")
        != _promotion_policy_config()["policy_config_sha256"]
    ):
        raise ValidationError("candidate result promotion policy is missing or invalid")
    stage = stored.get("stage")
    seed = stored.get("seed")
    candidate = stored.get("candidate")
    source_sha256 = stored.get("source_config_sha256_at_start_and_end")
    if (
        stage not in {"tuning", "heldout"}
        or not isinstance(seed, int)
        or isinstance(seed, bool)
        or seed < 0
        or not isinstance(candidate, str)
        or not SAFE_NAME.fullmatch(candidate)
        or not re.fullmatch(r"[0-9a-f]{64}", str(stored.get("candidate_sha256", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(source_sha256 or ""))
    ):
        raise ValidationError("candidate result identity is malformed")
    if expected_stage is not None and stage != expected_stage:
        raise ValidationError("candidate result stage differs from its checkpoint bucket")
    if expected_seed is not None and seed != int(expected_seed):
        raise ValidationError("candidate result seed differs from its checkpoint bucket")
    if expected_candidate is not None and candidate != expected_candidate:
        raise ValidationError("candidate result name differs from its checkpoint bucket")
    if expected_candidate_spec is not None:
        expected_candidate_sha256 = hashlib.sha256(
            _canonical_json_bytes(expected_candidate_spec)
        ).hexdigest()
        if stored.get("candidate_sha256") != expected_candidate_sha256:
            raise ValidationError("candidate result spec hash differs from the sealed candidate")
    evaluation = stored.get("evaluation")
    if not isinstance(evaluation, Mapping):
        raise ValidationError("candidate result evaluation is missing")
    if evaluation.get("promotion_comparators") != PROMOTION_COMPARATORS:
        raise ValidationError("candidate result promotion comparators are missing or invalid")
    comparator_metrics = evaluation.get("dual_comparator_paired")
    if not isinstance(comparator_metrics, Mapping) or set(comparator_metrics) != set(
        PROMOTION_COMPARATORS
    ):
        raise ValidationError("candidate result dual-comparator metrics are missing or invalid")
    try:
        promotion_hashes = {
            str(comparator_metrics[name]["promotion_mask_sha256"]) for name in PROMOTION_COMPARATORS
        }
    except (KeyError, TypeError) as exc:
        raise ValidationError("candidate result comparator masks are missing") from exc
    if len(promotion_hashes) != 1:
        raise ValidationError("candidate result comparator masks differ")
    common_mask = evaluation.get("promotion_common_mask")
    if (
        not isinstance(common_mask, Mapping)
        or common_mask.get("sha256") != next(iter(promotion_hashes))
        or float(common_mask.get("coverage", -1.0)) != 1.0
    ):
        raise ValidationError("candidate result common promotion mask is invalid")
    try:
        common_rows = int(common_mask["rows"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("candidate result common promotion row count is invalid") from exc
    if common_rows < PROMOTION_MINIMUM_COMMON_ROWS or any(
        int(comparator_metrics[name].get("common_rows", -1)) != common_rows
        or int(comparator_metrics[name].get("evaluation_scope_rows", -1)) != common_rows
        or float(comparator_metrics[name].get("coverage", -1.0)) != 1.0
        for name in PROMOTION_COMPARATORS
    ):
        raise ValidationError("candidate result comparator coverage differs")
    if expected_candidate_spec is not None and evaluation.get("selection_column") != str(
        expected_candidate_spec["selection_column"]
    ):
        raise ValidationError("candidate result selection column differs from the sealed candidate")
    if expected_source_config_sha256 is not None and source_sha256 != expected_source_config_sha256:
        raise ValidationError("candidate result source/config hash differs from the manifest")
    if (
        expected_invariance_assignment is not None
        and stored.get("invariance_assignment") != expected_invariance_assignment
    ):
        raise ValidationError("candidate result invariance assignment differs from the manifest")
    if result_artifact is not None:
        result_path = _verify_artifact(result_artifact, context="candidate result JSON")
        disk = _read_json(result_path)
        _verify_sealed(disk, "result_sha256", context="candidate result JSON")
        if disk != stored:
            raise ValidationError("checkpoint result and result.json differ")
    for name, artifact in stored["artifacts"].items():
        _verify_artifact(artifact, context=f"candidate result {name}")
    try:
        evidence_seed = int(stored["seed"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("candidate result seed is missing") from exc
    _load_promotion_daily_evidence(
        stored.get("promotion_daily_evidence", {}),
        expected_seed=evidence_seed,
        expected_challenger_column=str(stored.get("evaluation", {}).get("selection_column", "")),
    )
    determinism = stored.get("serial_vs_parallel_determinism", {})
    for name in ("serial_csv", "serial_diagnostics", "serial_log"):
        if name in determinism:
            _verify_artifact(determinism[name], context=f"determinism {name}")
    prefix = stored.get("causal_prefix_invariance", {})
    for name in ("prefix_input", "prefix_output", "prefix_diagnostics", "prefix_log"):
        if name in prefix:
            _verify_artifact(prefix[name], context=f"prefix invariance {name}")
    assignment = stored.get("invariance_assignment")
    if not isinstance(assignment, Mapping):
        raise ValidationError("candidate result has no invariance assignment")
    required_assignment_keys = {
        "group_id",
        "signature_sha256",
        "representative_candidate",
    }
    if set(assignment) != required_assignment_keys:
        raise ValidationError("candidate result has an invalid invariance assignment")
    for context, evidence in (
        ("serial/parallel", determinism),
        ("causal-prefix", prefix),
    ):
        if not isinstance(evidence, Mapping):
            raise ValidationError(f"candidate result has no {context} evidence")
        for key in required_assignment_keys:
            if evidence.get(key) != assignment[key]:
                raise ValidationError(f"candidate result {context} assignment differs")
        if evidence.get("parallel_outer_jobs") != DETERMINISM_PARALLEL_OUTER_JOBS:
            raise ValidationError(f"candidate result {context} parallel worker count differs")
        if context == "serial/parallel" and (
            evidence.get("comparison") != f"serial-vs-{DETERMINISM_PARALLEL_OUTER_JOBS}"
            or evidence.get("serial_outer_jobs") != DETERMINISM_SERIAL_OUTER_JOBS
        ):
            raise ValidationError("candidate result determinism comparison differs")
        required = evidence.get("required")
        if required is True:
            if (
                stored.get("stage") != "tuning"
                or stored.get("candidate") != assignment["representative_candidate"]
                or evidence.get("evidence_seed") != stored.get("seed")
                or evidence.get("pass") is not True
            ):
                raise ValidationError(f"candidate result has invalid required {context} evidence")
        elif required is False:
            if (
                evidence.get("inherited_from") != assignment["representative_candidate"]
                or evidence.get("pass") is not None
            ):
                raise ValidationError(f"candidate result has invalid inherited {context} evidence")
        else:
            raise ValidationError(f"candidate result has ambiguous {context} requirement")


def _verified_invariance_group_evidence(
    checkpoint: Mapping[str, Any],
    candidates: Mapping[str, Mapping[str, Any]],
    plan: Mapping[str, Any],
    *,
    first_tuning_seed: int,
) -> dict[str, Any]:
    """Resolve inheritance from one sealed, passing representative per exact group."""

    _verify_invariance_plan(plan, candidate_names=candidates)
    first_seed_runs = checkpoint.get("runs", {}).get("tuning", {}).get(str(first_tuning_seed), {})
    if not isinstance(first_seed_runs, Mapping):
        raise ValidationError("first tuning seed has no candidate results")
    verified: dict[str, Any] = {}
    for group_id, group in plan["groups"].items():
        representative = str(group["representative_candidate"])
        record = first_seed_runs.get(representative)
        if not isinstance(record, Mapping):
            raise ValidationError(
                f"invariance representative {representative!r} is missing for group {group_id}"
            )
        _verify_result_record(
            record,
            expected_stage="tuning",
            expected_seed=int(first_tuning_seed),
            expected_candidate=representative,
            expected_candidate_spec=candidates[representative],
            expected_invariance_assignment=plan["candidate_assignments"][representative],
        )
        assignment = plan["candidate_assignments"][representative]
        if (
            record.get("stage") != "tuning"
            or record.get("seed") != int(first_tuning_seed)
            or record.get("candidate") != representative
            or record.get("invariance_assignment") != assignment
        ):
            raise ValidationError(f"invariance representative record is mismatched: {group_id}")
        evidence_records: dict[str, Any] = {}
        for key in ("serial_vs_parallel_determinism", "causal_prefix_invariance"):
            evidence = record.get(key)
            if not isinstance(evidence, Mapping):
                raise ValidationError(f"invariance representative lacks {key}: {group_id}")
            if (
                evidence.get("required") is not True
                or evidence.get("pass") is not True
                or evidence.get("evidence_seed") != int(first_tuning_seed)
                or any(evidence.get(field) != value for field, value in assignment.items())
            ):
                raise ValidationError(f"invariance representative failed {key}: {group_id}")
            evidence_records[key] = {
                "required": True,
                "pass": True,
                "representative_candidate": representative,
                "evidence_seed": int(first_tuning_seed),
            }
        verified[group_id] = {
            "group_id": group_id,
            "signature_sha256": group["signature_sha256"],
            "representative_candidate": representative,
            "candidates": list(group["candidates"]),
            "representative_result_sha256": record["result_sha256"],
            **evidence_records,
        }
    return verified


def _run_stage(
    stage: str,
    seeds: Sequence[int],
    candidates: Mapping[str, Mapping[str, Any]],
    args: argparse.Namespace,
    manifest: Mapping[str, Any],
) -> None:
    checkpoint_path = Path(args.output_root).resolve() / "checkpoint.json"
    checkpoint = _load_checkpoint(checkpoint_path, str(manifest["manifest_sha256"]))
    snapshot = manifest["source_snapshot"]
    for seed in seeds:
        canonical, truth, _, checkpoint = _ensure_v03_input(
            stage=stage,
            seed=int(seed),
            args=args,
            checkpoint=checkpoint,
            checkpoint_path=checkpoint_path,
        )
        for name, candidate in candidates.items():
            seed_runs = checkpoint["runs"][stage].setdefault(str(seed), {})
            existing = seed_runs.get(name)
            if existing is not None:
                _verify_result_record(
                    existing,
                    expected_stage=stage,
                    expected_seed=int(seed),
                    expected_candidate=name,
                    expected_candidate_spec=candidate,
                    expected_source_config_sha256=str(snapshot["combined_sha256"]),
                    expected_invariance_assignment=args.invariance_plan["candidate_assignments"][
                        name
                    ],
                )
                print(f"[resume] {stage} seed={seed} candidate={name}")
                continue
            print(f"[run] {stage} seed={seed} candidate={name}", flush=True)
            record = _run_one_candidate(
                stage=stage,
                seed=int(seed),
                name=name,
                candidate=candidate,
                canonical=canonical,
                truth=truth,
                args=args,
                snapshot=snapshot,
            )
            _verify_result_record(
                record,
                expected_stage=stage,
                expected_seed=int(seed),
                expected_candidate=name,
                expected_candidate_spec=candidate,
                expected_source_config_sha256=str(snapshot["combined_sha256"]),
                expected_invariance_assignment=args.invariance_plan["candidate_assignments"][name],
            )
            checkpoint["runs"][stage].setdefault(str(seed), {})[name] = record
            checkpoint = _write_checkpoint(checkpoint_path, checkpoint)
            primary = record["evaluation"]["dual_comparator_paired"][PROMOTION_PRIMARY_COMPARATOR]
            print(
                f"  fair MAE={primary['challenger']['fair_log_mae']:.8f} "
                f"gain={primary['gain']['fair_log_mae']:+.8f} "
                f"wall={record['runtime']['wall_seconds']:.2f}s",
                flush=True,
            )
    assert_source_snapshot(snapshot)
    checkpoint["stage_completions"][stage] = {
        "completed_at_utc": _utc_now(),
        "seeds": [int(seed) for seed in seeds],
        "candidates": sorted(candidates),
        "source_config_sha256_at_start": snapshot["combined_sha256"],
        "source_config_sha256_at_end": source_snapshot(
            Path(snapshot["v03"]["root"]), Path(snapshot["v04"]["root"])
        )["combined_sha256"],
    }
    _write_checkpoint(checkpoint_path, checkpoint)


def _common_tuning_metrics(
    checkpoint: Mapping[str, Any],
    seeds: Sequence[int],
    candidates: Mapping[str, Mapping[str, Any]],
    *,
    tolerance_fraction: float,
    invariance_plan: Mapping[str, Any],
    policy_config: Mapping[str, Any],
    source_config_sha256: str,
) -> dict[str, Any]:
    if not seeds:
        raise ValidationError("tuning metrics require at least one seed")
    invariance_evidence = _verified_invariance_group_evidence(
        checkpoint,
        candidates,
        invariance_plan,
        first_tuning_seed=int(seeds[0]),
    )
    by_candidate: dict[str, list[dict[str, Any]]] = {name: [] for name in candidates}
    daily_by_candidate: dict[str, dict[int, pd.DataFrame]] = {name: {} for name in candidates}
    masks: dict[str, Any] = {}
    for seed in seeds:
        seed_records = checkpoint["runs"]["tuning"].get(str(seed), {})
        missing = set(candidates).difference(seed_records)
        if missing:
            raise ValidationError(f"tuning seed {seed} is incomplete: {sorted(missing)}")
        frames: dict[str, pd.DataFrame] = {}
        truth_frame: pd.DataFrame | None = None
        aligned: pd.DataFrame | None = None
        shared: np.ndarray | None = None
        dates: pd.Series | None = None
        observed: pd.Series | None = None
        fair: pd.Series | None = None
        for name, candidate in candidates.items():
            record = seed_records[name]
            _verify_result_record(
                record,
                expected_stage="tuning",
                expected_seed=int(seed),
                expected_candidate=name,
                expected_candidate_spec=candidate,
                expected_source_config_sha256=source_config_sha256,
                expected_invariance_assignment=invariance_plan["candidate_assignments"][name],
            )
            daily_by_candidate[name][int(seed)] = _load_promotion_daily_evidence(
                record.get("promotion_daily_evidence", {}),
                expected_seed=int(seed),
                expected_challenger_column=str(candidate["selection_column"]),
            )
            frame = _read_csv(
                _verify_artifact(record["artifacts"]["output_csv"], context="tuning output")
            )
            frames[name] = frame
            if truth_frame is None:
                truth_frame = _read_csv(
                    _verify_artifact(record["artifacts"]["truth_csv"], context="tuning truth")
                )
                aligned = _align_truth(frame, truth_frame)
                dates = frame["date"]
                observed = frame["observed_pe"]
                fair = aligned["true_fair_pe"]
                production_scope = (
                    pd.to_datetime(dates, errors="raise")
                    .ge(PRODUCTION_EVALUATION_START)
                    .to_numpy(dtype=bool)
                )
                fair_available = _require_fair_truth(
                    fair,
                    scope_mask=production_scope,
                    context=f"tuning seed {seed}",
                )
                shared = production_scope & fair_available
            assert shared is not None
            selection = str(candidate["selection_column"])
            missing_columns = {selection, *PROMOTION_COMPARATORS.values()}.difference(frame)
            if missing_columns:
                raise ValidationError(
                    f"dual-comparator columns missing for {name}/seed {seed}: "
                    f"{sorted(missing_columns)}"
                )
            shared &= _positive_finite(frame[selection])
            for comparator_column in PROMOTION_COMPARATORS.values():
                shared &= _positive_finite(frame[comparator_column])
        assert (
            dates is not None and observed is not None and fair is not None and shared is not None
        )
        if not shared.any():
            raise ValidationError(f"cross-candidate common mask is empty for seed {seed}")
        if int(shared.sum()) != int(production_scope.sum()):
            raise ValidationError(f"tuning seed {seed} lacks full daily paired fair evidence")
        masks[str(seed)] = {
            "production_scope_rows": int(production_scope.sum()),
            "promotion_fair_truth_rows": int(fair_available.sum()),
            "rows": int(shared.sum()),
            "coverage": float(shared.sum() / production_scope.sum()),
            "sha256": _mask_sha(shared, dates),
        }
        for name, candidate in candidates.items():
            comparator_metrics = {
                comparator_name: paired_log_metrics(
                    frames[name][comparator_column],
                    frames[name][str(candidate["selection_column"])],
                    observed,
                    fair,
                    dates,
                    forced_mask=shared,
                )
                for comparator_name, comparator_column in PROMOTION_COMPARATORS.items()
            }
            if (
                len({metric["promotion_mask_sha256"] for metric in comparator_metrics.values()})
                != 1
            ):
                raise ValidationError(f"candidate {name!r} comparator masks differ")
            record = seed_records[name]
            metric_row: dict[str, Any] = {
                "seed": int(seed),
                "comparators": comparator_metrics,
                "structural_no_harm_pass": bool(record["evaluation"]["no_harm_gate"]["pass"]),
            }
            assignment = invariance_plan["candidate_assignments"][name]
            if record.get("invariance_assignment") != assignment:
                raise ValidationError(f"candidate {name!r} inherited from a different model config")
            group_evidence = invariance_evidence.get(assignment["group_id"])
            if not isinstance(group_evidence, Mapping):
                raise ValidationError(f"candidate {name!r} has no verified invariance evidence")
            metric_row["invariance_group_id"] = assignment["group_id"]
            metric_row["invariance_signature_sha256"] = assignment["signature_sha256"]
            metric_row["invariance_representative_candidate"] = assignment[
                "representative_candidate"
            ]
            metric_row["determinism_pass"] = (
                group_evidence["serial_vs_parallel_determinism"]["pass"] is True
            )
            metric_row["causal_prefix_invariance_pass"] = (
                group_evidence["causal_prefix_invariance"]["pass"] is True
            )
            by_candidate[name].append(metric_row)

    summaries: dict[str, Any] = {}
    tolerance = float(tolerance_fraction)
    for name, rows in by_candidate.items():
        summaries[name] = _summarize_tuning_candidate(
            rows,
            tolerance_fraction=tolerance,
            invariance_assignment=invariance_plan["candidate_assignments"][name],
            daily_evidence_by_seed=daily_by_candidate[name],
            policy_config=policy_config,
        )
    return {
        "metric_roles": _metric_roles_contract(),
        "invariance_plan_sha256": invariance_plan["invariance_plan_sha256"],
        "invariance_group_evidence": invariance_evidence,
        "common_masks": masks,
        "candidates": summaries,
    }


def _select_candidate(common: Mapping[str, Any]) -> str:
    _verify_metric_roles(common.get("metric_roles"), context="tuning selection")
    eligible = [
        name for name, summary in common["candidates"].items() if summary["eligible_for_lock"]
    ]
    if not eligible:
        raise ValidationError(
            "no tuning candidate passed prospective determinism/statistical gates"
        )

    def rank(name: str) -> tuple[float, str]:
        summary = common["candidates"][name]
        comparator_summaries = summary.get("comparators")
        if not isinstance(comparator_summaries, Mapping) or set(comparator_summaries) != set(
            PROMOTION_COMPARATORS
        ):
            raise ValidationError(f"candidate {name!r} lacks dual-comparator rank metrics")
        gains: list[float] = []
        for comparator_name in PROMOTION_COMPARATORS:
            for metric in PROMOTION_METRICS:
                try:
                    value = float(
                        comparator_summaries[comparator_name]["aggregate"][metric][
                            "relative_mean_gain"
                        ]
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValidationError(
                        f"candidate {name!r} lacks fair-truth dual-comparator rank metrics"
                    ) from exc
                if not math.isfinite(value):
                    raise ValidationError(f"candidate {name!r} has invalid fair-truth rank metrics")
                gains.append(value)
        worst_gain = min(gains)
        recorded = summary.get("worst_relative_pooled_gain_across_comparator_metrics")
        if recorded is None or float(recorded) != worst_gain:
            raise ValidationError(f"candidate {name!r} worst-gain rank summary differs")
        return -worst_gain, name

    return min(eligible, key=rank)


def _assert_heldout_unopened_before_lock(
    root: Path,
    checkpoint: Mapping[str, Any],
) -> None:
    try:
        heldout_inputs = checkpoint["inputs"]["heldout"]
        heldout_runs = checkpoint["runs"]["heldout"]
    except (KeyError, TypeError) as exc:
        raise ValidationError("checkpoint heldout state is malformed") from exc
    if not isinstance(heldout_inputs, Mapping) or not isinstance(heldout_runs, Mapping):
        raise ValidationError("checkpoint heldout state is malformed")
    if heldout_inputs or heldout_runs:
        raise ValidationError("heldout checkpoint evidence exists before candidate lock")

    heldout_tree = root / "artifacts" / "heldout"
    report = root / "heldout_report.json"
    report_temporaries = tuple(root.glob(".heldout_report.json.*.tmp")) if root.is_dir() else ()
    if heldout_tree.exists() or report.exists() or report_temporaries:
        discovered = [
            str(path) for path in (heldout_tree, report, *report_temporaries) if path.exists()
        ]
        raise ValidationError(
            f"planned/untracked heldout artifacts exist before candidate lock: {discovered}"
        )


def _lock_candidate(
    args: argparse.Namespace,
    manifest: Mapping[str, Any],
    candidates: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    root = Path(args.output_root).resolve()
    metric_roles = manifest.get("metric_roles")
    _verify_metric_roles(metric_roles, context="run manifest")
    policy_config = manifest.get("promotion_policy_config")
    _verify_promotion_policy_config(policy_config, context="run manifest")
    policy_lock_sha256 = manifest.get("promotion_policy_lock_sha256")
    if not isinstance(policy_lock_sha256, str):
        raise ValidationError("run manifest has no prospective policy-lock hash")
    invariance_plan = manifest.get("invariance_plan")
    if not isinstance(invariance_plan, Mapping):
        raise ValidationError("run manifest has no invariance plan")
    _verify_invariance_plan(invariance_plan, candidate_names=candidates)
    lock_path = root / "candidate.lock.json"
    checkpoint = _load_checkpoint(root / "checkpoint.json", str(manifest["manifest_sha256"]))
    _assert_heldout_unopened_before_lock(root, checkpoint)
    if lock_path.exists():
        existing = _read_json(lock_path)
        _verify_sealed(existing, "lock_sha256", context="candidate lock")
        selected = str(existing.get("selected_candidate", ""))
        if (
            existing.get("format_version") != LOCK_FORMAT_VERSION
            or existing.get("manifest_sha256") != manifest["manifest_sha256"]
            or existing.get("promotion_policy_lock_sha256") != policy_lock_sha256
            or existing.get("promotion_policy_config_sha256")
            != policy_config["policy_config_sha256"]
            or existing.get("spent_seed_reservation") != manifest.get("spent_seed_reservation")
            or selected not in candidates
            or existing.get("selected_spec") != candidates[selected]
            or existing.get("selected_spec_sha256")
            != hashlib.sha256(_canonical_json_bytes(candidates[selected])).hexdigest()
            or existing.get("checkpoint_sha256_at_lock") != checkpoint["checkpoint_sha256"]
            or existing.get("heldout_opened") is not False
            or existing.get("promotion_comparators") != PROMOTION_COMPARATORS
            or existing.get("invariance_plan_sha256") != invariance_plan["invariance_plan_sha256"]
            or existing.get("selected_invariance_assignment")
            != invariance_plan["candidate_assignments"].get(selected)
            or existing.get("metric_roles") != metric_roles
        ):
            raise ValidationError("existing candidate lock conflicts with this manifest")
        metrics_path = _verify_artifact(existing["tuning_metrics"], context="locked tuning metrics")
        existing_metrics = _read_json(metrics_path)
        _verify_sealed(
            existing_metrics,
            "tuning_metrics_sha256",
            context="locked tuning metrics",
        )
        _verify_metric_roles(existing_metrics.get("metric_roles"), context="tuning metrics")
        if (
            existing_metrics.get("format_version") != REPORT_FORMAT_VERSION
            or existing_metrics.get("manifest_sha256") != manifest["manifest_sha256"]
            or existing_metrics.get("promotion_policy_lock_sha256") != policy_lock_sha256
            or existing_metrics.get("promotion_policy_config_sha256")
            != policy_config["policy_config_sha256"]
            or existing_metrics.get("spent_seed_reservation")
            != manifest.get("spent_seed_reservation")
        ):
            raise ValidationError("locked tuning metrics predate the prospective policy")
        existing_summaries = existing_metrics.get("candidates")
        if not isinstance(existing_summaries, Mapping) or set(existing_summaries) != set(
            candidates
        ):
            raise ValidationError("locked tuning metrics candidate set differs")
        for candidate_name, candidate_summary in existing_summaries.items():
            _verify_dual_candidate_summary(
                candidate_summary,
                policy_config=policy_config,
                context=f"existing tuning candidate {candidate_name}",
            )
        if _select_candidate(existing_metrics) != selected:
            raise ValidationError("existing candidate lock no longer matches sealed tuning rank")
        selected_summary = existing_metrics.get("candidates", {}).get(selected)
        if not isinstance(selected_summary, Mapping):
            raise ValidationError("existing candidate lock lacks its tuning summary")
        _verify_dual_candidate_summary(
            selected_summary,
            policy_config=policy_config,
            context="existing candidate lock",
        )
        if selected_summary.get("eligible_for_lock") is not True:
            raise ValidationError("existing locked candidate failed prospective tuning gates")
        selected_group = existing["selected_invariance_assignment"]["group_id"]
        verified_evidence = _verified_invariance_group_evidence(
            checkpoint,
            candidates,
            invariance_plan,
            first_tuning_seed=int(args.tuning_seeds[0]),
        )
        if (
            existing_metrics.get("invariance_plan_sha256")
            != invariance_plan["invariance_plan_sha256"]
            or existing.get("selected_invariance_evidence")
            != existing_metrics.get("invariance_group_evidence", {}).get(selected_group)
            or existing.get("selected_invariance_evidence") != verified_evidence.get(selected_group)
        ):
            raise ValidationError("existing candidate lock has invalid invariance evidence")
        return existing
    common = _common_tuning_metrics(
        checkpoint,
        args.tuning_seeds,
        candidates,
        tolerance_fraction=float(args.no_harm_tolerance),
        invariance_plan=invariance_plan,
        policy_config=manifest["promotion_policy_config"],
        source_config_sha256=str(manifest["source_config_sha256_at_start"]),
    )
    _verify_metric_roles(common.get("metric_roles"), context="computed tuning metrics")
    for candidate_name, candidate_summary in common["candidates"].items():
        _verify_dual_candidate_summary(
            candidate_summary,
            policy_config=policy_config,
            context=f"computed tuning candidate {candidate_name}",
        )
    common_payload = _seal_payload(
        {
            "format_version": REPORT_FORMAT_VERSION,
            "manifest_sha256": manifest["manifest_sha256"],
            "promotion_policy_lock_sha256": policy_lock_sha256,
            "promotion_policy_config_sha256": policy_config["policy_config_sha256"],
            "spent_seed_reservation": manifest["spent_seed_reservation"],
            "created_at_utc": _utc_now(),
            "invariance_plan_sha256": invariance_plan["invariance_plan_sha256"],
            **common,
        },
        "tuning_metrics_sha256",
    )
    common_path = root / "tuning_common_metrics.json"
    _atomic_write_json(common_path, common_payload)
    try:
        selected = _select_candidate(common)
    except ValidationError:
        rejection = _seal_payload(
            {
                "manifest_sha256": manifest["manifest_sha256"],
                "tuning_metrics": _artifact(common_path),
                "metric_roles": metric_roles,
                "promotion_policy_lock_sha256": policy_lock_sha256,
                "reason": "no candidate passed prospective tuning statistical gates",
                "created_at_utc": _utc_now(),
            },
            "rejection_sha256",
        )
        _atomic_write_json(root / "lock_rejected.json", rejection)
        raise
    payload = {
        "format_version": LOCK_FORMAT_VERSION,
        "manifest_sha256": manifest["manifest_sha256"],
        "promotion_policy_lock_sha256": policy_lock_sha256,
        "promotion_policy_config_sha256": policy_config["policy_config_sha256"],
        "spent_seed_reservation": manifest["spent_seed_reservation"],
        "checkpoint_sha256_at_lock": checkpoint["checkpoint_sha256"],
        "tuning_metrics": _artifact(common_path),
        "selected_candidate": selected,
        "selected_spec": candidates[selected],
        "selected_spec_sha256": hashlib.sha256(
            _canonical_json_bytes(candidates[selected])
        ).hexdigest(),
        "promotion_comparators": copy.deepcopy(PROMOTION_COMPARATORS),
        "metric_roles": metric_roles,
        "invariance_plan_sha256": invariance_plan["invariance_plan_sha256"],
        "selected_invariance_assignment": invariance_plan["candidate_assignments"][selected],
        "selected_invariance_evidence": common["invariance_group_evidence"][
            invariance_plan["candidate_assignments"][selected]["group_id"]
        ],
        "tuning_seeds_consumed": list(args.tuning_seeds),
        "heldout_seed_commitment_sha256": hashlib.sha256(
            _canonical_json_bytes({"locked_seeds": list(args.locked_seeds)})
        ).hexdigest(),
        "locked_at_utc": _utc_now(),
        "heldout_opened": False,
    }
    sealed = _seal_payload(payload, "lock_sha256")
    _atomic_write_json(lock_path, sealed)
    return sealed


def _heldout_report(
    args: argparse.Namespace,
    manifest: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> dict[str, Any]:
    root = Path(args.output_root).resolve()
    checkpoint = _load_checkpoint(root / "checkpoint.json", str(manifest["manifest_sha256"]))
    selected = str(lock["selected_candidate"])
    spec = lock["selected_spec"]
    manifest_candidates = manifest.get("candidates")
    if (
        not isinstance(manifest_candidates, Mapping)
        or selected not in manifest_candidates
        or manifest_candidates[selected] != spec
    ):
        raise ValidationError("candidate lock spec differs from the run manifest")
    metric_roles = manifest.get("metric_roles")
    _verify_metric_roles(metric_roles, context="run manifest")
    policy_config = manifest.get("promotion_policy_config")
    _verify_promotion_policy_config(policy_config, context="heldout report")
    if (
        lock.get("format_version") != LOCK_FORMAT_VERSION
        or lock.get("manifest_sha256") != manifest["manifest_sha256"]
        or lock.get("promotion_policy_lock_sha256") != manifest.get("promotion_policy_lock_sha256")
        or lock.get("promotion_policy_config_sha256") != policy_config["policy_config_sha256"]
        or lock.get("spent_seed_reservation") != manifest.get("spent_seed_reservation")
        or lock.get("promotion_comparators") != PROMOTION_COMPARATORS
        or lock.get("selected_spec_sha256")
        != hashlib.sha256(_canonical_json_bytes(spec)).hexdigest()
        or lock.get("heldout_opened") is not False
    ):
        raise ValidationError("candidate lock predates or differs from prospective policy")
    if lock.get("metric_roles") != metric_roles:
        raise ValidationError("candidate lock metric roles differ from the run manifest")
    invariance_plan = manifest.get("invariance_plan")
    if not isinstance(invariance_plan, Mapping):
        raise ValidationError("run manifest has no invariance plan")
    _verify_invariance_plan(invariance_plan)
    assignment = invariance_plan["candidate_assignments"].get(selected)
    if (
        not isinstance(assignment, Mapping)
        or lock.get("invariance_plan_sha256") != invariance_plan["invariance_plan_sha256"]
        or lock.get("selected_invariance_assignment") != assignment
    ):
        raise ValidationError("candidate lock has invalid invariance assignment")
    selected_evidence = lock.get("selected_invariance_evidence")
    verified_evidence = _verified_invariance_group_evidence(
        checkpoint,
        manifest_candidates,
        invariance_plan,
        first_tuning_seed=int(args.tuning_seeds[0]),
    ).get(assignment["group_id"])
    if (
        not isinstance(selected_evidence, Mapping)
        or selected_evidence.get("group_id") != assignment["group_id"]
        or selected_evidence.get("signature_sha256") != assignment["signature_sha256"]
        or selected_evidence.get("representative_candidate")
        != assignment["representative_candidate"]
        or selected_evidence.get("serial_vs_parallel_determinism", {}).get("pass") is not True
        or selected_evidence.get("causal_prefix_invariance", {}).get("pass") is not True
        or selected_evidence != verified_evidence
    ):
        raise ValidationError("candidate lock has missing or failed invariance evidence")
    rows: list[dict[str, Any]] = []
    daily_evidence_by_seed: dict[int, pd.DataFrame] = {}
    runtime_wall = 0.0
    peak_rss: int | None = None
    for seed in args.locked_seeds:
        record = checkpoint["runs"]["heldout"].get(str(seed), {}).get(selected)
        if record is None:
            raise ValidationError(f"heldout seed {seed} is incomplete")
        _verify_result_record(
            record,
            expected_stage="heldout",
            expected_seed=int(seed),
            expected_candidate=selected,
            expected_candidate_spec=spec,
            expected_source_config_sha256=str(manifest["source_config_sha256_at_start"]),
            expected_invariance_assignment=assignment,
        )
        if record.get("invariance_assignment") != assignment:
            raise ValidationError(f"heldout seed {seed} has a different invariance assignment")
        comparator_metrics = copy.deepcopy(record["evaluation"]["dual_comparator_paired"])
        if not isinstance(comparator_metrics, Mapping) or set(comparator_metrics) != set(
            PROMOTION_COMPARATORS
        ):
            raise ValidationError(f"heldout seed {seed} lacks dual-comparator metrics")
        rows.append(
            {
                "seed": int(seed),
                "comparators": comparator_metrics,
                "structural_no_harm_pass": bool(record["evaluation"]["no_harm_gate"]["pass"]),
                "determinism_pass": True,
                "causal_prefix_invariance_pass": True,
            }
        )
        daily_evidence_by_seed[int(seed)] = _load_promotion_daily_evidence(
            record.get("promotion_daily_evidence", {}),
            expected_seed=int(seed),
            expected_challenger_column=str(spec["selection_column"]),
        )
        runtime_wall += float(record["runtime"]["wall_seconds"])
        rss = record["runtime"].get("peak_rss_bytes")
        if rss is not None:
            peak_rss = int(rss) if peak_rss is None else max(peak_rss, int(rss))

    tolerance = float(args.no_harm_tolerance)
    prospective_summary = _summarize_tuning_candidate(
        rows,
        tolerance_fraction=tolerance,
        invariance_assignment=assignment,
        daily_evidence_by_seed=daily_evidence_by_seed,
        policy_config=policy_config,
    )
    _verify_dual_candidate_summary(
        prospective_summary,
        policy_config=policy_config,
        context="heldout candidate",
    )
    promotion = bool(prospective_summary["eligible_for_lock"])
    payload = _seal_payload(
        {
            "format_version": REPORT_FORMAT_VERSION,
            "manifest_sha256": manifest["manifest_sha256"],
            "lock_sha256": lock["lock_sha256"],
            "promotion_policy_lock_sha256": manifest["promotion_policy_lock_sha256"],
            "promotion_policy_config_sha256": policy_config["policy_config_sha256"],
            "spent_seed_reservation": manifest["spent_seed_reservation"],
            "candidate": selected,
            "candidate_spec": spec,
            "promotion_comparators": copy.deepcopy(PROMOTION_COMPARATORS),
            "metric_roles": metric_roles,
            "invariance_plan_sha256": invariance_plan["invariance_plan_sha256"],
            "selected_invariance_assignment": assignment,
            "selected_invariance_evidence": selected_evidence,
            "tuning_seeds": list(args.tuning_seeds),
            "heldout_seeds": list(args.locked_seeds),
            "seed_sets_disjoint": True,
            "per_seed_dual_comparator": rows,
            "comparators": prospective_summary["comparators"],
            "worst_relative_pooled_gain_across_comparator_metrics": prospective_summary[
                "worst_relative_pooled_gain_across_comparator_metrics"
            ],
            "prospective_deterministic_gates": prospective_summary[
                "prospective_deterministic_gates"
            ],
            "prospective_block_bootstrap": prospective_summary["prospective_block_bootstrap"],
            "promotion_no_harm_tolerance_fraction": tolerance,
            "worst_degradation_fraction_across_promotion_metrics": prospective_summary[
                "worst_degradation_fraction_across_promotion_metrics"
            ],
            "worst_degradation_fraction_across_diagnostic_only_metrics": prospective_summary[
                "worst_degradation_fraction_across_diagnostic_only_metrics"
            ],
            "promotion_pass": promotion,
            "runtime": {
                "overlay_wall_seconds_sum": runtime_wall,
                "max_process_tree_peak_rss_bytes": peak_rss,
                "rss_scope": "process_tree_sum_sampled_50ms",
            },
            "source_config_sha256_at_start_and_end": manifest["source_config_sha256_at_start"],
            "completed_at_utc": _utc_now(),
        },
        "report_sha256",
    )
    _atomic_write_json(root / "heldout_report.json", payload)
    return payload


def _prepare_common(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    # This is the first validation after argument parsing.  It must precede source
    # probing, manifest/output writes and the global seed reservation.
    args.output_root = _require_managed_output_root(Path(args.output_root))
    args.v03_root = Path(args.v03_root).resolve()
    args.v03_python = Path(args.v03_python).resolve()
    args.v03_config = Path(args.v03_config).resolve()
    args.v04_config = Path(args.v04_config).resolve()
    args.tuning_seeds = parse_seeds(args.tuning_seeds)
    args.locked_seeds = parse_seeds(args.locked_seeds)
    validate_seed_design(args.tuning_seeds, args.locked_seeds)
    if args.generation_start != GENERATION_START:
        raise ValidationError(
            f"generation start is locked to {GENERATION_START} for the full warm-up"
        )
    if args.evaluation_start != PRODUCTION_EVALUATION_START:
        raise ValidationError(
            f"production evaluation start is locked to {PRODUCTION_EVALUATION_START}"
        )
    args.outer_jobs = _require_determinism_parallel_outer_jobs(args.outer_jobs)
    if float(args.no_harm_tolerance) != PROMOTION_WORST_SEED_DEGRADATION_CAP:
        raise ValidationError("prospective material-harm cap is sealed at 0.005 and is not tunable")
    candidates = load_candidates(Path(args.candidates_json) if args.candidates_json else None)
    # Candidate JSON is untrusted input.  Validate every merged effective config
    # before even probing/spawning the v0.3 interpreter or generating seed data.
    effective_configs: dict[str, dict[str, Any]] = {}
    for name, candidate in candidates.items():
        effective_configs[name] = _validated_effective_config(
            args.v04_config,
            candidate["overrides"],
            model_seed=args.tuning_seeds[0] + 500_000,
            outer_jobs=int(args.outer_jobs),
        )
    args.invariance_plan = _build_invariance_plan(effective_configs)
    for group in args.invariance_plan["groups"].values():
        representative = group["representative_candidate"]
        _validated_effective_config(
            args.v04_config,
            candidates[representative]["overrides"],
            model_seed=args.tuning_seeds[0] + 500_000,
            outer_jobs=DETERMINISM_SERIAL_OUTER_JOBS,
        )
    demo_generator_version = _read_v03_demo_generator_version(args.v03_root)
    args.path_policy = _preflight_planned_paths(
        args,
        candidates,
        demo_generator_version,
    )
    python_info = _probe_python310(args.v03_python, args.v03_root)
    if python_info.get("demo_generator_version") != demo_generator_version:
        raise ValidationError(
            "v0.3 source/probed DEMO_GENERATOR_VERSION differs before manifest creation"
        )
    snapshot = source_snapshot(args.v03_root, PROJECT_ROOT)
    args.promotion_policy_path = args.output_root / "promotion_policy.lock.json"
    if (
        args.command == "tune"
        and not args.promotion_policy_path.exists()
        and args.output_root.exists()
        and any(args.output_root.iterdir())
    ):
        raise ValidationError(
            "prospective policy requires a new empty output directory; existing artifacts "
            "cannot be reclassified"
        )
    reservation_contract = _spent_seed_reservation_contract(args, candidates, snapshot)
    args.spent_seed_reservation = _reserve_or_verify_spent_seeds(
        SPENT_SEED_REGISTRY_PATH,
        reservation_contract,
        allow_create=args.command == "tune" and not args.promotion_policy_path.exists(),
    )
    policy_contract = _promotion_policy_lock_contract(args, candidates, snapshot)
    args.promotion_policy_lock = _load_or_create_promotion_policy_lock(
        args.promotion_policy_path,
        policy_contract,
        allow_create=args.command == "tune",
    )
    contract = _contract_from_args(args, candidates, snapshot, python_info)
    manifest_path = args.output_root / "run_manifest.json"
    manifest = _load_or_create_manifest(
        manifest_path,
        contract,
        allow_create=args.command == "tune",
    )
    _verify_manifest_storage_contract(manifest, args.path_policy)
    _verify_metric_roles(manifest.get("metric_roles"), context="run manifest")
    manifest_plan = manifest.get("invariance_plan")
    if not isinstance(manifest_plan, Mapping):
        raise ValidationError("run manifest has no invariance plan")
    _verify_invariance_plan(manifest_plan, candidate_names=candidates)
    args.invariance_plan = manifest_plan
    assert_source_snapshot(manifest["source_snapshot"])
    return manifest, candidates


def _command_tune(args: argparse.Namespace) -> int:
    manifest, candidates = _prepare_common(args)
    root = Path(args.output_root)
    lock_path = root / "candidate.lock.json"
    if lock_path.exists():
        raise ValidationError("candidate is already locked; tuning cannot be reopened")
    _run_stage("tuning", args.tuning_seeds, candidates, args, manifest)
    print("Tuning complete. Run the separate 'lock' command before heldout.")
    return 0


def _command_lock(args: argparse.Namespace) -> int:
    manifest, candidates = _prepare_common(args)
    assert_source_snapshot(manifest["source_snapshot"])
    lock = _lock_candidate(args, manifest, candidates)
    assert_source_snapshot(manifest["source_snapshot"])
    print(f"Locked candidate: {lock['selected_candidate']}")
    print("Heldout remains unopened. Run the separate 'holdout' command.")
    return 0


def _command_holdout(args: argparse.Namespace) -> int:
    manifest, candidates = _prepare_common(args)
    root = Path(args.output_root)
    lock_path = root / "candidate.lock.json"
    if not lock_path.exists():
        raise ValidationError("candidate.lock.json is required before heldout can open")
    lock = _read_json(lock_path)
    _verify_sealed(lock, "lock_sha256", context="candidate lock")
    policy_config = manifest.get("promotion_policy_config")
    _verify_promotion_policy_config(policy_config, context="holdout command")
    if (
        lock.get("format_version") != LOCK_FORMAT_VERSION
        or lock.get("manifest_sha256") != manifest["manifest_sha256"]
        or lock.get("promotion_policy_lock_sha256") != manifest.get("promotion_policy_lock_sha256")
        or lock.get("promotion_policy_config_sha256") != policy_config["policy_config_sha256"]
        or lock.get("spent_seed_reservation") != manifest.get("spent_seed_reservation")
        or lock.get("promotion_comparators") != PROMOTION_COMPARATORS
        or lock.get("heldout_opened") is not False
    ):
        raise ValidationError("candidate lock belongs to another manifest")
    tuning_metrics_path = _verify_artifact(lock["tuning_metrics"], context="locked tuning metrics")
    tuning_metrics = _read_json(tuning_metrics_path)
    _verify_sealed(tuning_metrics, "tuning_metrics_sha256", context="locked tuning metrics")
    if (
        tuning_metrics.get("format_version") != REPORT_FORMAT_VERSION
        or tuning_metrics.get("manifest_sha256") != manifest["manifest_sha256"]
        or tuning_metrics.get("promotion_policy_lock_sha256")
        != manifest.get("promotion_policy_lock_sha256")
        or tuning_metrics.get("promotion_policy_config_sha256")
        != policy_config["policy_config_sha256"]
        or tuning_metrics.get("spent_seed_reservation") != manifest.get("spent_seed_reservation")
    ):
        raise ValidationError("locked tuning metrics predate the prospective policy")
    metric_roles = manifest["metric_roles"]
    _verify_metric_roles(tuning_metrics.get("metric_roles"), context="locked tuning metrics")
    if lock.get("metric_roles") != metric_roles:
        raise ValidationError("candidate lock metric roles differ from the run manifest")
    expected_commitment = hashlib.sha256(
        _canonical_json_bytes({"locked_seeds": list(args.locked_seeds)})
    ).hexdigest()
    if lock.get("heldout_seed_commitment_sha256") != expected_commitment:
        raise ValidationError("heldout seed commitment differs from candidate lock")
    if lock.get("tuning_seeds_consumed") != list(args.tuning_seeds):
        raise ValidationError("tuning seed set differs from candidate lock")
    selected = str(lock["selected_candidate"])
    if selected not in candidates or candidates[selected] != lock["selected_spec"]:
        raise ValidationError("locked candidate spec differs from the sealed manifest")
    if (
        lock.get("selected_spec_sha256")
        != hashlib.sha256(_canonical_json_bytes(candidates[selected])).hexdigest()
    ):
        raise ValidationError("locked candidate spec hash differs from the sealed manifest")
    selected_tuning = tuning_metrics.get("candidates", {}).get(selected)
    tuning_summaries = tuning_metrics.get("candidates")
    if not isinstance(tuning_summaries, Mapping) or set(tuning_summaries) != set(candidates):
        raise ValidationError("locked tuning metrics candidate set differs")
    for candidate_name, candidate_summary in tuning_summaries.items():
        _verify_dual_candidate_summary(
            candidate_summary,
            policy_config=policy_config,
            context=f"locked tuning candidate {candidate_name}",
        )
    if _select_candidate(tuning_metrics) != selected:
        raise ValidationError("locked candidate differs from sealed tuning rank")
    if isinstance(selected_tuning, Mapping):
        _verify_dual_candidate_summary(
            selected_tuning,
            policy_config=policy_config,
            context="locked tuning candidate",
        )
    if (
        not isinstance(selected_tuning, Mapping)
        or selected_tuning.get("eligible_for_lock") is not True
        or selected_tuning.get("prospective_deterministic_gates", {}).get("pass") is not True
        or selected_tuning.get("prospective_block_bootstrap", {}).get("pass") is not True
        or selected_tuning.get("prospective_block_bootstrap", {}).get("policy_config_sha256")
        != policy_config["policy_config_sha256"]
    ):
        raise ValidationError("locked candidate lacks passing prospective tuning statistics")
    invariance_plan = manifest["invariance_plan"]
    assignment = invariance_plan["candidate_assignments"][selected]
    selected_group = assignment["group_id"]
    tuning_evidence = tuning_metrics.get("invariance_group_evidence", {}).get(selected_group)
    checkpoint = _load_checkpoint(root / "checkpoint.json", str(manifest["manifest_sha256"]))
    verified_evidence = _verified_invariance_group_evidence(
        checkpoint,
        candidates,
        invariance_plan,
        first_tuning_seed=int(args.tuning_seeds[0]),
    ).get(selected_group)
    if (
        lock.get("invariance_plan_sha256") != invariance_plan["invariance_plan_sha256"]
        or tuning_metrics.get("invariance_plan_sha256") != invariance_plan["invariance_plan_sha256"]
        or lock.get("selected_invariance_assignment") != assignment
        or not isinstance(tuning_evidence, Mapping)
        or lock.get("selected_invariance_evidence") != tuning_evidence
        or lock.get("selected_invariance_evidence") != verified_evidence
        or tuning_evidence.get("serial_vs_parallel_determinism", {}).get("pass") is not True
        or tuning_evidence.get("causal_prefix_invariance", {}).get("pass") is not True
    ):
        raise ValidationError("locked candidate has missing or failed invariance evidence")
    selected_candidates = {selected: lock["selected_spec"]}
    _run_stage("heldout", args.locked_seeds, selected_candidates, args, manifest)
    assert_source_snapshot(manifest["source_snapshot"])
    report = _heldout_report(args, manifest, lock)
    print(f"Heldout promotion pass: {report['promotion_pass']}")
    print(f"Report: {root / 'heldout_report.json'}")
    return 0 if report["promotion_pass"] else 3


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--v03-root", type=Path, default=DEFAULT_V03_ROOT)
    parser.add_argument("--v03-python", type=Path, default=DEFAULT_V03_PYTHON)
    parser.add_argument("--v03-config", type=Path, default=DEFAULT_V03_CONFIG)
    parser.add_argument("--v04-config", type=Path, default=DEFAULT_V04_CONFIG)
    parser.add_argument("--candidates-json", type=Path)
    parser.add_argument(
        "--tuning-seeds",
        default=",".join(str(seed) for seed in DEFAULT_TUNING_SEEDS),
    )
    parser.add_argument(
        "--locked-seeds",
        default=",".join(str(seed) for seed in DEFAULT_LOCKED_SEEDS),
    )
    parser.add_argument("--generation-start", default=GENERATION_START)
    parser.add_argument("--evaluation-start", default=PRODUCTION_EVALUATION_START)
    parser.add_argument(
        "--outer-jobs",
        type=int,
        default=DETERMINISM_PARALLEL_OUTER_JOBS,
        help=(
            "Immutable prospective parallel worker count for the serial-vs-"
            f"{DETERMINISM_PARALLEL_OUTER_JOBS} determinism comparison"
        ),
    )
    parser.add_argument(
        "--overlay-adapter",
        choices=("auto", "in-memory", "cli"),
        default="auto",
    )
    parser.add_argument(
        "--no-harm-tolerance",
        type=float,
        default=PROMOTION_WORST_SEED_DEGRADATION_CAP,
        help="Immutable prospective per-seed material-harm cap (must be 0.005)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, help_text, function in (
        ("tune", "run/resume tuning seeds only", _command_tune),
        ("lock", "rank completed tuning results and seal one candidate", _command_lock),
        ("holdout", "open locked heldout seeds after candidate.lock exists", _command_holdout),
    ):
        command = subparsers.add_parser(name, help=help_text)
        _add_common_arguments(command)
        command.set_defaults(function=function)

    worker = subparsers.add_parser("_overlay-worker", help=argparse.SUPPRESS)
    worker.add_argument("--input-csv", required=True)
    worker.add_argument("--output-csv", required=True)
    worker.add_argument("--diagnostics-json", required=True)
    worker.add_argument("--overrides-json", required=True)
    worker.add_argument("--config", required=True)
    worker.add_argument("--model-seed", type=int, required=True)
    worker.add_argument("--outer-jobs", type=int, required=True)
    worker.add_argument("--adapter", choices=("auto", "in-memory", "cli"), required=True)
    worker.set_defaults(function=_overlay_worker)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.function(args))
    except KeyboardInterrupt:
        print("Interrupted; completed checkpoints remain resumable.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[FAIL-CLOSED] {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
