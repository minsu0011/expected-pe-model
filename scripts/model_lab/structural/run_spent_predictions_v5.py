"""V5 truth-blind Structural spent runner; blocked until a fresh independent GO."""

# ruff: noqa: E402 -- runtime/thread guards intentionally precede numerical imports.

from __future__ import annotations

import os

THREAD_ENV = {
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "MKL_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
    "NUMEXPR_NUM_THREADS": "1",
}
for _key, _value in THREAD_ENV.items():
    os.environ[_key] = _value
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import ctypes
from ctypes import wintypes
import hashlib
from importlib import metadata, util
import json
import multiprocessing as mp
from pathlib import Path
import platform
import sys
import sysconfig
import time
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

PINNED_LAUNCHER = (ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe").resolve()
PINNED_LAUNCHER_RAW = "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
PINNED_PROCESS_IMAGE = Path("C:/Users/minsu/anaconda3/envs/myenv/python.exe")
PINNED_PROCESS_IMAGE_RAW = "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
PINNED_VERSION = (3, 10, 19)
RUNTIME_ENVIRONMENT_RAW = "1c23932a1b4bb25daecd5939c7d58b1e89de160e30d1a4777ce62c43ea164f55"
RUNTIME_ENVIRONMENT_LOGICAL = "68c2155e71a8952c3edf5f9679f2de1f152a958d7c9aa94bc392f4501c4a2b49"
RUNTIME_ENVIRONMENT_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/RUNTIME_ENVIRONMENT_V5.json"
)
REQUIRED_DISTRIBUTIONS = {
    "joblib": "1.5.3",
    "numpy": "1.26.4",
    "pandas": "2.2.3",
    "pyarrow": "21.0.0",
    "scikit-learn": "1.7.2",
    "scipy": "1.15.3",
    "threadpoolctl": "3.6.0",
    "xgboost": "3.2.0",
}

_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_PSAPI = ctypes.WinDLL("psapi", use_last_error=True)
_KERNEL32.GetCurrentProcess.restype = wintypes.HANDLE
_KERNEL32.GetModuleFileNameW.argtypes = [
    wintypes.HMODULE,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
_KERNEL32.GetModuleFileNameW.restype = wintypes.DWORD
_KERNEL32.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
_KERNEL32.GlobalMemoryStatusEx.restype = wintypes.BOOL
_KERNEL32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
_KERNEL32.OpenProcess.restype = wintypes.HANDLE
_KERNEL32.CloseHandle.argtypes = [wintypes.HANDLE]
_KERNEL32.CloseHandle.restype = wintypes.BOOL
_KERNEL32.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
_KERNEL32.SetProcessAffinityMask.restype = wintypes.BOOL
_KERNEL32.GetProcessAffinityMask.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(ctypes.c_size_t),
]
_KERNEL32.GetProcessAffinityMask.restype = wintypes.BOOL


def _raw_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _actual_process_image() -> Path:
    buffer = ctypes.create_unicode_buffer(32768)
    length = _KERNEL32.GetModuleFileNameW(None, buffer, len(buffer))
    if not length:
        raise RuntimeError("GetModuleFileNameW failed")
    return Path(buffer.value).resolve(strict=True)


def _preimport_runtime_gate() -> None:
    executable = Path(sys.executable).resolve(strict=True)
    if executable != PINNED_LAUNCHER or _raw_sha256(executable) != PINNED_LAUNCHER_RAW:
        raise RuntimeError("Structural V5 rejects non-pinned Python launcher")
    if sys.version_info[:3] != PINNED_VERSION or platform.python_implementation() != "CPython":
        raise RuntimeError("Structural V5 requires exact CPython 3.10.19")
    image = _actual_process_image()
    if image != PINNED_PROCESS_IMAGE or _raw_sha256(image) != PINNED_PROCESS_IMAGE_RAW:
        raise RuntimeError("Structural V5 process image differs from the runtime pin")


if __name__ in {"__main__", "__mp_main__"}:
    _preimport_runtime_gate()

import numpy as np
import pandas as pd

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    PREDICTION_COLUMNS,
    file_record,
    seal_payload,
    write_immutable_json,
    write_round_trip_csv,
)
from pe_regime_v04.model_lab.structural.authorization import EXPECTED_ENABLED
from pe_regime_v04.model_lab.structural.authorization_v5 import (
    load_structural_execution_authorization_v5,
)
from pe_regime_v04.model_lab.structural.contracts import (
    StructuralContractError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    verify_payload_seal,
)
from pe_regime_v04.model_lab.structural.dispatcher import StructuralDispatcher
from pe_regime_v04.model_lab.structural.features import (
    MARKET_CURRENT,
    REGIME_CURRENT,
    REQUIRED_UPSTREAM_AUDITS,
    TRACK_A_FEATURE_COLUMNS,
    TRACK_C_FEATURE_COLUMNS,
    TrackASourceAuditBinding,
    build_track_a_lag1_artifact,
)
from pe_regime_v04.model_lab.structural.nested import (
    FORMAL_OUTER_COVERAGE_SHA256,
    FORMAL_OUTER_FOLD_COUNT,
    FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
)
from pe_regime_v04.model_lab.structural.resources import (
    CPU_AFFINITY,
    MAX_TOTAL_RSS_BYTES,
    MINIMUM_FREE_RAM_BYTES,
)


def _load_v4_runner():
    path = ROOT / "scripts/model_lab/structural/run_spent_predictions_v4.py"
    spec = util.spec_from_file_location("_structural_v4_frozen_dependency", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load frozen V4 runner dependency")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v4 = _load_v4_runner()

SEEDS = (6301, 6421, 6521, 6607, 6701)
FOLD_IDS = tuple(f"fold_{index:03d}" for index in range(12, FORMAL_OUTER_FOLD_COUNT))
WORKERS = 8
CHUNKS_PER_SEED_CANDIDATE = 8
TRACK_A_AUDIT_RAW = "1ace868983aff8ad73419380d26af88c5efefc1dd748fe78d77e579e8513cd38"
V4_RUNNER_RAW = "cc5c3345baf6319a2e1f5612ba9735b0cbd86943810a9219c3c9f87502e398f0"
AUTHORIZATION_V5_PATH = ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v5.py"
V4_FAILURE_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_20260819/V4_FAILED_ATTEMPT.json"
)
V4_FAILURE_RAW = "d8b6723854ce03a897bbef6febcc8e5bae0654896c3f73a1bcaddeabe4544cb8"
ACTIVATION_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/ACTIVATION_EXECUTION_V5.json"
)
POLICY_PIN_PATH = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/"
    "EXTERNAL_POLICY_PIN_EXECUTION_V5.json"
)


class _MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


_PSAPI.GetProcessMemoryInfo.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(_ProcessMemoryCounters),
    wintypes.DWORD,
]
_PSAPI.GetProcessMemoryInfo.restype = wintypes.BOOL


def _available_memory() -> int:
    status = _MemoryStatus()
    status.dwLength = ctypes.sizeof(status)
    if not _KERNEL32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise StructuralContractError("GlobalMemoryStatusEx failed")
    return int(status.ullAvailPhys)


def _process_rss(pid: int) -> int:
    process = _KERNEL32.OpenProcess(0x0400 | 0x0010, False, pid)
    if not process:
        return 0
    try:
        counters = _ProcessMemoryCounters()
        counters.cb = ctypes.sizeof(counters)
        if not _PSAPI.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            return 0
        return int(counters.WorkingSetSize)
    finally:
        _KERNEL32.CloseHandle(process)


def _set_affinity() -> None:
    mask = sum(1 << cpu for cpu in CPU_AFFINITY)
    if not _KERNEL32.SetProcessAffinityMask(_KERNEL32.GetCurrentProcess(), ctypes.c_size_t(mask)):
        raise StructuralContractError("SetProcessAffinityMask failed")


def _get_affinity() -> tuple[int, ...]:
    process_mask = ctypes.c_size_t()
    system_mask = ctypes.c_size_t()
    if not _KERNEL32.GetProcessAffinityMask(
        _KERNEL32.GetCurrentProcess(),
        ctypes.byref(process_mask),
        ctypes.byref(system_mask),
    ):
        raise StructuralContractError("GetProcessAffinityMask failed")
    return tuple(index for index in range(64) if process_mask.value & (1 << index))


def _read_sealed(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise StructuralContractError(f"sealed object required: {path}")
    verify_payload_seal(value)
    return value


def _verify_runtime() -> dict[str, Any]:
    _preimport_runtime_gate()
    if sha256_file(RUNTIME_ENVIRONMENT_PATH) != RUNTIME_ENVIRONMENT_RAW:
        raise StructuralContractError("V5 runtime environment bytes changed")
    environment = _read_sealed(RUNTIME_ENVIRONMENT_PATH)
    if (
        environment.get("manifest_sha256") != RUNTIME_ENVIRONMENT_LOGICAL
        or environment.get("required_distribution_versions") != REQUIRED_DISTRIBUTIONS
        or environment.get("thread_gpu_policy")
        != {**THREAD_ENV, "CUDA_VISIBLE_DEVICES": "-1", "NVIDIA_VISIBLE_DEVICES": "void"}
    ):
        raise StructuralContractError("V5 runtime environment contract changed")
    if {name: metadata.version(name) for name in REQUIRED_DISTRIBUTIONS} != REQUIRED_DISTRIBUTIONS:
        raise StructuralContractError("V5 runtime distribution versions changed")
    runtime = environment["runtime"]
    if (
        Path(sys.prefix).resolve().as_posix() != runtime["sys_prefix"]
        or Path(sys.base_prefix).resolve().as_posix() != runtime["sys_base_prefix"]
        or Path(sysconfig.get_path("stdlib")).resolve().as_posix() != runtime["stdlib"]
    ):
        raise StructuralContractError("V5 Python prefix/stdlib changed")
    return environment


def _verify_activation(
    *, activation_raw_sha256: str, policy_raw_sha256: str, policy_pin_raw_sha256: str
) -> dict[str, Any]:
    if sha256_file(ACTIVATION_PATH) != activation_raw_sha256:
        raise StructuralContractError("V5 execution activation bytes changed")
    activation = _read_sealed(ACTIVATION_PATH)
    if sha256_file(POLICY_PIN_PATH) != policy_pin_raw_sha256:
        raise StructuralContractError("V5 external policy pin bytes changed")
    pin = _read_sealed(POLICY_PIN_PATH)
    bindings = activation.get("exact_bindings", {})
    runner = Path(__file__).resolve()
    expected = {
        "physical_prediction_runner_v5": (runner, sha256_file(runner)),
        "frozen_runner_v4_dependency": (
            ROOT / "scripts/model_lab/structural/run_spent_predictions_v4.py",
            V4_RUNNER_RAW,
        ),
        "authorization_v5": (AUTHORIZATION_V5_PATH, sha256_file(AUTHORIZATION_V5_PATH)),
        "runtime_environment_v5": (RUNTIME_ENVIRONMENT_PATH, RUNTIME_ENVIRONMENT_RAW),
        "v4_failed_attempt": (V4_FAILURE_PATH, V4_FAILURE_RAW),
    }
    for name, (path, raw) in expected.items():
        row = bindings.get(name, {})
        if (
            row.get("path") != path.relative_to(ROOT).as_posix()
            or row.get("bytes") != path.stat().st_size
            or row.get("raw_sha256") != raw
        ):
            raise StructuralContractError(f"V5 execution closure changed: {name}")
    if (
        pin.get("authority_policy", {}).get("raw_sha256") != policy_raw_sha256
        or pin.get("activation_binding", {}).get("raw_sha256") != activation_raw_sha256
        or pin.get("activation_binding", {}).get("logical_sha256")
        != activation.get("manifest_sha256")
        or pin.get("formal_spent_activated") is not True
    ):
        raise StructuralContractError("V5 external policy pin changed")
    contract = activation.get("execution_contract", {})
    folds = activation.get("fold_contract", {})
    if (
        tuple(contract.get("candidate_ids", ())) != EXPECTED_ENABLED
        or tuple(contract.get("seeds", ())) != SEEDS
        or contract.get("outer_workers") != WORKERS
        or contract.get("inner_threads") != 1
        or contract.get("gpu") != "OFF"
        or contract.get("task_count") != 200
        or contract.get("chunks_per_seed_candidate") != CHUNKS_PER_SEED_CANDIDATE
        or tuple(folds.get("required_evaluation_fold_ids", ())) != FOLD_IDS
        or folds.get("full_membership_schedule_sha256") != FORMAL_OUTER_POSITION_SCHEDULE_SHA256
        or folds.get("coverage_sha256") != FORMAL_OUTER_COVERAGE_SHA256
    ):
        raise StructuralContractError("V5 activation execution/fold contract changed")
    return activation


def _worker_initializer() -> None:
    for key, value in THREAD_ENV.items():
        os.environ[key] = value
    os.environ["CUDA_VISIBLE_DEVICES"] = "-1"
    os.environ["NVIDIA_VISIBLE_DEVICES"] = "void"
    _verify_runtime()
    _set_affinity()


def _worker_telemetry() -> dict[str, Any]:
    from threadpoolctl import threadpool_info

    return {
        "pid": os.getpid(),
        "rss_bytes": _process_rss(os.getpid()),
        "affinity": list(_get_affinity()),
        "thread_environment": {key: os.environ.get(key) for key in THREAD_ENV},
        "native_pool_threads": sorted(
            {
                int(row["num_threads"])
                for row in threadpool_info()
                if row.get("num_threads") is not None
            }
        ),
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "nvidia_visible_devices": os.environ.get("NVIDIA_VISIBLE_DEVICES"),
        "sys_executable": Path(sys.executable).resolve().as_posix(),
        "python_version": list(sys.version_info[:3]),
        "actual_process_image": _actual_process_image().as_posix(),
        "runtime_environment_raw_sha256": RUNTIME_ENVIRONMENT_RAW,
    }


def _eligible_decomposition_training(
    features: pd.DataFrame,
    target: pd.Series,
    dates: pd.Series,
    session_positions: Sequence[int],
) -> tuple[pd.DataFrame, pd.Series, pd.Series, dict[str, Any]]:
    values = pd.to_numeric(target, errors="coerce").to_numpy(dtype=np.float64, na_value=np.nan)
    positions = np.asarray(session_positions, dtype=np.int64)
    if not (len(features) == len(values) == len(dates) == len(positions)):
        raise StructuralContractError("V5 decomposition outer-train rows are misaligned")
    valid = np.isfinite(values) & (values > 0.0)
    if not valid.any():
        raise StructuralContractError("V5 decomposition outer train has zero eligible targets")
    first_valid = int(np.flatnonzero(valid)[0])
    if valid[:first_valid].any() or not valid[first_valid:].all():
        raise StructuralContractError(
            "V5 permits only a leading invalid warm-up prefix in decomposition outer train"
        )
    eligible_positions = positions[valid]
    if len(eligible_positions) > 1 and not np.all(np.diff(eligible_positions) == 1):
        raise StructuralContractError("V5 eligible decomposition sessions must remain consecutive")
    selected = np.flatnonzero(valid)
    filtered_positions = positions[~valid].tolist()
    selected_features = features.iloc[selected].reset_index(drop=True)
    missing_cells = int(
        selected_features.apply(pd.to_numeric, errors="coerce")
        .replace([np.inf, -np.inf], np.nan)
        .isna()
        .sum()
        .sum()
    )
    audit = {
        "eligibility_rule": "positive_finite_target_leading_warmup_filter_v1",
        "outer_train_rows": len(values),
        "eligible_train_rows": int(valid.sum()),
        "filtered_train_rows": int((~valid).sum()),
        "filtered_session_positions": filtered_positions,
        "eligible_session_positions_sha256": sha256_bytes(
            canonical_json_bytes(eligible_positions.tolist())
        ),
        "train_feature_nonfinite_cells_imputed_train_only": missing_cells,
    }
    return (
        selected_features,
        target.iloc[selected].reset_index(drop=True),
        dates.iloc[selected].reset_index(drop=True),
        audit,
    )


def _run_decomposition(
    project_root: Path,
    seed: int,
    candidate_id: str,
    fold_ids: tuple[str, ...],
    dispatcher: StructuralDispatcher,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    frame = v4._seed_frame(project_root, seed)
    folds = v4._folds(frame)
    fold_by_id = {fold.fold_id: fold for fold in folds[12:]}
    symbol = str(frame["symbol"].iloc[0])
    if candidate_id == "decomp_block_ridge_ar1_lag1":
        source = frame.loc[:, ["date", *MARKET_CURRENT, *REGIME_CURRENT]].copy()
        source.insert(0, "entity_id", symbol)
        source.insert(0, "seed", seed)
        artifact = build_track_a_lag1_artifact(
            source,
            source_audit=TrackASourceAuditBinding(
                audit_sha256=TRACK_A_AUDIT_RAW,
                passed_audits=REQUIRED_UPSTREAM_AUDITS,
            ),
        ).to_frame()
        features = frame.loc[:, list(TRACK_A_FEATURE_COLUMNS[:9])].copy()
        for column in TRACK_A_FEATURE_COLUMNS[9:]:
            features[column] = artifact[column].to_numpy(copy=True)
        features = features.loc[:, list(TRACK_A_FEATURE_COLUMNS)]
    else:
        features = frame.loc[:, list(TRACK_C_FEATURE_COLUMNS)].copy()
    predictions: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for fold_id in fold_ids:
        if fold_id not in fold_by_id:
            raise StructuralContractError("V5 decomposition chunk contains an unknown fold")
        fold = fold_by_id[fold_id]
        started = time.perf_counter()
        train_positions = list(fold.train_positions)
        test_positions = list(fold.test_positions)
        train_features, train_target, train_dates, eligibility = _eligible_decomposition_training(
            features.iloc[train_positions].reset_index(drop=True),
            frame["observed_pe"].iloc[train_positions].reset_index(drop=True),
            frame["date"].iloc[train_positions].reset_index(drop=True),
            train_positions,
        )
        fold_hash = sha256_bytes(
            canonical_json_bytes(
                {
                    "seed": seed,
                    "fold_id": fold.fold_id,
                    "train_positions": train_positions,
                    "eligible_train_positions_sha256": eligibility[
                        "eligible_session_positions_sha256"
                    ],
                    "target_eligibility_rule": eligibility["eligibility_rule"],
                    "test_positions": test_positions,
                    "schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
                }
            )
        )
        binding = dispatcher.decomposition_binding(candidate_id=candidate_id, fold_sha256=fold_hash)
        fit = dispatcher.fit_decomposition(
            candidate_id,
            train_features,
            train_target,
            train_dates,
            binding=binding,
        )
        output = dispatcher.predict_decomposition(
            candidate_id,
            fit,
            features.iloc[test_positions].reset_index(drop=True),
            frame["date"].iloc[test_positions].reset_index(drop=True),
        )
        elapsed = time.perf_counter() - started
        predictions.extend(
            v4._prediction_rows(
                output,
                seed=seed,
                symbol=symbol,
                model_id=candidate_id,
                fold_id=fold.fold_id,
                test_start=test_positions[0],
            )
        )
        diagnostic = v4._diagnostic(
            seed=seed,
            model_id=candidate_id,
            fold_id=fold.fold_id,
            test_start=test_positions[0],
            test_rows=len(test_positions),
            runtime=elapsed,
            pid=os.getpid(),
            fit_sha256=fit.fit_sha256,
            ar1_rho=fit.ar1.rho,
        )
        diagnostic["warnings_json"] = json.dumps(eligibility, sort_keys=True, separators=(",", ":"))
        diagnostics.append(diagnostic)
    return predictions, diagnostics


def _worker(payload: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "project_root",
        "seed",
        "candidate_id",
        "fold_ids",
        "activation_raw_sha256",
        "policy_raw_sha256",
        "policy_pin_raw_sha256",
        "payload_sha256",
    }
    if set(payload) != required:
        raise StructuralContractError("V5 worker payload schema changed")
    unsigned = {key: payload[key] for key in required if key != "payload_sha256"}
    if sha256_bytes(canonical_json_bytes(unsigned)) != payload["payload_sha256"]:
        raise StructuralContractError("V5 worker payload seal changed")
    _verify_runtime()
    _verify_activation(
        activation_raw_sha256=str(payload["activation_raw_sha256"]),
        policy_raw_sha256=str(payload["policy_raw_sha256"]),
        policy_pin_raw_sha256=str(payload["policy_pin_raw_sha256"]),
    )
    project_root = Path(str(payload["project_root"])).resolve(strict=True)
    authorization = load_structural_execution_authorization_v5(
        project_root,
        external_policy_sha256=str(payload["policy_raw_sha256"]),
        scope="FORMAL_SPENT",
    )
    dispatcher = StructuralDispatcher.from_authorization(authorization)
    seed = int(payload["seed"])
    candidate_id = str(payload["candidate_id"])
    fold_ids = tuple(str(value) for value in payload["fold_ids"])
    if (
        seed not in SEEDS
        or candidate_id not in EXPECTED_ENABLED
        or not fold_ids
        or any(fold_id not in FOLD_IDS for fold_id in fold_ids)
    ):
        raise StructuralContractError("V5 worker payload is outside activated universe")
    if candidate_id.startswith("decomp_"):
        predictions, diagnostics = _run_decomposition(
            project_root, seed, candidate_id, fold_ids, dispatcher
        )
    else:
        predictions = []
        diagnostics = []
        for fold_id in fold_ids:
            rows, diagnostic = v4._run_nested_fold(
                project_root, seed, candidate_id, fold_id, dispatcher
            )
            predictions.extend(rows)
            diagnostics.append(diagnostic)
    return {
        "payload_sha256": str(payload["payload_sha256"]),
        "predictions": predictions,
        "diagnostics": diagnostics,
        "telemetry": _worker_telemetry(),
    }


def _chunk_fold_ids() -> tuple[tuple[str, ...], ...]:
    chunks = tuple(FOLD_IDS[offset::CHUNKS_PER_SEED_CANDIDATE] for offset in range(8))
    flattened = [fold_id for chunk in chunks for fold_id in chunk]
    if sorted(flattened) != sorted(FOLD_IDS) or len(flattened) != len(set(flattened)):
        raise StructuralContractError("V5 fold chunks do not partition the formal schedule")
    return chunks


def _payloads(
    *, activation_raw_sha256: str, policy_raw_sha256: str, policy_pin_raw_sha256: str
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for seed in SEEDS:
        for candidate_id in EXPECTED_ENABLED:
            for fold_ids in _chunk_fold_ids():
                unsigned = {
                    "project_root": str(ROOT),
                    "seed": seed,
                    "candidate_id": candidate_id,
                    "fold_ids": list(fold_ids),
                    "activation_raw_sha256": activation_raw_sha256,
                    "policy_raw_sha256": policy_raw_sha256,
                    "policy_pin_raw_sha256": policy_pin_raw_sha256,
                }
                output.append(
                    {
                        **unsigned,
                        "payload_sha256": sha256_bytes(canonical_json_bytes(unsigned)),
                    }
                )
    if len(output) != 200:
        raise StructuralContractError("V5 task count changed")
    return output


def _assemble_results(
    results: Sequence[Mapping[str, Any]],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    predictions = pd.DataFrame([row for result in results for row in result["predictions"]]).loc[
        :, list(PREDICTION_COLUMNS)
    ]
    diagnostics = pd.DataFrame([row for result in results for row in result["diagnostics"]]).loc[
        :, list(v4.DIAGNOSTIC_COLUMNS)
    ]
    return (
        predictions.sort_values(["seed", "date", "model_id"], kind="mergesort").reset_index(
            drop=True
        ),
        diagnostics.sort_values(
            ["seed", "test_start_position", "model_id"], kind="mergesort"
        ).reset_index(drop=True),
    )


def _aggregate_rss(executor: ProcessPoolExecutor) -> tuple[int, list[int]]:
    processes = getattr(executor, "_processes", {})
    pids = sorted({os.getpid(), *(process.pid for process in processes.values())})
    return sum(_process_rss(pid) for pid in pids), pids


def _shutdown_failed(executor: ProcessPoolExecutor, pending: Sequence[Any]) -> None:
    for future in pending:
        future.cancel()
    v4._terminate(executor)
    executor.shutdown(wait=False, cancel_futures=True)


def run(
    output_directory: Path,
    *,
    activation_raw_sha256: str,
    policy_raw_sha256: str,
    policy_pin_raw_sha256: str,
) -> Path:
    _verify_runtime()
    activation = _verify_activation(
        activation_raw_sha256=activation_raw_sha256,
        policy_raw_sha256=policy_raw_sha256,
        policy_pin_raw_sha256=policy_pin_raw_sha256,
    )
    authorization = load_structural_execution_authorization_v5(
        ROOT, external_policy_sha256=policy_raw_sha256, scope="FORMAL_SPENT"
    )
    authorization.verify()
    output_directory = output_directory.resolve()
    prediction_path = output_directory / "structural_predictions.csv"
    diagnostic_path = output_directory / "structural_fold_diagnostics.csv"
    manifest_path = output_directory / "PREDICTION_MANIFEST.json"
    if any(path.exists() for path in (prediction_path, diagnostic_path, manifest_path)):
        raise FileExistsError("V5 structural prediction outputs are immutable")
    output_directory.mkdir(parents=True, exist_ok=True)
    if _available_memory() < MINIMUM_FREE_RAM_BYTES:
        raise StructuralContractError("free RAM is below activated 16-GiB floor")
    payloads = _payloads(
        activation_raw_sha256=activation_raw_sha256,
        policy_raw_sha256=policy_raw_sha256,
        policy_pin_raw_sha256=policy_pin_raw_sha256,
    )
    results: list[dict[str, Any]] = []
    max_rss = 0
    min_free = _available_memory()
    observed_pids: set[int] = set()
    started = time.perf_counter()
    executor = ProcessPoolExecutor(
        max_workers=WORKERS,
        mp_context=mp.get_context("spawn"),
        initializer=_worker_initializer,
    )
    pending: set[Any] = set()
    try:
        future_map = {executor.submit(_worker, payload): payload for payload in payloads}
        pending = set(future_map)
        while pending:
            rss, pids = _aggregate_rss(executor)
            free = _available_memory()
            max_rss = max(max_rss, rss)
            min_free = min(min_free, free)
            observed_pids.update(pids)
            if rss > MAX_TOTAL_RSS_BYTES or free < MINIMUM_FREE_RAM_BYTES:
                raise StructuralContractError("V5 live aggregate RSS/free-RAM guard breached")
            done, pending = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
            for future in done:
                results.append(future.result())
    except BaseException:
        _shutdown_failed(executor, tuple(pending))
        raise
    else:
        executor.shutdown(wait=True)
    wall = time.perf_counter() - started
    predictions, diagnostics = _assemble_results(results)
    if set(predictions["model_id"]) != set(EXPECTED_ENABLED):
        raise StructuralContractError("V5 prediction candidate universe changed")
    for candidate_id in EXPECTED_ENABLED:
        candidate = predictions.loc[predictions["model_id"] == candidate_id]
        if len(candidate) != len(SEEDS) * 1296:
            raise StructuralContractError(f"V5 candidate coverage changed: {candidate_id}")
        for seed in SEEDS:
            group = candidate.loc[candidate["seed"] == seed]
            if (
                len(group) != 1296
                or group["date"].duplicated().any()
                or tuple(group["test_start_position"].drop_duplicates())
                != tuple(range(504, 1800, 21))
            ):
                raise StructuralContractError(
                    f"V5 required identity changed: {candidate_id}/{seed}"
                )
    telemetry = [result["telemetry"] for result in results]
    if any(
        row["thread_environment"] != THREAD_ENV
        or row["cuda_visible_devices"] != "-1"
        or row["nvidia_visible_devices"] != "void"
        or tuple(row["affinity"]) != CPU_AFFINITY
        or any(value != 1 for value in row["native_pool_threads"])
        or Path(row["sys_executable"]) != PINNED_LAUNCHER
        or tuple(row["python_version"]) != PINNED_VERSION
        or Path(row["actual_process_image"]) != PINNED_PROCESS_IMAGE
        or row["runtime_environment_raw_sha256"] != RUNTIME_ENVIRONMENT_RAW
        for row in telemetry
    ):
        raise StructuralContractError("V5 worker runtime/thread/GPU/affinity telemetry failed")
    prediction_record = write_round_trip_csv(
        predictions, prediction_path, columns=PREDICTION_COLUMNS
    )
    diagnostic_record = write_round_trip_csv(
        diagnostics, diagnostic_path, columns=v4.DIAGNOSTIC_COLUMNS
    )
    runtime = diagnostics.groupby("model_id", sort=True)["runtime_seconds"].sum().to_dict()
    manifest = seal_payload(
        {
            "format_version": 2,
            "mode": "structural_v5_truth_blind_spent_prediction_artifact",
            "activation_binding": file_record(ACTIVATION_PATH),
            "external_policy_pin": file_record(POLICY_PIN_PATH),
            "runtime_environment": file_record(RUNTIME_ENVIRONMENT_PATH),
            "external_policy_raw_sha256": policy_raw_sha256,
            "authorization_sha256": authorization.authorization_sha256,
            "predict_inputs": file_record(
                ROOT / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json"
            ),
            "evaluation_data_used": False,
            "candidate_scores_computed": False,
            "seeds": list(SEEDS),
            "seed_role": "ALREADY_SPENT_WAVE1_ONLY",
            "candidate_model_ids": list(EXPECTED_ENABLED),
            "formal_fold_count_bound": FORMAL_OUTER_FOLD_COUNT,
            "formal_schedule_sha256": FORMAL_OUTER_POSITION_SCHEDULE_SHA256,
            "formal_coverage_sha256": FORMAL_OUTER_COVERAGE_SHA256,
            "executed_required_fold_ids": list(FOLD_IDS),
            "required_rows_per_seed_candidate": 1296,
            "prediction_rows": len(predictions),
            "diagnostic_rows": len(diagnostics),
            "predictions_csv": prediction_record,
            "fold_diagnostics_csv": diagnostic_record,
            "runtime_seconds_by_model": {key: float(value) for key, value in runtime.items()},
            "end_to_end_wall_seconds_diagnostic_only": wall,
            "outer_backend": "ProcessPoolExecutor",
            "start_method": "spawn",
            "outer_workers": WORKERS,
            "chunks_per_seed_candidate": CHUNKS_PER_SEED_CANDIDATE,
            "task_count": len(payloads),
            "inner_threads": 1,
            "gpu": "sealed_off",
            "peak_live_aggregate_rss_bytes": max_rss,
            "minimum_live_free_ram_bytes": min_free,
            "observed_process_ids": sorted(observed_pids),
            "worker_telemetry": telemetry,
            "activation_decision": activation["decision"],
            "target_eligibility_rule": "positive_finite_target_leading_warmup_filter_v1",
            "feature_imputation": "outer-train median; all-missing column drop; frozen transform",
            "fresh_seed_selected_or_reserved": False,
            "heldout_opened": False,
        }
    )
    write_immutable_json(manifest_path, manifest)
    return manifest_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path)
    parser.add_argument("--activation-raw-sha256")
    parser.add_argument("--policy-raw-sha256")
    parser.add_argument("--policy-pin-raw-sha256")
    parser.add_argument("--runtime-preflight-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _verify_runtime()
    if args.runtime_preflight_only:
        print("STRUCTURAL_V5_RUNTIME_PREFLIGHT_PASS")
        return 0
    required = (
        args.output_directory,
        args.activation_raw_sha256,
        args.policy_raw_sha256,
        args.policy_pin_raw_sha256,
    )
    if any(value is None for value in required):
        raise SystemExit("prediction mode requires output/activation/policy/pin arguments")
    print(
        run(
            args.output_directory,
            activation_raw_sha256=args.activation_raw_sha256,
            policy_raw_sha256=args.policy_raw_sha256,
            policy_pin_raw_sha256=args.policy_pin_raw_sha256,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
