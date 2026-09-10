"""Independent deterministic CUDA worker for C5-R2 sequence research."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any, Mapping

import numpy as np


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from research.model_zoo.pe_c5_r2_sequence_research_v1.contracts import (  # noqa: E402
    DGP_IDS,
    EVALUATION_END_EXCLUSIVE,
    EVALUATION_START,
    FEATURE_NAMES,
    LOOKBACK,
    TEST_BLOCK,
    TEST_STARTS,
    TRAIN_LABEL_START,
    canonical_json_bytes,
    raw_sha256,
    validate_candidate_configuration,
    validate_sample_boundary,
)
from research.model_zoo.pe_c5_r2_sequence_research_v1.evaluation import (  # noqa: E402
    dlinear_signal,
    score_track,
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prediction_semantic_digest(predictions: Mapping[str, Mapping[str, np.ndarray]]) -> str:
    """Hash prediction keys, shapes, and exact little-endian float64 values."""

    digest = hashlib.sha256()
    for track in sorted(predictions):
        for model in sorted(predictions[track]):
            values = np.asarray(predictions[track][model], dtype="<f8", order="C")
            header = f"{track}|{model}|{values.shape[0]}|{values.shape[1]}\n".encode("ascii")
            digest.update(header)
            digest.update(values.tobytes(order="C"))
    return digest.hexdigest()


def build_window_view(features: np.ndarray) -> np.ndarray:
    """Return a read-only view where window index ``t-63`` predicts label ``t``."""

    values = np.asarray(features, dtype=np.float32)
    if values.ndim != 3 or values.shape[2] != len(FEATURE_NAMES):
        raise ValueError("feature tensor geometry differs")
    windows = np.lib.stride_tricks.sliding_window_view(values, LOOKBACK, axis=1)
    return windows.transpose(0, 1, 3, 2)


def _rss_bytes() -> int:
    if os.name != "nt":
        return 0

    class ProcessMemoryCountersEx(ctypes.Structure):
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
            ("PrivateUsage", ctypes.c_size_t),
        ]

    counters = ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    handle = ctypes.windll.kernel32.GetCurrentProcess()
    if not ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        return 0
    return int(counters.WorkingSetSize)


class GpuSampler:
    """Low-frequency nvidia-smi sampler that does not enter the model process graph."""

    def __init__(self) -> None:
        self.samples: list[dict[str, float]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)

    def _run(self) -> None:
        command = [
            "nvidia-smi",
            "--query-gpu=utilization.gpu,memory.used,power.draw",
            "--format=csv,noheader,nounits",
            "--id=0",
        ]
        while not self._stop.is_set():
            try:
                raw = subprocess.check_output(command, text=True, timeout=5.0).strip()
                parts = [float(item.strip()) for item in raw.split(",")]
                if len(parts) == 3:
                    self.samples.append(
                        {
                            "gpu_utilization_percent": parts[0],
                            "gpu_memory_used_mib": parts[1],
                            "gpu_power_watts": parts[2],
                        }
                    )
            except (OSError, subprocess.SubprocessError, ValueError):
                pass
            self._stop.wait(0.75)

    def payload(self) -> dict[str, object]:
        if not self.samples:
            return {"sample_count": 0}
        return {
            "sample_count": len(self.samples),
            "mean_gpu_utilization_percent": float(
                np.mean([item["gpu_utilization_percent"] for item in self.samples])
            ),
            "max_gpu_utilization_percent": float(
                max(item["gpu_utilization_percent"] for item in self.samples)
            ),
            "max_gpu_memory_used_mib": float(
                max(item["gpu_memory_used_mib"] for item in self.samples)
            ),
            "max_gpu_power_watts": float(max(item["gpu_power_watts"] for item in self.samples)),
        }


def _configure_torch() -> tuple[Any, Any]:
    import torch
    from torch import nn

    if os.environ.get("CUBLAS_WORKSPACE_CONFIG") != ":4096:8":
        raise RuntimeError("CUBLAS_WORKSPACE_CONFIG differs")
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is unavailable for the frozen C5-R2 worker")
    if torch.cuda.device_count() != 1:
        raise RuntimeError("exact one visible CUDA device required")
    name = torch.cuda.get_device_name(0)
    if name != "NVIDIA GeForce RTX 5080":
        raise RuntimeError("frozen GPU identity differs")
    torch.use_deterministic_algorithms(True)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    torch.set_float32_matmul_precision("highest")
    torch.set_num_threads(1)
    torch.set_num_interop_threads(1)
    return torch, nn


def _make_model(model_name: str, torch: Any, nn: Any, config: Mapping[str, Any]) -> Any:
    if model_name == "dlinear_residual":

        class DLinearResidual(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.kernel = int(config["moving_average_kernel"])
                self.linear = nn.Linear(2 * LOOKBACK * len(FEATURE_NAMES), 1)
                nn.init.zeros_(self.linear.weight)
                nn.init.zeros_(self.linear.bias)

            def forward(self, values: Any) -> Any:
                import torch.nn.functional as functional

                channels = values.transpose(1, 2)
                padding = self.kernel // 2
                padded = functional.pad(channels, (padding, padding), mode="replicate")
                trend = functional.avg_pool1d(padded, self.kernel, stride=1)
                seasonal = channels - trend
                decomposed = torch.cat((trend, seasonal), dim=1).flatten(1)
                return self.linear(decomposed).squeeze(-1)

        return DLinearResidual()
    if model_name == "compact_gru":

        class CompactGru(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                self.gru = nn.GRU(
                    input_size=len(FEATURE_NAMES),
                    hidden_size=int(config["hidden_size"]),
                    num_layers=int(config["num_layers"]),
                    dropout=float(config["dropout"]),
                    batch_first=True,
                )
                self.head = nn.Linear(int(config["hidden_size"]), 1)

            def forward(self, values: Any) -> Any:
                sequence, _ = self.gru(values)
                return self.head(sequence[:, -1, :]).squeeze(-1)

        return CompactGru()
    raise ValueError(f"unsupported model {model_name}")


def _feature_normalization(features: np.ndarray, test_start: int) -> tuple[np.ndarray, ...]:
    prefix = features[:, :test_start, :].reshape(-1, features.shape[-1]).astype(np.float64)
    median = np.nanmedian(prefix, axis=0)
    median = np.where(np.isfinite(median), median, 0.0)
    filled = np.where(np.isfinite(prefix), prefix, median)
    mean = np.mean(filled, axis=0)
    std = np.std(filled, axis=0)
    std = np.where(std >= 1e-6, std, 1.0)
    return median.astype(np.float32), mean.astype(np.float32), std.astype(np.float32)


def _prepare_examples(
    *,
    windows: np.ndarray,
    features: np.ndarray,
    labels: np.ndarray,
    positions: np.ndarray,
    normalization: tuple[np.ndarray, np.ndarray, np.ndarray],
    require_all: bool,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    task_count = features.shape[0]
    task_index = np.repeat(np.arange(task_count, dtype=np.int64), len(positions))
    label_position = np.tile(positions.astype(np.int64), task_count)
    source_window = windows[task_index, label_position - LOOKBACK]
    anchor = features[task_index, label_position - 1, 0].astype(np.float64)
    target = labels[task_index, label_position].astype(np.float64)
    valid = np.isfinite(anchor) & np.isfinite(target)
    if require_all and not bool(valid.all()):
        raise RuntimeError("evaluation example contains missing anchor/label")
    task_index = task_index[valid]
    label_position = label_position[valid]
    source_window = source_window[valid].astype(np.float32, copy=True)
    target = target[valid]
    anchor = anchor[valid]
    median, mean, std = normalization
    source_window = np.where(np.isfinite(source_window), source_window, median)
    source_window = (source_window - mean) / std
    residual = target - anchor
    return source_window.astype(np.float32), residual, task_index, label_position


def _torch_predict(model: Any, values: Any, *, batch_size: int, torch: Any) -> np.ndarray:
    output: list[np.ndarray] = []
    model.eval()
    with torch.no_grad():
        for start in range(0, len(values), batch_size):
            batch = values[start : start + batch_size]
            output.append(model(batch).detach().cpu().numpy().astype(np.float64))
    return np.concatenate(output)


def _fit_fold(
    *,
    model_name: str,
    track: str,
    fold_ordinal: int,
    test_start: int,
    features: np.ndarray,
    windows: np.ndarray,
    labels: np.ndarray,
    config: Mapping[str, Any],
    torch: Any,
    nn: Any,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, object]]:
    fold_started = time.perf_counter()
    fold_seed = (
        55100
        + (0 if track == "P" else 1000)
        + (0 if model_name == "dlinear_residual" else 10000)
        + fold_ordinal
    )
    torch.manual_seed(fold_seed)
    torch.cuda.manual_seed_all(fold_seed)
    normalization = _feature_normalization(features, test_start)
    tune_start = max(TRAIN_LABEL_START, test_start - 63)
    fit_positions = np.arange(TRAIN_LABEL_START, tune_start, dtype=np.int64)
    tune_positions = np.arange(tune_start, test_start, dtype=np.int64)
    test_end = min(test_start + TEST_BLOCK, EVALUATION_END_EXCLUSIVE)
    test_positions = np.arange(test_start, test_end, dtype=np.int64)
    x_fit, y_fit, _, _ = _prepare_examples(
        windows=windows,
        features=features,
        labels=labels,
        positions=fit_positions,
        normalization=normalization,
        require_all=False,
    )
    x_tune, y_tune, _, _ = _prepare_examples(
        windows=windows,
        features=features,
        labels=labels,
        positions=tune_positions,
        normalization=normalization,
        require_all=False,
    )
    x_test, _, test_tasks, test_labels = _prepare_examples(
        windows=windows,
        features=features,
        labels=labels,
        positions=test_positions,
        normalization=normalization,
        require_all=True,
    )
    if len(x_fit) < 1000 or len(x_tune) < 100 or len(x_test) != len(test_positions) * 50:
        raise RuntimeError("fold fit/tune/test geometry differs")
    target_mean = float(np.mean(y_fit))
    target_std = max(float(np.std(y_fit)), 1e-4)
    y_fit_scaled = ((y_fit - target_mean) / target_std).astype(np.float32)
    y_tune_scaled = ((y_tune - target_mean) / target_std).astype(np.float32)
    device = torch.device("cuda:0")
    fit_tensor = torch.from_numpy(x_fit).to(device=device, dtype=torch.float32)
    fit_target = torch.from_numpy(y_fit_scaled).to(device=device, dtype=torch.float32)
    tune_tensor = torch.from_numpy(x_tune).to(device=device, dtype=torch.float32)
    tune_target = torch.from_numpy(y_tune_scaled).to(device=device, dtype=torch.float32)
    test_tensor = torch.from_numpy(x_test).to(device=device, dtype=torch.float32)
    model = _make_model(model_name, torch, nn, config).to(device)
    parameter_count = sum(parameter.numel() for parameter in model.parameters())
    if parameter_count != int(config["parameter_count"]):
        raise RuntimeError("model parameter count differs from candidate lock")
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=float(config["learning_rate"]),
        weight_decay=float(config["weight_decay"]),
    )
    criterion = nn.SmoothL1Loss(beta=1.0)
    batch_size = int(config["batch_size"])
    best_loss = float("inf")
    best_state: dict[str, Any] | None = None
    best_epoch = -1
    stale = 0
    epochs_completed = 0
    for epoch in range(int(config["max_epochs"])):
        order = np.random.default_rng(fold_seed + epoch * 1009).permutation(len(fit_tensor))
        model.train()
        for start in range(0, len(order), batch_size):
            indexes = torch.from_numpy(order[start : start + batch_size]).to(device)
            optimizer.zero_grad(set_to_none=True)
            prediction = model(fit_tensor[indexes])
            loss = criterion(prediction, fit_target[indexes])
            loss.backward()
            optimizer.step()
        tune_prediction = _torch_predict(model, tune_tensor, batch_size=batch_size, torch=torch)
        tune_loss = float(
            np.mean(
                np.where(
                    np.abs(tune_prediction - y_tune_scaled) < 1.0,
                    0.5 * np.square(tune_prediction - y_tune_scaled),
                    np.abs(tune_prediction - y_tune_scaled) - 0.5,
                )
            )
        )
        epochs_completed = epoch + 1
        if tune_loss < best_loss - 1e-7:
            best_loss = tune_loss
            best_epoch = epoch + 1
            best_state = {
                name: value.detach().clone() for name, value in model.state_dict().items()
            }
            stale = 0
        else:
            stale += 1
        if epochs_completed >= int(config["minimum_epochs"]) and stale >= int(config["patience"]):
            break
    if best_state is None:
        raise RuntimeError("training produced no best state")
    model.load_state_dict(best_state)
    predicted_scaled = _torch_predict(model, test_tensor, batch_size=batch_size, torch=torch)
    predicted_residual = target_mean + target_std * predicted_scaled
    anchor = features[test_tasks, test_labels - 1, 0].astype(np.float64)
    prediction = anchor + predicted_residual
    receipt = {
        "track": track,
        "model": model_name,
        "fold_ordinal": fold_ordinal,
        "fold_id": f"fold_{fold_ordinal:03d}",
        "test_start_position": test_start,
        "test_end_exclusive": test_end,
        "fit_label_position_min": int(fit_positions[0]),
        "fit_label_position_max": int(fit_positions[-1]),
        "tuning_label_position_min": int(tune_positions[0]),
        "tuning_label_position_max": int(tune_positions[-1]),
        "fit_rows": len(x_fit),
        "tuning_rows": len(x_tune),
        "prediction_rows": len(prediction),
        "source_position_max": test_end - 2,
        "source_strictly_before_each_label": True,
        "within_test_block_parameter_updates": 0,
        "parameter_count": parameter_count,
        "epochs_completed": epochs_completed,
        "best_epoch": best_epoch,
        "best_training_prefix_tune_loss": best_loss,
        "target_standardization_mean": target_mean,
        "target_standardization_std": target_std,
        "config_seed": fold_seed,
        "precision": "float32",
        "device": "cuda:0",
        "elapsed_seconds": time.perf_counter() - fold_started,
    }
    del (
        model,
        optimizer,
        fit_tensor,
        fit_target,
        tune_tensor,
        tune_target,
        test_tensor,
        best_state,
    )
    torch.cuda.empty_cache()
    return prediction, test_tasks, test_labels, receipt


def _fit_rolling_model(
    *,
    model_name: str,
    track: str,
    features: np.ndarray,
    labels: np.ndarray,
    config: Mapping[str, Any],
    torch: Any,
    nn: Any,
) -> tuple[np.ndarray, list[dict[str, object]]]:
    windows = build_window_view(features)
    output = np.full(
        (features.shape[0], EVALUATION_END_EXCLUSIVE - EVALUATION_START),
        np.nan,
        dtype=np.float64,
    )
    receipts: list[dict[str, object]] = []
    for fold_ordinal, test_start in enumerate(TEST_STARTS):
        prediction, tasks, positions, receipt = _fit_fold(
            model_name=model_name,
            track=track,
            fold_ordinal=fold_ordinal,
            test_start=test_start,
            features=features,
            windows=windows,
            labels=labels,
            config=config,
            torch=torch,
            nn=nn,
        )
        for task, position, value in zip(tasks, positions, prediction, strict=True):
            validate_sample_boundary(
                label_position=int(position),
                source_position_min=int(position) - LOOKBACK,
                source_position_max=int(position) - 1,
            )
            index = int(position) - EVALUATION_START
            if np.isfinite(output[int(task), index]):
                raise RuntimeError("test block prediction overlap detected")
            output[int(task), index] = float(value)
        receipts.append(receipt)
    if not np.isfinite(output).all():
        raise RuntimeError("rolling prediction coverage differs")
    return output, receipts


def _persistence(features: np.ndarray) -> np.ndarray:
    result = features[:, EVALUATION_START - 1 : EVALUATION_END_EXCLUSIVE - 1, 0].astype(np.float64)
    if not np.isfinite(result).all():
        raise RuntimeError("lagged-v04 persistence contains nonfinite values")
    return result


def _load_public_cache(path: Path) -> tuple[np.ndarray, np.ndarray]:
    with np.load(path, allow_pickle=False) as archive:
        names = tuple(str(item) for item in archive["feature_names"].tolist())
        features = archive["features"].astype(np.float32)
        labels = archive["public_observed_log_pe"].astype(np.float64)
        forbidden = set(archive.files) & {
            "simulator_true_log_fair_pe",
            "true_log_fair_pe",
            "true_fair_pe",
        }
    if names != FEATURE_NAMES or forbidden:
        raise RuntimeError("Track P cache feature/truth boundary differs")
    return features, labels


def _load_simulator_cache(path: Path) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    with np.load(path, allow_pickle=False) as archive:
        exact = {
            "simulator_true_log_fair_pe",
            "c4_expected_log_pe",
            "c2_expected_log_pe",
        }
        if set(archive.files) != exact:
            raise RuntimeError("Track S cache key universe differs")
        labels = archive["simulator_true_log_fair_pe"].astype(np.float64)
        cores = {
            "C4": archive["c4_expected_log_pe"].astype(np.float64),
            "C2": archive["c2_expected_log_pe"].astype(np.float64),
        }
    return labels, cores


def _save_predictions(
    path: Path,
    predictions: Mapping[str, Mapping[str, np.ndarray]],
) -> None:
    flattened = {
        f"{track}__{model}": np.asarray(values, dtype=np.float64)
        for track, models in predictions.items()
        for model, values in models.items()
    }
    if path.exists():
        raise RuntimeError("worker prediction leaf already exists")
    np.savez_compressed(path, **flattened)


def run_worker(
    *,
    config_lock: Path,
    data_manifest: Path,
    public_cache: Path,
    simulator_cache: Path,
    output_dir: Path,
    process_label: str,
) -> dict[str, object]:
    started = time.perf_counter()
    rss_start = _rss_bytes()
    output = Path(output_dir)
    if not output.is_dir() or any(output.iterdir()):
        raise RuntimeError("worker output directory must exist and be empty")
    config_payload = json.loads(config_lock.read_text(encoding="utf-8"))
    configuration = config_payload.get("candidate_configuration")
    if not isinstance(configuration, dict):
        raise RuntimeError("candidate configuration missing")
    validate_candidate_configuration(configuration)
    manifest = json.loads(data_manifest.read_text(encoding="utf-8"))
    if (
        manifest.get("status") != "PASS_SPLIT_TRACK_CACHE_AFTER_SCORE_BLIND_CONFIG_LOCK"
        or manifest.get("candidate_config_lock_raw_sha256") != _sha(config_lock)
        or manifest["cache_refs"]["track_p"]["raw_sha256"] != _sha(public_cache)
        or manifest["cache_refs"]["track_s"]["raw_sha256"] != _sha(simulator_cache)
    ):
        raise RuntimeError("worker data/config binding differs")
    torch, nn = _configure_torch()
    torch.cuda.reset_peak_memory_stats(0)
    sampler = GpuSampler()
    sampler.start()
    fold_receipts: list[dict[str, object]] = []
    try:
        features, public_labels = _load_public_cache(public_cache)
        track_p_predictions = {"lagged_v04_persistence": _persistence(features)}
        dlinear_p, receipts = _fit_rolling_model(
            model_name="dlinear_residual",
            track="P",
            features=features,
            labels=public_labels,
            config=configuration["models"]["dlinear_residual"],
            torch=torch,
            nn=nn,
        )
        fold_receipts.extend(receipts)
        track_p_predictions["dlinear_residual"] = dlinear_p
        p_target = public_labels[:, EVALUATION_START:EVALUATION_END_EXCLUSIVE]
        p_metrics = score_track(
            predictions=track_p_predictions,
            target=p_target,
            dgp_ids=DGP_IDS,
            core_predictions=None,
            survivor_rule=configuration["survivor_rule"],
        )
        p_signal, p_decision = dlinear_signal(
            {"P": p_metrics},
            configuration["conditional_execution"]["dlinear_signal"],
        )
        if p_signal:
            gru_p, receipts = _fit_rolling_model(
                model_name="compact_gru",
                track="P",
                features=features,
                labels=public_labels,
                config=configuration["models"]["compact_gru"],
                torch=torch,
                nn=nn,
            )
            fold_receipts.extend(receipts)
            track_p_predictions["compact_gru"] = gru_p
            p_metrics = score_track(
                predictions=track_p_predictions,
                target=p_target,
                dgp_ids=DGP_IDS,
                core_predictions=None,
                survivor_rule=configuration["survivor_rule"],
            )
        # Track P prediction is complete before this process opens Track-S simulator truth.
        simulator_labels, cores = _load_simulator_cache(simulator_cache)
        track_s_predictions = {"lagged_v04_persistence": _persistence(features)}
        dlinear_s, receipts = _fit_rolling_model(
            model_name="dlinear_residual",
            track="S",
            features=features,
            labels=simulator_labels,
            config=configuration["models"]["dlinear_residual"],
            torch=torch,
            nn=nn,
        )
        fold_receipts.extend(receipts)
        track_s_predictions["dlinear_residual"] = dlinear_s
        s_target = simulator_labels[:, EVALUATION_START:EVALUATION_END_EXCLUSIVE]
        s_metrics = score_track(
            predictions=track_s_predictions,
            target=s_target,
            dgp_ids=DGP_IDS,
            core_predictions=cores,
            survivor_rule=configuration["survivor_rule"],
        )
        s_signal, s_decision = dlinear_signal(
            {"S": s_metrics},
            configuration["conditional_execution"]["dlinear_signal"],
        )
        if s_signal:
            gru_s, receipts = _fit_rolling_model(
                model_name="compact_gru",
                track="S",
                features=features,
                labels=simulator_labels,
                config=configuration["models"]["compact_gru"],
                torch=torch,
                nn=nn,
            )
            fold_receipts.extend(receipts)
            track_s_predictions["compact_gru"] = gru_s
            s_metrics = score_track(
                predictions=track_s_predictions,
                target=s_target,
                dgp_ids=DGP_IDS,
                core_predictions=cores,
                survivor_rule=configuration["survivor_rule"],
            )
        metrics = {"P": p_metrics, "S": s_metrics}
        signal_by_track = {"P": p_decision["P"], "S": s_decision["S"]}
        run_gru = p_signal or s_signal
        predictions = {"P": track_p_predictions, "S": track_s_predictions}
        digest = prediction_semantic_digest(predictions)
        _save_predictions(output / "PREDICTIONS.npz", predictions)
        metrics_payload = {
            "schema_version": "expected_pe.c5_r2.sequence_research.worker_metrics.v1",
            "candidate_config_lock_raw_sha256": _sha(config_lock),
            "data_manifest_raw_sha256": _sha(data_manifest),
            "gru_triggered": run_gru,
            "dlinear_signal_by_track": signal_by_track,
            "metrics": metrics,
            "prediction_semantic_sha256": digest,
        }
        _write_new(output / "METRICS.json", canonical_json_bytes(metrics_payload))
        _write_new(
            output / "FOLD_RECEIPTS.json",
            canonical_json_bytes(
                {
                    "schema_version": "expected_pe.c5_r2.sequence_research.fold_receipts.v1",
                    "fold_receipt_count": len(fold_receipts),
                    "all_source_positions_strictly_before_label": all(
                        item["source_strictly_before_each_label"] is True for item in fold_receipts
                    ),
                    "all_within_test_block_parameter_updates_zero": all(
                        item["within_test_block_parameter_updates"] == 0 for item in fold_receipts
                    ),
                    "receipts": fold_receipts,
                }
            ),
        )
    finally:
        sampler.stop()
    elapsed = time.perf_counter() - started
    gpu_properties = torch.cuda.get_device_properties(0)
    receipt = {
        "schema_version": "expected_pe.c5_r2.sequence_research.worker_receipt.v1",
        "status": "PASS_DETERMINISTIC_FP32_CUDA_SEQUENCE_WORKER",
        "process_label": process_label,
        "pid": os.getpid(),
        "python": sys.executable.replace("\\", "/"),
        "python_version": sys.version,
        "torch_version": torch.__version__,
        "cuda_runtime": torch.version.cuda,
        "gpu": {
            "available": torch.cuda.is_available(),
            "name": torch.cuda.get_device_name(0),
            "compute_capability": list(torch.cuda.get_device_capability(0)),
            "total_memory_bytes": int(gpu_properties.total_memory),
            "actual_training_device": "cuda:0",
            "actual_gpu_use": torch.cuda.max_memory_allocated(0) > 0,
            "peak_allocated_bytes": int(torch.cuda.max_memory_allocated(0)),
            "peak_reserved_bytes": int(torch.cuda.max_memory_reserved(0)),
            "sampler": sampler.payload(),
        },
        "determinism": {
            "torch_deterministic_algorithms": torch.are_deterministic_algorithms_enabled(),
            "cublas_workspace_config": os.environ.get("CUBLAS_WORKSPACE_CONFIG"),
            "tf32_matmul": torch.backends.cuda.matmul.allow_tf32,
            "tf32_cudnn": torch.backends.cudnn.allow_tf32,
            "amp_used": False,
            "precision": "float32",
        },
        "access": {
            "track_p_simulator_cache_open_count_before_track_p_prediction": 0,
            "track_p_same_row_or_future_input_count": 0,
            "track_s_spent_simulator_cache_open_count": 1,
            "fresh_truth_open_count": 0,
            "heldout_truth_open_count": 0,
            "qualification_or_r3_selection_metric_open_count": 0,
        },
        "execution": {
            "fold_receipt_count": len(fold_receipts),
            "within_test_block_parameter_updates": 0,
            "gru_triggered": run_gru,
            "dlinear_signal_by_track": signal_by_track,
            "prediction_semantic_sha256": digest,
            "prediction_array_count": sum(len(values) for values in predictions.values()),
            "elapsed_seconds": elapsed,
            "rss_start_bytes": rss_start,
            "rss_end_bytes": _rss_bytes(),
        },
        "track_roles": {
            "S": "SIMULATOR_SPECIALIST_NOT_DEPLOYABLE_NOT_PROMOTION_ELIGIBLE",
            "P": "PIT_OBSERVABLE_RESEARCH_PROTOTYPE_NO_PROMOTION_AUTHORITY",
        },
        "config_lock_raw_sha256": _sha(config_lock),
        "data_manifest_raw_sha256": _sha(data_manifest),
        "metrics_raw_sha256": _sha(output / "METRICS.json"),
        "fold_receipts_raw_sha256": _sha(output / "FOLD_RECEIPTS.json"),
        "predictions_file_raw_sha256": _sha(output / "PREDICTIONS.npz"),
        "promotion_authority": False,
    }
    unsigned = dict(receipt)
    receipt["receipt_semantic_sha256"] = raw_sha256(canonical_json_bytes(unsigned))
    _write_new(output / "WORKER_RECEIPT.json", canonical_json_bytes(receipt))
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-lock", type=Path, required=True)
    parser.add_argument("--data-manifest", type=Path, required=True)
    parser.add_argument("--public-cache", type=Path, required=True)
    parser.add_argument("--simulator-cache", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--process-label", choices=("A", "B"), required=True)
    args = parser.parse_args()
    receipt = run_worker(
        config_lock=args.config_lock,
        data_manifest=args.data_manifest,
        public_cache=args.public_cache,
        simulator_cache=args.simulator_cache,
        output_dir=args.output_dir,
        process_label=args.process_label,
    )
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "process_label": receipt["process_label"],
                "prediction_semantic_sha256": receipt["execution"]["prediction_semantic_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_window_view", "prediction_semantic_digest", "run_worker"]
