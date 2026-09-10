"""No-score spawn/runtime and monolithic-versus-chunked scheduling parity evidence."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import importlib.util
import json
import multiprocessing as mp
from pathlib import Path
import sys
import time
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_bytes,
    sha256_file,
)


RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v5.py"
OUTPUT = (
    ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/"
    "NO_SCORE_SCHEDULING_PARITY_V5.json"
)


def _runner():
    spec = importlib.util.spec_from_file_location("_v5_benchmark_runner", RUNNER)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load V5 runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _synthetic_task(payload: Mapping[str, Any]) -> dict[str, Any]:
    module = _runner()
    rows = [
        {
            "seed": int(payload["seed"]),
            "candidate_id": str(payload["candidate_id"]),
            "fold_id": str(fold_id),
            "synthetic_digest": sha256_bytes(
                canonical_json_bytes(
                    [int(payload["seed"]), str(payload["candidate_id"]), str(fold_id)]
                )
            ),
        }
        for fold_id in payload["fold_ids"]
    ]
    # Small deterministic CPU work encourages actual worker fan-out without model fitting.
    state = canonical_json_bytes(rows)
    for _ in range(256):
        state = bytes.fromhex(sha256_bytes(state))
    return {"rows": rows, "telemetry": module._worker_telemetry()}


def _initializer() -> None:
    _runner()._worker_initializer()


def _payloads(*, chunked: bool) -> list[dict[str, Any]]:
    module = _runner()
    chunks = module._chunk_fold_ids() if chunked else (module.FOLD_IDS,)
    return [
        {"seed": seed, "candidate_id": candidate_id, "fold_ids": list(folds)}
        for seed in module.SEEDS
        for candidate_id in module.EXPECTED_ENABLED
        for folds in chunks
    ]


def _run(payloads: list[dict[str, Any]], workers: int) -> dict[str, Any]:
    module = _runner()
    started = time.perf_counter()
    with ProcessPoolExecutor(
        max_workers=workers,
        mp_context=mp.get_context("spawn"),
        initializer=_initializer,
    ) as executor:
        results = list(executor.map(_synthetic_task, payloads, chunksize=1))
    rows = sorted(
        [row for result in results for row in result["rows"]],
        key=lambda row: (row["seed"], row["candidate_id"], row["fold_id"]),
    )
    telemetry = [result["telemetry"] for result in results]
    return {
        "workers_requested": workers,
        "task_count": len(payloads),
        "row_count": len(rows),
        "canonical_rows_sha256": sha256_bytes(canonical_json_bytes(rows)),
        "wall_seconds_diagnostic_only": time.perf_counter() - started,
        "observed_worker_pids": sorted({int(row["pid"]) for row in telemetry}),
        "runtime_checks_passed": all(
            row["sys_executable"] == module.PINNED_LAUNCHER.as_posix()
            and row["python_version"] == list(module.PINNED_VERSION)
            and row["actual_process_image"] == module.PINNED_PROCESS_IMAGE.as_posix()
            and row["runtime_environment_raw_sha256"] == module.RUNTIME_ENVIRONMENT_RAW
            and row["thread_environment"] == module.THREAD_ENV
            and row["cuda_visible_devices"] == "-1"
            and row["nvidia_visible_devices"] == "void"
            and row["affinity"] == list(module.CPU_AFFINITY)
            and all(value == 1 for value in row["native_pool_threads"])
            for row in telemetry
        ),
    }


def main() -> int:
    module = _runner()
    module._verify_runtime()
    monolithic = _run(_payloads(chunked=False), 8)
    chunked = [_run(_payloads(chunked=True), workers) for workers in (8, 16, 24, 32)]
    digests = {
        monolithic["canonical_rows_sha256"],
        *(row["canonical_rows_sha256"] for row in chunked),
    }
    if len(digests) != 1 or monolithic["row_count"] != 1550:
        raise RuntimeError("V5 synthetic scheduling parity failed")
    if not monolithic["runtime_checks_passed"] or not all(
        row["runtime_checks_passed"] for row in chunked
    ):
        raise RuntimeError("V5 worker runtime checks failed")
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v5_no_score_scheduling_parity",
            "model_predictions_generated": False,
            "scores_computed": False,
            "truth_opened": False,
            "runner": {
                "path": RUNNER.relative_to(ROOT).as_posix(),
                "bytes": RUNNER.stat().st_size,
                "raw_sha256": sha256_file(RUNNER),
            },
            "monolithic_reference": monolithic,
            "chunked_8_16_24_32": chunked,
            "same_canonical_bytes": True,
            "selected_execution_policy_unchanged": {
                "workers": 8,
                "inner_threads": 1,
                "gpu": "OFF",
                "chunks_per_seed_candidate": 8,
            },
        }
    )
    if OUTPUT.exists():
        raise FileExistsError(OUTPUT)
    OUTPUT.write_bytes(canonical_json_bytes(payload) + b"\n")
    print(
        json.dumps(
            {
                "raw_sha256": sha256_file(OUTPUT),
                "logical_sha256": payload["manifest_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
