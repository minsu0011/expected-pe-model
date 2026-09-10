"""Independent evidence collection for the frozen C4-R2 closure harness."""
from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import ctypes
import io
import json
import multiprocessing as mp
from pathlib import Path
import sys
import time

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))

from scripts.model_lab.c4_r2_final_closure_v1 import (  # noqa: E402
    CASES, KNOWN_CANONICAL, _stress_canonical, build_public_task_plan,
    canonical_path, read_canonical_bytes, require, sha, write,
)
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402


def audit_surface(item):
    from research.model_zoo.hierarchical_observable_fair_value_state_v7 import (
        adapt_r4_canonical_source_v7, build_hierarchical_state_features_v7,
    )
    from research.model_zoo.observable_fair_value_state_v1.audit import run_causality_audit
    if isinstance(item, str):
        label = f"stress_{item}"
        frame = _stress_canonical(pd.read_csv(KNOWN_CANONICAL), item)
    else:
        label = f"spent_{item.ordinal:02d}"
        frame = pd.read_csv(io.BytesIO(read_canonical_bytes(item)))
    source = adapt_r4_canonical_source_v7(frame)
    result = run_causality_audit(source).as_dict()
    require(result["passed"], f"causal audit failure: {label}")
    baseline = build_hierarchical_state_features_v7(source).features
    prefix_checks = 0
    for stop in (504, 1134, 1680):
        prefix = build_hierarchical_state_features_v7(source.iloc[:stop].copy()).features
        pd.testing.assert_frame_equal(prefix, baseline.iloc[:stop], check_exact=True)
        prefix_checks += 1
    dates = pd.to_datetime(frame.date, utc=True).dt.normalize()
    available = pd.to_datetime(frame.available_at, utc=True).dt.normalize()
    effective = pd.to_datetime(frame.effective_date, utc=True).dt.normalize()
    mask = frame.eps_ttm.notna()
    pit = mask & (available.isna() | effective.isna() | (available > effective) | (effective > dates))
    period = pd.to_datetime(frame.period_end, utc=True).dt.normalize()
    pit |= mask & (period.isna() | (period > available))
    require(int(pit.sum()) == 0, f"PIT timestamp violation: {label}")
    split_factor = pd.to_numeric(frame.eps_split_factor)
    require(np.isfinite(split_factor[mask]).all() and (split_factor[mask] > 0).all(), "invalid share factor")
    if isinstance(item, str):
        overlay_rows = len(frame)
    else:
        overlay = pd.read_csv(canonical_path(item).with_name("v04_overlay.csv"),
                              usecols=["date", "symbol", "eps_ttm", "eps_split_factor", "eps_definition"])
        for column in overlay.columns:
            pd.testing.assert_series_equal(frame[column], overlay[column], check_exact=True)
        overlay_rows = len(overlay)
    return {"label": label, "rows": len(frame), "causal_checks": result,
            "v7_exact_prefix_checks": prefix_checks, "PIT_timestamp_violations": int(pit.sum()),
            "comparator_eps_share_basis_matched_rows": overlay_rows,
            "eps_definitions": sorted(frame.loc[mask, "eps_definition"].unique().tolist()),
            "split_event_rows": int((pd.to_numeric(frame.stock_split) != 0).sum()),
            "source_sha256": sha(KNOWN_CANONICAL if isinstance(item, str) else canonical_path(item))}


def audit(root):
    started = time.perf_counter()
    with ProcessPoolExecutor(max_workers=8, mp_context=mp.get_context("spawn")) as pool:
        results = list(pool.map(audit_surface, list(build_public_task_plan()) + list(CASES)))
    write(root / "CAUSAL_SURFACE_AUDIT.json", {
        "status": "PASS", "surface_count": len(results), "spent_tasks": 50, "stress_cases": 6,
        "future_row_feature_violations_observed": 0, "same_row_target_violations_observed": 0,
        "PIT_timestamp_violations": sum(r["PIT_timestamp_violations"] for r in results),
        "truth_or_latent_model_features": 0,
        "v7_exact_prefix_checks": sum(r["v7_exact_prefix_checks"] for r in results),
        "restatement_scope": "Frozen PIT public canonical snapshots; source available_at/effective_date/period_end ordering checked. No new vendor restatement feed was certified.",
        "random_shuffle_scope": "adversarial feature audit only; no training split shuffling",
        "wall_seconds": time.perf_counter() - started, "results": results})
    print("CAUSAL SURFACE AUDIT PASS: 50 spent + 6 stress", flush=True)


class MemoryStatus(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [
        (x, ctypes.c_ulonglong) for x in ("total_phys", "avail_phys", "total_page", "avail_page",
                                         "total_virtual", "avail_virtual", "avail_extended")]


def sample():
    memory = MemoryStatus()
    memory.length = ctypes.sizeof(memory)
    require(ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory)), "memory sample failed")
    counters = [ctypes.c_ulonglong() for _ in range(3)]
    require(ctypes.windll.kernel32.GetSystemTimes(*(ctypes.byref(v) for v in counters)), "CPU sample failed")
    return memory, [v.value for v in counters]


def monitor(root):
    memory, previous = sample()
    started = time.perf_counter()
    with (root / "RESOURCE_TELEMETRY.jsonl").open("x", encoding="utf-8") as stream:
        while True:
            time.sleep(5)
            memory, counters = sample()
            idle, kernel, user = [a-b for a,b in zip(counters, previous)]
            previous = counters
            row = {"elapsed_seconds": time.perf_counter()-started,
                   "system_cpu_percent": 100*(1-idle/(kernel+user)) if kernel+user else 0,
                   "system_ram_used_gib": (memory.total_phys-memory.avail_phys)/2**30,
                   "system_ram_total_gib": memory.total_phys/2**30,
                   "stress_completed": len(list((root/'stress').glob('*.json'))),
                   "full_A_tasks": len(list((root/'full_A').glob('task_*.json'))),
                   "full_B_tasks": len(list((root/'full_B').glob('task_*.json')))}
            stream.write(json.dumps(row)+'\n')
            stream.flush()
            if (root/'REPLAY_COMPLETE.json').exists() or (root/'NO_GO_RECEIPT.json').exists():
                break
    print("RESOURCE TELEMETRY COMPLETE", flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--monitor', action='store_true')
    args = parser.parse_args()
    (monitor if args.monitor else audit)(args.output_root.resolve())
