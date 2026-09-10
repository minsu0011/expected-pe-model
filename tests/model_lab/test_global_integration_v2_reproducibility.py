from __future__ import annotations

import json
import math
import os
from pathlib import Path
import subprocess
import sys

import numpy as np
import pytest

from research.model_zoo.aggressive_lab.global_integration.ensembles import (
    _correlation as ensemble_correlation,
)
from research.model_zoo.aggressive_lab.global_integration.metrics import (
    _correlation as model_correlation,
)
from research.model_zoo.aggressive_lab.global_integration.schema import OUTPUT_FILENAMES


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_V2_REPLAY_HASHES = {
    "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv": (
        21_309_125,
        "304c8c13aee41dcf299622601243364b50c077d11a254e3e89650ba3b10eaba3",
    ),
    "EXPECTED_PE_GLOBAL_LEADERBOARD.csv": (
        88_053,
        "e5b6ffb66a7977d47a8effe3db8e88343f8af007c42ab05cd977b1c3a142f144",
    ),
    "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv": (
        9_190,
        "06997dafccef2357a003db49792db8f4e935376824eebe72c51c73576d81d74c",
    ),
}

_REPLAY_SCRIPT = r"""
from __future__ import annotations
import hashlib
import io
import json
from pathlib import Path
import pandas as pd
from scripts.model_lab.aggressive_lab.finalize_global_integration import replay_in_memory

tables = replay_in_memory(Path.cwd())
receipt = {}
v1_directory = Path.cwd() / "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820"
for filename, frame in tables.as_mapping().items():
    stream = io.StringIO(newline="")
    frame.to_csv(
        stream,
        index=False,
        lineterminator="\n",
        float_format="%.17g",
    )
    payload = stream.getvalue().encode("utf-8")
    replayed_tokens = pd.read_csv(io.StringIO(stream.getvalue()), dtype=str, keep_default_na=False)
    v1_tokens = pd.read_csv(v1_directory / filename, dtype=str, keep_default_na=False)
    correlation_columns = [column for column in frame.columns if "correlation" in column]
    noncorrelation_columns = [column for column in frame.columns if column not in correlation_columns]
    correlation_differences = sum(
        int((replayed_tokens[column] != v1_tokens[column]).sum())
        for column in correlation_columns
    )
    receipt[filename] = {
        "rows": len(frame),
        "bytes": len(payload),
        "raw_sha256": hashlib.sha256(payload).hexdigest(),
        "noncorrelation_tokens_equal_v1": replayed_tokens.loc[:, noncorrelation_columns].equals(
            v1_tokens.loc[:, noncorrelation_columns]
        ),
        "correlation_token_difference_count_vs_v1": correlation_differences,
    }
print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
"""


def _cross_process_receipt(*, threads: int, python_hash_seed: int) -> dict[str, object]:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": os.pathsep.join((str(ROOT / "src"), str(ROOT))),
            "PYTHONHASHSEED": str(python_hash_seed),
            "OMP_NUM_THREADS": str(threads),
            "MKL_NUM_THREADS": str(threads),
            "OPENBLAS_NUM_THREADS": str(threads),
            "NUMEXPR_NUM_THREADS": str(threads),
            "VECLIB_MAXIMUM_THREADS": str(threads),
            "CUDA_VISIBLE_DEVICES": "-1",
            "NVIDIA_VISIBLE_DEVICES": "void",
        }
    )
    completed = subprocess.run(
        [sys.executable, "-c", _REPLAY_SCRIPT],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(completed.stdout)


@pytest.mark.parametrize("correlation", [model_correlation, ensemble_correlation])
def test_fixed_order_correlation_contract(correlation: object) -> None:
    calculate = correlation
    left = np.asarray([1.0, 1.0e16, -1.0e16, 3.0, 8.0, -2.0], dtype=np.float64)
    right = np.asarray([-4.0, 7.0, 2.0, 9.0, -5.0, 6.0], dtype=np.float64)
    forward = calculate(left, right)  # type: ignore[operator]
    repeated = calculate(left.copy(), right.copy())  # type: ignore[operator]
    assert forward.hex() == repeated.hex()
    assert math.isnan(calculate(np.ones(3), np.arange(3.0)))  # type: ignore[operator]
    assert math.isnan(calculate(np.asarray([1.0]), np.asarray([2.0])))  # type: ignore[operator]
    with pytest.raises(ValueError, match="differ in length"):
        calculate(np.arange(3.0), np.arange(2.0))  # type: ignore[operator]


def test_actual_v2_csvs_are_hash_exact_across_fresh_processes() -> None:
    single_thread = _cross_process_receipt(threads=1, python_hash_seed=7)
    four_threads = _cross_process_receipt(threads=4, python_hash_seed=1_337)
    assert single_thread == four_threads
    assert tuple(single_thread) == tuple(sorted(OUTPUT_FILENAMES))
    assert {name: row["rows"] for name, row in single_thread.items()} == {
        "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv": 22_100,
        "EXPECTED_PE_GLOBAL_LEADERBOARD.csv": 82,
        "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv": 13,
    }
    assert {
        name: (row["bytes"], row["raw_sha256"]) for name, row in single_thread.items()
    } == EXPECTED_V2_REPLAY_HASHES
    assert all(row["noncorrelation_tokens_equal_v1"] for row in single_thread.values())
    assert (
        single_thread["EXPECTED_PE_GLOBAL_LEADERBOARD.csv"][
            "correlation_token_difference_count_vs_v1"
        ]
        > 0
    )
    assert (
        single_thread["EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv"][
            "correlation_token_difference_count_vs_v1"
        ]
        > 0
    )
    assert (
        single_thread["EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv"][
            "correlation_token_difference_count_vs_v1"
        ]
        == 0
    )
