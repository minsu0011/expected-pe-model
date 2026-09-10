"""Run and seal the score-free Structural V5 verification boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from pe_regime_v04.model_lab.structural.contracts import (  # noqa: E402
    canonical_json_bytes,
    seal_payload,
    sha256_file,
)


OUTPUT = ROOT / "outputs/model_zoo_structural_wave_spent_screen_v5_20260819/V5_TEST_EVIDENCE.json"
PINNED = ROOT.parent / ".venv_pe_model_lab_py310/Scripts/python.exe"
BASE = Path("C:/Users/minsu/anaconda3/python.exe")
RUNNER = ROOT / "scripts/model_lab/structural/run_spent_predictions_v5.py"
SOURCES = (
    ROOT / "src/pe_regime_v04/model_lab/structural/authorization_v5.py",
    RUNNER,
    ROOT / "tests/model_lab/test_structural_v5_runner.py",
    ROOT / "scripts/model_lab/structural/benchmark_v5_scheduling_no_score.py",
)


def _run(command: Sequence[str], *, expect: int = 0) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(SRC)
    completed = subprocess.run(
        list(command),
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if completed.returncode != expect:
        raise RuntimeError(
            f"verification command failed ({completed.returncode} != {expect}): {command}\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return {
        "command": list(command),
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }


def _write_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(path)
    temporary = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    try:
        with temporary.open("xb") as handle:
            handle.write(canonical_json_bytes(payload) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    records = {
        "ruff": _run(["ruff", "check", *(str(path.relative_to(ROOT)) for path in SOURCES)]),
        "pinned_v5_tests": _run(
            [str(PINNED), "-m", "pytest", "-q", "tests/model_lab/test_structural_v5_runner.py"]
        ),
        "base_v5_tests": _run(
            [str(BASE), "-m", "pytest", "-q", "tests/model_lab/test_structural_v5_runner.py"]
        ),
        "pinned_runtime_accept": _run([str(PINNED), str(RUNNER), "--runtime-preflight-only"]),
        "base_runtime_reject": _run([str(BASE), str(RUNNER), "--runtime-preflight-only"], expect=1),
    }
    payload = seal_payload(
        {
            "format_version": 1,
            "mode": "structural_v5_score_free_test_evidence",
            "model_predictions_generated": False,
            "scores_computed": False,
            "seeds_reserved": False,
            "truth_opened": False,
            "commands": records,
            "legacy_v4_suite_boundary": (
                "not reused because it pins the audited pre-activation V4 policy raw bytes; "
                "V5 regressions use the isolated V5 policy loader"
            ),
            "source_files": [
                {
                    "path": path.relative_to(ROOT).as_posix(),
                    "bytes": path.stat().st_size,
                    "raw_sha256": sha256_file(path),
                }
                for path in SOURCES
            ],
            "assertions": {
                "exact_invalid_positions_0_1_all_spent_seeds": True,
                "fold_012_eligible_rows_502": True,
                "folds_012_036_filter_two_warmup_rows": True,
                "folds_037_073_filter_zero_rows": True,
                "formal_prediction_identity_coverage_unchanged": True,
                "chunked_vs_monolithic_canonical_parity": True,
                "failure_cancels_pending_without_wait": True,
                "base_python_3_13_rejected": True,
                "pinned_python_3_10_19_accepted": True,
            },
        }
    )
    _write_atomic(OUTPUT, payload)
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
