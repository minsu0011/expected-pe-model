from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys

import pandas as pd
import pytest

from pe_regime_v04.model_lab.contracts import ContractError
from research.model_zoo.aggressive_lab import EVIDENCE_CLASS, PROMOTION_AUTHORITY
from research.model_zoo.aggressive_lab.artifacts import write_tournament_evaluation
from research.model_zoo.aggressive_lab.contracts import (
    DESIGN_LOCK_RAW_SHA256,
    AggressiveLabContractError,
    TournamentThresholds,
    load_sealed_design_lock,
)
from research.model_zoo.aggressive_lab.evaluation import (
    evaluate_tournament,
    pairwise_complementarity,
)


def _predictions(*, complementary: bool = False) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    for seed in (1, 2, 3, 4, 5):
        for position, truth in enumerate((10.0, 20.0, 30.0, 40.0)):
            date = pd.Timestamp("2020-01-02") + pd.offsets.BDay(position)
            if complementary:
                incumbent_error = (0.04, 0.08, 0.12, 0.16)[position]
                candidate_error = (-0.16, -0.12, -0.08, -0.04)[position]
                incumbent = truth * math.exp(incumbent_error)
                candidate = truth * math.exp(candidate_error)
            else:
                incumbent = truth * math.exp(0.10 if position % 2 == 0 else -0.10)
                candidate = truth * math.exp(0.02 if position % 2 == 0 else -0.02)
            for model_id, prediction in {
                "v04_expected_pe": incumbent,
                "candidate": candidate,
            }.items():
                rows.append(
                    {
                        "seed": seed,
                        "date": date,
                        "model_id": model_id,
                        "prediction": prediction,
                        "true_fair_pe": truth,
                    }
                )
    return pd.DataFrame(rows)


def test_design_lock_is_code_owned_and_canonical() -> None:
    design = load_sealed_design_lock()
    path = Path("outputs/model_zoo_aggressive_lab_20260820/DESIGN_LOCK.json")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == DESIGN_LOCK_RAW_SHA256
    assert design["evidence_class"] == EVIDENCE_CLASS
    assert design["promotion_authority"] == PROMOTION_AUTHORITY
    assert design["resource_policy"]["cpu_ids"] == list(range(16, 32))


def test_tournament_gate_and_common_mask() -> None:
    result = evaluate_tournament(_predictions(), incumbent_model_id="v04_expected_pe")
    row = result.comparisons.iloc[0]
    assert bool(row["tournament_gate_pass"])
    assert row["status"] == "PROMISING"
    assert row["seed_win_rate"] == 1.0
    assert result.evaluation.summary["identity_sha256"].nunique() == 1


def test_complementarity_route_preserves_near_champion() -> None:
    result = evaluate_tournament(
        _predictions(complementary=True),
        incumbent_model_id="v04_expected_pe",
        thresholds=TournamentThresholds(
            min_mean_mae_gain=0.01,
            research_max_abs_error_correlation=0.25,
        ),
    )
    row = result.comparisons.iloc[0]
    assert not bool(row["tournament_gate_pass"])
    assert bool(row["research_continue"])
    assert row["status"] == "ENSEMBLE_COMPONENT"
    assert row["error_sign_disagreement_rate"] == 1.0


def test_truth_mismatch_fails_closed() -> None:
    frame = _predictions()
    target = frame.index[(frame["model_id"] == "candidate")][0]
    frame.loc[target, "true_fair_pe"] = 999.0
    with pytest.raises(ContractError, match="truth"):
        evaluate_tournament(frame, incumbent_model_id="v04_expected_pe")


def test_pairwise_complementarity_uses_identical_mask() -> None:
    pairwise = pairwise_complementarity(_predictions(complementary=True))
    assert len(pairwise) == 1
    row = pairwise.iloc[0]
    assert row["rows"] == 20
    assert row["absolute_error_correlation"] == pytest.approx(-1.0)
    assert row["error_sign_disagreement_rate"] == 1.0
    assert row["oracle_mae_relative_gain_vs_better_single"] > 0.0


def test_writer_is_immutable_and_labels_nonpromotion(tmp_path: Path) -> None:
    result = evaluate_tournament(_predictions(), incumbent_model_id="v04_expected_pe")
    output = tmp_path / "evidence"
    manifest = write_tournament_evaluation(result, output, metadata={"test": True})
    assert manifest["evidence_class"] == EVIDENCE_CLASS
    assert manifest["promotion_authority"] == PROMOTION_AUTHORITY
    on_disk = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert on_disk["artifact_sha256"] == manifest["artifact_sha256"]
    with pytest.raises(AggressiveLabContractError, match="already exists"):
        write_tournament_evaluation(result, output, metadata={"test": True})


@pytest.mark.skipif(os.name != "nt" or (os.cpu_count() or 0) < 32, reason="Windows 32-CPU host")
def test_battleground_affinity_in_fresh_process() -> None:
    code = (
        "import json; "
        "from research.model_zoo.aggressive_lab.resources import seal_battleground_process; "
        "print(json.dumps(seal_battleground_process().as_dict(), sort_keys=True))"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = "src;."
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path.cwd(),
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    receipt = json.loads(completed.stdout)
    assert receipt["cpu_ids"] == list(range(16, 32))
    assert receipt["affinity_mask_hex"] == "0xFFFF0000"
    assert receipt["gpu_sealed"] is True
