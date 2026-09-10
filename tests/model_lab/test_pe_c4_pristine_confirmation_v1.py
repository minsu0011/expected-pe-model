from __future__ import annotations

import json

import numpy as np
import pandas as pd

from research.model_zoo.pe_c4_pristine_confirmation_v1.canonical import (
    canonical_json_bytes,
    read_canonical_json,
    semantic_sha256,
    write_canonical_json_new,
)
from research.model_zoo.pe_c4_pristine_confirmation_v1.contracts import (
    C4_ID,
    CHAMPION_ID,
    DGP_IDS,
    GLOBAL_HOFS_LOG_SHRINK,
    HELDOUT_GATE,
    SEEDS,
    Task,
    tasks,
)
from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.metrics import (
    classify_heldout_gate,
)


def test_canonical_writer_reader_is_one_exact_contract(tmp_path) -> None:
    payload = {"한글": [2, 1], "a": {"z": True}}
    path = tmp_path / "payload.json"
    write_canonical_json_new(path, payload)
    assert path.read_bytes() == canonical_json_bytes(payload)
    assert path.read_bytes().endswith(b"\n")
    assert read_canonical_json(path) == payload
    assert len(semantic_sha256(payload)) == 64
    assert json.loads(path.read_text(encoding="utf-8")) == payload


def test_pristine_plan_is_fresh_fixed_and_complete() -> None:
    plan = tasks()
    assert SEEDS == (7879, 7883, 7901, 7907, 7919)
    assert len(plan) == 50
    assert len({(task.data_seed, task.dgp_id) for task in plan}) == 50
    assert tuple(task.dgp_id for task in plan[:10]) == DGP_IDS
    assert plan[0] == Task(0, 7879, "pristine_seed_01", "A")


def test_unchanged_c4_formula_and_exact_gate() -> None:
    champion = np.asarray([10.0, 20.0], dtype=np.float64)
    raw = np.log(np.asarray([40.0, 5.0], dtype=np.float64))
    observed = np.exp(np.log(champion) + GLOBAL_HOFS_LOG_SHRINK * (raw - np.log(champion)))
    np.testing.assert_allclose(observed, np.asarray([20.0, 10.0]), rtol=1e-15, atol=0.0)
    assert (CHAMPION_ID, C4_ID) == ("v04_expected_pe", "hofs_v4_expected_pe")
    gate = classify_heldout_gate(
        pooled_mae_gain=HELDOUT_GATE["pooled_mae_relative_gain_min"],
        pooled_rmse_gain=HELDOUT_GATE["pooled_rmse_relative_gain_min"],
        seed_wins=4,
        seed_total=5,
        worst_seed_dgp_harm=0.03,
        worst_dgp_mean_harm=0.01,
        pooled_p95_non_worse=True,
        pooled_extreme_frequency_non_worse=True,
        systematic_dgp_joint_tail_failure_count=0,
        bootstrap_mae_gain_lower_5pct=np.nextafter(0.0, 1.0),
    )
    assert gate["all_heldout_gates_pass"] is True


def test_prediction_long_order_contract() -> None:
    identity = pd.DataFrame(
        {
            "seed_alias": ["pristine_seed_01"] * 2,
            "dgp_id": ["A"] * 2,
            "session_position": [504, 505],
        }
    )
    repeated = identity.iloc[np.repeat(np.arange(2), 2)].reset_index(drop=True)
    repeated["model"] = np.tile([CHAMPION_ID, C4_ID], 2)
    assert repeated["model"].tolist() == [CHAMPION_ID, C4_ID, CHAMPION_ID, C4_ID]
