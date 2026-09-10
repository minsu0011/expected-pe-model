from __future__ import annotations

import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.bounded_consensus_v1 import (
    RESEARCH_GATE,
    VARIANT_IDS,
    VARIANT_SPECS,
    AblationSurfaceSchema,
    BoundedConsensusContractError,
    TailEvaluationSchema,
    adapt_ablation_surfaces,
    build_observable_state_confidence,
    compute_variant,
    design_lock_payload,
    design_lock_sha256,
    evaluate_bounded_consensus_tails,
)
from research.model_zoo.bounded_consensus_v1.contracts import (
    STATE_CONFIDENCE_OUTPUT_COLUMN,
    STATE_CONFIDENCE_SOURCE_COLUMNS,
    forbidden_model_input_columns,
)
from research.model_zoo.bounded_consensus_v1.source_audit import audit_source_boundary
from research.model_zoo.observable_fair_value_state_v1 import contract_sha256


def _state_frame(rows: int) -> pd.DataFrame:
    positions = np.arange(rows, dtype=np.float64)
    return pd.DataFrame(
        {
            "ofs_v1_eps_confidence_01": 0.9 - 0.05 * (positions % 2),
            "ofs_v1_eps_staleness_log1p": np.log1p(positions % 30),
            "ofs_v1_regime_entropy": 0.25 + 0.05 * (positions % 3),
            "ofs_v1_regime_confidence": 0.75 - 0.03 * (positions % 3),
            "ofs_v1_state_abs_innovation_lag1": 0.02 + 0.005 * (positions % 4),
        }
    )


def _adapter_frame(rows: int = 30) -> pd.DataFrame:
    positions = np.arange(rows, dtype=np.float64)
    base = 20.0 + 0.01 * positions
    correction_a = 0.02 + 0.001 * (positions % 5)
    correction_b = 0.018 + 0.001 * (positions % 3)
    correction_b[7] = -0.01
    frame = pd.DataFrame(
        {
            "seed": 1701,
            "dgp_id": "DGP_A",
            "date": pd.bdate_range("2020-01-02", periods=rows),
            "fold_id": (positions // 5).astype(int),
            "v04_surface": base,
            "state_surface_a": base * np.exp(correction_a),
            "state_surface_b": base * np.exp(correction_b),
        }
    )
    confidence = build_observable_state_confidence(_state_frame(rows))
    frame[STATE_CONFIDENCE_OUTPUT_COLUMN] = confidence.confidence
    return frame


def _schema() -> AblationSurfaceSchema:
    return AblationSurfaceSchema(
        base_prediction_column="v04_surface",
        challenger_a_prediction_column="state_surface_a",
        challenger_b_prediction_column="state_surface_b",
        challenger_a_id="ofs_v1_state_ablation_a",
        challenger_b_id="ofs_v1_state_ablation_b",
        observable_state_confidence_column=STATE_CONFIDENCE_OUTPUT_COLUMN,
        oof_fold_column="fold_id",
        group_columns=("seed",),
        identity_columns=("seed", "dgp_id", "date"),
    )


def test_design_lock_has_five_structures_and_exact_research_gates() -> None:
    payload = design_lock_payload()
    assert len(VARIANT_IDS) == 5
    assert len(VARIANT_SPECS) == 5
    assert all(not spec.tunable_after_results for spec in VARIANT_SPECS)
    assert payload["disagreement_correction"] == 0.0
    assert payload["truth_access"] == "tail_evaluator_only"
    assert payload["heldout_derived_thresholds"] is False
    assert payload["oracle_diagnostics_used_by_gate"] is False
    assert RESEARCH_GATE.expected_seed_count == 10
    assert RESEARCH_GATE.strong_mae_relative_gain_min == 0.005
    assert RESEARCH_GATE.strong_seed_wins_min == 6
    assert RESEARCH_GATE.strong_worst_seed_mae_harm_max == 0.03
    assert RESEARCH_GATE.signal_seed_wins_min == 5
    assert RESEARCH_GATE.signal_worst_seed_mae_harm_max == 0.05
    assert len(design_lock_sha256()) == 64
    assert design_lock_sha256() == design_lock_sha256()


def test_fixed_state_confidence_is_monotone_and_missing_fails_closed() -> None:
    baseline = pd.DataFrame(
        {
            "ofs_v1_eps_confidence_01": [0.9] * 6,
            "ofs_v1_eps_staleness_log1p": [math.log1p(10.0)] * 6,
            "ofs_v1_regime_entropy": [0.2] * 6,
            "ofs_v1_regime_confidence": [0.8] * 6,
            "ofs_v1_state_abs_innovation_lag1": [0.05] * 6,
        }
    )
    baseline.loc[1, "ofs_v1_eps_confidence_01"] = 0.4
    baseline.loc[2, "ofs_v1_eps_staleness_log1p"] = math.log1p(200.0)
    baseline.loc[3, "ofs_v1_regime_entropy"] = 0.8
    baseline.loc[4, "ofs_v1_state_abs_innovation_lag1"] = 0.8
    baseline.loc[5, "ofs_v1_state_abs_innovation_lag1"] = np.nan
    result = build_observable_state_confidence(baseline)
    values = result.confidence.to_numpy()
    assert tuple(baseline.columns) == STATE_CONFIDENCE_SOURCE_COLUMNS
    assert values[1] < values[0]
    assert values[2] < values[0]
    assert values[3] < values[0]
    assert values[4] < values[0]
    assert values[5] == 0.0
    assert result.missing_or_invalid_rows == 1
    assert not any("observed_pe" in column for column in STATE_CONFIDENCE_SOURCE_COLUMNS)


def test_generic_adapter_runs_all_five_and_disagreement_is_exactly_base() -> None:
    frame = _adapter_frame()
    batch = adapt_ablation_surfaces(
        frame,
        schema=_schema(),
        state_contract_sha256=contract_sha256(),
    )
    assert tuple(batch.results) == VARIANT_IDS
    long = batch.to_long_frame()
    assert len(long) == len(frame) * 5
    assert long["bce_v1_alpha"].between(0.0, 1.0).all()
    disagreement = ~long["bce_v1_directional_agreement"]
    assert long.loc[disagreement, "bce_v1_applied_log_correction"].eq(0.0).all()
    assert np.array_equal(
        long.loc[disagreement, "bce_v1_prediction"].to_numpy(),
        long.loc[disagreement, "bce_v1_base_prediction"].to_numpy(),
    )
    assert long["bce_v1_scoring_eligible"].all()
    assert long["bce_v1_design_lock_sha256"].eq(design_lock_sha256()).all()


def test_model_adapter_rejects_truth_current_pe_heldout_and_wrong_state_contract() -> None:
    frame = _adapter_frame()
    for forbidden_column in ("true_fair_pe", "observed_pe", "heldout_cap", "tracking_error"):
        attacked = frame.copy()
        attacked[forbidden_column] = 1.0
        with pytest.raises(BoundedConsensusContractError, match="cannot enter"):
            adapt_ablation_surfaces(
                attacked,
                schema=_schema(),
                state_contract_sha256=contract_sha256(),
            )
    assert forbidden_model_input_columns(["future_return", "target_value"])
    with pytest.raises(BoundedConsensusContractError, match="contract hash"):
        adapt_ablation_surfaces(
            frame,
            schema=_schema(),
            state_contract_sha256="0" * 64,
        )


def test_variant_e_uses_only_prior_atomic_oof_folds() -> None:
    rows = 25
    base = np.full(rows, 20.0)
    correction_a = np.linspace(0.01, 0.04, rows)
    correction_b = np.linspace(0.012, 0.035, rows)
    folds = np.repeat(np.arange(5), 5)
    kwargs = {
        "variant_id": "bce_v1_e_prior_oof_prefix_quantile_clip",
        "base_prediction": base,
        "challenger_a_prediction": base * np.exp(correction_a),
        "challenger_b_prediction": base * np.exp(correction_b),
        "group_codes": np.zeros(rows, dtype=int),
        "dates": pd.bdate_range("2020-01-02", periods=rows),
        "oof_fold_ids": folds,
    }
    baseline = compute_variant(**kwargs)
    assert np.isnan(baseline.correction_budget[:10]).all()
    assert np.isfinite(baseline.correction_budget[10:]).all()
    attacked_a = correction_a.copy()
    attacked_b = correction_b.copy()
    attacked_a[10:15] = 0.4
    attacked_b[10:15] = 0.3
    attacked = compute_variant(
        **{
            **kwargs,
            "challenger_a_prediction": base * np.exp(attacked_a),
            "challenger_b_prediction": base * np.exp(attacked_b),
        }
    )
    np.testing.assert_array_equal(
        baseline.correction_budget[10:15], attacked.correction_budget[10:15]
    )
    assert not np.array_equal(baseline.correction_budget[15:20], attacked.correction_budget[15:20])

    bad_folds = folds.copy()
    bad_folds[20:] = 1
    with pytest.raises(BoundedConsensusContractError, match="one chronological block"):
        compute_variant(**{**kwargs, "oof_fold_ids": bad_folds})


def test_rolling_budget_is_prefix_invariant_and_adapter_is_row_order_invariant() -> None:
    frame = _adapter_frame(40)
    baseline = adapt_ablation_surfaces(
        frame,
        schema=_schema(),
        state_contract_sha256=contract_sha256(),
    )
    changed = frame.copy()
    changed.loc[30:, "state_surface_a"] *= 1.8
    changed.loc[30:, "state_surface_b"] *= 1.7
    attacked = adapt_ablation_surfaces(
        changed,
        schema=_schema(),
        state_contract_sha256=contract_sha256(),
    )
    variant_b = "bce_v1_b_causal_rolling_dispersion_budget"
    np.testing.assert_array_equal(
        baseline.results[variant_b].loc[:29, "bce_v1_alpha"].to_numpy(),
        attacked.results[variant_b].loc[:29, "bce_v1_alpha"].to_numpy(),
    )

    shuffled = frame.sample(frac=1.0, random_state=71)
    shuffled_batch = adapt_ablation_surfaces(
        shuffled,
        schema=_schema(),
        state_contract_sha256=contract_sha256(),
    )
    columns = ["seed", "date", "bce_v1_alpha", "bce_v1_prediction"]
    left = baseline.results[variant_b].loc[:, columns].sort_values(["seed", "date"])
    right = shuffled_batch.results[variant_b].loc[:, columns].sort_values(["seed", "date"])
    pd.testing.assert_frame_equal(left.reset_index(drop=True), right.reset_index(drop=True))


def _tail_frame() -> pd.DataFrame:
    factor_by_variant = {
        VARIANT_IDS[0]: lambda seed: 0.90,
        VARIANT_IDS[1]: lambda seed: 0.90 if seed < 5 else 1.00,
        VARIANT_IDS[2]: lambda seed: 1.10,
        VARIANT_IDS[3]: lambda seed: 0.95,
        VARIANT_IDS[4]: lambda seed: 0.90,
    }
    rows: list[dict[str, object]] = []
    truth = 20.0
    for variant_id in VARIANT_IDS:
        for seed in range(10):
            for dgp_number, dgp_id in enumerate(("DGP_A", "DGP_B")):
                sign = -1.0 if (seed + dgp_number) % 2 else 1.0
                base_error = sign * 0.10
                candidate_error = base_error * factor_by_variant[variant_id](seed)
                rows.append(
                    {
                        "bce_v1_variant_id": variant_id,
                        "seed": seed,
                        "dgp_id": dgp_id,
                        "date": pd.Timestamp("2025-01-02") + pd.Timedelta(days=dgp_number),
                        "bce_v1_scoring_eligible": True,
                        "truth": truth,
                        "bce_v1_base_prediction": truth * math.exp(base_error),
                        "bce_v1_challenger_a_prediction": truth * math.exp(base_error * 0.8),
                        "bce_v1_challenger_b_prediction": truth * math.exp(base_error * 1.2),
                        "bce_v1_prediction": truth * math.exp(candidate_error),
                    }
                )
    return pd.DataFrame(rows)


def test_tail_evaluator_emits_fixed_tail_stability_and_oracle_diagnostics() -> None:
    frame = _tail_frame()
    schema = TailEvaluationSchema(truth_column="truth")
    result = evaluate_bounded_consensus_tails(frame, schema=schema)
    pooled = result.pooled_metrics.set_index("bce_v1_variant_id")
    assert pooled.loc[VARIANT_IDS[0], "research_gate_status"] == "STRONG_SURVIVOR"
    assert pooled.loc[VARIANT_IDS[1], "research_gate_status"] == "SIGNAL_ONLY"
    assert pooled.loc[VARIANT_IDS[2], "research_gate_status"] == "REJECT"
    assert pooled.loc[VARIANT_IDS[0], "seed_wins"] == 10
    assert pooled.loc[VARIANT_IDS[1], "seed_wins"] == 5
    assert pooled.loc[VARIANT_IDS[2], "worst_seed_mae_relative_harm"] == pytest.approx(0.10)
    assert "candidate_fair_abs_log_error_p95" in pooled.columns
    assert "candidate_fair_abs_log_error_p99" in pooled.columns
    assert "candidate_extreme_error_frequency" in pooled.columns
    assert len(result.seed_metrics) == 50
    assert len(result.dgp_metrics) == 10
    assert len(result.seed_dgp_metrics) == 100
    assert {
        "signed_residual_correlation",
        "absolute_error_correlation",
    }.issubset(result.correlation_diagnostics.columns)
    assert result.correlation_diagnostics["research_gate_used"].eq(False).all()
    assert result.oracle_diagnostics["diagnostic_only"].all()
    assert result.oracle_diagnostics["research_gate_used"].eq(False).all()
    assert result.design_lock_sha256 == design_lock_sha256()


def test_tail_gate_is_ineligible_off_ten_seeds_and_common_mask_fails_closed() -> None:
    schema = TailEvaluationSchema(truth_column="truth")
    nine_seed = _tail_frame().loc[lambda data: data["seed"] < 9].copy()
    result = evaluate_bounded_consensus_tails(nine_seed, schema=schema)
    assert result.pooled_metrics["research_gate_status"].eq("INELIGIBLE_SEED_COUNT").all()

    mismatch = _tail_frame()
    position = mismatch.index[mismatch["bce_v1_variant_id"].eq(VARIANT_IDS[-1])][0]
    mismatch.loc[position, "bce_v1_base_prediction"] *= 1.01
    with pytest.raises(BoundedConsensusContractError, match="changed across variants"):
        evaluate_bounded_consensus_tails(mismatch, schema=schema)


def test_source_boundary_scanner_blocks_v5_literals_and_model_truth_access(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    package_dir = project_root / "research" / "model_zoo" / "bounded_consensus_v1"
    v5_audit = (
        project_root
        / "outputs"
        / "model_zoo_prospective_fresh_ensemble_v5_heldout_terminal_audit_20260820"
        / "AUDIT.json"
    )
    baseline = audit_source_boundary(
        package_dir=package_dir,
        v5_terminal_audit_path=v5_audit,
    )
    assert baseline.passed
    assert baseline.v5_path_token_count > 0
    assert baseline.v5_hash_literal_count > 0
    assert baseline.v5_metric_literal_count > 0
    assert baseline.leakage_hit_count == 0
    assert baseline.forbidden_identifier_hit_count == 0
    assert baseline.forbidden_import_hit_count == 0

    attacked_package = tmp_path / "bounded_consensus_v1"
    shutil.copytree(package_dir, attacked_package)
    raw = v5_audit.read_text(encoding="utf-8")
    heldout_hash = re.search(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", raw).group(0)
    heldout_metric = re.search(r"(?<![\w.])-?\d+\.\d{6,}(?![\w.])", raw).group(0)
    heldout_id = "prospective_fresh_ensemble_v5_heldout_terminal_audit_20260820"
    with (attacked_package / "variants.py").open("a", encoding="utf-8") as handle:
        handle.write(
            f'\ntruth = 1.0\n_v5_path = "{heldout_id}"\n'
            f'_v5_hash = "{heldout_hash}"\n_v5_metric = {heldout_metric}\n'
        )
    attacked = audit_source_boundary(
        package_dir=attacked_package,
        v5_terminal_audit_path=v5_audit,
    )
    assert not attacked.passed
    assert attacked.leakage_hit_count >= 3
    assert attacked.forbidden_identifier_hit_count >= 1


def test_tail_csv_bytes_are_exact_across_thread_and_hashseed_children(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[2]
    input_path = tmp_path / "tail_input.csv"
    _tail_frame().to_csv(input_path, index=False, lineterminator="\n")
    child_code = f"""
import hashlib
import pandas as pd
from research.model_zoo.bounded_consensus_v1 import TailEvaluationSchema, evaluate_bounded_consensus_tails
frame = pd.read_csv(r"{input_path}", parse_dates=["date"])
result = evaluate_bounded_consensus_tails(frame, schema=TailEvaluationSchema(truth_column="truth"))
names = ("pooled_metrics", "seed_metrics", "dgp_metrics", "seed_dgp_metrics", "correlation_diagnostics", "oracle_diagnostics")
parts = []
for name in names:
    csv_bytes = getattr(result, name).to_csv(index=False, lineterminator="\\n", na_rep="NaN").encode("utf-8")
    parts.append(name.encode("ascii") + b"\\n" + csv_bytes)
print(hashlib.sha256(b"\\n--TABLE--\\n".join(parts)).hexdigest())
"""

    def _child_hash(*, hash_seed: str, threads: str) -> str:
        environment = os.environ.copy()
        environment.update(
            {
                "PYTHONHASHSEED": hash_seed,
                "PYTHONPATH": os.pathsep.join([str(project_root), str(project_root / "src")]),
                "OMP_NUM_THREADS": threads,
                "OPENBLAS_NUM_THREADS": threads,
                "MKL_NUM_THREADS": threads,
                "NUMEXPR_NUM_THREADS": threads,
            }
        )
        completed = subprocess.run(
            [sys.executable, "-c", child_code],
            cwd=project_root,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        return completed.stdout.strip()

    first = _child_hash(hash_seed="7", threads="1")
    second = _child_hash(hash_seed="991", threads="8")
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert first == second
