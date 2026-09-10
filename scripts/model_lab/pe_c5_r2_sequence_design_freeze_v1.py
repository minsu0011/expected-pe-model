"""Freeze the C5-R2 scientific identity without fitting or scoring."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))


def _raw(path: Path) -> bytes:
    return path.read_bytes()


def _sha(path: Path) -> str:
    return hashlib.sha256(_raw(path)).hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)


def run(output_root: Path) -> dict[str, object]:
    from research.model_zoo.pe_c5_r2_sequence_design_v1.contracts import (
        ALLOWED_INPUT_NAMES,
        LOOKBACK,
        PROHIBITED_INPUT_NAMES,
        TEST_STARTS,
        build_sample_receipts,
    )

    root = Path(output_root)
    if root.exists():
        raise RuntimeError("C5-R2 design root already exists")
    root.mkdir(parents=True)
    probe_positions = tuple(range(504, 1800))
    receipts = build_sample_receipts(probe_positions)
    if any(receipt.source_positions[-1] >= receipt.label_position for receipt in receipts):
        raise RuntimeError("C5-R2 chronology probe failed")
    source_files = (
        "research/model_zoo/pe_c5_r2_sequence_design_v1/contracts.py",
        "scripts/model_lab/pe_c5_r2_sequence_design_freeze_v1.py",
    )
    source_records = [
        {
            "relative_path": relative,
            "raw_sha256": _sha((PROJECT_ROOT / relative).resolve(strict=True)),
            "size_bytes": (PROJECT_ROOT / relative).stat().st_size,
        }
        for relative in source_files
    ]
    design = {
        "schema_version": "expected_pe.c5_r2.sequence_scientific_contract.v1",
        "status": "FROZEN_SCORE_FREE_LEAKAGE_FREE_SEQUENCE_DESIGN",
        "scientific_identity": "forecast next fair-log-PE residual using only positions < t",
        "label_position": "t",
        "target": "true_log_fair_pe[t]-v04_expected_log_pe[t-1]",
        "deployed_prediction": "v04_expected_log_pe[t-1]+predicted_residual[t]",
        "lookback_sessions": LOOKBACK,
        "input_source_constraint": "max(source_position) < label_position",
        "input_feature_order": list(ALLOWED_INPUT_NAMES),
        "prohibited_same_row_or_future_inputs": sorted(PROHIBITED_INPUT_NAMES),
        "same_row_target_shortcut_removed": True,
        "same_row_proxy_equivalent_removed": True,
        "future_leakage_allowed": False,
        "fold_contract": {
            "test_starts": list(TEST_STARTS),
            "step": 21,
            "first_label_position": 504,
            "last_label_position": 1799,
            "fit_labels_max": "test_start_position-1",
            "within_test_block_parameter_updates": 0,
            "embargo": "one label boundary; every tensor receipt checked row-wise",
        },
        "candidate_order": [
            "lagged_v04_persistence",
            "dlinear_residual",
            "compact_gru",
            "gru_d_missingness_aware",
            "compact_lstm",
            "causal_tcn_rebuilt",
        ],
        "candidate_budget": {
            "one_predeclared_configuration_per_family": True,
            "initial_neural_parameter_cap": 250_000,
            "initial_training_epoch_cap": 80,
            "early_stopping_uses_training_prefix_only": True,
            "transformer_s4_mamba_initial_wave": False,
        },
        "evaluation": [
            "paired_log_MAE_and_RMSE",
            "jump_response_delay",
            "slow_state_tracking_error",
            "shock_recovery_half_life",
            "systematic_joint_tail",
            "signed_and_absolute_error_correlation_with_C4",
            "signed_and_absolute_error_correlation_with_C2",
            "oracle_pair_gain_for_portfolio_diversity",
        ],
        "portfolio_admission_rule": (
            "admit only if positive standalone or oracle-pair gain, controlled tail, "
            "and materially lower error correlation than core C4/C2"
        ),
        "research_data": "spent/public synthetic surfaces only until identity freeze",
        "formal_evidence_requires_new_fresh_identity": True,
        "hardware_plan": {
            "gpu": "RTX 5080 deterministic float32 training",
            "cpu": "7950X3D data preparation and fold workers",
            "ram": "96 GiB memory-mapped sequence cache",
            "determinism": [
                "torch deterministic algorithms",
                "CUBLAS_WORKSPACE_CONFIG=:4096:8",
                "no mixed precision in parity reference",
                "two-process prediction digest equality",
            ],
        },
        "mechanical_chronology_probe": {
            "sample_count": len(receipts),
            "first_receipt": receipts[0].payload(),
            "last_receipt": receipts[-1].payload(),
            "all_max_source_lt_label": True,
        },
        "source_records": source_records,
        "fit_count": 0,
        "score_count": 0,
        "truth_open_count": 0,
        "promotion_authority": False,
    }
    _write(root / "C5_R2_SCIENTIFIC_DESIGN_LOCK.json", _canonical(design))
    report = """# C5-R2 Scientific Design Freeze

C5-R2 is now a genuine temporal forecasting task. For a label at position `t`, its 63-session tensor contains only positions `t-63 ... t-1`; the anchor is `v04_expected_log_pe[t-1]`. Same-row truth, deterministic target transforms, same-row proxy equivalents, and future-named features are prohibited by code.

The initial comparison starts with lagged-v04 persistence and DLinear residual, then compact GRU/GRU-D/LSTM and a rebuilt causal TCN. Transformer/S4/Mamba families are deferred until a compact sequence baseline demonstrates value.

Evaluation includes response delay, slow-state tracking, shock recovery, joint tail, and error correlation with C4/C2. A lower-correlation specialist may enter the portfolio even without beating C4 globally, but only with positive paired/oracle value and controlled tail risk.

This artifact is score-free and creates no qualification, heldout, registry, or promotion authority.
"""
    _write(root / "C5_R2_DESIGN_REPORT.md", report.encode("utf-8"))
    leaves = ("C5_R2_DESIGN_REPORT.md", "C5_R2_SCIENTIFIC_DESIGN_LOCK.json")
    _write(
        root / "CHECKSUMS.sha256",
        "".join(f"{_sha(root / leaf)}  {leaf}\n" for leaf in leaves).encode("ascii"),
    )
    return design


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    design = run(args.output_root)
    print(json.dumps({"status": design["status"], "output_root": str(args.output_root)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
