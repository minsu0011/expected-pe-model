"""Score five predeclared C2-R2 reliability variants on spent research surfaces."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any

import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

PREDICTIONS = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v1_predictions_r1_"
    "20260821/PREDICTIONS.csv"
)
PUBLIC_ROOT = PROJECT_ROOT / "outputs/model_zoo_dgp_state_tournament_v1_inputs_r4_20260821"
TRUTH_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_dgp_state_tournament_v1_truth_vault_r2_20260821/vault"
)
C4_PREDICTIONS = PROJECT_ROOT / (
    "outputs/model_zoo_hofs_research_adapter_v1_full_r2_20260822/STANDARDIZED_PREDICTIONS.csv"
)
SEED_VALUES = (2026082001, 2026082003, 2026082007, 2026082011, 2026082017)
SEED_ALIASES = tuple(f"research_seed_{index:02d}" for index in range(1, 6))
DGP_IDS = tuple("ABCDEFGHIJ")
IDENTITY_COLUMNS = (
    "seed_alias",
    "dgp_id",
    "date",
    "symbol",
    "session_position",
    "fold_id",
)
FEATURE_COLUMNS = (
    "date",
    "symbol",
    "eps_confidence",
    "eps_staleness_days",
    "regime_entropy",
    "regime_confidence",
    "regime_conditional_pe_log_z",
    "benchmark_realized_vol_20",
    "valuation_confidence",
)
VARIANTS = {
    "c2_r2_a_disagreement_shrink": {
        "formula": "alpha=base_conf/(1+challenger_log_disagreement/log(1.05))",
        "purpose": "reduce correction when the two challengers disagree",
    },
    "c2_r2_b_robust_cap_040": {
        "formula": "applied_correction=clip(base_conf*raw_correction, +/-log(1.04))",
        "purpose": "bound single-row correction magnitude",
    },
    "c2_r2_c_ood_state_shrink": {
        "formula": "alpha=base_conf*exp(-abs(valuation_z)/3)*sqrt(regime_confidence)",
        "purpose": "shrink observable valuation-state OOD conditions",
    },
    "c2_r2_d_staleness_vol_shrink": {
        "formula": "alpha=base_conf*sqrt(eps_confidence)*exp(-staleness/252)/(1+vol20/0.03)",
        "purpose": "shrink stale/low-confidence EPS and volatile markets",
    },
    "c2_r2_e_tail_reliability": {
        "formula": "alpha=base_conf*sqrt(state_rel*data_rel); correction clipped +/-log(1.035)",
        "purpose": "joint reliability with explicit tail cap",
    },
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)


def _load_public_features(base: pd.DataFrame) -> pd.DataFrame:
    frames = []
    for seed_alias, seed in zip(SEED_ALIASES, SEED_VALUES, strict=True):
        for dgp in DGP_IDS:
            path = (
                PUBLIC_ROOT / "replays/pass_1" / f"seed_{seed}" / f"dgp_{dgp}" / "canonical150.csv"
            )
            frame = pd.read_csv(path, usecols=list(FEATURE_COLUMNS), float_precision="round_trip")
            frame = frame.iloc[504:1800].copy()
            frame.insert(0, "dgp_id", dgp)
            frame.insert(0, "seed_alias", seed_alias)
            frames.append(frame)
    features = pd.concat(frames, ignore_index=True)
    if len(features) != len(base) or not features.loc[
        :, ["seed_alias", "dgp_id", "date", "symbol"]
    ].equals(base.loc[:, ["seed_alias", "dgp_id", "date", "symbol"]]):
        raise RuntimeError("spent public feature identity differs")
    return features


def _feature_vector(frame: pd.DataFrame, column: str, fill: float) -> np.ndarray:
    return pd.to_numeric(frame[column], errors="coerce").fillna(fill).to_numpy(dtype=np.float64)


def _build_variants(base: pd.DataFrame, features: pd.DataFrame) -> dict[str, np.ndarray]:
    champion = pd.to_numeric(base["incumbent__v04_expected_pe"]).to_numpy(dtype=np.float64)
    lgbm = pd.to_numeric(base["challenger__lgbm_full_state"]).to_numpy(dtype=np.float64)
    histgb = pd.to_numeric(base["challenger__histgb_full_state"]).to_numpy(dtype=np.float64)
    base_conf = np.clip(pd.to_numeric(base["alpha__bce_d"]).to_numpy(dtype=np.float64), 0.0, 1.0)
    raw = pd.to_numeric(base["raw_log_consensus_correction"]).to_numpy(dtype=np.float64)
    log_champion = np.log(champion)
    reconstructed = np.exp(log_champion + base_conf * raw)
    if not np.allclose(
        reconstructed,
        pd.to_numeric(base["candidate__bce_d"]).to_numpy(dtype=np.float64),
        rtol=1e-13,
        atol=1e-13,
    ):
        raise RuntimeError("frozen C2 reconstruction differs")
    disagreement = np.abs(np.log(lgbm) - np.log(histgb)) / 2.0
    eps_conf = np.clip(_feature_vector(features, "eps_confidence", 0.0), 0.0, 1.0)
    staleness = np.maximum(_feature_vector(features, "eps_staleness_days", 365.0), 0.0)
    entropy = np.maximum(_feature_vector(features, "regime_entropy", 1.0), 0.0)
    regime_conf = np.clip(_feature_vector(features, "regime_confidence", 0.0), 0.0, 1.0)
    valuation_z = np.abs(_feature_vector(features, "regime_conditional_pe_log_z", 3.0))
    vol20 = np.maximum(_feature_vector(features, "benchmark_realized_vol_20", 0.05), 0.0)
    state_rel = np.exp(-valuation_z / 3.0) * np.sqrt(regime_conf) * np.exp(-entropy / 4.0)
    data_rel = np.sqrt(eps_conf) * np.exp(-staleness / 252.0) / (1.0 + vol20 / 0.03)

    applied = {
        "c2_r2_a_disagreement_shrink": base_conf / (1.0 + disagreement / math.log(1.05)) * raw,
        "c2_r2_b_robust_cap_040": np.clip(base_conf * raw, -math.log(1.04), math.log(1.04)),
        "c2_r2_c_ood_state_shrink": base_conf * state_rel * raw,
        "c2_r2_d_staleness_vol_shrink": base_conf * data_rel * raw,
        "c2_r2_e_tail_reliability": np.clip(
            base_conf * np.sqrt(state_rel * data_rel) * raw,
            -math.log(1.035),
            math.log(1.035),
        ),
    }
    if set(applied) != set(VARIANTS):
        raise RuntimeError("C2-R2 variant universe differs")
    result = {name: log_champion + correction for name, correction in applied.items()}
    if any(not np.isfinite(values).all() for values in result.values()):
        raise RuntimeError("C2-R2 produced nonfinite prediction")
    return result


def _load_truth(base: pd.DataFrame) -> np.ndarray:
    values = []
    identities = []
    for seed_alias, seed in zip(SEED_ALIASES, SEED_VALUES, strict=True):
        for dgp in DGP_IDS:
            path = TRUTH_ROOT / f"seed_{seed}" / f"dgp_{dgp}" / "truth.csv"
            frame = pd.read_csv(path, float_precision="round_trip").iloc[504:1800]
            values.extend(pd.to_numeric(frame["true_log_fair_pe"]).tolist())
            identities.extend(
                zip(
                    [seed_alias] * len(frame),
                    [dgp] * len(frame),
                    frame["date"].astype(str),
                    strict=True,
                )
            )
    observed = list(zip(base["seed_alias"], base["dgp_id"], base["date"].astype(str), strict=True))
    if identities != observed:
        raise RuntimeError("spent truth identity differs")
    target = np.asarray(values, dtype=np.float64)
    if len(target) != 64_800 or not np.isfinite(target).all():
        raise RuntimeError("spent truth geometry differs")
    return target


def _score(
    base: pd.DataFrame,
    variants: dict[str, np.ndarray],
    target: np.ndarray,
    c4_log: np.ndarray,
) -> tuple[pd.DataFrame, dict[str, Any]]:
    from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1.evaluator import (
        _summary,
        _systematic_tail,
    )

    champion_log = np.log(
        pd.to_numeric(base["incumbent__v04_expected_pe"]).to_numpy(dtype=np.float64)
    )
    champion_error = (champion_log - target).tolist()
    champion_summary = _summary(champion_error)
    dgp_groups = {dgp: np.flatnonzero(base["dgp_id"].to_numpy() == dgp).tolist() for dgp in DGP_IDS}
    seed_groups = {
        seed: np.flatnonzero(base["seed_alias"].to_numpy() == seed).tolist()
        for seed in SEED_ALIASES
    }
    cell_groups = {
        (seed, dgp): np.flatnonzero(
            (base["seed_alias"].to_numpy() == seed) & (base["dgp_id"].to_numpy() == dgp)
        ).tolist()
        for seed in SEED_ALIASES
        for dgp in DGP_IDS
    }
    rows = []
    details: dict[str, Any] = {}
    for name, prediction in variants.items():
        error = (prediction - target).tolist()
        summary = _summary(error)
        mae_gain = (champion_summary["mae"] - summary["mae"]) / champion_summary["mae"]
        rmse_gain = (champion_summary["rmse"] - summary["rmse"]) / champion_summary["rmse"]
        seed_gains = {}
        cell_gains = {}
        for seed, indexes in seed_groups.items():
            candidate = _summary(error, indexes)
            reference = _summary(champion_error, indexes)
            seed_gains[seed] = (reference["mae"] - candidate["mae"]) / reference["mae"]
        for cell, indexes in cell_groups.items():
            candidate = _summary(error, indexes)
            reference = _summary(champion_error, indexes)
            cell_gains["|".join(cell)] = (reference["mae"] - candidate["mae"]) / reference["mae"]
        dgp_gains = {
            dgp: math.fsum(cell_gains[f"{seed}|{dgp}"] for seed in SEED_ALIASES) / len(SEED_ALIASES)
            for dgp in DGP_IDS
        }
        tail = _systematic_tail(name, error, champion_error, dgp_groups, summary, champion_summary)
        corr_c4 = float(np.corrcoef(error, c4_log - target)[0, 1])
        passes_target = (
            mae_gain >= 0.04
            and max(0.0, -min(dgp_gains.values())) <= 0.01
            and max(0.0, -min(cell_gains.values())) <= 0.03
            and int(tail["systematic_dgp_joint_tail_failure_count"]) == 0
        )
        row = {
            "variant": name,
            "research_mae_gain": mae_gain,
            "research_rmse_gain": rmse_gain,
            "seed_wins": sum(value > 0.0 for value in seed_gains.values()),
            "dgp_wins": sum(value > 0.0 for value in dgp_gains.values()),
            "seed_dgp_wins": sum(value > 0.0 for value in cell_gains.values()),
            "worst_dgp_harm": max(0.0, -min(dgp_gains.values())),
            "worst_cell_harm": max(0.0, -min(cell_gains.values())),
            "joint_tail_failures": int(tail["systematic_dgp_joint_tail_failure_count"]),
            "signed_error_corr_with_c4": corr_c4,
            "research_target_pass": passes_target,
            "decision": "FREEZE_FOR_FUTURE_FRESH_QUALIFICATION"
            if passes_target
            else "REJECT_OR_REDESIGN",
        }
        rows.append(row)
        details[name] = {
            "summary": summary,
            "seed_gains": seed_gains,
            "dgp_gains": dgp_gains,
            "cell_gains": cell_gains,
            "tail": tail,
            "formula": VARIANTS[name],
        }
    table = pd.DataFrame(rows).sort_values(
        ["research_target_pass", "joint_tail_failures", "worst_dgp_harm", "research_mae_gain"],
        ascending=[False, True, True, False],
        kind="mergesort",
    )
    return table, details


def run(output_root: Path) -> dict[str, Any]:
    root = Path(output_root)
    if root.exists():
        raise RuntimeError("C2-R2 output root already exists")
    root.mkdir(parents=True)
    input_hashes = {
        "spent_bce_predictions": _sha(PREDICTIONS),
        "spent_truth_receipt": _sha(TRUTH_ROOT.parent / "VAULT_RECEIPT.json"),
        "spent_c4_predictions": _sha(C4_PREDICTIONS),
    }
    design = {
        "schema_version": "expected_pe.c2_r2.spent_research.v1.design",
        "status": "FROZEN_BEFORE_SPENT_TRUTH_SCORE",
        "evidence_class": "RESEARCH_ONLY_SPENT_PUBLIC_SYNTHETIC",
        "variants": VARIANTS,
        "variant_count": len(VARIANTS),
        "dgp_labels_used_as_features": False,
        "qualification_or_r3_heldout_used_for_selection": False,
        "pit_observable_features_only": list(FEATURE_COLUMNS),
        "target": "retain roughly 4-5% MAE gain while eliminating joint-tail failures",
        "input_hashes": input_hashes,
        "promotion_authority": False,
    }
    _write_new(root / "DESIGN_LOCK.json", _json_bytes(design))

    base = pd.read_csv(PREDICTIONS, float_precision="round_trip")
    if (
        len(base) != 64_800
        or tuple(base.loc[:, list(IDENTITY_COLUMNS)].columns) != IDENTITY_COLUMNS
    ):
        raise RuntimeError("spent BCE prediction geometry differs")
    features = _load_public_features(base)
    variants = _build_variants(base, features)
    prediction_frame = base.loc[:, list(IDENTITY_COLUMNS)].copy()
    for name, values in variants.items():
        prediction_frame[name] = values
    prediction_raw = prediction_frame.to_csv(index=False, lineterminator="\n").encode("utf-8")
    _write_new(root / "PREDICTIONS.csv", prediction_raw)
    freeze = {
        "status": "FROZEN_FIVE_C2_R2_VARIANTS_BEFORE_SPENT_TRUTH_SCORE",
        "prediction_rows": len(prediction_frame),
        "prediction_raw_sha256": hashlib.sha256(prediction_raw).hexdigest(),
        "input_hashes": input_hashes,
        "truth_open_count_before_freeze": 0,
        "formal_authority": False,
    }
    _write_new(root / "PREDICTION_FREEZE.json", _json_bytes(freeze))

    target = _load_truth(base)
    c4 = pd.read_csv(C4_PREDICTIONS, float_precision="round_trip")
    if len(c4) != len(base) or not c4.loc[:, ["seed_alias", "dgp_id", "date"]].equals(
        base.loc[:, ["seed_alias", "dgp_id", "date"]]
    ):
        raise RuntimeError("spent C4 identity differs")
    c4_log = pd.to_numeric(c4["expected_log_pe"]).to_numpy(dtype=np.float64)
    table, details = _score(base, variants, target, c4_log)
    table_raw = table.to_csv(index=False, lineterminator="\n").encode("utf-8")
    _write_new(root / "VARIANT_SCORECARD.csv", table_raw)
    _write_new(root / "DETAILS.json", _json_bytes(details))
    passed = table.loc[table["research_target_pass"], "variant"].tolist()
    result = {
        "schema_version": "expected_pe.c2_r2.spent_research.v1.result",
        "status": "PASS_RESEARCH_VARIANT_FOUND" if passed else "NO_VARIANT_MET_RESEARCH_TARGET",
        "evidence_class": "RESEARCH_ONLY_SPENT_PUBLIC_SYNTHETIC",
        "passed_variants_in_rank_order": passed,
        "recommended_variant": passed[0] if passed else None,
        "formal_qualification_required": bool(passed),
        "qualification_or_r3_evidence_reused": False,
        "promotion_authority": False,
        "scorecard_raw_sha256": hashlib.sha256(table_raw).hexdigest(),
    }
    _write_new(root / "RESULT.json", _json_bytes(result))
    report_lines = [
        "# C2-R2 Spent Research Result",
        "",
        "This is research-only evidence from already spent/public synthetic surfaces.",
        "Qualification and R3 heldout results were not used for selection.",
        "",
        table.to_csv(index=False, lineterminator="\n").strip(),
        "",
        f"Recommended variant: `{result['recommended_variant']}`",
        "" if passed else "No variant met the predeclared 4%/tail/harm target.",
    ]
    _write_new(root / "REPORT.md", "\n".join(report_lines).encode("utf-8"))
    leaves = (
        "DESIGN_LOCK.json",
        "DETAILS.json",
        "PREDICTIONS.csv",
        "PREDICTION_FREEZE.json",
        "REPORT.md",
        "RESULT.json",
        "VARIANT_SCORECARD.csv",
    )
    _write_new(
        root / "CHECKSUMS.sha256",
        "".join(f"{_sha(root / leaf)}  {leaf}\n" for leaf in leaves).encode("ascii"),
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output_root), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
