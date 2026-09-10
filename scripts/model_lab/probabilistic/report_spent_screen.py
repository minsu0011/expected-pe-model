from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Report the immutable formal spent-screen receipts"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--bundle-spec", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import (
        checksum_manifest,
        immutable_write_json,
        immutable_write_text,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        sha256_file,
        verify_payload_seal,
    )
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS
    from pe_regime_v04.model_lab.probabilistic.spent import SPENT_SEEDS

    result_path = args.result if args.result.is_absolute() else root / args.result
    bundle_path = args.bundle_spec if args.bundle_spec.is_absolute() else root / args.bundle_spec
    output = args.output_directory
    if not output.is_absolute():
        output = root / output
    result = json.loads(result_path.read_bytes())
    bundle = json.loads(bundle_path.read_bytes())
    verify_payload_seal(result)
    verify_payload_seal(bundle)
    if (
        result.get("status") != "PASS_PHYSICAL_EVALUATOR_SINGLE_USE"
        or result.get("formal_execution_authorized") is not True
        or result.get("metric_receipts_only") is not True
        or result.get("truth_bytes_returned") is not False
        or result.get("prediction_bytes_returned") is not False
    ):
        raise RuntimeError("formal physical evaluator result boundary differs")
    selection = result.get("formal_selection")
    verify_payload_seal(selection)
    if set(selection.get("decisions", {})) != set(CANDIDATE_IDS):
        raise RuntimeError("formal selection does not contain exactly three candidates")
    candidates = result["candidate_metric_receipts"]
    references = result["reference_metric_receipts"]
    comparators = result["point_comparator_metric_receipts"]
    if set(candidates) != set(CANDIDATE_IDS):
        raise RuntimeError("candidate metric receipt set differs")
    runtime = {}
    for model_id in CANDIDATE_IDS:
        runtime_path = root / bundle["candidates"][model_id]["runtime_receipt_path"]
        payload = json.loads(runtime_path.read_bytes())
        verify_payload_seal(payload)
        if sha256_file(runtime_path) != result["runtime_receipt_sha256_by_candidate"][model_id]:
            raise RuntimeError("runtime receipt differs from physical result")
        runtime[model_id] = payload["metrics"]
    summaries = {}
    for model_id in CANDIDATE_IDS:
        receipt = candidates[model_id]
        verify_payload_seal(receipt)
        metrics = receipt["metrics"]
        per_seed = metrics["per_seed"]
        if tuple(sorted(int(value) for value in per_seed)) != tuple(sorted(SPENT_SEEDS)):
            raise RuntimeError("candidate per-seed metric support differs")
        worst_wis = max(per_seed, key=lambda value: (per_seed[value]["wis"], int(value)))
        worst_mae = max(per_seed, key=lambda value: (per_seed[value]["fair_log_mae"], int(value)))
        summaries[model_id] = {
            "fair_log_mae": metrics["fair_median"]["fair_log_mae"],
            "fair_log_rmse": metrics["fair_median"]["fair_log_rmse"],
            "mean_pinball_loss": metrics["mean_pinball_loss"],
            "wis": metrics["wis"],
            "mean_abs_calibration_error": metrics["mean_absolute_quantile_calibration_error"],
            "max_abs_calibration_error": metrics["maximum_absolute_quantile_calibration_error"],
            "p10_p90_coverage": metrics["p10_p90_coverage"],
            "p25_p75_coverage": metrics["p25_p75_coverage"],
            "per_seed": per_seed,
            "worst_wis_seed": int(worst_wis),
            "worst_wis": per_seed[worst_wis]["wis"],
            "worst_mae_seed": int(worst_mae),
            "worst_mae": per_seed[worst_mae]["fair_log_mae"],
            "runtime": runtime[model_id],
            "ngboost_density": metrics.get("ngboost_density"),
            "quantile_pit_status": metrics.get("quantile_pit_status"),
            "screen_decision": selection["decisions"][model_id],
        }
    report = {
        "schema_version": "expected_pe_model_zoo.probabilistic_spent_report.v1",
        "status": "COMPLETE_SPENT_SEED_CHEAP_SCREEN",
        "authorization_raw_sha256": result["authorization_raw_sha256"],
        "source_closure_sha256": result["source_closure_sha256"],
        "physical_result": {
            "path": result_path.relative_to(root).as_posix(),
            "sha256": sha256_file(result_path),
            "parent_pid": result["parent_pid"],
            "evaluator_pid": result["evaluator_pid"],
        },
        "spent_seeds": list(SPENT_SEEDS),
        "candidates": summaries,
        "probabilistic_references": {key: value["metrics"] for key, value in references.items()},
        "point_comparators": {key: value["metrics"] for key, value in comparators.items()},
        "rank_order": selection["rank_order"],
        "eligible_ranked": selection["eligible_ranked"],
        "selected": selection["selected"],
        "maximum_candidates_advanced": 1,
        "decision": (
            "RESEARCH_ONLY_ADVANCE_PROPOSED"
            if selection["selected"]
            else "RESEARCH_ONLY_NO_ADVANCEMENT"
        ),
        "stage2_tuning_authorized": False,
        "promotion_authorized": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
        "registry_lifecycle_ceiling": "RESEARCH_ONLY",
    }
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "REPORT.json"
    immutable_write_json(json_path, report)
    rows = []
    for model_id in CANDIDATE_IDS:
        item = summaries[model_id]
        rows.append(
            "| {model} | {mae:.8f} | {rmse:.8f} | {pinball:.8f} | {wis:.8f} | "
            "{cal:.6f} | {cov80:.6f} | {cov50:.6f} | {minutes:.3f} | {decision} |".format(
                model=model_id,
                mae=item["fair_log_mae"],
                rmse=item["fair_log_rmse"],
                pinball=item["mean_pinball_loss"],
                wis=item["wis"],
                cal=item["mean_abs_calibration_error"],
                cov80=item["p10_p90_coverage"],
                cov50=item["p25_p75_coverage"],
                minutes=item["runtime"]["runtime_minutes"],
                decision=item["screen_decision"]["advancement_path"],
            )
        )
    markdown = "\n".join(
        [
            "# Probabilistic V5 spent-seed cheap screen",
            "",
            f"Decision: **{report['decision']}**. Selected: `{selection['selected']}`.",
            "",
            "All values below come from the single-use physical evaluator over the exact five already-spent seeds. No fresh seed or heldout was opened.",
            "",
            "| Candidate | P50 log MAE | P50 log RMSE | Pinball | WIS | Mean |cal| | P10–P90 cov. | P25–P75 cov. | Runtime min | Gate path |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
            *rows,
            "",
            "Ranking order: " + ", ".join(selection["rank_order"]) + ".",
            "",
            "Lifecycle ceiling is RESEARCH_ONLY. Tuning, lock, promotion, fresh-seed use, and heldout access remain unauthorized.",
            "",
        ]
    )
    markdown_path = output / "REPORT.md"
    immutable_write_text(markdown_path, markdown)
    checksums_path = output / "CHECKSUMS.sha256"
    immutable_write_text(
        checksums_path,
        checksum_manifest((json_path, markdown_path, result_path), root=root),
    )
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
