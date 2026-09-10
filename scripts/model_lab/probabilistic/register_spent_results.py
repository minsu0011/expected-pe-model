from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append definition+RESEARCH_ONLY spent-screen result events exactly once"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output-manifest", type=Path, required=True)
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
        sha256_file,
        verify_payload_seal,
    )
    from pe_regime_v04.model_lab.probabilistic.spec import (
        CANDIDATE_IDS,
        MODEL_BY_ID,
    )
    from pe_regime_v04.model_lab.registry import (
        ModelRegistration,
        RegistryPaths,
        load_feature_registry,
        load_model_registry,
        load_model_registry_history,
        validate_registry_cross_references,
        write_model_registry,
    )

    report_path = args.report if args.report.is_absolute() else root / args.report
    output_manifest = (
        args.output_manifest if args.output_manifest.is_absolute() else root / args.output_manifest
    )
    report = json.loads(report_path.read_bytes())
    verify_payload_seal(report)
    if (
        report.get("status") != "COMPLETE_SPENT_SEED_CHEAP_SCREEN"
        or report.get("stage2_tuning_authorized") is not False
        or report.get("promotion_authorized") is not False
        or report.get("fresh_seed_reserved_or_opened") is not False
        or report.get("heldout_opened") is not False
        or set(report.get("candidates", {})) != set(CANDIDATE_IDS)
    ):
        raise RuntimeError("registry report exceeds the research-only result authority")
    registry_root = root / "research/model_zoo"
    model_paths = RegistryPaths(
        registry_root / "model_registry.csv", registry_root / "model_registry.json"
    )
    feature_paths = RegistryPaths(
        registry_root / "feature_registry.csv", registry_root / "feature_registry.json"
    )
    repositories = {
        "scikit-learn": "https://github.com/scikit-learn/scikit-learn",
        "ngboost": "https://github.com/stanfordmlgroup/ngboost",
    }
    papers = {
        "scikit-learn": "https://jmlr.org/papers/v12/pedregosa11a.html",
        "ngboost": "https://proceedings.mlr.press/v119/duan20a.html",
    }
    definitions = []
    results = []
    selected = set(report["selected"])
    for model_id in CANDIDATE_IDS:
        definition = MODEL_BY_ID[model_id]
        package_name = definition.package.split("==", 1)[0]
        hyperparameters = {
            "design_parameters": dict(definition.parameters),
            "design_sha256": PROBABILISTIC_DESIGN_SHA256,
            "target_transform": "natural_log_positive_finite_observed_pe",
            "prediction_transform": "exp_five_quantiles_p10_p25_p50_p75_p90",
            "crossing_policy": "stable_monotone_rearrangement",
            "outer_fold": "252_min_1008_max_21_test_21_step_terminal_partial",
            "formal_score_start_position": 504,
            "outer_workers": 32,
            "inner_threads": 1,
            "gpu": "OFF",
            "warning_policy": "any_warning_or_failure_stops_without_retry",
        }
        base = ModelRegistration(
            model_id=model_id,
            family=definition.family,
            variant=definition.variant,
            version="prob-v5-ae2442-v1",
            registry_revision=0,
            track="C",
            estimand="hybrid market-conditioned expected P/E distribution; not intrinsic fair value",
            external_reference=True,
            paper=papers[package_name],
            repository=repositories[package_name],
            package=definition.package,
            license=definition.license,
            target="log(observed_pe)",
            feature_set="probabilistic_track_c_locked_36",
            uses_same_row_price=True,
            uses_same_row_observed_pe=False,
            causal=True,
            pit_safe=True,
            train_window="rolling up to 1008 sessions; minimum 252 positive finite labels",
            refit_frequency="every 21 sessions with terminal partial test allowed",
            hyperparameters=hyperparameters,
            tuning_status="UNTESTED",
            locked_status="UNTESTED",
            heldout_status="NOT_OPENED",
            fair_log_mae=None,
            fair_log_rmse=None,
            worst_seed=None,
            compute_time=None,
            status="UNTESTED",
            notes="Definition event accompanying one fixed spent-seed cheap screen; no tuning or heldout authority.",
            entrypoint="pe_regime_v04.model_lab.probabilistic.adapters:create_adapter",
            feature_ids=tuple(definition.feature_columns),
            prediction_name="expected_pe",
            output_semantics="positive market-conditioned Expected-P/E five-quantile research distribution",
            deterministic=True,
            description=f"Frozen probabilistic V5 {definition.variant} research candidate",
            parameters_sha256=hashlib.sha256(_canonical(hyperparameters)).hexdigest(),
        )
        metrics = report["candidates"][model_id]
        result = replace(
            base,
            registry_revision=1,
            fair_log_mae=float(metrics["fair_log_mae"]),
            fair_log_rmse=float(metrics["fair_log_rmse"]),
            worst_seed=int(metrics["worst_mae_seed"]),
            compute_time=float(metrics["runtime"]["runtime_minutes"]) * 60.0,
            status="RESEARCH_ONLY",
            notes=(
                "Exact five already-spent seed cheap-screen result; "
                f"formal gate={'selected_research_proposal' if model_id in selected else 'not_selected'}; "
                "tuning/lock/promotion/fresh/heldout remain unauthorized; "
                f"report_sha256={sha256_file(report_path)}"
            ),
        )
        definitions.append(base)
        results.append(result)

    existing = list(load_model_registry_history(model_paths))
    histories = {}
    for item in existing:
        histories.setdefault(item.definition_id, []).append(item)
    additions = []
    skipped = []
    for definition, result in zip(definitions, results, strict=True):
        history = histories.get(definition.definition_id, [])
        expected = [definition, result]
        if history and history != expected[: len(history)]:
            raise RuntimeError(
                f"probabilistic registry history conflicts: {definition.definition_id}"
            )
        if len(history) > 2:
            raise RuntimeError("probabilistic registry history has unauthorized extra revisions")
        additions.extend(expected[len(history) :])
        skipped.extend(item.registration_id for item in expected[: len(history)])
    planned = [*existing, *additions]
    before = {
        "csv_sha256": sha256_file(model_paths.csv_path),
        "json_sha256": sha256_file(model_paths.json_path),
        "records": len(existing),
    }
    with tempfile.TemporaryDirectory(prefix="probabilistic-registry-preflight-") as temporary:
        temporary_root = Path(temporary)
        temporary_paths = RegistryPaths(
            temporary_root / "model_registry.csv", temporary_root / "model_registry.json"
        )
        shutil.copy2(model_paths.csv_path, temporary_paths.csv_path)
        shutil.copy2(model_paths.json_path, temporary_paths.json_path)
        write_model_registry(temporary_paths, planned)
        validate_registry_cross_references(
            load_model_registry(temporary_paths),
            load_feature_registry(feature_paths),
            formal_run=True,
        )
    if (
        sha256_file(model_paths.csv_path) != before["csv_sha256"]
        or sha256_file(model_paths.json_path) != before["json_sha256"]
    ):
        raise RuntimeError("model registry changed during probabilistic preflight")
    snapshot = write_model_registry(model_paths, planned)
    validate_registry_cross_references(
        load_model_registry(model_paths), load_feature_registry(feature_paths), formal_run=True
    )
    manifest = {
        "schema_version": "expected_pe_model_zoo.probabilistic_registry_results.v1",
        "status": "PASS_RESEARCH_ONLY_RESULT_REVISIONS",
        "report_path": report_path.relative_to(root).as_posix(),
        "report_sha256": sha256_file(report_path),
        "before": before,
        "after": {
            "csv_sha256": snapshot.csv_sha256,
            "json_sha256": snapshot.json_sha256,
            "logical_sha256": snapshot.logical_sha256,
            "records": snapshot.record_count,
        },
        "appended": [item.registration_id for item in additions],
        "skipped_exact": skipped,
        "result_statuses": {item.model_id: item.status for item in results},
        "tuning_statuses": {item.model_id: item.tuning_status for item in results},
        "locked_statuses": {item.model_id: item.locked_status for item in results},
        "heldout_statuses": {item.model_id: item.heldout_status for item in results},
        "promotion_authorized": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
    }
    immutable_write_json(output_manifest, manifest)
    print(output_manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
