from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile


V2_AUTHORIZATION_RAW_SHA256 = (
    "1118e6eb77ee2b1817a3b7fd564a77cef93b249cb0eaa3c4a0f7d5e36928febf"
)
TERMINAL_FAILURE_RECEIPT = {
    "path": (
        "outputs/model_zoo_probabilistic_wave_formal_execution_fail_closed_20260819/"
        "FAILURE.json"
    ),
    "raw_sha256": "f99260f3bc36fd3a440d926305401c4b55fe472dc9d2c27e80252b52807dcc27",
    "logical_sha256": "f7303b23a420b619946ab79c7d1d354382248cf43d81cb12c0d2fcc56c63b396",
}
TERMINAL_FAILURE_AUDIT = {
    "path": (
        "outputs/model_zoo_probabilistic_wave_spent_terminal_failure_"
        "independent_audit_20260819/AUDIT.json"
    ),
    "raw_sha256": "cf08ec76b6928ac58d3e47d259a316eaf79a59ce2259bccb5be2f7f4c5379287",
    "logical_sha256": "2166e9666b9f309bdd0354fe83808c1b2aa82e391e762caeaa6ff526bb88ac8f",
}
SURVIVOR_CUSTODY = {
    "qlinear_l1_with_regime_v1": {
        "surface_raw_sha256": (
            "e7fa93c5fbf3833e019e1bec92364ae415d53fee076ab7601594ef95722940e4"
        ),
        "prediction_raw_sha256": (
            "7d6c7934330e7547118d4d64676389f6102025edb474c559fae5f7c0f05e2fc8"
        ),
        "prediction_receipt_raw_sha256": (
            "7950de7186f07144c2455d32e7b49562a42ff5b732283c8a94cb2d68bccaca81"
        ),
        "runtime_receipt_raw_sha256": (
            "5a8d709c8e5998eac07e37dd49497de468885539e71498c3fc57339916949543"
        ),
    },
    "qhistgb_with_regime_v1": {
        "surface_raw_sha256": (
            "ed8769377917c05c135e3678f05c5b43d6eecd72d2cc9670b571a909ac9cb479"
        ),
        "prediction_raw_sha256": (
            "786d648ee4145392ab58373947b580c4cc6a83f254ba42d810d5633a7398b10e"
        ),
        "prediction_receipt_raw_sha256": (
            "60b27bb0c15f30bd0f8da2f15376dc154ecb5d316d4c718e1268c69cc40ebbee"
        ),
        "runtime_receipt_raw_sha256": (
            "97008171c3f4af9c67f06a89b1c458782cff6b6949ae3d8b866a60ee1b64550f"
        ),
    },
}


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


def _exact_json(root: Path, record: dict[str, str], *, context: str) -> dict[str, object]:
    path = root / record["path"]
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != record["raw_sha256"]:
        raise RuntimeError(f"{context} raw bytes changed")
    payload = json.loads(raw)
    if payload.get("manifest_sha256") != record["logical_sha256"]:
        raise RuntimeError(f"{context} logical seal changed")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append exact unscored-survivor and terminal-BROKEN registry events"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "outputs/model_zoo_probabilistic_wave_terminal_registry_append_20260819/"
            "REGISTRY_APPEND.json"
        ),
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    sys.path.insert(0, str(root / "src"))

    from pe_regime_v04.model_lab.probabilistic.artifacts import (
        immutable_write_bytes,
        immutable_write_json,
    )
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        PROBABILISTIC_DESIGN_SHA256,
        sha256_file,
    )
    from pe_regime_v04.model_lab.probabilistic.spec import CANDIDATE_IDS, MODEL_BY_ID
    from pe_regime_v04.model_lab.registry import (
        ModelRegistration,
        RegistryPaths,
        load_feature_registry,
        load_model_registry,
        load_model_registry_history,
        validate_registry_cross_references,
        write_model_registry,
    )

    failure = _exact_json(root, TERMINAL_FAILURE_RECEIPT, context="terminal failure receipt")
    audit = _exact_json(root, TERMINAL_FAILURE_AUDIT, context="terminal failure audit")
    broken_id = "ngboost_normal_crps_with_regime_v1"
    if (
        failure.get("status") != "TERMINAL_FAIL_CLOSED"
        or failure.get("failure", {}).get("candidate_id") != broken_id
        or failure.get("decision", {}).get("retry_authorized") is not False
        or failure.get("decision", {}).get("fallback_authorized") is not False
        or audit.get("decision", {}).get("probabilistic_spent_screen")
        != "NO_GO_TERMINAL_INCOMPLETE"
        or audit.get("decision", {}).get("ngboost_candidate_status") != "BROKEN"
        or audit.get("decision", {}).get("completed_candidate_custody_accepted") is not True
    ):
        raise RuntimeError("terminal registry append authority differs")

    registry_root = root / "research/model_zoo"
    model_paths = RegistryPaths(
        registry_root / "model_registry.csv", registry_root / "model_registry.json"
    )
    feature_paths = RegistryPaths(
        registry_root / "feature_registry.csv", registry_root / "feature_registry.json"
    )
    before_history = list(load_model_registry_history(model_paths))
    if any(record.model_id in CANDIDATE_IDS for record in before_history):
        raise RuntimeError("probabilistic registry events already exist or conflict")
    before = {
        "csv_sha256": sha256_file(model_paths.csv_path),
        "json_sha256": sha256_file(model_paths.json_path),
        "records": len(before_history),
    }
    if before != {
        "csv_sha256": "0cf9b9e568265419f372593d72900df3a3dbbea88087f243d66d62f4d0fca3f1",
        "json_sha256": "2f7628a254fe711d3b004ee85e425cd02fd2bc1604405f83b5f600303b9e2c25",
        "records": len(before_history),
    }:
        raise RuntimeError("model registry predecessor raw roots differ")
    output = args.output if args.output.is_absolute() else root / args.output
    before_directory = output.parent
    before_csv_path = before_directory / (
        f"model_registry.before.{before['csv_sha256']}.csv"
    )
    before_json_path = before_directory / (
        f"model_registry.before.{before['json_sha256']}.json"
    )
    immutable_write_bytes(before_csv_path, model_paths.csv_path.read_bytes())
    immutable_write_bytes(before_json_path, model_paths.json_path.read_bytes())

    repositories = {
        "scikit-learn": "https://github.com/scikit-learn/scikit-learn",
        "ngboost": "https://github.com/stanfordmlgroup/ngboost",
    }
    papers = {
        "scikit-learn": "https://jmlr.org/papers/v12/pedregosa11a.html",
        "ngboost": "https://proceedings.mlr.press/v119/duan20a.html",
    }
    definitions: list[ModelRegistration] = []
    terminal_states: list[ModelRegistration] = []
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
        # Registry JSON is the canonical representation; normalize tuples such
        # as the locked quantile vector before preflight/equality checks.
        hyperparameters = json.loads(json.dumps(hyperparameters, allow_nan=False))
        base = ModelRegistration(
            model_id=model_id,
            family=definition.family,
            variant=definition.variant,
            version="prob-v5-ae2442-v1",
            registry_revision=0,
            track="C",
            estimand=(
                "hybrid market-conditioned expected P/E distribution; not intrinsic fair value"
            ),
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
            notes=(
                "Immutable definition only; no score, tuning, lock, promotion, fresh seed, "
                "or heldout authority."
            ),
            entrypoint="pe_regime_v04.model_lab.probabilistic.adapters:create_adapter",
            feature_ids=tuple(definition.feature_columns),
            prediction_name="expected_pe",
            output_semantics=(
                "positive market-conditioned Expected-P/E five-quantile research distribution"
            ),
            deterministic=True,
            description=f"Frozen probabilistic V5 {definition.variant} research candidate",
            parameters_sha256=hashlib.sha256(_canonical(hyperparameters)).hexdigest(),
        )
        if model_id in SURVIVOR_CUSTODY:
            custody = SURVIVOR_CUSTODY[model_id]
            status = "RESEARCH_ONLY"
            disposition = "UNSCORED_PREDICTION_CUSTODY_ONLY"
            evidence = ";".join(f"{key}={value}" for key, value in custody.items())
        else:
            status = "BROKEN"
            disposition = "BROKEN_TERMINAL_NO_RETRY_NO_FALLBACK"
            evidence = (
                f"failure_raw_sha256={TERMINAL_FAILURE_RECEIPT['raw_sha256']};"
                f"failure_logical_sha256={TERMINAL_FAILURE_RECEIPT['logical_sha256']};"
                f"terminal_audit_raw_sha256={TERMINAL_FAILURE_AUDIT['raw_sha256']};"
                f"terminal_audit_logical_sha256={TERMINAL_FAILURE_AUDIT['logical_sha256']}"
            )
        state = replace(
            base,
            registry_revision=1,
            status=status,
            notes=(
                f"result_status={disposition};metrics=null;tuning=UNTESTED;locked=UNTESTED;"
                f"heldout=NOT_OPENED;authorization_raw_sha256={V2_AUTHORIZATION_RAW_SHA256};"
                f"{evidence}"
            ),
        )
        definitions.append(base)
        terminal_states.append(state)

    additions = [
        item
        for pair in zip(definitions, terminal_states, strict=True)
        for item in pair
    ]
    planned = [*before_history, *additions]
    with tempfile.TemporaryDirectory(prefix="probabilistic-terminal-registry-") as temporary:
        temporary_root = Path(temporary)
        temporary_paths = RegistryPaths(
            temporary_root / "model_registry.csv", temporary_root / "model_registry.json"
        )
        shutil.copy2(model_paths.csv_path, temporary_paths.csv_path)
        shutil.copy2(model_paths.json_path, temporary_paths.json_path)
        expected_snapshot = write_model_registry(temporary_paths, planned)
        temp_history = load_model_registry_history(temporary_paths)
        temp_latest = load_model_registry(temporary_paths)
        validate_registry_cross_references(
            temp_latest, load_feature_registry(feature_paths), formal_run=True
        )
        if list(temp_history[-len(additions) :]) != additions:
            raise RuntimeError(
                "temporary registry history append differs: "
                f"expected={[item.registration_id for item in additions]}, "
                f"actual={[item.registration_id for item in temp_history[-len(additions):]]}"
            )
        latest_by_id = {record.model_id: record for record in temp_latest}
        if any(latest_by_id[item.model_id] != item for item in terminal_states):
            raise RuntimeError("temporary registry latest projection differs")

    if (
        sha256_file(model_paths.csv_path) != before["csv_sha256"]
        or sha256_file(model_paths.json_path) != before["json_sha256"]
    ):
        raise RuntimeError("model registry changed during append preflight")
    actual_snapshot = write_model_registry(model_paths, planned)
    if actual_snapshot != replace(expected_snapshot, paths=model_paths):
        raise RuntimeError("registry commit differs from preflight snapshot")
    history = load_model_registry_history(model_paths)
    latest = load_model_registry(model_paths)
    validate_registry_cross_references(
        latest, load_feature_registry(feature_paths), formal_run=True
    )
    if list(history[-len(additions) :]) != additions:
        raise RuntimeError("committed registry history differs")
    latest_by_id = {record.model_id: record for record in latest}
    if any(latest_by_id[item.model_id] != item for item in terminal_states):
        raise RuntimeError("committed registry latest projection differs")

    manifest = {
        "schema_version": "expected_pe_model_zoo.probabilistic_terminal_registry_append.v1",
        "status": "PASS_APPEND_ONLY_TERMINAL_STATE",
        "before": before,
        "recoverable_before_snapshot": {
            "csv_path": before_csv_path.relative_to(root).as_posix(),
            "csv_sha256": before["csv_sha256"],
            "json_path": before_json_path.relative_to(root).as_posix(),
            "json_sha256": before["json_sha256"],
        },
        "after": {
            "csv_sha256": actual_snapshot.csv_sha256,
            "json_sha256": actual_snapshot.json_sha256,
            "logical_sha256": actual_snapshot.logical_sha256,
            "records": actual_snapshot.record_count,
        },
        "appended_registration_ids": [item.registration_id for item in additions],
        "latest": {
            item.model_id: {
                "registration_id": item.registration_id,
                "registry_revision": item.registry_revision,
                "status": item.status,
                "logical_result_status": (
                    "BROKEN_TERMINAL_NO_RETRY_NO_FALLBACK"
                    if item.model_id == broken_id
                    else "UNSCORED_PREDICTION_CUSTODY_ONLY"
                ),
                "tuning_status": item.tuning_status,
                "locked_status": item.locked_status,
                "heldout_status": item.heldout_status,
                "fair_log_mae": item.fair_log_mae,
                "fair_log_rmse": item.fair_log_rmse,
                "worst_seed": item.worst_seed,
                "compute_time": item.compute_time,
            }
            for item in terminal_states
        },
        "terminal_failure_receipt": TERMINAL_FAILURE_RECEIPT,
        "terminal_failure_audit": TERMINAL_FAILURE_AUDIT,
        "v2_authorization_raw_sha256": V2_AUTHORIZATION_RAW_SHA256,
        "csv_json_parity_verified": True,
        "history_prefix_preserved": True,
        "latest_projection_verified": True,
        "metrics_generated_or_read": False,
        "truth_opened": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
        "promotion_authorized": False,
    }
    immutable_write_json(output, manifest)
    print(
        json.dumps(
            {
                "manifest": output.relative_to(root).as_posix(),
                "manifest_raw_sha256": sha256_file(output),
                "after": manifest["after"],
                "appended_registration_ids": manifest["appended_registration_ids"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
