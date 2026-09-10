from __future__ import annotations

from dataclasses import dataclass, replace
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab.probabilistic.adapters import (
    adapter_binding_sha256_by_id,
    candidate_environment_sha256_by_id,
)
from pe_regime_v04.model_lab.probabilistic.authorization import (
    SCORE_FREE_SCOPE,
    build_execution_authorization_payload,
    load_execution_authorization,
)
from pe_regime_v04.model_lab.probabilistic.contracts import (
    NORMAL_QUANTILE_Z,
    ProbabilisticContractError,
    seal_payload,
    sha256_bytes,
)
from pe_regime_v04.model_lab.probabilistic.coverage import verify_prediction_coverage
from pe_regime_v04.model_lab.probabilistic.custody import (
    build_feature_provenance,
    load_verified_pit_features,
    load_verified_point_comparator,
    load_verified_point_comparator_with_receipt,
    load_verified_prediction_artifact,
    load_verified_reference_prediction_artifact,
    load_verified_training_labels,
    materialize_authorized_fold,
    seal_prediction_artifact,
    seal_point_comparator_custody_receipt,
    seal_reference_prediction_artifact,
    write_content_addressed_csv,
    write_content_addressed_json,
)
from pe_regime_v04.model_lab.probabilistic.environment import verify_dedicated_freeze
from pe_regime_v04.model_lab.probabilistic.formal_pins import (
    load_external_execution_request,
    verify_externally_pinned_pointer,
)
from pe_regime_v04.model_lab.probabilistic.evaluation import (
    VerifiedEvaluationReceipt,
    create_evaluation_session,
    load_detached_truth,
)
from pe_regime_v04.model_lab.probabilistic.governance import (
    run_score_free_governance_evidence,
    select_from_verified_receipts,
)
from pe_regime_v04.model_lab.probabilistic.nested import build_outer_folds
from pe_regime_v04.model_lab.probabilistic.references import (
    create_reference_execution_accumulator,
    load_verified_point_prediction_history,
    point_residual_quantiles_252,
    reference_binding_sha256_by_id,
    rolling_log_quantiles_252,
    load_verified_reference_execution_receipt,
    write_reference_execution_receipt,
)
from pe_regime_v04.model_lab.probabilistic.resources import (
    THREAD_ENVIRONMENT,
    create_candidate_resource_guard,
    verify_worker_count_parity,
)
from pe_regime_v04.model_lab.probabilistic.runner import fit_predict_fold
from pe_regime_v04.model_lab.probabilistic.spec import FEATURE_COLUMNS
from pe_regime_v04.model_lab.probabilistic.source_closure import (
    build_source_closure_payload,
    execution_closure_paths,
)


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _isolate_probabilistic_resource_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Give every intervention test the exact design environment, then restore it."""

    for key, value in THREAD_ENVIRONMENT.items():
        monkeypatch.setenv(key, value)


def test_probabilistic_resource_environment_is_isolated_per_test() -> None:
    assert {key: os.environ.get(key) for key in THREAD_ENVIRONMENT} == THREAD_ENVIRONMENT


@dataclass(frozen=True)
class SyntheticCustody:
    authorization: object
    identity: pd.DataFrame
    features: object
    labels: object
    point_history: object
    truth_path: Path
    feature_path: Path
    source_path: Path
    fold: object
    directory: Path


def _formal_identity(folds: tuple[object, ...], dates: pd.DatetimeIndex) -> pd.DataFrame:
    records: list[dict[str, object]] = []
    for fold in folds[12:]:
        for position in fold.test_positions:
            records.append(
                {
                    "seed": 101,
                    "entity_id": "SYNTH",
                    "date": dates[position],
                    "ordered_position": position,
                    "fold_id": fold.fold_id,
                }
            )
    return pd.DataFrame(records)


@pytest.fixture(scope="module")
def custody(tmp_path_factory: pytest.TempPathFactory) -> SyntheticCustody:
    directory = tmp_path_factory.mktemp("probabilistic_custody")
    rows = 1800
    dates = pd.date_range("2018-01-01", periods=rows, freq="D")
    rng = np.random.default_rng(20260819)
    feature_values = rng.normal(size=(rows, len(FEATURE_COLUMNS)))
    feature_frame = pd.DataFrame(feature_values, columns=FEATURE_COLUMNS)
    feature_frame.insert(0, "ordered_position", np.arange(rows))
    feature_frame.insert(0, "date", dates)
    feature_frame.insert(0, "entity_id", "SYNTH")
    feature_frame.insert(0, "seed", 101)
    label_frame = feature_frame.loc[:, ["seed", "entity_id", "date", "ordered_position"]].copy()
    label_frame["label_available_at"] = dates
    label_frame["observed_pe"] = np.exp(
        2.7 + 0.05 * feature_values[:, 0] + rng.normal(0.0, 0.12, rows)
    )
    folds = build_outer_folds(label_frame, label_available_at_column="label_available_at")
    identity = _formal_identity(folds, dates)
    truth = identity.copy()
    truth["true_fair_pe"] = np.exp(2.72 + np.arange(len(identity)) / 100000.0)
    point = label_frame.loc[:, ["seed", "entity_id", "date", "ordered_position"]].copy()
    point["point_expected_pe"] = np.exp(2.69 + np.arange(rows) / 100000.0)

    feature_path = write_content_addressed_csv(directory, "pit_features", feature_frame)
    feature_hash = sha256_bytes(feature_path.read_bytes())
    provenance = build_feature_provenance(feature_artifact_raw_sha256=feature_hash)
    provenance_path = write_content_addressed_json(directory, "pit_feature_provenance", provenance)
    label_path = write_content_addressed_csv(directory, "training_labels", label_frame)
    identity_path = write_content_addressed_csv(directory, "formal_identity", identity)
    truth_path = write_content_addressed_csv(directory, "detached_truth", truth)
    point_path = write_content_addressed_csv(directory, "point_history", point)
    source_path = write_content_addressed_json(
        directory, "source_closure", build_source_closure_payload(ROOT)
    )
    bindings = {
        "adapter_binding_sha256_by_id": adapter_binding_sha256_by_id(),
        "candidate_source_snapshot_sha256": sha256_bytes(source_path.read_bytes()),
        "comparator_prediction_sha256_by_id": {
            "point_history": sha256_bytes(point_path.read_bytes()),
            "v04_expected_pe": sha256_bytes(b"synthetic-v04-comparator"),
            "ml_expected_pe": sha256_bytes(b"synthetic-ml-comparator"),
        },
        "detached_truth_manifest_sha256": sha256_bytes(truth_path.read_bytes()),
        "environment_manifest_sha256_by_id": candidate_environment_sha256_by_id(),
        "feature_artifact_raw_sha256": feature_hash,
        "feature_provenance_sha256": sha256_bytes(provenance_path.read_bytes()),
        "probabilistic_reference_sha256_by_id": reference_binding_sha256_by_id(),
        "spent_role_authorization_sha256": sha256_bytes(b"synthetic-spent-role"),
        "training_label_artifact_raw_sha256": sha256_bytes(label_path.read_bytes()),
    }
    payload = build_execution_authorization_payload(
        identity_raw=identity_path.read_bytes(),
        bindings=bindings,
        authorization_scope=SCORE_FREE_SCOPE,
        formal_execution_authorized=False,
        synthetic_evaluation_authorized=True,
    )
    precommit_path = write_content_addressed_json(directory, "execution_authorization", payload)
    authorization = load_execution_authorization(
        precommit_path,
        identity_path,
        source_path,
        expected_precommit_sha256=sha256_bytes(precommit_path.read_bytes()),
    )
    features = load_verified_pit_features(
        feature_path, provenance_path, authorization=authorization
    )
    labels = load_verified_training_labels(label_path, authorization=authorization)
    point_history = load_verified_point_prediction_history(
        point_path, authorization=authorization, comparator_id="point_history"
    )
    return SyntheticCustody(
        authorization=authorization,
        identity=identity,
        features=features,
        labels=labels,
        point_history=point_history,
        truth_path=truth_path,
        feature_path=feature_path,
        source_path=source_path,
        fold=folds[12],
        directory=directory,
    )


def _predictions(
    identity: pd.DataFrame,
    *,
    density: bool = False,
    model_id: str | None = None,
) -> pd.DataFrame:
    rows = len(identity)
    loc = 2.7 + np.arange(rows, dtype=np.float64) / 100000.0
    if density:
        scale = np.full(rows, 0.2)
        logs = loc[:, None] + scale[:, None] * NORMAL_QUANTILE_Z[None, :]
        model_id = model_id or "ngboost_normal_crps_with_regime_v1"
    else:
        logs = loc[:, None] + np.asarray([-0.3, -0.15, 0.0, 0.15, 0.3])[None, :]
        model_id = model_id or "qlinear_l1_with_regime_v1"
    pe = np.exp(logs)
    output = identity.copy()
    output["model_id"] = model_id
    for index, label in enumerate(("p10", "p25", "p50", "p75", "p90")):
        output[f"predicted_pe_{label}"] = pe[:, index]
    output["expected_pe"] = pe[:, 2]
    output["uncertainty_log_iqr"] = np.log(pe[:, 3]) - np.log(pe[:, 1])
    output["uncertainty_log_idr"] = np.log(pe[:, 4]) - np.log(pe[:, 0])
    output["uncertainty_robust_sigma"] = output["uncertainty_log_iqr"] / 1.3489795003921634
    output["uncertainty_p90_p10_ratio"] = pe[:, 4] / pe[:, 0]
    if density:
        output["density_loc"] = loc
        output["density_scale"] = scale
    return output


def _seal_load(custody: SyntheticCustody, frame: pd.DataFrame):
    prediction_path, receipt_path = seal_prediction_artifact(
        frame, custody.directory, authorization=custody.authorization
    )
    return load_verified_prediction_artifact(
        prediction_path, receipt_path, authorization=custody.authorization
    )


def _variant_artifacts(
    custody: SyntheticCustody,
    directory: Path,
    *,
    feature_position: int | None = None,
    label_positions: tuple[int, ...] = (),
):
    feature_frame = object.__getattribute__(custody.features, "_frame").copy(deep=True)
    label_frame = object.__getattribute__(custody.labels, "_frame").copy(deep=True)
    point_frame = object.__getattribute__(custody.point_history, "_frame").copy(deep=True)
    if feature_position is not None:
        feature_frame.loc[feature_position, FEATURE_COLUMNS[0]] += 1000.0
    if label_positions:
        label_frame.loc[list(label_positions), "observed_pe"] *= 1000.0
    feature_path = write_content_addressed_csv(directory, "variant_features", feature_frame)
    feature_hash = sha256_bytes(feature_path.read_bytes())
    provenance_path = write_content_addressed_json(
        directory,
        "variant_provenance",
        build_feature_provenance(feature_artifact_raw_sha256=feature_hash),
    )
    label_path = write_content_addressed_csv(directory, "variant_labels", label_frame)
    point_path = write_content_addressed_csv(directory, "variant_points", point_frame)
    identity_path = write_content_addressed_csv(directory, "variant_identity", custody.identity)
    bindings = {
        "adapter_binding_sha256_by_id": adapter_binding_sha256_by_id(),
        "candidate_source_snapshot_sha256": sha256_bytes(custody.source_path.read_bytes()),
        "comparator_prediction_sha256_by_id": {
            "point_history": sha256_bytes(point_path.read_bytes()),
            "v04_expected_pe": sha256_bytes(b"variant-v04"),
            "ml_expected_pe": sha256_bytes(b"variant-ml"),
        },
        "detached_truth_manifest_sha256": sha256_bytes(custody.truth_path.read_bytes()),
        "environment_manifest_sha256_by_id": candidate_environment_sha256_by_id(),
        "feature_artifact_raw_sha256": feature_hash,
        "feature_provenance_sha256": sha256_bytes(provenance_path.read_bytes()),
        "probabilistic_reference_sha256_by_id": reference_binding_sha256_by_id(),
        "spent_role_authorization_sha256": sha256_bytes(b"variant-role"),
        "training_label_artifact_raw_sha256": sha256_bytes(label_path.read_bytes()),
    }
    payload = build_execution_authorization_payload(
        identity_raw=identity_path.read_bytes(), bindings=bindings
    )
    precommit_path = write_content_addressed_json(directory, "variant_authorization", payload)
    authorization = load_execution_authorization(
        precommit_path,
        identity_path,
        custody.source_path,
        expected_precommit_sha256=sha256_bytes(precommit_path.read_bytes()),
    )
    return (
        authorization,
        load_verified_pit_features(feature_path, provenance_path, authorization=authorization),
        load_verified_training_labels(label_path, authorization=authorization),
    )


def _run_current_qlinear(
    custody: SyntheticCustody,
    *,
    authorization,
    features,
    labels,
) -> pd.DataFrame:
    result = fit_predict_fold(
        model_id="qlinear_l1_with_regime_v1",
        features=features,
        labels=labels,
        authorization=authorization,
        fold=custody.fold,
        experiment_id="synthetic-causal-intervention",
        seed=101,
        entity_id="SYNTH",
        resource_guard=create_candidate_resource_guard(
            authorization=authorization,
            model_id="qlinear_l1_with_regime_v1",
            worker_count=8,
        ),
    )
    return result.output


def test_factory_authorization_rejects_caller_mask_shrink(custody: SyntheticCustody) -> None:
    prediction = _predictions(custody.identity).iloc[:1]
    with pytest.raises(ProbabilisticContractError, match="identity/order"):
        seal_prediction_artifact(prediction, custody.directory, authorization=custody.authorization)


def test_prediction_row_reordering_and_quantile_deletion_fail(custody: SyntheticCustody) -> None:
    reordered = _predictions(custody.identity).iloc[::-1].reset_index(drop=True)
    with pytest.raises(ProbabilisticContractError, match="identity/order"):
        seal_prediction_artifact(reordered, custody.directory, authorization=custody.authorization)
    deleted = _predictions(custody.identity).drop(columns="predicted_pe_p25")
    with pytest.raises(ProbabilisticContractError, match="schema mismatch"):
        seal_prediction_artifact(deleted, custody.directory, authorization=custody.authorization)


def test_prediction_custody_is_defensive_and_authorized(custody: SyntheticCustody) -> None:
    verified = _seal_load(custody, _predictions(custody.identity))
    changed = verified.frame
    changed.loc[0, "expected_pe"] *= 2.0
    verified.verify_integrity()
    assert verified.frame.loc[0, "expected_pe"] != changed.loc[0, "expected_pe"]
    assert (
        verify_prediction_coverage(verified, authorization=custody.authorization)
        == verified.identity_sha256
    )


def test_in_process_truth_and_session_apis_are_tombstoned(
    custody: SyntheticCustody,
) -> None:
    with pytest.raises(ProbabilisticContractError, match="physical evaluator process"):
        create_evaluation_session(authorization=custody.authorization, candidates={})
    with pytest.raises(ProbabilisticContractError, match="physical evaluator process"):
        load_detached_truth(custody.truth_path, authorization=custody.authorization)


def test_truth_requires_all_three_sealed_candidate_receipts(
    custody: SyntheticCustody,
) -> None:
    from pe_regime_v04.model_lab.probabilistic.contracts import (
        _make_verified_prediction_batch,
    )

    with pytest.raises(ProbabilisticContractError, match="tombstoned"):
        _make_verified_prediction_batch()


def test_ngboost_loc_scale_quantile_inconsistency_is_rejected(
    custody: SyntheticCustody,
) -> None:
    prediction = _predictions(custody.identity, density=True)
    prediction.loc[0, "density_loc"] += 0.01
    with pytest.raises(ProbabilisticContractError, match="Normal loc/scale"):
        seal_prediction_artifact(prediction, custody.directory, authorization=custody.authorization)


def test_runner_surface_has_no_adapter_or_bare_frame_injection() -> None:
    parameters = inspect.signature(fit_predict_fold).parameters
    assert "adapter" not in parameters
    assert "train_frame" not in parameters
    assert "test_frame" not in parameters
    assert {
        "features",
        "labels",
        "authorization",
        "entity_id",
        "resource_guard",
    }.issubset(parameters)


def test_exact_fold_positions_are_materialized_from_custody(custody: SyntheticCustody) -> None:
    train, test = materialize_authorized_fold(
        features=custody.features,
        labels=custody.labels,
        authorization=custody.authorization,
        fold=custody.fold,
        seed=101,
        entity_id="SYNTH",
    )
    assert np.array_equal(train["ordered_position"], custody.fold.train_positions)
    assert np.array_equal(test["ordered_position"], custody.fold.test_positions)
    assert "observed_pe" in train and "observed_pe" not in test


def test_forged_short_training_membership_is_rejected(custody: SyntheticCustody) -> None:
    forged = replace(custody.fold, train_positions=custody.fold.train_positions[-40:])
    with pytest.raises(ProbabilisticContractError, match="exact canonical"):
        materialize_authorized_fold(
            features=custody.features,
            labels=custody.labels,
            authorization=custody.authorization,
            fold=forged,
            seed=101,
            entity_id="SYNTH",
        )


def test_candidate_guard_rejects_output_batch_substitution(custody: SyntheticCustody) -> None:
    guard = create_candidate_resource_guard(
        authorization=custody.authorization,
        model_id="qlinear_l1_with_regime_v1",
        worker_count=8,
    )
    result = fit_predict_fold(
        model_id="qlinear_l1_with_regime_v1",
        features=custody.features,
        labels=custody.labels,
        authorization=custody.authorization,
        fold=custody.fold,
        experiment_id="candidate-output-binding",
        seed=101,
        entity_id="SYNTH",
        resource_guard=guard,
    )
    substitute_guard = create_candidate_resource_guard(
        authorization=custody.authorization,
        model_id="qlinear_l1_with_regime_v1",
        worker_count=8,
    )
    substitute_guard.before_fold(
        authorization=custody.authorization,
        model_id="qlinear_l1_with_regime_v1",
        seed=101,
        entity_id="SYNTH",
        fold_id=custody.fold.fold_id,
    )
    tampered = result.output.copy()
    tampered.loc[0, "expected_pe"] *= 2.0
    with pytest.raises(ProbabilisticContractError, match="adapter batch"):
        substitute_guard.after_fold(
            batch=result.batch,
            output=tampered,
            fold_id=custody.fold.fold_id,
        )


def test_factory_runner_executes_one_authorized_chronological_fold(
    custody: SyntheticCustody,
) -> None:
    result = fit_predict_fold(
        model_id="qlinear_l1_with_regime_v1",
        features=custody.features,
        labels=custody.labels,
        authorization=custody.authorization,
        fold=custody.fold,
        experiment_id="synthetic-score-free",
        seed=101,
        entity_id="SYNTH",
        resource_guard=create_candidate_resource_guard(
            authorization=custody.authorization,
            model_id="qlinear_l1_with_regime_v1",
            worker_count=8,
        ),
    )
    assert len(result.output) == len(custody.fold.test_positions)
    assert result.batch.raw_log_quantiles.shape == (21, 5)
    assert result.adapter.fit_attempts == 1


def test_candidate_specific_ngboost_authorization_executes_in_dedicated_environment(
    custody: SyntheticCustody,
) -> None:
    if importlib.util.find_spec("ngboost") is None:
        pytest.skip("dedicated NGBoost environment only")
    result = fit_predict_fold(
        model_id="ngboost_normal_crps_with_regime_v1",
        features=custody.features,
        labels=custody.labels,
        authorization=custody.authorization,
        fold=custody.fold,
        experiment_id="synthetic-score-free-ngboost-authorized",
        seed=101,
        entity_id="SYNTH",
        resource_guard=create_candidate_resource_guard(
            authorization=custody.authorization,
            model_id="ngboost_normal_crps_with_regime_v1",
            worker_count=8,
        ),
    )
    assert result.batch.density_parameters is not None
    loc = result.batch.density_parameters["loc"]
    scale = result.batch.density_parameters["scale"]
    expected = loc[:, None] + scale[:, None] * NORMAL_QUANTILE_Z[None, :]
    np.testing.assert_array_equal(result.batch.raw_log_quantiles, expected)


def test_actual_pit_feature_byte_substitution_fails(custody: SyntheticCustody) -> None:
    changed = custody.feature_path.read_bytes().replace(b"SYNTH", b"OTHER", 1)
    substitute = custody.directory / f"pit_features.{sha256_bytes(changed)}.csv"
    substitute.write_bytes(changed)
    provenance = next(custody.directory.glob("pit_feature_provenance.*.json"))
    with pytest.raises(ProbabilisticContractError, match="differs from authorization"):
        load_verified_pit_features(substitute, provenance, authorization=custody.authorization)


def test_execution_source_closure_drift_fails_before_capability_use(
    custody: SyntheticCustody, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = (ROOT / "src/pe_regime_v04/model_lab/folds.py").resolve()
    original = Path.read_bytes

    def altered(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\n# synthetic drift probe" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", altered)
    with pytest.raises(ProbabilisticContractError, match="source/config bytes drifted"):
        custody.authorization.verify_integrity()


def test_clean_process_loaded_shared_model_lab_modules_are_exactly_bound() -> None:
    package = ROOT / "src/pe_regime_v04/model_lab"
    probe = """
import json
from pathlib import Path
import sys
import pe_regime_v04.model_lab
root = Path(sys.argv[1]).resolve()
package = (root / 'src/pe_regime_v04/model_lab').resolve()
paths = []
for name, module in sys.modules.items():
    if name != 'pe_regime_v04.model_lab' and not name.startswith('pe_regime_v04.model_lab.'):
        continue
    source = getattr(module, '__file__', None)
    if source is None:
        continue
    path = Path(source).resolve()
    if path.parent == package:
        paths.append(path.relative_to(root).as_posix())
print(json.dumps(sorted(set(paths))))
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-c", probe, str(ROOT)],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    loaded = set(json.loads(completed.stdout))
    expected = {
        (package / name).relative_to(ROOT).as_posix()
        for name in (
            "__init__.py",
            "analysis.py",
            "baselines.py",
            "contracts.py",
            "dataset.py",
            "evaluator.py",
            "experiment.py",
            "folds.py",
            "matrices.py",
            "registry.py",
        )
    }
    bound = {path.relative_to(ROOT).as_posix() for path in execution_closure_paths(ROOT)}
    assert loaded == expected
    assert loaded.issubset(bound)


@pytest.mark.parametrize(
    "module_name",
    ["analysis.py", "baselines.py", "experiment.py", "matrices.py", "registry.py"],
)
def test_each_previously_omitted_loaded_shared_module_drift_fails(
    custody: SyntheticCustody,
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
) -> None:
    target = (ROOT / "src/pe_regime_v04/model_lab" / module_name).resolve()
    original = Path.read_bytes

    def altered(path: Path) -> bytes:
        raw = original(path)
        return raw + b"\n# synthetic shared-module drift probe" if path.resolve() == target else raw

    monkeypatch.setattr(Path, "read_bytes", altered)
    with pytest.raises(ProbabilisticContractError, match=module_name):
        custody.authorization.verify_integrity()


def test_future_row_perturbation_does_not_change_completed_fold_predictions(
    custody: SyntheticCustody, tmp_path: Path
) -> None:
    base = _run_current_qlinear(
        custody,
        authorization=custody.authorization,
        features=custody.features,
        labels=custody.labels,
    )
    authorization, features, labels = _variant_artifacts(custody, tmp_path, feature_position=600)
    perturbed = _run_current_qlinear(
        custody,
        authorization=authorization,
        features=features,
        labels=labels,
    )
    pd.testing.assert_frame_equal(base, perturbed, check_exact=True)


def test_outer_test_target_perturbation_does_not_change_predictions(
    custody: SyntheticCustody, tmp_path: Path
) -> None:
    base = _run_current_qlinear(
        custody,
        authorization=custody.authorization,
        features=custody.features,
        labels=custody.labels,
    )
    authorization, features, labels = _variant_artifacts(
        custody, tmp_path, label_positions=tuple(custody.fold.test_positions)
    )
    perturbed = _run_current_qlinear(
        custody,
        authorization=authorization,
        features=features,
        labels=labels,
    )
    pd.testing.assert_frame_equal(base, perturbed, check_exact=True)


def test_seed_entity_boundary_substitution_fails(custody: SyntheticCustody) -> None:
    raw = custody.feature_path.read_bytes().replace(b"SYNTH", b"OTHER", 1)
    substitute = custody.directory / f"pit_features.{sha256_bytes(raw)}.csv"
    substitute.write_bytes(raw)
    provenance = next(custody.directory.glob("pit_feature_provenance.*.json"))
    with pytest.raises(ProbabilisticContractError, match="differs from authorization"):
        load_verified_pit_features(substitute, provenance, authorization=custody.authorization)


def test_comparator_artifact_substitution_fails(custody: SyntheticCustody) -> None:
    point_path = next(custody.directory.glob("point_history.*.csv"))
    raw = point_path.read_bytes().replace(b"SYNTH", b"OTHER", 1)
    substitute = custody.directory / f"point_history.{sha256_bytes(raw)}.csv"
    substitute.write_bytes(raw)
    with pytest.raises(ProbabilisticContractError, match="differs from its address"):
        load_verified_point_prediction_history(
            substitute,
            authorization=custody.authorization,
            comparator_id="point_history",
        )


def test_grouped_references_use_exact_prior_shift(custody: SyntheticCustody) -> None:
    rolling = rolling_log_quantiles_252(
        labels=custody.labels,
        authorization=custody.authorization,
        fold=custody.fold,
        seed=101,
        entity_id="SYNTH",
    )
    residual = point_residual_quantiles_252(
        point_history=custody.point_history,
        labels=custody.labels,
        authorization=custody.authorization,
        fold=custody.fold,
        seed=101,
        entity_id="SYNTH",
    )
    assert rolling.rows == residual.rows == len(custody.fold.test_positions)
    assert "verified_prediction" not in inspect.signature(point_residual_quantiles_252).parameters
    assert (
        "uses_same_row_observed_pe"
        not in inspect.signature(point_residual_quantiles_252).parameters
    )


def test_reference_private_frame_mutation_is_detected(custody: SyntheticCustody) -> None:
    label_frame = object.__getattribute__(custody.labels, "_frame")
    original_label = label_frame.loc[0, "observed_pe"]
    label_frame.loc[0, "observed_pe"] *= 2.0
    try:
        with pytest.raises(ProbabilisticContractError, match="frame changed"):
            rolling_log_quantiles_252(
                labels=custody.labels,
                authorization=custody.authorization,
                fold=custody.fold,
                seed=101,
                entity_id="SYNTH",
            )
    finally:
        label_frame.loc[0, "observed_pe"] = original_label
    point_frame = object.__getattribute__(custody.point_history, "_frame")
    original_point = point_frame.loc[0, "point_expected_pe"]
    point_frame.loc[0, "point_expected_pe"] *= 2.0
    try:
        with pytest.raises(ProbabilisticContractError, match="frame changed"):
            point_residual_quantiles_252(
                point_history=custody.point_history,
                labels=custody.labels,
                authorization=custody.authorization,
                fold=custody.fold,
                seed=101,
                entity_id="SYNTH",
            )
    finally:
        point_frame.loc[0, "point_expected_pe"] = original_point


def test_residual_current_position_injection_fails(custody: SyntheticCustody) -> None:
    injected = replace(
        custody.fold,
        train_positions=(*custody.fold.train_positions[:-1], custody.fold.test_positions[0]),
    )
    with pytest.raises(ProbabilisticContractError, match="exact canonical"):
        point_residual_quantiles_252(
            point_history=custody.point_history,
            labels=custody.labels,
            authorization=custody.authorization,
            fold=injected,
            seed=101,
            entity_id="SYNTH",
        )


def test_reference_rejects_old_noncanonical_252_window(custody: SyntheticCustody) -> None:
    old = replace(custody.fold, train_positions=tuple(range(252)))
    for factory in (rolling_log_quantiles_252, point_residual_quantiles_252):
        kwargs = {
            "labels": custody.labels,
            "authorization": custody.authorization,
            "fold": old,
            "seed": 101,
            "entity_id": "SYNTH",
        }
        if factory is point_residual_quantiles_252:
            kwargs["point_history"] = custody.point_history
        with pytest.raises(ProbabilisticContractError, match="exact canonical"):
            factory(**kwargs)


def test_prefix_truncation_shared_completed_folds_are_identical() -> None:
    base = pd.DataFrame({"date": pd.date_range("2010-01-01", periods=600, freq="D")})
    longer = pd.DataFrame({"date": pd.date_range("2010-01-01", periods=621, freq="D")})
    first = build_outer_folds(base)
    second = build_outer_folds(longer)
    completed = tuple(fold for fold in first if len(fold.test_positions) == 21)
    assert completed == second[: len(completed)]


def test_prefix_truncation_shared_completed_predictions_are_identical(
    custody: SyntheticCustody, tmp_path: Path
) -> None:
    completed = _run_current_qlinear(
        custody,
        authorization=custody.authorization,
        features=custody.features,
        labels=custody.labels,
    )
    authorization, longer_features, labels = _variant_artifacts(
        custody, tmp_path, feature_position=1799
    )
    longer = _run_current_qlinear(
        custody,
        authorization=authorization,
        features=longer_features,
        labels=labels,
    )
    pd.testing.assert_frame_equal(completed, longer, check_exact=True)


def test_real_fixed_receipt_ranking_advances_at_most_one(
    custody: SyntheticCustody,
) -> None:
    result = run_score_free_governance_evidence(custody.authorization)
    assert result["selected"] == ["qhistgb_with_regime_v1"]
    assert len(result["selected"]) <= 1
    assert result["gate_application_count_per_candidate"] == 1
    assert result["candidate_receipt_count"] == 3
    assert set(result["candidate_receipt_ids"]) == {
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
        "ngboost_normal_crps_with_regime_v1",
    }


def test_physical_evaluator_returns_metric_receipts_only() -> None:
    path = (
        ROOT / "outputs/model_zoo_probabilistic_wave_screen_20260819/"
        "PHYSICAL_EVALUATOR_RESULT_V4.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["metric_receipts_only"] is True
    assert payload["truth_bytes_returned"] is False
    assert payload["prediction_bytes_returned"] is False
    assert payload["evaluator_pid"] != payload["parent_pid"]
    assert set(payload["candidate_metric_receipts"]) == {
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
        "ngboost_normal_crps_with_regime_v1",
    }


def test_reference_and_distinct_point_receipts_require_full_custody(
    custody: SyntheticCustody, tmp_path: Path
) -> None:
    feature_frame = object.__getattribute__(custody.features, "_frame").copy(deep=True)
    label_frame = object.__getattribute__(custody.labels, "_frame").copy(deep=True)
    point_history_frame = object.__getattribute__(custody.point_history, "_frame").copy(deep=True)
    feature_path = write_content_addressed_csv(tmp_path, "receipt_features", feature_frame)
    provenance_path = write_content_addressed_json(
        tmp_path,
        "receipt_provenance",
        build_feature_provenance(
            feature_artifact_raw_sha256=sha256_bytes(feature_path.read_bytes())
        ),
    )
    label_path = write_content_addressed_csv(tmp_path, "receipt_labels", label_frame)
    point_history_path = write_content_addressed_csv(
        tmp_path, "receipt_point_history", point_history_frame
    )
    identity_path = write_content_addressed_csv(tmp_path, "receipt_identity", custody.identity)
    v04 = custody.identity.copy()
    v04["expected_pe"] = np.exp(2.70 + np.arange(len(v04)) / 100000.0)
    ml = custody.identity.copy()
    ml["expected_pe"] = np.exp(2.71 + np.arange(len(ml)) / 100000.0)
    v04_path = write_content_addressed_csv(tmp_path, "v04_comparator", v04)
    ml_path = write_content_addressed_csv(tmp_path, "ml_comparator", ml)
    bindings = {
        "adapter_binding_sha256_by_id": adapter_binding_sha256_by_id(),
        "candidate_source_snapshot_sha256": sha256_bytes(custody.source_path.read_bytes()),
        "comparator_prediction_sha256_by_id": {
            "point_history": sha256_bytes(point_history_path.read_bytes()),
            "v04_expected_pe": sha256_bytes(v04_path.read_bytes()),
            "ml_expected_pe": sha256_bytes(ml_path.read_bytes()),
        },
        "detached_truth_manifest_sha256": sha256_bytes(custody.truth_path.read_bytes()),
        "environment_manifest_sha256_by_id": candidate_environment_sha256_by_id(),
        "feature_artifact_raw_sha256": sha256_bytes(feature_path.read_bytes()),
        "feature_provenance_sha256": sha256_bytes(provenance_path.read_bytes()),
        "probabilistic_reference_sha256_by_id": reference_binding_sha256_by_id(),
        "spent_role_authorization_sha256": sha256_bytes(b"receipt-role"),
        "training_label_artifact_raw_sha256": sha256_bytes(label_path.read_bytes()),
    }
    payload = build_execution_authorization_payload(
        identity_raw=identity_path.read_bytes(), bindings=bindings
    )
    authorization_path = write_content_addressed_json(tmp_path, "receipt_authorization", payload)
    authorization = load_execution_authorization(
        authorization_path,
        identity_path,
        custody.source_path,
        expected_precommit_sha256=sha256_bytes(authorization_path.read_bytes()),
    )
    v04_artifact = load_verified_point_comparator(
        v04_path, comparator_id="v04_expected_pe", authorization=authorization
    )
    ml_artifact = load_verified_point_comparator(
        ml_path, comparator_id="ml_expected_pe", authorization=authorization
    )
    assert v04_artifact.raw_sha256 != ml_artifact.raw_sha256
    v04_receipt_path = seal_point_comparator_custody_receipt(
        v04_artifact, tmp_path, authorization=authorization
    )
    ml_receipt_path = seal_point_comparator_custody_receipt(
        ml_artifact, tmp_path, authorization=authorization
    )
    loaded_v04 = load_verified_point_comparator_with_receipt(
        v04_path,
        v04_receipt_path,
        comparator_id="v04_expected_pe",
        authorization=authorization,
    )
    assert loaded_v04.raw_sha256 == v04_artifact.raw_sha256
    with pytest.raises(ProbabilisticContractError, match="differs"):
        load_verified_point_comparator_with_receipt(
            v04_path,
            ml_receipt_path,
            comparator_id="ml_expected_pe",
            authorization=authorization,
        )

    labels = load_verified_training_labels(label_path, authorization=authorization)
    folds = build_outer_folds(label_frame, label_available_at_column="label_available_at")
    accumulator = create_reference_execution_accumulator(
        authorization=authorization, reference_id="rolling_log_quantiles_252"
    )
    for fold in folds[12:]:
        accumulator.record(
            rolling_log_quantiles_252(
                labels=labels,
                authorization=authorization,
                fold=fold,
                seed=101,
                entity_id="SYNTH",
            )
        )
    reference, execution_receipt = accumulator.seal(tmp_path)
    execution_path = write_reference_execution_receipt(execution_receipt, tmp_path)
    loaded_execution = load_verified_reference_execution_receipt(
        execution_path,
        authorization=authorization,
        predictions=reference,
        reference_id="rolling_log_quantiles_252",
    )
    assert loaded_execution.provenance["prediction_raw_sha256"] == reference.raw_sha256
    assert loaded_execution.provenance["common_identity_sha256"] == reference.identity_sha256
    fabricated_frame = reference.frame
    fabricated_frame.loc[0, "predicted_pe_p10"] *= 0.99
    fabricated_frame.loc[0, "uncertainty_log_idr"] = np.log(
        fabricated_frame.loc[0, "predicted_pe_p90"]
    ) - np.log(fabricated_frame.loc[0, "predicted_pe_p10"])
    fabricated_frame.loc[0, "uncertainty_p90_p10_ratio"] = (
        fabricated_frame.loc[0, "predicted_pe_p90"] / fabricated_frame.loc[0, "predicted_pe_p10"]
    )
    fabricated_path, fabricated_receipt_path = seal_reference_prediction_artifact(
        fabricated_frame, tmp_path / "fabricated", authorization=authorization
    )
    fabricated = load_verified_reference_prediction_artifact(
        fabricated_path, fabricated_receipt_path, authorization=authorization
    )
    with pytest.raises(ProbabilisticContractError, match="differs"):
        load_verified_reference_execution_receipt(
            execution_path,
            authorization=authorization,
            predictions=fabricated,
            reference_id="rolling_log_quantiles_252",
        )


def test_ranking_rejects_arbitrary_metric_mappings(custody: SyntheticCustody) -> None:
    with pytest.raises(ProbabilisticContractError, match="arbitrary metric mappings"):
        select_from_verified_receipts(
            authorization=custody.authorization,
            candidates={"qlinear_l1_with_regime_v1": {}},  # type: ignore[dict-item]
            probabilistic_references={},
            point_comparators={},
            runtime_by_candidate={},
        )
    with pytest.raises(ProbabilisticContractError, match="evaluator custody"):
        VerifiedEvaluationReceipt(payload={})  # type: ignore[call-arg]


def test_worker_count_parity_contract_requires_all_real_lane_receipts() -> None:
    digest = "a" * 64
    assert verify_worker_count_parity({8: digest, 16: digest, 24: digest, 32: digest}) == digest
    with pytest.raises(ProbabilisticContractError, match="changed prediction"):
        verify_worker_count_parity({8: digest, 16: digest, 24: "b" * 64, 32: digest})


def test_real_candidate_serialization_replay_evidence_is_complete() -> None:
    output = ROOT / "outputs/model_zoo_probabilistic_wave_screen_20260819"
    model_ids: set[str] = set()
    for name in (
        "MODEL_LAB_SERIALIZATION_REPLAY.json",
        "NGBOOST_SERIALIZATION_REPLAY.json",
    ):
        payload = json.loads((output / name).read_text(encoding="utf-8"))
        for record in payload["records"]:
            model_ids.add(record["model_id"])
            assert record["prediction_sha256_before"] == record["prediction_sha256_after"]
            assert record["fit_attempts"] == 1
            assert record["warnings"] == []
    assert model_ids == {
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
        "ngboost_normal_crps_with_regime_v1",
    }


def test_real_outer_fit_worker_parity_and_projection_evidence() -> None:
    path = (
        ROOT
        / "outputs/model_zoo_probabilistic_wave_screen_20260819/RESOURCE_RUNTIME_EVIDENCE_V3.json"
    )
    payload = json.loads(path.read_text(encoding="utf-8"))
    benchmark = payload["spawn_parity"]
    assert set(benchmark["candidate_ids"]) == {
        "qlinear_l1_with_regime_v1",
        "qhistgb_with_regime_v1",
        "ngboost_normal_crps_with_regime_v1",
    }
    assert benchmark["projection_guard_passed"] is True
    assert benchmark["selected_worker_count"] in {8, 16, 24, 32}
    assert benchmark["selected_projection_maximum_candidate_minutes"] <= 90
    assert [lane["worker_count"] for lane in benchmark["lanes"]] == [8, 16, 24, 32]
    assert len({lane["prediction_sha256"] for lane in benchmark["lanes"]}) == 1
    for lane in benchmark["lanes"]:
        assert len(lane["observed_worker_pids"]) == lane["worker_count"]
        assert set(lane["candidate_ids"]) == set(benchmark["candidate_ids"])
        assert lane["actual_outer_fit_task_count"] == lane["worker_count"]
        for model_id, record in lane["canonical_outputs"].items():
            assert record["published_quantile_count"] == 5
            if model_id != "ngboost_normal_crps_with_regime_v1":
                assert record["sequential_quantile_estimator_count"] == 5
        assert lane["live_peak_process_tree_rss_gib"] <= 64.0
        assert lane["live_minimum_free_ram_gib"] >= 16.0
        assert lane["resource_snapshot"]["gpu"] == "OFF"


def test_environment_drift_fails_exact_pins() -> None:
    freeze = "\n".join(
        [
            "ngboost==0.5.11",
            "numpy==1.26.4",
            "pandas==2.2.3",
            "scikit-learn==1.7.2",
            "scipy==1.15.3",
            "pyarrow==21.0.0",
        ]
    )
    verify_dedicated_freeze(freeze)
    with pytest.raises(ProbabilisticContractError, match="environment drift"):
        verify_dedicated_freeze(freeze.replace("scikit-learn==1.7.2", "scikit-learn==1.8.0"))


def test_external_raw_pin_rejects_coordinated_alternate_pointer_reseal(
    tmp_path: Path,
) -> None:
    publication = json.loads(
        (
            ROOT / "outputs/model_zoo_probabilistic_wave_spent_screen_20260819/"
            "FORMAL_ACTIVATION_PUBLICATION_V2.json"
        ).read_bytes()
    )
    request_path = ROOT / publication["execution_request_path"]
    request = load_external_execution_request(
        request_path,
        expected_raw_sha256=publication["execution_request_raw_sha256"],
        repo_root=ROOT,
    )
    pointer_path = ROOT / publication["pointer_path"]
    altered_pointer = json.loads(pointer_path.read_bytes())
    altered_pointer["coordinated_reseal_marker"] = "different-reviewed-chain"
    alternate_path = write_content_addressed_json(
        tmp_path,
        "alternate_formal_pointer",
        seal_payload(altered_pointer),
    )
    with pytest.raises(ProbabilisticContractError, match="external raw pin"):
        verify_externally_pinned_pointer(alternate_path, request=request)

    from pe_regime_v04.model_lab.probabilistic.physical_evaluator import (
        _load_authorization_from_pointer,
    )

    with pytest.raises(ProbabilisticContractError, match="externally pinned launch authority"):
        _load_authorization_from_pointer(pointer_path, repo_root=ROOT)
