from __future__ import annotations

import ast
import copy
from dataclasses import replace
import hashlib
import itertools
import json
import math
from pathlib import Path
import struct
from typing import Iterator

import pytest

from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v1 import evaluator as v1_math
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2 import (
    ActivationLockV2,
    ArtifactRef,
    BindingSlot,
    DependencyLockV2,
    EvaluatorV2Error,
    FinalPretruthBindingV2,
    PolicyV2,
    PredictionDecodeContract,
    ProductionEntryDenied,
    SourceOnlyOneShotMachine,
    c5_terminal_line,
    decode_prediction_rows,
    validate_c5_terminal_line,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2 import metric_core
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.canonical import (
    canonical_json_bytes,
    strict_canonical_json_object,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.constants import (
    ACTIVATION_LOCK_SCHEMA,
    ACTIVATION_LOCK_STATUS,
    ARCHITECTURE_V2_RAW_SHA256,
    ARCHITECTURE_V2_RELATIVE,
    ARCHITECTURE_V2_SIZE_BYTES,
    ARCHITECTURE_V3_RAW_SHA256,
    ARCHITECTURE_V3_RELATIVE,
    ARCHITECTURE_V3_SIZE_BYTES,
    C5_AUDIT_RAW_SHA256,
    C5_CHECKSUMS_RAW_SHA256,
    C5_ID,
    CONSUMPTION_MARKER_LEAF,
    DEPENDENCY_FINAL_STATUS,
    DEPENDENCY_LOCK_SCHEMA,
    DEPENDENCY_PENDING_STATUS,
    FAILURE_LEAF,
    FINAL_BINDING_SCHEMA,
    FINAL_BINDING_STATUS,
    IDENTITY_COUNT,
    MODEL_IDS,
    MODEL_LINE_IDS,
    POLICY_RAW_SHA256,
    POLICY_RELATIVE,
    POLICY_SIZE_BYTES,
    PREDICTION_COLUMNS,
    PREDICTION_CONTRACT_RAW_SHA256,
    PREDICTION_CONTRACT_RELATIVE,
    PREDICTION_CONTRACT_SIZE_BYTES,
    PROMPT_RAW_SHA256,
    PROMPT_SIZE_BYTES,
    RESULT_LEAF,
    SCOREABLE_CANDIDATE_IDS,
    SCORECARD_COLUMNS,
    SCORECARD_TEMPLATE_RAW_SHA256,
    SCORECARD_TEMPLATE_RELATIVE,
    SCORECARD_TEMPLATE_SIZE_BYTES,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.contracts import (
    ARTIFACT_REF_KEYS,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.custody import (
    HeldArtifact,
    _snapshot_artifact_ref_untrusted,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.prediction import (
    identity_semantic_sha256,
)
from research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2.publication import (
    HeldLeafReceipt,
    create_consumption_marker,
    publish_create_new,
)


ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / POLICY_RELATIVE


class _RefFactory:
    def __init__(self) -> None:
        self.ordinal = 100

    def make(
        self,
        name: str,
        *,
        raw_sha256: str | None = None,
        size_bytes: int = 1,
        exact_relative_path: bool = False,
    ) -> dict[str, object]:
        self.ordinal += 1
        return {
            "relative_path": name if exact_relative_path else f"frozen/{name}",
            "raw_sha256": raw_sha256 or f"{self.ordinal:064x}",
            "size_bytes": size_bytes,
            "volume_serial_number": 99,
            "file_id_128": f"{self.ordinal:032x}",
        }


def _slot(artifact: dict[str, object] | None, *, reason: str = "NOT_FROZEN") -> dict[str, object]:
    if artifact is None:
        return {"artifact": None, "reason_code": reason, "state": "PENDING"}
    return {"artifact": artifact, "reason_code": None, "state": "FINAL"}


def _dependency_payload(*, final: bool = True) -> dict[str, object]:
    factory = _RefFactory()
    expected = {
        "qualification_policy_v2": factory.make(
            POLICY_RELATIVE,
            raw_sha256=POLICY_RAW_SHA256,
            size_bytes=POLICY_SIZE_BYTES,
            exact_relative_path=True,
        ),
        "authoritative_prompt": factory.make(
            "AUTHORITATIVE_PROMPT.txt",
            raw_sha256=PROMPT_RAW_SHA256,
            size_bytes=PROMPT_SIZE_BYTES,
        ),
        "policy_declared_phase2_v2": factory.make(
            ARCHITECTURE_V2_RELATIVE,
            raw_sha256=ARCHITECTURE_V2_RAW_SHA256,
            size_bytes=ARCHITECTURE_V2_SIZE_BYTES,
            exact_relative_path=True,
        ),
        "effective_phase2_v3": factory.make(
            ARCHITECTURE_V3_RELATIVE,
            raw_sha256=ARCHITECTURE_V3_RAW_SHA256,
            size_bytes=ARCHITECTURE_V3_SIZE_BYTES,
            exact_relative_path=True,
        ),
        "prediction_contract_v2": factory.make(
            PREDICTION_CONTRACT_RELATIVE,
            raw_sha256=PREDICTION_CONTRACT_RAW_SHA256,
            size_bytes=PREDICTION_CONTRACT_SIZE_BYTES,
            exact_relative_path=True,
        ),
        "scorecard_template": factory.make(
            SCORECARD_TEMPLATE_RELATIVE,
            raw_sha256=SCORECARD_TEMPLATE_RAW_SHA256,
            size_bytes=SCORECARD_TEMPLATE_SIZE_BYTES,
            exact_relative_path=True,
        ),
        "c5_terminal_audit": factory.make(
            "forensic/C5_AUDIT.json", raw_sha256=C5_AUDIT_RAW_SHA256
        ),
        "c5_terminal_checksums": factory.make(
            "forensic/C5_CHECKSUMS.sha256", raw_sha256=C5_CHECKSUMS_RAW_SHA256
        ),
    }
    return {
        "schema_version": DEPENDENCY_LOCK_SCHEMA,
        "status": DEPENDENCY_FINAL_STATUS if final else DEPENDENCY_PENDING_STATUS,
        **{
            key: _slot(value if final or key != "effective_phase2_v3" else None)
            for key, value in expected.items()
        },
        "scoring_authority": False,
        "truth_authority": False,
        "heldout_authority": False,
    }


def _audit(factory: _RefFactory, name: str) -> dict[str, object]:
    return {
        "result": factory.make(f"{name}/RESULT.json"),
        "checksums": factory.make(f"{name}/CHECKSUMS.sha256"),
        "verdict": "GO",
        "P0": 0,
        "P1": 0,
        "P2": 0,
    }


def _final_payload(dependency: DependencyLockV2) -> dict[str, object]:
    factory = _RefFactory()
    policy = dependency.slot("qualification_policy_v2").artifact
    prompt = dependency.slot("authoritative_prompt").artifact
    c5_audit = dependency.slot("c5_terminal_audit").artifact
    c5_checksums = dependency.slot("c5_terminal_checksums").artifact
    assert policy is not None and prompt is not None
    assert c5_audit is not None and c5_checksums is not None
    common_semantic = "a" * 64
    common = {
        "execution_binding_lock": factory.make("common/EXECUTION_BINDING_LOCK.json"),
        "public_manifest": factory.make("common/PUBLIC_MANIFEST.json"),
        "full_identities": factory.make("common/FULL_IDENTITIES.jsonl"),
        "checksums": factory.make("common/CHECKSUMS.sha256"),
        "source_identity": factory.make("common/SOURCE_IDENTITY.json"),
        "common_full_identities_semantic_sha256": common_semantic,
    }
    prediction_ref = factory.make("prediction/PREDICTIONS.jsonl")
    prediction_semantic = "b" * 64
    post_prediction = _audit(factory, "post_prediction")
    post_prediction.update(
        {
            "prediction_artifact_raw_sha256": prediction_ref["raw_sha256"],
            "prediction_artifact_semantic_sha256": prediction_semantic,
        }
    )
    models = []
    for ordinal, (model_id, line_id) in enumerate(zip(MODEL_IDS, MODEL_LINE_IDS, strict=True)):
        models.append(
            {
                "model_id": model_id,
                "model_ordinal": ordinal,
                "line_id": line_id,
                "source_model_version": f"final::{model_id}",
                "definition_lock": factory.make(f"models/{ordinal}/DEFINITION.json"),
                "source_identity": factory.make(f"models/{ordinal}/SOURCE_IDENTITY.json"),
                "execution_binding": factory.make(f"models/{ordinal}/EXECUTION_BINDING.json"),
            }
        )
    runtimes = [
        {
            "lane_id": "shared_c1_c3",
            "candidate_ids": list(SCOREABLE_CANDIDATE_IDS[:3]),
            "receipt": factory.make("runtime/shared/RECEIPT.json"),
            "source_identity": factory.make("runtime/shared/SOURCE_IDENTITY.json"),
        },
        {
            "lane_id": "isolated_c4",
            "candidate_ids": [SCOREABLE_CANDIDATE_IDS[3]],
            "receipt": factory.make("runtime/c4/RECEIPT.json"),
            "source_identity": factory.make("runtime/c4/SOURCE_IDENTITY.json"),
        },
    ]
    evaluator_bundle = {
        "archive": factory.make("evaluator/EVALUATOR.pyz"),
        "source_identity": factory.make("evaluator/SOURCE_IDENTITY.json"),
        "command_lock": factory.make("evaluator/COMMAND_LOCK.json"),
        "checksums": factory.make("evaluator/CHECKSUMS.sha256"),
        "adversarial_tests": factory.make("evaluator/ADVERSARIAL_TESTS.json"),
        "launcher": factory.make("evaluator/ONCE.ps1"),
    }
    return {
        "schema_version": FINAL_BINDING_SCHEMA,
        "status": FINAL_BINDING_STATUS,
        "qualification_policy_v2": policy.as_mapping(),
        "authoritative_prompt": prompt.as_mapping(),
        "evaluator_dependency_lock": factory.make(
            "locks/EVALUATOR_DEPENDENCY_LOCK.json",
            raw_sha256=dependency.raw_sha256,
            size_bytes=len(dependency.raw),
        ),
        "common_generation": common,
        "post_generation_audit": _audit(factory, "post_generation"),
        "prediction_artifact": {
            "artifact": prediction_ref,
            "semantic_sha256": prediction_semantic,
            "row_count": 324_000,
            "identity_count": 64_800,
            "columns_in_order": list(PREDICTION_COLUMNS),
        },
        "post_prediction_audit": post_prediction,
        "model_bindings_in_order": models,
        "runtime_bindings_in_order": runtimes,
        "evaluator_bundle": evaluator_bundle,
        "c5_terminal_binding": {
            "candidate_id": C5_ID,
            "line_id": "PE-C5",
            "state": "TERMINAL_NOT_APPLICABLE",
            "terminal_status": "NOT_RUN_TERMINAL_CUSTODY_NO_GO",
            "retry_allowed": False,
            "performance_claim_allowed": False,
            "audit": c5_audit.as_mapping(),
            "checksums": c5_checksums.as_mapping(),
        },
        "comparison_model_id": MODEL_IDS[0],
        "scoreable_candidate_ids_in_order": list(SCOREABLE_CANDIDATE_IDS),
        "prediction_columns_in_order": list(PREDICTION_COLUMNS),
        "scorecard_columns_in_order": list(SCORECARD_COLUMNS),
        "common_full_identities_semantic_sha256": common_semantic,
        "heldout_authority": False,
        "truth_access_count": 0,
        "same_identity_retry_allowed": False,
    }


def _final() -> tuple[DependencyLockV2, FinalPretruthBindingV2, dict[str, object]]:
    dependency = DependencyLockV2.from_json_bytes(
        canonical_json_bytes(_dependency_payload(final=True))
    )
    payload = _final_payload(dependency)
    final = FinalPretruthBindingV2.from_json_bytes(
        canonical_json_bytes(payload), dependency_lock=dependency
    )
    return dependency, final, payload


def _activation_payload(final: FinalPretruthBindingV2) -> dict[str, object]:
    factory = _RefFactory()
    return {
        "schema_version": ACTIVATION_LOCK_SCHEMA,
        "status": ACTIVATION_LOCK_STATUS,
        "final_pretruth_binding": factory.make(
            "activation/FINAL_BINDING.json",
            raw_sha256=final.raw_sha256,
            size_bytes=len(final.raw),
        ),
        "pre_score_audit": factory.make("activation/PRESCORE_AUDIT.json"),
        "pre_score_audit_checksums": factory.make("activation/CHECKSUMS.sha256"),
        "evaluator_archive": final.evaluator_archive.as_mapping(),
        "qualification_authority": factory.make("activation/AUTHORITY.json"),
        "attempt_ordinal": 1,
        "consumption_marker_leaf": CONSUMPTION_MARKER_LEAF,
        "result_leaf": RESULT_LEAF,
        "failure_leaf": FAILURE_LEAF,
        "heldout_authority": False,
        "truth_open_count_at_activation": 0,
        "caller_supplied_path_count": 0,
        "issuer_public_key_hex": "ab" * 32,
        "authority_signature_hex": "cd" * 64,
        "authority_nonce_sha256": "e" * 64,
    }


def test_policy_v2_requires_exact_literal_canonical_27_key_bytes() -> None:
    raw = POLICY_PATH.read_bytes()
    policy = PolicyV2.from_json_bytes(raw)
    assert policy.raw_sha256 == POLICY_RAW_SHA256
    assert len(policy.payload) == 27

    attacked = copy.deepcopy(policy.payload)
    attacked["dependency_bindings"] = {"attacker_selected": True}
    attacked["truth_open_preconditions_in_order"] = ["truth first"]
    attacked["extra_top_level"] = True
    with pytest.raises(EvaluatorV2Error, match="literal raw identity"):
        PolicyV2.from_json_bytes(canonical_json_bytes(attacked))

    compact = (
        json.dumps(policy.payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()
    with pytest.raises(EvaluatorV2Error, match="literal raw identity"):
        PolicyV2.from_json_bytes(compact)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("raw_sha256", "0" * 64),
        ("raw_sha256", "A" * 64),
        ("file_id_128", "0" * 32),
        ("file_id_128", "A" * 32),
        ("volume_serial_number", 0),
        ("volume_serial_number", True),
        ("size_bytes", 0),
        ("size_bytes", 1.0),
        ("relative_path", "../escape.json"),
        ("relative_path", "C:/escape.json"),
    ],
)
def test_artifact_ref_rejects_zero_subclasses_and_path_escape(
    field: str, value: object
) -> None:
    row = _RefFactory().make("safe.json")
    assert tuple(row) == ARTIFACT_REF_KEYS
    row[field] = value
    with pytest.raises(EvaluatorV2Error):
        ArtifactRef.from_mapping(row, label="attack")


def test_binding_slot_has_disjoint_pending_final_terminal_shapes() -> None:
    final = BindingSlot.from_mapping(_slot(_RefFactory().make("x.json")), label="slot")
    assert final.state == "FINAL" and final.artifact is not None
    pending = BindingSlot.from_mapping(_slot(None), label="slot")
    assert pending.state == "PENDING" and pending.artifact is None
    terminal = BindingSlot.from_mapping(
        {"artifact": None, "reason_code": "TERMINAL", "state": "TERMINAL_NOT_APPLICABLE"},
        label="slot",
    )
    assert terminal.state == "TERMINAL_NOT_APPLICABLE"
    with pytest.raises(EvaluatorV2Error):
        BindingSlot.from_mapping(
            {"artifact": _RefFactory().make("x.json"), "reason_code": "pending", "state": "PENDING"},
            label="slot",
        )


def test_dependency_lock_pending_and_final_status_are_causally_exact() -> None:
    pending = DependencyLockV2.from_json_bytes(
        canonical_json_bytes(_dependency_payload(final=False))
    )
    assert pending.status == DEPENDENCY_PENDING_STATUS
    final_payload = _dependency_payload(final=True)
    final = DependencyLockV2.from_json_bytes(canonical_json_bytes(final_payload))
    assert final.status == DEPENDENCY_FINAL_STATUS
    assert final.slot("effective_phase2_v3").artifact is not None

    attacked = copy.deepcopy(final_payload)
    attacked["effective_phase2_v3"]["artifact"]["raw_sha256"] = ARCHITECTURE_V2_RAW_SHA256
    with pytest.raises(EvaluatorV2Error, match="literal identity"):
        DependencyLockV2.from_json_bytes(canonical_json_bytes(attacked))

    attacked = copy.deepcopy(final_payload)
    attacked["effective_phase2_v3"] = _slot(None)
    with pytest.raises(EvaluatorV2Error, match="status"):
        DependencyLockV2.from_json_bytes(canonical_json_bytes(attacked))


@pytest.mark.parametrize(
    "attack",
    [
        "pending_version",
        "c5_scored",
        "c5_ref_drift",
        "runtime_lane",
        "extra_key",
        "zero_hash",
        "bool_count",
    ],
)
def test_final_binding_attacks_fail_closed(attack: str) -> None:
    dependency = DependencyLockV2.from_json_bytes(
        canonical_json_bytes(_dependency_payload(final=True))
    )
    payload = _final_payload(dependency)
    if attack == "pending_version":
        payload["model_bindings_in_order"][1]["source_model_version"] = "pending"
    elif attack == "c5_scored":
        payload["scoreable_candidate_ids_in_order"].append(C5_ID)
    elif attack == "c5_ref_drift":
        payload["c5_terminal_binding"]["audit"]["file_id_128"] = "f" * 32
    elif attack == "runtime_lane":
        payload["runtime_bindings_in_order"][0]["lane_id"] = "isolated_c4"
    elif attack == "extra_key":
        payload["attacker"] = True
    elif attack == "zero_hash":
        payload["prediction_artifact"]["artifact"]["raw_sha256"] = "0" * 64
    else:
        payload["truth_access_count"] = False
    with pytest.raises(EvaluatorV2Error):
        FinalPretruthBindingV2.from_json_bytes(
            canonical_json_bytes(payload), dependency_lock=dependency
        )


def test_final_binding_happy_path_and_artifact_universe_are_immutable() -> None:
    dependency, final, _ = _final()
    assert final.raw_sha256 == hashlib.sha256(final.raw).hexdigest()
    assert len(final.source_model_versions) == 5
    assert len(final.artifact_refs()) > 30
    assert dependency.status == DEPENDENCY_FINAL_STATUS


def test_activation_lock_is_structurally_strict_but_cannot_be_trusted() -> None:
    _dependency, final, _payload = _final()
    activation_payload = _activation_payload(final)
    activation = ActivationLockV2.structurally_validate(
        canonical_json_bytes(activation_payload), final_binding=final
    )
    with pytest.raises(ProductionEntryDenied, match="no frozen external activation issuer"):
        activation.require_trusted_external_issuer()

    attacked = copy.deepcopy(activation_payload)
    attacked["consumption_marker_leaf"] = "caller.json"
    with pytest.raises(EvaluatorV2Error):
        ActivationLockV2.structurally_validate(
            canonical_json_bytes(attacked), final_binding=final
        )
    attacked = copy.deepcopy(activation_payload)
    attacked["authority_signature_hex"] = "0" * 128
    with pytest.raises(EvaluatorV2Error):
        ActivationLockV2.structurally_validate(
            canonical_json_bytes(attacked), final_binding=final
        )


def test_c5_terminal_line_is_exact_null_non_scored_and_non_ranked() -> None:
    row = dict(c5_terminal_line())
    validated = validate_c5_terminal_line(row)
    assert tuple(row) == SCORECARD_COLUMNS
    assert validated["deployable"] is False
    assert validated["pit_safe"] is None and validated["causal_safe"] is None
    assert "rank" not in row
    for field in ("mae", "rmse", "seed_wins", "oracle_pair_mae"):
        assert row[field] is None
    for field, value in (("mae", 1.0), ("deployable", True), ("pit_safe", False)):
        attacked = dict(row)
        attacked[field] = value
        with pytest.raises(EvaluatorV2Error, match="terminal"):
            validate_c5_terminal_line(attacked)


class _Trap:
    touched = False

    def __iter__(self) -> Iterator[object]:
        self.touched = True
        raise AssertionError("input was touched")


def test_one_shot_source_only_denies_before_any_input_access_and_keeps_counts_zero() -> None:
    trap = _Trap()
    machine = SourceOnlyOneShotMachine()
    with pytest.raises(ProductionEntryDenied, match="source-only/prebinding"):
        machine.enter_production(
            dependency_lock_raw=trap,
            final_binding_raw=trap,
            activation_lock_raw=trap,
            prediction_rows=trap,
        )
    assert trap.touched is False
    receipt = strict_canonical_json_object(machine.receipt_bytes(), label="source receipt")
    assert receipt["status"] == "SOURCE_ONLY_PREBINDING_DENIED"
    assert receipt["production_activation_enabled"] is False
    assert set(receipt["counts"].values()) == {0}


def _assert_bitwise_equal(left: object, right: object) -> None:
    assert type(left) is type(right)
    if type(left) is float:
        assert struct.pack(">d", left) == struct.pack(">d", right)
    elif type(left) is dict:
        assert tuple(left) == tuple(right)
        for key in left:
            _assert_bitwise_equal(left[key], right[key])
    elif type(left) in {list, tuple}:
        assert len(left) == len(right)
        for l_item, r_item in zip(left, right, strict=True):
            _assert_bitwise_equal(l_item, r_item)
    else:
        assert left == right


def test_metric_core_is_bitwise_equal_to_v1_on_synthetic_public_vectors() -> None:
    vectors = (
        [0.0, 0.1, -0.2, 0.3, -0.4, 1.0e-12],
        [1.0, 1.0, 1.0, 1.0],
        [0.09531017980432493, -0.09531017980432493, 0.0],
    )
    for vector in vectors:
        for q in (0.0, 0.5, 0.95, 0.99, 1.0):
            _assert_bitwise_equal(
                v1_math.type7_quantile(vector, q), metric_core.type7_quantile(vector, q)
            )
        _assert_bitwise_equal(v1_math._summary(vector), metric_core._summary(vector))
        if len(vector) >= 3:
            _assert_bitwise_equal(
                v1_math._summary(vector, (0, 2)),
                metric_core._summary(vector, (0, 2)),
            )
    for candidate, champion in ((0.8, 1.0), (1.25, 2.5)):
        _assert_bitwise_equal(
            v1_math._gain(candidate, champion, label="synthetic"),
            metric_core._gain(candidate, champion, label="synthetic"),
        )
        _assert_bitwise_equal(
            v1_math._relative_deterioration(
                candidate, champion, label="synthetic"
            ),
            metric_core._relative_deterioration(
                candidate, champion, label="synthetic"
            ),
        )
    _assert_bitwise_equal(
        v1_math._population_variance(vectors[0], label="synthetic"),
        metric_core._population_variance(vectors[0], label="synthetic"),
    )
    correlation_pairs = (
        ([1.0], [2.0]),
        ([1.0, 1.0], [2.0, 3.0]),
        ([1.0, 2.0, 4.0], [4.0, 2.0, 1.0]),
    )
    for left, right in correlation_pairs:
        _assert_bitwise_equal(
            v1_math.fixed_order_correlation(left, right),
            metric_core.fixed_order_correlation(left, right),
        )
    candidate_errors = [0.0, 0.1, -0.2, 0.05]
    champion_errors = [0.0, -0.1, -0.15, 0.2]
    candidate_log = [3.0 + value for value in candidate_errors]
    champion_log = [3.0 + value for value in champion_errors]
    candidate_pooled = v1_math._summary(candidate_errors)
    champion_pooled = v1_math._summary(champion_errors)
    _assert_bitwise_equal(
        v1_math._metric_record(
            SCOREABLE_CANDIDATE_IDS[0],
            candidate_pooled,
            champion_pooled,
            dgp_id="A",
            fold_id="fold_012",
        ),
        metric_core._metric_record(
            SCOREABLE_CANDIDATE_IDS[0],
            candidate_pooled,
            champion_pooled,
            dgp_id="A",
            fold_id="fold_012",
        ),
    )
    _assert_bitwise_equal(
        v1_math._complementarity(
            SCOREABLE_CANDIDATE_IDS[0],
            candidate_log,
            champion_log,
            candidate_errors,
            champion_errors,
            candidate_pooled,
            champion_pooled,
        ),
        metric_core._complementarity(
            SCOREABLE_CANDIDATE_IDS[0],
            candidate_log,
            champion_log,
            candidate_errors,
            champion_errors,
            candidate_pooled,
            champion_pooled,
        ),
    )


SOURCE_VERSIONS = tuple((model_id, f"final::{model_id}") for model_id in MODEL_IDS)


def _fold(position: int) -> tuple[str, int, int]:
    fold_number = 12 + (position - 504) // 21
    start = 504 + (fold_number - 12) * 21
    return f"fold_{fold_number:03d}", start - 1, start


def _identities() -> Iterator[tuple[str, str, int, str, str, str, int, int]]:
    for seed_ordinal in range(5):
        for dgp_id in "ABCDEFGHIJ":
            for position in range(504, 1800):
                fold_id, train_end, test_start = _fold(position)
                yield (
                    f"qualification_seed_{seed_ordinal + 1:02d}",
                    dgp_id,
                    position,
                    f"{20_000_000 + position:08d}",
                    "DGP_ISSUER",
                    fold_id,
                    train_end,
                    test_start,
                )


def _prediction_rows(*, attack: str | None = None) -> Iterator[dict[str, object]]:
    for identity_ordinal, identity in enumerate(_identities()):
        for model_ordinal, model_id in enumerate(MODEL_IDS):
            emitted_ordinal: object = model_ordinal
            emitted_model = model_id
            if identity_ordinal == 0 and model_ordinal == 0 and attack == "bool_ordinal":
                emitted_ordinal = False
            if identity_ordinal == 0 and model_ordinal == 0 and attack == "model_order":
                emitted_model = MODEL_IDS[1]
            expected_log = 3.0 + model_ordinal * 0.001
            values: dict[str, object] = {
                **dict(zip(PREDICTION_COLUMNS[:8], identity, strict=True)),
                "pe_model_id": emitted_model,
                "model_ordinal": emitted_ordinal,
                "expected_pe": math.exp(expected_log),
                "expected_log_pe": expected_log,
                "uncertainty": None,
                "confidence": 1.0,
                "regime_state": "synthetic_public",
                "specialist_tags": "synthetic_public",
                "prediction_valid": True,
                "pit_valid": True,
                "source_model_version": SOURCE_VERSIONS[model_ordinal][1],
                "valuation_state_confidence": None,
                "out_of_distribution_score": None,
                "model_disagreement": None,
                "state_uncertainty": None,
                "applied_alpha": None,
                "raw_log_correction": None,
            }
            if identity_ordinal == 0 and model_ordinal == 0:
                if attack == "identity_shift":
                    values["session_position"] = 505
                elif attack == "source_version":
                    values["source_model_version"] = "attacker"
                elif attack == "false_valid":
                    values["prediction_valid"] = False
                elif attack == "nonfinite":
                    values["expected_log_pe"] = float("nan")
                elif attack == "log_mismatch":
                    values["expected_log_pe"] = expected_log + 0.1
            yield {key: values[key] for key in PREDICTION_COLUMNS}


def test_prediction_decoder_consumes_exact_324k_five_row_geometry() -> None:
    semantic = identity_semantic_sha256(_identities())
    contract = PredictionDecodeContract(
        source_model_versions=SOURCE_VERSIONS,
        common_full_identities_semantic_sha256=semantic,
    )
    decoded = decode_prediction_rows(_prediction_rows(), contract=contract)
    assert len(decoded.identities) == IDENTITY_COUNT
    assert decoded.common_identity_semantic_sha256 == semantic
    assert tuple(key for key, _ in decoded.expected_log_pe) == MODEL_IDS
    assert all(len(values) == IDENTITY_COUNT for _, values in decoded.expected_log_pe)


@pytest.mark.parametrize(
    "attack",
    (
        "model_order",
        "bool_ordinal",
        "identity_shift",
        "source_version",
        "false_valid",
        "nonfinite",
        "log_mismatch",
    ),
)
def test_prediction_decoder_rejects_first_block_identity_attacks(attack: str) -> None:
    contract = PredictionDecodeContract(
        source_model_versions=SOURCE_VERSIONS,
        common_full_identities_semantic_sha256="a" * 64,
    )
    with pytest.raises(EvaluatorV2Error):
        decode_prediction_rows(_prediction_rows(attack=attack), contract=contract)


def test_prediction_decoder_rejects_truncation_and_extra_columns_before_truth() -> None:
    contract = PredictionDecodeContract(
        source_model_versions=SOURCE_VERSIONS,
        common_full_identities_semantic_sha256="a" * 64,
    )
    with pytest.raises(EvaluatorV2Error, match="ended before"):
        decode_prediction_rows(iter(()), contract=contract)
    row = next(_prediction_rows())
    row["truth_leak"] = 1
    with pytest.raises(EvaluatorV2Error, match="columns/order"):
        decode_prediction_rows(itertools.chain((row,), _prediction_rows()), contract=contract)


class _FakeLeaf:
    def __init__(self, parent: "_FakeParent", name: str, *, file_id: str) -> None:
        self.parent = parent
        self.name = name
        self.file_id = file_id
        self.open = True

    def receipt(self) -> HeldLeafReceipt:
        raw, file_id, reparse = self.parent.records[self.name]
        return HeldLeafReceipt(
            name=self.name,
            raw_sha256=hashlib.sha256(raw).hexdigest(),
            size_bytes=len(raw),
            volume_serial_number=7,
            file_id_128=file_id,
            reparse=reparse,
            write_share_allowed=False,
            delete_share_allowed=False,
            handle_still_open=self.open,
        )

    def raw_bytes(self) -> bytes:
        return self.parent.records[self.name][0]

    def close(self) -> None:
        self.open = False


class _FakeParent:
    def __init__(self) -> None:
        self.records: dict[str, tuple[bytes, str, bool]] = {}
        self.counter = 0
        self.flush_count = 0
        self.swap_on_reopen = False

    def inventory(self) -> tuple[HeldLeafReceipt, ...]:
        return tuple(
            HeldLeafReceipt(
                name=name,
                raw_sha256=hashlib.sha256(raw).hexdigest(),
                size_bytes=len(raw),
                volume_serial_number=7,
                file_id_128=file_id,
                reparse=reparse,
                write_share_allowed=False,
                delete_share_allowed=False,
                handle_still_open=True,
            )
            for name, (raw, file_id, reparse) in sorted(
                self.records.items(), key=lambda item: (item[0].casefold(), item[0])
            )
        )

    def create_new_held(self, name: str, raw: bytes) -> _FakeLeaf:
        if name in self.records:
            raise FileExistsError(name)
        self.counter += 1
        file_id = f"{self.counter:032x}"
        self.records[name] = (raw, file_id, False)
        return _FakeLeaf(self, name, file_id=file_id)

    def rename_no_replace(self, leaf: _FakeLeaf, final_name: str) -> None:
        if final_name in self.records:
            raise FileExistsError(final_name)
        self.records[final_name] = self.records.pop(leaf.name)
        leaf.name = final_name

    def flush(self) -> None:
        self.flush_count += 1

    def reopen_held(self, name: str) -> _FakeLeaf:
        raw, file_id, reparse = self.records[name]
        if self.swap_on_reopen:
            file_id = "f" * 32
            self.records[name] = (raw, file_id, reparse)
        return _FakeLeaf(self, name, file_id=file_id)


def test_held_parent_create_new_marker_and_publication_choreography() -> None:
    parent = _FakeParent()
    raw = canonical_json_bytes({"schema_version": "synthetic", "status": "CONSUMED"})
    marker = create_consumption_marker(parent=parent, canonical_marker_raw=raw)
    try:
        marker.assert_live()
        assert marker.receipt.name == CONSUMPTION_MARKER_LEAF
        assert parent.flush_count == 2
        assert set(parent.records) == {CONSUMPTION_MARKER_LEAF}
    finally:
        marker.close()
    with pytest.raises(EvaluatorV2Error, match="consumed"):
        create_consumption_marker(parent=parent, canonical_marker_raw=raw)


def test_held_parent_publication_rejects_reopen_fileid_swap() -> None:
    parent = _FakeParent()
    parent.swap_on_reopen = True
    with pytest.raises(EvaluatorV2Error, match="reopen"):
        publish_create_new(
            parent=parent,
            staging_leaf=".RESULT.json.next",
            final_leaf="RESULT.json",
            raw=b"x",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("size_bytes", 1.0),
        ("volume_serial_number", True),
        ("file_id_128", "A" * 32),
        ("write_share_allowed", 0),
    ),
)
def test_held_parent_inventory_rejects_nonexact_receipt_types(
    field: str, value: object
) -> None:
    class _MalformedInventoryParent(_FakeParent):
        def inventory(self) -> tuple[HeldLeafReceipt, ...]:
            good = super().inventory()
            return (replace(good[0], **{field: value}),)

    parent = _MalformedInventoryParent()
    parent.records["existing.json"] = (b"x", "1" * 32, False)
    with pytest.raises(EvaluatorV2Error, match="inventory receipt fields"):
        publish_create_new(
            parent=parent,
            staging_leaf=".RESULT.json.next",
            final_leaf="RESULT.json",
            raw=b"x",
        )


def test_held_writer_rejects_float_size_receipt() -> None:
    class _MalformedLeaf(_FakeLeaf):
        def receipt(self) -> HeldLeafReceipt:
            return replace(super().receipt(), size_bytes=1.0)  # type: ignore[arg-type]

    class _MalformedWriterParent(_FakeParent):
        def create_new_held(self, name: str, raw: bytes) -> _FakeLeaf:
            leaf = super().create_new_held(name, raw)
            return _MalformedLeaf(self, leaf.name, file_id=leaf.file_id)

    with pytest.raises(EvaluatorV2Error, match="held leaf receipt"):
        publish_create_new(
            parent=_MalformedWriterParent(),
            staging_leaf=".RESULT.json.next",
            final_leaf="RESULT.json",
            raw=b"x",
        )


def test_native_held_artifact_ref_rejects_identity_drift(tmp_path: Path) -> None:
    path = tmp_path / "public.json"
    path.write_bytes(b"public-only\n")
    ref = _snapshot_artifact_ref_untrusted(
        project_root=tmp_path, relative_path="public.json"
    )
    with HeldArtifact(project_root=tmp_path, ref=ref) as held:
        assert held.raw_bytes() == b"public-only\n"
        assert held.receipt()["reparse_ancestor_count"] == 0
        with pytest.raises(OSError):
            path.write_bytes(b"mutation\n")
    with pytest.raises(EvaluatorV2Error, match="identity/bytes"):
        HeldArtifact(project_root=tmp_path, ref=replace(ref, file_id_128="f" * 32)).__enter__()


def test_new_namespace_has_no_truth_scorer_or_authority_export() -> None:
    import research.model_zoo.pe_five_candidate_fresh_qualification_evaluator_v2 as package

    forbidden_exports = {
        "evaluate_qualification",
        "issue_authority",
        "open_truth",
        "publish_failure",
        "publish_result",
        "score_qualification",
    }
    assert forbidden_exports.isdisjoint(package.__all__)


def test_source_only_entry_has_no_input_or_filesystem_call_path() -> None:
    package_root = (
        ROOT
        / "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2"
    )
    for source in sorted(package_root.glob("*.py")):
        ast.parse(source.read_text(encoding="utf-8"), filename=str(source))

    one_shot_source = package_root / "one_shot.py"
    tree = ast.parse(one_shot_source.read_text(encoding="utf-8"))
    entry = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "enter_production"
    )
    forbidden_calls = {"open", "iter", "read_bytes", "read_text", "resolve"}
    observed_calls = {
        node.func.id
        for node in ast.walk(entry)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    observed_calls.update(
        node.func.attr
        for node in ast.walk(entry)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    )
    assert observed_calls.isdisjoint(forbidden_calls)
