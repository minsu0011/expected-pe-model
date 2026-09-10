from __future__ import annotations

import json
from pathlib import Path

import pytest

from pe_regime_v04.model_lab.probabilistic.contracts import ProbabilisticContractError
from pe_regime_v04.model_lab.probabilistic.formal_pins import (
    load_formal_launch_authority,
)
from pe_regime_v04.model_lab.probabilistic.two_survivor_continuation import (
    BROKEN_CANDIDATE_ID,
    COMPARATOR_IDS,
    REFERENCE_IDS,
    SURVIVOR_CUSTODY,
    SURVIVOR_IDS,
    V2_ROOTS,
    build_continuation_activation_payload,
    load_verified_terminal_custody,
    require_two_survivor_authority,
    validate_bundle_shape,
    verify_file_against_record,
)


ROOT = Path(__file__).resolve().parents[2]


def _bundle_shape() -> dict[str, object]:
    record = {"path": "placeholder.aaaaaaaa.json", "raw_sha256": "a" * 64}
    return {
        "candidates": {model_id: {} for model_id in SURVIVOR_IDS},
        "references": {reference_id: {} for reference_id in REFERENCE_IDS},
        "comparators": {comparator_id: {} for comparator_id in COMPARATOR_IDS},
        "candidate_runtimes": {model_id: {} for model_id in SURVIVOR_IDS},
        "global_runtime": record,
    }


def test_exact_terminal_two_survivor_custody_loads_without_refit() -> None:
    custody = load_verified_terminal_custody(ROOT)
    assert custody.repo_root == ROOT.resolve()
    assert tuple(SURVIVOR_CUSTODY) == SURVIVOR_IDS
    assert BROKEN_CANDIDATE_ID not in SURVIVOR_CUSTODY
    assert not (ROOT / "outputs/p5s/c/2").exists()


def test_continuation_activation_is_inactive_score_free_and_exact_two() -> None:
    payload = build_continuation_activation_payload(
        source_snapshot_path=f"outputs/p5s/v3/a/source.{'a' * 64}.json",
        source_snapshot_raw_sha256="a" * 64,
    )
    assert payload["formal"] is False
    assert payload["heavy_compute_authorized"] is False
    assert payload["reference_generation_authorized"] is False
    assert payload["truth_open_authorized"] is False
    assert payload["score_computation_authorized"] is False
    assert payload["candidate_refit_or_retry_authorized"] is False
    assert payload["workflow_policy"]["survivor_ids"] == list(SURVIVOR_IDS)
    assert payload["workflow_policy"]["excluded_candidate"]["model_id"] == (
        BROKEN_CANDIDATE_ID
    )


@pytest.mark.parametrize("model_id", SURVIVOR_IDS)
def test_any_survivor_prediction_mutation_is_rejected(
    model_id: str, tmp_path: Path
) -> None:
    record = SURVIVOR_CUSTODY[model_id]["prediction"]
    original = (ROOT / record["path"]).read_bytes()
    changed = tmp_path / "mutated.csv"
    changed.write_bytes(original + b"\n")
    with pytest.raises(ProbabilisticContractError, match="raw bytes changed"):
        verify_file_against_record(changed, record, context=f"{model_id}.prediction")


def test_bundle_shape_requires_exact_two_of_every_participant_and_global_runtime() -> None:
    payload = _bundle_shape()
    validate_bundle_shape(payload)

    missing_candidate = _bundle_shape()
    del missing_candidate["candidates"][SURVIVOR_IDS[1]]  # type: ignore[index]
    with pytest.raises(ProbabilisticContractError, match="exactly 2"):
        validate_bundle_shape(missing_candidate)

    ngboost_included = _bundle_shape()
    ngboost_included["candidates"][BROKEN_CANDIDATE_ID] = {}  # type: ignore[index]
    with pytest.raises(ProbabilisticContractError, match="exactly 2|NGBoost"):
        validate_bundle_shape(ngboost_included)

    missing_reference = _bundle_shape()
    del missing_reference["references"][REFERENCE_IDS[0]]  # type: ignore[index]
    with pytest.raises(ProbabilisticContractError, match="exactly 2"):
        validate_bundle_shape(missing_reference)

    missing_comparator = _bundle_shape()
    del missing_comparator["comparators"][COMPARATOR_IDS[0]]  # type: ignore[index]
    with pytest.raises(ProbabilisticContractError, match="exactly 2"):
        validate_bundle_shape(missing_comparator)

    missing_runtime = _bundle_shape()
    del missing_runtime["candidate_runtimes"][SURVIVOR_IDS[0]]  # type: ignore[index]
    with pytest.raises(ProbabilisticContractError, match="exactly 2"):
        validate_bundle_shape(missing_runtime)

    no_global_runtime = _bundle_shape()
    del no_global_runtime["global_runtime"]
    with pytest.raises(ProbabilisticContractError, match="global runtime"):
        validate_bundle_shape(no_global_runtime)


def test_isolated_continuation_rejects_old_or_lookalike_authority() -> None:
    with pytest.raises(ProbabilisticContractError, match="old or generic"):
        require_two_survivor_authority(object())


def test_consumed_v2_request_and_go_are_centrally_revoked() -> None:
    with pytest.raises(ProbabilisticContractError, match="terminally revoked"):
        load_formal_launch_authority(
            execution_request_path=ROOT / V2_ROOTS["external_request"]["path"],
            expected_execution_request_sha256=V2_ROOTS["external_request"]["raw_sha256"],
            independent_go_path=ROOT / V2_ROOTS["v2_independent_go"]["path"],
            expected_independent_go_sha256=V2_ROOTS["v2_independent_go"]["raw_sha256"],
            repo_root=ROOT,
        )


def test_terminal_roots_are_the_independent_failure_seals() -> None:
    failure = json.loads((ROOT / V2_ROOTS["terminal_failure_receipt"]["path"]).read_bytes())
    audit = json.loads((ROOT / V2_ROOTS["terminal_failure_audit"]["path"]).read_bytes())
    assert failure["manifest_sha256"] == V2_ROOTS["terminal_failure_receipt"][
        "logical_sha256"
    ]
    assert audit["manifest_sha256"] == V2_ROOTS["terminal_failure_audit"][
        "logical_sha256"
    ]
    assert audit["decision"]["evaluation_or_gate_authorized"] is False

