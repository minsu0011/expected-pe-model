"""Source-only adversarial tests for the frozen R6 generation design."""

from __future__ import annotations

import ast
import copy
import hashlib
from pathlib import Path

import pytest

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6_qualification_generation.contracts import (
    DGPS,
    FULL_IDENTITY_COUNT,
    HELDOUT_SEEDS,
    PUBLIC_TASK_FILE_UNIVERSE,
    QUALIFICATION_SEEDS,
    REGISTRY_AFTER,
    ROWS_PER_TASK,
    TASK_COUNT,
    TRUTH_COLUMNS,
    TRUTH_HEADER_SHA256,
    R6QualificationGenerationError,
    canonical_json_bytes,
    require_marker_transition,
    require_registry_state,
    require_stage_authority,
    sealed,
    sha256_bytes,
    validate_vault_metadata_receipt,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6_qualification_generation.preflight import (
    build_source_tcb_closure,
    verify_control_chain,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6_qualification_generation.protected_lane import (
    validate_dedicated_process_request,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6_qualification_generation.public_lane import (
    PublicLaneError,
    validate_task_request,
    validate_two_pass_parity,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TOKEN = "a" * 64
TOKEN_SHA256 = hashlib.sha256(TOKEN.encode("ascii")).hexdigest()
DESIGN_SHA256 = "b" * 64


def _request() -> dict[str, object]:
    return {
        "activation_token": TOKEN,
        "design_checksums_raw_sha256": DESIGN_SHA256,
        "dgp": "A",
        "marker_state": "CLAIMED_EXCLUSIVE",
        "public_run_id": "20260821T120000",
        "replay_pass": 1,
        "schema_version": (
            "expected_pe.observable_state_bce_dgp_tournament.v2.r6."
            "qualification_public_request.v1"
        ),
        "seed": QUALIFICATION_SEEDS[0],
        "stage": "QUALIFICATION",
        "task_relative": f"replays/pass_1/seed_{QUALIFICATION_SEEDS[0]}/dgp_A",
    }


def _validate(request: dict[str, object]) -> None:
    validate_task_request(
        request,
        design_checksums_raw_sha256=DESIGN_SHA256,
        activation_token_sha256=TOKEN_SHA256,
    )


def _parity_rows() -> list[dict[str, object]]:
    digest = "c" * 64
    return [
        {
            "seed": seed,
            "dgp": dgp,
            "artifact_raw_sha256": {
                name: digest for name in PUBLIC_TASK_FILE_UNIVERSE
            },
            "identity_sha256": digest,
        }
        for seed in QUALIFICATION_SEEDS
        for dgp in DGPS
    ]


def test_exact_qualification_geometry_and_truth_schema() -> None:
    assert QUALIFICATION_SEEDS == (7573, 7577, 7583, 7589, 7591)
    assert HELDOUT_SEEDS == (7603, 7607, 7621, 7639, 7643)
    assert DGPS == tuple("ABCDEFGHIJ")
    assert TASK_COUNT == 50
    assert ROWS_PER_TASK == 1_800
    assert FULL_IDENTITY_COUNT == 90_000
    assert len(TRUTH_COLUMNS) == 7
    assert sha256_bytes((",".join(TRUTH_COLUMNS) + "\n").encode("ascii")) == (
        TRUTH_HEADER_SHA256
    )


def test_exact_sealed_control_chain_is_read_only() -> None:
    closure = verify_control_chain()
    assert closure["snapshot"]["post_reservation_custody"]["file_count"] == 7
    assert closure["snapshot"]["runtime"]["file_count"] == 1


def test_source_tcb_binds_actual_generator_and_public_isolation() -> None:
    closure = build_source_tcb_closure()
    contract = closure["actual_generator_contract"]
    assert contract["dgp_ids"] == list(DGPS)
    assert contract["truth_columns"] == list(TRUTH_COLUMNS)
    assert closure["generator_invocation_count"] == 0
    public_source = PROJECT_ROOT / (
        "research/model_zoo/observable_state_bce_dgp_tournament_v2_r6_"
        "qualification_generation/public_lane.py"
    )
    tree = ast.parse(public_source.read_text(encoding="utf-8"))
    imports = [
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    ]
    assert all("protected_lane" not in (name or "") for name in imports)
    lowered = public_source.read_text(encoding="utf-8").casefold()
    assert all(token not in lowered for token in ("heldout", "latent", "protected", "truth", "vault"))


def test_valid_public_request_passes() -> None:
    _validate(_request())


def test_wrong_stage_fails_closed() -> None:
    request = _request()
    request["stage"] = "HELDOUT"
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_wrong_seed_fails_closed() -> None:
    request = _request()
    request["seed"] = HELDOUT_SEEDS[0]
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_wrong_dgp_fails_closed() -> None:
    request = _request()
    request["dgp"] = "K"
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_wrong_schema_fails_closed() -> None:
    request = _request()
    request["unexpected"] = False
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_wrong_public_task_path_fails_closed() -> None:
    request = _request()
    request["task_relative"] = "replays/pass_1/seed_7573/dgp_B"
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_wrong_design_hash_fails_closed() -> None:
    request = _request()
    request["design_checksums_raw_sha256"] = "d" * 64
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_wrong_activation_token_fails_closed() -> None:
    request = _request()
    request["activation_token"] = "e" * 64
    with pytest.raises(PublicLaneError):
        _validate(request)


def test_dedicated_process_and_metadata_receipt_are_location_free() -> None:
    request = {
        "activation_token": TOKEN,
        "dgp_ids": list(DGPS),
        "opaque_destination_capability": "f" * 64,
        "schema_version": (
            "expected_pe.observable_state_bce_dgp_tournament.v2.r6."
            "qualification_dedicated_process_request.v1"
        ),
        "seed_ids": list(QUALIFICATION_SEEDS),
        "stage": "QUALIFICATION",
    }
    validate_dedicated_process_request(
        request,
        expected_activation_token_sha256=TOKEN_SHA256,
    )
    receipt = sealed(
        {
            "artifact_count": 100,
            "aggregate_raw_sha256": "1" * 64,
            "dgp_ids_sha256": sha256_bytes(canonical_json_bytes(list(DGPS))),
            "generator_invocations": 50,
            "schema_version": (
                "expected_pe.observable_state_bce_dgp_tournament.v2.r6."
                "qualification_vault_metadata_receipt.v1"
            ),
            "seed_ids_sha256": sha256_bytes(
                canonical_json_bytes(list(QUALIFICATION_SEEDS))
            ),
            "stage": "QUALIFICATION",
            "status": "PASS_OPAQUE_METADATA_ONLY_SEPARATE_PROCESS",
            "task_count": 50,
            "truth_header_sha256": TRUTH_HEADER_SHA256,
        }
    )
    validate_vault_metadata_receipt(receipt)
    contaminated = dict(receipt)
    contaminated["artifact_path"] = "forbidden"
    with pytest.raises(R6QualificationGenerationError):
        validate_vault_metadata_receipt(contaminated)


def test_public_replay_parity_mismatch_fails_closed() -> None:
    first = _parity_rows()
    second = copy.deepcopy(first)
    assert len(validate_two_pass_parity(first, second)) == 64
    second[0]["artifact_raw_sha256"]["canonical150.csv"] = "2" * 64  # type: ignore[index]
    with pytest.raises(PublicLaneError):
        validate_two_pass_parity(first, second)


def test_premature_heldout_activation_fails_closed() -> None:
    with pytest.raises(R6QualificationGenerationError):
        require_stage_authority(
            stage="HELDOUT",
            qualification_authorized=False,
            heldout_authorized=False,
            selection_lock_sha256=None,
        )


def test_registry_drift_fails_closed() -> None:
    require_registry_state(REGISTRY_AFTER)
    drifted = dict(REGISTRY_AFTER)
    drifted["entry_count"] = 11
    with pytest.raises(R6QualificationGenerationError):
        require_registry_state(drifted)


def test_one_shot_marker_reuse_and_skip_fail_closed() -> None:
    require_marker_transition(prior="ABSENT", requested="CLAIMED_EXCLUSIVE")
    require_marker_transition(prior="CLAIMED_EXCLUSIVE", requested="COMPLETED")
    for prior, requested in (
        ("ABSENT", "COMPLETED"),
        ("COMPLETED", "CLAIMED_EXCLUSIVE"),
        ("CLAIMED_EXCLUSIVE", "CLAIMED_EXCLUSIVE"),
    ):
        with pytest.raises(R6QualificationGenerationError):
            require_marker_transition(prior=prior, requested=requested)
