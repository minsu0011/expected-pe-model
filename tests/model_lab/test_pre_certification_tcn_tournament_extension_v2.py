from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from research.model_zoo.pre_certification_research_tournament_v1.contracts import (
    BCE_B_ID,
    BCE_D_ID,
    CHAMPION_ID,
    COMMON_IDENTITIES,
    DGP_IDS,
    FIXED_040_ID,
    RESEARCH_EVIDENCE_CLASS,
    SCORE_END,
    SCORE_ROWS_PER_TASK,
    SCORE_START,
    SEED_ALIASES,
    SEEDS,
    TASK_COUNT,
    fold_id_for_position,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.comparators import (
    assert_exact_normalized_join,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.contracts import (
    DESIGN_STATUS,
    EXECUTION_PROFILE_SELECTION_PLACEHOLDER,
    EXTENDED_CANDIDATE_IDS,
    EXTENDED_MODEL_COLUMNS,
    EXTENDED_MODEL_IDS,
    HOFS_R3_MODEL_ID,
    REQUIRED_CONCRETE_TCN_HASH_FIELDS,
    SELECTED_EXECUTION_PROFILE_ID,
    SHARDED_EXECUTION_PROFILE_ID,
    SINGLE_EXECUTION_PROFILE_ID,
    TCN_INPUT_ROOT,
    TCN_MODEL_ID,
    TCN_RAW_PREDICTION_COLUMNS,
    TCN_SOURCE_MODEL_VERSION,
    TCNTournamentExtensionError,
    UNBOUND_SHA256,
    design_lock_payload,
    require_frozen_execution_profile,
    require_concrete_tcn_hash_binding,
    semantic_sha256,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.prediction_validation import (
    _verify_checksum_ledger,
    normalize_tcn_predictions,
    validate_binding_round_trip,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.path_guards import (
    assert_regular_descendant,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.profile_evidence import (
    verify_frozen_sharded_profile,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.scoring import (
    compute_full_metrics,
)
from research.model_zoo.pre_certification_tcn_tournament_extension_v2.shard_invariants import (
    EXPECTED_SHARD_ASSIGNMENT,
    EXPECTED_SHARD_IDS,
    EXPECTED_SHARD_PREDICTION_ROWS,
    derive_shard_prediction_rows,
    exact_fold_test_row_count,
    require_exact_shard_prediction_rows,
    validate_three_way_partition,
)


def _identity_arrays() -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    seeds = np.repeat(
        np.asarray(SEEDS, dtype=np.int64),
        len(DGP_IDS) * SCORE_ROWS_PER_TASK,
    )
    aliases = np.repeat(
        np.asarray(SEED_ALIASES, dtype=object),
        len(DGP_IDS) * SCORE_ROWS_PER_TASK,
    )
    dgps = np.tile(
        np.repeat(np.asarray(DGP_IDS, dtype=object), SCORE_ROWS_PER_TASK),
        len(SEEDS),
    )
    positions = np.tile(np.arange(SCORE_START, SCORE_END, dtype=np.int64), TASK_COUNT)
    return seeds, aliases, dgps, positions


def _synthetic_tcn() -> pd.DataFrame:
    seeds, aliases, dgps, positions = _identity_arrays()
    dates = np.tile(
        pd.bdate_range("2015-01-02", periods=SCORE_ROWS_PER_TASK).strftime(
            "%Y-%m-%dT00:00:00Z"
        ),
        TASK_COUNT,
    )
    test_start = SCORE_START + ((positions - SCORE_START) // 21) * 21
    train_end = test_start - 133
    expected_log = 3.0 + 0.01 * np.sin(np.arange(COMMON_IDENTITIES) / 97.0)
    return pd.DataFrame(
        {
            "seed": seeds,
            "seed_alias": aliases,
            "dgp_id": dgps,
            "date": dates,
            "ticker": "DGP_ISSUER",
            "session_position": positions,
            "fold_id": [fold_id_for_position(int(value)) for value in positions],
            "train_end_position": train_end,
            "test_start_position": test_start,
            "pe_model_id": TCN_MODEL_ID,
            "expected_pe": np.exp(expected_log),
            "expected_log_pe": expected_log,
            "uncertainty": 0.02,
            "confidence": 0.8,
            "regime_state": "SIDEWAYS",
            "specialist_tags": "causal_sequence|research_only|spent_r4",
            "prediction_valid": True,
            "pit_valid": True,
            "source_model_version": TCN_SOURCE_MODEL_VERSION,
            "fallback_used": False,
            "fallback_reason": "NONE",
            "fit_max_source_position": train_end,
            "proxy_target_max_source_position": train_end - 1,
        },
        columns=TCN_RAW_PREDICTION_COLUMNS,
    )


def _joined_metric_fixture() -> pd.DataFrame:
    _, aliases, dgps, positions = _identity_arrays()
    phase = np.arange(COMMON_IDENTITIES, dtype=np.float64)
    truth = 3.0 + 0.03 * np.sin(phase / 137.0)
    champion_error = 0.06 + 0.015 * np.sin(phase / 31.0)
    candidate_scales = {
        BCE_B_ID: 0.90,
        BCE_D_ID: 0.85,
        FIXED_040_ID: 0.95,
        HOFS_R3_MODEL_ID: 0.70,
        TCN_MODEL_ID: 0.80,
    }
    frame = pd.DataFrame(
        {
            "seed_alias": aliases,
            "dgp_id": dgps,
            "session_position": positions,
            "fold_id": [fold_id_for_position(int(value)) for value in positions],
            "true_log_fair_pe": truth,
        }
    )
    frame[EXTENDED_MODEL_COLUMNS[CHAMPION_ID]] = np.exp(truth + champion_error)
    for model_id, scale in candidate_scales.items():
        frame[EXTENDED_MODEL_COLUMNS[model_id]] = np.exp(truth + champion_error * scale)
    return frame


def _synthetic_shard_partition() -> tuple[
    list[dict[str, object]],
    dict[str, list[tuple[int, str, int]]],
    dict[str, tuple[str, ...]],
]:
    assignment: dict[str, tuple[str, ...]] = {
        shard_id: tuple(
            f"fold_{number:03d}"
            for number in range(12, 74)
            if (number - 12) % 3 == index
        )
        for index, shard_id in enumerate(EXPECTED_SHARD_IDS)
    }
    owner = {
        fold_id: shard_id
        for shard_id, fold_ids in assignment.items()
        for fold_id in fold_ids
    }
    identities: dict[str, list[tuple[int, str, int]]] = {
        shard_id: [] for shard_id in EXPECTED_SHARD_IDS
    }
    for seed in SEEDS:
        for dgp_id in DGP_IDS:
            for position in range(SCORE_START, SCORE_END):
                identities[owner[fold_id_for_position(position)]].append(
                    (seed, dgp_id, position)
                )
    receipts = [
        {
            "shard_id": shard_id,
            "assigned_fold_ids": list(assignment[shard_id]),
            "prediction_rows": len(identities[shard_id]),
        }
        for shard_id in EXPECTED_SHARD_IDS
    ]
    return receipts, identities, assignment


def test_design_is_closed_and_reserves_exact_future_root() -> None:
    design = design_lock_payload()
    assert design["status"] == DESIGN_STATUS
    assert design["future_tcn_input"]["reserved_exact_root"] == TCN_INPUT_ROOT
    assert design["future_tcn_input"]["prediction_rows"] == COMMON_IDENTITIES
    assert SELECTED_EXECUTION_PROFILE_ID == SHARDED_EXECUTION_PROFILE_ID
    assert design["future_tcn_input"]["selected_execution_profile_id"] == (
        SHARDED_EXECUTION_PROFILE_ID
    )
    assert design["predecessor_rejection"]["false_uniform_overstatement_rows"] == 300
    assert design["shard_row_geometry"]["pinned_prediction_rows"] == {
        "shard_00": 21_750,
        "shard_01": 22_050,
        "shard_02": 21_000,
    }
    assert design["authority"]["spent_truth_now"] is False
    assert design["authority"]["scoring_now"] is False
    assert design["authority"]["fresh"] is False
    assert design["authority"]["heldout"] is False
    assert design["authority"]["latent"] is False
    assert design["frozen_comparators"]["hofs_r3"]["selected_model_id"] == (
        HOFS_R3_MODEL_ID
    )


def test_unbound_or_malformed_hashes_fail_closed() -> None:
    placeholders = {
        field: UNBOUND_SHA256 for field in REQUIRED_CONCRETE_TCN_HASH_FIELDS
    }
    with pytest.raises(TCNTournamentExtensionError, match="unbound or malformed"):
        require_concrete_tcn_hash_binding(placeholders)
    concrete = {field: "a" * 64 for field in REQUIRED_CONCRETE_TCN_HASH_FIELDS}
    require_concrete_tcn_hash_binding(concrete)
    concrete[REQUIRED_CONCRETE_TCN_HASH_FIELDS[-1]] = "A" * 64
    with pytest.raises(TCNTournamentExtensionError, match="unbound or malformed"):
        require_concrete_tcn_hash_binding(concrete)
    with pytest.raises(TCNTournamentExtensionError, match="profile selection is unbound"):
        require_frozen_execution_profile(EXECUTION_PROFILE_SELECTION_PLACEHOLDER)
    rejected_v1 = "tcn_batch64_three_way_fold_shards_research_" + "v1"
    with pytest.raises(TCNTournamentExtensionError, match="not an exact allowed profile"):
        require_frozen_execution_profile(rejected_v1)
    require_frozen_execution_profile(SHARDED_EXECUTION_PROFILE_ID)
    with pytest.raises(TCNTournamentExtensionError, match="not an exact allowed profile"):
        require_frozen_execution_profile(SINGLE_EXECUTION_PROFILE_ID)


def test_hash_profile_placeholder_or_mixed_binding_is_rejected() -> None:
    base = {
        "schema_version": "expected_pe.tcn_tournament_input_binding.v2",
        "status": "PASS_CONCRETE_TCN_INPUT_HASH_BINDING_TRUTH_FREE",
        "input_root": TCN_INPUT_ROOT,
        "selected_execution_profile_id": EXECUTION_PROFILE_SELECTION_PLACEHOLDER,
        "truth_fresh_heldout_latent_payload_files_opened": 0,
        **{field: "b" * 64 for field in REQUIRED_CONCRETE_TCN_HASH_FIELDS},
    }
    base["binding_semantic_sha256"] = semantic_sha256(base)
    with pytest.raises(TCNTournamentExtensionError, match="profile selection is unbound"):
        validate_binding_round_trip(base)
    base["selected_execution_profile_id"] = SINGLE_EXECUTION_PROFILE_ID
    base["binding_semantic_sha256"] = semantic_sha256(
        {key: value for key, value in base.items() if key != "binding_semantic_sha256"}
    )
    with pytest.raises(TCNTournamentExtensionError, match="not an exact allowed profile"):
        validate_binding_round_trip(base)


def test_sealed_sharded_v2_prepare_only_metadata_binding() -> None:
    project = Path(__file__).resolve().parents[2]
    receipt = verify_frozen_sharded_profile(project)
    assert receipt["status"] == "PASS_EXACT_SHARDED_V2_PREPARE_ONLY_PROFILE_BINDING"
    assert receipt["prediction_payload_files_opened"] == 0
    assert receipt["truth_payload_files_opened"] == 0
    assert receipt["full_run_allowed"] is False


def test_tcn_raw_schema_normalizes_exact_64800_common_rows() -> None:
    normalized = normalize_tcn_predictions(_synthetic_tcn())
    assert len(normalized) == COMMON_IDENTITIES
    assert set(normalized["pe_model_id"]) == {TCN_MODEL_ID}
    assert set(normalized["evidence_class"]) == {RESEARCH_EVIDENCE_CLASS}
    assert normalized["date"].str.fullmatch(r"\d{4}-\d{2}-\d{2}").all()
    assert np.allclose(
        np.log(normalized["expected_pe"].to_numpy()),
        normalized["expected_log_pe"].to_numpy(),
    )


def test_tcn_normalizer_rejects_identity_and_provenance_drift() -> None:
    identity_drift = _synthetic_tcn()
    identity_drift.loc[0, "seed_alias"] = "research_seed_99"
    with pytest.raises(TCNTournamentExtensionError, match="ordered seed/DGP/position"):
        normalize_tcn_predictions(identity_drift)
    provenance_drift = _synthetic_tcn()
    provenance_drift.loc[0, "proxy_target_max_source_position"] = int(
        provenance_drift.loc[0, "test_start_position"]
    )
    with pytest.raises(TCNTournamentExtensionError, match="provenance"):
        normalize_tcn_predictions(provenance_drift)
    fallback_drift = _synthetic_tcn()
    fallback_drift.loc[0, "fallback_used"] = True
    fallback_drift.loc[0, "fallback_reason"] = "INSUFFICIENT_GLOBAL_PREFIX_LT_756"
    with pytest.raises(TCNTournamentExtensionError, match="fallback"):
        normalize_tcn_predictions(fallback_drift)


def test_exact_six_field_join_has_no_model_specific_mask() -> None:
    normalized = normalize_tcn_predictions(_synthetic_tcn())
    reference = normalized.copy()
    reference["pe_model_id"] = CHAMPION_ID
    assert_exact_normalized_join(reference, normalized, challenger_label=TCN_MODEL_ID)
    drift = normalized.copy()
    drift.loc[0, "date"] = "1999-01-01"
    with pytest.raises(TCNTournamentExtensionError, match="six-field identity join"):
        assert_exact_normalized_join(reference, drift, challenger_label=TCN_MODEL_ID)


def test_original_candidate_and_ancestor_reparse_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import research.model_zoo.pre_certification_tcn_tournament_extension_v2.path_guards as guards

    ancestor = tmp_path / "ancestor"
    ancestor.mkdir()
    candidate = ancestor / "payload.bin"
    candidate.write_bytes(b"payload")
    monkeypatch.setattr(
        guards,
        "_is_reparse_point",
        lambda path: path in {ancestor},
    )
    with pytest.raises(TCNTournamentExtensionError, match="reparse point"):
        assert_regular_descendant(candidate, tmp_path, kind="synthetic ancestor")
    monkeypatch.setattr(
        guards,
        "_is_reparse_point",
        lambda path: path in {candidate},
    )
    with pytest.raises(TCNTournamentExtensionError, match="reparse point"):
        assert_regular_descendant(candidate, tmp_path, kind="synthetic candidate")


def test_single_root_ledger_rejects_extra_unknown_and_missing_members(tmp_path: Path) -> None:
    from research.model_zoo.pre_certification_tcn_tournament_extension_v2.contracts import (
        TCN_REQUIRED_ROOT_FILES,
    )

    def write_ledger() -> None:
        members = sorted(path for path in tmp_path.rglob("*") if path.is_file())
        rows = [
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(tmp_path).as_posix()}"
            for path in members
            if path.name != "CHECKSUMS.sha256"
        ]
        (tmp_path / "CHECKSUMS.sha256").write_text(
            "\n".join(rows) + "\n", encoding="ascii", newline="\n"
        )

    for relative in set(TCN_REQUIRED_ROOT_FILES) - {"CHECKSUMS.sha256"}:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode("ascii"))
    write_ledger()
    _verify_checksum_ledger(tmp_path)
    unknown = tmp_path / "UNKNOWN.bin"
    unknown.write_bytes(b"unknown")
    write_ledger()
    with pytest.raises(TCNTournamentExtensionError, match="missing, extra, or unknown"):
        _verify_checksum_ledger(tmp_path)
    unknown.unlink()
    missing = tmp_path / "SHARDED_RUN_RECEIPT.json"
    missing.unlink()
    write_ledger()
    with pytest.raises(TCNTournamentExtensionError, match="missing, extra, or unknown"):
        _verify_checksum_ledger(tmp_path)


def test_three_shard_partition_accepts_exact_disjoint_complete_surface() -> None:
    receipts, identities, assignment = _synthetic_shard_partition()
    result = validate_three_way_partition(
        receipts,
        identities,
        expected_assignment=assignment,
    )
    assert result["identity_rows"] == COMMON_IDENTITIES
    assert result["fold_count"] == 62
    assert result["identity_overlap"] == 0
    assert result["identity_gaps"] == 0


def test_boundary_fold_and_exact_pinned_shard_row_geometry() -> None:
    assert exact_fold_test_row_count("fold_012") == 21
    assert exact_fold_test_row_count("fold_072") == 21
    assert exact_fold_test_row_count("fold_073") == 15
    assert derive_shard_prediction_rows(EXPECTED_SHARD_ASSIGNMENT) == {
        "shard_00": 21_750,
        "shard_01": 22_050,
        "shard_02": 21_000,
    }
    assert EXPECTED_SHARD_PREDICTION_ROWS == {
        "shard_00": 21_750,
        "shard_01": 22_050,
        "shard_02": 21_000,
    }
    assert sum(EXPECTED_SHARD_PREDICTION_ROWS.values()) == COMMON_IDENTITIES


def test_frozen_r1_false_uniform_1050_boundary_count_is_rejected() -> None:
    false_uniform = {
        shard_id: len(folds) * 1_050
        for shard_id, folds in EXPECTED_SHARD_ASSIGNMENT.items()
    }
    assert false_uniform == {
        "shard_00": 22_050,
        "shard_01": 22_050,
        "shard_02": 21_000,
    }
    assert sum(false_uniform.values()) == 65_100
    with pytest.raises(TCNTournamentExtensionError, match="clipped-fold"):
        require_exact_shard_prediction_rows("shard_00", false_uniform["shard_00"])
    for shard_id, exact_rows in EXPECTED_SHARD_PREDICTION_ROWS.items():
        require_exact_shard_prediction_rows(shard_id, exact_rows)


@pytest.mark.parametrize("mutation", ("duplicate", "missing", "extra"))
def test_three_shard_partition_rejects_receipt_universe_drift(mutation: str) -> None:
    receipts, identities, assignment = _synthetic_shard_partition()
    if mutation == "duplicate":
        receipts[-1] = dict(receipts[0])
    elif mutation == "missing":
        receipts.pop()
    else:
        receipts.append({"shard_id": "shard_03", "fold_ids": [], "prediction_rows": 0})
    with pytest.raises(TCNTournamentExtensionError, match="receipt"):
        validate_three_way_partition(
            receipts,
            identities,
            expected_assignment=assignment,
        )


@pytest.mark.parametrize("mutation", ("overlap", "gap"))
def test_three_shard_partition_rejects_row_overlap_or_gap(mutation: str) -> None:
    receipts, identities, assignment = _synthetic_shard_partition()
    if mutation == "overlap":
        source = identities["shard_00"][0]
        identities["shard_00"].append(source)
        receipts[0]["prediction_rows"] = len(identities["shard_00"])
    else:
        identities["shard_00"].pop()
        receipts[0]["prediction_rows"] = len(identities["shard_00"])
    with pytest.raises(TCNTournamentExtensionError, match="identity|ownership"):
        validate_three_way_partition(
            receipts,
            identities,
            expected_assignment=assignment,
        )


def test_complete_metric_surface_has_exact_geometry_and_pairs() -> None:
    result = compute_full_metrics(_joined_metric_fixture(), bootstrap_replicates=12)
    assert len(EXTENDED_MODEL_IDS) == 6
    assert len(EXTENDED_CANDIDATE_IDS) == 5
    assert len(result.pooled_metrics) == 6
    assert len(result.seed_metrics) == 25
    assert len(result.dgp_metrics) == 50
    assert len(result.seed_dgp_metrics) == 250
    assert len(result.fold_metrics) == 15_500
    assert len(result.tail_metrics) == 5
    assert len(result.complementarity) == 15
    assert len(result.bootstrap_metrics) == 5
    assert len(result.candidate_summary) == 5
    tcn = next(row for row in result.candidate_summary if row["candidate_id"] == TCN_MODEL_ID)
    assert tcn["mae_gain_vs_v04"] == pytest.approx(0.20)
    assert tcn["bootstrap_mae_gain_lower_5pct"] > 0.0


def test_truth_free_validator_module_has_no_spent_loader_or_outcome_root() -> None:
    project = Path(__file__).resolve().parents[2]
    source = (
        project
        / "research/model_zoo/pre_certification_tcn_tournament_extension_v2/"
        "prediction_validation.py"
    ).read_text(encoding="utf-8")
    assert "_load_spent_truth" not in source
    assert "TRUTH_ROOT" not in source
    assert "true_log_fair_pe" not in source


def test_extension_sources_contain_no_reserved_qualification_or_heldout_seed_literals() -> None:
    project = Path(__file__).resolve().parents[2]
    package = project / "research/model_zoo/pre_certification_tcn_tournament_extension_v2"
    integer_literals = {
        node.value
        for path in package.rglob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.Constant)
        and type(node.value) is int
    }
    forbidden = {
        int("75" + suffix) for suffix in ("73", "77", "83", "89", "91")
    } | {int("76" + suffix) for suffix in ("03", "07", "21", "39", "43")}
    assert integer_literals.isdisjoint(forbidden)
