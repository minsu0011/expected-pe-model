from __future__ import annotations

import importlib.util
import json
import sys
from argparse import Namespace
from pathlib import Path, PureWindowsPath

import numpy as np
import pandas as pd
import pytest


ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))
SCRIPT = ROOT / "scripts" / "run_v04_multiseed_validation.py"
SPEC = importlib.util.spec_from_file_location("v04_multiseed_validation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
harness = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = harness
SPEC.loader.exec_module(harness)


DEMO_GENERATOR_VERSION = "smooth_fair_pe_pit_truth_xnys_v5"


def _path_args(
    output_root,
    *,
    tuning_seeds=(2309, 2411, 2503, 2609, 2707),
    locked_seeds=(2801, 2903, 3001, 3109, 3203),
) -> Namespace:
    return Namespace(
        output_root=output_root,
        tuning_seeds=tuning_seeds,
        locked_seeds=locked_seeds,
        outer_jobs=32,
        overlay_adapter="in-memory",
        invariance_plan={"groups": {"model_group": {"representative_candidate": "current"}}},
    )


def _attach_spent_seed_reservation(
    args: Namespace,
    candidates: dict[str, dict[str, object]],
    snapshot: dict[str, object],
    registry_path: Path,
) -> dict[str, object]:
    contract = harness._spent_seed_reservation_contract(args, candidates, snapshot)
    args.spent_seed_reservation = harness._reserve_or_verify_spent_seeds(
        registry_path,
        contract,
        allow_create=True,
    )
    return contract


def test_seed_design_requires_unseen_disjoint_five_by_five() -> None:
    harness.validate_seed_design(
        (2309, 2411, 2503, 2609, 2707),
        (2801, 2903, 3001, 3109, 3203),
    )
    with pytest.raises(harness.ValidationError, match="at least five"):
        harness.validate_seed_design(
            (2309, 2411, 2503, 2609),
            (2801, 2903, 3001, 3109, 3203),
        )
    with pytest.raises(harness.ValidationError, match="duplicates"):
        harness.validate_seed_design(
            (2309, 2309, 2503, 2609, 2707),
            (2801, 2903, 3001, 3109, 3203),
        )
    with pytest.raises(harness.ValidationError, match="overlap"):
        harness.validate_seed_design(
            (2309, 2411, 2503, 2609, 2707),
            (2707, 2801, 2903, 3001, 3109),
        )
    with pytest.raises(harness.ValidationError, match="spent historical"):
        harness.validate_seed_design(
            (1301, 2309, 2411, 2503, 2609),
            (2801, 2903, 3001, 3109, 3203),
        )
    with pytest.raises(harness.ValidationError, match="duplicates"):
        harness.parse_seeds("11,11,37")


def test_candidate_columns_are_code_owned_promotion_surfaces(tmp_path: Path) -> None:
    # Historical HARNESS 2.5 candidate files named their incumbent.  HARNESS 2.6
    # deliberately refuses them instead of silently upgrading their semantics.
    for path in (
        ROOT / "config" / "v04_validation_candidates.json",
        ROOT / "config" / "v04_fair_shrinkage_candidate.json",
        ROOT / "config" / "v04_fair_shrinkage_20_candidate.json",
        ROOT / "config" / "v04_kalman_diagnostic_candidate.json",
        ROOT / "config" / "v04_fundamental_vintage_q50_g252_candidate.json",
        ROOT / "config" / "v04_lagged_market_conditioned_candidate.json",
        ROOT / "config" / "v04_ml_incumbent_weekly_median_shrinkage_candidate.json",
    ):
        with pytest.raises(harness.ValidationError, match="cannot choose incumbent_column"):
            harness.load_candidates(path)

    accepted = tmp_path / "kalman.json"
    accepted.write_text(
        json.dumps(
            {
                "candidates": {
                    "kalman": {
                        "selection_column": (
                            "v04_market_conditioned_kalman_diagnostic_expected_pe"
                        ),
                        "overrides": {},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    assert harness.load_candidates(accepted)["kalman"]["selection_column"].startswith(
        "v04_market_conditioned_kalman"
    )
    assert harness.load_candidates(accepted)["kalman"] == {
        "selection_column": "v04_market_conditioned_kalman_diagnostic_expected_pe",
        "overrides": {},
    }
    assert harness.PROMOTION_COMPARATORS == {
        "primary_product": "v04_expected_pe",
        "anti_gaming": "ml_expected_pe",
    }
    assert "ml_incumbent_weekly_median_shrinkage" in harness.INVARIANCE_CONFIG_SECTIONS
    assert "v04_ml_weekly_median_shrinkage_expected_pe" in harness.EXPECTED_PE_COLUMNS
    assert (
        harness.OPTIONAL_EXPECTED_PE_CONFIG_SECTIONS["v04_ml_weekly_median_shrinkage_expected_pe"]
        == "ml_incumbent_weekly_median_shrinkage"
    )
    matured = ROOT / "config" / "v04_matured_proxy_regularized_gate_candidate.json"
    assert harness.load_candidates(matured) == {
        "causal_matured_forward_median_regularized_promotion_v1": {
            "selection_column": "v04_matured_proxy_regularized_expected_pe",
            "overrides": {"matured_proxy_gate": {"enabled": True}},
        }
    }
    assert "matured_proxy_gate" in harness.INVARIANCE_CONFIG_SECTIONS
    assert "v04_matured_proxy_regularized_expected_pe" in harness.EXPECTED_PE_COLUMNS
    assert (
        harness.OPTIONAL_EXPECTED_PE_CONFIG_SECTIONS["v04_matured_proxy_regularized_expected_pe"]
        == "matured_proxy_gate"
    )


@pytest.mark.parametrize(
    "selection",
    ["observed_pe", "v04_global_statistical_expected_pe", "ml_expected_pe"],
)
def test_candidate_semantic_substitution_fails_before_seed_reservation(
    tmp_path: Path,
    selection: str,
) -> None:
    path = tmp_path / f"{selection}.json"
    path.write_text(
        json.dumps(
            {
                "candidates": {
                    "adversarial": {
                        "selection_column": selection,
                        "overrides": {},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(harness.ValidationError, match="code-owned promotion surface"):
        harness.load_candidates(path)


@pytest.mark.parametrize("incumbent", ["ml_expected_pe", "v04_expected_pe", "observed_pe"])
def test_candidate_incumbent_key_is_always_rejected(
    tmp_path: Path,
    incumbent: str,
) -> None:
    path = tmp_path / f"incumbent_{incumbent}.json"
    path.write_text(
        json.dumps(
            {
                "candidates": {
                    "adversarial": {
                        "selection_column": "v04_expected_pe",
                        "incumbent_column": incumbent,
                        "overrides": {},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(harness.ValidationError, match="cannot choose incumbent_column"):
        harness.load_candidates(path)


def test_repo_wide_spent_seed_registry_is_idempotent_append_only_and_cross_root(
    tmp_path: Path,
) -> None:
    registry_path = tmp_path / "registry" / "spent.json"
    candidates = harness.DEFAULT_CANDIDATES
    snapshot = {"combined_sha256": "c" * 64}
    args_a = Namespace(
        output_root=tmp_path / "run_a",
        tuning_seeds=(2309, 2411, 2503, 2609, 2707),
        locked_seeds=(2801, 2903, 3001, 3109, 3203),
    )
    contract_a = harness._spent_seed_reservation_contract(args_a, candidates, snapshot)
    first = harness._reserve_or_verify_spent_seeds(
        registry_path,
        contract_a,
        allow_create=True,
    )
    resumed = harness._reserve_or_verify_spent_seeds(
        registry_path,
        contract_a,
        allow_create=True,
    )
    assert resumed == first
    assert (
        harness._verify_spent_seed_reservation_receipt(
            first,
            expected_contract=contract_a,
        )
        == contract_a
    )

    reused = Namespace(
        output_root=tmp_path / "run_reused",
        tuning_seeds=args_a.tuning_seeds,
        locked_seeds=args_a.locked_seeds,
    )
    with pytest.raises(harness.ValidationError, match="already reserved/spent"):
        harness._reserve_or_verify_spent_seeds(
            registry_path,
            harness._spent_seed_reservation_contract(reused, candidates, snapshot),
            allow_create=True,
        )

    args_b = Namespace(
        output_root=tmp_path / "run_b",
        tuning_seeds=(3301, 3407, 3511, 3607, 3701),
        locked_seeds=(3803, 3907, 4001, 4099, 4201),
    )
    contract_b = harness._spent_seed_reservation_contract(args_b, candidates, snapshot)
    second = harness._reserve_or_verify_spent_seeds(
        registry_path,
        contract_b,
        allow_create=True,
    )
    registry = harness._read_spent_seed_registry(registry_path)
    assert harness.SPENT_SEED_REGISTRY_FORMAT_VERSION == 1
    assert registry["format_version"] == 1
    assert second["reservation_sequence"] == 2
    assert len(registry["entries"]) == 2
    assert registry["entries"][1]["previous_entry_sha256"] == registry["entries"][0]["entry_sha256"]

    tampered = json.loads(registry_path.read_text(encoding="utf-8"))
    tampered["entries"][1]["previous_entry_sha256"] = "0" * 64
    tampered["entries"][1] = harness._seal_payload(
        tampered["entries"][1],
        "entry_sha256",
    )
    tampered = harness._seal_payload(tampered, "registry_sha256")
    harness._atomic_write_json(registry_path, tampered)
    with pytest.raises(harness.ValidationError, match="hash chain"):
        harness._read_spent_seed_registry(registry_path)


def test_full_load_execution_policy_precedes_numpy_and_is_runtime_verified() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.index(
        "_EXECUTION_IMPORT_RUNTIME = _execution_policy_runtime(apply=True)"
    ) < source.index("import numpy as np")
    runtime = harness._execution_policy_runtime(apply=False)
    assert runtime["logical_cpu_ids"] == list(harness.EXECUTION_LOGICAL_CPU_IDS)
    assert runtime["affinity_mask_hex"] == f"0x{harness.EXECUTION_AFFINITY_MASK:08X}"
    assert all(
        1 <= value <= harness.EXECUTION_MAXIMUM_CPU_THREADS
        for value in runtime["thread_environment"].values()
    )
    assert runtime["gpu_environment"] == harness.EXECUTION_GPU_ENVIRONMENT


def test_harness26_uses_a_new_fail_closed_artifact_epoch() -> None:
    assert harness.HARNESS_VERSION == "2.6"
    assert harness.MANIFEST_FORMAT_VERSION == 4
    assert harness.CHECKPOINT_FORMAT_VERSION == 4
    assert harness.ARTIFACT_FORMAT_VERSION == 3
    assert harness.ARTIFACT_LAYOUT_VERSION == 3
    assert harness.RESULT_FORMAT_VERSION == 3
    assert harness.LOCK_FORMAT_VERSION == 3
    assert harness.REPORT_FORMAT_VERSION == 3
    assert harness.PROMOTION_POLICY_FORMAT_VERSION == 2
    assert harness.PATH_POLICY_VERSION == 2
    assert harness.SPENT_SEED_REGISTRY_FORMAT_VERSION == 1


def test_paired_metrics_keep_fair_promotion_independent_of_observed_mask() -> None:
    dates = pd.Series(pd.date_range("2020-01-01", periods=5, freq="D"))
    baseline = pd.Series([10.0, 20.0, np.nan, 40.0, 50.0])
    challenger = pd.Series([11.0, np.nan, 30.0, 44.0, 50.0])
    observed = pd.Series([10.0, 20.0, 30.0, 40.0, np.inf])
    fair = pd.Series([10.0, 20.0, 30.0, 40.0, 50.0])
    scope = np.array([False, True, True, True, True])

    result = harness.paired_log_metrics(
        baseline,
        challenger,
        observed,
        fair,
        dates,
        forced_mask=scope,
    )

    # Fair promotion retains rows 3 and 4. Observed diagnostics retain only row 3.
    assert result["evaluation_scope_rows"] == 4
    assert result["common_rows"] == 2
    assert result["coverage"] == pytest.approx(0.5)
    assert result["diagnostic_common_rows"] == 1
    assert result["diagnostic_coverage"] == pytest.approx(0.25)
    assert result["baseline"]["fair_log_mae"] == pytest.approx(0.0)
    assert result["challenger"]["fair_log_mae"] == pytest.approx(np.log(1.1) / 2.0)
    assert result["challenger"]["fair_log_rmse"] == pytest.approx(np.log(1.1) / np.sqrt(2.0))
    assert result["gain"]["observed_log_mae"] < 0.0

    with pytest.raises(harness.ValidationError, match="true_fair_pe is unavailable"):
        harness.paired_log_metrics(
            baseline,
            challenger.fillna(30.0),
            observed.fillna(30.0),
            pd.Series([np.nan] * len(fair)),
            dates,
            forced_mask=scope,
        )


def test_regime_metrics_handles_rowwise_finite_mask_without_broadcasting() -> None:
    probabilities = pd.DataFrame(
        [
            [0.7, 0.2, 0.1],
            [np.nan, np.nan, np.nan],
            [0.1, 0.2, 0.7],
        ],
        columns=["p_bear", "p_sideways", "p_bull"],
    )
    metrics = harness._regime_metrics(
        probabilities,
        pd.Series(["BEAR", "SIDEWAYS", "BULL"]),
    )
    assert metrics["evaluated_rows"] == 2
    assert metrics["accuracy"] == 1.0


def _gate_frame() -> pd.DataFrame:
    baseline = np.array([10.0, 10.0, 10.0, 10.0])
    challenger = np.array([11.0, 11.0, 11.0, 11.0])
    weight = np.array([0.0, 0.5, 0.0, 0.2])
    blended = np.exp((1.0 - weight) * np.log(baseline) + weight * np.log(challenger))
    return pd.DataFrame(
        {
            "v04_ml_incumbent_expected_pe": baseline,
            "v04_matched_best_ml_expected_pe": challenger,
            "v04_ml_incumbent_blended": blended,
            "v04_ml_incumbent_oos_gain": [np.nan, 0.02, 0.005, 0.03],
            "v04_ml_incumbent_challenger_weight": weight,
            "v04_ml_incumbent_accepted": [False, True, False, True],
        }
    )


def test_no_harm_gate_rejects_weight_without_decisive_past_gain() -> None:
    config = {"ml_incumbent_gate": {"improvement_margin": 0.01}}
    valid = harness.validate_no_harm_gates(_gate_frame(), config)
    assert valid["pass"] is True

    invalid = _gate_frame()
    invalid.loc[2, "v04_ml_incumbent_challenger_weight"] = 0.25
    invalid.loc[2, "v04_ml_incumbent_accepted"] = True
    report = harness.validate_no_harm_gates(invalid, config)
    assert report["pass"] is False
    assert report["gates"]["v04_ml_incumbent"]["weight_without_decisive_gain_rows"] == 1


def test_sealed_checkpoint_detects_tampering(tmp_path: Path) -> None:
    checkpoint = harness._new_checkpoint("manifest-sha")
    harness._verify_sealed(checkpoint, "checkpoint_sha256", context="test")
    path = tmp_path / "checkpoint.json"
    harness._atomic_write_json(path, checkpoint)
    loaded = harness._load_checkpoint(path, "manifest-sha")
    assert loaded == checkpoint

    tampered = json.loads(path.read_text(encoding="utf-8"))
    tampered["inputs"]["tuning"]["11"] = {"unexpected": True}
    path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(harness.ValidationError, match="hash"):
        harness._load_checkpoint(path, "manifest-sha")


def test_candidate_lock_rejects_checkpoint_and_untracked_heldout_paths(
    tmp_path: Path,
) -> None:
    clean = harness._new_checkpoint("manifest-sha")
    harness._assert_heldout_unopened_before_lock(tmp_path / "clean", clean)

    checkpoint_touched = harness._new_checkpoint("manifest-sha")
    checkpoint_touched["inputs"]["heldout"]["2801"] = {}
    with pytest.raises(harness.ValidationError, match="checkpoint evidence"):
        harness._assert_heldout_unopened_before_lock(
            tmp_path / "checkpoint",
            checkpoint_touched,
        )

    untracked_root = tmp_path / "untracked"
    (untracked_root / "artifacts" / "heldout").mkdir(parents=True)
    with pytest.raises(harness.ValidationError, match="planned/untracked"):
        harness._assert_heldout_unopened_before_lock(untracked_root, clean)

    temporary_root = tmp_path / "temporary"
    temporary_root.mkdir()
    (temporary_root / ".heldout_report.json.123.tmp").write_text("{}", encoding="utf-8")
    with pytest.raises(harness.ValidationError, match="planned/untracked"):
        harness._assert_heldout_unopened_before_lock(temporary_root, clean)


def test_resumed_v03_input_must_match_its_seed_bucket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = harness._new_checkpoint("manifest-sha")
    checkpoint["inputs"]["tuning"]["2309"] = {
        "seed": 9999,
        "generator_rows": harness.ROWS,
        "canonical_csv": {},
        "truth_csv": {},
        "cli_log": {},
        "validation": {},
    }
    monkeypatch.setattr(
        harness,
        "_verify_artifact",
        lambda record, *, context: tmp_path / f"{context}.csv",
    )
    monkeypatch.setattr(harness, "_validate_v03_pair", lambda canonical, truth: {})
    with pytest.raises(harness.ValidationError, match="identity differs from its bucket"):
        harness._ensure_v03_input(
            stage="tuning",
            seed=2309,
            args=Namespace(output_root=tmp_path),
            checkpoint=checkpoint,
            checkpoint_path=tmp_path / "checkpoint.json",
        )


def test_completed_checkpoint_is_resumed_without_rerunning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint = harness._new_checkpoint("manifest-sha")
    checkpoint["runs"]["tuning"]["11"] = {"current": {"already": "done"}}
    harness._atomic_write_json(
        checkpoint_path,
        harness._seal_payload(checkpoint, "checkpoint_sha256"),
    )
    verified: list[tuple[object, dict[str, object]]] = []

    def fake_input(**kwargs):
        return tmp_path / "input.csv", tmp_path / "truth.csv", {}, kwargs["checkpoint"]

    monkeypatch.setattr(harness, "_ensure_v03_input", fake_input)

    def fake_verify(record, **kwargs):
        verified.append((record, kwargs))

    monkeypatch.setattr(harness, "_verify_result_record", fake_verify)
    monkeypatch.setattr(
        harness,
        "_run_one_candidate",
        lambda **kwargs: pytest.fail("a completed checkpoint must not rerun"),
    )
    monkeypatch.setattr(harness, "assert_source_snapshot", lambda snapshot: None)
    monkeypatch.setattr(
        harness,
        "source_snapshot",
        lambda v03, v04: {"combined_sha256": "source-sha"},
    )
    assignment = {
        "group_id": "g",
        "signature_sha256": "1" * 64,
        "representative_candidate": "current",
    }
    args = Namespace(
        output_root=tmp_path,
        tuning_seeds=(11, 23, 37),
        invariance_plan={"candidate_assignments": {"current": assignment}},
    )
    manifest = {
        "manifest_sha256": "manifest-sha",
        "source_snapshot": {
            "combined_sha256": "source-sha",
            "v03": {"root": str(tmp_path / "v03")},
            "v04": {"root": str(tmp_path / "v04")},
        },
    }
    harness._run_stage(
        "tuning",
        (11,),
        {"current": {}},
        args,
        manifest,
    )
    assert verified == [
        (
            {"already": "done"},
            {
                "expected_stage": "tuning",
                "expected_seed": 11,
                "expected_candidate": "current",
                "expected_candidate_spec": {},
                "expected_source_config_sha256": "source-sha",
                "expected_invariance_assignment": assignment,
            },
        )
    ]
    resumed = harness._load_checkpoint(checkpoint_path, "manifest-sha")
    assert resumed["stage_completions"]["tuning"]["seeds"] == [11]


def test_source_config_snapshot_detects_a_changed_file(tmp_path: Path) -> None:
    v03 = tmp_path / "v03"
    v04 = tmp_path / "v04"
    for root, marker in ((v03, "old"), (v04, "new")):
        (root / "src").mkdir(parents=True)
        (root / "config").mkdir()
        (root / "src" / "module.py").write_text(f"VALUE = {marker!r}\n", encoding="utf-8")
        (root / "config" / "model.yaml").write_text("seed: 42\n", encoding="utf-8")
    snapshot = harness.source_snapshot(v03, v04)
    harness.assert_source_snapshot(snapshot)

    (v04 / "config" / "model.yaml").write_text("seed: 43\n", encoding="utf-8")
    with pytest.raises(harness.ValidationError, match="snapshot changed"):
        harness.assert_source_snapshot(snapshot)


def test_windows_preflight_reproduces_prospective_layout_failure_path() -> None:
    # C:\ plus 129 characters is the observed 132-character long output root.
    output_root = PureWindowsPath("C:/" + "r" * 129)
    policy = harness._planned_path_policy(
        _path_args(output_root),
        {"current": {}},
        DEMO_GENERATOR_VERSION,
        platform_name="nt",
        long_paths_enabled=False,
    )

    assert len(str(output_root)) == 132
    assert policy["longest_planned_path_chars"] == 264
    assert "artifacts\\heldout" in policy["longest_planned_path"]
    assert policy["longest_planned_path"].endswith("DEMO_price_split_adjusted.csv")
    with pytest.raises(
        harness.ValidationError,
        match=r"safe_file_path_chars=259;.*longest_planned_path_chars=264",
    ):
        harness._enforce_planned_path_policy(policy)


def test_windows_preflight_accepts_short_s20p1_root() -> None:
    output_root = PureWindowsPath(
        r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
        r"\outputs\s20p1"
    )
    policy = harness._planned_path_policy(
        _path_args(
            output_root,
            tuning_seeds=(1301, 1409, 1511, 1601, 1709),
            locked_seeds=(1801, 1901, 2003, 2111, 2203),
        ),
        {"current": {}},
        DEMO_GENERATOR_VERSION,
        platform_name="nt",
        long_paths_enabled=False,
    )

    assert len(str(output_root)) == 85
    assert policy["longest_planned_path_chars"] == 217
    assert policy["classic_limits_enforced"] is True
    harness._enforce_planned_path_policy(policy)


def test_planned_layout_names_the_fixed_parallel32_artifacts() -> None:
    paths = harness._planned_artifact_paths(
        _path_args(PureWindowsPath("C:/short")),
        {"current": {}},
        DEMO_GENERATOR_VERSION,
    )
    rendered = {str(record.path) for record in paths}

    assert any(path.endswith("parallel32.csv") for path in rendered)
    assert any(path.endswith("parallel32_diagnostics.json") for path in rendered)
    assert any(path.endswith("parallel32.log") for path in rendered)
    assert not any("parallel16" in path for path in rendered)


def test_windows_preflight_includes_longer_heldout_seed_paths() -> None:
    policy = harness._planned_path_policy(
        _path_args(
            PureWindowsPath("C:/short"),
            tuning_seeds=(1, 2, 3),
            locked_seeds=(1_000_001, 1_000_002, 1_000_003),
        ),
        {"current": {}},
        DEMO_GENERATOR_VERSION,
        platform_name="nt",
        long_paths_enabled=False,
    )

    assert policy["scope"] == "all_tuning_and_heldout_seeds_x_all_committed_candidates"
    assert "artifacts\\heldout\\seed_1000003" in policy["longest_planned_path"]
    assert policy["longest_planned_path_label"].startswith("heldout:1000003:")


def test_long_root_is_rejected_before_manifest_output_or_subprocess(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "PROJECT_ROOT", tmp_path)
    long_root = tmp_path / "outputs" / ("r" * 140)
    subprocess_called = False

    def forbidden_probe(*args, **kwargs):
        nonlocal subprocess_called
        subprocess_called = True
        pytest.fail("path-invalid run reached the CPython/subprocess probe")

    monkeypatch.setattr(harness, "_runtime_platform_name", lambda: "nt")
    monkeypatch.setattr(harness, "_windows_long_paths_enabled", lambda: False)
    monkeypatch.setattr(harness, "_probe_python310", forbidden_probe)
    args = Namespace(
        command="tune",
        output_root=long_root,
        v03_root=ROOT.parent / "PE_Regime_Engine_v0.2.0",
        v03_python=ROOT.parent / "PE_Regime_Engine_v0.2.0" / ".venv" / "Scripts" / "python.exe",
        v03_config=ROOT.parent / "PE_Regime_Engine_v0.2.0" / "config" / "high_accuracy.yaml",
        v04_config=ROOT / "config" / "v04_bottleneck.yaml",
        candidates_json=None,
        tuning_seeds="2309,2411,2503,2609,2707",
        locked_seeds="2801,2903,3001,3109,3203",
        generation_start=harness.GENERATION_START,
        evaluation_start=harness.PRODUCTION_EVALUATION_START,
        outer_jobs=32,
        overlay_adapter="in-memory",
        no_harm_tolerance=0.005,
    )

    with pytest.raises(
        harness.ValidationError,
        match=r"before any output write or subprocess:.*safe_file_path_chars=259",
    ):
        harness._prepare_common(args)
    assert subprocess_called is False
    assert not long_root.exists()


def test_prospective_output_root_is_confined_to_managed_anchor_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    managed = project / "outputs"
    managed.mkdir(parents=True)
    monkeypatch.setattr(harness, "PROJECT_ROOT", project)

    valid = managed / "kalman_run"
    assert harness._require_managed_output_root(valid) == valid.resolve()
    assert not valid.exists()

    with pytest.raises(harness.ValidationError, match="dedicated directory"):
        harness._require_managed_output_root(managed)
    with pytest.raises(harness.ValidationError, match="repository-managed anchor tree"):
        harness._require_managed_output_root(tmp_path / "external_run")
    with pytest.raises(harness.ValidationError, match="repository-managed anchor tree"):
        harness._require_managed_output_root(managed / "nested" / ".." / ".." / "traversal_escape")

    external = tmp_path / "junction_target"
    external.mkdir()
    link = managed / "junction"
    try:
        link.symlink_to(external, target_is_directory=True)
    except OSError:
        # Windows without Developer Mode cannot create a test symlink.  Simulate
        # the same resolved-path boundary so the fail-closed branch remains tested.
        escaped = link / "run"
        original_resolve = Path.resolve

        def resolved_path(path: Path, *args, **kwargs) -> Path:
            if path == escaped:
                return (external / "run").resolve()
            return original_resolve(path, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", resolved_path)
    with pytest.raises(harness.ValidationError, match="repository-managed anchor tree"):
        harness._require_managed_output_root(link / "run")


def test_external_output_root_fails_before_write_registry_or_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    (project / "outputs").mkdir(parents=True)
    external = tmp_path / "external_run"
    monkeypatch.setattr(harness, "PROJECT_ROOT", project)
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("called")
        pytest.fail("external output root reached a stateful operation")

    monkeypatch.setattr(harness, "_atomic_write_json", forbidden)
    monkeypatch.setattr(harness, "_reserve_or_verify_spent_seeds", forbidden)
    monkeypatch.setattr(harness, "_probe_python310", forbidden)
    with pytest.raises(harness.ValidationError, match="repository-managed anchor tree"):
        harness._prepare_common(Namespace(output_root=external))
    assert calls == []
    assert not external.exists()
    assert not (project / "outputs" / "v04_spent_seed_registry.json").exists()


def test_reserved_or_non_directory_output_root_fails_before_state_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    managed = project / "outputs"
    managed.mkdir(parents=True)
    ledger = managed / "v04_spent_seed_registry.json"
    blocking_file = managed / "not_a_directory"
    blocking_file.write_text("test fixture", encoding="utf-8")
    monkeypatch.setattr(harness, "PROJECT_ROOT", project)
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("called")
        pytest.fail("invalid output root reached a stateful operation")

    monkeypatch.setattr(harness, "_atomic_write_json", forbidden)
    monkeypatch.setattr(harness, "_reserve_or_verify_spent_seeds", forbidden)
    monkeypatch.setattr(harness, "_probe_python310", forbidden)

    invalid_roots = (
        (ledger, "reserved spent-seed ledger"),
        (ledger / "nested_run", "reserved spent-seed ledger"),
        (blocking_file / "nested_run", "non-directory path component"),
    )
    for output_root, message in invalid_roots:
        with pytest.raises(harness.ValidationError, match=message):
            harness._prepare_common(Namespace(output_root=output_root))

    assert calls == []
    assert not ledger.exists()
    assert blocking_file.read_text(encoding="utf-8") == "test fixture"


@pytest.mark.parametrize("outer_jobs", [16, 24])
def test_non32_parallel_count_fails_before_state_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    outer_jobs: int,
) -> None:
    project = tmp_path / "project"
    output_root = project / "outputs" / f"wrong_{outer_jobs}"
    monkeypatch.setattr(harness, "PROJECT_ROOT", project)
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("called")
        pytest.fail("wrong parallel worker count reached a stateful operation")

    monkeypatch.setattr(harness, "_atomic_write_json", forbidden)
    monkeypatch.setattr(harness, "_reserve_or_verify_spent_seeds", forbidden)
    monkeypatch.setattr(harness, "_probe_python310", forbidden)
    monkeypatch.setattr(harness, "_run_command", forbidden)
    args = Namespace(
        command="tune",
        output_root=output_root,
        v03_root=tmp_path / "v03",
        v03_python=tmp_path / "python.exe",
        v03_config=tmp_path / "v03.yaml",
        v04_config=ROOT / "config" / "v04_bottleneck.yaml",
        candidates_json=None,
        tuning_seeds="2309,2411,2503,2609,2707",
        locked_seeds="2801,2903,3001,3109,3203",
        generation_start=harness.GENERATION_START,
        evaluation_start=harness.PRODUCTION_EVALUATION_START,
        outer_jobs=outer_jobs,
        overlay_adapter="in-memory",
        no_harm_tolerance=0.005,
    )

    with pytest.raises(harness.ValidationError, match="fixed at serial vs 32"):
        harness._prepare_common(args)

    assert calls == []
    assert not output_root.exists()
    assert not (project / "outputs" / "v04_spent_seed_registry.json").exists()


def test_manifest_seals_and_revalidates_path_policy(tmp_path: Path) -> None:
    policy = harness._planned_path_policy(
        _path_args(PureWindowsPath("C:/short")),
        {"current": {}},
        DEMO_GENERATOR_VERSION,
        platform_name="nt",
        long_paths_enabled=False,
    )
    v03_root = ROOT.parent / "PE_Regime_Engine_v0.2.0"
    output_root = tmp_path / "run"
    snapshot = {"combined_sha256": "a" * 64}
    candidates = {"current": harness.DEFAULT_CANDIDATES["current"]}
    args = Namespace(
        output_root=output_root,
        path_policy=policy,
        v03_root=v03_root,
        v04_root=ROOT,
        v03_python=v03_root / ".venv" / "Scripts" / "python.exe",
        v03_config=v03_root / "config" / "high_accuracy.yaml",
        v04_config=ROOT / "config" / "v04_bottleneck.yaml",
        generation_start=harness.GENERATION_START,
        evaluation_start=harness.PRODUCTION_EVALUATION_START,
        tuning_seeds=(2309, 2411, 2503, 2609, 2707),
        locked_seeds=(2801, 2903, 3001, 3109, 3203),
        invariance_plan={"groups": {}, "candidate_assignments": {}},
        overlay_adapter="in-memory",
        outer_jobs=32,
        no_harm_tolerance=0.005,
    )
    _attach_spent_seed_reservation(
        args,
        candidates,
        snapshot,
        tmp_path / "registry" / "spent.json",
    )
    args.promotion_policy_path = output_root / "promotion_policy.lock.json"
    policy_contract = harness._promotion_policy_lock_contract(
        args,
        candidates,
        snapshot,
    )
    args.promotion_policy_lock = harness._seal_payload(
        policy_contract,
        "policy_lock_sha256",
    )
    harness._atomic_write_json(args.promotion_policy_path, args.promotion_policy_lock)
    contract = harness._contract_from_args(
        args,
        candidates,
        snapshot,
        {"version": [3, 10, 19]},
    )
    assert contract["format_version"] == harness.MANIFEST_FORMAT_VERSION
    assert contract["artifact_format_version"] == harness.ARTIFACT_FORMAT_VERSION
    assert contract["artifact_layout_version"] == harness.ARTIFACT_LAYOUT_VERSION
    assert contract["path_policy"]["longest_planned_path_chars"] == 140
    assert contract["harness_version"] == "2.6"
    assert contract["promotion_comparators"] == harness.PROMOTION_COMPARATORS
    assert contract["parallel_outer_jobs"] == 32
    assert contract["determinism_comparison"] == {
        "name": "serial-vs-32",
        "serial_outer_jobs": 1,
        "parallel_outer_jobs": 32,
        "bit_exact_required": True,
    }

    manifest_path = output_root / "run_manifest.json"
    manifest = harness._load_or_create_manifest(manifest_path, contract, allow_create=True)
    harness._verify_manifest_storage_contract(manifest, policy)

    old_manifest_path = output_root / "old_v23_manifest.json"
    old_manifest = dict(manifest)
    old_manifest["harness_version"] = "2.5"
    old_manifest = harness._seal_payload(old_manifest, "manifest_sha256")
    harness._atomic_write_json(old_manifest_path, old_manifest)
    with pytest.raises(harness.ValidationError, match="format/harness/layout is incompatible"):
        harness._load_or_create_manifest(
            old_manifest_path,
            contract,
            allow_create=False,
        )

    changed_policy = json.loads(json.dumps(policy))
    changed_policy["longest_planned_path_chars"] += 1
    with pytest.raises(harness.ValidationError, match="path policy differs"):
        harness._verify_manifest_storage_contract(manifest, changed_policy)
    changed_contract = json.loads(json.dumps(contract))
    changed_contract["path_policy"] = changed_policy
    with pytest.raises(harness.ValidationError, match="invocation differs"):
        harness._load_or_create_manifest(
            manifest_path,
            changed_contract,
            allow_create=False,
        )

    tampered = json.loads(manifest_path.read_text(encoding="utf-8"))
    tampered["path_policy"]["longest_planned_path_chars"] += 1
    manifest_path.write_text(json.dumps(tampered), encoding="utf-8")
    with pytest.raises(harness.ValidationError, match="hash"):
        harness._load_or_create_manifest(manifest_path, contract, allow_create=False)


def test_harness25_checkpoint_result_and_artifact_cannot_resume(tmp_path: Path) -> None:
    checkpoint = harness._new_checkpoint("manifest-sha")
    checkpoint["format_version"] = 3
    checkpoint["artifact_format_version"] = 2
    checkpoint["artifact_layout_version"] = 2
    old_checkpoint = harness._seal_payload(checkpoint, "checkpoint_sha256")
    path = tmp_path / "checkpoint.json"
    harness._atomic_write_json(path, old_checkpoint)

    with pytest.raises(harness.ValidationError, match="format/layout is incompatible"):
        harness._load_checkpoint(path, "manifest-sha")

    old_result = harness._seal_payload(
        {"format_version": 2},
        "result_sha256",
    )
    with pytest.raises(harness.ValidationError, match="predates the prospective policy"):
        harness._verify_result_record(old_result)

    artifact_path = tmp_path / "legacy.txt"
    artifact_path.write_text("legacy", encoding="utf-8")
    legacy_artifact = {
        "path": str(artifact_path),
        "bytes": artifact_path.stat().st_size,
        "sha256": harness._file_sha256(artifact_path),
    }
    with pytest.raises(harness.ValidationError, match="artifact format is incompatible"):
        harness._verify_artifact(legacy_artifact, context="legacy 2.5")


def test_append_contract_freezes_all_150_columns_and_rejects_infinity() -> None:
    original = pd.DataFrame(
        {f"column_{index:03d}": [float(index), float(index + 1)] for index in range(150)}
    )
    appended = ("v04_signal", "v04_expected_pe")
    output = original.copy()
    output["v04_signal"] = [0.1, np.nan]
    output["v04_expected_pe"] = [20.0, np.nan]
    report = harness._validate_append_contract(original, output, appended)
    assert report["v03_frozen_parity_exact"] is True
    assert report["v03_prefix_columns"] == 150

    changed = output.copy()
    changed.loc[0, "column_042"] += 1.0
    with pytest.raises(AssertionError):
        harness._validate_append_contract(original, changed, appended)

    infinite = output.copy()
    infinite.loc[0, "v04_signal"] = np.inf
    with pytest.raises(harness.ValidationError, match="infinity"):
        harness._validate_append_contract(original, infinite, appended)


def test_apply_result_adapter_accepts_stable_tuple_api() -> None:
    frame = pd.DataFrame({"value": [1.0]})
    output, diagnostics = harness._normalize_apply_result(
        (frame, {"invariants": {"all_input_columns_exact": True}})
    )
    assert output is frame
    assert diagnostics["invariants"]["all_input_columns_exact"] is True
    with pytest.raises(harness.ValidationError, match="apply_v04_layers"):
        harness._normalize_apply_result(("not-a-frame", {}))


def test_causal_prefix_hash_must_match_truncated_run() -> None:
    full = {"prefix_frame_sha256": {"1500": "same-hash"}}
    prefix = {"output_contract": {"frame_exact_sha256": "same-hash"}}
    assert harness._compare_prefix_diagnostics(full, prefix)["pass"] is True
    prefix["output_contract"]["frame_exact_sha256"] = "future-leaked"
    assert harness._compare_prefix_diagnostics(full, prefix)["pass"] is False


def test_adapter_is_an_isolated_cpython310_worker_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command, *, cwd, log_path, env):
        captured.update(command=list(command), cwd=cwd, log_path=log_path, env=env)
        return harness.CommandMeasurement(1.25, 1234)

    monkeypatch.setattr(harness, "_run_command", fake_run)
    args = Namespace(
        v03_python=tmp_path / "python.exe",
        v03_root=tmp_path / "v03",
        v04_config=tmp_path / "v04.yaml",
        overlay_adapter="in-memory",
    )
    result = harness._run_v04_adapter(
        input_csv=tmp_path / "input.csv",
        output_csv=tmp_path / "output.csv",
        diagnostics_json=tmp_path / "diagnostics.json",
        overrides_json=tmp_path / "overrides.json",
        model_seed=500_011,
        outer_jobs=32,
        args=args,
        log_path=tmp_path / "worker.log",
    )
    command = captured["command"]
    assert command[0] == str(args.v03_python.resolve())
    assert "_overlay-worker" in command
    assert command[command.index("--outer-jobs") + 1] == "32"
    assert command[command.index("--adapter") + 1] == "in-memory"
    assert captured["env"]["CUDA_VISIBLE_DEVICES"] == "-1"
    assert captured["env"]["NVIDIA_VISIBLE_DEVICES"] == "void"
    assert result.peak_rss_bytes == 1234


def test_serial_vs32_invariance_orchestration_is_explicit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical = tmp_path / "canonical.csv"
    truth = tmp_path / "truth.csv"
    pd.DataFrame(
        {
            "date": ["2020-01-02", "2020-01-03", "2020-01-06"],
            "value": [1.0, 2.0, 3.0],
        }
    ).to_csv(canonical, index=False)
    pd.DataFrame({"date": ["2020-01-02"], "true_fair_pe": [20.0]}).to_csv(
        truth,
        index=False,
    )
    calls: list[int] = []

    def fake_adapter(**kwargs):
        outer_jobs = int(kwargs["outer_jobs"])
        calls.append(outer_jobs)
        input_frame = pd.read_csv(kwargs["input_csv"])
        output_path = Path(kwargs["output_csv"])
        output_path.parent.mkdir(parents=True, exist_ok=True)
        input_frame.to_csv(output_path, index=False)
        frame_sha = "a" * 64
        diagnostics = {
            "outer_jobs": outer_jobs,
            "output_contract": {"frame_exact_sha256": frame_sha},
            "prefix_frame_sha256": {str(harness.CAUSAL_PREFIX_ROWS): frame_sha},
        }
        harness._atomic_write_json(Path(kwargs["diagnostics_json"]), diagnostics)
        Path(kwargs["log_path"]).write_text("fixture\n", encoding="utf-8")
        return harness.CommandMeasurement(0.01, 100)

    monkeypatch.setattr(harness, "assert_source_snapshot", lambda snapshot: None)
    monkeypatch.setattr(harness, "_validated_effective_config", lambda *args, **kwargs: {})
    monkeypatch.setattr(harness, "_run_v04_adapter", fake_adapter)
    monkeypatch.setattr(harness, "analyze_overlay_output", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        harness,
        "_write_promotion_daily_evidence",
        lambda **kwargs: {"fixture": True},
    )
    effective = {
        "current": {
            "regime_stacker": {"horizon": 21, "outer_n_jobs": 32},
            "expected_pe": {
                "include_return_forecast_features": False,
                "outer_n_jobs": 32,
            },
            "fundamental_vintage": {"enabled": True},
            "lagged_market_conditioned": {"enabled": False},
            "ml_incumbent_weekly_median_shrinkage": {"enabled": False},
            "matured_proxy_gate": {"enabled": False},
        }
    }
    args = Namespace(
        output_root=tmp_path / "run",
        v04_config=ROOT / "config" / "v04_bottleneck.yaml",
        outer_jobs=32,
        tuning_seeds=(11, 23, 37, 41, 53),
        overlay_adapter="in-memory",
        invariance_plan=harness._build_invariance_plan(effective),
    )

    result = harness._run_one_candidate(
        stage="tuning",
        seed=11,
        name="current",
        candidate=harness.DEFAULT_CANDIDATES["current"],
        canonical=canonical,
        truth=truth,
        args=args,
        snapshot={"combined_sha256": "b" * 64},
    )

    assert calls == [32, 1, 32]
    determinism = result["serial_vs_parallel_determinism"]
    assert determinism["comparison"] == "serial-vs-32"
    assert determinism["serial_outer_jobs"] == 1
    assert determinism["parallel_outer_jobs"] == 32
    assert determinism["pass"] is True
    assert result["causal_prefix_invariance"]["parallel_outer_jobs"] == 32
    assert result["integration_contract"]["outer_jobs"] == 32
    assert result["artifacts"]["output_csv"]["path"].endswith("parallel32.csv")


def test_forced_model_configs_match_serial_vs32_contract() -> None:
    base = {"regime_stacker": {}, "expected_pe": {}}
    serial = harness._force_parallelism(base, harness.DETERMINISM_SERIAL_OUTER_JOBS)
    parallel = harness._force_parallelism(base, harness.DETERMINISM_PARALLEL_OUTER_JOBS)

    for section in ("regime_stacker", "expected_pe"):
        assert serial[section] == {
            "outer_n_jobs": 1,
            "parallel_backend": "serial",
            "n_jobs": 1,
        }
        assert parallel[section] == {
            "outer_n_jobs": 32,
            "parallel_backend": "thread",
            "n_jobs": 1,
        }


def test_candidate_selection_is_fail_closed_and_ranked_by_worst_of_four() -> None:
    def summary(
        primary: tuple[float, float],
        anti: tuple[float, float],
        *,
        eligible: bool,
    ) -> dict[str, object]:
        gains = {
            "primary_product": primary,
            "anti_gaming": anti,
        }
        return {
            "eligible_for_lock": eligible,
            "worst_relative_pooled_gain_across_comparator_metrics": min(
                *primary,
                *anti,
            ),
            "comparators": {
                comparator: {
                    "aggregate": {
                        "fair_log_mae": {"relative_mean_gain": values[0]},
                        "fair_log_rmse": {"relative_mean_gain": values[1]},
                    }
                }
                for comparator, values in gains.items()
            },
        }

    common = {
        "metric_roles": harness._metric_roles_contract(),
        "candidates": {
            # Tempting primary score, but anti-gaming is the limiting comparator.
            "primary_star": summary((0.08, 0.07), (0.011, 0.010), eligible=True),
            "winner": summary((0.03, 0.025), (0.021, 0.020), eligible=True),
            "ineligible_best": summary((0.5, 0.5), (0.5, 0.5), eligible=False),
        },
    }
    assert harness._select_candidate(common) == "winner"
    with pytest.raises(harness.ValidationError, match="no tuning candidate"):
        harness._select_candidate(
            {
                "metric_roles": harness._metric_roles_contract(),
                "candidates": {"bad": summary((0.5, 0.5), (0.5, 0.5), eligible=False)},
            }
        )

    lexical_tie = {
        "metric_roles": harness._metric_roles_contract(),
        "candidates": {
            "a_first": summary((0.03, 0.02), (0.02, 0.02), eligible=True),
            "z_second": summary((0.02, 0.02), (0.03, 0.02), eligible=True),
        },
    }
    assert harness._select_candidate(lexical_tie) == "a_first"


def _paired_seed_row(
    *,
    seed: int,
    fair: tuple[float, float],
    observed: tuple[float, float],
):
    return {
        "seed": seed,
        "baseline": {
            "fair_log_mae": fair[0],
            "fair_log_rmse": fair[0],
            "observed_log_mae": observed[0],
            "observed_log_rmse": observed[0],
        },
        "challenger": {
            "fair_log_mae": fair[1],
            "fair_log_rmse": fair[1],
            "observed_log_mae": observed[1],
            "observed_log_rmse": observed[1],
        },
        "structural_no_harm_pass": True,
        "determinism_pass": True,
        "causal_prefix_invariance_pass": True,
    }


def test_promotion_rejects_observed_improvement_when_fair_truth_worsens() -> None:
    rows = [
        _paired_seed_row(seed=seed, fair=(1.0, 1.1), observed=(1.0, 0.5))
        for seed in (2309, 2411, 2503, 2609, 2707)
    ]
    summary = harness._aggregate_paired_seed_metrics(
        rows,
        tolerance_fraction=0.005,
    )
    gates = harness._prospective_deterministic_gates(rows)
    assert summary["aggregate"]["observed_log_mae"]["mean_gain"] > 0.0
    assert summary["aggregate"]["fair_log_mae"]["mean_gain"] < 0.0
    assert summary["aggregate"]["fair_log_mae"]["role"] == "promotion"
    assert summary["aggregate"]["observed_log_mae"]["role"] == "diagnostic_only"
    assert summary["empirical_no_harm_pass"] is False
    assert gates["pass"] is False


def test_promotion_accepts_fair_improvement_despite_observed_worsening() -> None:
    rows = [
        _paired_seed_row(seed=seed, fair=(1.0, 0.5), observed=(1.0, 1.1))
        for seed in (2309, 2411, 2503, 2609, 2707)
    ]
    summary = harness._aggregate_paired_seed_metrics(
        rows,
        tolerance_fraction=0.005,
    )
    gates = harness._prospective_deterministic_gates(rows)
    assert summary["aggregate"]["fair_log_rmse"]["mean_gain"] > 0.0
    assert summary["aggregate"]["observed_log_rmse"]["mean_gain"] < 0.0
    assert summary["empirical_no_harm_pass"] is True
    assert gates["pass"] is True


def test_zero_observed_diagnostic_loss_cannot_veto_fair_promotion() -> None:
    rows = [
        _paired_seed_row(seed=seed, fair=(1.0, 0.5), observed=(0.0, 0.25))
        for seed in (2309, 2411, 2503, 2609, 2707)
    ]

    summary = harness._aggregate_paired_seed_metrics(
        rows,
        tolerance_fraction=0.005,
    )
    gates = harness._prospective_deterministic_gates(rows)

    observed = summary["aggregate"]["observed_log_mae"]
    assert observed["baseline_mean"] == 0.0
    assert observed["challenger_mean"] == 0.25
    assert observed["mean_gain"] == -0.25
    assert observed["relative_mean_gain"] is None
    assert observed["worst_seed_degradation_fraction"] is None
    assert observed["per_seed_relative_gain"] is None
    assert summary["worst_degradation_fraction_across_diagnostic_only_metrics"] is None
    assert summary["empirical_no_harm_pass"] is True
    assert gates["pass"] is True


def _prospective_rows(
    mae_gains: list[float],
    rmse_gains: list[float] | None = None,
) -> list[dict[str, object]]:
    if rmse_gains is None:
        rmse_gains = list(mae_gains)
    seeds = (2309, 2411, 2503, 2609, 2707)
    return [
        {
            "seed": seed,
            "baseline": {
                "fair_log_mae": 1.0,
                "fair_log_rmse": 1.0,
                "observed_log_mae": 1.0,
                "observed_log_rmse": 1.0,
            },
            "challenger": {
                "fair_log_mae": 1.0 - mae_gain,
                "fair_log_rmse": 1.0 - rmse_gain,
                "observed_log_mae": 1.0,
                "observed_log_rmse": 1.0,
            },
        }
        for seed, mae_gain, rmse_gain in zip(
            seeds,
            mae_gains,
            rmse_gains,
            strict=True,
        )
    ]


def test_prospective_gates_allow_four_of_five_only_below_material_cap() -> None:
    allowed = harness._prospective_deterministic_gates(
        _prospective_rows([0.01, 0.01, 0.01, 0.01, -0.0049])
    )
    assert allowed["joint_seed_wins"] == 4
    assert allowed["required_joint_seed_wins"] == 4
    assert allowed["worst_seed_material_harm_pass"] is True
    assert allowed["pooled_practical_margin_pass"] is True
    assert allowed["leave_one_seed_out_pass"] is True
    assert allowed["pass"] is True

    material_harm = harness._prospective_deterministic_gates(
        _prospective_rows([0.01, 0.01, 0.01, 0.01, -0.0051])
    )
    assert material_harm["joint_seed_wins"] == 4
    assert material_harm["worst_seed_material_harm_pass"] is False
    assert material_harm["pass"] is False


def test_prospective_gates_require_joint_wins_and_both_practical_margins() -> None:
    disjoint_metric_wins = harness._prospective_deterministic_gates(
        _prospective_rows(
            [0.01, 0.01, 0.01, 0.01, -0.001],
            [0.01, 0.01, 0.01, -0.001, 0.01],
        )
    )
    assert disjoint_metric_wins["per_metric"]["fair_log_mae"]["strict_seed_wins"] == 4
    assert disjoint_metric_wins["per_metric"]["fair_log_rmse"]["strict_seed_wins"] == 4
    assert disjoint_metric_wins["joint_seed_wins"] == 3
    assert disjoint_metric_wins["pass"] is False

    too_small = harness._prospective_deterministic_gates(_prospective_rows([0.004] * 5))
    assert too_small["joint_seed_win_pass"] is True
    assert too_small["pooled_practical_margin_pass"] is False
    assert too_small["pass"] is False


def _daily_evidence_frame(
    seed: int,
    *,
    primary_log_error: float = 0.11,
    anti_log_error: float = 0.10,
    challenger_log_error: float = 0.08,
    rows: int = 1260,
) -> pd.DataFrame:
    dates = pd.bdate_range("2015-01-02", periods=rows)
    phase = np.arange(rows, dtype=float)
    fair = 20.0 + 0.5 * np.sin(phase / 31.0) + seed * 0.0
    return pd.DataFrame(
        {
            "seed": np.full(rows, seed, dtype=np.int64),
            "date": dates.strftime("%Y-%m-%d"),
            "true_fair_pe": fair,
            "observed_pe": fair * np.exp(0.12),
            "primary_v04_expected_pe": fair * np.exp(primary_log_error),
            "anti_ml_expected_pe": fair * np.exp(anti_log_error),
            "challenger_pe": fair * np.exp(challenger_log_error),
        },
        columns=list(harness.PROMOTION_DAILY_EVIDENCE_COLUMNS),
    )


def _dual_rows_from_evidence(
    evidence: dict[int, pd.DataFrame],
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    evidence_columns = {
        "primary_product": "primary_v04_expected_pe",
        "anti_gaming": "anti_ml_expected_pe",
    }
    for seed, frame in evidence.items():
        comparator_rows = {
            comparator: harness.paired_log_metrics(
                frame[column],
                frame["challenger_pe"],
                frame["observed_pe"],
                frame["true_fair_pe"],
                frame["date"],
            )
            for comparator, column in evidence_columns.items()
        }
        rows.append(
            {
                "seed": seed,
                "comparators": comparator_rows,
                "structural_no_harm_pass": True,
                "determinism_pass": True,
                "causal_prefix_invariance_pass": True,
            }
        )
    return rows


def test_daily_paired_evidence_is_full_positive_and_date_aligned() -> None:
    frame = _daily_evidence_frame(2309)
    metadata = harness._validate_promotion_daily_evidence_frame(
        frame,
        expected_seed=2309,
    )
    assert metadata["rows"] == 1260
    assert metadata["coverage"] == 1.0

    missing = frame.copy()
    missing.loc[100, "challenger_pe"] = np.nan
    with pytest.raises(harness.ValidationError, match="finite and positive"):
        harness._validate_promotion_daily_evidence_frame(missing, expected_seed=2309)

    evidence = {seed: _daily_evidence_frame(seed) for seed in (2309, 2411, 2503, 2609, 2707)}
    shifted = evidence[2707].copy()
    shifted.loc[1259, "date"] = "2030-01-01"
    evidence[2707] = shifted
    with pytest.raises(harness.ValidationError, match="date indexes differ"):
        harness._prepare_bootstrap_evidence(evidence)

    with pytest.raises(harness.ValidationError, match="evidence artifact is missing"):
        harness._load_promotion_daily_evidence({}, expected_seed=2309)

    for comparator_column, bad_value in (
        ("primary_v04_expected_pe", 0.0),
        ("anti_ml_expected_pe", np.nan),
    ):
        invalid_comparator = frame.copy()
        invalid_comparator.loc[100, comparator_column] = bad_value
        with pytest.raises(harness.ValidationError, match="finite and positive"):
            harness._validate_promotion_daily_evidence_frame(
                invalid_comparator,
                expected_seed=2309,
            )


def test_tampered_comparator_evidence_artifact_fails_closed(tmp_path: Path) -> None:
    frame = _daily_evidence_frame(2309)
    path = tmp_path / "promotion_daily_evidence.csv"
    frame.to_csv(path, index=False, float_format="%.17g", lineterminator="\n")
    metadata = harness._validate_promotion_daily_evidence_frame(frame, expected_seed=2309)
    record = {
        **metadata,
        "comparator_columns": dict(harness.PROMOTION_COMPARATORS),
        "challenger_column": "v04_expected_pe",
        "artifact": harness._artifact(path),
    }
    loaded = harness._load_promotion_daily_evidence(
        record,
        expected_seed=2309,
        expected_challenger_column="v04_expected_pe",
    )
    assert len(loaded) == len(frame)

    tampered = frame.copy()
    tampered.loc[100, "anti_ml_expected_pe"] *= 1.01
    tampered.to_csv(path, index=False, float_format="%.17g", lineterminator="\n")
    with pytest.raises(harness.ValidationError, match="artifact (size|hash) changed"):
        harness._load_promotion_daily_evidence(
            record,
            expected_seed=2309,
            expected_challenger_column="v04_expected_pe",
        )


def test_hierarchical_block_bootstrap_is_deterministic_and_has_24_lcbs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_ITERATIONS", 199)
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_CHUNK_SIZE", 32)
    policy = harness._promotion_policy_config()
    evidence = {seed: _daily_evidence_frame(seed) for seed in (2309, 2411, 2503, 2609, 2707)}

    first = harness._promotion_block_bootstrap(evidence, policy_config=policy)
    second = harness._promotion_block_bootstrap(evidence, policy_config=policy)
    assert first == second
    assert first["expected_cells"] == 24
    assert len(first["cells"]) == 24
    assert first["iterations_per_cell"] == 199
    assert first["pass"] is True
    assert {cell["method"] for cell in first["cells"]} == {
        "moving_block",
        "stationary",
    }
    assert {cell["block_length"] for cell in first["cells"]} == {21, 42, 63}
    assert {cell["comparator"] for cell in first["cells"]} == set(harness.PROMOTION_COMPARATORS)
    assert all(cell["comparator_metric_alpha_bonferroni"] == 0.0125 for cell in first["cells"])
    assert all(cell["simultaneous_lcb"] > 0.0 for cell in first["cells"])
    harness._verify_promotion_block_bootstrap_summary(
        first,
        policy_config=policy,
        context="test",
    )

    missing_cell = json.loads(json.dumps(first))
    missing_cell["cells"].pop()
    missing_cell["cells_sha256"] = harness.hashlib.sha256(
        harness._canonical_json_bytes({"cells": missing_cell["cells"]})
    ).hexdigest()
    missing_cell = harness._seal_payload(missing_cell, "bootstrap_sha256")
    with pytest.raises(harness.ValidationError, match="all 24"):
        harness._verify_promotion_block_bootstrap_summary(
            missing_cell,
            policy_config=policy,
            context="test",
        )

    hash_mismatch = json.loads(json.dumps(first))
    hash_mismatch["cells"][0]["replicate_sha256"] = "0" * 64
    hash_mismatch = harness._seal_payload(hash_mismatch, "bootstrap_sha256")
    with pytest.raises(harness.ValidationError, match="cell hash differs"):
        harness._verify_promotion_block_bootstrap_summary(
            hash_mismatch,
            policy_config=policy,
            context="test",
        )

    zero_gain = {
        seed: _daily_evidence_frame(
            seed,
            primary_log_error=0.10,
            anti_log_error=0.10,
            challenger_log_error=0.10,
        )
        for seed in evidence
    }
    rejected = harness._promotion_block_bootstrap(zero_gain, policy_config=policy)
    assert rejected["pass"] is False
    assert all(cell["simultaneous_lcb"] == pytest.approx(0.0) for cell in rejected["cells"])
    harness._verify_promotion_block_bootstrap_summary(
        rejected,
        policy_config=policy,
        context="test rejection",
    )


def test_tuning_summary_enforces_full_evidence_and_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_ITERATIONS", 99)
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_CHUNK_SIZE", 32)
    policy = harness._promotion_policy_config()
    evidence = {seed: _daily_evidence_frame(seed) for seed in (2309, 2411, 2503, 2609, 2707)}
    rows = _dual_rows_from_evidence(evidence)

    summary = harness._summarize_tuning_candidate(
        rows,
        tolerance_fraction=0.005,
        invariance_assignment={"group_id": "g"},
        daily_evidence_by_seed=evidence,
        policy_config=policy,
    )
    assert summary["prospective_deterministic_gates"]["pass"] is True
    assert all(
        item["pass"] is True
        for item in summary["prospective_deterministic_gates"]["comparators"].values()
    )
    assert summary["prospective_block_bootstrap"]["pass"] is True
    assert summary["eligible_for_lock"] is True

    missing = dict(evidence)
    missing.pop(2707)
    with pytest.raises(harness.ValidationError, match="seed set differs"):
        harness._summarize_tuning_candidate(
            rows,
            tolerance_fraction=0.005,
            invariance_assignment={"group_id": "g"},
            daily_evidence_by_seed=missing,
            policy_config=policy,
        )


@pytest.mark.parametrize(
    ("primary_error", "anti_error", "passing", "failing"),
    [
        (0.10, 0.05, "primary_product", "anti_gaming"),
        (0.05, 0.10, "anti_gaming", "primary_product"),
    ],
)
def test_dual_comparator_requires_both_comparators_to_pass(
    monkeypatch: pytest.MonkeyPatch,
    primary_error: float,
    anti_error: float,
    passing: str,
    failing: str,
) -> None:
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_ITERATIONS", 99)
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_CHUNK_SIZE", 32)
    policy = harness._promotion_policy_config()
    evidence = {
        seed: _daily_evidence_frame(
            seed,
            primary_log_error=primary_error,
            anti_log_error=anti_error,
            challenger_log_error=0.08,
        )
        for seed in (2309, 2411, 2503, 2609, 2707)
    }
    summary = harness._summarize_tuning_candidate(
        _dual_rows_from_evidence(evidence),
        tolerance_fraction=0.005,
        invariance_assignment={"group_id": "g"},
        daily_evidence_by_seed=evidence,
        policy_config=policy,
    )

    gates = summary["prospective_deterministic_gates"]["comparators"]
    assert gates[passing]["pass"] is True
    assert gates[failing]["pass"] is False
    assert summary["prospective_deterministic_gates"]["pass"] is False
    assert summary["prospective_block_bootstrap"]["pass"] is False
    assert summary["eligible_for_lock"] is False


def test_lock_resume_dual_summary_tampering_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_ITERATIONS", 49)
    monkeypatch.setattr(harness, "PROMOTION_BOOTSTRAP_CHUNK_SIZE", 16)
    policy = harness._promotion_policy_config()
    evidence = {seed: _daily_evidence_frame(seed) for seed in (2309, 2411, 2503, 2609, 2707)}
    summary = harness._summarize_tuning_candidate(
        _dual_rows_from_evidence(evidence),
        tolerance_fraction=0.005,
        invariance_assignment={"group_id": "g"},
        daily_evidence_by_seed=evidence,
        policy_config=policy,
    )
    harness._verify_dual_candidate_summary(
        summary,
        policy_config=policy,
        context="test lock resume",
    )

    comparator_tamper = json.loads(json.dumps(summary))
    comparator_tamper["comparators"]["anti_gaming"]["per_seed"][0]["baseline"]["fair_log_mae"] *= (
        1.01
    )
    with pytest.raises(harness.ValidationError, match="per-seed evidence differs"):
        harness._verify_dual_candidate_summary(
            comparator_tamper,
            policy_config=policy,
            context="test lock resume",
        )

    seed_tamper = json.loads(json.dumps(summary))
    seed_tamper["prospective_block_bootstrap"]["seed_ids"][0] += 1
    seed_tamper["prospective_block_bootstrap"] = harness._seal_payload(
        seed_tamper["prospective_block_bootstrap"],
        "bootstrap_sha256",
    )
    with pytest.raises(harness.ValidationError, match="bootstrap seed set differs"):
        harness._verify_dual_candidate_summary(
            seed_tamper,
            policy_config=policy,
            context="test lock resume",
        )

    seed_type_tamper = json.loads(json.dumps(summary))
    seed_type_tamper["per_seed"][0]["seed"] = str(seed_type_tamper["per_seed"][0]["seed"])
    with pytest.raises(harness.ValidationError, match="seed identity is malformed"):
        harness._verify_dual_candidate_summary(
            seed_type_tamper,
            policy_config=policy,
            context="test lock resume",
        )


def test_policy_lock_refuses_retroactive_nonempty_output_root(tmp_path: Path) -> None:
    output_root = tmp_path / "legacy_w20"
    output_root.mkdir()
    (output_root / "heldout_report.json").write_text("{}", encoding="utf-8")
    args = Namespace(
        output_root=output_root,
        tuning_seeds=(2309, 2411, 2503, 2609, 2707),
        locked_seeds=(2801, 2903, 3001, 3109, 3203),
    )
    snapshot = {"combined_sha256": "b" * 64}
    _attach_spent_seed_reservation(
        args,
        harness.DEFAULT_CANDIDATES,
        snapshot,
        tmp_path / "registry" / "spent.json",
    )
    contract = harness._promotion_policy_lock_contract(
        args,
        harness.DEFAULT_CANDIDATES,
        snapshot,
    )
    with pytest.raises(harness.ValidationError, match="cannot be reclassified"):
        harness._load_or_create_promotion_policy_lock(
            output_root / "promotion_policy.lock.json",
            contract,
            allow_create=True,
        )


def test_prospective_policy_seals_rng_iterations_and_gpu_off() -> None:
    policy = harness._promotion_policy_config()
    harness._verify_promotion_policy_config(policy, context="test")
    assert policy["bootstrap"]["iterations"] == 49_999
    assert policy["bootstrap"]["rng"] == "PCG64DXSM"
    assert policy["bootstrap"]["block_lengths"] == [21, 42, 63]
    assert policy["bootstrap"]["comparator_metric_hypotheses"] == 4
    assert policy["bootstrap"]["comparator_metric_alpha_bonferroni"] == 0.0125
    assert policy["promotion_comparators"] == harness.PROMOTION_COMPARATORS
    assert policy["both_comparators_must_pass"] is True
    execution = policy["execution"]
    assert execution["maximum_cpu_workers"] == len(harness.EXECUTION_LOGICAL_CPU_IDS)
    assert execution["logical_cpu_ids"] == list(harness.EXECUTION_LOGICAL_CPU_IDS)
    assert execution["affinity_mask_hex"] == f"0x{harness.EXECUTION_AFFINITY_MASK:08X}"
    assert execution["affinity_enforced_before_numpy_import"] is True
    assert execution["gpu"] == "sealed_off"
    assert execution["gpu_environment"] == harness.EXECUTION_GPU_ENVIRONMENT
    assert execution["determinism_comparison"] == {
        "name": "serial-vs-32",
        "serial_outer_jobs": 1,
        "parallel_outer_jobs": 32,
        "bit_exact_required": True,
    }

    tampered = json.loads(json.dumps(policy))
    tampered["bootstrap"]["iterations"] -= 1
    tampered = harness._seal_payload(tampered, "policy_config_sha256")
    with pytest.raises(harness.ValidationError, match="differs"):
        harness._verify_promotion_policy_config(tampered, context="test")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"unknown_section": {}}, "unknown keys"),
        ({"expected_pe": {"unknown_nested": 1}}, "expected_pe: unknown keys"),
        (
            {"final_guard": {"improvement_margin": -0.01}},
            "improvement_margin must be finite and non-negative",
        ),
    ],
)
def test_invalid_candidate_override_fails_before_any_subprocess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    message: str,
) -> None:
    monkeypatch.setattr(harness, "PROJECT_ROOT", tmp_path)
    candidates_path = tmp_path / "candidates.json"
    candidates_path.write_text(json.dumps({"bad": {"overrides": overrides}}), encoding="utf-8")
    subprocess_called = False

    def forbidden_probe(*args, **kwargs):
        nonlocal subprocess_called
        subprocess_called = True
        pytest.fail("invalid override reached the CPython/subprocess probe")

    monkeypatch.setattr(harness, "_probe_python310", forbidden_probe)
    args = Namespace(
        command="tune",
        output_root=tmp_path / "outputs" / "output",
        v03_root=tmp_path / "v03",
        v03_python=tmp_path / "python.exe",
        v03_config=ROOT.parent / "PE_Regime_Engine_v0.2.0" / "config" / "high_accuracy.yaml",
        v04_config=ROOT / "config" / "v04_bottleneck.yaml",
        candidates_json=candidates_path,
        tuning_seeds="2309,2411,2503,2609,2707",
        locked_seeds="2801,2903,3001,3109,3203",
        generation_start=harness.GENERATION_START,
        evaluation_start=harness.PRODUCTION_EVALUATION_START,
        outer_jobs=32,
        overlay_adapter="in-memory",
        no_harm_tolerance=0.005,
    )
    with pytest.raises(ValueError, match=message):
        harness._prepare_common(args)
    assert subprocess_called is False


def test_overlay_worker_revalidates_serialized_nested_override(tmp_path: Path) -> None:
    overrides = tmp_path / "worker_overrides.json"
    overrides.write_text(
        json.dumps({"expected_pe": {"worker_only_unknown": True}}),
        encoding="utf-8",
    )
    args = Namespace(
        input_csv=tmp_path / "must-not-be-read.csv",
        output_csv=tmp_path / "output.csv",
        diagnostics_json=tmp_path / "diagnostics.json",
        overrides_json=overrides,
        config=ROOT / "config" / "v04_bottleneck.yaml",
        model_seed=500_011,
        outer_jobs=32,
        adapter="in-memory",
    )
    with pytest.raises(ValueError, match="expected_pe: unknown keys"):
        harness._overlay_worker(args)
    assert not Path(args.output_csv).exists()


def _analysis_surface_frames(
    optional_values: list[float],
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    rows = len(optional_values)
    dates = pd.date_range(harness.PRODUCTION_EVALUATION_START, periods=rows, freq="D")
    canonical_data: dict[str, object] = {
        "date": dates,
        "observed_pe": np.linspace(10.0, 11.0, rows),
        "ml_expected_pe": np.linspace(10.2, 11.2, rows),
        "benchmark_close": np.linspace(100.0, 101.0, rows),
    }
    canonical_data.update(
        {
            f"canonical_{position:03d}": float(position)
            for position in range(harness.CANONICAL_V03_COLUMNS - len(canonical_data))
        }
    )
    canonical = pd.DataFrame(canonical_data)

    output = canonical.copy()
    output["v04_expected_pe"] = np.linspace(10.1, 11.1, rows)
    output["v04_fundamental_vintage_expected_pe"] = optional_values
    for prefix in ("", "v04_current_", "v04_return_forecast_"):
        output[f"{prefix}p_bear"] = 0.2
        output[f"{prefix}p_sideways"] = 0.6
        output[f"{prefix}p_bull"] = 0.2
    truth = pd.DataFrame(
        {
            "date": dates,
            "true_fair_pe": np.linspace(10.0, 11.0, rows),
            "true_regime": ["SIDEWAYS"] * rows,
        }
    )
    return canonical, truth, output


def _analyze_optional_surface(
    monkeypatch: pytest.MonkeyPatch,
    optional_values: list[float],
    *,
    enabled: bool,
    selection_column: str = "v04_expected_pe",
) -> dict:
    canonical, truth, output = _analysis_surface_frames(optional_values)
    paths = {
        Path("canonical.csv"): canonical,
        Path("truth.csv"): truth,
        Path("output.csv"): output,
    }
    monkeypatch.setattr(harness, "_read_csv", lambda path: paths[Path(path)].copy())
    monkeypatch.setattr(
        harness,
        "validate_no_harm_gates",
        lambda *args, **kwargs: {"pass": True, "failure_count": 0, "gates": {}},
    )
    effective = harness._load_yaml_config(ROOT / "config" / "v04_bottleneck.yaml")
    effective["fundamental_vintage"]["enabled"] = enabled
    candidate = {
        "selection_column": selection_column,
        "overrides": {},
    }
    return harness.analyze_overlay_output(
        Path("canonical.csv"),
        Path("truth.csv"),
        Path("output.csv"),
        candidate,
        effective,
    )


def test_analyze_records_default_off_all_nan_optional_surface_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _analyze_optional_surface(
        monkeypatch,
        [np.nan, np.nan, np.nan, np.nan],
        enabled=False,
    )

    metric = result["candidate_suite_vs_anti_gaming"]["v04_fundamental_vintage_expected_pe"]
    assert metric["status"] == "unavailable"
    assert metric["reason"] == "configured_disabled_and_all_values_missing"
    assert metric["configured_enabled"] is False
    assert metric["evaluation_scope_rows"] == 4
    assert metric["common_rows"] == 0
    assert metric["coverage"] == 0.0
    assert metric["baseline"] is None
    assert all(metric["common_rows"] == 4 for metric in result["dual_comparator_paired"].values())


def test_analyze_selected_all_nan_optional_surface_remains_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(harness.ValidationError, match="full natural daily coverage"):
        _analyze_optional_surface(
            monkeypatch,
            [np.nan, np.nan, np.nan, np.nan],
            enabled=False,
            selection_column="v04_fundamental_vintage_expected_pe",
        )


@pytest.mark.parametrize(
    ("optional_values", "expected_common_rows"),
    [
        ([np.nan, 10.4, 10.8, 11.2], 3),
        ([10.0, 10.4, 10.8, 11.2], 4),
    ],
)
def test_analyze_enabled_optional_surface_preserves_partial_and_full_metrics(
    monkeypatch: pytest.MonkeyPatch,
    optional_values: list[float],
    expected_common_rows: int,
) -> None:
    result = _analyze_optional_surface(
        monkeypatch,
        optional_values,
        enabled=True,
    )

    metric = result["candidate_suite_vs_anti_gaming"]["v04_fundamental_vintage_expected_pe"]
    assert metric["status"] == "available"
    assert metric["configured_enabled"] is True
    assert metric["common_rows"] == expected_common_rows
    assert metric["coverage"] == pytest.approx(expected_common_rows / 4.0)
    assert metric["baseline"]["fair_log_mae"] >= 0.0
    assert metric["challenger"]["fair_log_mae"] >= 0.0


def test_analyze_enabled_all_nan_optional_surface_remains_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(harness.ValidationError, match="paired finite-positive fair mask is empty"):
        _analyze_optional_surface(
            monkeypatch,
            [np.nan, np.nan, np.nan, np.nan],
            enabled=True,
        )


def test_analyze_disabled_optional_surface_rejects_partial_emission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(
        harness.ValidationError,
        match="disabled optional expected-P/E surface .* emitted values",
    ):
        _analyze_optional_surface(
            monkeypatch,
            [np.nan, 10.4, np.nan, np.nan],
            enabled=False,
        )


@pytest.mark.parametrize(
    ("comparator_column", "bad_value"),
    [("v04_expected_pe", np.nan), ("ml_expected_pe", 0.0)],
)
def test_analyze_rejects_differing_dual_comparator_coverage(
    monkeypatch: pytest.MonkeyPatch,
    comparator_column: str,
    bad_value: float,
) -> None:
    canonical, truth, output = _analysis_surface_frames([10.0, 10.4, 10.8, 11.2])
    output.loc[1, comparator_column] = bad_value
    paths = {
        Path("canonical.csv"): canonical,
        Path("truth.csv"): truth,
        Path("output.csv"): output,
    }
    monkeypatch.setattr(harness, "_read_csv", lambda path: paths[Path(path)].copy())
    monkeypatch.setattr(
        harness,
        "validate_no_harm_gates",
        lambda *args, **kwargs: {"pass": True, "failure_count": 0, "gates": {}},
    )
    effective = harness._load_yaml_config(ROOT / "config" / "v04_bottleneck.yaml")
    with pytest.raises(harness.ValidationError, match="full natural daily coverage"):
        harness.analyze_overlay_output(
            Path("canonical.csv"),
            Path("truth.csv"),
            Path("output.csv"),
            harness.DEFAULT_CANDIDATES["current"],
            effective,
        )


def test_analyze_path_revalidates_effective_config_before_reading_artifacts(
    tmp_path: Path,
) -> None:
    effective = harness._load_yaml_config(ROOT / "config" / "v04_bottleneck.yaml")
    effective["final_guard"]["improvement_margin"] = -1.0
    with pytest.raises(ValueError, match="improvement_margin must be finite and non-negative"):
        harness.analyze_overlay_output(
            tmp_path / "canonical-must-not-be-read.csv",
            tmp_path / "truth-must-not-be-read.csv",
            tmp_path / "output-must-not-be-read.csv",
            harness.DEFAULT_CANDIDATES["current"],
            effective,
        )


def _effective_model_config(
    *,
    return_forecast: bool,
    gate_margin: float = 0.0,
    lagged_enabled: bool = False,
    smoothing_enabled: bool = False,
    matured_proxy_enabled: bool = False,
):
    return {
        "regime_stacker": {"horizon": 21, "outer_n_jobs": 32},
        "expected_pe": {
            "include_return_forecast_features": return_forecast,
            "outer_n_jobs": 32,
        },
        "fundamental_vintage": {"enabled": True},
        "lagged_market_conditioned": {"enabled": lagged_enabled},
        "ml_incumbent_weekly_median_shrinkage": {"enabled": smoothing_enabled},
        "matured_proxy_gate": {"enabled": matured_proxy_enabled},
        "ml_incumbent_gate": {"improvement_margin": gate_margin},
    }


def test_one_representative_per_unique_effective_model_config_gets_reruns() -> None:
    effective = {
        "a_first": _effective_model_config(return_forecast=False),
        "b_gate": _effective_model_config(return_forecast=False, gate_margin=0.01),
        "c_gate": _effective_model_config(return_forecast=False, gate_margin=0.02),
        "d_forecast": _effective_model_config(return_forecast=True, gate_margin=0.02),
        "e_lagged": _effective_model_config(
            return_forecast=False,
            lagged_enabled=True,
        ),
        "f_smoothing": _effective_model_config(
            return_forecast=False,
            smoothing_enabled=True,
        ),
        "g_matured": _effective_model_config(
            return_forecast=False,
            matured_proxy_enabled=True,
        ),
    }
    plan = harness._build_invariance_plan(effective)
    args = Namespace(tuning_seeds=(11, 23, 37), invariance_plan=plan)
    invocations = [
        harness._requires_expensive_invariance_check(
            stage="tuning", seed=seed, name=name, args=args
        )
        for seed in args.tuning_seeds
        for name in effective
    ]
    assert len(plan["groups"]) == 5
    assert sum(invocations) == 5
    assert harness._requires_expensive_invariance_check(
        stage="tuning", seed=11, name="a_first", args=args
    )
    assert harness._requires_expensive_invariance_check(
        stage="tuning", seed=11, name="d_forecast", args=args
    )
    assignments = plan["candidate_assignments"]
    assert assignments["a_first"] == assignments["b_gate"] == assignments["c_gate"]
    assert assignments["d_forecast"] != assignments["a_first"]
    assert assignments["e_lagged"] != assignments["a_first"]
    assert assignments["f_smoothing"] != assignments["a_first"]
    assert assignments["f_smoothing"] != assignments["e_lagged"]
    assert assignments["g_matured"] != assignments["a_first"]
    assert assignments["g_matured"] != assignments["e_lagged"]
    assert assignments["g_matured"] != assignments["f_smoothing"]
    assert assignments["b_gate"]["representative_candidate"] == "a_first"
    assert assignments["d_forecast"]["representative_candidate"] == "d_forecast"


def test_group_invariance_evidence_fails_closed_when_missing_or_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = {
        "a_current": {},
        "b_same": {},
        "c_forecast": {},
    }
    plan = harness._build_invariance_plan(
        {
            "a_current": _effective_model_config(return_forecast=False),
            "b_same": _effective_model_config(return_forecast=False, gate_margin=0.01),
            "c_forecast": _effective_model_config(return_forecast=True),
        }
    )

    def representative_record(name: str) -> dict[str, object]:
        assignment = plan["candidate_assignments"][name]
        evidence = {
            "required": True,
            "pass": True,
            "evidence_seed": 11,
            "comparison": "serial-vs-32",
            "serial_outer_jobs": 1,
            "parallel_outer_jobs": 32,
            **assignment,
        }
        return {
            "stage": "tuning",
            "seed": 11,
            "candidate": name,
            "invariance_assignment": assignment,
            "serial_vs_parallel_determinism": dict(evidence),
            "causal_prefix_invariance": dict(evidence),
            "result_sha256": f"result-{name}",
        }

    representatives = {
        group["representative_candidate"]: representative_record(group["representative_candidate"])
        for group in plan["groups"].values()
    }
    checkpoint = {"runs": {"tuning": {"11": representatives}}}
    monkeypatch.setattr(harness, "_verify_result_record", lambda record, **kwargs: None)
    verified = harness._verified_invariance_group_evidence(
        checkpoint,
        candidates,
        plan,
        first_tuning_seed=11,
    )
    assert set(verified) == set(plan["groups"])

    missing = {"runs": {"tuning": {"11": dict(representatives)}}}
    missing["runs"]["tuning"]["11"].pop("c_forecast")
    with pytest.raises(harness.ValidationError, match="representative .* missing"):
        harness._verified_invariance_group_evidence(
            missing,
            candidates,
            plan,
            first_tuning_seed=11,
        )

    failed = {"runs": {"tuning": {"11": dict(representatives)}}}
    failed_record = dict(failed["runs"]["tuning"]["11"]["c_forecast"])
    failed_record["causal_prefix_invariance"] = dict(failed_record["causal_prefix_invariance"])
    failed_record["causal_prefix_invariance"]["pass"] = False
    failed["runs"]["tuning"]["11"]["c_forecast"] = failed_record
    with pytest.raises(harness.ValidationError, match="failed causal_prefix_invariance"):
        harness._verified_invariance_group_evidence(
            failed,
            candidates,
            plan,
            first_tuning_seed=11,
        )


def test_forward_proxy_is_distinct_and_horizon_matured() -> None:
    close = pd.Series(np.linspace(100.0, 140.0, 30))
    proxy = harness._forward_return_proxy(
        close,
        horizon=21,
        bull_threshold=0.03,
        bear_threshold=-0.03,
    )
    assert proxy.iloc[:9].eq("BULL").all()
    assert proxy.iloc[-21:].isna().all()


def test_holdout_manifest_cannot_be_created_before_tune(tmp_path: Path) -> None:
    with pytest.raises(harness.ValidationError, match="tune must create"):
        harness._load_or_create_manifest(
            tmp_path / "run_manifest.json",
            {"format_version": 1},
            allow_create=False,
        )


def test_cli_deliberately_has_no_all_stage() -> None:
    parser = harness.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["all"])


@pytest.mark.parametrize("command", ["tune", "lock", "holdout"])
def test_cli_defaults_to_the_fixed_parallel32_contract(command: str) -> None:
    args = harness.build_parser().parse_args([command])
    assert args.outer_jobs == 32
