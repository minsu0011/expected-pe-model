"""Score-free invariants for the sealed A--J DGP implementation.

Every seed in this module is explicitly a non-evidence fixture.  These tests do
not import, fit, predict, rank, or score a candidate model.
"""

from __future__ import annotations

from dataclasses import replace
from functools import lru_cache
import base64
import hashlib
import json
import math
from pathlib import Path
from types import MappingProxyType

import numpy as np
import pandas as pd
import pytest

from pe_regime_v04.model_lab import prepare_model_input, prepare_pit_feature_sidecar_asof
from pe_regime_v04.model_lab.contracts import ContractError

from research.model_zoo.dgp_suite import (
    COMMON_MASK_POLICY_SHA256,
    ENTITY_ID,
    EXPECTED_ELIGIBLE_COUNTS,
    FIXTURE_MASTER_SEED,
    FIXTURE_ROLE,
    ROWS,
    SCORE_END,
    SCORE_START,
    DGPContractError,
    FixtureSeed,
    PrimaryCandidateSurface,
    VerifiedCommonMask,
    VerifiedComparatorArtifact,
    VerifiedEvaluatorTruthArtifact,
    VerifiedFixedComparatorBundle,
    artifact_bytes,
    align_primary_comparators,
    build_verified_common_mask,
    execution_contract_payload,
    generate_dgp,
    load_fixed_fixture_trust_root,
    load_sealed_execution_contract,
    prepare_primary_candidate_surface,
    public_factor_metadata,
    require_primary_candidate_surface,
    validate_canonical150_output,
    validate_scoreable_public_surface,
    verify_fixed_comparator_bundle,
    verify_replayable_non_evidence_bundle,
    verified_public_factor_sidecar,
    write_dgp_artifacts,
)
from research.model_zoo.dgp_suite.artifacts import canonical_csv_bytes
from research.model_zoo.dgp_suite.boundary import (
    CANONICAL_HEADER_SHA256,
    canonical_json_bytes,
    load_comparator_production_policy,
    reject_forbidden_columns,
    sealed_canonical_header,
)
from research.model_zoo.dgp_suite.common_mask import _build_common_mask_frames
from research.model_zoo.dgp_suite.design import (
    DESIGN_JSON_SHA256,
    DESIGN_MD_SHA256,
    STRUCTURAL_PARAMETERS_SHA256,
    generator_source_hashes,
    implementation_source_hashes,
    load_design_seal,
)
from research.model_zoo.dgp_suite.execution_snapshot import (
    RUNTIME_ATTESTATION_POLICY_RAW_SHA256,
    RUNTIME_MANIFEST_VERSION,
    RUNTIME_SOURCE_SNAPSHOT_VERSION,
    SNAPSHOT_VERSION,
    capture_execution_snapshot,
    code_object_sha256,
    load_runtime_attestation_policy,
    verify_child_execution_attestation,
    verify_content_addressed_snapshot,
    verify_snapshot_in_child,
    write_content_addressed_snapshot,
)
from research.model_zoo.dgp_suite import execution_snapshot as execution_snapshot_module
from research.model_zoo.dgp_suite.fixture_trust import (
    FIXED_FIXTURE_TRUST_ROOT_RAW_SHA256,
    GENERATOR_CAPABILITY_POLICY_RAW_SHA256,
)
from research.model_zoo.dgp_suite.generator import (
    FORBIDDEN_PUBLIC_PREFIXES,
    PIT_COLUMNS,
    GeneratedDGP,
)
from research.model_zoo.dgp_suite.model_surface import MODEL_SURFACE_VERSION
from research.model_zoo.dgp_suite.primary_surface import (
    _transform_canonical_components,
    primary_transformation_sha256,
)
from research.model_zoo.dgp_suite.rng import named_rng, substream_digest, substream_material
from research.model_zoo.dgp_suite.sidecar import canonical_pit_csv_bytes
from research.model_zoo.dgp_suite.v5_adapter import (
    V03_ARCHIVE_SHA256,
    V03_DEMO_MEMBER_SHA256,
    xnys_schedule,
)


FIXTURE = FixtureSeed(FIXTURE_MASTER_SEED)

_DGP_SUITE_ROOT = Path(__file__).resolve().parents[2] / "research" / "model_zoo" / "dgp_suite"
_KNOWN_UNSEALED_CONTRACT_TRANSITION = {
    "sealed_raw_sha256": "ca53195bf49ceda5f1ab14dbe7c208ed15e77257a00018b8311929fdc6cd8935",
    "sealed_contract_sha256": "e3a17ef212aa232b941a588e81700b1e1add82123414ba4909bae8ea893b6f82",
    "sealed_implementation_sha256": (
        "66b9ee660c05a6083e4a7f95f85d22df543cb736162ba65e74bf56d31558e9ea"
    ),
    "current_contract_sha256": "f07e7edf70ba179af8ca1304417aa8f129c8587faf5ad377cef608150f74263f",
    "current_implementation_sha256": (
        "3d6ec80ecea4d74029c2548165888707f69056d1f4548ea963e94b272e1b39b4"
    ),
}
_KNOWN_UNSEALED_RUNTIME_POLICY_TRANSITION = {
    "sealed_raw_sha256": "a2d2cd35f3ba2a3896f14eaa13a17f4477190196098c618589391bdc2a090c0a",
    "current_raw_sha256": "858d7f4f6370290061ccdc08f9c86bd7e69bf9346034bbf68db3ace3a4f3ba03",
}


def _xfail_exact_known_unsealed_contract_transition() -> None:
    sealed_raw = (_DGP_SUITE_ROOT / "EXECUTION_CONTRACT.json").read_bytes()
    sealed = json.loads(sealed_raw)
    current = dict(execution_contract_payload())
    if sealed == current:
        return

    transition = _KNOWN_UNSEALED_CONTRACT_TRANSITION
    assert hashlib.sha256(sealed_raw).hexdigest() == transition["sealed_raw_sha256"]
    differences = {
        key: (sealed.get(key), current.get(key))
        for key in sorted(set(sealed) | set(current))
        if sealed.get(key) != current.get(key)
    }
    assert differences == {
        "contract_sha256": (
            transition["sealed_contract_sha256"],
            transition["current_contract_sha256"],
        ),
        "dgp_suite_implementation_combined_sha256": (
            transition["sealed_implementation_sha256"],
            transition["current_implementation_sha256"],
        ),
    }
    assert current["execution_authorized"] is False
    assert current["score_computation_authorized"] is False
    pytest.xfail("exact known score-free DGP V5 transition remains intentionally unsealed")


def _xfail_exact_known_unsealed_runtime_policy_transition() -> None:
    policy_raw = (_DGP_SUITE_ROOT / "RUNTIME_ATTESTATION_POLICY.json").read_bytes()
    current_raw_sha256 = hashlib.sha256(policy_raw).hexdigest()
    if current_raw_sha256 == RUNTIME_ATTESTATION_POLICY_RAW_SHA256:
        return

    transition = _KNOWN_UNSEALED_RUNTIME_POLICY_TRANSITION
    assert RUNTIME_ATTESTATION_POLICY_RAW_SHA256 == transition["sealed_raw_sha256"]
    assert current_raw_sha256 == transition["current_raw_sha256"]
    policy = json.loads(policy_raw)
    assert set(policy["authorization"].values()) == {False}
    pytest.xfail("exact known score-free DGP V5 runtime policy remains intentionally unsealed")


def _synthetic_loaded_bytes_attestation() -> tuple[
    dict[str, object], bytes, bytes, dict[str, dict[str, object]], str
]:
    snapshot_sha256 = "a" * 64
    dependency_raw = b"VALUE = 7\n"
    dependency_sha256 = hashlib.sha256(dependency_raw).hexdigest()
    executable_sha256 = "e" * 64
    dependency_origin = "test-runtime/dependency.py"
    process_origin = "python-process-image"
    process_path_key = "c:/sealed/python.exe"
    runtime_manifest = {
        "distributions": {
            "test_runtime": {
                "files": {
                    "test-runtime/dependency.py": {
                        "absolute_path": "C:/sealed/test-runtime/dependency.py",
                        "is_package": False,
                        "module_name": "test_runtime.dependency",
                        "origin_id": dependency_origin,
                        "sha256": dependency_sha256,
                        "size": len(dependency_raw),
                    }
                },
                "root": "C:/sealed/test-runtime",
            }
        },
        "manifest_version": RUNTIME_MANIFEST_VERSION,
        "python_executable": {
            "absolute_path": "C:/sealed/python.exe",
            "sha256": executable_sha256,
        },
        "process_image": {
            "absolute_path": "C:/sealed/python.exe",
            "origin_id": process_origin,
            "sha256": executable_sha256,
            "size": 11,
        },
        "stdlib": {"files": {}, "roots": []},
    }
    runtime_manifest_bytes = canonical_json_bytes(runtime_manifest)
    runtime_source_snapshot = canonical_json_bytes(
        {
            "modules": {
                "test_runtime.dependency": {
                    "is_package": False,
                    "logical_path": dependency_origin,
                    "origin_id": dependency_origin,
                    "source_base64": base64.b64encode(dependency_raw).decode("ascii"),
                    "source_class": "distribution/test_runtime",
                    "source_sha256": dependency_sha256,
                }
            },
            "snapshot_version": RUNTIME_SOURCE_SNAPSHOT_VERSION,
        }
    )
    runtime_source_sha256 = hashlib.sha256(runtime_source_snapshot).hexdigest()
    combined_source_sha256 = hashlib.sha256(
        canonical_json_bytes([runtime_source_sha256])
    ).hexdigest()
    source_raw = b"VALUE = 1\n"
    logical_path = "sealed_test_package/__init__.py"
    filename = f"sealed-memory://{snapshot_sha256}/{logical_path}"
    project_sources: dict[str, dict[str, object]] = {
        "sealed_test_package": {
            "is_package": True,
            "logical_path": logical_path,
            "raw": source_raw,
        }
    }
    project_modules = {
        "sealed_test_package": {
            "code_filename": filename,
            "code_sha256": code_object_sha256(
                compile(source_raw, filename, "exec", dont_inherit=True, optimize=0)
            ),
            "is_package": True,
            "logical_path": logical_path,
            "source_sha256": hashlib.sha256(source_raw).hexdigest(),
        }
    }
    project = {"modules": project_modules}
    project["manifest_sha256"] = hashlib.sha256(canonical_json_bytes(project)).hexdigest()
    runtime = {
        "enumeration": {
            "non_system_module_count": 1,
            "non_system_path_set_sha256": hashlib.sha256(
                canonical_json_bytes([process_path_key])
            ).hexdigest(),
            "observed_process_module_count": 1,
            "observed_process_path_set_sha256": hashlib.sha256(
                canonical_json_bytes([process_path_key])
            ).hexdigest(),
            "system_module_count": 0,
            "system_path_set_sha256": hashlib.sha256(canonical_json_bytes([])).hexdigest(),
        },
        "modules": {
            "test_runtime.dependency": {
                "code_filename": (f"sealed-runtime://{combined_source_sha256}/{dependency_origin}"),
                "code_sha256": code_object_sha256(
                    compile(
                        dependency_raw,
                        f"sealed-runtime://{combined_source_sha256}/{dependency_origin}",
                        "exec",
                        dont_inherit=True,
                        optimize=0,
                    )
                ),
                "is_package": False,
                "kind": "sealed-memory-source",
                "origin_id": dependency_origin,
                "payload_sha256": dependency_sha256,
                "source_class": "distribution/test_runtime",
            }
        },
        "native_libraries": {
            process_path_key: {
                "kind": "process-image",
                "origin_id": process_origin,
                "path_key": process_path_key,
                "payload_sha256": executable_sha256,
            }
        },
        "source_snapshot_sha256": combined_source_sha256,
    }
    runtime["manifest_sha256"] = hashlib.sha256(canonical_json_bytes(runtime)).hexdigest()
    approved_sha256 = hashlib.sha256(
        canonical_json_bytes(
            {
                dependency_origin: dependency_sha256,
                process_origin: executable_sha256,
            }
        )
    ).hexdigest()
    attestation: dict[str, object] = {
        "approved_payload_sha256": approved_sha256,
        "postflight_sha256": approved_sha256,
        "preflight_sha256": approved_sha256,
        "project": project,
        "runtime": runtime,
        "runtime_manifest_sha256": hashlib.sha256(runtime_manifest_bytes).hexdigest(),
        "stage": "synthetic",
    }
    attestation["attestation_sha256"] = hashlib.sha256(
        canonical_json_bytes(attestation)
    ).hexdigest()
    return (
        attestation,
        runtime_manifest_bytes,
        runtime_source_snapshot,
        project_sources,
        snapshot_sha256,
    )


def _reseal_synthetic_attestation(attestation: dict[str, object]) -> None:
    runtime = attestation["runtime"]
    runtime["manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {
                "enumeration": runtime["enumeration"],
                "modules": runtime["modules"],
                "native_libraries": runtime["native_libraries"],
                "source_snapshot_sha256": runtime["source_snapshot_sha256"],
            }
        )
    ).hexdigest()
    attestation.pop("attestation_sha256", None)
    attestation["attestation_sha256"] = hashlib.sha256(
        canonical_json_bytes(attestation)
    ).hexdigest()


@lru_cache(maxsize=10)
def _generated(dgp_id: str) -> GeneratedDGP:
    return generate_dgp(dgp_id, fixture_seed=FIXTURE)


def _canonical_stub(dates: pd.Series) -> pd.DataFrame:
    data: dict[str, object] = {"date": dates.astype(str).str[:10].tolist()}
    for index in range(149):
        data[f"input_{index:03d}"] = np.zeros(len(dates), dtype=np.float64)
    return pd.DataFrame(data)


def _cutoffs(dates: pd.Series) -> pd.Series:
    values = pd.to_datetime(dates.astype(str).str[:10]).dt.tz_localize("UTC") + pd.Timedelta(
        hours=12, minutes=30
    )
    return pd.Series(values.array, index=dates.index)


def test_design_and_fixture_boundary_are_pinned_and_score_free() -> None:
    seal = load_design_seal()
    assert seal.design_md_sha256 == DESIGN_MD_SHA256
    assert seal.design_json_sha256 == DESIGN_JSON_SHA256
    assert seal.structural_parameters_sha256 == STRUCTURAL_PARAMETERS_SHA256
    assert (
        seal.design["status"]
        == "design_only_outputs_only_no_scores_no_seed_reservation_no_execution_no_production_change"
    )
    assert FIXTURE.role == FIXTURE_ROLE
    source_hashes, combined = implementation_source_hashes()
    assert len(source_hashes) == 14
    assert len(combined) == 64
    assert all(len(value) == 64 for value in source_hashes.values())
    with pytest.raises(DGPContractError, match="non-evidence"):
        FixtureSeed(1, role="TUNING")
    with pytest.raises(DGPContractError, match="non-negative integer"):
        FixtureSeed(True)


def test_named_rng_material_and_substreams_are_exact_and_independent() -> None:
    expected = (
        "model_lab_multi_dgp_AJ_v1|master_seed=2026081901|dgp=F|component=rate|issuer=0"
    ).encode("ascii")
    assert substream_material(FIXTURE, dgp_id="F", component="rate") == expected
    assert (
        substream_digest(FIXTURE, dgp_id="F", component="rate")
        == hashlib.sha256(expected).hexdigest()
    )
    first = named_rng(FIXTURE, dgp_id="F", component="rate").normal(size=16)
    repeat = named_rng(FIXTURE, dgp_id="F", component="rate").normal(size=16)
    other = named_rng(FIXTURE, dgp_id="F", component="missingness_x2").normal(size=16)
    np.testing.assert_array_equal(first, repeat)
    assert not np.array_equal(first, other)


def test_xnys_schedule_is_exact_monotonic_and_uses_aware_closes() -> None:
    schedule = xnys_schedule()
    assert len(schedule.sessions) == ROWS
    assert schedule.sessions[0] == pd.Timestamp("2013-01-02")
    assert pd.DatetimeIndex(schedule.sessions).is_unique
    assert pd.DatetimeIndex(schedule.sessions).is_monotonic_increasing
    assert all(value.tzinfo is not None for value in schedule.session_closes_utc)
    assert all(
        previous < current
        for previous, current in zip(
            schedule.previous_session_closes_utc, schedule.session_closes_utc, strict=True
        )
    )


def test_a_is_exact_sealed_v5_reference_not_a_reimplementation() -> None:
    generated = _generated("A")
    assert generated.generation_audit["reference_archive_sha256"] == V03_ARCHIVE_SHA256
    assert generated.generation_audit["reference_source_member_sha256"] == V03_DEMO_MEMBER_SHA256
    assert generated.generation_audit["reference_raw_sha256"] == {
        "benchmark": "cc7d9ed35b9f69a9165ddc5d5611920dfde1d866f7f98e915f509ca6364662f2",
        "eps": "68b7ae904e0aba4bdfd57252c37aa5d0be10327d2a1382aa61d7fbb3f51ab188",
        "price": "95e3d96f0c71a6764480ecb18308fa15b9e65d1b42d101be43560f6059bf4a74",
        "price_split_adjusted": (
            "67e009c7f516da78f4479ab63241181403ab8de7feabfc780eeac41ffc15df64"
        ),
        "truth": "d19b49d291450d45569f452879234b50ab08bde67fa709d601583c3b1ebc2613",
    }
    public_bytes, evaluator_bytes = artifact_bytes(generated)
    for name in ("price", "benchmark", "eps_events"):
        assert public_bytes[name] == generated.exact_public_bytes[name]
    assert evaluator_bytes["truth"] == generated.exact_evaluator_bytes["truth"]


@pytest.mark.parametrize("dgp_id", tuple("ABCDEFGHIJ"))
def test_every_dgp_has_exact_public_evaluator_split_and_scoreable_raw_surface(
    dgp_id: str,
) -> None:
    generated = _generated(dgp_id)
    assert generated.rows == ROWS
    assert set(generated.public) == {
        "price",
        "benchmark",
        "eps_events",
        "public_factors",
        "corporate_actions",
    }
    assert set(generated.evaluator_only) == {"truth", "latent_events"}
    assert len(generated.public["price"]) == ROWS
    assert len(generated.public["benchmark"]) == ROWS
    assert len(generated.evaluator_only["truth"]) == ROWS
    for frame in generated.public.values():
        assert not any(str(column).startswith(FORBIDDEN_PUBLIC_PREFIXES) for column in frame)
        assert "true_fair_pe" not in frame
    assert "true_fair_pe" in generated.evaluator_only["truth"]
    assert generated.generation_audit["model_executed"] is False
    assert generated.generation_audit["candidate_score_computed"] is False
    assert generated.generation_audit["seed_filtering_performed"] is False
    assert (
        generated.generation_audit["structural_parameters_sha256"] == STRUCTURAL_PARAMETERS_SHA256
    )
    assert generated.generation_audit["generator_combined_sha256"] == generator_source_hashes()[1]
    validate_scoreable_public_surface(generated)


@pytest.mark.parametrize("dgp_id", tuple("BCDEFGHIJ"))
def test_b_to_j_long_sidecars_are_accepted_by_frozen_verified_loader(dgp_id: str) -> None:
    generated = _generated(dgp_id)
    sidecar = verified_public_factor_sidecar(generated)
    normalized = sidecar.to_frame()
    assert tuple(normalized.columns) == PIT_COLUMNS
    assert len(normalized) == len(generated.public["public_factors"])
    assert (
        normalized["available_at"]
        .le(
            pd.to_datetime(normalized["effective_session"], utc=True)
            + pd.Timedelta(hours=12, minutes=30)
        )
        .all()
    )


def test_common_eps_equation_release_lags_and_preavailability_history_are_exact() -> None:
    generated = _generated("B")
    events = generated.public["eps_events"].reset_index(drop=True)
    innovations = np.clip(
        named_rng(FIXTURE, dgp_id="B", component="eps").normal(size=len(events)), -4.0, 4.0
    )
    expected = np.empty(len(events), dtype=np.float64)
    expected[0] = 2.2
    for quarter in range(1, len(expected)):
        expected[quarter] = expected[quarter - 1] * max(
            0.97,
            1.0 + 0.015 + 0.010 * math.sin(quarter / 5.0) + 0.006 * innovations[quarter],
        )
    np.testing.assert_allclose(events["eps_ttm"], expected, rtol=0.0, atol=1e-14)
    position = {date: row for row, date in enumerate(generated.public["price"]["date"].astype(str))}
    effective_rows = [position[str(value)] for value in events["effective_session"]]
    assert effective_rows == [quarter * 63 + (2, 5, 8)[quarter % 3] for quarter in range(29)]
    truth = generated.evaluator_only["truth"]
    assert truth.loc[:1, "true_pit_eps"].isna().all()
    assert truth.loc[2, "true_pit_eps"] == pytest.approx(expected[0])
    assert truth.loc[67, "true_pit_eps"] == pytest.approx(expected[0])
    assert truth.loc[68, "true_pit_eps"] == pytest.approx(expected[1])


@pytest.mark.parametrize("dgp_id", tuple("BCDEFGHIJ"))
def test_b_to_j_fair_equations_and_observed_price_identity_are_exact(dgp_id: str) -> None:
    generated = _generated(dgp_id)
    truth = generated.evaluator_only["truth"]
    latent = generated.evaluator_only["latent_events"]
    factors = (
        generated.public["public_factors"]
        .pivot(index="effective_session", columns="factor_id", values="value")
        .reset_index(drop=True)
    )
    h = latent["latent_hidden_residual"].to_numpy(dtype=np.float64)
    rows = np.arange(ROWS)
    if dgp_id == "B":
        expected = (
            math.log(23.0)
            - 0.090 * np.tanh(factors["rate_r"])
            + 0.070 * np.tanh(factors["pit_eps_growth_g"])
            + 0.050 * np.sin(np.pi * factors["calendar_cal"] / 2.0)
            + h
        )
    elif dgp_id == "C":
        expected = (
            math.log(22.0)
            + 0.055 * factors["x1"]
            - 0.045 * factors["x4"]
            + 0.035 * factors["x7"]
            + 0.025 * factors["x10"]
            + h
        )
    elif dgp_id == "D":
        regime = latent["latent_regime"].to_numpy(dtype=np.int64)
        effect = np.asarray((-0.040, 0.0, 0.040))[regime]
        expected = (
            math.log(22.0)
            + effect
            + 0.100 * factors["x1"].gt(0.35)
            - 0.080 * factors["x2"].lt(-0.45)
            + 0.070 * factors["x1"].mul(factors["x3"]).gt(0.40)
            + 0.040 * np.sign(factors["x3"]) * np.minimum(np.abs(factors["x2"]), 1.0)
            + h
        )
    elif dgp_id == "E":
        expected = math.log(22.0) + 0.060 * factors["x1"] - 0.050 * factors["x2"] + h
    elif dgp_id == "F":
        expected = (
            math.log(22.0)
            - 0.040 * np.tanh(factors["short_rate_z"])
            + 0.055 * factors["x1"]
            + 0.045 * np.tanh(factors["x2"])
            + h
        )
    elif dgp_id == "G":
        expected = (
            math.log(26.0)
            + 0.080 * np.tanh(factors["sector_index_z"])
            - math.log(1.30) * (rows >= 990)
            + h
        )
    elif dgp_id == "H":
        expected = (
            math.log(22.0)
            + 0.050 * factors["x"]
            + latent["latent_pulse_up"]
            + latent["latent_pulse_down"]
            + h
        )
    elif dgp_id == "I":
        expected = math.log(21.0) + 0.050 * factors["x"] + h
    else:
        expected = math.log(22.0) + 0.080 * factors["x"] + 0.030 * factors["pit_eps_growth_g"] + h
    finite = np.isfinite(np.asarray(expected, dtype=np.float64))
    np.testing.assert_allclose(
        truth.loc[finite, "true_log_fair_pe"],
        np.asarray(expected)[finite],
        rtol=0.0,
        atol=1e-13,
    )
    reconstructed_close = (
        truth["true_economic_eps_contemporaneous"]
        * truth["true_fair_pe"]
        * np.exp(latent["latent_observation_error"] + latent["latent_contamination"])
    )
    np.testing.assert_allclose(
        generated.public["price"]["close"], reconstructed_close, rtol=0.0, atol=1e-12
    )
    assert (
        generated.public["price"]["high"]
        .ge(generated.public["price"][["open", "close"]].max(axis=1))
        .all()
    )
    assert (
        generated.public["price"]["low"]
        .le(generated.public["price"][["open", "close"]].min(axis=1))
        .all()
    )


def test_f_sidecar_selects_at_code_owned_1230_cutoff_and_rate_is_prior_close_plus_one() -> None:
    generated = _generated("F")
    raw = generated.public["public_factors"]
    schedule = xnys_schedule()
    rate = raw.loc[raw["factor_id"].eq("short_rate_z")].reset_index(drop=True)
    expected = pd.DatetimeIndex(schedule.previous_session_closes_utc) + pd.Timedelta(seconds=1)
    np.testing.assert_array_equal(
        pd.DatetimeIndex(pd.to_datetime(rate["available_at"], utc=True)).asi8,
        expected.asi8,
    )

    positions = [0, 503, 504, 900, 1799]
    dates = generated.public["price"].iloc[positions]["date"].reset_index(drop=True)
    prepared = prepare_model_input(_canonical_stub(dates), [])
    metadata = public_factor_metadata(generated)
    selected = prepare_pit_feature_sidecar_asof(
        prepared,
        verified_public_factor_sidecar(generated),
        metadata,
        decision_cutoffs=_cutoffs(dates),
        cutoff_policy_id="DGP_FUNDAMENTAL_1230_UTC",
        entity_ids=ENTITY_ID,
    )
    assert len(selected.prepared.features) == len(positions)
    assert selected.cutoff_policy_id == "DGP_FUNDAMENTAL_1230_UTC"
    assert (
        selected.raw_sidecar_sha256 == verified_public_factor_sidecar(generated).raw_sidecar_sha256
    )
    assert {name for name, _ in selected.factor_source_sha256} == {
        item.feature_id for item in metadata
    }
    with pytest.raises(ContractError, match="unknown code-owned cutoff"):
        prepare_pit_feature_sidecar_asof(
            prepared,
            verified_public_factor_sidecar(generated),
            metadata,
            decision_cutoffs=_cutoffs(dates),
            cutoff_policy_id="CALLER_CHOSEN_2359",
            entity_ids=ENTITY_ID,
        )


def test_f_missingness_is_explicit_causal_mar_and_never_masks_rate() -> None:
    generated = _generated("F")
    factors = generated.public["public_factors"]
    rate = factors.loc[factors["factor_id"].eq("short_rate_z")]
    assert not rate["is_missing"].any()
    for factor_id in ("x2", "x4", "x6"):
        values = factors.loc[factors["factor_id"].eq(factor_id)].reset_index(drop=True)
        flags = factors.loc[factors["factor_id"].eq(f"{factor_id}_missing")].reset_index(drop=True)
        np.testing.assert_array_equal(
            values["is_missing"].to_numpy(), flags["value"].eq(1).to_numpy()
        )
        assert values.loc[values["is_missing"], "value"].isna().all()
        assert np.isfinite(values.loc[~values["is_missing"], "value"]).all()
    latent_columns = generated.evaluator_only["latent_events"].columns
    assert "latent_missing_probability" in latent_columns
    assert "latent_missing_probability" not in factors.columns


def test_g_announcement_and_permanent_step_are_causal_and_exact() -> None:
    generated = _generated("G")
    factors = generated.public["public_factors"]
    sector = factors.loc[factors["factor_id"].eq("sector_index_z")].reset_index(drop=True)
    announcement = factors.loc[factors["factor_id"].eq("sector_shock_announcement")].reset_index(
        drop=True
    )
    assert announcement.loc[989, "value"] == 0.0
    assert announcement.loc[990, "value"] == -2.0
    assert announcement.loc[991, "value"] == 0.0
    assert pd.Timestamp(announcement.loc[990, "available_at"]) == pd.Timestamp(
        xnys_schedule().session_closes_utc[989]
    )
    # The exact public level step is the deterministic -2 intervention plus its AR path.
    assert abs((sector.loc[990, "value"] - sector.loc[989, "value"])) > 1.0
    truth = generated.evaluator_only["truth"]
    assert truth.loc[990, "true_fair_pe"] < truth.loc[989, "true_fair_pe"]
    assert not any("fair_jump" in str(column) for column in factors.columns)


def test_h_structural_events_have_exact_rows_and_hidden_future_decay() -> None:
    generated = _generated("H")
    event = (
        generated.public["public_factors"]
        .loc[generated.public["public_factors"]["factor_id"].eq("event_signed_magnitude")]
        .reset_index(drop=True)
    )
    nonzero = np.flatnonzero(event["value"].to_numpy(dtype=float))
    assert nonzero.tolist() == [684, 1296]
    assert event.loc[684, "value"] == pytest.approx(math.log(1.25))
    assert event.loc[1296, "value"] == pytest.approx(-math.log(1.20))
    assert pd.Timestamp(event.loc[684, "available_at"]) == pd.Timestamp(
        xnys_schedule().session_closes_utc[683]
    )
    assert "latent_pulse_up" in generated.evaluator_only["latent_events"]
    assert "latent_pulse_up" not in generated.public["public_factors"]


def test_i_amendment_actions_loss_masks_and_two_basis_ledgers_are_exact() -> None:
    generated = _generated("I")
    truth = generated.evaluator_only["truth"]
    events = generated.public["eps_events"]
    actions = generated.public["corporate_actions"]
    assert actions["new_shares_over_old_shares"].tolist() == [2.0, 0.25]
    assert actions["effective_session"].tolist() == [
        generated.public["price"].loc[810, "date"],
        generated.public["price"].loc[1404, "date"],
    ]
    q11 = events.loc[events["event_id"].str.startswith("I_Q11")].sort_values("revision_id")
    assert q11["revision_id"].tolist() == [0, 1]
    original_row = 11 * 63 + 8
    amendment_row = original_row + 35
    assert q11["effective_session"].tolist() == [
        generated.public["price"].loc[original_row, "date"],
        generated.public["price"].loc[amendment_row, "date"],
    ]
    assert truth.loc[amendment_row - 1, "true_pit_eps"] == pytest.approx(q11.iloc[0]["eps_ttm"])
    assert truth.loc[amendment_row, "true_pit_eps"] == pytest.approx(q11.iloc[1]["eps_ttm"])
    negative = truth["true_pit_eps"].le(0.0)
    assert negative.any()
    assert truth.loc[negative, "true_observed_pe"].isna().all()
    assert not truth.loc[negative, "true_expected_pe_eligible"].any()
    final_basis = float(truth.iloc[-1]["true_row_basis"])
    np.testing.assert_allclose(
        truth["true_final_snapshot_close"],
        generated.public["price"]["close"] * truth["true_row_basis"] / final_basis,
        rtol=0.0,
        atol=1e-12,
    )
    eligible = truth["true_pit_eps"].notna()
    np.testing.assert_allclose(
        truth.loc[eligible, "true_final_snapshot_pit_eps"],
        truth.loc[eligible, "true_pit_eps"] * truth.loc[eligible, "true_row_basis"] / final_basis,
        rtol=0.0,
        atol=1e-12,
    )


def test_j_proxy_correlation_inverts_while_proxy_coefficient_stays_zero() -> None:
    generated = _generated("J")
    factors = generated.public["public_factors"].pivot(
        index="effective_session", columns="factor_id", values="value"
    )
    before = factors.iloc[:1080]
    after = factors.iloc[1080:]
    assert before["x"].corr(before["z"]) > 0.65
    assert after["x"].corr(after["z"]) < -0.65
    assert "latent_rho" in generated.evaluator_only["latent_events"]
    assert "rho" not in factors.columns
    assert "break_row" not in factors.columns


@pytest.mark.parametrize("dgp_id", tuple("ABCDEFGHIJ"))
def test_full_vs_truncated_generation_has_exact_common_public_prefix(dgp_id: str) -> None:
    full = _generated(dgp_id)
    truncated = generate_dgp(dgp_id, fixture_seed=FIXTURE, rows=1000)
    for artifact in full.public:
        expected = full.public[artifact]
        if "date" in expected:
            expected = expected.iloc[:1000].reset_index(drop=True)
        elif "effective_session" in expected:
            last = full.public["price"].loc[999, "date"]
            expected = expected.loc[
                expected["effective_session"].astype(str).str[:10].le(last)
            ].reset_index(drop=True)
        elif "effective_date" in expected:
            last = full.public["price"].loc[999, "date"]
            expected = expected.loc[
                expected["effective_date"].astype(str).str[:10].le(last)
            ].reset_index(drop=True)
        pd.testing.assert_frame_equal(truncated.public[artifact], expected)


def test_adversarial_public_truth_column_and_sidecar_schema_drift_fail_closed(
    tmp_path: Path,
) -> None:
    generated = _generated("B")
    contaminated_price = generated.public["price"].assign(true_fair_pe=22.0)
    public = dict(generated.public)
    public["price"] = contaminated_price
    contaminated = replace(generated, public=MappingProxyType(public))
    with pytest.raises(DGPContractError, match="evaluator-only"):
        write_dgp_artifacts(contaminated, tmp_path / "contaminated")
    reordered = generated.public["public_factors"].loc[:, list(reversed(PIT_COLUMNS))]
    with pytest.raises(DGPContractError, match="frozen PIT schema"):
        canonical_pit_csv_bytes(reordered)


def test_physical_writer_is_deterministic_immutable_and_never_copies_truth_public(
    tmp_path: Path,
) -> None:
    generated = generate_dgp("B", fixture_seed=FIXTURE, rows=64)
    root = tmp_path / "DGP_B"
    first = write_dgp_artifacts(generated, root)
    second = write_dgp_artifacts(generated, root)
    assert first == second
    assert (root / "public" / "price.csv").is_file()
    assert (root / "evaluator_only" / "truth.csv").is_file()
    assert not (root / "public" / "truth.csv").exists()
    audit = json.loads((root / "evaluator_only" / "generation_audit.json").read_bytes())
    assert audit["candidate_score_computed"] is False
    assert audit["generator_capability_policy_raw_sha256"] == GENERATOR_CAPABILITY_POLICY_RAW_SHA256
    assert (root / "generation_capability.json").is_file()
    (root / "public" / "price.csv").write_bytes(b"tampered\n")
    with pytest.raises(DGPContractError, match="different bytes"):
        write_dgp_artifacts(generated, root)


def test_dual_comparator_contract_is_exact_truth_blind_and_not_authorized() -> None:
    _xfail_exact_known_unsealed_contract_transition()
    payload = dict(execution_contract_payload())
    assert dict(load_sealed_execution_contract()) == payload
    digest = payload.pop("contract_sha256")
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert digest == expected
    assert payload["surface_version"] == MODEL_SURFACE_VERSION
    comparators = {item["output_column"]: item for item in payload["comparators"]}
    assert set(comparators) == {"ml_expected_pe", "v04_expected_pe"}
    assert all(item["truth_access"] is False for item in comparators.values())
    assert all(item["row_alignment"].endswith("_at_t_minus_1") for item in comparators.values())
    assert all(item["raw_same_session_output_is_diagnostic_only"] for item in comparators.values())
    assert payload["truth_merge_stage"] == "evaluation_only_after_all_predictions"
    assert payload["canonical_header_sha256"] == CANONICAL_HEADER_SHA256
    assert payload["dgp_suite_implementation_combined_sha256"] == implementation_source_hashes()[1]
    assert payload["common_mask_policy_sha256"] == COMMON_MASK_POLICY_SHA256
    assert payload["primary_candidate_transformation_sha256"] == primary_transformation_sha256()
    assert payload["expected_eligible_counts"] == EXPECTED_ELIGIBLE_COUNTS
    assert payload["score_start_inclusive"] == SCORE_START
    assert payload["score_end_exclusive"] == SCORE_END
    assert payload["execution_authorized"] is False
    assert payload["score_computation_authorized"] is False

    raw = pd.DataFrame(
        {
            "date": ["2015-01-02", "2015-01-05", "2015-01-06"],
            "ml_expected_pe": [20.0, 21.0, 22.0],
            "v04_expected_pe": [23.0, 24.0, 25.0],
        }
    )
    with pytest.raises(DGPContractError, match="content-addressed"):
        align_primary_comparators(raw)
    with pytest.raises(DGPContractError, match="content-addressed"):
        validate_canonical150_output(raw)
    with pytest.raises(DGPContractError, match="content-addressed"):
        prepare_primary_candidate_surface(raw)  # type: ignore[arg-type]
    with pytest.raises(DGPContractError, match="exact pipeline"):
        VerifiedComparatorArtifact()


def test_public_artifact_bytes_repeat_exactly_without_any_score() -> None:
    first = artifact_bytes(_generated("E"))
    second = artifact_bytes(_generated("E"))
    assert first == second
    assert canonical_csv_bytes(_generated("E").evaluator_only["truth"]) not in first[0].values()


def test_evaluator_only_truth_intervention_cannot_change_any_public_artifact() -> None:
    generated = _generated("J")
    changed_truth = generated.evaluator_only["truth"].copy()
    changed_truth["true_fair_pe"] *= 1.5
    evaluator = dict(generated.evaluator_only)
    evaluator["truth"] = changed_truth
    intervened = replace(generated, evaluator_only=MappingProxyType(evaluator))
    original_public, original_evaluator = artifact_bytes(generated)
    changed_public, changed_evaluator = artifact_bytes(intervened)
    assert original_public == changed_public
    assert original_evaluator["truth"] != changed_evaluator["truth"]


def _exact_canonical_fixture(rows: int = 4) -> pd.DataFrame:
    header = sealed_canonical_header()
    values = np.arange(1, rows + 1, dtype=np.float64)
    frame = pd.DataFrame({column: values.copy() for column in header})
    dates = pd.bdate_range("2015-01-02", periods=rows)
    frame["date"] = dates.strftime("%Y-%m-%d")
    frame["symbol"] = "SYNTH_ISSUER_0"
    frame["available_at"] = [
        (date.tz_localize("UTC") + pd.Timedelta(hours=12)).isoformat() for date in dates
    ]
    frame["effective_date"] = dates.strftime("%Y-%m-%d")
    frame["close"] = np.linspace(100.0, 103.0, rows)
    frame["observed_pe"] = np.linspace(20.0, 23.0, rows)
    frame["eps_ttm"] = np.linspace(2.0, 2.3, rows)
    return frame.loc[:, list(header)]


def _common_mask_fixture(
    dgp_id: str,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    seed = FIXTURE_MASTER_SEED
    dates = pd.bdate_range("2013-01-02", periods=SCORE_END)
    eps = np.full(SCORE_END, 2.0, dtype=np.float64)
    if dgp_id == "I":
        eps[SCORE_START : SCORE_START + 189] = -0.5
    truth = pd.DataFrame(
        {
            "date": dates,
            "true_fair_pe": np.full(SCORE_END, 22.0, dtype=np.float64),
            "true_pit_eps": eps,
            "true_expected_pe_eligible": eps > 0.0,
        }
    )
    comparators = pd.DataFrame(
        {
            "seed": np.full(SCORE_END, seed, dtype=np.int64),
            "dgp_id": np.full(SCORE_END, dgp_id, dtype=object),
            "date": dates,
            "v03_prediction": np.full(SCORE_END, 21.0, dtype=np.float64),
            "v04_prediction": np.full(SCORE_END, 22.0, dtype=np.float64),
        }
    )
    eligible = eps[SCORE_START:SCORE_END] > 0.0
    eligible_dates = dates[SCORE_START:SCORE_END][eligible]
    candidate = pd.DataFrame(
        {
            "seed": np.full(len(eligible_dates), seed, dtype=np.int64),
            "dgp_id": np.full(len(eligible_dates), dgp_id, dtype=object),
            "date": eligible_dates,
            "fold_id": [f"fold_{row // 21:03d}" for row in range(len(eligible_dates))],
            "prediction": np.full(len(eligible_dates), 23.0, dtype=np.float64),
        }
    )
    return candidate, comparators, truth


@pytest.mark.parametrize(
    "column",
    (
        "true_log_fair_pe",
        "latent_regime",
        "future_event_time",
        "rng_state",
        "seed",
        "master_seed",
        "dgp_id",
        "fold_id",
        "model_id",
        "true_fair_pe",
    ),
)
def test_repaired_boundary_rejects_every_forbidden_prefix_and_control(column: str) -> None:
    with pytest.raises(DGPContractError, match="forbidden evaluator/control"):
        reject_forbidden_columns(["safe_feature", column], context="adversarial handoff")


def test_repaired_boundary_binds_exact_canonical150_and_rejects_name_only_frames() -> None:
    header = sealed_canonical_header()
    assert len(header) == 150
    assert len(set(header)) == 150
    raw = pd.DataFrame(
        {
            "date": ["2015-01-02", "2015-01-05"],
            "ml_expected_pe": [999.0, 998.0],
            "v04_expected_pe": [777.0, 776.0],
        }
    )
    with pytest.raises(DGPContractError, match="content-addressed"):
        align_primary_comparators(raw)
    with pytest.raises(DGPContractError, match="exact pipeline"):
        VerifiedComparatorArtifact()


def test_repaired_boundary_rejects_forbidden_long_sidecar_factor_id() -> None:
    frame = pd.DataFrame(
        [
            {
                "entity_id": ENTITY_ID,
                "factor_id": "future_hidden_signal",
                "observed_at": "2015-01-01T21:00:00+00:00",
                "available_at": "2015-01-01T21:00:01+00:00",
                "effective_session": "2015-01-02",
                "source_id": "TEST_NON_EVIDENCE",
                "revision_id": 0,
                "is_missing": False,
                "value": 1.0,
            }
        ],
        columns=PIT_COLUMNS,
    )
    with pytest.raises(DGPContractError, match="forbidden evaluator/control"):
        canonical_pit_csv_bytes(frame)


def test_primary_candidate_surface_lags_market_and_isolates_same_session_target() -> None:
    canonical = _exact_canonical_fixture()
    surface = _transform_canonical_components(canonical)
    features = surface.features
    for column in ("open", "high", "low", "close", "volume", "observed_pe"):
        assert column not in features
        assert f"{column}__pit_lag1" in features
        assert pd.isna(features.loc[0, f"{column}__pit_lag1"])
    assert "ml_expected_pe" not in features
    assert "expected_pe" not in features
    assert surface.training_target.name == "observed_pe_target"
    assert surface.decision_cutoffs.dt.strftime("%H:%M:%S").eq("12:30:00").all()
    assert len(primary_transformation_sha256()) == 64
    with pytest.raises(DGPContractError, match="PrimaryCandidateSurface"):
        require_primary_candidate_surface(surface)
    with pytest.raises(DGPContractError, match="code-owned transformation"):
        PrimaryCandidateSurface()
    with pytest.raises(DGPContractError, match="PrimaryCandidateSurface"):
        require_primary_candidate_surface(canonical)


def test_primary_candidate_surface_interventions_obey_t_minus_1_and_pit_rules() -> None:
    canonical = _exact_canonical_fixture()
    base = _transform_canonical_components(canonical)

    market_intervention = canonical.copy()
    market_intervention.loc[1, "close"] = 999.0
    changed_market = _transform_canonical_components(market_intervention)
    assert (
        changed_market.features.loc[1, "close__pit_lag1"] == base.features.loc[1, "close__pit_lag1"]
    )
    assert changed_market.features.loc[2, "close__pit_lag1"] == 999.0

    target_intervention = canonical.copy()
    target_intervention.loc[1, "observed_pe"] = 999.0
    changed_target = _transform_canonical_components(target_intervention)
    assert (
        changed_target.features.loc[1, "observed_pe__pit_lag1"]
        == base.features.loc[1, "observed_pe__pit_lag1"]
    )
    assert changed_target.features.loc[2, "observed_pe__pit_lag1"] == 999.0
    assert changed_target.training_target.loc[1] == 999.0

    filing_intervention = canonical.copy()
    filing_intervention.loc[1, "eps_ttm"] = 9.0
    changed_filing = _transform_canonical_components(filing_intervention)
    assert changed_filing.features.loc[1, "eps_ttm"] == 9.0

    future_filing = canonical.copy()
    future_filing.loc[1, "available_at"] = "2015-01-05T12:30:01+00:00"
    with pytest.raises(DGPContractError, match="12:30 cutoff"):
        _transform_canonical_components(future_filing)


@pytest.mark.parametrize("dgp_id,expected", (("B", 1296), ("I", 1107)))
def test_common_mask_core_seals_exact_identical_identities_and_counts(
    dgp_id: str,
    expected: int,
) -> None:
    candidate, comparators, truth = _common_mask_fixture(dgp_id)
    built = _build_common_mask_frames(
        candidate,
        comparators,
        truth,
        master_seed=FIXTURE_MASTER_SEED,
        dgp_id=dgp_id,
        comparator_receipt_sha256="a" * 64,
        truth_raw_sha256="b" * 64,
    )
    assert len(built.identities) == expected == EXPECTED_ELIGIBLE_COUNTS[dgp_id]
    receipt = built.receipt
    assert receipt["mask_policy_sha256"] == COMMON_MASK_POLICY_SHA256
    assert (
        len(
            {
                receipt["candidate_identity_sha256"],
                receipt["v03_identity_sha256"],
                receipt["v04_identity_sha256"],
                receipt["truth_identity_sha256"],
            }
        )
        == 1
    )


def test_common_mask_core_rejects_drops_bad_predictions_and_identity_drift() -> None:
    candidate, comparators, truth = _common_mask_fixture("B")

    with pytest.raises(DGPContractError, match="every and only"):
        _build_common_mask_frames(
            candidate.iloc[:-1].copy(),
            comparators,
            truth,
            master_seed=FIXTURE_MASTER_SEED,
            dgp_id="B",
            comparator_receipt_sha256="a" * 64,
            truth_raw_sha256="b" * 64,
        )

    bad_comparator = comparators.copy()
    bad_comparator.loc[SCORE_START, "v03_prediction"] = np.nan
    with pytest.raises(DGPContractError, match="v03_prediction"):
        _build_common_mask_frames(
            candidate,
            bad_comparator,
            truth,
            master_seed=FIXTURE_MASTER_SEED,
            dgp_id="B",
            comparator_receipt_sha256="a" * 64,
            truth_raw_sha256="b" * 64,
        )

    wrong_seed = candidate.copy()
    wrong_seed.loc[0, "seed"] += 1
    with pytest.raises(DGPContractError, match="identity"):
        _build_common_mask_frames(
            wrong_seed,
            comparators,
            truth,
            master_seed=FIXTURE_MASTER_SEED,
            dgp_id="B",
            comparator_receipt_sha256="a" * 64,
            truth_raw_sha256="b" * 64,
        )


def test_common_mask_public_types_cannot_be_forged_from_dataframes() -> None:
    candidate, comparators, truth = _common_mask_fixture("B")
    with pytest.raises(DGPContractError, match="content-addressed"):
        build_verified_common_mask(candidate, comparators, truth)  # type: ignore[arg-type]
    with pytest.raises(DGPContractError, match="common-mask verifier"):
        VerifiedCommonMask()
    with pytest.raises(DGPContractError, match="physical verified loader"):
        VerifiedEvaluatorTruthArtifact()


def test_execution_snapshot_is_single_read_content_addressed_and_tamper_evident(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _xfail_exact_known_unsealed_runtime_policy_transition()
    policy = load_comparator_production_policy(verify_runtime=True)
    snapshot = capture_execution_snapshot(
        policy, python_executable=Path(__import__("sys").executable)
    )
    manifest = snapshot.manifest
    runtime_policy = load_runtime_attestation_policy()
    assert manifest["snapshot_version"] == SNAPSHOT_VERSION
    assert manifest["runtime_attestation_policy_raw_sha256"] == (
        RUNTIME_ATTESTATION_POLICY_RAW_SHA256
    )
    assert (
        snapshot.runtime_manifest_sha256
        == (runtime_policy["runtime_payload"]["runtime_manifest_sha256"])
    )
    assert manifest["v03_archive_sha256"] == V03_ARCHIVE_SHA256
    assert manifest["v04_entry_sha256"] == {
        **policy["v04"]["source_sha256"],
        policy["v04"]["config_path"]: policy["v04"]["config_sha256"],
        policy["v04"]["design_lock_path"]: policy["v04"]["design_lock_sha256"],
    }

    staged = write_content_addressed_snapshot(
        tmp_path, "swap_restore_probe", snapshot.v04_snapshot_bytes
    )
    original = staged.read_bytes()
    staged.chmod(0o666)
    staged.write_bytes(original + b"adversarial swap")
    with pytest.raises(DGPContractError, match="snapshot changed"):
        verify_content_addressed_snapshot(staged, snapshot.v04_snapshot_sha256)
    staged.write_bytes(original)
    assert (
        hashlib.sha256(
            verify_content_addressed_snapshot(staged, snapshot.v04_snapshot_sha256)
        ).hexdigest()
        == snapshot.v04_snapshot_sha256
    )

    real_run = execution_snapshot_module.subprocess.run

    def swap_then_restore(*args: object, **kwargs: object) -> object:
        staged.chmod(0o666)
        staged.write_bytes(original + b"swap immediately before child import")
        try:
            return real_run(*args, **kwargs)
        finally:
            staged.write_bytes(original)

    monkeypatch.setattr(execution_snapshot_module.subprocess, "run", swap_then_restore)
    with pytest.raises(DGPContractError, match="child rejected swapped"):
        verify_snapshot_in_child(staged, snapshot.v04_snapshot_sha256)


def test_loaded_project_source_and_code_are_recomputed_not_self_attested() -> None:
    attestation, runtime_manifest, runtime_sources, project_sources, snapshot_sha256 = (
        _synthetic_loaded_bytes_attestation()
    )
    verified = verify_child_execution_attestation(
        attestation,
        stage="synthetic",
        snapshot_sha256=snapshot_sha256,
        project_sources=project_sources,
        required_project_modules={"sealed_test_package"},
        runtime_manifest_bytes=runtime_manifest,
        runtime_source_snapshot_bytes=runtime_sources,
        include_distributions=True,
        extra_origin_hashes={},
    )
    assert verified["attestation_sha256"] == attestation["attestation_sha256"]

    altered = json.loads(canonical_json_bytes(attestation))
    altered["project"]["modules"]["sealed_test_package"]["source_sha256"] = "c" * 64
    altered["project"]["manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes({"modules": altered["project"]["modules"]})
    ).hexdigest()
    altered.pop("attestation_sha256")
    altered["attestation_sha256"] = hashlib.sha256(canonical_json_bytes(altered)).hexdigest()
    with pytest.raises(DGPContractError, match="loaded project source/code differs"):
        verify_child_execution_attestation(
            altered,
            stage="synthetic",
            snapshot_sha256=snapshot_sha256,
            project_sources=project_sources,
            required_project_modules={"sealed_test_package"},
            runtime_manifest_bytes=runtime_manifest,
            runtime_source_snapshot_bytes=runtime_sources,
            include_distributions=True,
            extra_origin_hashes={},
        )


def test_loaded_dependency_bytes_cannot_be_changed_and_self_resealed() -> None:
    attestation, runtime_manifest, runtime_sources, project_sources, snapshot_sha256 = (
        _synthetic_loaded_bytes_attestation()
    )
    altered = json.loads(canonical_json_bytes(attestation))
    altered["runtime"]["modules"]["test_runtime.dependency"]["payload_sha256"] = "c" * 64
    altered["runtime"]["manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {
                "enumeration": altered["runtime"]["enumeration"],
                "modules": altered["runtime"]["modules"],
                "native_libraries": altered["runtime"]["native_libraries"],
                "source_snapshot_sha256": altered["runtime"]["source_snapshot_sha256"],
            }
        )
    ).hexdigest()
    altered.pop("attestation_sha256")
    altered["attestation_sha256"] = hashlib.sha256(canonical_json_bytes(altered)).hexdigest()
    with pytest.raises(DGPContractError, match="dependency source/code differs"):
        verify_child_execution_attestation(
            altered,
            stage="synthetic",
            snapshot_sha256=snapshot_sha256,
            project_sources=project_sources,
            required_project_modules={"sealed_test_package"},
            runtime_manifest_bytes=runtime_manifest,
            runtime_source_snapshot_bytes=runtime_sources,
            include_distributions=True,
            extra_origin_hashes={},
        )


def test_loaded_dependency_cannot_be_relabelled_as_interpreter_payload() -> None:
    attestation, runtime_manifest, runtime_sources, project_sources, snapshot_sha256 = (
        _synthetic_loaded_bytes_attestation()
    )
    runtime_payload = json.loads(runtime_manifest)
    altered = json.loads(canonical_json_bytes(attestation))
    record = altered["runtime"]["modules"]["test_runtime.dependency"]
    record.update(
        {
            "kind": "frozen",
            "origin_id": "python-executable/frozen",
            "payload_sha256": runtime_payload["python_executable"]["sha256"],
        }
    )
    altered["runtime"]["manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes(
            {
                "enumeration": altered["runtime"]["enumeration"],
                "modules": altered["runtime"]["modules"],
                "native_libraries": altered["runtime"]["native_libraries"],
                "source_snapshot_sha256": altered["runtime"]["source_snapshot_sha256"],
            }
        )
    ).hexdigest()
    altered.pop("attestation_sha256")
    altered["attestation_sha256"] = hashlib.sha256(canonical_json_bytes(altered)).hexdigest()
    with pytest.raises(DGPContractError, match="built-in/frozen"):
        verify_child_execution_attestation(
            altered,
            stage="synthetic",
            snapshot_sha256=snapshot_sha256,
            project_sources=project_sources,
            required_project_modules={"sealed_test_package"},
            runtime_manifest_bytes=runtime_manifest,
            runtime_source_snapshot_bytes=runtime_sources,
            include_distributions=True,
            extra_origin_hashes={},
        )


@pytest.mark.parametrize("collection", ["modules", "native_libraries"])
def test_loaded_runtime_attestation_rejects_empty_collections(collection: str) -> None:
    attestation, runtime_manifest, runtime_sources, project_sources, snapshot_sha256 = (
        _synthetic_loaded_bytes_attestation()
    )
    altered = json.loads(canonical_json_bytes(attestation))
    altered["runtime"][collection] = {}
    _reseal_synthetic_attestation(altered)
    with pytest.raises(DGPContractError, match="collection is empty"):
        verify_child_execution_attestation(
            altered,
            stage="synthetic",
            snapshot_sha256=snapshot_sha256,
            project_sources=project_sources,
            required_project_modules={"sealed_test_package"},
            runtime_manifest_bytes=runtime_manifest,
            runtime_source_snapshot_bytes=runtime_sources,
            include_distributions=True,
            extra_origin_hashes={},
        )


def test_loaded_dependency_module_name_and_code_hash_are_not_self_asserted() -> None:
    attestation, runtime_manifest, runtime_sources, project_sources, snapshot_sha256 = (
        _synthetic_loaded_bytes_attestation()
    )
    for mutation in ("rename", "code"):
        altered = json.loads(canonical_json_bytes(attestation))
        if mutation == "rename":
            altered["runtime"]["modules"]["arbitrary.approved_name"] = altered["runtime"][
                "modules"
            ].pop("test_runtime.dependency")
        else:
            altered["runtime"]["modules"]["test_runtime.dependency"]["code_sha256"] = "9" * 64
        _reseal_synthetic_attestation(altered)
        with pytest.raises(DGPContractError, match="dependency source"):
            verify_child_execution_attestation(
                altered,
                stage="synthetic",
                snapshot_sha256=snapshot_sha256,
                project_sources=project_sources,
                required_project_modules={"sealed_test_package"},
                runtime_manifest_bytes=runtime_manifest,
                runtime_source_snapshot_bytes=runtime_sources,
                include_distributions=True,
                extra_origin_hashes={},
            )


def test_process_image_and_native_enumeration_cannot_be_omitted_or_relabelled() -> None:
    attestation, runtime_manifest, runtime_sources, project_sources, snapshot_sha256 = (
        _synthetic_loaded_bytes_attestation()
    )
    probes: list[tuple[dict[str, object], str]] = []

    missing_process = json.loads(canonical_json_bytes(attestation))
    missing_process["runtime"]["native_libraries"] = {
        "c:/sealed/test-runtime/dependency.py": {
            "kind": "native-payload",
            "origin_id": "test-runtime/dependency.py",
            "path_key": "c:/sealed/test-runtime/dependency.py",
            "payload_sha256": hashlib.sha256(b"VALUE = 7\n").hexdigest(),
        }
    }
    missing_process["runtime"]["enumeration"]["non_system_path_set_sha256"] = hashlib.sha256(
        canonical_json_bytes(["c:/sealed/test-runtime/dependency.py"])
    ).hexdigest()
    probes.append((missing_process, "non-native payload|process image"))

    incomplete_enumeration = json.loads(canonical_json_bytes(attestation))
    incomplete_enumeration["runtime"]["enumeration"]["non_system_module_count"] = 0
    probes.append((incomplete_enumeration, "enumeration"))

    for altered, message in probes:
        _reseal_synthetic_attestation(altered)
        with pytest.raises(DGPContractError, match=message):
            verify_child_execution_attestation(
                altered,
                stage="synthetic",
                snapshot_sha256=snapshot_sha256,
                project_sources=project_sources,
                required_project_modules={"sealed_test_package"},
                runtime_manifest_bytes=runtime_manifest,
                runtime_source_snapshot_bytes=runtime_sources,
                include_distributions=True,
                extra_origin_hashes={},
            )


def test_fixed_fixture_root_rejects_altered_price_and_self_resealed_ledgers(
    tmp_path: Path,
) -> None:
    root = tmp_path / "DGP_B"
    write_dgp_artifacts(_generated("B"), root)
    verified = verify_fixed_comparator_bundle(root, master_seed=FIXTURE_MASTER_SEED, dgp_id="B")
    assert isinstance(verified, VerifiedFixedComparatorBundle)
    trust = load_fixed_fixture_trust_root()
    assert trust["manifests"]["B"]["artifact_sha256"]["public/price.csv"] == (
        hashlib.sha256((root / "public" / "price.csv").read_bytes()).hexdigest()
    )

    price_path = root / "public" / "price.csv"
    altered = pd.read_csv(price_path, float_precision="round_trip")
    altered.loc[600, "close"] = float(altered.loc[600, "close"]) * 1.01
    price_path.write_bytes(canonical_csv_bytes(altered))
    altered_sha = hashlib.sha256(price_path.read_bytes()).hexdigest()

    audit_path = root / "evaluator_only" / "generation_audit.json"
    audit = json.loads(audit_path.read_bytes())
    audit["artifact_sha256"]["public/price.csv"] = altered_sha
    audit_raw = canonical_json_bytes(audit)
    audit_path.write_bytes(audit_raw)

    capability_path = root / "generation_capability.json"
    capability = json.loads(capability_path.read_bytes())
    capability["artifact_sha256"]["public/price.csv"] = altered_sha
    capability["generation_audit_raw_sha256"] = hashlib.sha256(audit_raw).hexdigest()
    capability.pop("capability_sha256")
    capability["capability_sha256"] = hashlib.sha256(canonical_json_bytes(capability)).hexdigest()
    capability_path.write_bytes(canonical_json_bytes(capability))
    with pytest.raises(DGPContractError, match="implementation trust root"):
        verify_fixed_comparator_bundle(root, master_seed=FIXTURE_MASTER_SEED, dgp_id="B")


def test_future_non_evidence_bundle_requires_atomic_capability_and_exact_replay(
    tmp_path: Path,
) -> None:
    seed = FixtureSeed(FIXTURE_MASTER_SEED + 17)
    root = tmp_path / "future_non_evidence_B"
    generated = generate_dgp("B", fixture_seed=seed, rows=32)
    hashes = write_dgp_artifacts(generated, root)
    assert len(hashes) == 9
    capability = verify_replayable_non_evidence_bundle(root, fixture_seed=seed, dgp_id="B", rows=32)
    assert capability["deterministic_replay_required"] is True

    (root / "generation_capability.json").unlink()
    with pytest.raises(DGPContractError, match="incomplete"):
        verify_replayable_non_evidence_bundle(root, fixture_seed=seed, dgp_id="B", rows=32)


def test_fixed_fixture_trust_root_is_directly_bound_into_implementation_seal() -> None:
    trust = load_fixed_fixture_trust_root()
    assert len(trust["manifests"]) == 10
    assert len(FIXED_FIXTURE_TRUST_ROOT_RAW_SHA256) == 64
    assert trust["candidate_score_computation_authorized"] is False
