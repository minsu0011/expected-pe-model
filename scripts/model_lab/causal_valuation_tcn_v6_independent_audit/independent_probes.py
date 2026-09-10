"""Independent synthetic-only provenance probes for frozen TCN V6.

This program constructs its own deterministic synthetic source.  It never
opens a project dataset, evaluator, registry, score, heldout, truth, vault, or
latent artifact; it performs no optimizer step, fit, or real prediction.
"""

from __future__ import annotations

import copy
from dataclasses import fields
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Callable


PROJECT = Path(
    "C:/Users/minsu/Documents/EPS/PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
)
sys.path.insert(0, str(PROJECT))

import numpy as np  # noqa: E402
import torch  # noqa: E402

from research.model_zoo.causal_valuation_tcn_v6 import models as model_module  # noqa: E402
from research.model_zoo.causal_valuation_tcn_v6.contracts import (  # noqa: E402
    CANDIDATE_IDS,
    CONVOLUTIONAL_RECEPTIVE_FIELD,
    EMBARGO_SESSIONS,
    END_TO_END_RAW_INPUT_RECEPTIVE_FIELD,
    FEATURE_COLUMNS,
    NUISANCE_PROJECTION_TOLERANCE,
    PURGE_SESSIONS,
    SEQUENCE_LENGTH,
    CausalValuationContractError,
)
from research.model_zoo.causal_valuation_tcn_v6.custody import (  # noqa: E402
    build_canonical_source_custody,
    build_causal_prefix_windows,
    build_global_date_fold,
    chronological_fold_row_masks,
)
from research.model_zoo.causal_valuation_tcn_v6.models import (  # noqa: E402
    StaticStateMLPModel,
    TorchSequenceCustody,
    build_fixed_model,
    build_training_center_custody,
    reconstruct_deployable_model,
    torch_sequence_custody_sha256,
)
from research.model_zoo.causal_valuation_tcn_v6.training import (  # noqa: E402
    TrainingOnlyDGPNuisance,
    build_nuisance_training_custody,
    build_sealed_model_prediction_artifact,
)


STATIC_ID = "cvtcn_v6_static_state_mlp"


def _clone(value: object, **changes: object) -> object:
    clone = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(
            clone,
            field.name,
            changes.get(field.name, getattr(value, field.name)),
        )
    return clone


def _rejected(call: Callable[[], object]) -> bool:
    try:
        call()
    except (CausalValuationContractError, TypeError, NotImplementedError):
        return True
    return False


def _fixture(*, future_change: bool = False) -> tuple[Any, Any, Any]:
    generator = np.random.default_rng(2026082197)
    calendar = tuple(
        (date(2020, 1, 2) + timedelta(days=position)).isoformat()
        for position in range(910)
    )
    features = generator.normal(size=(910, len(FEATURE_COLUMNS))).astype(np.float32)
    for position in range(910):
        features[position, (position * 17 + 5) % len(FEATURE_COLUMNS)] = np.nan
        if position % 19 == 0:
            features[position, (position * 11 + 2) % len(FEATURE_COLUMNS)] = np.nan
    baseline = (13.5 + 0.004 * np.arange(910)).astype(np.float32)
    if future_change:
        features[894:] = np.where(
            np.isfinite(features[894:]), np.float32(31.25), features[894:]
        )
        baseline[894:] = np.float32(44.0)
    source = build_canonical_source_custody(
        external_source_sha256=hashlib.sha256(
            b"independent-tcn-v6-provenance-fixture-v1"
            + (b"-future-change" if future_change else b"")
        ).hexdigest(),
        entity_ids=("INDEPENDENT_V6_ENTITY",) * 910,
        dates=calendar,
        global_session_dates=calendar,
        feature_columns=FEATURE_COLUMNS,
        features=features,
        baseline_pe=baseline,
        dgp_group_ids=tuple("ABCDEFGHIJ"[position % 10] for position in range(910)),
    )
    batch = build_causal_prefix_windows(source)
    fold = build_global_date_fold(
        batch,
        fold_id="independent_v6_fold",
        train_end_date=calendar[755],
        validation_end_date=calendar[899],
    )
    return batch, fold, source


def _rf_fixture() -> tuple[Any, Any]:
    calendar = tuple(
        (date(2021, 1, 4) + timedelta(days=position)).isoformat()
        for position in range(910)
    )
    features = np.zeros((910, len(FEATURE_COLUMNS)), dtype=np.float32)
    features[772, 0] = np.float32(1.75)
    features[773:900, 0] = np.nan
    source = build_canonical_source_custody(
        external_source_sha256=hashlib.sha256(
            b"independent-tcn-v6-rf-fixture-v1"
        ).hexdigest(),
        entity_ids=("INDEPENDENT_RF_ENTITY",) * 910,
        dates=calendar,
        global_session_dates=calendar,
        feature_columns=FEATURE_COLUMNS,
        features=features,
        baseline_pe=np.full(910, 15.0, dtype=np.float32),
        dgp_group_ids=tuple("ABCDEFGHIJ"[position % 10] for position in range(910)),
    )
    batch = build_causal_prefix_windows(source)
    fold = build_global_date_fold(
        batch,
        fold_id="independent_v6_rf_fold",
        train_end_date=calendar[755],
        validation_end_date=calendar[899],
    )
    return batch, fold


def _future_center(validation: TorchSequenceCustody) -> torch.Tensor:
    values = validation.values.detach().cpu()
    observed = validation.observed_mask.detach().cpu()
    centers: list[torch.Tensor] = []
    for feature_index in range(len(FEATURE_COLUMNS)):
        finite = values[:, :, feature_index][observed[:, :, feature_index]]
        centers.append(torch.kthvalue(finite, (int(finite.numel()) + 1) // 2).values)
    return torch.stack(centers).to(torch.float32)


def _center_and_state_boundaries(batch: Any, fold: Any) -> dict[str, object]:
    per_candidate: dict[str, object] = {}
    internal_token_boundary_accepted = False
    for offset, candidate_id in enumerate(CANDIDATE_IDS):
        torch.manual_seed(2026082300 + offset)
        train = TorchSequenceCustody.from_canonical_fold(
            batch, fold, candidate_id=candidate_id, split="train", device="cpu"
        )
        validation = TorchSequenceCustody.from_canonical_fold(
            batch,
            fold,
            candidate_id=candidate_id,
            split="validation",
            device="cpu",
        )
        canonical_center = build_training_center_custody(train)
        model = build_fixed_model(candidate_id, training_inputs=train).eval()
        state = model.deployable_state_dict(training_inputs=train)
        live_center_matches = torch.equal(
            model.encoder.training_center.detach().cpu(),
            torch.tensor(canonical_center.centers, dtype=torch.float32),
        )
        alternate = _future_center(validation)
        if torch.equal(alternate, model.encoder.training_center.detach().cpu()):
            raise RuntimeError("independent future center unexpectedly equals train center")
        with torch.no_grad():
            model.encoder.training_center.copy_(alternate)

        forward_rejected = _rejected(
            lambda: model(validation, training_inputs=train)
        )
        concrete_forward_rejected = _rejected(
            lambda: type(model).forward(model, validation, training_inputs=train)
        )
        encoder_forward_rejected = _rejected(
            lambda: type(model.encoder).forward(
                model.encoder, validation, training_inputs=train
            )
        )
        export_rejected = _rejected(
            lambda: model.deployable_state_dict(training_inputs=train)
        )
        ordinary_export_rejected = _rejected(
            lambda: model.state_dict(training_inputs=train)
        )
        base_export_rejected = _rejected(lambda: torch.nn.Module.state_dict(model))
        partial_encoder_export_rejected = _rejected(
            lambda: torch.nn.Module.state_dict(model.encoder)
        )

        bad_state = {name: value.clone() for name, value in state.items()}
        bad_state["encoder.training_center"] = alternate.clone()
        clean = build_fixed_model(candidate_id, training_inputs=train).eval()
        load_rejected = _rejected(
            lambda: clean.load_state_dict(
                bad_state, strict=True, training_inputs=train
            )
        )
        base_load_rejected = _rejected(
            lambda: torch.nn.Module.load_state_dict(clean, bad_state, strict=True)
        )
        reconstruct_rejected = _rejected(
            lambda: reconstruct_deployable_model(
                candidate_id, bad_state, training_inputs=train
            )
        )
        artifact_rejected = _rejected(
            lambda: build_sealed_model_prediction_artifact(
                training_inputs=train, deployable_state=bad_state
            )
        )

        shallow = copy.copy(model)
        shallow.encoder = copy.deepcopy(model.encoder)
        deep = copy.deepcopy(model)
        copy_forward_rejected = all(
            _rejected(lambda item=item: item(validation, training_inputs=train))
            for item in (shallow, deep)
        )
        copy_export_rejected = all(
            _rejected(
                lambda item=item: item.deployable_state_dict(training_inputs=train)
            )
            for item in (shallow, deep)
        )

        # The ordinary base-hook checks above are fail-closed.  This additional
        # lifecycle check asks whether the module's own identity token can be
        # installed as caller-controlled state and thereby open the base hook.
        object.__setattr__(
            model, "_state_export_capability", model_module._STATE_EXPORT_CAPABILITY
        )
        object.__setattr__(
            model.encoder,
            "_state_export_capability",
            model_module._STATE_EXPORT_CAPABILITY,
        )
        try:
            internal_state = torch.nn.Module.state_dict(model)
            internal_export_accepted = torch.equal(
                internal_state["encoder.training_center"].detach().cpu(), alternate
            )
        except CausalValuationContractError:
            internal_export_accepted = False
        finally:
            object.__delattr__(model.encoder, "_state_export_capability")
            object.__delattr__(model, "_state_export_capability")

        token_load_target = build_fixed_model(
            candidate_id, training_inputs=train
        ).eval()
        object.__setattr__(
            token_load_target,
            "_state_load_capability",
            model_module._STATE_LOAD_CAPABILITY,
        )
        object.__setattr__(
            token_load_target.encoder,
            "_state_load_capability",
            model_module._STATE_LOAD_CAPABILITY,
        )
        try:
            torch.nn.Module.load_state_dict(token_load_target, bad_state, strict=True)
            internal_load_accepted = torch.equal(
                token_load_target.encoder.training_center.detach().cpu(), alternate
            )
        except CausalValuationContractError:
            internal_load_accepted = False
        finally:
            object.__delattr__(token_load_target.encoder, "_state_load_capability")
            object.__delattr__(token_load_target, "_state_load_capability")
        post_internal_forward_rejected = _rejected(
            lambda: token_load_target(validation, training_inputs=train)
        )
        post_internal_export_rejected = _rejected(
            lambda: token_load_target.deployable_state_dict(training_inputs=train)
        )
        internal_token_boundary_accepted |= (
            internal_export_accepted or internal_load_accepted
        )

        per_candidate[candidate_id] = {
            "canonical_center_matches_live_rows": live_center_matches,
            "substituted_center_forward_rejected": forward_rejected,
            "substituted_center_concrete_forward_rejected": concrete_forward_rejected,
            "substituted_center_encoder_forward_rejected": encoder_forward_rejected,
            "substituted_center_deploy_export_rejected": export_rejected,
            "substituted_center_ordinary_export_rejected": ordinary_export_rejected,
            "base_export_without_token_rejected": base_export_rejected,
            "partial_encoder_export_rejected": partial_encoder_export_rejected,
            "public_bad_center_load_rejected": load_rejected,
            "base_bad_center_load_without_token_rejected": base_load_rejected,
            "bad_center_reconstruct_rejected": reconstruct_rejected,
            "bad_center_prediction_artifact_rejected": artifact_rejected,
            "copy_and_deepcopy_forward_rejected": copy_forward_rejected,
            "copy_and_deepcopy_export_rejected": copy_export_rejected,
            "caller_installed_internal_export_token_accepted": internal_export_accepted,
            "caller_installed_internal_load_token_accepted": internal_load_accepted,
            "public_forward_after_internal_load_rejected": post_internal_forward_rejected,
            "public_export_after_internal_load_rejected": post_internal_export_rejected,
        }
    return {
        "candidates": per_candidate,
        "caller_reachable_internal_token_boundary_accepted": (
            internal_token_boundary_accepted
        ),
    }


def _fold_and_rf_boundaries(batch: Any, fold: Any) -> dict[str, object]:
    rows = chronological_fold_row_masks(batch, fold)
    rf_batch, rf_fold = _rf_fixture()
    raw_fields: dict[str, object] = {}
    for offset, candidate_id in enumerate(CANDIDATE_IDS):
        train = TorchSequenceCustody.from_canonical_fold(
            rf_batch,
            rf_fold,
            candidate_id=candidate_id,
            split="train",
            device="cpu",
        )
        validation = TorchSequenceCustody.from_canonical_fold(
            rf_batch,
            rf_fold,
            candidate_id=candidate_id,
            split="validation",
            device="cpu",
        )
        values = validation.values.detach().clone().requires_grad_(True)
        live = _clone(validation, values=values)
        if torch_sequence_custody_sha256(live, include_stored_hash=False) != (
            validation.tensor_custody_sha256
        ):
            raise RuntimeError("requires-grad clone changed tensor custody bytes")
        torch.manual_seed(2026082400 + offset)
        model = build_fixed_model(candidate_id, training_inputs=train).eval()
        output = model(live, training_inputs=train).log_expected_pe
        final_gradient = torch.autograd.grad(
            output[-1, -1], values, retain_graph=True
        )[0][-1]
        active = tuple(
            bool((final_gradient[index].abs().max() > 0.0).item())
            for index in range(SEQUENCE_LENGTH)
        )
        earlier_gradient = torch.autograd.grad(output[-1, 64], values)[0][-1]
        declared = END_TO_END_RAW_INPUT_RECEPTIVE_FIELD[candidate_id]
        raw_fields[candidate_id] = {
            "declared_raw_receptive_field": declared,
            "first_active_raw_position": next(
                (index for index, flag in enumerate(active) if flag), None
            ),
            "active_raw_position_count": sum(active),
            "outside_declared_raw_field_active": any(
                active[: SEQUENCE_LENGTH - declared]
            ),
            "future_gradient_max_abs_from_position_64": float(
                earlier_gradient[65:].abs().max().item()
            ),
        }

    torch.manual_seed(2026082499)
    train = TorchSequenceCustody.from_canonical_fold(
        rf_batch,
        rf_fold,
        candidate_id="cvtcn_v6_tcn_residual",
        split="train",
        device="cpu",
    )
    tcn = build_fixed_model(
        "cvtcn_v6_tcn_residual", training_inputs=train
    ).eval()
    hidden = torch.randn(1, SEQUENCE_LENGTH, 32, requires_grad=True)
    mask = torch.ones(1, SEQUENCE_LENGTH, dtype=torch.bool)
    convolved = hidden
    for block in tcn.blocks:
        convolved = block(convolved, mask)
    gradient = torch.autograd.grad(tcn.head(convolved)[0, -1, 0], hidden)[0][0]
    active_hidden = tuple(
        bool((gradient[index].abs().max() > 0.0).item())
        for index in range(SEQUENCE_LENGTH)
    )
    return {
        "purge_sessions": fold.purge_sessions,
        "embargo_sessions": fold.embargo_sessions,
        "train_rows": len(rows.train_positions),
        "validation_history_min_session_index": (
            rows.validation_history_min_session_index
        ),
        "train_end_session_index": fold.train_end_session_index,
        "train_validation_raw_overlap_count": (
            rows.train_validation_window_overlap_count
        ),
        "declared_convolutional_receptive_field": (
            CONVOLUTIONAL_RECEPTIVE_FIELD
        ),
        "convolution_first_active_hidden_position": next(
            (index for index, flag in enumerate(active_hidden) if flag), None
        ),
        "convolution_active_hidden_position_count": sum(active_hidden),
        "raw_receptive_fields": raw_fields,
        "passed": (
            fold.purge_sessions == PURGE_SESSIONS == 127
            and fold.embargo_sessions == EMBARGO_SESSIONS == 5
            and len(rows.train_positions) == 756
            and rows.validation_history_min_session_index
            > fold.train_end_session_index
            and rows.train_validation_window_overlap_count == 0
            and sum(active_hidden) == CONVOLUTIONAL_RECEPTIVE_FIELD == 125
            and all(
                not item["outside_declared_raw_field_active"]
                and item["future_gradient_max_abs_from_position_64"] == 0.0
                for item in raw_fields.values()
            )
        ),
    }


def _nuisance_and_role_boundaries(batch: Any, fold: Any) -> dict[str, object]:
    train = TorchSequenceCustody.from_canonical_fold(
        batch, fold, candidate_id=STATIC_ID, split="train", device="cpu"
    )
    validation = TorchSequenceCustody.from_canonical_fold(
        batch,
        fold,
        candidate_id=STATIC_ID,
        split="validation",
        device="cpu",
    )
    mapping = build_nuisance_training_custody(train)
    nuisance = TrainingOnlyDGPNuisance(mapping)
    with torch.no_grad():
        nuisance.raw_effects.copy_(torch.linspace(-0.35, 0.55, 10))
    effects, weights, weighted_sum, residual = nuisance.projected_effects(
        mapping=mapping, training_inputs=train
    )
    counts = torch.bincount(
        torch.tensor(mapping.group_indices_by_training_row, dtype=torch.int64),
        minlength=10,
    ).to(torch.float64)
    manual_weights = counts / counts.sum()
    raw64 = nuisance.raw_effects.detach().to(torch.float64)
    manual_effects = raw64 - torch.sum(raw64 * manual_weights)
    initial = torch.sum(manual_effects * manual_weights)
    manual_effects = torch.cat(
        (
            manual_effects[:-1],
            (manual_effects[-1] - initial / manual_weights[-1]).reshape(1),
        )
    )

    relabeled = _clone(
        validation,
        split="train",
        tensor_custody_sha256="0" * 64,
    )
    object.__setattr__(
        relabeled,
        "tensor_custody_sha256",
        torch_sequence_custody_sha256(relabeled, include_stored_hash=False),
    )
    relabeled_train_rejected = _rejected(
        lambda: build_training_center_custody(relabeled)
    )
    validation_center_rejected = _rejected(
        lambda: build_training_center_custody(validation)
    )
    validation_nuisance_rejected = _rejected(
        lambda: build_nuisance_training_custody(validation)
    )

    alternate_batch, alternate_fold, _ = _fixture(future_change=True)
    alternate_validation = TorchSequenceCustody.from_canonical_fold(
        alternate_batch,
        alternate_fold,
        candidate_id=STATIC_ID,
        split="validation",
        device="cpu",
    )
    model = build_fixed_model(STATIC_ID, training_inputs=train).eval()
    cross_source_forward_rejected = _rejected(
        lambda: model(alternate_validation, training_inputs=train)
    )

    return {
        "weighted_sum": float(weighted_sum.detach().cpu().item()),
        "projection_residual": float(residual.detach().cpu().item()),
        "projection_tolerance": NUISANCE_PROJECTION_TOLERANCE,
        "weights_match_fresh_counts": torch.equal(weights, manual_weights),
        "effects_match_fresh_projection": torch.equal(effects, manual_effects),
        "residual_matches_fresh_projection": torch.equal(
            residual, torch.abs(torch.sum(manual_effects * manual_weights))
        ),
        "validation_center_factory_rejected": validation_center_rejected,
        "validation_nuisance_factory_rejected": validation_nuisance_rejected,
        "validation_relabel_and_rehash_as_train_rejected": relabeled_train_rejected,
        "cross_source_validation_forward_rejected": cross_source_forward_rejected,
        "passed": (
            torch.equal(weights, manual_weights)
            and torch.equal(effects, manual_effects)
            and float(residual.detach().cpu().item())
            <= NUISANCE_PROJECTION_TOLERANCE
            and validation_center_rejected
            and validation_nuisance_rejected
            and relabeled_train_rejected
            and cross_source_forward_rejected
        ),
    }


def main() -> int:
    torch.manual_seed(2026082297)
    torch.use_deterministic_algorithms(True)
    torch.set_deterministic_debug_mode("error")
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False

    batch, fold, _ = _fixture()
    center_state = _center_and_state_boundaries(batch, fold)
    fold_rf = _fold_and_rf_boundaries(batch, fold)
    nuisance_role = _nuisance_and_role_boundaries(batch, fold)
    direct_initializer = StaticStateMLPModel().eval()
    train = TorchSequenceCustody.from_canonical_fold(
        batch, fold, candidate_id=STATIC_ID, split="train", device="cpu"
    )
    validation = TorchSequenceCustody.from_canonical_fold(
        batch,
        fold,
        candidate_id=STATIC_ID,
        split="validation",
        device="cpu",
    )
    initializer_forward_rejected = _rejected(
        lambda: direct_initializer(validation, training_inputs=train)
    )
    public_candidate_controls_passed = all(
        all(
            bool(candidate[key])
            for key in (
                "canonical_center_matches_live_rows",
                "substituted_center_forward_rejected",
                "substituted_center_concrete_forward_rejected",
                "substituted_center_encoder_forward_rejected",
                "substituted_center_deploy_export_rejected",
                "substituted_center_ordinary_export_rejected",
                "base_export_without_token_rejected",
                "partial_encoder_export_rejected",
                "public_bad_center_load_rejected",
                "base_bad_center_load_without_token_rejected",
                "bad_center_reconstruct_rejected",
                "bad_center_prediction_artifact_rejected",
                "copy_and_deepcopy_forward_rejected",
                "copy_and_deepcopy_export_rejected",
                "public_forward_after_internal_load_rejected",
                "public_export_after_internal_load_rejected",
            )
        )
        for candidate in center_state["candidates"].values()
    )
    result = {
        "schema_version": "expected_pe.causal_valuation_tcn_v6.independent_probes.v1",
        "status": "COMPLETE_SYNTHETIC_ONLY",
        "center_and_state_boundaries": center_state,
        "fold_and_receptive_field_boundaries": fold_rf,
        "nuisance_and_role_boundaries": nuisance_role,
        "initializer_forward_rejected": initializer_forward_rejected,
        "public_candidate_controls_passed": public_candidate_controls_passed,
        "finding_candidate": {
            "caller_reachable_internal_state_token_boundary": bool(
                center_state["caller_reachable_internal_token_boundary_accepted"]
            )
        },
        "zero_access": {
            "external_dataset_open_count": 0,
            "real_fit_count": 0,
            "optimizer_step_count": 0,
            "real_prediction_count": 0,
            "truth_vault_latent_open_count": 0,
            "heldout_open_count": 0,
            "score_count": 0,
            "registry_open_or_mutation_count": 0,
            "seed_derivation_or_reservation_count": 0,
        },
    }
    sys.stdout.write(
        json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
