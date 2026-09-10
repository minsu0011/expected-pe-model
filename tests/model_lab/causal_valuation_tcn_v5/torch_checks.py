"""Synthetic-only V3 finding reproductions and V5 direct-surface attacks."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import date, timedelta
import hashlib
import inspect
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

import numpy as np
import torch

from research.model_zoo.causal_valuation_tcn_v5.contracts import (
    CANDIDATE_IDS,
    CONVOLUTIONAL_RECEPTIVE_FIELD,
    EMBARGO_SESSIONS,
    END_TO_END_RAW_INPUT_RECEPTIVE_FIELD,
    FEATURE_COLUMNS,
    MIN_PREFIX_TRAIN_ROWS,
    NUISANCE_PROJECTION,
    NUISANCE_PROJECTION_TOLERANCE,
    NUISANCE_ZERO_SEMANTICS,
    PURGE_SESSIONS,
    SEQUENCE_LENGTH,
    V3_AUDIT_BINDING,
    V4_AUDIT_BINDING,
    CausalValuationContractError,
)
from research.model_zoo.causal_valuation_tcn_v5.custody import (
    CausalSequenceBatch,
    FoldRowCustody,
    build_canonical_source_custody,
    build_causal_prefix_windows,
    build_global_date_fold,
    chronological_fold_row_masks,
    chronological_fold_sha256,
    fold_row_custody_sha256,
    sequence_batch_sha256,
    validate_canonical_source,
    validate_fold_row_custody,
)
from research.model_zoo.causal_valuation_tcn_v5.models import (
    TorchSequenceCustody,
    build_fixed_model,
    build_training_center_custody,
    training_center_custody_sha256,
    torch_sequence_custody_sha256,
)
from research.model_zoo.causal_valuation_tcn_v5.path_guard import (
    CausalPathError,
    require_clean_tree,
)
from research.model_zoo.causal_valuation_tcn_v5.smoke_worker import _fixture
from research.model_zoo.causal_valuation_tcn_v5.source_audit import run_source_audit
from research.model_zoo.causal_valuation_tcn_v5.training import (
    EndToEndNuisanceCustody,
    NuisanceTrainingCustody,
    TrainingOnlyDGPNuisance,
    build_end_to_end_nuisance_custody,
    build_marginalization_receipt,
    build_nuisance_training_custody,
    build_sealed_model_prediction_artifact,
    end_to_end_nuisance_custody_sha256,
    fixed_training_loss,
    load_sealed_model_prediction_artifact,
    nuisance_mapping_sha256,
    sealed_prediction_artifact_sha256,
    verify_marginalization_receipt,
)


STATIC_ID = "cvtcn_v5_static_state_mlp"


def _clone(instance, **changes):
    clone = object.__new__(type(instance))
    for field in fields(instance):
        object.__setattr__(
            clone, field.name, changes.get(field.name, getattr(instance, field.name))
        )
    return clone


def _tensor_hash(value: torch.Tensor, *, domain: bytes) -> str:
    tensor = value.detach().contiguous().cpu()
    hasher = hashlib.sha256(domain)
    dtype = str(tensor.dtype).encode("ascii")
    hasher.update(struct.pack("<I", len(dtype)))
    hasher.update(dtype)
    hasher.update(struct.pack("<I", tensor.ndim))
    for dimension in tensor.shape:
        hasher.update(struct.pack("<Q", dimension))
    hasher.update(tensor.numpy().tobytes(order="C"))
    return hasher.hexdigest()


def _small_source(*, gap: int = 10):
    calendar = tuple(
        (date(2026, 1, 1) + timedelta(days=index)).isoformat()
        for index in range(gap + 1)
    )
    features = np.ones((2, 42), dtype=np.float32)
    features[1, 0] = np.nan
    return build_canonical_source_custody(
        external_source_sha256=hashlib.sha256(b"small-v5-source").hexdigest(),
        entity_ids=("E", "E"),
        dates=(calendar[0], calendar[gap]),
        global_session_dates=calendar,
        feature_columns=FEATURE_COLUMNS,
        features=features,
        baseline_pe=np.asarray([10.0, 11.0], dtype=np.float32),
        dgp_group_ids=("A", "B"),
    )


def _receptive_field_fixture():
    calendar = tuple(
        (date(2020, 1, 2) + timedelta(days=position)).isoformat()
        for position in range(910)
    )
    features = np.zeros((910, 42), dtype=np.float32)
    features[772, 0] = np.float32(1.0)
    features[773:900, 0] = np.nan
    source = build_canonical_source_custody(
        external_source_sha256=hashlib.sha256(b"v5-rf-boundary-fixture").hexdigest(),
        entity_ids=("ENTITY_RF",) * 910,
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
        fold_id="v5_rf_boundary_fold",
        train_end_date=calendar[755],
        validation_end_date=calendar[899],
    )
    return batch, fold


class V5ContractChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        torch.manual_seed(2026082108)
        cls.batch, cls.fold, cls.source = _fixture(np)
        cls.fold_rows = chronological_fold_row_masks(cls.batch, cls.fold)
        cls.train_inputs = TorchSequenceCustody.from_canonical_fold(
            cls.batch,
            cls.fold,
            candidate_id=STATIC_ID,
            split="train",
            device="cpu",
        )
        cls.static_model = build_fixed_model(
            STATIC_ID, training_inputs=cls.train_inputs
        ).eval()
        cls.state = cls.static_model.deployable_state_dict()
        cls.prediction_artifact = build_sealed_model_prediction_artifact(
            training_inputs=cls.train_inputs, deployable_state=cls.state
        )
        cls.target = torch.log(cls.train_inputs.baseline_pe[:, -1]).detach().clone()
        cls.valid = torch.ones_like(cls.target, dtype=torch.bool)
        cls.mapping = build_nuisance_training_custody(cls.train_inputs)
        cls.nuisance = TrainingOnlyDGPNuisance(cls.mapping)
        cls.end_to_end = build_end_to_end_nuisance_custody(
            training_inputs=cls.train_inputs,
            mapping=cls.mapping,
            nuisance=cls.nuisance,
            prediction_artifact=cls.prediction_artifact,
            target_log_pe=cls.target,
            valid_mask=cls.valid,
        )

    def test_01_exact_frozen_geometry_and_fold_policy(self) -> None:
        self.assertEqual((SEQUENCE_LENGTH, MIN_PREFIX_TRAIN_ROWS), (128, 756))
        self.assertEqual((PURGE_SESSIONS, EMBARGO_SESSIONS), (127, 5))
        self.assertEqual(len(self.fold_rows.train_positions), 756)
        self.assertGreater(
            self.fold_rows.validation_history_min_session_index,
            self.fold.train_end_session_index,
        )
        self.assertEqual(self.fold_rows.train_validation_window_overlap_count, 0)

    def test_02_external_source_identity_is_lowercase_sha256(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            build_canonical_source_custody(
                external_source_sha256="not-a-sha",
                entity_ids=("E",),
                dates=("2026-01-01",),
                global_session_dates=("2026-01-01",),
                feature_columns=FEATURE_COLUMNS,
                features=np.zeros((1, 42), dtype=np.float32),
                baseline_pe=np.ones(1, dtype=np.float32),
                dgp_group_ids=("A",),
            )

    def test_03_source_live_digest_is_revalidated(self) -> None:
        source = _small_source()
        source.features.setflags(write=True)
        source.features[0, 0] = np.float32(9.0)
        with self.assertRaises(CausalValuationContractError):
            validate_canonical_source(source)

    def test_04_windows_are_rederived_from_source(self) -> None:
        batch = build_causal_prefix_windows(_small_source())
        bad = _clone(batch, values=batch.values.copy())
        bad.values[-1, -1, 1] = np.float32(99.0)
        with self.assertRaises(CausalValuationContractError):
            sequence_batch_sha256(bad)

    def test_05_missing_age_uses_global_session_distance(self) -> None:
        batch = build_causal_prefix_windows(_small_source(gap=10))
        self.assertEqual(float(batch.age_sessions[1, -1, 0]), 10.0)
        self.assertEqual(tuple(batch.window_session_indices[1, -2:]), (0, 10))

    def test_06_exact_length_128_cannot_be_rehashed(self) -> None:
        payload = {field.name: getattr(self.batch, field.name) for field in fields(self.batch)}
        payload["values"] = self.batch.values[:, 1:].copy()
        with self.assertRaises(CausalValuationContractError):
            CausalSequenceBatch(**payload)

    def test_07_fold_row_public_constructor_is_closed(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            FoldRowCustody()

    def test_08_caller_supplied_fold_rows_are_rejected(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            TorchSequenceCustody.from_fold_rows(
                self.batch,
                self.fold_rows,
                candidate_id=STATIC_ID,
                split="train",
                device="cpu",
            )

    def test_09_identity_free_torch_constructor_is_closed(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            TorchSequenceCustody.from_sequence_batch(self.batch, device="cpu")

    def test_10_torch_public_constructor_is_factory_only(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            TorchSequenceCustody()

    def test_11_v3_fabricated_train_eligibility_resealed_is_rejected(self) -> None:
        positions = (*self.fold_rows.train_positions[1:], 756)
        mask = np.zeros_like(self.fold_rows.train_mask)
        mask[np.asarray(positions)] = True
        mask.setflags(write=False)
        forged = _clone(
            self.fold_rows,
            train_mask=mask,
            train_positions=positions,
            train_row_identity_sha256="1" * 64,
            custody_sha256="0" * 64,
        )
        object.__setattr__(
            forged,
            "custody_sha256",
            fold_row_custody_sha256(forged, include_stored_hash=False),
        )
        with self.assertRaises(CausalValuationContractError):
            validate_fold_row_custody(self.batch, forged)

    def test_12_v3_live_fold_reseal_is_rejected_downstream(self) -> None:
        purge = list(self.fold.purge_dates)
        purge[0] = self.fold.embargo_dates[0]
        bad_fold = _clone(self.fold, purge_dates=tuple(purge), fold_sha256="0" * 64)
        object.__setattr__(
            bad_fold,
            "fold_sha256",
            chronological_fold_sha256(bad_fold, include_stored_hash=False),
        )
        bad_rows = _clone(self.fold_rows, fold=bad_fold, custody_sha256="0" * 64)
        object.__setattr__(
            bad_rows,
            "custody_sha256",
            fold_row_custody_sha256(bad_rows, include_stored_hash=False),
        )
        bad_inputs = _clone(
            self.train_inputs,
            fold_rows=bad_rows,
            fold_sha256=bad_fold.fold_sha256,
            fold_row_custody_sha256=bad_rows.custody_sha256,
            tensor_custody_sha256="0" * 64,
        )
        object.__setattr__(
            bad_inputs,
            "tensor_custody_sha256",
            torch_sequence_custody_sha256(bad_inputs, include_stored_hash=False),
        )
        with self.assertRaises(CausalValuationContractError):
            self.static_model(bad_inputs)

    def test_13_canonical_fold_factory_accepts_only_calendar_derivation(self) -> None:
        bad_fold = _clone(self.fold, validation_end_date=self.fold.train_end_date)
        with self.assertRaises(CausalValuationContractError):
            TorchSequenceCustody.from_canonical_fold(
                self.batch,
                bad_fold,
                candidate_id=STATIC_ID,
                split="train",
                device="cpu",
            )

    def test_14_tensor_drift_is_rejected_at_direct_model_entry(self) -> None:
        bad = _clone(self.train_inputs, values=self.train_inputs.values.clone())
        bad.values[0, -1, 0] += 1.0
        with self.assertRaises(CausalValuationContractError):
            self.static_model(bad)

    def test_15_candidate_membership_checked_by_model(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            build_fixed_model(
                "cvtcn_v5_tcn_residual", training_inputs=self.train_inputs
            )

    def test_16_static_control_is_same_row_only(self) -> None:
        changed = np.array(self.source.features, copy=True)
        changed[:899] = np.where(
            np.isfinite(changed[:899]), np.float32(-44.0), changed[:899]
        )
        source = build_canonical_source_custody(
            external_source_sha256=self.source.external_source_sha256,
            entity_ids=self.source.entity_ids,
            dates=self.source.dates,
            global_session_dates=self.source.global_session_dates,
            feature_columns=FEATURE_COLUMNS,
            features=changed,
            baseline_pe=np.array(self.source.baseline_pe, copy=True),
            dgp_group_ids=self.source.dgp_group_ids,
        )
        batch = build_causal_prefix_windows(source)
        fold = build_global_date_fold(
            batch,
            fold_id=self.fold.fold_id,
            train_end_date=self.fold.train_end_date,
            validation_end_date=self.fold.validation_end_date,
        )
        original = TorchSequenceCustody.from_canonical_fold(
            self.batch,
            self.fold,
            candidate_id=STATIC_ID,
            split="validation",
            device="cpu",
        )
        alternate = TorchSequenceCustody.from_canonical_fold(
            batch, fold, candidate_id=STATIC_ID, split="validation", device="cpu"
        )
        with torch.no_grad():
            left = self.static_model(original).log_expected_pe[-1, -1]
            right = self.static_model(alternate).log_expected_pe[-1, -1]
        self.assertTrue(torch.equal(left, right))

    def test_17_sparse_validation_history_overlap_is_rejected(self) -> None:
        calendar = tuple(
            (date(2021, 1, 1) + timedelta(days=index)).isoformat()
            for index in range(900)
        )
        rows = [(calendar[index], "A") for index in range(900)]
        rows.extend(((calendar[700], "B"), (calendar[888], "B")))
        rows.sort()
        source = build_canonical_source_custody(
            external_source_sha256=hashlib.sha256(b"sparse-v5").hexdigest(),
            entity_ids=tuple(entity for _, entity in rows),
            dates=tuple(raw_date for raw_date, _ in rows),
            global_session_dates=calendar,
            feature_columns=FEATURE_COLUMNS,
            features=np.zeros((len(rows), 42), dtype=np.float32),
            baseline_pe=np.full(len(rows), 15.0, dtype=np.float32),
            dgp_group_ids=tuple("ABCDEFGHIJ"[index % 10] for index in range(len(rows))),
        )
        batch = build_causal_prefix_windows(source)
        fold = build_global_date_fold(
            batch,
            fold_id="sparse_overlap",
            train_end_date=calendar[755],
            validation_end_date=calendar[899],
        )
        with self.assertRaises(CausalValuationContractError):
            chronological_fold_row_masks(batch, fold)

    def test_18_mapping_public_constructor_is_closed(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            NuisanceTrainingCustody()

    def test_19_reordered_mapping_rehashed_is_rejected(self) -> None:
        groups = list(self.mapping.group_ids_by_training_row)
        groups[0], groups[1] = groups[1], groups[0]
        indices = tuple("ABCDEFGHIJ".index(value) for value in groups)
        forged = _clone(
            self.mapping,
            group_ids_by_training_row=tuple(groups),
            group_indices_by_training_row=indices,
            mapping_sha256="0" * 64,
        )
        object.__setattr__(forged, "mapping_sha256", nuisance_mapping_sha256(forged))
        with self.assertRaises(CausalValuationContractError):
            TrainingOnlyDGPNuisance(forged).projected_effects(
                mapping=forged, training_inputs=self.train_inputs
            )

    def test_20_renamed_group_universe_rehashed_is_rejected(self) -> None:
        forged = _clone(
            self.mapping,
            group_universe=(*self.mapping.group_universe[:-1], "K"),
            mapping_sha256="0" * 64,
        )
        object.__setattr__(forged, "mapping_sha256", nuisance_mapping_sha256(forged))
        with self.assertRaises(CausalValuationContractError):
            TrainingOnlyDGPNuisance(forged).projected_effects(
                mapping=forged, training_inputs=self.train_inputs
            )

    def test_21_prediction_vectors_are_absent_from_public_training_apis(self) -> None:
        for function in (build_end_to_end_nuisance_custody, fixed_training_loss):
            self.assertNotIn("predicted_log_pe", inspect.signature(function).parameters)
            self.assertIn("prediction_artifact", inspect.signature(function).parameters)

    def test_22_sealed_prediction_load_recomputes_exact_forward(self) -> None:
        loaded = load_sealed_model_prediction_artifact(
            artifact=self.prediction_artifact, training_inputs=self.train_inputs
        )
        self.assertTrue(torch.equal(loaded, self.prediction_artifact.prediction_values))

    def test_23_resealed_caller_prediction_values_are_rejected(self) -> None:
        values = self.prediction_artifact.prediction_values.clone()
        values[0] += 0.01
        value_hash = _tensor_hash(
            values, domain=b"expected_pe.causal_valuation_tcn_v5.predictions.v2\0"
        )
        forged = _clone(
            self.prediction_artifact,
            prediction_values=values,
            prediction_values_sha256=value_hash,
            artifact_sha256="0" * 64,
        )
        object.__setattr__(
            forged, "artifact_sha256", sealed_prediction_artifact_sha256(forged)
        )
        with self.assertRaises(CausalValuationContractError):
            load_sealed_model_prediction_artifact(
                artifact=forged, training_inputs=self.train_inputs
            )

    def test_24_nonfinite_deploy_state_is_rejected(self) -> None:
        bad = {name: value.clone() for name, value in self.state.items()}
        first = next(iter(bad))
        bad[first].reshape(-1)[0] = float("nan")
        with self.assertRaises(CausalValuationContractError):
            build_sealed_model_prediction_artifact(
                training_inputs=self.train_inputs, deployable_state=bad
            )

    def test_25_unrelated_state_artifact_cannot_replace_bound_artifact(self) -> None:
        torch.manual_seed(991)
        state = build_fixed_model(
            STATIC_ID, training_inputs=self.train_inputs
        ).deployable_state_dict()
        other = build_sealed_model_prediction_artifact(
            training_inputs=self.train_inputs, deployable_state=state
        )
        with self.assertRaises(CausalValuationContractError):
            fixed_training_loss(
                custody=self.end_to_end,
                training_inputs=self.train_inputs,
                mapping=self.mapping,
                nuisance=self.nuisance,
                prediction_artifact=other,
                target_log_pe=self.target,
                valid_mask=self.valid,
            )

    def test_26_nonfinite_target_is_rejected(self) -> None:
        target = self.target.clone()
        target[0] = float("inf")
        with self.assertRaises(CausalValuationContractError):
            build_end_to_end_nuisance_custody(
                training_inputs=self.train_inputs,
                mapping=self.mapping,
                nuisance=self.nuisance,
                prediction_artifact=self.prediction_artifact,
                target_log_pe=target,
                valid_mask=self.valid,
            )

    def test_27_nan_nuisance_parameter_is_rejected(self) -> None:
        nuisance = TrainingOnlyDGPNuisance(self.mapping)
        nuisance.raw_effects.data[0] = float("nan")
        with self.assertRaises(CausalValuationContractError):
            nuisance.projected_effects(mapping=self.mapping, training_inputs=self.train_inputs)

    def test_28_infinite_nuisance_parameter_is_rejected(self) -> None:
        nuisance = TrainingOnlyDGPNuisance(self.mapping)
        nuisance.raw_effects.data[0] = float("inf")
        with self.assertRaises(CausalValuationContractError):
            nuisance.projected_effects(mapping=self.mapping, training_inputs=self.train_inputs)

    def test_29_actual_weighted_sum_and_residual_are_recorded(self) -> None:
        receipt = build_marginalization_receipt(
            custody=self.end_to_end,
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=self.nuisance,
            prediction_artifact=self.prediction_artifact,
            target_log_pe=self.target,
            valid_mask=self.valid,
        )
        effects, weights, actual, residual = self.nuisance.projected_effects(
            mapping=self.mapping, training_inputs=self.train_inputs
        )
        self.assertTrue(bool(torch.isfinite(effects).all().item()))
        self.assertEqual(receipt.nuisance_projection, NUISANCE_PROJECTION)
        self.assertEqual(receipt.nuisance_zero_semantics, NUISANCE_ZERO_SEMANTICS)
        self.assertEqual(
            receipt.nuisance_effect_weighted_sum, float(actual.detach().cpu().item())
        )
        self.assertEqual(
            receipt.nuisance_projection_residual, float(residual.detach().cpu().item())
        )
        self.assertEqual(float(weights.sum().item()), 1.0)

    def test_30_nonzero_projection_claim_resealed_is_rejected(self) -> None:
        forged = _clone(
            self.end_to_end,
            nuisance_effect_weighted_sum=0.1,
            nuisance_projection_residual=0.1,
            custody_sha256="0" * 64,
        )
        object.__setattr__(
            forged,
            "custody_sha256",
            end_to_end_nuisance_custody_sha256(forged),
        )
        with self.assertRaises(CausalValuationContractError):
            EndToEndNuisanceCustody.__post_init__(forged)

    def test_31_nan_projection_claim_resealed_is_rejected(self) -> None:
        forged = _clone(
            self.end_to_end,
            nuisance_effect_weighted_sum=float("nan"),
            nuisance_projection_residual=float("nan"),
        )
        with self.assertRaises(CausalValuationContractError):
            EndToEndNuisanceCustody.__post_init__(forged)

    def test_32_fixed_loss_is_finite_after_full_revalidation(self) -> None:
        loss = fixed_training_loss(
            custody=self.end_to_end,
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=self.nuisance,
            prediction_artifact=self.prediction_artifact,
            target_log_pe=self.target,
            valid_mask=self.valid,
        )
        self.assertTrue(bool(torch.isfinite(loss).item()))

    def test_33_decision_position_reseal_is_rejected(self) -> None:
        forged = _clone(
            self.prediction_artifact,
            sequence_decision_position=126,
            artifact_sha256="0" * 64,
        )
        object.__setattr__(
            forged, "artifact_sha256", sealed_prediction_artifact_sha256(forged)
        )
        with self.assertRaises(CausalValuationContractError):
            load_sealed_model_prediction_artifact(
                artifact=forged, training_inputs=self.train_inputs
            )

    def test_34_exact_clean_tree_rejects_extra_pyc_and_reparse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "a.py").write_text("x=1\n", encoding="utf-8")
            require_clean_tree(root, expected_files={"a.py"}, expected_directories=set())
            (root / "extra.pyc").write_bytes(b"shadow")
            with self.assertRaises(CausalPathError):
                require_clean_tree(root, expected_files={"a.py"}, expected_directories=set())
            (root / "extra.pyc").unlink()
            with mock.patch(
                "research.model_zoo.causal_valuation_tcn_v5.path_guard._metadata_is_reparse",
                return_value=True,
            ):
                with self.assertRaises(CausalPathError):
                    require_clean_tree(
                        root, expected_files={"a.py"}, expected_directories=set()
                    )

    def test_35_v3_terminal_no_go_binding_is_exact(self) -> None:
        self.assertEqual(
            V3_AUDIT_BINDING["finding_ids"],
            ("P0-001", "P1-001", "P1-002", "P1-003"),
        )
        self.assertIn("NO_GO", V3_AUDIT_BINDING["verdict"])

    def test_36_launcher_and_candidate_universe_are_exact(self) -> None:
        launcher = Path(
            "scripts/model_lab/causal_valuation_tcn_v5/trusted_launcher.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--spec", launcher)
        self.assertIn("VerifiedBytesFinder", launcher)
        self.assertEqual(
            CANDIDATE_IDS,
            (
                "cvtcn_v5_tcn_residual",
                "cvtcn_v5_grud_residual",
                "cvtcn_v5_static_state_mlp",
            ),
        )

    def test_37_v1_to_v4_and_live_v5_source_custody_passes(self) -> None:
        receipt = run_source_audit(
            Path(
                "C:/Users/minsu/Documents/EPS/"
                "PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
            )
        )
        self.assertTrue(receipt.passed)
        self.assertTrue(receipt.v3_design_binding_passed)
        self.assertTrue(receipt.v3_terminal_audit_binding_passed)
        self.assertTrue(receipt.v4_design_binding_passed)
        self.assertTrue(receipt.v4_terminal_audit_binding_passed)

    def test_38_v4_terminal_no_go_binding_is_exact(self) -> None:
        self.assertEqual(
            V4_AUDIT_BINDING["finding_ids"], ("P0-001", "P1-001", "P1-002")
        )
        self.assertEqual(
            V4_AUDIT_BINDING["checksums_raw_sha256"],
            "949861fb6ba0c0c9e0ba65c5b69a3cecd93855597472d535a65e6977da4c67e2",
        )
        self.assertIn("NO_GO", V4_AUDIT_BINDING["verdict"])

    def test_39_free_training_center_tensor_surface_is_absent(self) -> None:
        self.assertFalse(hasattr(self.static_model, "set_training_centers"))
        self.assertNotIn("centers", inspect.signature(build_fixed_model).parameters)
        self.assertNotIn(
            "centers", inspect.signature(build_training_center_custody).parameters
        )
        with self.assertRaises(CausalValuationContractError):
            type(self.static_model)()(self.train_inputs)

    def test_40_validation_row_substitution_cannot_build_training_centers(self) -> None:
        validation = TorchSequenceCustody.from_canonical_fold(
            self.batch,
            self.fold,
            candidate_id=STATIC_ID,
            split="validation",
            device="cpu",
        )
        with self.assertRaises(CausalValuationContractError):
            build_training_center_custody(validation)
        relabeled = _clone(validation, split="train", tensor_custody_sha256="0" * 64)
        object.__setattr__(
            relabeled,
            "tensor_custody_sha256",
            torch_sequence_custody_sha256(relabeled, include_stored_hash=False),
        )
        with self.assertRaises(CausalValuationContractError):
            build_training_center_custody(relabeled)

    def test_41_robust_center_is_train_row_bound_lower_median(self) -> None:
        custody = build_training_center_custody(self.train_inputs)
        finite = self.train_inputs.values[:, :, 0][
            self.train_inputs.observed_mask[:, :, 0]
        ]
        ordered = torch.sort(finite.to(torch.float32), stable=True).values
        expected = float(ordered[(ordered.numel() - 1) // 2].item())
        self.assertEqual(custody.centers[0], expected)
        self.assertEqual(custody.training_positions, self.train_inputs.member_positions)
        self.assertEqual(
            custody.training_row_identity_sha256,
            self.train_inputs.member_row_identity_sha256,
        )
        self.assertEqual(custody, self.static_model.training_center_custody)
        self.assertEqual(
            custody.custody_sha256, training_center_custody_sha256(custody)
        )

    def test_42_output_changing_center_state_injection_is_rejected(self) -> None:
        bad = {name: value.clone() for name, value in self.state.items()}
        bad["encoder.training_center"] += 100.0
        with self.assertRaises(CausalValuationContractError):
            build_sealed_model_prediction_artifact(
                training_inputs=self.train_inputs, deployable_state=bad
            )
        self.static_model.load_state_dict(bad, strict=True)
        try:
            with self.assertRaises(CausalValuationContractError):
                self.static_model(self.train_inputs)
        finally:
            self.static_model.load_state_dict(self.state, strict=True)

    def test_43_prediction_artifact_binds_center_provenance(self) -> None:
        forged = _clone(
            self.prediction_artifact,
            training_center_values_sha256="1" * 64,
            artifact_sha256="0" * 64,
        )
        object.__setattr__(
            forged, "artifact_sha256", sealed_prediction_artifact_sha256(forged)
        )
        with self.assertRaises(CausalValuationContractError):
            load_sealed_model_prediction_artifact(
                artifact=forged, training_inputs=self.train_inputs
            )

    def test_44_raw_receptive_fields_and_no_future_match_all_gradients(self) -> None:
        self.assertEqual(CONVOLUTIONAL_RECEPTIVE_FIELD, 125)
        self.assertEqual(PURGE_SESSIONS, max(END_TO_END_RAW_INPUT_RECEPTIVE_FIELD.values()) - 1)
        rf_batch, rf_fold = _receptive_field_fixture()
        for candidate_id in CANDIDATE_IDS:
            train_inputs = TorchSequenceCustody.from_canonical_fold(
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
            live = _clone(validation, values=values, tensor_custody_sha256="0" * 64)
            object.__setattr__(
                live,
                "tensor_custody_sha256",
                torch_sequence_custody_sha256(live, include_stored_hash=False),
            )
            torch.manual_seed(2026082108)
            model = build_fixed_model(
                candidate_id, training_inputs=train_inputs
            ).eval()
            final = model(live).log_expected_pe[-1, -1]
            gradient = torch.autograd.grad(final, values, retain_graph=True)[0][-1]
            active = tuple(
                bool((gradient[position].abs().max() > 0.0).item())
                for position in range(SEQUENCE_LENGTH)
            )
            declared = END_TO_END_RAW_INPUT_RECEPTIVE_FIELD[candidate_id]
            self.assertFalse(any(active[: SEQUENCE_LENGTH - declared]))
            self.assertTrue(active[SEQUENCE_LENGTH - declared])
            self.assertTrue(active[-1])
            prior = model(live).log_expected_pe[-1, 64]
            prior_gradient = torch.autograd.grad(prior, values)[0][-1]
            self.assertEqual(
                float(prior_gradient[65:].abs().max().item()), 0.0
            )

    def test_45_every_candidate_has_no_train_validation_raw_row_overlap(self) -> None:
        for candidate_id in CANDIDATE_IDS:
            train_inputs = TorchSequenceCustody.from_canonical_fold(
                self.batch,
                self.fold,
                candidate_id=candidate_id,
                split="train",
                device="cpu",
            )
            validation = TorchSequenceCustody.from_canonical_fold(
                self.batch,
                self.fold,
                candidate_id=candidate_id,
                split="validation",
                device="cpu",
            )
            train_raw = set(
                train_inputs.window_session_indices[
                    train_inputs.padding_mask
                ].tolist()
            )
            validation_raw = set(
                validation.window_session_indices[validation.padding_mask].tolist()
            )
            self.assertFalse(train_raw & validation_raw)
            self.assertEqual(
                train_inputs.fold_rows.train_validation_window_overlap_count, 0
            )

    def test_46_sub_tolerance_forged_receipt_is_recomputed_and_rejected(self) -> None:
        receipt = build_marginalization_receipt(
            custody=self.end_to_end,
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=self.nuisance,
            prediction_artifact=self.prediction_artifact,
            target_log_pe=self.target,
            valid_mask=self.valid,
        )
        with self.assertRaises((TypeError, CausalValuationContractError)):
            replace(
                receipt,
                nuisance_effect_weighted_sum=5.0e-13,
                nuisance_projection_residual=5.0e-13,
            )
        forged = _clone(
            receipt,
            nuisance_effect_weighted_sum=5.0e-13,
            nuisance_projection_residual=5.0e-13,
        )
        with self.assertRaises(CausalValuationContractError):
            verify_marginalization_receipt(
                receipt=forged,
                custody=self.end_to_end,
                training_inputs=self.train_inputs,
                mapping=self.mapping,
                nuisance=self.nuisance,
                prediction_artifact=self.prediction_artifact,
                target_log_pe=self.target,
                valid_mask=self.valid,
            )

    def test_47_bounded_nuisance_values_are_actual_and_finite(self) -> None:
        nuisance = TrainingOnlyDGPNuisance(self.mapping)
        nuisance.raw_effects.data.copy_(torch.linspace(-0.4, 0.5, 10))
        custody = build_end_to_end_nuisance_custody(
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=nuisance,
            prediction_artifact=self.prediction_artifact,
            target_log_pe=self.target,
            valid_mask=self.valid,
        )
        receipt = build_marginalization_receipt(
            custody=custody,
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=nuisance,
            prediction_artifact=self.prediction_artifact,
            target_log_pe=self.target,
            valid_mask=self.valid,
        )
        _, _, actual_sum, actual_residual = nuisance.projected_effects(
            mapping=self.mapping, training_inputs=self.train_inputs
        )
        self.assertEqual(
            receipt.nuisance_effect_weighted_sum, float(actual_sum.item())
        )
        self.assertEqual(
            receipt.nuisance_projection_residual, float(actual_residual.item())
        )
        self.assertLessEqual(
            receipt.nuisance_projection_residual, NUISANCE_PROJECTION_TOLERANCE
        )
        self.assertEqual(receipt.nuisance_zero_semantics, NUISANCE_ZERO_SEMANTICS)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(V5ContractChecks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print(
        json.dumps(
            {
                "schema_version": "expected_pe.causal_valuation_tcn_v5.adversarial_tests.v1",
                "status": "PASS_CAUSAL_VALUATION_TCN_V5_ADVERSARIAL_TESTS",
                "tests_run": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "scope": "synthetic_contract_and_source_attacks_only",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
