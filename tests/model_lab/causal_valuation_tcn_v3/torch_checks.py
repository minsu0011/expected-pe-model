"""Synthetic-only adversarial and positive contract checks for TCN V3."""

from __future__ import annotations

from dataclasses import fields, replace
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import numpy as np
import torch

from research.model_zoo.causal_valuation_tcn_v3.contracts import (
    CANDIDATE_IDS,
    EMBARGO_SESSIONS,
    FEATURE_COLUMNS,
    MIN_PREFIX_TRAIN_ROWS,
    PURGE_SESSIONS,
    SEQUENCE_LENGTH,
    CausalValuationContractError,
)
from research.model_zoo.causal_valuation_tcn_v3.custody import (
    CausalSequenceBatch,
    build_canonical_source_custody,
    build_causal_prefix_windows,
    build_global_date_fold,
    chronological_fold_row_masks,
    sequence_batch_sha256,
    validate_canonical_source,
)
from research.model_zoo.causal_valuation_tcn_v3.models import (
    TorchSequenceCustody,
    build_fixed_model,
)
from research.model_zoo.causal_valuation_tcn_v3.path_guard import (
    CausalPathError,
    require_clean_tree,
)
from research.model_zoo.causal_valuation_tcn_v3.smoke_worker import _fixture
from research.model_zoo.causal_valuation_tcn_v3.training import (
    TrainingOnlyDGPNuisance,
    build_end_to_end_nuisance_custody,
    build_marginalization_receipt,
    build_nuisance_training_custody,
    fixed_training_loss,
)


STATIC_ID = "cvtcn_v3_static_state_mlp"
ZERO_SHA = "0" * 64


def _small_source(*, gap: int = 10):
    calendar = tuple(
        (date(2026, 1, 1) + timedelta(days=index)).isoformat()
        for index in range(gap + 1)
    )
    features = np.ones((2, 42), dtype=np.float32)
    features[1, 0] = np.nan
    return build_canonical_source_custody(
        external_source_sha256=hashlib.sha256(b"small-v3-source").hexdigest(),
        entity_ids=("E", "E"),
        dates=(calendar[0], calendar[gap]),
        global_session_dates=calendar,
        feature_columns=FEATURE_COLUMNS,
        features=features,
        baseline_pe=np.asarray([10.0, 11.0], dtype=np.float32),
        dgp_group_ids=("A", "B"),
    )


class V3ContractChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        torch.manual_seed(2026082107)
        cls.batch, cls.fold_rows, cls.source = _fixture(np)
        cls.train_inputs = TorchSequenceCustody.from_fold_rows(
            cls.batch,
            cls.fold_rows,
            candidate_id=STATIC_ID,
            split="train",
            device="cpu",
        )
        cls.static_model = build_fixed_model(STATIC_ID).eval()
        cls.static_model.set_training_centers(torch.zeros(42, dtype=torch.float32))
        with torch.no_grad():
            cls.predicted = cls.static_model(cls.train_inputs).log_expected_pe[:, -1]
        cls.target = torch.log(cls.train_inputs.baseline_pe[:, -1]).detach().clone()
        cls.valid = torch.ones_like(cls.target, dtype=torch.bool)
        cls.mapping = build_nuisance_training_custody(cls.train_inputs)
        cls.nuisance = TrainingOnlyDGPNuisance(cls.mapping)
        cls.state = cls.static_model.deployable_state_dict()
        cls.end_to_end = build_end_to_end_nuisance_custody(
            training_inputs=cls.train_inputs,
            mapping=cls.mapping,
            nuisance=cls.nuisance,
            predicted_log_pe=cls.predicted,
            target_log_pe=cls.target,
            valid_mask=cls.valid,
            deployable_state=cls.state,
        )

    def test_01_exact_frozen_geometry_and_fold_policy(self) -> None:
        self.assertEqual(SEQUENCE_LENGTH, 128)
        self.assertEqual(MIN_PREFIX_TRAIN_ROWS, 756)
        self.assertEqual(PURGE_SESSIONS, 127)
        self.assertEqual(EMBARGO_SESSIONS, 5)
        self.assertEqual(len(self.fold_rows.train_positions), 756)
        self.assertEqual(self.fold_rows.fold.purge_sessions, 127)
        self.assertEqual(self.fold_rows.fold.embargo_sessions, 5)
        self.assertGreater(
            self.fold_rows.validation_history_min_session_index,
            self.fold_rows.fold.train_end_session_index,
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

    def test_04_windows_are_rederived_from_source_not_self_authenticated(self) -> None:
        batch = build_causal_prefix_windows(_small_source())
        payload = {field.name: getattr(batch, field.name) for field in fields(batch)}
        payload["values"] = batch.values.copy()
        payload["values"][-1, -1, 1] = np.float32(99.0)
        provisional = object.__new__(CausalSequenceBatch)
        for name, value in payload.items():
            object.__setattr__(provisional, name, value)
        with self.assertRaises(CausalValuationContractError):
            sequence_batch_sha256(provisional)

    def test_05_sparse_missing_age_uses_global_session_distance(self) -> None:
        batch = build_causal_prefix_windows(_small_source(gap=10))
        self.assertEqual(float(batch.age_sessions[0, -1, 0]), 0.0)
        self.assertEqual(float(batch.age_sessions[1, -1, 0]), 10.0)
        self.assertEqual(int(batch.window_session_indices[1, -2]), 0)
        self.assertEqual(int(batch.window_session_indices[1, -1]), 10)

    def test_06_exact_length_128_cannot_be_rehashed_away(self) -> None:
        payload = {field.name: getattr(self.batch, field.name) for field in fields(self.batch)}
        payload["values"] = self.batch.values[:, 1:].copy()
        with self.assertRaises(CausalValuationContractError):
            CausalSequenceBatch(**payload)

    def test_07_identity_free_torch_constructor_is_closed(self) -> None:
        with self.assertRaises(CausalValuationContractError):
            TorchSequenceCustody.from_sequence_batch(self.batch, device="cpu")

    def test_08_torch_session_or_tensor_drift_rejected_at_forward(self) -> None:
        inputs = TorchSequenceCustody.from_fold_rows(
            self.batch,
            self.fold_rows,
            candidate_id=STATIC_ID,
            split="validation",
            device="cpu",
        )
        bad_sessions = inputs.window_session_indices.clone()
        bad_sessions[0, -1] = bad_sessions[0, -2]
        with self.assertRaises(CausalValuationContractError):
            replace(
                inputs,
                window_session_indices=bad_sessions,
                tensor_custody_sha256=ZERO_SHA,
            )
        bad_values = inputs.values.clone()
        bad_values[0, -1, 0] += 1.0
        with self.assertRaises(CausalValuationContractError):
            replace(inputs, values=bad_values, tensor_custody_sha256=ZERO_SHA)

    def test_09_candidate_and_fold_membership_checked_by_model(self) -> None:
        inputs = TorchSequenceCustody.from_fold_rows(
            self.batch,
            self.fold_rows,
            candidate_id=STATIC_ID,
            split="validation",
            device="cpu",
        )
        other = build_fixed_model("cvtcn_v3_tcn_residual").eval()
        with self.assertRaises(CausalValuationContractError):
            other(inputs)

    def test_10_static_control_is_truly_same_row(self) -> None:
        changed = np.array(self.source.features, copy=True)
        changed[:899] = np.where(np.isfinite(changed[:899]), np.float32(-44.0), changed[:899])
        alternate_source = build_canonical_source_custody(
            external_source_sha256=self.source.external_source_sha256,
            entity_ids=self.source.entity_ids,
            dates=self.source.dates,
            global_session_dates=self.source.global_session_dates,
            feature_columns=FEATURE_COLUMNS,
            features=changed,
            baseline_pe=np.array(self.source.baseline_pe, copy=True),
            dgp_group_ids=self.source.dgp_group_ids,
        )
        alternate_batch = build_causal_prefix_windows(alternate_source)
        fold = build_global_date_fold(
            alternate_batch,
            fold_id=self.fold_rows.fold.fold_id,
            train_end_date=self.fold_rows.fold.train_end_date,
            validation_end_date=self.fold_rows.fold.validation_end_date,
        )
        alternate_rows = chronological_fold_row_masks(alternate_batch, fold)
        original = TorchSequenceCustody.from_fold_rows(
            self.batch,
            self.fold_rows,
            candidate_id=STATIC_ID,
            split="validation",
            device="cpu",
        )
        alternate = TorchSequenceCustody.from_fold_rows(
            alternate_batch,
            alternate_rows,
            candidate_id=STATIC_ID,
            split="validation",
            device="cpu",
        )
        with torch.no_grad():
            left = self.static_model(original).log_expected_pe[-1, -1]
            right = self.static_model(alternate).log_expected_pe[-1, -1]
        self.assertTrue(torch.equal(left, right))

    def test_11_sparse_validation_entity_history_overlap_is_rejected(self) -> None:
        calendar = tuple(
            (date(2021, 1, 1) + timedelta(days=index)).isoformat()
            for index in range(900)
        )
        rows = [(calendar[index], "A") for index in range(900)]
        rows.extend(((calendar[700], "B"), (calendar[888], "B")))
        rows.sort()
        entities = tuple(entity for _, entity in rows)
        dates = tuple(raw_date for raw_date, _ in rows)
        source = build_canonical_source_custody(
            external_source_sha256=hashlib.sha256(b"sparse-overlap-v3").hexdigest(),
            entity_ids=entities,
            dates=dates,
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

    def test_12_source_derived_A_to_J_mapping_cannot_be_substituted(self) -> None:
        groups = list(self.mapping.group_ids_by_training_row)
        groups[0], groups[1] = groups[1], groups[0]
        with self.assertRaises(CausalValuationContractError):
            replace(
                self.mapping,
                group_ids_by_training_row=tuple(groups),
                mapping_sha256=ZERO_SHA,
            )

    def test_13_prediction_target_and_row_identity_share_one_loss_custody(self) -> None:
        loss = fixed_training_loss(
            custody=self.end_to_end,
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=self.nuisance,
            predicted_log_pe=self.predicted,
            target_log_pe=self.target,
            valid_mask=self.valid,
            deployable_state=self.state,
        )
        self.assertTrue(bool(torch.isfinite(loss).item()))
        changed = self.predicted.detach().clone()
        changed[0] += 0.01
        with self.assertRaises(CausalValuationContractError):
            fixed_training_loss(
                custody=self.end_to_end,
                training_inputs=self.train_inputs,
                mapping=self.mapping,
                nuisance=self.nuisance,
                predicted_log_pe=changed,
                target_log_pe=self.target,
                valid_mask=self.valid,
                deployable_state=self.state,
            )

    def test_14_unrelated_same_candidate_deploy_state_is_rejected(self) -> None:
        torch.manual_seed(991)
        unrelated = build_fixed_model(STATIC_ID).deployable_state_dict()
        with self.assertRaises(CausalValuationContractError):
            fixed_training_loss(
                custody=self.end_to_end,
                training_inputs=self.train_inputs,
                mapping=self.mapping,
                nuisance=self.nuisance,
                predicted_log_pe=self.predicted,
                target_log_pe=self.target,
                valid_mask=self.valid,
                deployable_state=unrelated,
            )

    def test_15_deploy_receipt_proves_zero_sum_and_nuisance_removal(self) -> None:
        receipt = build_marginalization_receipt(
            custody=self.end_to_end,
            training_inputs=self.train_inputs,
            mapping=self.mapping,
            nuisance=self.nuisance,
            predicted_log_pe=self.predicted,
            target_log_pe=self.target,
            valid_mask=self.valid,
            deployable_state=self.state,
        )
        self.assertEqual(receipt.nuisance_effect_sum, 0.0)
        self.assertFalse(receipt.nuisance_in_deployable_state)
        self.assertNotIn("nuisance", " ".join(receipt.deploy_state_keys))

    def test_16_exact_clean_tree_rejects_extra_pyc_and_reparse(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "a.py").write_text("x=1\n", encoding="utf-8")
            require_clean_tree(root, expected_files={"a.py"}, expected_directories=set())
            (root / "extra.pyc").write_bytes(b"shadow")
            with self.assertRaises(CausalPathError):
                require_clean_tree(root, expected_files={"a.py"}, expected_directories=set())
            (root / "extra.pyc").unlink()
            with mock.patch(
                "research.model_zoo.causal_valuation_tcn_v3.path_guard._metadata_is_reparse",
                return_value=True,
            ):
                with self.assertRaises(CausalPathError):
                    require_clean_tree(root, expected_files={"a.py"}, expected_directories=set())

    def test_17_launcher_has_no_caller_source_map_or_normal_governed_import(self) -> None:
        launcher = Path(
            "scripts/model_lab/causal_valuation_tcn_v3/trusted_launcher.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--spec", launcher)
        self.assertIn("PINNED_SOURCE_LOCK_SHA256", launcher)
        self.assertIn("PINNED_RUNTIME_LOCK_SHA256", launcher)
        self.assertIn("VerifiedBytesFinder", launcher)
        self.assertIn("verified-bytes://", launcher)

    def test_18_candidate_universe_is_exact_and_forward_is_custody_only(self) -> None:
        self.assertEqual(
            CANDIDATE_IDS,
            (
                "cvtcn_v3_tcn_residual",
                "cvtcn_v3_grud_residual",
                "cvtcn_v3_static_state_mlp",
            ),
        )
        for candidate_id in CANDIDATE_IDS:
            self.assertEqual(tuple(build_fixed_model(candidate_id).forward.__annotations__), ("inputs", "return"))


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(V3ContractChecks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print(
        json.dumps(
            {
                "schema_version": "expected_pe.causal_valuation_tcn_v3.adversarial_tests.v1",
                "status": "PASS_CAUSAL_VALUATION_TCN_V3_ADVERSARIAL_TESTS",
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
