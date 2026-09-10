"""Stdlib unittest entry point executed only by the pinned torch interpreter."""

from __future__ import annotations

from datetime import date, timedelta
import inspect
from pathlib import Path
import unittest

import numpy as np
import torch

from research.model_zoo.causal_valuation_tcn_v1.contracts import (
    CANDIDATE_IDS,
    FEATURE_COLUMNS,
    MAX_ABS_LOG_CORRECTION,
    RECEPTIVE_FIELD,
    VARIANTS,
    CausalValuationContractError,
    contract_payload,
)
from research.model_zoo.causal_valuation_tcn_v1.custody import (
    ChronologicalFold,
    build_causal_prefix_windows,
    chronological_fold_row_masks,
)
from research.model_zoo.causal_valuation_tcn_v1.models import (
    build_fixed_model,
    parameter_counts,
)
from research.model_zoo.causal_valuation_tcn_v1.source_audit import run_source_audit
from research.model_zoo.causal_valuation_tcn_v1.training import (
    TrainingOnlyDGPNuisance,
    build_marginalization_receipt,
    fixed_training_loss,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _flat_fixture() -> tuple[list[str], list[str], np.ndarray, np.ndarray]:
    entities: list[str] = []
    dates: list[str] = []
    rows: list[np.ndarray] = []
    baselines: list[float] = []
    rng = np.random.default_rng(2026082107)
    start = date(2024, 1, 2)
    for offset in range(8):
        current = (start + timedelta(days=offset)).isoformat()
        for entity_position, entity in enumerate(("ENTITY_A", "ENTITY_B")):
            entities.append(entity)
            dates.append(current)
            row = rng.normal(size=42).astype(np.float32)
            if (offset + entity_position) % 3 == 0:
                row[(offset + entity_position) % 42] = np.nan
            rows.append(row)
            baselines.append(15.0 + 0.1 * offset + 0.2 * entity_position)
    return entities, dates, np.stack(rows), np.asarray(baselines, dtype=np.float32)


class CausalValuationTCNV1Tests(unittest.TestCase):
    def test_contract_has_exact_three_variants_and_no_sweep(self) -> None:
        self.assertEqual(len(VARIANTS), 3)
        self.assertEqual(
            CANDIDATE_IDS,
            (
                "cvtcn_v1_tcn_residual",
                "cvtcn_v1_grud_residual",
                "cvtcn_v1_static_state_mlp",
            ),
        )
        self.assertEqual(RECEPTIVE_FIELD, 125)
        payload = contract_payload()
        self.assertFalse(payload["fixed_training_policy"]["hyperparameter_sweep"])
        self.assertFalse(payload["chronological_fold_policy"]["same_row_target_as_input"])
        self.assertFalse(payload["access_boundary"]["launch_authority_created"])

    def test_entity_prefix_custody_mask_age_and_fold(self) -> None:
        entities, dates, features, baseline = _flat_fixture()
        batch = build_causal_prefix_windows(
            entity_ids=entities,
            dates=dates,
            feature_columns=FEATURE_COLUMNS,
            features=features,
            baseline_pe=baseline,
        )
        self.assertEqual(batch.values.shape, (16, 128, 42))
        self.assertEqual(batch.padding_mask.sum(axis=1).tolist(), [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8])
        self.assertTrue(np.array_equal(batch.observed_mask, np.isfinite(batch.values) & batch.padding_mask[:, :, None]))
        self.assertTrue(np.all(batch.age_sessions >= 0.0))
        fold = ChronologicalFold(
            fold_id="unit_fold",
            train_end_date=dates[7],
            validation_start_date=dates[8],
            validation_end_date=dates[-1],
        )
        train, validation = chronological_fold_row_masks(batch, fold)
        self.assertFalse(bool(np.any(train & validation)))
        self.assertEqual(int(train.sum()), 8)
        self.assertEqual(int(validation.sum()), 8)

    def test_custody_rejects_sort_identity_and_feature_drift(self) -> None:
        entities, dates, features, baseline = _flat_fixture()
        attacked_entities = entities.copy()
        attacked_entities[0], attacked_entities[1] = attacked_entities[1], attacked_entities[0]
        with self.assertRaisesRegex(CausalValuationContractError, "sorted"):
            build_causal_prefix_windows(
                entity_ids=attacked_entities,
                dates=dates,
                feature_columns=FEATURE_COLUMNS,
                features=features,
                baseline_pe=baseline,
            )
        with self.assertRaisesRegex(CausalValuationContractError, "column"):
            build_causal_prefix_windows(
                entity_ids=entities,
                dates=dates,
                feature_columns=tuple(reversed(FEATURE_COLUMNS)),
                features=features,
                baseline_pe=baseline,
            )

    def test_all_models_are_bounded_target_free_and_causal(self) -> None:
        entities, dates, features, baseline = _flat_fixture()
        batch = build_causal_prefix_windows(
            entity_ids=entities,
            dates=dates,
            feature_columns=FEATURE_COLUMNS,
            features=features,
            baseline_pe=baseline,
        )
        values = torch.from_numpy(batch.values)
        observed = torch.from_numpy(batch.observed_mask)
        ages = torch.from_numpy(batch.age_sessions)
        padding = torch.from_numpy(batch.padding_mask)
        base = torch.from_numpy(batch.baseline_pe)
        for candidate_position, candidate_id in enumerate(CANDIDATE_IDS):
            torch.manual_seed(2026082107 + candidate_position)
            model = build_fixed_model(candidate_id).eval()
            parameters = inspect.signature(model.forward).parameters
            self.assertNotIn("target", parameters)
            self.assertNotIn("truth", parameters)
            with torch.no_grad():
                original = model(values, observed, ages, padding, base)
                attacked_values = values.clone()
                attacked_base = base.clone()
                attacked_values[:, -1] = torch.where(
                    observed[:, -1], torch.full_like(attacked_values[:, -1], 50.0), attacked_values[:, -1]
                )
                attacked_base[:, -1] = 100.0
                attacked = model(attacked_values, observed, ages, padding, attacked_base)
            self.assertLessEqual(
                float(original.bounded_log_correction.abs().max()),
                MAX_ABS_LOG_CORRECTION + 1e-7,
            )
            torch.testing.assert_close(
                original.log_expected_pe[:, :-1],
                attacked.log_expected_pe[:, :-1],
                rtol=0.0,
                atol=0.0,
            )

    def test_parameter_budgets_and_dgp_marginalization(self) -> None:
        counts = parameter_counts()
        for variant in VARIANTS:
            self.assertLessEqual(counts[variant.candidate_id], variant.parameter_budget_max)
        model = build_fixed_model(CANDIDATE_IDS[0])
        nuisance = TrainingOnlyDGPNuisance(2)
        predicted = torch.zeros((2, 3), dtype=torch.float32, requires_grad=True)
        target = torch.full((2, 3), 0.02, dtype=torch.float32)
        valid = torch.ones((2, 3), dtype=torch.bool)
        groups = torch.tensor([[0, 1, 0], [1, 0, 1]], dtype=torch.int64)
        loss = fixed_training_loss(
            predicted_log_pe=predicted,
            target_log_pe=target,
            valid_mask=valid,
            nuisance=nuisance,
            dgp_group_index=groups,
        )
        self.assertTrue(bool(torch.isfinite(loss)))
        loss.backward()
        deploy = model.deployable_state_dict()
        receipt = build_marginalization_receipt(
            candidate_id=CANDIDATE_IDS[0],
            nuisance=nuisance,
            group_index=groups,
            deployable_state_keys=tuple(deploy),
        )
        self.assertEqual(receipt.deploy_nuisance_value, 0.0)
        self.assertFalse(receipt.nuisance_in_deployable_state)

    def test_static_source_isolation_and_bound_references(self) -> None:
        receipt = run_source_audit(PROJECT_ROOT)
        self.assertTrue(receipt.passed, receipt.payload())
        self.assertEqual(receipt.protected_payload_open_count, 0)
        self.assertEqual(receipt.score_call_count, 0)
        self.assertEqual(receipt.registry_mutation_count, 0)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False)
    if not result.result.wasSuccessful():
        raise SystemExit(1)
    print("PASS_CAUSAL_VALUATION_TCN_V1_TORCH_CHECKS")
