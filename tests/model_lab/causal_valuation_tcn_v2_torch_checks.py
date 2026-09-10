"""Adversarial score-free tests for every V1 independent-audit finding."""

from __future__ import annotations

from dataclasses import fields
from datetime import date, timedelta
import hashlib
import inspect
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import numpy as np
import torch

from research.model_zoo.causal_valuation_tcn_v2.artifacts import (
    ARTIFACT_FILE_NAMES,
    BUNDLE_DIRECTORY_NAME,
    DEFAULT_OUTPUT_CONTAINER,
    EXTERNAL_ANCHOR_NAME,
    _json_bytes,
    _raw_sha256,
    _schema_sha256,
    _verify_bundle_against_anchor,
)
from research.model_zoo.causal_valuation_tcn_v2.contracts import (
    CANDIDATE_IDS,
    DGP_GROUP_UNIVERSE,
    EMBARGO_SESSIONS,
    FEATURE_COLUMNS,
    MIN_PREFIX_TRAIN_ROWS,
    PURGE_SESSIONS,
    SEQUENCE_LENGTH,
    V1_AUDIT_BINDING,
    CausalValuationContractError,
    canonical_json_bytes,
    contract_payload,
)
from research.model_zoo.causal_valuation_tcn_v2.custody import (
    CausalSequenceBatch,
    build_causal_prefix_windows,
    build_global_date_fold,
    chronological_fold_row_masks,
    sequence_batch_sha256,
)
from research.model_zoo.causal_valuation_tcn_v2.models import (
    TorchSequenceCustody,
    build_fixed_model,
    reconstruct_deployable_model,
)
from research.model_zoo.causal_valuation_tcn_v2.path_guard import (
    CausalPathError,
    require_clean_tree,
)
from research.model_zoo.causal_valuation_tcn_v2.safe_json import (
    parse_json_object_bytes,
)
from research.model_zoo.causal_valuation_tcn_v2.source_audit import run_source_audit
from research.model_zoo.causal_valuation_tcn_v2.training import (
    TrainingOnlyDGPNuisance,
    build_marginalization_receipt,
    build_nuisance_training_custody,
    fixed_training_loss,
)


LIVE_PROJECT_ROOT = Path(
    os.environ.get(
        "CVTCN_V2_LIVE_PROJECT_ROOT",
        Path(__file__).absolute().parents[2],
    )
)
TEST_OUTPUT_CONTAINER = Path(
    os.environ.get("CVTCN_V2_TEST_OUTPUT_CONTAINER", str(DEFAULT_OUTPUT_CONTAINER))
)


def _calendar(length: int, *, start: date = date(2020, 1, 2)) -> tuple[str, ...]:
    return tuple((start + timedelta(days=position)).isoformat() for position in range(length))


def _small_batch() -> CausalSequenceBatch:
    calendar = _calendar(12, start=date(2025, 1, 2))
    generator = np.random.default_rng(2026082107)
    entities: list[str] = []
    dates: list[str] = []
    values: list[np.ndarray] = []
    baseline: list[float] = []
    for raw_date in calendar:
        for entity_position, entity in enumerate(("A", "B", "C")):
            entities.append(entity)
            dates.append(raw_date)
            row = generator.normal(size=42).astype(np.float32)
            row[(len(values) + entity_position) % 42] = np.nan
            values.append(row)
            baseline.append(14.0 + 0.02 * len(values))
    return build_causal_prefix_windows(
        entity_ids=entities,
        dates=dates,
        global_session_dates=calendar,
        feature_columns=FEATURE_COLUMNS,
        features=np.stack(values),
        baseline_pe=np.asarray(baseline, dtype=np.float32),
    )


def _dense_fold_batch() -> CausalSequenceBatch:
    calendar = _calendar(900)
    generator = np.random.default_rng(1729)
    values = generator.normal(size=(900, 42)).astype(np.float32)
    values[np.arange(900) % 17 == 0, 3] = np.nan
    return build_causal_prefix_windows(
        entity_ids=["ENTITY"] * 900,
        dates=calendar,
        global_session_dates=calendar,
        feature_columns=FEATURE_COLUMNS,
        features=values,
        baseline_pe=np.full(900, 16.0, dtype=np.float32),
    )


def _mutated_batch(batch: CausalSequenceBatch, **changes: object) -> CausalSequenceBatch:
    payload = {field.name: getattr(batch, field.name) for field in fields(batch)}
    payload.update(changes)
    payload["custody_sha256"] = ""
    provisional = object.__new__(CausalSequenceBatch)
    for name, value in payload.items():
        object.__setattr__(provisional, name, value)
    payload["custody_sha256"] = sequence_batch_sha256(provisional)
    return CausalSequenceBatch(**payload)


def _semantic_reseal(payload: dict[str, object]) -> dict[str, object]:
    unsigned = dict(payload)
    unsigned.pop("semantic_sha256", None)
    unsigned["semantic_sha256"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    return unsigned


def _rewrite_checksums(root: Path) -> None:
    payload_names = [name for name in ARTIFACT_FILE_NAMES if name != "CHECKSUMS.sha256"]
    ledger = "".join(
        f"{_raw_sha256((root / name).read_bytes())}  {name}\n" for name in payload_names
    ).encode("ascii")
    (root / "CHECKSUMS.sha256").write_bytes(ledger)


def _self_reseal_core(root: Path, name: str, mutate: object) -> None:
    payload = json.loads((root / name).read_text(encoding="ascii"))
    mutate(payload)
    payload = _semantic_reseal(payload)
    content = _json_bytes(payload)
    (root / name).write_bytes(content)
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="ascii"))
    record = manifest["core_files"][name]
    record["bytes"] = len(content)
    record["raw_sha256"] = _raw_sha256(content)
    record["semantic_sha256"] = payload["semantic_sha256"]
    record["exact_schema_sha256"] = _schema_sha256(payload)
    prefix = "access" if name == "ACCESS_RECEIPT.json" else "design"
    manifest[f"{prefix}_raw_sha256"] = _raw_sha256(content)
    manifest[f"{prefix}_semantic_sha256"] = payload["semantic_sha256"]
    manifest = _semantic_reseal(manifest)
    manifest_content = _json_bytes(manifest)
    (root / "MANIFEST.json").write_bytes(manifest_content)
    seal = json.loads((root / "SEAL.json").read_text(encoding="ascii"))
    seal[f"{prefix}_raw_sha256"] = _raw_sha256(content)
    seal[f"{prefix}_semantic_sha256"] = payload["semantic_sha256"]
    seal["manifest_raw_sha256"] = _raw_sha256(manifest_content)
    seal["manifest_semantic_sha256"] = manifest["semantic_sha256"]
    seal["payload_raw_sha256"][name] = _raw_sha256(content)
    seal["payload_raw_sha256"]["MANIFEST.json"] = _raw_sha256(manifest_content)
    seal["payload_semantic_sha256"][name] = payload["semantic_sha256"]
    seal["payload_semantic_sha256"]["MANIFEST.json"] = manifest["semantic_sha256"]
    seal = _semantic_reseal(seal)
    (root / "SEAL.json").write_bytes(_json_bytes(seal))
    _rewrite_checksums(root)


class CausalValuationTCNV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.small = _small_batch()
        cls.fold_batch = _dense_fold_batch()
        cls.fold = build_global_date_fold(
            cls.fold_batch,
            fold_id="fold_001",
            train_end_date=cls.fold_batch.global_session_dates[755],
            validation_end_date=cls.fold_batch.global_session_dates[899],
        )
        cls.fold_rows = chronological_fold_row_masks(cls.fold_batch, cls.fold)

    def test_01_contract_is_isolated_fixed_and_v1_terminal(self) -> None:
        payload = contract_payload()
        self.assertEqual(payload["sequence_length"], 128)
        self.assertEqual(payload["minimum_prefix_train_rows"], 756)
        self.assertEqual(tuple(payload["dgp_group_universe"]), DGP_GROUP_UNIVERSE)
        self.assertEqual(tuple(V1_AUDIT_BINDING["finding_ids"]), tuple(payload["v1_terminal_audit_binding"]["finding_ids"]))
        self.assertEqual(len(CANDIDATE_IDS), 3)
        self.assertTrue(all("v2" in candidate for candidate in CANDIDATE_IDS))
        self.assertFalse(any(payload["access_boundary"][key] for key in payload["access_boundary"] if key != "permitted_data"))

    def test_02_exact_sequence_age_mask_and_direct_128_surface(self) -> None:
        batch = self.small
        self.assertEqual(batch.values.shape[1:], (SEQUENCE_LENGTH, 42))
        self.assertTrue(np.all(batch.age_sessions[batch.observed_mask] == 0.0))
        observed = np.argwhere(batch.observed_mask)[0]
        attacked_age = batch.age_sessions.copy()
        attacked_age[tuple(observed)] = np.float32(7.0)
        with self.assertRaisesRegex(CausalValuationContractError, "observed value.*age zero"):
            _mutated_batch(batch, age_sessions=attacked_age)
        missing_candidates = np.argwhere(
            batch.padding_mask[:, :, None]
            & ~batch.observed_mask
            & (batch.age_sessions < 4096.0)
        )
        self.assertGreater(len(missing_candidates), 0)
        missing = missing_candidates[0]
        recurrence_attack = batch.age_sessions.copy()
        recurrence_attack[tuple(missing)] += np.float32(1.0)
        with self.assertRaisesRegex(CausalValuationContractError, "exact capped.*recurrence"):
            _mutated_batch(batch, age_sessions=recurrence_attack)
        valid_inputs = TorchSequenceCustody.from_sequence_batch(batch, device="cpu")
        with self.assertRaisesRegex(CausalValuationContractError, "exactly 128"):
            TorchSequenceCustody(
                values=valid_inputs.values[:, :127],
                observed_mask=valid_inputs.observed_mask[:, :127],
                age_sessions=valid_inputs.age_sessions[:, :127],
                age_anchor=valid_inputs.age_anchor,
                window_session_indices=valid_inputs.window_session_indices[:, :127],
                padding_mask=valid_inputs.padding_mask[:, :127],
                baseline_pe=valid_inputs.baseline_pe[:, :127],
                source_custody_sha256=valid_inputs.source_custody_sha256,
                tensor_custody_sha256="0" * 64,
            )

    def test_03_global_calendar_boundaries_and_byte_exact_fold_receipt(self) -> None:
        fold = self.fold
        self.assertEqual(fold.purge_sessions, PURGE_SESSIONS)
        self.assertEqual(fold.embargo_sessions, EMBARGO_SESSIONS)
        self.assertEqual(fold.purge_start_session_index, fold.train_end_session_index + 1)
        self.assertEqual(fold.purge_end_session_index, fold.train_end_session_index + 127)
        self.assertEqual(fold.embargo_start_session_index, fold.train_end_session_index + 128)
        self.assertEqual(fold.embargo_end_session_index, fold.train_end_session_index + 132)
        self.assertEqual(fold.validation_start_session_index, fold.train_end_session_index + 133)
        self.assertEqual(len(fold.purge_dates), 127)
        self.assertEqual(len(fold.embargo_dates), 5)
        self.assertEqual(len(self.fold_rows.train_positions), MIN_PREFIX_TRAIN_ROWS)
        self.assertEqual(self.fold_rows.train_validation_window_overlap_count, 0)
        self.assertGreater(
            self.fold_rows.validation_history_min_session_index,
            fold.train_end_session_index,
        )
        rebuilt = build_global_date_fold(
            self.fold_batch,
            fold_id=fold.fold_id,
            train_end_date=fold.train_end_date,
            validation_end_date=fold.validation_end_date,
        )
        self.assertEqual(rebuilt, fold)
        self.assertEqual(rebuilt.fold_sha256.encode("ascii"), fold.fold_sha256.encode("ascii"))

    def test_04_global_date_intervention_proves_validation_history_disjoint(self) -> None:
        flat = self.fold_batch.values[:, -1].copy()
        train_decisions = np.asarray(
            [value <= self.fold.train_end_date for value in self.fold_batch.decision_dates]
        )
        flat[train_decisions] = np.where(
            np.isfinite(flat[train_decisions]), flat[train_decisions] + 1000.0, flat[train_decisions]
        )
        attacked = build_causal_prefix_windows(
            entity_ids=self.fold_batch.entity_ids,
            dates=self.fold_batch.decision_dates,
            global_session_dates=self.fold_batch.global_session_dates,
            feature_columns=FEATURE_COLUMNS,
            features=flat,
            baseline_pe=self.fold_batch.baseline_pe[:, -1],
        )
        positions = np.asarray(self.fold_rows.validation_positions, dtype=np.int64)
        self.assertTrue(
            np.array_equal(
                self.fold_batch.values[positions], attacked.values[positions], equal_nan=True
            )
        )
        self.assertTrue(np.array_equal(self.fold_batch.observed_mask[positions], attacked.observed_mask[positions]))
        self.assertTrue(np.array_equal(self.fold_batch.age_sessions[positions], attacked.age_sessions[positions]))
        self.assertTrue(np.array_equal(self.fold_batch.window_session_indices[positions], attacked.window_session_indices[positions]))

    def test_05_minimum_rows_and_sparse_history_overlap_fail_closed(self) -> None:
        calendar = _calendar(140, start=date(2030, 1, 1))
        values = np.zeros((140, 42), dtype=np.float32)
        small = build_causal_prefix_windows(
            entity_ids=["E"] * 140,
            dates=calendar,
            global_session_dates=calendar,
            feature_columns=FEATURE_COLUMNS,
            features=values,
            baseline_pe=np.full(140, 15.0, dtype=np.float32),
        )
        fold = build_global_date_fold(
            small,
            fold_id="under_min",
            train_end_date=calendar[3],
            validation_end_date=calendar[-1],
        )
        with self.assertRaisesRegex(CausalValuationContractError, "fewer than 756"):
            chronological_fold_row_masks(small, fold)

        sparse_dates = (*self.fold_batch.global_session_dates[:756], *self.fold_batch.global_session_dates[888:])
        sparse = build_causal_prefix_windows(
            entity_ids=["SPARSE"] * len(sparse_dates),
            dates=sparse_dates,
            global_session_dates=self.fold_batch.global_session_dates,
            feature_columns=FEATURE_COLUMNS,
            features=np.zeros((len(sparse_dates), 42), dtype=np.float32),
            baseline_pe=np.full(len(sparse_dates), 15.0, dtype=np.float32),
        )
        sparse_fold = build_global_date_fold(
            sparse,
            fold_id="sparse_overlap",
            train_end_date=self.fold_batch.global_session_dates[755],
            validation_end_date=self.fold_batch.global_session_dates[-1],
        )
        with self.assertRaisesRegex(CausalValuationContractError, "reaches into.*training"):
            chronological_fold_row_masks(sparse, sparse_fold)

    def test_06_static_control_same_row_only_and_target_not_forward(self) -> None:
        original = self.small
        row = len(original.entity_ids) - 1
        current = SEQUENCE_LENGTH - 1
        prior = current - 1
        feature = int(np.flatnonzero(original.observed_mask[row, prior])[0])
        values = original.values.copy()
        values[row, prior, feature] += np.float32(500.0)
        attacked = _mutated_batch(original, values=values)
        first = TorchSequenceCustody.from_sequence_batch(original, device="cpu")
        second = TorchSequenceCustody.from_sequence_batch(attacked, device="cpu")
        torch.manual_seed(31)
        model = build_fixed_model("cvtcn_v2_static_state_mlp").eval()
        self.assertEqual(tuple(inspect.signature(model.forward).parameters), ("inputs",))
        with torch.no_grad():
            left = model(first).log_expected_pe[row, current]
            right = model(second).log_expected_pe[row, current]
        torch.testing.assert_close(left, right, rtol=0.0, atol=0.0)
        with self.assertRaises(TypeError):
            model(first, target=torch.zeros(1))
        with self.assertRaises(CausalValuationContractError):
            model(first.values)

    def test_07_all_models_causal_bounded_and_custody_only(self) -> None:
        inputs = TorchSequenceCustody.from_sequence_batch(self.small, device="cpu")
        values = self.small.values.copy()
        baseline = self.small.baseline_pe.copy()
        future = np.arange(SEQUENCE_LENGTH) > 71
        values[:, future] = np.where(self.small.observed_mask[:, future], 99.0, values[:, future])
        baseline[:, future] = np.where(self.small.padding_mask[:, future], 100.0, baseline[:, future])
        attacked = _mutated_batch(self.small, values=values.astype(np.float32), baseline_pe=baseline.astype(np.float32))
        attacked_inputs = TorchSequenceCustody.from_sequence_batch(attacked, device="cpu")
        for position, candidate_id in enumerate(CANDIDATE_IDS):
            torch.manual_seed(100 + position)
            model = build_fixed_model(candidate_id).eval()
            with torch.no_grad():
                original_output = model(inputs)
                attacked_output = model(attacked_inputs)
            torch.testing.assert_close(
                original_output.log_expected_pe[:, :72],
                attacked_output.log_expected_pe[:, :72],
                rtol=0.0,
                atol=0.0,
            )

    def test_08_nuisance_candidate_fold_group_parameter_and_deploy_identity(self) -> None:
        groups = tuple(
            DGP_GROUP_UNIVERSE[position % len(DGP_GROUP_UNIVERSE)]
            for position in range(len(self.fold_rows.train_positions))
        )
        mapping = build_nuisance_training_custody(
            candidate_id=CANDIDATE_IDS[0],
            fold_rows=self.fold_rows,
            group_ids_by_training_row=groups,
        )
        nuisance = TrainingOnlyDGPNuisance(mapping)
        model = build_fixed_model(CANDIDATE_IDS[0])
        state = model.deployable_state_dict()
        receipt = build_marginalization_receipt(
            candidate_id=CANDIDATE_IDS[0],
            nuisance=nuisance,
            mapping=mapping,
            deployable_state=state,
        )
        self.assertEqual(receipt.deploy_nuisance_value, 0.0)
        self.assertFalse(receipt.nuisance_in_deployable_state)
        self.assertTrue(receipt.independently_reconstructed)
        reconstructed = reconstruct_deployable_model(CANDIDATE_IDS[0], state)
        self.assertEqual(tuple(sorted(reconstructed.state_dict())), receipt.deploy_state_keys)
        with self.assertRaisesRegex(CausalValuationContractError, "candidate identity"):
            build_nuisance_training_custody(
                candidate_id="unknown_candidate",
                fold_rows=self.fold_rows,
                group_ids_by_training_row=groups,
            )
        renamed = dict(state)
        first_key = sorted(renamed)[0]
        renamed["group_effect.raw_effects"] = renamed.pop(first_key)
        with self.assertRaisesRegex(CausalValuationContractError, "exact key universe"):
            build_marginalization_receipt(
                candidate_id=CANDIDATE_IDS[0],
                nuisance=nuisance,
                mapping=mapping,
                deployable_state=renamed,
            )
        length = len(mapping.training_positions)
        predicted = torch.zeros(length, dtype=torch.float32)
        target = torch.zeros_like(predicted)
        valid = torch.ones(length, dtype=torch.bool)
        wrong_groups = torch.tensor(mapping.group_indices_by_training_row, dtype=torch.int64)
        wrong_groups[0], wrong_groups[1] = wrong_groups[1], wrong_groups[0]
        with self.assertRaisesRegex(CausalValuationContractError, "differs from exact"):
            fixed_training_loss(
                predicted_log_pe=predicted,
                target_log_pe=target,
                valid_mask=valid,
                nuisance=nuisance,
                mapping=mapping,
                dgp_group_index=wrong_groups,
            )

    def test_09_strict_json_type_duplicate_and_closed_schema_errors(self) -> None:
        with self.assertRaisesRegex(CausalValuationContractError, "JSON root must"):
            parse_json_object_bytes(b"[]", artifact="attack.json")
        with self.assertRaisesRegex(CausalValuationContractError, "duplicate JSON key"):
            parse_json_object_bytes(b'{"a":1,"a":2}', artifact="attack.json")

    def test_10_utf8_round_trip_and_exact_source_isolation(self) -> None:
        for name in ("DESIGN.md", "MODEL_HYPOTHESIS.md"):
            content = (
                LIVE_PROJECT_ROOT
                / "research/model_zoo/causal_valuation_tcn_v2"
                / name
            ).read_bytes()
            text = content.decode("utf-8", errors="strict")
            self.assertEqual(text.encode("utf-8"), content)
            self.assertNotIn("\ufffd", text)
            self.assertNotIn("??", text)
        audit = run_source_audit(LIVE_PROJECT_ROOT)
        self.assertTrue(audit.passed, audit.payload())
        self.assertEqual(audit.bytecode_file_count, 0)
        self.assertTrue(audit.v1_audit_binding_passed)
        self.assertTrue(audit.v1_source_closure_passed)

    def test_11_path_universe_rejects_extra_directory_and_bytecode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="cvtcn_v2_path_probe_") as raw:
            root = Path(raw)
            (root / "allowed.py").write_text("x = 1\n", encoding="utf-8")
            (root / "extra").mkdir()
            (root / "extra/attack.pyc").write_bytes(b"attack")
            with self.assertRaises(CausalPathError):
                require_clean_tree(
                    root,
                    expected_files={"allowed.py"},
                    expected_directories=set(),
                )

    @unittest.skipUnless(TEST_OUTPUT_CONTAINER.exists(), "runs against a complete V2 bundle")
    def test_12_external_anchor_rejects_fully_self_resealed_semantic_attacks(self) -> None:
        bundle = TEST_OUTPUT_CONTAINER / BUNDLE_DIRECTORY_NAME
        anchor = (TEST_OUTPUT_CONTAINER / EXTERNAL_ANCHOR_NAME).read_bytes()
        with tempfile.TemporaryDirectory(prefix="cvtcn_v2_artifact_attack_") as raw:
            attack = Path(raw) / "bundle"
            shutil.copytree(bundle, attack)
            _self_reseal_core(
                attack,
                "ACCESS_RECEIPT.json",
                lambda payload: payload.__setitem__("score_computed", True),
            )
            with self.assertRaises(CausalValuationContractError):
                _verify_bundle_against_anchor(attack, anchor, verify_live_source=False)
        with tempfile.TemporaryDirectory(prefix="cvtcn_v2_design_attack_") as raw:
            attack = Path(raw) / "bundle"
            shutil.copytree(bundle, attack)

            def mutate_design(payload: dict[str, object]) -> None:
                contract = payload["contract"]
                contract["variants"][0]["candidate_id"] = "attacker_candidate"
                payload["contract_sha256"] = hashlib.sha256(canonical_json_bytes(contract)).hexdigest()

            _self_reseal_core(attack, "DESIGN_CONTRACT.json", mutate_design)
            with self.assertRaises(CausalValuationContractError):
                _verify_bundle_against_anchor(attack, anchor, verify_live_source=False)

    @unittest.skipUnless(TEST_OUTPUT_CONTAINER.exists(), "runs against a complete V2 bundle")
    def test_13_bundle_schema_extra_child_junction_and_malformed_manifest_fail(self) -> None:
        bundle = TEST_OUTPUT_CONTAINER / BUNDLE_DIRECTORY_NAME
        anchor = (TEST_OUTPUT_CONTAINER / EXTERNAL_ANCHOR_NAME).read_bytes()
        with tempfile.TemporaryDirectory(prefix="cvtcn_v2_bundle_attack_") as raw:
            attack = Path(raw) / "bundle"
            shutil.copytree(bundle, attack)
            (attack / "EXTRA.txt").write_text("attack", encoding="ascii")
            with self.assertRaisesRegex(CausalValuationContractError, "file universe"):
                _verify_bundle_against_anchor(attack, anchor, verify_live_source=False)
        with tempfile.TemporaryDirectory(prefix="cvtcn_v2_manifest_attack_") as raw:
            attack = Path(raw) / "bundle"
            shutil.copytree(bundle, attack)
            (attack / "MANIFEST.json").write_bytes(b"[]")
            with self.assertRaisesRegex(CausalValuationContractError, "JSON root"):
                _verify_bundle_against_anchor(attack, anchor, verify_live_source=False)
        if os.name == "nt":
            with tempfile.TemporaryDirectory(prefix="cvtcn_v2_junction_attack_") as raw:
                junction = Path(raw) / "junction"
                process = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(bundle)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if process.returncode == 0:
                    try:
                        with self.assertRaisesRegex(CausalValuationContractError, "non-reparse"):
                            _verify_bundle_against_anchor(junction, anchor, verify_live_source=False)
                    finally:
                        os.rmdir(junction)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CausalValuationTCNV2Tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)
    print(
        json.dumps(
            {
                "status": "PASS_CAUSAL_VALUATION_TCN_V2_ADVERSARIAL_TESTS",
                "tests_run": result.testsRun,
                "skipped": len(result.skipped),
                "v1_findings_covered": list(V1_AUDIT_BINDING["finding_ids"]),
            },
            sort_keys=True,
        )
    )
