from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts.model_lab import pe_four_model_heldout_r3_vault_manifest_normalizer as subject


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = (
    PROJECT_ROOT
    / "outputs/.model_zoo_pe_four_model_heldout_vault_r3_20260824T134417"
    / "VAULT_MANIFEST.json"
)


def test_formal_manifest_has_exact_deterministic_serializer_mismatch() -> None:
    raw = MANIFEST.read_bytes()
    value = subject._strict_object(raw, label="formal vault manifest")
    pretty = subject._pretty(value)
    unsigned = dict(value)
    stored = unsigned.pop("vault_manifest_semantic_sha256")

    assert subject._r7_compact(value) == raw
    assert len(raw) == 16_720
    assert hashlib.sha256(raw).hexdigest() == (
        "731efc61fe7469bb6b9efd9ab517bbc7ea6699d2896234d4a1ca9373c755dc87"
    )
    assert len(pretty) == 19_308
    assert hashlib.sha256(pretty).hexdigest() == (
        "d0a3ac148f153c7c726c132012045b9837f3390a7bccd4ba634bf2a9c3df2d4e"
    )
    assert subject._strict_object(pretty, label="pretty") == value
    assert subject._semantic(unsigned) == stored
    assert stored == (
        "877be05224a3b8c85020a56a2ad80afba4d18c9976194199c2690db36da33893"
    )


def test_strict_json_rejects_duplicate_keys_and_nonfinite_values() -> None:
    with pytest.raises(subject.R3VaultManifestRecoveryError, match="duplicate key"):
        subject._strict_object(b'{"a":1,"a":2}', label="duplicate")
    with pytest.raises(subject.R3VaultManifestRecoveryError, match="nonfinite"):
        subject._strict_object(b'{"a":NaN}', label="nonfinite")


def test_claim_and_receipt_semantics_are_field_exclusion_compatible() -> None:
    core = {
        "schema_version": subject.CLAIM_SCHEMA,
        "status": subject.CLAIM_STATUS,
        "run_id": "r3_20260824T134417",
        "truth_payload_open_count": 0,
        "score_open_count": 0,
    }
    sealed = {**core, "claim_semantic_sha256": subject._semantic(core)}
    raw = subject._pretty(sealed)
    decoded = json.loads(raw)
    observed = decoded.pop("claim_semantic_sha256")

    assert observed == subject._semantic(decoded)
    assert raw.endswith(b"\n")
