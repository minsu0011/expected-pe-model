from __future__ import annotations

from pathlib import Path

import pytest

from scripts.model_lab.aggressive_lab.finalize_global_integration_v2 import (
    DEFAULT_OUTPUT_DIRECTORY,
    EXPECTED_V2_CSV_RECEIPTS,
    FINALIZATION_TOKEN,
    assert_token,
    verify_frozen_source_tree,
    verify_v1_supersession_evidence,
)


ROOT = Path(__file__).resolve().parents[2]


def test_v2_finalizer_requires_its_distinct_exact_token() -> None:
    with pytest.raises(PermissionError, match="deterministic-correlation V2"):
        assert_token("FINALIZE_EXPECTED_PE_GLOBAL_LEADERBOARDS_EXPLORATION_ONLY_20260820")
    assert len(assert_token(FINALIZATION_TOKEN)) == 64
    assert DEFAULT_OUTPUT_DIRECTORY.endswith("exploration_only_v2_20260820")
    assert not (ROOT / DEFAULT_OUTPUT_DIRECTORY).exists()


def test_v2_finalizer_preserves_and_pins_v1_publication_and_audit() -> None:
    receipt = verify_v1_supersession_evidence(ROOT)
    assert receipt["status"] == "V1_FINAL_NO_GO_REPRODUCIBILITY_P1_PRESERVED"
    assert receipt["record_count"] == 9
    assert (
        receipt["publication_manifest_raw_sha256"]
        == "bceb8cdbbca6307fbe46553725d17ef27676ae1557de22e85c2f44c493254881"
    )
    assert (
        receipt["audit_raw_sha256"]
        == "57a02e2c738efc0807402023dcce3f903780514e8042de6da5869b6116c10242"
    )


def test_v2_finalizer_has_exact_cross_process_golden_csv_pins() -> None:
    assert EXPECTED_V2_CSV_RECEIPTS == {
        "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv": (
            22_100,
            21_309_125,
            "304c8c13aee41dcf299622601243364b50c077d11a254e3e89650ba3b10eaba3",
        ),
        "EXPECTED_PE_GLOBAL_LEADERBOARD.csv": (
            82,
            88_053,
            "e5b6ffb66a7977d47a8effe3db8e88343f8af007c42ab05cd977b1c3a142f144",
        ),
        "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv": (
            13,
            9_190,
            "06997dafccef2357a003db49792db8f4e935376824eebe72c51c73576d81d74c",
        ),
    }


def test_v2_finalizer_verifies_refrozen_source_tree() -> None:
    receipt = verify_frozen_source_tree(ROOT)
    assert receipt["record_count"] == 17
