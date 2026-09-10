"""Publish the sealed receipt for the terminal H-OFS full-r1 standardization failure."""

from __future__ import annotations

import math
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for import_root in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from research.model_zoo.hofs_research_adapter_v1.contracts import (  # noqa: E402
    FAILED_R1_OUTPUT_ROOT,
    FAILURE_RECEIPT_ROOT,
    V7_NUMERIC_SOURCE_SHA256,
    semantic_sha256,
)
from research.model_zoo.hofs_research_adapter_v1.publisher import (  # noqa: E402
    pretty_json_bytes,
    publish_atomic,
)


R1_FAILURE_SOURCE_FILES = [
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/__init__.py", "raw_sha256": "bc5b1349b301ed2b9eb1096d251ca3e2a7fa74f0da2dff8b61810fd8c7d7b9e9", "bytes": 602},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/artifacts.py", "raw_sha256": "dbb5f0e71ae4036a3fd62c523db171eb93827917f3d79e81abe212768c2465e6", "bytes": 13252},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/contracts.py", "raw_sha256": "0f2c82ea613b91b9193940d3fec46275c36ee5f7435d37c5b6070feb3af34465", "bytes": 10223},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/inputs.py", "raw_sha256": "627ac3a73fcfee88b10b6229b1043b79cc98c8b5425e693b108d844126586551", "bytes": 6774},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/publisher.py", "raw_sha256": "2f95c1e9465e9ed407abe45d3018d0db94214d3833cfc381200abaa9c19f0fe2", "bytes": 4762},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/runner.py", "raw_sha256": "67c81f631b543bbe8ade4d32ba7641ac2c1ef47206eac2778bf123b2d4206da6", "bytes": 8231},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/worker.py", "raw_sha256": "063adf84d37e39a6a155c28c745995baafe1105ba88600da7026dbcdd8d93855", "bytes": 16353},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/DESIGN.md", "raw_sha256": "9aa4df496d22b5e8035f21abcb166bbf41f8141a0e79b22b431836317f77997a", "bytes": 2312},
    {"relative_path": "research/model_zoo/hofs_research_adapter_v1/MODEL_HYPOTHESIS.md", "raw_sha256": "0ce69dc1617a5af02427428f41929ebf60d74eb40de145b36542c753e6f7ff90", "bytes": 1599},
    {"relative_path": "research/model_zoo/pre_certification_research_tournament_v1/adapters.py", "raw_sha256": "7645f17e3ef13bcef441af6a3573d69034aa007ddd2b0ce8cf5897253b36fb7f", "bytes": 11573},
    {"relative_path": "scripts/model_lab/hofs_research_adapter_v1/run_adapter.py", "raw_sha256": "ddd968962b223e4dd46a4aa06fdec3a892ffbaa6e7451ece72ff3053de18300f", "bytes": 3358},
    {"relative_path": "tests/model_lab/test_hofs_research_adapter_v1.py", "raw_sha256": "7cfcd851400f0e2b0d8009aa936557e8171d0dc7a783c510abed0571d2efcdda", "bytes": 8066},
]


def main() -> int:
    failed_root = PROJECT_ROOT / FAILED_R1_OUTPUT_ROOT
    staging = list(
        (PROJECT_ROOT / "outputs").glob(
            ".model_zoo_hofs_research_adapter_v1_full_r1_20260822.staging-*"
        )
    )
    if failed_root.exists() or staging:
        raise RuntimeError("r1 failure boundary is not clean")
    receipt = {
        "schema_version": "expected_pe.hofs_research_adapter_v1.full_r1_failure.v1",
        "status": "TERMINAL_FAIL_CLOSED_STANDARDIZER_LOG_SCALE_SEMANTICS",
        "evidence_class": "RESEARCH_ONLY",
        "failed_execution_id": "hofs_research_adapter_v1_full_r1",
        "failed_output_root": FAILED_R1_OUTPUT_ROOT,
        "failed_output_root_created": False,
        "failed_output_root_reuse_forbidden": True,
        "partial_publication": False,
        "staging_residue_count": 0,
        "command": (
            "python scripts/model_lab/hofs_research_adapter_v1/run_adapter.py --mode full "
            "--coordination-token FULL_RUN_RESOURCE_COORDINATED"
        ),
        "exit_code": 1,
        "exception_type": "ResearchTournamentContractError",
        "exception_message": "H-OFS source prediction domain drifted",
        "completed_fit_count_before_standardizer_failure": 3100,
        "completed_prediction_rows_in_memory_before_failure": 64800,
        "published_prediction_rows": 0,
        "model_output_files_published": 0,
        "cause": {
            "erroneous_clause": "np.any(scale < 0.0)",
            "erroneous_source_path": (
                "research/model_zoo/pre_certification_research_tournament_v1/adapters.py"
            ),
            "erroneous_source_raw_sha256": (
                "7645f17e3ef13bcef441af6a3573d69034aa007ddd2b0ce8cf5897253b36fb7f"
            ),
            "v7_contract_semantics": "natural_log_of_final_uncertainty_scale",
            "v7_scale_bounds": [0.01, 0.50],
            "valid_log_scale_bounds": [math.log(0.01), math.log(0.50)],
            "failing_full_row_count_implied_by_frozen_bounds": 64800,
            "failing_full_identity_surface": {
                "tasks": 50,
                "source_row_position_start_inclusive": 504,
                "source_row_position_end_exclusive": 1800,
            },
            "full_actual_min_max_not_persisted_due_atomic_failure": True,
            "frozen_smoke_confirmation": {
                "predictions_raw_sha256": (
                    "c9f210d5b23ef224edff362ef675693e5b8de7a5002a86f8d41b3bcc03f33b43"
                ),
                "checksums_raw_sha256": (
                    "9057b73dfdcce6bdb1b3a7d17c73423ee2bb9d44a95b01eb48165f61f0208c50"
                ),
                "rows": 1296,
                "negative_finite_log_scale_rows": 1296,
                "observed_min": -3.7244056373240655,
                "observed_max": -3.4253789474475584,
            },
        },
        "access": {
            "public_canonical_files_opened": 50,
            "public_overlay_files_opened": 0,
            "protected_outcome_or_evaluation_payload_files_opened": 0,
            "score_calls": 0,
            "registry_or_champion_mutations": 0,
        },
        "r1_failure_source_snapshot_semantic_sha256": semantic_sha256(
            R1_FAILURE_SOURCE_FILES
        ),
        "v7_numeric_source_sha256": dict(V7_NUMERIC_SOURCE_SHA256),
        "next_execution_identity": "hofs_research_adapter_v1_full_r2",
    }
    receipt["manifest_sha256"] = semantic_sha256(receipt)
    source_snapshot = {
        "schema_version": "expected_pe.hofs_research_adapter_v1.r1_source_snapshot.v1",
        "files": R1_FAILURE_SOURCE_FILES,
        "file_count": len(R1_FAILURE_SOURCE_FILES),
        "semantic_sha256": semantic_sha256(R1_FAILURE_SOURCE_FILES),
    }
    manifest = {
        "schema_version": "expected_pe.hofs_research_adapter_v1.failure_manifest.v1",
        "status": receipt["status"],
        "evidence_class": "RESEARCH_ONLY",
        "file_universe_without_checksums": [
            "FAILURE_RECEIPT.json",
            "MANIFEST.json",
            "REPORT.md",
            "SOURCE_SNAPSHOT.json",
        ],
        "failure_receipt_semantic_sha256": semantic_sha256(receipt),
        "contains_model_predictions": False,
    }
    files = {
        "FAILURE_RECEIPT.json": pretty_json_bytes(receipt),
        "MANIFEST.json": pretty_json_bytes(manifest),
        "REPORT.md": (
            "# H-OFS full-r1 terminal failure receipt\n\n"
            "Evidence: **RESEARCH_ONLY**. The 3,100-fit computation completed, but an incorrect "
            "standardizer check rejected the frozen V7 log-scale field. Atomic publication "
            "prevented every model output and prediction file from being published. The r1 "
            "execution identity and root are terminal and will never be reused.\n"
        ).encode("utf-8"),
        "SOURCE_SNAPSHOT.json": pretty_json_bytes(source_snapshot),
    }
    publication = publish_atomic(FAILURE_RECEIPT_ROOT, files)
    print(publication)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
