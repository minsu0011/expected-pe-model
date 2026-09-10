"""Publish the deterministic-correlation V2 global integration supersession.

V1 remains immutable and FINAL_NO_GO_REPRODUCIBILITY_P1.  This script uses the
already-audited V1 publication machinery only as a library; it has a distinct token,
source seal, golden CSV hashes, output directory, and supersession receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from research.model_zoo.aggressive_lab.global_integration.deterministic import (
    CORRELATION_ALGORITHM_ID,
)
from research.model_zoo.aggressive_lab.global_integration.schema import (
    ENSEMBLE_LEADERBOARD_FILENAME,
    GLOBAL_LEADERBOARD_FILENAME,
    MULTI_DGP_LEADERBOARD_FILENAME,
    SCHEMA_VERSION,
)
from scripts.model_lab.aggressive_lab import finalize_global_integration as v1


FINALIZER_SCHEMA_VERSION = "expected_pe_global_integration.finalization.v2"
FINALIZATION_TOKEN = "FINALIZE_EXPECTED_PE_GLOBAL_LEADERBOARDS_EXPLORATION_ONLY_V2_20260820"
DEFAULT_OUTPUT_DIRECTORY = (
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_v2_20260820"
)

FROZEN_SOURCE_TREE_SHA256 = "35c05d28f7342a17f82adb6b37151a8f1dd931268873252add25bf351e5bd3e1"
FROZEN_SOURCE_RECORDS: Mapping[str, tuple[str, int]] = {
    "research/model_zoo/aggressive_lab/global_integration/__init__.py": (
        "673ed1c252bb5423d8a54a26b7b7ae33d956e754fffccdeefe48998da456a87f",
        335,
    ),
    "research/model_zoo/aggressive_lab/global_integration/builder.py": (
        "13744dcef1dae9c545d19766e341475d91e541c1467b1954de6eb8bbbd2d47b0",
        44_151,
    ),
    "research/model_zoo/aggressive_lab/global_integration/catalog.py": (
        "2ea1c45acdf30e0d81c747e71c8899b4c280cce9a7a9009e4022145c1f9cda43",
        28_376,
    ),
    "research/model_zoo/aggressive_lab/global_integration/CONTRACT.json": (
        "37991a312560e6f40090480738f5bf4207c41b94dc059ad9ad31b4d6b99316bb",
        2_025,
    ),
    "research/model_zoo/aggressive_lab/global_integration/contract.py": (
        "439378e9d825f8175ed794da75f5e5285fd779f3942d51991eafaa5edb1e708f",
        1_976,
    ),
    "research/model_zoo/aggressive_lab/global_integration/deterministic.py": (
        "ca0d07145af643f762af440404f2052bf2c8fa35fa5f9be72fbd92dbd7732e35",
        1_689,
    ),
    "research/model_zoo/aggressive_lab/global_integration/dgp_adapter.py": (
        "345cf02e24a6926c6aacf9433b5656975056c841f882bda4c1a824f669ab26ba",
        6_242,
    ),
    "research/model_zoo/aggressive_lab/global_integration/ensembles.py": (
        "51b2eb126d7a61f1da37f55ff96ea7334b93377b9a04e41d1e9d243574eca597",
        13_337,
    ),
    "research/model_zoo/aggressive_lab/global_integration/metrics.py": (
        "a43fc26bfe842bd459c94ae117e154a824e32ab837a4df823d869eb5ab6f200b",
        5_572,
    ),
    "research/model_zoo/aggressive_lab/global_integration/normalization.py": (
        "15bf7e77f9ed930f4eb4e67a5e10ca38a1f28023e621872fd9f7b68bd4a0bcef",
        8_766,
    ),
    "research/model_zoo/aggressive_lab/global_integration/schema.py": (
        "ee017fd1bfaf0e91572d3a7227555186272ecd23c02421be9cac1db0eeb853ce",
        5_876,
    ),
    "research/model_zoo/aggressive_lab/global_integration/thresholds.py": (
        "09536072b3ca2fd523ba858fa47e5722236d3f4d649db4df8108090b686b776d",
        2_787,
    ),
    "scripts/model_lab/aggressive_lab/inspect_global_integration.py": (
        "80515970338bf5c2bab9df6dc251302cdc83e5d054ee99c216aa54ecbca96ae4",
        693,
    ),
    "scripts/model_lab/aggressive_lab/finalize_global_integration.py": (
        "8ca15aee11a3042ebac8545a7fbec637a6b917a9caf4b7eaceff23f14312555b",
        33_188,
    ),
    "tests/model_lab/test_global_integration.py": (
        "141add03c95265aa891d9b9624442f697997b83b708ece505c3a320272e96dc9",
        17_677,
    ),
    "tests/model_lab/test_global_integration_v2_reproducibility.py": (
        "99a5ed402051824ad85a3938ff95032a3622f8329bbfdb3d15e2a66a7184836f",
        5_643,
    ),
    "tests/model_lab/test_finalize_global_integration_v2.py": (
        "3b685d650427a76fbb0106815c0f237bb0e0ae4531cae644fdfb0e201daef1b8",
        2_142,
    ),
}

EXPECTED_V2_CSV_RECEIPTS: Mapping[str, tuple[int, int, str]] = {
    ENSEMBLE_LEADERBOARD_FILENAME: (
        22_100,
        21_309_125,
        "304c8c13aee41dcf299622601243364b50c077d11a254e3e89650ba3b10eaba3",
    ),
    GLOBAL_LEADERBOARD_FILENAME: (
        82,
        88_053,
        "e5b6ffb66a7977d47a8effe3db8e88343f8af007c42ab05cd977b1c3a142f144",
    ),
    MULTI_DGP_LEADERBOARD_FILENAME: (
        13,
        9_190,
        "06997dafccef2357a003db49792db8f4e935376824eebe72c51c73576d81d74c",
    ),
}

V1_EVIDENCE_PINS: Mapping[str, tuple[str, int]] = {
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820/"
    "CHECKSUMS.sha256": (
        "de1a49e268449b68ea93b245d872cae68bf935b4cf0eaa2e5f6e824771705ab0",
        464,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820/"
    "EXPECTED_PE_ENSEMBLE_LEADERBOARD.csv": (
        "6e91d0f271fdd2a5ea57785d36bc8cb7042d06bf692da6736b13e09cc997b0a4",
        21_309_311,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820/"
    "EXPECTED_PE_GLOBAL_LEADERBOARD.csv": (
        "ad258d6c106321330973db9655258e864a8ee44a2cf289aea322020b0b81ae48",
        88_054,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820/"
    "EXPECTED_PE_MULTI_DGP_LEADERBOARD.csv": (
        "06997dafccef2357a003db49792db8f4e935376824eebe72c51c73576d81d74c",
        9_190,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820/MANIFEST.json": (
        "bceb8cdbbca6307fbe46553725d17ef27676ae1557de22e85c2f44c493254881",
        29_907,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820/REPORT.md": (
        "cf5af190957e9c187084761f4865b9c3e0b2b3bd5ab56963d3012277f1488fda",
        1_297,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_independent_audit_20260820/AUDIT.json": (
        "57a02e2c738efc0807402023dcce3f903780514e8042de6da5869b6116c10242",
        8_989,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_independent_audit_20260820/"
    "CHECKSUMS.sha256": (
        "d0fb1cfe710bc03cd4dd0c85e959823fb04017dd134aff80ed8c3429d5a7da03",
        153,
    ),
    "outputs/model_zoo_expected_pe_global_leaderboards_independent_audit_20260820/REPORT.md": (
        "0649d3af2ee7ca90d0312b5db629885ec5b120b88dc5e3cf632a7d3d1ef77fa6",
        3_773,
    ),
}


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def assert_token(token: str) -> str:
    if token != FINALIZATION_TOKEN:
        raise PermissionError("exact deterministic-correlation V2 finalization token is required")
    return _sha256_bytes(token.encode("utf-8"))


def _resolve_file(root: Path, relative: str) -> Path:
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"pinned path escaped repository root: {relative}") from exc
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def verify_frozen_source_tree(root: Path) -> dict[str, Any]:
    root = root.resolve()
    records: list[dict[str, Any]] = []
    aggregate_lines: list[str] = []
    for relative in sorted(FROZEN_SOURCE_RECORDS, key=str.casefold):
        expected_sha256, expected_bytes = FROZEN_SOURCE_RECORDS[relative]
        payload = _resolve_file(root, relative).read_bytes()
        actual_sha256 = _sha256_bytes(payload)
        if len(payload) != expected_bytes or actual_sha256 != expected_sha256:
            raise ValueError(f"frozen V2 source differs: {relative}")
        records.append({"path": relative, "bytes": len(payload), "raw_sha256": actual_sha256})
        aggregate_lines.append(f"{actual_sha256}  {relative}\n")
    aggregate = _sha256_bytes("".join(aggregate_lines).encode("utf-8"))
    if aggregate != FROZEN_SOURCE_TREE_SHA256:
        raise ValueError("frozen V2 source-tree aggregate differs")
    return {
        "algorithm": "sha256(casefold-sorted '<raw_sha256>  <relative_path>\\n')",
        "record_count": len(records),
        "aggregate_sha256": aggregate,
        "records": records,
    }


def verify_v1_supersession_evidence(root: Path) -> dict[str, Any]:
    root = root.resolve()
    records: list[dict[str, Any]] = []
    for relative in sorted(V1_EVIDENCE_PINS, key=str.casefold):
        expected_sha256, expected_bytes = V1_EVIDENCE_PINS[relative]
        path = _resolve_file(root, relative)
        if path.stat().st_size != expected_bytes or v1.sha256_file(path) != expected_sha256:
            raise ValueError(f"immutable V1 publication/audit evidence differs: {relative}")
        records.append({"path": relative, "bytes": expected_bytes, "raw_sha256": expected_sha256})
    expected_sets = {
        "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820": 6,
        "outputs/model_zoo_expected_pe_global_leaderboards_independent_audit_20260820": 3,
    }
    for relative, expected_count in expected_sets.items():
        directory = (root / relative).resolve()
        entries = tuple(directory.iterdir())
        if len(entries) != expected_count or any(not entry.is_file() for entry in entries):
            raise ValueError(f"immutable V1 evidence file set differs: {relative}")
    return {
        "status": "V1_FINAL_NO_GO_REPRODUCIBILITY_P1_PRESERVED",
        "record_count": len(records),
        "publication_manifest_raw_sha256": (
            "bceb8cdbbca6307fbe46553725d17ef27676ae1557de22e85c2f44c493254881"
        ),
        "audit_raw_sha256": ("57a02e2c738efc0807402023dcce3f903780514e8042de6da5869b6116c10242"),
        "records": records,
    }


def _report_bytes(validation: Mapping[str, Any], source_tree_hash: str) -> bytes:
    rows = validation["row_counts"]
    report = f"""# Expected P/E Global Leaderboards V2 — Deterministic correlation

Status: `EXPLORATION_ONLY / NOT_PROMOTION_EVIDENCE`

V2 supersedes the immutable V1 publication only for cross-process byte reproducibility.
V1 remains `FINAL_NO_GO_REPRODUCIBILITY_P1`; its publication and independent audit were
verified byte-for-byte immediately before this V2 publication.
The prior 13-record source tree `4407e490e8a77d87c62c51ddbfc223354f7f8c2622f658136b77b2b50f1fb8ae`
is intentionally superseded and is not claimed to replay from the current source checkout.

## V2 change

- Correlation algorithm: `{CORRELATION_ALGORITHM_ID}`
- Fixed identity order, Python binary64 values, `math.fsum` means/covariance/variances
- Explicit nonfinite, short-vector, and zero-variance handling
- Frozen V2 source tree: `{source_tree_hash}`

## Published tables

- `{GLOBAL_LEADERBOARD_FILENAME}`: {rows[GLOBAL_LEADERBOARD_FILENAME]} rows
- `{MULTI_DGP_LEADERBOARD_FILENAME}`: {rows[MULTI_DGP_LEADERBOARD_FILENAME]} rows
- `{ENSEMBLE_LEADERBOARD_FILENAME}`: {rows[ENSEMBLE_LEADERBOARD_FILENAME]} rows

All prior exploration-only constraints remain. No model was fit, no prediction was mutated,
and no fresh/held-out, registry, production, or promotion authority was granted. Ensemble
rows remain post-result exhaustive-search diagnostics requiring genuinely fresh validation.
"""
    return report.encode("utf-8")


def _assert_golden_csvs(csv_receipts: Mapping[str, Mapping[str, Any]]) -> None:
    if set(csv_receipts) != set(EXPECTED_V2_CSV_RECEIPTS):
        raise ValueError("V2 CSV receipt inventory differs")
    for filename, (rows, byte_count, raw_sha256) in EXPECTED_V2_CSV_RECEIPTS.items():
        receipt = csv_receipts[filename]
        if (receipt["rows"], receipt["bytes"], receipt["raw_sha256"]) != (
            rows,
            byte_count,
            raw_sha256,
        ):
            raise ValueError(f"V2 golden cross-process CSV receipt differs: {filename}")


def finalize(root: Path, output_dir: Path, token: str) -> dict[str, Any]:
    token_sha256 = assert_token(token)
    root = root.resolve()
    outputs, final_dir = v1._validate_output_directory(root, output_dir)
    source_before = verify_frozen_source_tree(root)
    terminal_before = v1.verify_terminal_bindings(root)
    v1_before = verify_v1_supersession_evidence(root)
    controls_before = v1.snapshot_protected_controls(root)

    tables = v1.replay_in_memory(root)
    validation = v1.validate_tables(tables)

    if verify_frozen_source_tree(root) != source_before:
        raise RuntimeError("frozen V2 source changed during replay")
    if v1.verify_terminal_bindings(root) != terminal_before:
        raise RuntimeError("terminal inputs changed during V2 replay")
    if verify_v1_supersession_evidence(root) != v1_before:
        raise RuntimeError("immutable V1 evidence changed during V2 replay")
    if v1.snapshot_protected_controls(root) != controls_before:
        raise RuntimeError("protected controls changed during V2 replay")

    staging = Path(tempfile.mkdtemp(prefix=f".{final_dir.name}.staging-", dir=outputs))
    published = False
    try:
        csv_receipts: dict[str, dict[str, Any]] = {}
        for filename, frame in tables.as_mapping().items():
            path = staging / filename
            v1._atomic_write_csv(path, frame)
            csv_receipts[filename] = {
                "bytes": path.stat().st_size,
                "raw_sha256": v1.sha256_file(path),
                "rows": len(frame),
                "columns": [str(column) for column in frame.columns],
            }
        _assert_golden_csvs(csv_receipts)

        report_payload = _report_bytes(validation, source_before["aggregate_sha256"])
        v1._atomic_write_bytes(staging / "REPORT.md", report_payload)
        report_hash = _sha256_bytes(report_payload)
        manifest = {
            "schema_version": FINALIZER_SCHEMA_VERSION,
            "table_schema_version": SCHEMA_VERSION,
            "status": "FINALIZED_EXPLORATION_ONLY_V2_DETERMINISTIC_CORRELATION",
            "evidence_class": "EXPLORATION_ONLY",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
            "authorization": {
                "exact_root_token_verified": True,
                "token_sha256": token_sha256,
            },
            "authority": {
                "production": False,
                "registry": False,
                "promotion": False,
                "fresh_data": False,
                "heldout_data": False,
                "model_fit": False,
                "prediction_mutation": False,
            },
            "supersession": {
                "supersedes_directory": (
                    "outputs/model_zoo_expected_pe_global_leaderboards_exploration_only_20260820"
                ),
                "v1_disposition": "FINAL_NO_GO_REPRODUCIBILITY_P1",
                "v1_frozen_source_tree_sha256": (
                    "4407e490e8a77d87c62c51ddbfc223354f7f8c2622f658136b77b2b50f1fb8ae"
                ),
                "v1_source_tree_intentionally_superseded": True,
                "v1_current_source_replay_claimed": False,
                "v1_publication_manifest_raw_sha256": v1_before["publication_manifest_raw_sha256"],
                "v1_independent_audit_raw_sha256": v1_before["audit_raw_sha256"],
                "v2_frozen_source_tree_sha256": source_before["aggregate_sha256"],
                "scope": "CORRELATION_BYTE_REPRODUCIBILITY_ONLY",
                "v1_mutated": False,
            },
            "deterministic_correlation": {
                "algorithm_id": CORRELATION_ALGORITHM_ID,
                "cross_process_golden_csv_receipts": {
                    filename: {
                        "rows": rows,
                        "bytes": byte_count,
                        "raw_sha256": raw_sha256,
                    }
                    for filename, (rows, byte_count, raw_sha256) in (
                        EXPECTED_V2_CSV_RECEIPTS.items()
                    )
                },
            },
            "publication": {
                "atomic_directory_rename": True,
                "output_directory": final_dir.relative_to(root).as_posix(),
                "exact_file_count": len(v1.EXPECTED_OUTPUT_FILES),
                "exact_filenames": sorted(v1.EXPECTED_OUTPUT_FILES),
            },
            "frozen_source_tree": source_before,
            "terminal_bindings": terminal_before,
            "v1_immutable_evidence": v1_before,
            "integrity_reverification": {
                "before_replay": True,
                "after_replay": True,
                "immediately_before_atomic_publish": True,
                "protected_control_snapshot": controls_before,
            },
            "validation": validation,
            "artifacts": {
                **csv_receipts,
                "REPORT.md": {
                    "bytes": len(report_payload),
                    "raw_sha256": report_hash,
                },
            },
            "finalizer_raw_sha256": v1.sha256_file(Path(__file__).resolve()),
            "caveat": (
                "Spent-data exploration only; deterministic bytes do not create fresh "
                "validation or promotion evidence."
            ),
        }
        manifest_payload = v1._json_bytes(manifest)
        v1._atomic_write_bytes(staging / "MANIFEST.json", manifest_payload)
        checksum_targets = {
            **{name: receipt["raw_sha256"] for name, receipt in csv_receipts.items()},
            "MANIFEST.json": _sha256_bytes(manifest_payload),
            "REPORT.md": report_hash,
        }
        checksum_payload = "".join(
            f"{checksum_targets[name]}  {name}\n" for name in sorted(checksum_targets)
        ).encode("utf-8")
        v1._atomic_write_bytes(staging / "CHECKSUMS.sha256", checksum_payload)
        v1._verify_staged_publication(staging, tables, checksum_targets)

        if verify_frozen_source_tree(root) != source_before:
            raise RuntimeError("frozen V2 source changed before atomic publication")
        if v1.verify_terminal_bindings(root) != terminal_before:
            raise RuntimeError("terminal inputs changed before V2 atomic publication")
        if verify_v1_supersession_evidence(root) != v1_before:
            raise RuntimeError("immutable V1 evidence changed before V2 publication")
        if v1.snapshot_protected_controls(root) != controls_before:
            raise RuntimeError("protected controls changed before V2 publication")
        if final_dir.exists():
            raise FileExistsError(f"V2 publication directory appeared during replay: {final_dir}")
        os.replace(staging, final_dir)
        published = True
        if {path.name for path in final_dir.iterdir()} != v1.EXPECTED_OUTPUT_FILES:
            raise RuntimeError("published V2 file set differs after atomic rename")
        return {
            "status": "FINALIZED_EXPLORATION_ONLY_V2_DETERMINISTIC_CORRELATION",
            "promotion_authority": "NOT_PROMOTION_EVIDENCE",
            "output_directory": final_dir.relative_to(root).as_posix(),
            "manifest_raw_sha256": checksum_targets["MANIFEST.json"],
            "checksums_raw_sha256": v1.sha256_file(final_dir / "CHECKSUMS.sha256"),
            "row_counts": validation["row_counts"],
        }
    finally:
        if not published and staging.exists():
            v1._safe_cleanup_staging(staging, outputs, final_dir.name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Root-token-gated deterministic-correlation V2 global finalizer."
    )
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=Path(DEFAULT_OUTPUT_DIRECTORY))
    parser.add_argument("--token", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = finalize(args.root, args.output_dir, args.token)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
