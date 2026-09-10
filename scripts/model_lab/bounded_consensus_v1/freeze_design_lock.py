"""Freeze the score-free Bounded Consensus V1 design and source-boundary audit."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
from typing import Any, Sequence

from research.model_zoo.bounded_consensus_v1 import (
    RESEARCH_GATE,
    VARIANT_SPECS,
    design_lock_payload,
    design_lock_sha256,
)
from research.model_zoo.bounded_consensus_v1.deterministic import CORRELATION_ALGORITHM_ID
from research.model_zoo.bounded_consensus_v1.source_audit import audit_source_boundary


ARTIFACT_ID = "bounded_consensus_v1_score_free_design_lock_20260820"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _source_paths(project_root: Path) -> list[Path]:
    package = project_root / "research" / "model_zoo" / "bounded_consensus_v1"
    paths = sorted(package.glob("*.py"))
    paths.extend(
        [
            package / "MODEL_HYPOTHESIS.md",
            project_root / "tests" / "model_lab" / "test_bounded_consensus_v1.py",
            Path(__file__).resolve(),
        ]
    )
    return sorted({path.resolve() for path in paths})


def _write_source_manifest(project_root: Path, output_path: Path) -> None:
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=("relative_path", "bytes", "sha256"),
            lineterminator="\n",
        )
        writer.writeheader()
        for path in _source_paths(project_root):
            writer.writerow(
                {
                    "relative_path": path.relative_to(project_root).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                }
            )


def freeze_design_lock(
    *,
    project_root: Path,
    output_dir: Path,
    v5_terminal_audit_path: Path,
) -> dict[str, Any]:
    project_root = project_root.resolve()
    output_dir = output_dir.resolve()
    package_dir = project_root / "research" / "model_zoo" / "bounded_consensus_v1"
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty design-lock output: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    source_audit = audit_source_boundary(
        package_dir=package_dir,
        v5_terminal_audit_path=v5_terminal_audit_path,
    )
    if not source_audit.passed:
        raise RuntimeError("model-side source boundary audit failed")

    lock_payload = design_lock_payload()
    lock_sha256 = design_lock_sha256()
    _write_json(
        output_dir / "DESIGN_LOCK.json",
        {"design_lock_sha256": lock_sha256, "payload": lock_payload},
    )
    _write_json(output_dir / "SOURCE_BOUNDARY_AUDIT.json", source_audit.as_dict())
    contract_audit = {
        "artifact_id": ARTIFACT_ID,
        "score_free": True,
        "performance_results_present": False,
        "design_lock_sha256": lock_sha256,
        "five_unique_structural_variants": len(VARIANT_SPECS) == 5
        and len({spec.variant_id for spec in VARIANT_SPECS}) == 5,
        "post_result_tuning_allowed": any(spec.tunable_after_results for spec in VARIANT_SPECS),
        "all_alpha_contract": [0.0, 1.0],
        "disagreement_correction": 0.0,
        "variant_e_calibration": "strictly_prior_matured_oof_fold_corrections_only",
        "variant_d_missing_or_invalid_confidence": 0.0,
        "research_gate": {
            "expected_seed_count": RESEARCH_GATE.expected_seed_count,
            "strong_status": "STRONG_SURVIVOR",
            "signal_status": "SIGNAL_ONLY",
            "terminal_status": "REJECT",
        },
        "oracle_diagnostics_used_by_gate": False,
        "correlation_algorithm_id": CORRELATION_ALGORITHM_ID,
        "source_boundary_audit_passed": source_audit.passed,
    }
    _write_json(output_dir / "CONTRACT_AUDIT.json", contract_audit)
    _write_source_manifest(project_root, output_dir / "SOURCE_MANIFEST.csv")
    shutil.copyfile(package_dir / "MODEL_HYPOTHESIS.md", output_dir / "MODEL_HYPOTHESIS.md")

    audit = {
        "artifact_id": ARTIFACT_ID,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "SCORE_FREE_DESIGN_LOCK_FROZEN",
        "experiment_id": lock_payload["experiment_id"],
        "family_id": lock_payload["family_id"],
        "design_lock_sha256": lock_sha256,
        "variant_count": len(VARIANT_SPECS),
        "source_boundary_passed": source_audit.passed,
        "v5_reference_sha256": source_audit.v5_reference_sha256,
        "v5_reference_used_by_model": False,
        "truth_access_model_side": False,
        "performance_score_access": False,
        "promotion_authority": lock_payload["promotion_authority"],
    }
    _write_json(output_dir / "AUDIT.json", audit)

    artifact_files = sorted(
        path for path in output_dir.iterdir() if path.is_file() and path.name != "CHECKSUMS.sha256"
    )
    checksum_lines = [f"{_sha256(path)}  {path.name}" for path in artifact_files]
    (output_dir / "CHECKSUMS.sha256").write_text(
        "\n".join(checksum_lines) + "\n",
        encoding="ascii",
        newline="\n",
    )
    return {
        **audit,
        "output_dir": str(output_dir),
        "artifact_file_count": len(artifact_files) + 1,
        "checksums_sha256": _sha256(output_dir / "CHECKSUMS.sha256"),
    }


def _parser() -> argparse.ArgumentParser:
    project_root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=project_root)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=project_root / "outputs" / ARTIFACT_ID,
    )
    parser.add_argument(
        "--v5-terminal-audit",
        type=Path,
        default=(
            project_root
            / "outputs"
            / "model_zoo_prospective_fresh_ensemble_v5_heldout_terminal_audit_20260820"
            / "AUDIT.json"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = freeze_design_lock(
        project_root=args.project_root,
        output_dir=args.output_dir,
        v5_terminal_audit_path=args.v5_terminal_audit,
    )
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
