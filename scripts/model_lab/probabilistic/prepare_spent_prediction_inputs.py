from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seal the exact truth-blind five-seed probabilistic input custody"
    )
    parser.add_argument("--repo-root", type=Path, default=_root())
    parser.add_argument(
        "--output-directory",
        type=Path,
        default=Path("outputs/p5s/i"),
    )
    args = parser.parse_args()
    root = args.repo_root.resolve()
    output = args.output_directory
    if not output.is_absolute():
        output = root / output
    sys.path.insert(0, str(root / "src"))

    from pe_regime_v04.model_lab.probabilistic.artifacts import immutable_write_json
    from pe_regime_v04.model_lab.probabilistic.authorization import common_mask_manifest
    from pe_regime_v04.model_lab.probabilistic.contracts import sha256_bytes, sha256_file
    from pe_regime_v04.model_lab.probabilistic.custody import (
        build_feature_provenance,
        write_content_addressed_csv,
        write_content_addressed_json,
    )
    from pe_regime_v04.model_lab.probabilistic.spent import (
        SPENT_SEEDS,
        verify_fixed_external_authorities,
    )
    from pe_regime_v04.model_lab.probabilistic.spent_inputs import (
        assemble_prediction_inputs,
    )

    verify_fixed_external_authorities(root, include_evaluation_input=False)
    frames = assemble_prediction_inputs(root)
    paths = {
        "feature": write_content_addressed_csv(output, "SPENT_PIT_FEATURES", frames["features"]),
        "label": write_content_addressed_csv(output, "SPENT_TRAINING_LABELS", frames["labels"]),
        "identity": write_content_addressed_csv(
            output, "SPENT_FORMAL_IDENTITY", frames["identity"]
        ),
        "point_history": write_content_addressed_csv(
            output, "SPENT_V04_POINT_HISTORY", frames["point_history"]
        ),
        "v04_comparator": write_content_addressed_csv(
            output, "SPENT_V04_COMPARATOR", frames["v04_expected_pe"]
        ),
        "ml_comparator": write_content_addressed_csv(
            output, "SPENT_ML_COMPARATOR", frames["ml_expected_pe"]
        ),
        "role": write_content_addressed_json(output, "SPENT_PREDICT_ROLE", frames["role"]),
        "common_mask": write_content_addressed_json(
            output, "SPENT_COMMON_MASK", common_mask_manifest(frames["identity"])
        ),
    }
    provenance = build_feature_provenance(feature_artifact_raw_sha256=sha256_file(paths["feature"]))
    paths["feature_provenance"] = write_content_addressed_json(
        output, "SPENT_PIT_FEATURE_PROVENANCE", provenance
    )

    def record(path: Path) -> dict[str, object]:
        return {
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }

    manifest = {
        "schema_version": "expected_pe_model_zoo.probabilistic_spent_predict_inputs.v1",
        "status": "SEALED_TRUTH_BLIND_INPUT_CUSTODY",
        "spent_seeds": list(SPENT_SEEDS),
        "rows": {
            "features": len(frames["features"]),
            "labels": len(frames["labels"]),
            "identity": len(frames["identity"]),
        },
        "artifacts": {name: record(path) for name, path in paths.items()},
        "evaluation_manifest_read": False,
        "truth_bytes_read": False,
        "predictions_generated": False,
        "scores_generated_or_read": False,
        "fresh_seed_reserved_or_opened": False,
        "heldout_opened": False,
    }
    manifest_path = output / "SPENT_PREDICT_INPUTS_MANIFEST.json"
    immutable_write_json(manifest_path, manifest)
    print(
        json.dumps(
            {
                "manifest": manifest_path.relative_to(root).as_posix(),
                "raw_sha256": sha256_bytes(manifest_path.read_bytes()),
                "status": "READY_FOR_FORMAL_ACTIVATION",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
