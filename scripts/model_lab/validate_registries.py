"""Validate the sealed example Model Lab registries without running models."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "src"))

from pe_regime_v04.model_lab import (  # noqa: E402
    RegistryPaths,
    feature_registry_json_schema,
    load_feature_registry,
    load_model_registry,
    model_registry_json_schema,
    validate_registry_cross_references,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-zoo",
        type=Path,
        default=REPOSITORY_ROOT / "research" / "model_zoo",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.model_zoo.resolve()
    model_paths = RegistryPaths(root / "model_registry.csv", root / "model_registry.json")
    feature_paths = RegistryPaths(root / "feature_registry.csv", root / "feature_registry.json")
    models = load_model_registry(model_paths)
    features = load_feature_registry(feature_paths)
    validate_registry_cross_references(models, features)

    schema_pairs = (
        (root / "schemas" / "model_registry.schema.json", model_registry_json_schema()),
        (root / "schemas" / "feature_registry.schema.json", feature_registry_json_schema()),
    )
    for path, expected in schema_pairs:
        if json.loads(path.read_text(encoding="utf-8")) != expected:
            raise RuntimeError(f"schema does not match code-owned contract: {path}")

    payload = {
        "status": "PASS",
        "model_records": len(models),
        "feature_records": len(features),
        "true_fair_evaluation_only": all(
            feature.evaluation_only
            and not feature.allowed_for_fit
            and not feature.allowed_for_predict
            for feature in features
            if feature.column_name == "true_fair_pe"
        ),
        "files_sha256": {
            str(path.relative_to(root)).replace("\\", "/"): _sha256(path)
            for path in (
                model_paths.csv_path,
                model_paths.json_path,
                feature_paths.csv_path,
                feature_paths.json_path,
                *(pair[0] for pair in schema_pairs),
            )
        },
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
