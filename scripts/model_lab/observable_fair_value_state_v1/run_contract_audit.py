"""Run the score-free Observable Fair-Value State V1 contract audit."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
import time

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_fair_value_state_v1 import (  # noqa: E402
    ABLATIONS,
    FEATURE_DEFINITIONS,
    contract_sha256,
    feature_columns_for_ablation,
    generate_observable_state_features,
    run_causality_audit,
)
from research.model_zoo.observable_fair_value_state_v1.contracts import (  # noqa: E402
    canonical_json_bytes,
    contract_payload,
)


DEFAULT_INPUT = PROJECT_ROOT / "sample_data" / "v03_canonical_high_sample.csv"
DEFAULT_OUTPUT = (
    PROJECT_ROOT / "outputs" / "model_zoo_observable_fair_value_state_v1_contract_audit_20260820"
)


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, raw: bytes) -> dict[str, object]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return {
        "path": path.resolve().as_posix(),
        "bytes": len(raw),
        "sha256": _sha256_bytes(raw),
    }


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "NOT_INSTALLED"


def run(input_path: Path, output_dir: Path) -> dict[str, object]:
    started = time.perf_counter()
    raw_input = input_path.read_bytes()
    frame = pd.read_csv(input_path, low_memory=False)
    state = generate_observable_state_features(frame)
    audit = run_causality_audit(frame)
    if not audit.passed:
        raise RuntimeError(f"Observable State V1 causal audit failed: {audit.as_dict()}")

    identity = frame.loc[:, [*state.group_columns, "date"]].copy()
    state_frame = pd.concat([identity, state.features], axis=1)
    state_csv = state_frame.to_csv(
        index=False,
        lineterminator="\n",
        float_format="%.17g",
        na_rep="",
    ).encode("utf-8")
    contract_document = {**contract_payload(), "contract_sha256": contract_sha256()}
    contract_record = _write(
        output_dir / "CONTRACT.json",
        canonical_json_bytes(contract_document) + b"\n",
    )
    state_record = _write(output_dir / "STATE_FEATURES.csv", state_csv)

    relative_available = state.relative_available_rows > 0
    ablations: list[dict[str, object]] = []
    for item in ABLATIONS:
        eligible = not item.requires_relative_data or relative_available
        columns = (
            feature_columns_for_ablation(
                item.ablation_id,
                relative_data_available=relative_available,
            )
            if eligible
            else ()
        )
        ablations.append(
            {
                "ablation_id": item.ablation_id,
                "eligible_on_input": eligible,
                "feature_count": len(columns),
                "reason": (
                    "ELIGIBLE" if eligible else "NO_EXPLICIT_SECTOR_PE_AND_MARKET_PE_RELATIVE_INPUT"
                ),
            }
        )

    audit_payload = {
        "format_version": 1,
        "lab_id": "observable_fair_value_state_v1",
        "status": "CONTRACT_AUDIT_PASS",
        "score_or_evaluation_truth_used": False,
        "v5_heldout_used": False,
        "production_champion_changed": False,
        "contract_sha256": contract_sha256(),
        "input": {
            "path": input_path.resolve().as_posix(),
            "bytes": len(raw_input),
            "sha256": _sha256_bytes(raw_input),
            "rows": len(frame),
            "columns": len(frame.columns),
        },
        "output": {
            "rows": len(state.features),
            "feature_count": len(FEATURE_DEFINITIONS),
            "group_columns": list(state.group_columns),
            "relative_source_present": state.relative_source_present,
            "relative_available_rows": state.relative_available_rows,
            "missing_rate_by_feature": {
                column: float(state.features[column].isna().mean())
                for column in state.features.columns
            },
        },
        "causality_audit": audit.as_dict(),
        "ablations": ablations,
        "dependencies": {
            "numpy": {"version": _version("numpy"), "license": "BSD-3-Clause"},
            "pandas": {"version": _version("pandas"), "license": "BSD-3-Clause"},
            "statsmodels": {
                "version": _version("statsmodels"),
                "license": "BSD-3-Clause",
                "imported_or_reused": False,
                "role": "conceptual local-linear-state documentation reference only",
            },
        },
        "artifacts": {
            "contract": contract_record,
            "state_features": state_record,
        },
        "runtime_seconds": time.perf_counter() - started,
        "next_stage": (
            "same-estimator feature-only ablation on spent research surfaces; "
            "no fresh heldout until a tournament survivor is design-locked"
        ),
    }
    audit_record = _write(
        output_dir / "AUDIT.json",
        canonical_json_bytes(audit_payload) + b"\n",
    )
    checksums = "".join(
        f"{record['sha256']}  {Path(str(record['path'])).name}\n"
        for record in (contract_record, state_record, audit_record)
    ).encode("ascii")
    checksum_record = _write(output_dir / "CHECKSUMS.sha256", checksums)
    return {
        **audit_payload,
        "artifacts": {
            **audit_payload["artifacts"],
            "audit": audit_record,
            "checksums": checksum_record,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    result = run(args.input.resolve(strict=True), args.output_dir.resolve())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
