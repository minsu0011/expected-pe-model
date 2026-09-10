from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(_REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPOSITORY_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.bindings import (  # noqa: E402
    FutureFinalFreezeBinding,
    FutureR5PostGenerationAuditBinding,
    FutureR8GenerationBinding,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_fresh_qualification_prediction.runner import (  # noqa: E402
    PREDICTION_ACTIVATION_LITERAL,
    run_prediction_only,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--activation", default=PREDICTION_ACTIVATION_LITERAL)
    parser.add_argument("--generation-design-sha256")
    parser.add_argument("--generation-manifest-sha256")
    parser.add_argument("--generation-freeze-sha256")
    parser.add_argument("--generation-checksums-sha256")
    parser.add_argument("--audit-access-ledger-sha256")
    parser.add_argument("--audit-raw-sha256")
    parser.add_argument("--audit-semantic-sha256")
    parser.add_argument("--audit-sha-file-sha256")
    parser.add_argument("--audit-seal-sha256")
    parser.add_argument("--audit-checksums-sha256")
    parser.add_argument("--final-design-raw-sha256")
    parser.add_argument("--final-design-semantic-sha256")
    parser.add_argument("--final-checksums-sha256")
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    generation = FutureR8GenerationBinding(
        generation_design_raw_sha256=args.generation_design_sha256,
        generation_manifest_raw_sha256=args.generation_manifest_sha256,
        freeze_receipt_raw_sha256=args.generation_freeze_sha256,
        checksums_raw_sha256=args.generation_checksums_sha256,
    )
    audit = FutureR5PostGenerationAuditBinding(
        access_ledger_raw_sha256=args.audit_access_ledger_sha256,
        audit_raw_sha256=args.audit_raw_sha256,
        audit_semantic_sha256=args.audit_semantic_sha256,
        audit_sha256_file_raw_sha256=args.audit_sha_file_sha256,
        seal_receipt_raw_sha256=args.audit_seal_sha256,
        checksums_raw_sha256=args.audit_checksums_sha256,
    )
    final_freeze = FutureFinalFreezeBinding(
        design_lock_raw_sha256=args.final_design_raw_sha256,
        design_lock_semantic_sha256=args.final_design_semantic_sha256,
        checksums_raw_sha256=args.final_checksums_sha256,
    )
    result = run_prediction_only(
        project_root=args.project_root,
        activation=args.activation,
        generation=generation,
        audit=audit,
        final_freeze=final_freeze,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
