"""One-shot launcher for target-bound C4 H-OFS V12 qualification prediction."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.hofs_v12_fresh_qualification_service_v2 import (  # noqa: E402
    bind_postgen_audited_common_root,
    capture_source_closure,
    publish_qualification_surface,
    run_bound_qualification,
)
from research.model_zoo.hofs_v12_fresh_qualification_service_v2.contracts import (  # noqa: E402
    GPU_OFF_ENVIRONMENT,
    OUTER_WORKERS,
    PROCESS_START_METHOD,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--common-root", type=Path)
    parser.add_argument("--postgen-audit", type=Path)
    parser.add_argument("--postgen-audit-seal", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--check-only", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if Path.cwd().resolve(strict=True) != PROJECT_ROOT.resolve(strict=True):
        raise RuntimeError("C4 qualification launcher must run from the project root")
    source = capture_source_closure()
    if args.check_only:
        if any(
            value is not None
            for value in (
                args.common_root,
                args.postgen_audit,
                args.postgen_audit_seal,
                args.output_root,
            )
        ):
            raise RuntimeError("check-only cannot receive actual common-root or output paths")
        print(
            json.dumps(
                {
                    "status": "PASS_C4_QUALIFICATION_CHECK_ONLY_NO_FRESH_ACCESS",
                    "outer_workers": OUTER_WORKERS,
                    "process_start_method": PROCESS_START_METHOD,
                    "gpu_off_environment": GPU_OFF_ENVIRONMENT,
                    "source_record_count": len(source.records),
                    "source_records_semantic_sha256": source.semantic_sha256,
                    "truth_access_count": 0,
                    "heldout_access_count": 0,
                    "score_access_count": 0,
                    "fresh_access_count": 0,
                },
                sort_keys=True,
            )
        )
        return 0
    if (
        args.common_root is None
        or args.postgen_audit is None
        or args.postgen_audit_seal is None
        or args.output_root is None
    ):
        raise RuntimeError(
            "actual launch requires common root, postgen audit, audit seal, and output root"
        )
    common = bind_postgen_audited_common_root(
        common_root=args.common_root,
        postgen_audit_path=args.postgen_audit,
        postgen_audit_seal_path=args.postgen_audit_seal,
        source_closure=source,
    )
    computation = run_bound_qualification(common)
    result = publish_qualification_surface(
        common=common,
        computation=computation,
        output_root=args.output_root,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
