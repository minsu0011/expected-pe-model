"""Verify the pinned DGP design and print the score-free execution contract."""

from __future__ import annotations

import json

from research.model_zoo.dgp_suite.design import load_design_seal
from research.model_zoo.dgp_suite.model_surface import execution_contract_payload


def main() -> int:
    seal = load_design_seal()
    payload = {
        "design_md_sha256": seal.design_md_sha256,
        "design_json_sha256": seal.design_json_sha256,
        "structural_parameters_sha256": seal.structural_parameters_sha256,
        "execution_contract": execution_contract_payload(),
        "model_executed": False,
        "candidate_score_computed": False,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
