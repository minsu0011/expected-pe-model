"""Run the immutable A--J writer smoke without fitting or scoring any model."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from research.model_zoo.dgp_suite import (
    FIXTURE_MASTER_SEED,
    FixtureSeed,
    generate_dgp,
    load_fixed_fixture_trust_root,
    write_dgp_artifacts,
)
from research.model_zoo.dgp_suite.artifacts import canonical_json_bytes


def _verify_one(root: Path, dgp_id: str, seed: FixtureSeed) -> dict[str, object]:
    generated = generate_dgp(dgp_id, fixture_seed=seed)
    destination = root / f"DGP_{dgp_id}"
    first = write_dgp_artifacts(generated, destination)
    second = write_dgp_artifacts(generated, destination)
    if first != second or len(first) != 9:
        raise RuntimeError(f"writer immutability failed for DGP {dgp_id}")
    if (
        generated.generation_audit["model_executed"] is not False
        or generated.generation_audit["candidate_score_computed"] is not False
    ):
        raise RuntimeError(f"score-free boundary failed for DGP {dgp_id}")
    if (destination / "public" / "truth.csv").exists():
        raise RuntimeError(f"public truth leak for DGP {dgp_id}")
    trusted = load_fixed_fixture_trust_root()["manifests"][dgp_id]
    expected = {
        **trusted["artifact_sha256"],
        "evaluator_only/generation_audit.json": trusted["generation_audit_raw_sha256"],
        "generation_capability.json": trusted["generation_capability_raw_sha256"],
    }
    if first != expected:
        raise RuntimeError(f"implementation trust-root mismatch for DGP {dgp_id}")
    generation_audit_raw = canonical_json_bytes(dict(generated.generation_audit))
    physical_audit_raw = (destination / "evaluator_only" / "generation_audit.json").read_bytes()
    return {
        "artifact_count": len(first),
        "generation_audit_sha256": hashlib.sha256(generation_audit_raw).hexdigest(),
        "generation_capability_sha256": first["generation_capability.json"],
        "immutable_second_write": True,
        "physical_audit_sha256": hashlib.sha256(physical_audit_raw).hexdigest(),
        "trust_root_match": True,
    }


def main() -> int:
    seed = FixtureSeed(FIXTURE_MASTER_SEED)
    with tempfile.TemporaryDirectory(prefix="pe_dgp_writer_smoke_") as temporary:
        root = Path(temporary)
        result = {dgp_id: _verify_one(root, dgp_id, seed) for dgp_id in tuple("ABCDEFGHIJ")}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
