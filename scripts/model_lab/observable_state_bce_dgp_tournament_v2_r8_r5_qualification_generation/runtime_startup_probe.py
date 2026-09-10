"""Check-only isolated replay of the externally pinned Python startup TCB."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[3]
for value in (PROJECT_ROOT, PROJECT_ROOT / "src"):
    if str(value) not in sys.path:
        sys.path.append(str(value))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.contracts import (  # noqa: E402
    BYTECODE_BLACKHOLE_RELATIVE,
    canonical_json_bytes,
    sha256_bytes,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.runtime_tcb import (  # noqa: E402
    load_runtime_tcb,
    require_isolated_child,
    verify_loaded_origin_closure,
    verify_startup_runtime_tcb,
)


def _load_source_lock(path: Path, *, expected_raw_sha256: str) -> dict[str, object]:
    raw = path.resolve(strict=True).read_bytes()
    if sha256_bytes(raw) != expected_raw_sha256:
        raise RuntimeError("isolated startup probe source-lock raw pin drifted")
    payload = json.loads(raw)
    stored = payload.pop("source_lock_semantic_sha256", None)
    if stored != sha256_bytes(canonical_json_bytes(payload)):
        raise RuntimeError("isolated startup probe source-lock semantic seal drifted")
    payload["source_lock_semantic_sha256"] = stored
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--source-lock", type=Path, required=True)
    parser.add_argument("--source-lock-sha256", required=True)
    arguments = parser.parse_args()
    blackhole = (PROJECT_ROOT / BYTECODE_BLACKHOLE_RELATIVE).resolve(strict=False)
    if Path(str(sys.pycache_prefix)).resolve(strict=False) != blackhole or blackhole.exists():
        raise RuntimeError("isolated startup probe bytecode blackhole binding drifted")
    require_isolated_child()
    source_lock = _load_source_lock(
        arguments.source_lock,
        expected_raw_sha256=arguments.source_lock_sha256,
    )
    runtime = load_runtime_tcb(
        arguments.runtime,
        expected_raw_sha256=arguments.runtime_sha256,
    )
    local_records = source_lock["records"]
    startup = verify_startup_runtime_tcb(runtime, local_source_records=local_records)
    loaded = verify_loaded_origin_closure(runtime, local_source_records=local_records)
    protected = sorted(
        name
        for name in sys.modules
        if name.endswith(".protected_role")
        or name == "research.model_zoo.dgp_exploration_v2.generator"
    )
    if protected:
        raise RuntimeError("isolated startup probe imported a protected generator module")
    payload = {
        "schema_version": "expected_pe.r8.r5.isolated_runtime_startup_probe.v1",
        "status": "PASS_NO_UNSEALED_STARTUP_OR_NATIVE_MODULE_ORIGIN",
        "startup": startup,
        "loaded": loaded,
        "python_native_member_count": len(runtime["python_native_members"]),
        "python_native_complete_tree_count": len(
            runtime["python_native_inventory"]["complete_tree_roots"]
        ),
        "unsealed_loaded_origin_count": 0,
        "protected_generator_import_count": 0,
        "qualification_generation_authorized": False,
        "payload_generation_count": 0,
        "truth_vault_latent_open_count": 0,
        "registry_mutation_count": 0,
    }
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True, allow_nan=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
