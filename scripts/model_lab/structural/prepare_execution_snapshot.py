"""Freeze the narrow V4 Structural execution dependency closure."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Mapping


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"JSON object required: {path}")
    return value


def main() -> int:
    root = _root()
    sys.path.insert(0, str(root / "src"))
    from pe_regime_v04.model_lab.structural.contracts import (
        STRUCTURAL_DESIGN_SHA256,
        canonical_json_bytes,
        seal_payload,
        sha256_bytes,
        sha256_file,
        verify_payload_seal,
    )

    output_dir = root / "outputs/model_zoo_structural_wave_screen_20260819"
    output = output_dir / "EXECUTION_SNAPSHOT_V4.json"
    if output.exists():
        raise FileExistsError(f"refusing to overwrite execution snapshot: {output}")
    trigger = output_dir / "TRIGGER_DECISION.json"
    base_lock = output_dir / "BASE_BINDING_LOCK_V4.json"
    track_a = output_dir / "TRACK_A_DATA_BOUND_AUDIT.json"
    benchmark = output_dir / "NO_SCORE_BACKEND_BENCHMARK.json"
    required_outputs = (trigger, base_lock, track_a, benchmark)
    values = {path.name: _read(path) for path in required_outputs}
    for value in values.values():
        verify_payload_seal(value)
    if sha256_file(trigger) != "45b6dee894ed72809c49902f4f78ff058a465db6ebfe8903a21c659883504765":
        raise RuntimeError("sealed trigger decision changed")
    if values[track_a.name].get("all_5_surfaces_all_6_audits_pass") is not True:
        raise RuntimeError("Track-A data-bound audit has not passed")
    benchmark_value = values[benchmark.name]
    if benchmark_value.get("parity", {}).get("all_8_16_24_32_repeats_exact") is not True:
        raise RuntimeError("spawn worker-count parity has not passed")
    if benchmark_value.get("warning_failure_ledger") != {"warnings": [], "failures": []}:
        raise RuntimeError("spawn benchmark warning/failure ledger is not clean")
    lock = values[base_lock.name]
    evidence = lock.get("binding_evidence")
    if not isinstance(evidence, Mapping) or "dgp_execution_contract" in evidence:
        raise RuntimeError("V4 base lock must exclude mutable DGP state")

    paths: set[Path] = set()
    # Structural runtime modules (namespace package: no __init__.py is added).
    paths.update((root / "src/pe_regime_v04/model_lab/structural").glob("*.py"))
    # The generated authority-policy module is the acyclic second layer. Its
    # exact bytes must be supplied by an independent external audit pin.
    paths.discard(root / "src/pe_regime_v04/model_lab/structural/authority_policy_v4.py")
    # Importing pe_regime_v04.model_lab executes this frozen Phase-1 package
    # surface; include exactly that local import closure, not tests or scripts.
    for name in (
        "__init__.py",
        "analysis.py",
        "baselines.py",
        "contracts.py",
        "dataset.py",
        "evaluator.py",
        "experiment.py",
        "folds.py",
        "matrices.py",
        "registry.py",
    ):
        paths.add(root / "src/pe_regime_v04/model_lab" / name)
    # Replay adapters provide their own exact source inventories.
    for section in ("residual_v04_replay", "wave1_pair_replay"):
        replay = evidence.get(section)
        if not isinstance(replay, Mapping) or not isinstance(replay.get("source_inventory"), list):
            raise RuntimeError(f"base lock {section} source inventory is missing")
        for row in replay["source_inventory"]:
            paths.add(root / str(row["path"]))

    paths.update(
        {
            root / "outputs/model_zoo_structural_wave_design_20260819/DESIGN.json",
            root / "outputs/model_zoo_wave1_screen_20260819/PREDICT_INPUTS.json",
            root / "outputs/model_zoo_wave1_screen_20260819/EXECUTION_BINDING.json",
            root
            / (
                "outputs/model_zoo_wave1_screen_20260819/execution_snapshots/"
                "040f0f1394875aefab1cdff0bb10c8ae80973cc296de4729b481eb35ce32d1c0.snapshot"
            ),
            root
            / (
                "outputs/model_zoo_wave1_screen_20260819/execution_snapshots/"
                "2ea4c225ed3bcd94d4bb13536a6f00735cdfadf32d1534d4b671ea75e6524d7d.snapshot"
            ),
            root
            / (
                "outputs/model_zoo_wave1_screen_20260819/execution_snapshots/"
                "7b86220669a4e4c013f59b36f990cae09a0f1710909de78132a4adb2621601ab.snapshot"
            ),
            root / "config/v04_bottleneck.yaml",
            root / "config/v04_matured_proxy_regularized_gate_design_lock.json",
            root / "config/v04_matured_proxy_regularized_gate_candidate.json",
            *required_outputs,
        }
    )
    forbidden = {
        root / "research/model_zoo/dgp_suite/EXECUTION_CONTRACT.json",
        root / "research/model_zoo/dgp_suite/RUNTIME_POLICY.json",
        root / "research/model_zoo/dgp_suite/RUNTIME_MANIFEST.json",
    }
    if paths.intersection(forbidden):
        raise RuntimeError("unrelated DGP files entered the Structural execution closure")

    inventory: list[dict[str, Any]] = []
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        if not path.is_file():
            raise RuntimeError(f"snapshot dependency is missing: {path}")
        inventory.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    inventory_sha = sha256_bytes(canonical_json_bytes(inventory))
    payload = seal_payload(
        {
            "format_version": 4,
            "mode": "structural_content_addressed_execution_snapshot",
            "state": "V4_PREPARED_AWAITING_INDEPENDENT_SCORE_FREE_REAUDIT_GO",
            "dependency_scope": "TRANSITIVE_STRUCTURAL_V04_PHASE1_WAVE1_RUNTIME_ONLY",
            "design_sha256": STRUCTURAL_DESIGN_SHA256,
            "trigger_decision_sha256": sha256_file(trigger),
            "trigger_decision_logical_sha256": values[trigger.name]["manifest_sha256"],
            "base_binding_lock_sha256": sha256_file(base_lock),
            "base_binding_lock_logical_sha256": values[base_lock.name]["manifest_sha256"],
            "track_a_data_bound_audit_sha256": sha256_file(track_a),
            "track_a_data_bound_audit_logical_sha256": values[track_a.name]["manifest_sha256"],
            "no_score_backend_benchmark_sha256": sha256_file(benchmark),
            "no_score_backend_benchmark_logical_sha256": values[benchmark.name]["manifest_sha256"],
            "selected_outer_worker_count": benchmark_value["selected_worker_count"],
            "source_inventory": inventory,
            "source_inventory_sha256": inventory_sha,
            "unrelated_dgp_contract_bound": False,
            "scripts_or_tests_in_runtime_inventory": False,
            "authority_policy_layer": "EXTERNAL_RAW_SHA_PIN_REQUIRED_NOT_IN_SNAPSHOT",
            "spent_execution_authorized": False,
            "repeat_independent_audit_required": True,
            "formal_authorizer_behavior": "FAIL_CLOSED_UNTIL_EXACT_V4_POLICY_GETS_GO",
            "attestations": {
                "structural_candidate_predictions_generated": False,
                "structural_candidate_scores_generated": False,
                "formal_exact_base_replay_executed": False,
                "fresh_seed_selected_or_reserved": False,
                "heldout_opened": False,
                "frozen_phase1_wave1_dgp_or_registry_modified": False,
            },
        }
    )
    output.write_bytes(canonical_json_bytes(payload) + b"\n")
    print(
        json.dumps(
            {
                "path": output.relative_to(root).as_posix(),
                "file_sha256": sha256_file(output),
                "manifest_sha256": payload["manifest_sha256"],
                "inventory_count": len(inventory),
                "selected_outer_worker_count": payload["selected_outer_worker_count"],
                "spent_execution_authorized": False,
                "unrelated_dgp_contract_bound": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
