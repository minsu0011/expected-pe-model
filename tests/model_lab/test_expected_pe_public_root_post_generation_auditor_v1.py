from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path

import pytest

from research.model_zoo.expected_pe_public_root_post_generation_auditor_v1 import (
    PRODUCTION_SPEC,
    audit_public_root,
    publish_atomic_audit,
)
from research.model_zoo.expected_pe_public_root_post_generation_auditor_v1.contracts import (
    AUDIT_SCHEMA_VERSION,
    GO_STATUS,
    NO_GO_STATUS,
    PUBLIC_ROOT_FILE_UNIVERSE,
    PUBLIC_TASK_FILE_UNIVERSE,
    PostGenerationAuditError,
    canonical_json_bytes,
    canonical_value_sha256,
)
from research.model_zoo.expected_pe_public_root_post_generation_auditor_v1.filesystem import (
    capture_identity,
)


TOKEN = "a" * 64


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _csv(
    header: list[str], rows: list[list[object]], *, utf8_bom: bool = False
) -> bytes:
    lines = [",".join(header)]
    lines.extend(",".join(str(value) for value in row) for row in rows)
    raw = ("\n".join(lines) + "\n").encode("utf-8")
    return b"\xef\xbb\xbf" + raw if utf8_bom else raw


def _header_sha(raw: bytes) -> str:
    return _sha(raw.split(b"\n", 1)[0].rstrip(b"\r"))


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def _fixture_spec():
    canonical = _csv(
        ["date", "expected_pe", "eps"],
        [["2020-01-01", 1, 2]],
        utf8_bom=True,
    )
    overlay = _csv(
        ["date", "expected_pe", "eps", "overlay"],
        [["2020-01-01", 1, 2, 3]],
        utf8_bom=True,
    )
    diagnostics = _csv(["date", "diagnostic"], [["2020-01-01", 0]])
    identities = _csv(
        ["seed", "dgp", "row_position", "date"],
        [[1, "A", 0, "2020-01-01"]],
    )
    return replace(
        PRODUCTION_SPEC,
        public_root_prefix="fixture_public_",
        expected_public_run_id=None,
        seeds=(1, 2),
        dgps=("A", "B"),
        rows_per_task=3,
        surface_headers={
            "canonical150.csv": (3, _header_sha(canonical)),
            "v04_overlay.csv": (4, _header_sha(overlay)),
            "comparator_diagnostics.csv": (2, _header_sha(diagnostics)),
        },
        full_identities_header_raw_sha256=_header_sha(identities),
        expected_design_checksums_raw_sha256="b" * 64,
        expected_source_lock_raw_sha256="c" * 64,
        expected_runtime_lock_semantic_sha256="d" * 64,
    )


def _dates(seed: int, dgp: str) -> list[str]:
    month = seed
    start = ord(dgp) - ord("A") + 1
    return [f"2020-{month:02d}-{day:02d}" for day in range(start, start + 3)]


def _task_artifacts(spec, seed: int, dgp: str) -> tuple[dict[str, bytes], list[str]]:
    dates = _dates(seed, dgp)
    canonical = _csv(
        ["date", "expected_pe", "eps"],
        [[value, position + 1, position + 2] for position, value in enumerate(dates)],
        utf8_bom=True,
    )
    overlay = _csv(
        ["date", "expected_pe", "eps", "overlay"],
        [[value, position + 1, position + 2, position + 3] for position, value in enumerate(dates)],
        utf8_bom=True,
    )
    diagnostics = _csv(
        ["date", "diagnostic"],
        [[value, position] for position, value in enumerate(dates)],
    )
    public = {
        "price": _csv(["date", "close"], [[value, 10 + i] for i, value in enumerate(dates)]),
        "benchmark": _csv(
            ["date", "benchmark_close"], [[value, 20 + i] for i, value in enumerate(dates)]
        ),
        "eps_events": _csv(["date", "eps"], [[value, 2 + i] for i, value in enumerate(dates)]),
        "public_factors": _csv(
            ["date", "factor"], [[value, 3 + i] for i, value in enumerate(dates)]
        ),
        "corporate_actions": _csv(
            ["date", "stock_split"], [[value, 0] for value in dates]
        ),
    }
    artifacts: dict[str, bytes] = {
        "canonical150.csv": canonical,
        "v04_overlay.csv": overlay,
        "comparator_diagnostics.csv": diagnostics,
    }
    artifacts.update({f"public/{name}.csv": raw for name, raw in public.items()})
    identity = canonical_value_sha256(dates)
    artifacts["GEOMETRY.json"] = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r7.qualification.task_geometry.v1",
            "seed": seed,
            "dgp": dgp,
            "rows": spec.rows_per_task,
            "canonical_columns": 3,
            "overlay_columns": 4,
            "diagnostic_columns": 2,
            "first_date": dates[0],
            "last_date": dates[-1],
            "identity_sha256": identity,
            "canonical_header_raw_sha256": spec.surface_headers["canonical150.csv"][1],
            "overlay_header_raw_sha256": spec.surface_headers["v04_overlay.csv"][1],
            "diagnostics_header_raw_sha256": spec.surface_headers[
                "comparator_diagnostics.csv"
            ][1],
        }
    )
    artifacts["PUBLIC_LEDGER.json"] = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r7.qualification.public_ledger.v1",
            "status": "PASS_EXACT_PUBLIC_CHANNEL_LEDGER",
            "seed": seed,
            "dgp": dgp,
            "artifacts": {
                name: {
                    "raw_sha256": _sha(raw),
                    "logical_sha256": TOKEN,
                    "rows": spec.rows_per_task,
                    "columns": raw.split(b"\n", 1)[0].decode().split(","),
                }
                for name, raw in public.items()
            },
            "protected_path_received": False,
            "protected_value_received": False,
        }
    )
    artifacts["REPLAY_RECEIPT.json"] = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r7.qualification.public_replay_receipt.v1",
            "status": "PASS_SCORE_FREE_PUBLIC_CANONICAL_OVERLAY_REPLAY",
            "stage": "QUALIFICATION",
            "truth_namespace_accessed": False,
            "protected_path_received": False,
            "score_fit_prediction_evaluation": False,
            "public_inputs_used": list(spec.replay_public_input_names),
            "public_input_raw_sha256": {
                name: _sha(public[name]) for name in spec.replay_public_input_names
            },
            "canonical150_raw_sha256": _sha(canonical),
            "canonical150_logical_sha256": TOKEN,
            "canonical150_header_semantic_sha256": TOKEN,
            "canonical150_header_raw_sha256": spec.surface_headers["canonical150.csv"][1],
            "canonical150_rows": spec.rows_per_task,
            "canonical150_columns": 3,
            "v04_overlay_raw_sha256": _sha(overlay),
            "v04_overlay_logical_sha256": TOKEN,
            "v04_overlay_header_raw_sha256": spec.surface_headers["v04_overlay.csv"][1],
            "v04_overlay_rows": spec.rows_per_task,
            "v04_overlay_columns": 4,
            "identity_sha256": identity,
            "replay_inventory_combined_sha256": TOKEN,
            "normalized_invocations": {"v03": ["$PYTHON"], "v04": ["$PYTHON"]},
            "child_attestation": {"v03": TOKEN, "v04": TOKEN},
        }
    )
    without_task_receipt = {name: _sha(raw) for name, raw in artifacts.items()}
    artifacts["TASK_RECEIPT.json"] = canonical_json_bytes(
        {
            "schema_version": "expected_pe.r7.qualification.public_task_receipt.v1",
            "status": "PASS_PUBLIC_TASK_FROZEN_PENDING_BYTE_PARITY",
            "stage": "QUALIFICATION",
            "seed": seed,
            "dgp": dgp,
            "artifact_raw_sha256_without_self": dict(sorted(without_task_receipt.items())),
            "identity_sha256": identity,
            "protected_path_received": False,
            "protected_value_received": False,
            "truth_namespace_accessed": False,
            "score_fit_prediction_evaluation": False,
        }
    )
    assert tuple(sorted(artifacts)) == PUBLIC_TASK_FILE_UNIVERSE
    return artifacts, dates


def _build_fixture(root: Path):
    spec = _fixture_spec()
    task_rows: list[dict[str, object]] = []
    identities: list[list[object]] = []
    for seed in spec.seeds:
        for dgp in spec.dgps:
            artifacts, dates = _task_artifacts(spec, seed, dgp)
            for replay_pass in spec.replay_passes:
                base = root / "replays" / f"pass_{replay_pass}" / f"seed_{seed}" / f"dgp_{dgp}"
                for relative, raw in artifacts.items():
                    _write(base / relative, raw)
            for position, value in enumerate(dates):
                identities.append([seed, dgp, position, value])
            task_rows.append(
                {
                    "seed": seed,
                    "dgp": dgp,
                    "artifact_raw_sha256": {
                        name: _sha(raw) for name, raw in sorted(artifacts.items())
                    },
                    "artifact_logical_sha256": {
                        name: TOKEN for name in artifacts if name.endswith(".csv")
                    },
                    "identity_sha256": canonical_value_sha256(dates),
                    "both_passes_reopened": True,
                    "byte_exact": True,
                }
            )
    full_identities = _csv(["seed", "dgp", "row_position", "date"], identities)
    _write(root / "FULL_IDENTITIES.csv", full_identities)
    protected = {
        "schema_version": "expected_pe.r7.qualification.protected_metadata_receipt.v1",
        "status": "PASS_OPAQUE_METADATA_ONLY_SEPARATE_PROCESS_TWO_PASS",
        "stage": "QUALIFICATION",
        "task_count": spec.task_count_per_pass,
        "artifact_count": spec.task_count_per_pass * len(spec.replay_passes) * 2,
        "generator_invocations": spec.task_count_per_pass * len(spec.replay_passes),
        "seed_ids_sha256": canonical_value_sha256(list(spec.seeds)),
        "dgp_ids_sha256": canonical_value_sha256(list(spec.dgps)),
        "truth_header_raw_sha256": "081a13f6ba0844beeb9cfc2b1cf211e937d2d1e4eeaaf555185eec50524e4f0d",
        "aggregate_metadata_sha256": TOKEN,
        "byte_hash_parity": True,
    }
    protected_raw = canonical_json_bytes(protected)
    _write(root / "PROTECTED_METADATA_RECEIPT.json", protected_raw)
    parity = {
        "schema_version": "expected_pe.r7.qualification.public_byte_parity.v1",
        "status": "PASS_TWO_INDEPENDENT_PUBLIC_PASSES_REOPENED_BYTE_AND_LOGICAL_EXACT",
        "task_count": spec.task_count_per_pass,
        "artifact_comparisons": spec.task_count_per_pass * len(spec.task_file_universe),
        "full_identity_count": spec.full_identity_count,
        "full_identity_raw_sha256": _sha(full_identities),
        "tasks": task_rows,
        "receipt_only_parity_accepted": False,
    }
    parity_raw = canonical_json_bytes(parity)
    _write(root / "PARITY_RECEIPT.json", parity_raw)
    _write(
        root / "ACCESS_RECEIPT.json",
        canonical_json_bytes(
            {
                "schema_version": "expected_pe.r7.qualification.public_access.v1",
                "status": "PASS_PUBLIC_ONLY_NO_PROTECTED_PATH_VALUE_OR_IMPORT",
                "truth_vault_latent_path_open_count": 0,
                "protected_value_received": False,
                "protected_path_received": False,
                "model_fit_prediction_score_evaluation": False,
            }
        ),
    )
    _write(
        root / "SOURCE_RECEIPT.json",
        canonical_json_bytes(
            {
                "schema_version": "expected_pe.r7.qualification.public_source_receipt.v1",
                "status": "PASS_VERIFIED_SOURCE_LOCK",
                "source_lock_raw_sha256": spec.expected_source_lock_raw_sha256,
                "design_checksums_raw_sha256": spec.expected_design_checksums_raw_sha256,
                "runtime_lock_semantic_sha256": spec.expected_runtime_lock_semantic_sha256,
            }
        ),
    )
    _write(
        root / "RESOURCE_RECEIPT.json",
        canonical_json_bytes(
            {
                "schema_version": "expected_pe.r7.qualification.public_resource.v1",
                "status": "PASS_CPU0_31_INNER1_GPU_OFF",
                "affinity_mask_hex": "0xFFFFFFFF",
                "logical_cpu_count": 32,
                "inner_threads": 1,
                "total_physical_gib": 96.0,
                "available_physical_gib": 64.0,
                "environment": [
                    ["CUDA_VISIBLE_DEVICES", "-1"],
                    ["MKL_NUM_THREADS", "1"],
                    ["NUMEXPR_NUM_THREADS", "1"],
                    ["NVIDIA_VISIBLE_DEVICES", "void"],
                    ["OMP_NUM_THREADS", "1"],
                    ["OPENBLAS_NUM_THREADS", "1"],
                    ["VECLIB_MAXIMUM_THREADS", "1"],
                ],
                "gpu_enabled": False,
            }
        ),
    )
    _write(
        root / "MANIFEST.json",
        canonical_json_bytes(
            {
                "schema_version": "expected_pe.r7.qualification.public_manifest.v1",
                "status": "PASS_PUBLIC_STAGING_EXACT_PENDING_ATOMIC_PUBLISH",
                "root_file_universe": list(spec.root_file_universe),
                "task_file_universe": list(spec.task_file_universe),
                "task_count_per_pass": spec.task_count_per_pass,
                "public_replay_passes": len(spec.replay_passes),
                "full_identity_count": spec.full_identity_count,
                "public_artifact_byte_parity": True,
                "protected_payload_present": False,
            }
        ),
    )
    _write(
        root / "FREEZE_RECEIPT.json",
        canonical_json_bytes(
            {
                "schema_version": "expected_pe.r7.qualification.public_freeze_receipt.v1",
                "status": "PASS_PUBLIC_ROOT_FROZEN_PENDING_ATOMIC_PUBLISH",
                "design_checksums_raw_sha256": spec.expected_design_checksums_raw_sha256,
                "parity_receipt_raw_sha256": _sha(parity_raw),
                "full_identities_raw_sha256": _sha(full_identities),
                "protected_metadata_receipt_raw_sha256": _sha(protected_raw),
                "qualification_only": True,
                "heldout_authority": False,
                "score_fit_prediction_evaluation": False,
            }
        ),
    )
    checksum_lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        checksum_lines.append(f"{_sha(path.read_bytes())}  {relative}")
    checksums_raw = ("\n".join(checksum_lines) + "\n").encode("ascii")
    _write(root / "CHECKSUMS.sha256", checksums_raw)
    assert tuple(sorted(path.name for path in root.iterdir() if path.is_file())) == (
        PUBLIC_ROOT_FILE_UNIVERSE
    )
    return spec, _sha(checksums_raw)


def test_production_contract_is_exact_50_by_2_by_12_and_90000() -> None:
    assert PRODUCTION_SPEC.expected_public_run_id == "20260824T000005"
    assert "r8_r14" in PRODUCTION_SPEC.public_root_prefix
    assert PRODUCTION_SPEC.task_count_per_pass == 50
    assert len(PRODUCTION_SPEC.replay_passes) == 2
    assert len(PRODUCTION_SPEC.task_file_universe) == 12
    assert PRODUCTION_SPEC.task_artifact_count == 1_200
    assert PRODUCTION_SPEC.target_root_file_count == 1_209
    assert PRODUCTION_SPEC.full_identity_count == 90_000
    assert len(PRODUCTION_SPEC.root_file_universe) == 9
    assert PRODUCTION_SPEC.full_identities_header_raw_sha256 == (
        "eef0415e9d126f903e493f225b405569b28a8f29432b6be513e0237e4604848c"
    )


def test_production_contract_rejects_any_other_public_run_id(tmp_path: Path) -> None:
    wrong_name = f"{PRODUCTION_SPEC.public_root_prefix}20260824T000006"
    with pytest.raises(PostGenerationAuditError) as caught:
        audit_public_root(
            tmp_path / "must_not_be_opened",
            expected_public_root_name=wrong_name,
            expected_checksums_raw_sha256=TOKEN,
        )
    assert caught.value.code == "P0_EXPECTED_TARGET_BINDING_INVALID"


def test_fixture_go_binds_tree_receipts_identities_and_access(tmp_path: Path) -> None:
    root = tmp_path / "fixture_public_run"
    root.mkdir()
    spec, checksums_sha = _build_fixture(root)
    report = audit_public_root(
        root,
        expected_public_root_name=root.name,
        expected_checksums_raw_sha256=checksums_sha,
        spec=spec,
    )
    assert report["schema_version"] == AUDIT_SCHEMA_VERSION
    assert report["status"] == report["verdict"] == GO_STATUS
    assert report["severity_counts"] == {"P0": 0, "P1": 0, "P2": 0}
    assert report["expected_public_tree_semantic_sha256"] == report[
        "public_tree_semantic_sha256"
    ]
    assert report["target_root_file_count"] == spec.target_root_file_count
    assert report["geometry"]["full_identity_count"] == spec.full_identity_count
    assert report["access"] == {
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "protected_namespace_open_count": 0,
        "public_protected_metadata_receipt_open_count": 1,
    }
    assert report["target_binding_sha256"] == canonical_value_sha256(
        report["target_binding"]
    )


def test_atomic_go_has_exact_three_file_output_and_seal(tmp_path: Path) -> None:
    root = tmp_path / "fixture_public_atomic"
    root.mkdir()
    spec, checksums_sha = _build_fixture(root)
    output = tmp_path / "audit_go"
    report = publish_atomic_audit(
        root,
        output_root=output,
        expected_public_root_name=root.name,
        expected_checksums_raw_sha256=checksums_sha,
        spec=spec,
    )
    assert report["status"] == GO_STATUS
    assert tuple(sorted(path.name for path in output.iterdir())) == (
        "AUDIT_SEAL.json",
        "CHECKSUMS.sha256",
        "POSTGEN_AUDIT.json",
    )
    audit_raw = (output / "POSTGEN_AUDIT.json").read_bytes()
    seal = json.loads((output / "AUDIT_SEAL.json").read_bytes())
    identity = capture_identity(output / "POSTGEN_AUDIT.json")
    assert seal["status"] == "SEALED_GO_POSTGEN_PUBLIC_ROOT_P0_0_P1_0_P2_0"
    assert seal["postgen_audit_raw_sha256"] == _sha(audit_raw)
    assert seal["postgen_audit_size_bytes"] == len(audit_raw)
    assert seal["postgen_audit_file_id_128"] == identity.file_id_128


def test_extra_public_file_atomically_emits_terminal_no_go(tmp_path: Path) -> None:
    root = tmp_path / "fixture_public_extra"
    root.mkdir()
    spec, checksums_sha = _build_fixture(root)
    (root / "unexpected.txt").write_text("not allowed", encoding="ascii")
    output = tmp_path / "audit_no_go"
    report = publish_atomic_audit(
        root,
        output_root=output,
        expected_public_root_name=root.name,
        expected_checksums_raw_sha256=checksums_sha,
        spec=spec,
    )
    assert report["status"] == report["verdict"] == NO_GO_STATUS
    assert report["severity_counts"] == {"P0": 1, "P1": 0, "P2": 0}
    assert report["findings"][0]["finding_id"] == "P0_PUBLIC_FILE_UNIVERSE"
    assert json.loads((output / "POSTGEN_AUDIT.json").read_bytes()) == report


def test_auditor_source_does_not_import_generator_model_scorer_or_vault() -> None:
    package = Path(__file__).resolve().parents[2] / (
        "research/model_zoo/expected_pe_public_root_post_generation_auditor_v1"
    )
    source = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    assert "observable_state_bce_dgp_tournament_v2_r8_r14_qualification_execution_v1" not in source
    assert "pe_c1_c3_fresh_qualification_service" not in source
    assert "hofs" not in source.casefold()
    assert "detached_evaluation" not in source
