from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pe_regime_v04.model_lab.models.wave1.artifacts import (
    file_record,
    load_sealed_json,
    seal_payload,
    write_immutable_json,
)
from pe_regime_v04.model_lab.models.wave1.audit import (
    AUDIT_APPROVAL_SCOPE,
    AUDIT_CHECK_NAMES,
    AuditTrustError,
    audit_inventory_sha256,
    verify_independent_audit_go,
)
from pe_regime_v04.model_lab.models.wave1.authorization import (
    ExecutionAuthorizationError,
    authorize_execution,
    verify_historical_execution_snapshots,
)
from pe_regime_v04.model_lab.models.wave1.binding import (
    RUNTIME_DEPENDENCY_RELATIVE_PATHS,
    build_execution_binding_payload,
    runtime_inventory,
    write_execution_package,
)
from pe_regime_v04.model_lab.models.wave1.spec import DESIGN_LOCK_SHA256, EVIDENCE_SEEDS


def _audit_go(tmp_path: Path) -> Path:
    root = Path(__file__).resolve().parents[2]
    audited = Path(__file__).resolve()
    relative = audited.relative_to(root).as_posix()
    inventory = [
        {
            "relative_path": relative,
            "bytes": audited.stat().st_size,
            "sha256": file_record(audited)["sha256"],
        }
    ]
    empty_sha = hashlib.sha256(b"").hexdigest()
    candidate = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_audit_candidate",
            "design_lock_sha256": DESIGN_LOCK_SHA256,
            "audit_scope": "WAVE1_NO_SCORE_PRE_EXECUTION",
            "runtime_inventory": inventory,
            "runtime_inventory_sha256": audit_inventory_sha256(inventory),
            "checks": [
                {
                    "name": name,
                    "command": f"synthetic-{name}",
                    "exit_code": 0,
                    "stdout_sha256": empty_sha,
                    "stderr_sha256": empty_sha,
                    "stdout_base64": "",
                    "stderr_base64": "",
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "summary": "PASS",
                }
                for name in AUDIT_CHECK_NAMES
            ],
            "mg1_schema_check": {
                "status": "PASS",
                "seeds": list(EVIDENCE_SEEDS),
                "candidate_predictions_run": False,
                "candidate_scores_seen": False,
                "fresh_or_heldout_opened": False,
            },
            "candidate_scores_seen": False,
            "candidate_predictions_run": False,
            "fresh_or_heldout_opened": False,
            "execution_binding_written": False,
            "execution_precommit_written": False,
            "registries_mutated": False,
        }
    )
    candidate_path = tmp_path / "AUDIT_CANDIDATE.json"
    write_immutable_json(candidate_path, candidate)
    go = seal_payload(
        {
            "format_version": 1,
            "mode": "wave1_independent_audit_go",
            "decision": "GO",
            "auditor_role": "independent_wave1_auditor",
            "approval_scope": list(AUDIT_APPROVAL_SCOPE),
            "audit_candidate": file_record(candidate_path),
            "audit_candidate_manifest_sha256": candidate["manifest_sha256"],
            "runtime_inventory_sha256": candidate["runtime_inventory_sha256"],
            "candidate_scores_seen": False,
            "candidate_predictions_run": False,
            "fresh_or_heldout_opened": False,
        }
    )
    go_path = tmp_path / "INDEPENDENT_AUDIT_GO.json"
    write_immutable_json(go_path, go)
    return go_path


def _package(tmp_path: Path) -> tuple[dict[str, Path], Path]:
    root = Path(__file__).resolve().parents[2]
    mutable = tmp_path / "runtime_source.py"
    mutable.write_text("VALUE = 1\n", encoding="utf-8")
    snapshot_directory = tmp_path / "snapshots"
    snapshot_directory.mkdir()

    def entry(label: str, live: Path) -> dict:
        snapshot = snapshot_directory / f"snapshot_{len(list(snapshot_directory.iterdir()))}"
        snapshot.write_bytes(live.read_bytes())
        return {
            "label": label,
            "live_path": str(live.resolve()),
            "snapshot": file_record(snapshot),
        }

    inventory = [
        entry(
            "outputs/model_zoo_wave1_screen_20260819/DESIGN_LOCK.json",
            (
                root / "outputs/model_zoo_wave1_screen_20260819/DESIGN_LOCK.json"
            ),
        ),
        entry(
            "outputs/model_zoo_wave1_screen_20260819/PRECOMMIT.json",
            (
                root / "outputs/model_zoo_wave1_screen_20260819/PRECOMMIT.json"
            ),
        ),
        entry("synthetic/runtime_source.py", mutable),
    ]
    binding = build_execution_binding_payload(
        runtime_verified_files=inventory,
        opaque_external_artifact_digests=[],
        fold_bindings=[],
        registry_state={"test_only": True},
        independent_audit_go=file_record(_audit_go(tmp_path)),
    )
    paths = write_execution_package(
        tmp_path / "package",
        binding_payload=binding,
        predict_entries=[],
        evaluate_entries=[],
    )
    return paths, mutable


def test_two_phase_inputs_bind_exact_precommit_without_exposing_evaluation_path(
    tmp_path: Path,
) -> None:
    paths, _ = _package(tmp_path)
    predict_text = paths["predict_inputs"].read_text(encoding="utf-8").lower()
    assert "evaluate_inputs" not in predict_text
    assert "true_fair_pe" not in predict_text
    predict = authorize_execution(
        paths["precommit"], paths["predict_inputs"], mode="predict"
    )
    evaluate = authorize_execution(
        paths["precommit"], paths["evaluate_inputs"], mode="evaluate"
    )
    assert predict.precommit_record == evaluate.precommit_record
    assert predict.binding_record == evaluate.binding_record


def test_authorization_rejects_runtime_source_tamper(tmp_path: Path) -> None:
    paths, mutable = _package(tmp_path)
    mutable.write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(ExecutionAuthorizationError, match="differs from its execution snapshot"):
        authorize_execution(paths["precommit"], paths["predict_inputs"], mode="predict")
    verified = verify_historical_execution_snapshots(paths["binding"])
    assert verified["mode"] == "execution_binding"


def test_authorization_rejects_old_or_resealed_input_binding(tmp_path: Path) -> None:
    paths, _ = _package(tmp_path)
    payload = load_sealed_json(paths["predict_inputs"], expected_mode="predict_inputs")
    payload["execution_binding"] = {
        "path": str((tmp_path / "old_binding.json").resolve()),
        "bytes": 0,
        "sha256": "0" * 64,
    }
    resealed = seal_payload(payload)
    bad_path = tmp_path / "bad_predict_inputs.json"
    bad_path.write_text(json.dumps(resealed), encoding="utf-8")
    with pytest.raises(ExecutionAuthorizationError, match="exact execution binding"):
        authorize_execution(paths["precommit"], bad_path, mode="predict")


def test_runtime_inventory_uses_exact_allowlist_and_content_snapshots(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    inventory = runtime_inventory(
        root,
        (),
        snapshot_directory=tmp_path / "snapshots",
    )
    assert {item["label"] for item in inventory} == set(
        RUNTIME_DEPENDENCY_RELATIVE_PATHS
    )
    assert len(inventory) == len(RUNTIME_DEPENDENCY_RELATIVE_PATHS)
    assert all(Path(item["snapshot"]["path"]).parent == tmp_path / "snapshots" for item in inventory)


def test_prediction_cli_has_precommit_but_no_evaluation_or_truth_argument() -> None:
    root = Path(__file__).resolve().parents[2]
    source = (root / "scripts/model_lab/wave1/predict.py").read_text(encoding="utf-8")
    assert '"--execution-precommit"' in source
    assert '"--evaluation-inputs"' not in source
    assert '"--truth' not in source


def test_magic_literal_go_without_seal_and_exact_inventory_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "fabricated_go.json"
    path.write_text(
        json.dumps(
            {
                "wave1_execution_binding_and_precommit": "GO",
                "candidate_scores_seen": False,
                "candidate_predictions_run": False,
                "fresh_or_heldout_opened": False,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(AuditTrustError):
        verify_independent_audit_go(
            path,
            project_root=Path(__file__).resolve().parents[2],
        )
