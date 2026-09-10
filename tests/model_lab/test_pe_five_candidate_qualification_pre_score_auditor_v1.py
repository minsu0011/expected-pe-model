from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.auditor import (
    _artifact_ref_from_snapshot,
    _no_go_report,
    _parse_checksums,
    _static_scorer_checks,
)
from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.canonical import (
    PreScoreAuditError,
    canonical_json_bytes,
    checksum_bytes,
    read_canonical_json,
    semantic_sha256,
    sha256_bytes,
)
from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.contracts import (
    COMMON_ROOT_NAME,
    COMBINED_ROOT_NAME,
    DGP_IDS,
    FROZEN_RUNTIME_DEPENDENCY_SHA256,
    MODEL_IDS,
    POLICY_RAW_SHA256,
    POSTGEN_AUDIT_ROOT_NAME,
    PRESCORE_AUDIT_ROOT_NAME,
    PRESCORE_TARGET_ROOT_NAME,
    PREDICTION_AUDIT_ROOT_NAME,
    QUALIFICATION_SEEDS,
    SCORER_ACTIVATION_SCHEMA,
    SCORER_ACTIVATION_STATUS,
    SCORER_SOURCE_RELATIVES,
    TARGET_SCHEMA,
    TARGET_STATUS,
)
from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.publication import (
    OutputRoot,
)
from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.custody import (
    HeldArtifactSet,
)
from research.model_zoo.pe_five_candidate_qualification_pre_score_auditor_v1.target import (
    TargetBinding,
)


def _digest(index: int, digits: int) -> str:
    return f"{index + 1:0{digits}x}"[-digits:]


def test_checksum_modes_separate_common_from_ascii_producers() -> None:
    records = {"BETA.json": "2" * 64, "alpha.csv": "1" * 64, "Gamma.json": "3" * 64}
    expected = (f"{'1' * 64}  alpha.csv\n{'2' * 64}  BETA.json\n{'3' * 64}  Gamma.json\n").encode(
        "ascii"
    )
    assert checksum_bytes(records, ordering="windows_path_casefold") == expected
    assert (
        _parse_checksums(
            expected,
            label="mixed-case common ledger",
            ordering="windows_path_casefold",
        )
        == records
    )
    ascii_ordered = (
        f"{'2' * 64}  BETA.json\n{'3' * 64}  Gamma.json\n{'1' * 64}  alpha.csv\n"
    ).encode("ascii")
    assert checksum_bytes(records, ordering="ascii") == ascii_ordered
    assert (
        _parse_checksums(
            ascii_ordered,
            label="mixed-case combined ledger",
            ordering="ascii",
        )
        == records
    )
    with pytest.raises(PreScoreAuditError, match="ordering/canonical"):
        _parse_checksums(
            ascii_ordered,
            label="wrong common-ledger mode",
            ordering="windows_path_casefold",
        )
    with pytest.raises(PreScoreAuditError, match="ordering/canonical"):
        _parse_checksums(expected, label="wrong combined-ledger mode", ordering="ascii")


def test_r4_prescore_root_identities_are_exact() -> None:
    assert PRESCORE_TARGET_ROOT_NAME == (
        "pe_five_model_qualification_prescore_target_r4_r8_r14_20260824T000005"
    )
    assert PRESCORE_AUDIT_ROOT_NAME == (
        "pe_five_model_qualification_prescore_audit_r4_r8_r14_20260824T000005"
    )


def _ref(path: str, index: int) -> dict[str, object]:
    return {
        "relative_path": path,
        "raw_sha256": _digest(index, 64),
        "size_bytes": 100 + index,
        "volume_serial_number": 17,
        "file_id_128": _digest(index, 32),
    }


def _target_value() -> dict[str, object]:
    index = 10

    def ref(path: str) -> dict[str, object]:
        nonlocal index
        index += 1
        return _ref(path, index)

    combined = COMBINED_ROOT_NAME
    postgen = f"outputs/{POSTGEN_AUDIT_ROOT_NAME}"
    prediction_audit = f"outputs/{PREDICTION_AUDIT_ROOT_NAME}"
    prediction = ref(f"outputs/{combined}/PREDICTIONS.csv")
    prediction_audit_ref = ref(f"{prediction_audit}/PREDICTION_FREEZE_AUDIT.json")
    prediction_seal_ref = ref(f"{prediction_audit}/AUDIT_SEAL.json")
    vault = (
        "outputs/.model_zoo_observable_state_bce_dgp_tournament_v2_r8_r14_"
        "qualification_vault_20260824T000005"
    )
    truth_refs = [
        ref(f"{vault}/pass_1/seed_{seed}/dgp_{dgp}/truth.csv")
        for seed in QUALIFICATION_SEEDS
        for dgp in DGP_IDS
    ]
    core = {
        "schema_version": SCORER_ACTIVATION_SCHEMA,
        "status": SCORER_ACTIVATION_STATUS,
        "run_id": "unit_qualification_once",
        "output_relative_path": "outputs/model_zoo_unit_qualification_result",
        "vault_relative_path": vault,
        "policy_raw_sha256": POLICY_RAW_SHA256,
        "heldout_authority": False,
        "prediction_ref": prediction,
        "prediction_audit_ref": prediction_audit_ref,
        "prediction_audit_seal_ref": prediction_seal_ref,
        "prediction_semantic_sha256": _digest(900, 64),
        "common_full_identities_semantic_sha256": _digest(901, 64),
        "source_model_versions": {
            model_id: f"sha256:{_digest(1000 + ordinal, 64)}"
            for ordinal, model_id in enumerate(MODEL_IDS)
        },
        "truth_refs": truth_refs,
    }
    source_refs = [ref(path) for path in SCORER_SOURCE_RELATIVES]
    for source_ref in source_refs:
        expected_dependency = FROZEN_RUNTIME_DEPENDENCY_SHA256.get(str(source_ref["relative_path"]))
        if expected_dependency is not None:
            source_ref["raw_sha256"] = expected_dependency
    source_refs[-1]["raw_sha256"] = POLICY_RAW_SHA256
    chain = {
        "common_run_id": "20260824T000005",
        "common_root_name": COMMON_ROOT_NAME,
        "common_checksums_ref": ref(f"outputs/{COMMON_ROOT_NAME}/CHECKSUMS.sha256"),
        "common_manifest_ref": ref(f"outputs/{COMMON_ROOT_NAME}/MANIFEST.json"),
        "common_full_identities_ref": ref(f"outputs/{COMMON_ROOT_NAME}/FULL_IDENTITIES.csv"),
        "postgen_audit_ref": ref(f"{postgen}/POSTGEN_AUDIT.json"),
        "postgen_audit_seal_ref": ref(f"{postgen}/AUDIT_SEAL.json"),
        "postgen_checksums_ref": ref(f"{postgen}/CHECKSUMS.sha256"),
        "combined_root_name": combined,
        "combined_checksums_ref": ref(f"outputs/{combined}/CHECKSUMS.sha256"),
        "combined_combination_receipt_ref": ref(f"outputs/{combined}/COMBINATION_RECEIPT.json"),
        "combined_input_binding_ref": ref(f"outputs/{combined}/INPUT_BINDING.json"),
        "combined_input_custody_ref": ref(f"outputs/{combined}/INPUT_CUSTODY_RECEIPT.json"),
        "combined_manifest_ref": ref(f"outputs/{combined}/PREDICTION_MANIFEST.json"),
        "combined_runtime_ref": ref(f"outputs/{combined}/RUNTIME_RECEIPT.json"),
        "combined_source_manifest_ref": ref(f"outputs/{combined}/SOURCE_MANIFEST.json"),
        "prediction_ref": prediction,
        "prediction_audit_ref": prediction_audit_ref,
        "prediction_audit_seal_ref": prediction_seal_ref,
        "prediction_auditor_source_manifest_ref": ref(
            f"{prediction_audit}/AUDITOR_SOURCE_MANIFEST.json"
        ),
        "prediction_audit_checksums_ref": ref(f"{prediction_audit}/CHECKSUMS.sha256"),
    }
    target = {
        "schema_version": TARGET_SCHEMA,
        "status": TARGET_STATUS,
        "activation_core": core,
        "activation_core_semantic_sha256": semantic_sha256(core),
        "scorer_source_refs": source_refs,
        "python_runtime": {
            "implementation": "cpython",
            "version_info": [3, 13, 7, "final", 0],
            "cache_tag": "cpython-313",
            "executable_final_path": "C:\\Python313\\python.exe",
            "executable_raw_sha256": _digest(2000, 64),
            "executable_size_bytes": 500_000,
            "executable_volume_serial_number": 17,
            "executable_file_id_128": _digest(2001, 32),
            "required_flags_in_order": ["-I", "-S", "-B", "-E"],
        },
        "prediction_chain": chain,
        "pre_score_output_relative_path": f"outputs/{PRESCORE_AUDIT_ROOT_NAME}",
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
    }
    target["target_binding_semantic_sha256"] = semantic_sha256(target)
    return target


def _parse(value: dict[str, object]) -> TargetBinding:
    raw = canonical_json_bytes(value)
    return TargetBinding.from_json_bytes(raw, expected_raw_sha256=sha256_bytes(raw))


def test_target_binding_accepts_exact_metadata_without_opening_truth() -> None:
    parsed = _parse(_target_value())
    assert len(parsed.activation_core["truth_refs"]) == 50
    assert all("/truth.csv" not in ref.relative_path for ref in parsed.open_refs())
    assert parsed.activation_core_semantic_sha256 == semantic_sha256(parsed.activation_core)


def test_target_binding_rejects_activation_core_tamper_even_with_new_outer_seal() -> None:
    value = _target_value()
    value["activation_core"]["run_id"] = "tampered"
    del value["target_binding_semantic_sha256"]
    value["target_binding_semantic_sha256"] = semantic_sha256(value)
    with pytest.raises(PreScoreAuditError, match="activation core semantic"):
        _parse(value)


def test_target_binding_rejects_pass2_truth_authority() -> None:
    value = _target_value()
    core = value["activation_core"]
    core["truth_refs"][0]["relative_path"] = str(core["truth_refs"][0]["relative_path"]).replace(
        "pass_1", "pass_2"
    )
    value["activation_core_semantic_sha256"] = semantic_sha256(core)
    del value["target_binding_semantic_sha256"]
    value["target_binding_semantic_sha256"] = semantic_sha256(value)
    with pytest.raises(PreScoreAuditError, match="pass-1"):
        _parse(value)


def test_canonical_parser_rejects_duplicate_keys_and_noncanonical_bytes() -> None:
    with pytest.raises(PreScoreAuditError, match="duplicate key"):
        read_canonical_json(b'{"a":1,"a":2}\n', label="duplicate")
    with pytest.raises(PreScoreAuditError, match="canonical bytes"):
        read_canonical_json(b'{"b": 1}\n', label="spacing")


def test_fail_closed_report_contains_no_protected_authority() -> None:
    report = _no_go_report(
        expected_target_hash=_digest(55, 64), error=RuntimeError("private detail")
    )
    assert report["status"] == "TERMINAL_NO_GO_PRE_SCORE_TARGET_BOUND"
    assert report["finding_counts"] == {"P0": 1, "P1": 0, "P2": 0}
    assert report["truth_open_count"] == 0
    assert report["score_open_count"] == 0
    assert report["heldout_open_count"] == 0
    assert "private detail" not in json.dumps(report)


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 FileId contract")
def test_output_root_fails_closed_when_identity_already_exists(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    target = outputs / PRESCORE_AUDIT_ROOT_NAME
    target.mkdir()
    with pytest.raises(PreScoreAuditError, match="absent direct public"):
        with OutputRoot(project_root=project, target=target):
            raise AssertionError("unreachable")


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 FileId contract")
def test_output_root_is_claimed_once_and_files_stay_held_until_commit(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    target = outputs / PRESCORE_AUDIT_ROOT_NAME
    with OutputRoot(project_root=project, target=target) as output:
        assert target.is_dir()
        published = output.publish(leaf="PRE_SCORE_AUDIT.json", raw=b"{}\n")
        expected = {published.path.name: published.ref_fields()}
        output.commit(expected=expected)
        assert target.is_dir()
        assert (target / "PRE_SCORE_AUDIT.json").read_bytes() == b"{}\n"
        published.close()
    with pytest.raises(PreScoreAuditError):
        with OutputRoot(project_root=project, target=target):
            raise AssertionError("unreachable")


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 held publication contract")
def test_published_final_leaf_denies_swap_and_write_until_commit(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    target = outputs / PRESCORE_AUDIT_ROOT_NAME
    with OutputRoot(project_root=project, target=target) as output:
        published = output.publish(leaf="PRE_SCORE_AUDIT.json", raw=b"held\n")
        try:
            with pytest.raises(PermissionError):
                published.path.write_bytes(b"attacker")
            with pytest.raises(PermissionError):
                os.replace(published.path, target / "ATTACKER.json")
            output.commit(expected={published.path.name: published.ref_fields()})
        finally:
            published.close()
    assert (target / "PRE_SCORE_AUDIT.json").read_bytes() == b"held\n"


def test_publication_protocol_has_no_path_create_move_or_cleanup_window() -> None:
    project = Path(__file__).resolve().parents[2]
    source = (
        project
        / "research/model_zoo/pe_five_candidate_qualification_pre_score_auditor_v1/publication.py"
    ).read_text(encoding="utf-8")
    auditor = (
        project
        / "research/model_zoo/pe_five_candidate_qualification_pre_score_auditor_v1/auditor.py"
    ).read_text(encoding="utf-8")
    target_mint = (
        project
        / "research/model_zoo/pe_five_candidate_qualification_pre_score_auditor_v1/target_mint.py"
    ).read_text(encoding="utf-8")
    assert "NtCreateFile" in source
    assert "_FILE_SHARE_READ" in source
    assert "os.rename(" not in source
    assert "os.replace(" not in source
    assert ".mkdir(" not in source
    assert ".unlink(" not in source
    assert "rmtree(" not in source
    assert auditor.index("leaf=ATTEMPT_CLAIM_LEAF") < auditor.index(
        'leaf="AUDITOR_SOURCE_MANIFEST.json"'
    )
    assert auditor.index('leaf="CHECKSUMS.sha256"') < auditor.index('leaf="AUDIT_SEAL.json"')
    assert target_mint.index("leaf=ATTEMPT_CLAIM_LEAF") < target_mint.index(
        'leaf="PRE_SCORE_TARGET_BINDING.json"'
    )
    assert target_mint.index('leaf="PRE_SCORE_TARGET_BINDING.json"') < target_mint.index(
        "leaf=TARGET_PUBLICATION_SEAL_LEAF"
    )


@pytest.mark.skipif(sys.platform != "win32", reason="Win32 held-source contract")
def test_actual_scorer_source_static_contract_is_pretruth_safe() -> None:
    project = Path(__file__).resolve().parents[2]
    refs = tuple(
        _artifact_ref_from_snapshot(project, relative) for relative in SCORER_SOURCE_RELATIVES
    )
    with HeldArtifactSet(project_root=project, refs=refs) as held:
        checks = _static_scorer_checks(
            held,
            target=SimpleNamespace(scorer_source_refs=refs),
        )
        assert checks and all(checks.values())


def test_isolated_cli_help_exposes_no_protected_path_authority() -> None:
    project = Path(__file__).resolve().parents[2]
    script = (
        project
        / "scripts/model_lab/pe_five_candidate_qualification_pre_score_auditor_v1/audit_once.py"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-E", str(script), "--help"],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout.casefold()
    assert "--target-binding" in output
    assert "--output-root" in output
    assert "--truth" not in output
    assert "--vault" not in output
    assert "--heldout" not in output
    assert "--score" not in output


def test_isolated_target_mint_help_has_one_hash_pinned_metadata_input() -> None:
    project = Path(__file__).resolve().parents[2]
    script = (
        project
        / "scripts/model_lab/pe_five_candidate_qualification_pre_score_auditor_v1/freeze_target.py"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-E", str(script), "--help"],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    output = completed.stdout.casefold()
    assert "--activation-core" in output
    assert "--activation-core-raw-sha256" in output
    assert "--output-root" in output
    assert "--truth" not in output
    assert "--vault" not in output
    assert "--heldout" not in output
    assert "--score" not in output
