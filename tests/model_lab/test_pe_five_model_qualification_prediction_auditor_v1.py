from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path

import pytest

from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1 import (
    auditor as auditor_module,
)
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1 import (
    publication,
    secure_publication,
)
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.auditor import (
    AuditGeometry,
    PredictionFreezeAuditError,
    _root_records,
    audit_prediction_csvs,
)
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.canonical import (
    canonical_json_bytes,
    checksum_bytes,
    parse_checksum_bytes,
)
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.contracts import (
    AUDIT_NO_GO_STATUS,
    AUDIT_OUTPUT_FILES,
    AUDIT_SCHEMA,
    AUDIT_STATUS,
    CLAIM_SCHEMA,
    CLAIM_STATUS,
    HOFS_TASK_SURFACE_COLUMNS,
    IDENTITY_COLUMNS,
    MODEL_IDS,
    PREDICTION_COLUMNS,
    PUBLICATION_PROTOCOL,
    PUBLICATION_TERMINAL_STATUS,
    SEAL_NO_GO_STATUS,
    SEAL_STATUS,
    SPECIALIST_TAGS,
)
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.secure_publication import (
    HeldDirectory,
    PublicationLeafClaimedError,
    SecurePublicationError,
    claim_output_root,
    publish_leaf,
)


def _csv_bytes(header: tuple[str, ...], rows: list[list[str]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _number(value: float) -> str:
    return format(value, ".17g")


def _fixture_csvs() -> tuple[bytes, bytes, bytes, AuditGeometry]:
    geometry = AuditGeometry(
        seed_aliases=("qualification_seed_01",),
        dgp_ids=("A",),
        rows_per_task=2,
        first_position=504,
        final_position=505,
        fold_starts=(504,),
    )
    combined: list[list[str]] = []
    prefix: list[list[str]] = []
    surfaces: list[list[str]] = []
    for offset in range(2):
        identity = [
            "qualification_seed_01",
            "A",
            str(504 + offset),
            f"2026-01-{offset + 1:02d}",
            "TEST",
            "fold_012",
            "503",
            "504",
        ]
        raw_hofs = math.log(25.0 + offset)
        tail_guard = 0.8
        log_scale = math.log(2.0)
        surfaces.append(
            [*identity, _number(raw_hofs), _number(tail_guard), _number(log_scale)]
        )
        champion_pe = 20.0 + offset
        for ordinal, model_id in enumerate(MODEL_IDS):
            if ordinal == 4:
                log_champion = math.log(champion_pe)
                expected_log = log_champion + 0.5 * (raw_hofs - log_champion)
                row = [
                    *identity,
                    model_id,
                    str(ordinal),
                    _number(math.exp(expected_log)),
                    _number(expected_log),
                    _number(math.exp(log_scale)),
                    _number(tail_guard),
                    "NON_ROUTING_ALL_REGIMES",
                    SPECIALIST_TAGS[model_id],
                    "True",
                    "True",
                    f"sha256:{ordinal:064x}",
                    _number(tail_guard),
                    "",
                    "",
                    _number(math.exp(log_scale)),
                    _number(0.5),
                    _number(raw_hofs - log_champion),
                ]
            else:
                alpha = 0.0 if ordinal == 0 else (0.4 if ordinal == 3 else 0.2)
                uncertainty = 0.1
                raw_correction = 0.1
                pe = champion_pe if ordinal == 0 else champion_pe * math.exp(alpha * raw_correction)
                row = [
                    *identity,
                    model_id,
                    str(ordinal),
                    _number(pe),
                    _number(math.log(pe)),
                    "" if ordinal == 0 else _number(uncertainty),
                    "" if ordinal == 0 else _number(alpha),
                    "NON_ROUTING_ALL_REGIMES",
                    SPECIALIST_TAGS[model_id],
                    "True",
                    "True",
                    f"sha256:{ordinal:064x}",
                    "",
                    "",
                    "" if ordinal == 0 else _number(uncertainty),
                    "",
                    _number(alpha),
                    _number(0.0 if ordinal == 0 else raw_correction),
                ]
                prefix.append(row.copy())
            combined.append(row)
    return (
        _csv_bytes(PREDICTION_COLUMNS, combined),
        _csv_bytes(PREDICTION_COLUMNS, prefix),
        _csv_bytes(HOFS_TASK_SURFACE_COLUMNS, surfaces),
        geometry,
    )


def _rows(raw: bytes) -> tuple[list[str], list[list[str]]]:
    reader = csv.reader(io.StringIO(raw.decode("utf-8"), newline=""))
    return next(reader), list(reader)


def test_independent_row_audit_accepts_exact_prefix_formula_and_geometry() -> None:
    combined, prefix, surface, geometry = _fixture_csvs()
    report = audit_prediction_csvs(combined, prefix, surface, geometry=geometry)
    assert report["task_count"] == 1
    assert report["identity_count"] == 2
    assert report["prediction_row_count"] == 10
    assert report["prefix_field_parity_exact"] is True
    assert report["c4_formula_recomputed"] is True
    assert len(report["prediction_semantic_sha256"]) == 64


def test_prefix_field_tamper_is_fail_closed() -> None:
    combined, prefix, surface, geometry = _fixture_csvs()
    header, rows = _rows(combined)
    rows[1][header.index("specialist_tags")] = "tampered"
    with pytest.raises(PredictionFreezeAuditError, match="frozen row fields changed"):
        audit_prediction_csvs(
            _csv_bytes(tuple(header), rows), prefix, surface, geometry=geometry
        )


def test_c4_formula_tamper_is_fail_closed() -> None:
    combined, prefix, surface, geometry = _fixture_csvs()
    header, rows = _rows(combined)
    rows[4][header.index("expected_pe")] = _number(float(rows[4][header.index("expected_pe")]) + 1.0)
    with pytest.raises(PredictionFreezeAuditError, match="C4 independent formula differs"):
        audit_prediction_csvs(
            _csv_bytes(tuple(header), rows), prefix, surface, geometry=geometry
        )


def test_model_adjacency_tamper_is_fail_closed() -> None:
    combined, prefix, surface, geometry = _fixture_csvs()
    header, rows = _rows(combined)
    rows[4][header.index("model_ordinal")] = "3"
    with pytest.raises(PredictionFreezeAuditError, match="ID/ordinal adjacency differs"):
        audit_prediction_csvs(
            _csv_bytes(tuple(header), rows), prefix, surface, geometry=geometry
        )


def test_checksum_parser_rejects_noncanonical_order_and_content_tamper(tmp_path: Path) -> None:
    assert parse_checksum_bytes(checksum_bytes({"A.json": "a" * 64, "B.json": "b" * 64})) == {
        "A.json": "a" * 64,
        "B.json": "b" * 64,
    }
    root = tmp_path / "artifact"
    root.mkdir()
    artifact = canonical_json_bytes({"value": 1})
    (root / "A.json").write_bytes(artifact)
    (root / "CHECKSUMS.sha256").write_bytes(
        checksum_bytes({"A.json": hashlib.sha256(artifact).hexdigest()})
    )
    _root_records(root, ("A.json", "CHECKSUMS.sha256"))
    (root / "A.json").write_bytes(canonical_json_bytes({"value": 2}))
    with pytest.raises(PredictionFreezeAuditError, match="checksum differs"):
        _root_records(root, ("A.json", "CHECKSUMS.sha256"))


def test_publication_claims_root_emits_terminal_seal_last_and_never_reuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    source = project / "audit_source.py"
    source.write_text("SOURCE = 1\n", encoding="utf-8")
    monkeypatch.setattr(publication, "SOURCE_RELATIVES", ("audit_source.py",))
    roots = {}
    for name in ("combined", "c1_binding", "c1_predictions", "c4", "common"):
        roots[name] = outputs / name
        roots[name].mkdir()
    postgen = outputs / "postgen"
    postgen.mkdir()
    (postgen / "POSTGEN_AUDIT.json").write_bytes(canonical_json_bytes({"invalid": True}))
    (postgen / "AUDIT_SEAL.json").write_bytes(canonical_json_bytes({"invalid": True}))
    destination = outputs / "prediction_audit"
    monkeypatch.setattr(publication, "PRODUCTION_OUTPUT_ROOT_NAME", destination.name)
    committed_leaves: list[str] = []
    original_publish_leaf = publication.publish_leaf

    def recorded_publish_leaf(*, parent: HeldDirectory, final_leaf: str, raw: bytes):
        committed_leaves.append(final_leaf)
        return original_publish_leaf(parent=parent, final_leaf=final_leaf, raw=raw)

    monkeypatch.setattr(publication, "publish_leaf", recorded_publish_leaf)
    report = publication.publish_prediction_freeze_audit(
        repository_root=project,
        output_root=destination,
        combined_root=roots["combined"],
        c1_c3_binding_root=roots["c1_binding"],
        c1_c3_prediction_root=roots["c1_predictions"],
        c4_surface_root=roots["c4"],
        common_root=roots["common"],
        postgen_audit_path=postgen / "POSTGEN_AUDIT.json",
        postgen_seal_path=postgen / "AUDIT_SEAL.json",
        expected_combined_root_name="combined",
        expected_combined_checksums_raw_sha256="0" * 64,
        expected_common_checksums_raw_sha256="1" * 64,
    )
    assert report["status"] == AUDIT_NO_GO_STATUS
    assert tuple(sorted(path.name for path in destination.iterdir())) == tuple(
        sorted(AUDIT_OUTPUT_FILES)
    )
    assert committed_leaves == [
        "ATTEMPT_CLAIM.json",
        "AUDITOR_SOURCE_MANIFEST.json",
        "PREDICTION_FREEZE_AUDIT.json",
        "CHECKSUMS.sha256",
        "AUDIT_SEAL.json",
    ]
    claim = json.loads((destination / "ATTEMPT_CLAIM.json").read_text("ascii"))
    seal = json.loads((destination / "AUDIT_SEAL.json").read_text("ascii"))
    assert claim["schema_version"] == CLAIM_SCHEMA
    assert claim["status"] == CLAIM_STATUS
    assert claim["retry_allowed"] is False
    assert seal["status"] == SEAL_NO_GO_STATUS
    assert seal["authorization_commit_published_last"] is True
    assert seal["atomic_directory_publish"] is False
    assert seal["publication_protocol"] == PUBLICATION_PROTOCOL
    published = json.loads((destination / "PREDICTION_FREEZE_AUDIT.json").read_text("ascii"))
    assert published["finding_counts"]["P0"] == 1
    assert published["access"] == {
        "truth_open_count": 0,
        "score_open_count": 0,
        "heldout_open_count": 0,
        "protected_namespace_open_count": 0,
    }
    with pytest.raises(PredictionFreezeAuditError, match="exact output root claim failed"):
        publication.publish_prediction_freeze_audit(
            repository_root=project,
            output_root=destination,
            combined_root=roots["combined"],
            c1_c3_binding_root=roots["c1_binding"],
            c1_c3_prediction_root=roots["c1_predictions"],
            c4_surface_root=roots["c4"],
            common_root=roots["common"],
            postgen_audit_path=postgen / "POSTGEN_AUDIT.json",
            postgen_seal_path=postgen / "AUDIT_SEAL.json",
            expected_combined_root_name="combined",
            expected_combined_checksums_raw_sha256="0" * 64,
            expected_common_checksums_raw_sha256="1" * 64,
        )


def test_held_root_and_final_leaf_reject_directory_file_swaps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    parent = HeldDirectory.open_existing(outputs)
    root = claim_output_root(
        path=outputs / "audit_r2",
        project_root=tmp_path,
        outputs_parent=parent,
    )
    published = None
    original_write = secure_publication._write_flush

    def adversarial_write(handle: int, raw: bytes) -> None:
        with pytest.raises(PermissionError):
            os.replace(root.path, outputs / "attacker_root")
        leaf = root.path / "LEAF.json"
        with pytest.raises(PermissionError):
            os.replace(leaf, root.path / "ATTACKER.json")
        with pytest.raises(PermissionError):
            leaf.write_bytes(b"attacker")
        original_write(handle, raw)

    monkeypatch.setattr(secure_publication, "_write_flush", adversarial_write)
    try:
        published = publish_leaf(
            parent=root,
            final_leaf="LEAF.json",
            raw=b"held exact bytes\n",
        )
        published.assert_live()
    finally:
        if published is not None:
            published.close()
        root.close()
        parent.close()
    assert (outputs / "audit_r2" / "LEAF.json").read_bytes() == b"held exact bytes\n"


def test_partial_final_leaf_consumes_name_and_cannot_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outputs = tmp_path / "outputs"
    outputs.mkdir()
    parent = HeldDirectory.open_existing(outputs)
    root = claim_output_root(
        path=outputs / "partial_r2",
        project_root=tmp_path,
        outputs_parent=parent,
    )
    original_write = secure_publication._write_flush

    def partial_write(handle: int, raw: bytes) -> None:
        original_write(handle, raw[:4])
        raise SecurePublicationError("injected partial-leaf failure")

    monkeypatch.setattr(secure_publication, "_write_flush", partial_write)
    failed = None
    terminal = None
    try:
        with pytest.raises(PublicationLeafClaimedError) as caught:
            publish_leaf(parent=root, final_leaf="BROKEN.json", raw=b"complete bytes\n")
        failed = caught.value.published
        assert (root.path / "BROKEN.json").read_bytes() == b"comp"
        with pytest.raises(SecurePublicationError, match="NtCreateFile"):
            publish_leaf(parent=root, final_leaf="BROKEN.json", raw=b"retry forbidden\n")
        monkeypatch.setattr(secure_publication, "_write_flush", original_write)
        terminal = publish_leaf(
            parent=root,
            final_leaf="PUBLICATION_TERMINAL.json",
            raw=canonical_json_bytes({"status": "TERMINAL_NO_RETRY"}),
        )
        terminal.assert_live()
    finally:
        if terminal is not None:
            terminal.close()
        if failed is not None:
            failed.close()
        root.close()
        parent.close()


def test_post_claim_partial_leaf_failure_leaves_durable_terminal_and_no_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    source = project / "audit_source.py"
    source.write_text("SOURCE = 1\n", encoding="utf-8")
    monkeypatch.setattr(publication, "SOURCE_RELATIVES", ("audit_source.py",))
    roots = {}
    for name in ("combined", "c1_binding", "c1_predictions", "c4", "common"):
        roots[name] = outputs / name
        roots[name].mkdir()
    postgen = outputs / "postgen"
    postgen.mkdir()
    (postgen / "POSTGEN_AUDIT.json").write_bytes(canonical_json_bytes({"invalid": True}))
    (postgen / "AUDIT_SEAL.json").write_bytes(canonical_json_bytes({"invalid": True}))
    destination = outputs / "partial_publication_r2"
    monkeypatch.setattr(publication, "PRODUCTION_OUTPUT_ROOT_NAME", destination.name)
    original_write = secure_publication._write_flush
    write_count = 0

    def fail_second_leaf(handle: int, raw: bytes) -> None:
        nonlocal write_count
        write_count += 1
        if write_count == 2:
            original_write(handle, raw[:7])
            raise SecurePublicationError("injected source-leaf partial failure")
        original_write(handle, raw)

    monkeypatch.setattr(secure_publication, "_write_flush", fail_second_leaf)
    arguments = {
        "repository_root": project,
        "output_root": destination,
        "combined_root": roots["combined"],
        "c1_c3_binding_root": roots["c1_binding"],
        "c1_c3_prediction_root": roots["c1_predictions"],
        "c4_surface_root": roots["c4"],
        "common_root": roots["common"],
        "postgen_audit_path": postgen / "POSTGEN_AUDIT.json",
        "postgen_seal_path": postgen / "AUDIT_SEAL.json",
        "expected_combined_root_name": "combined",
        "expected_combined_checksums_raw_sha256": "0" * 64,
        "expected_common_checksums_raw_sha256": "1" * 64,
    }
    with pytest.raises(
        PredictionFreezeAuditError, match="consumed and cannot authorize or retry"
    ):
        publication.publish_prediction_freeze_audit(**arguments)
    assert (destination / "ATTEMPT_CLAIM.json").is_file()
    assert (destination / "AUDITOR_SOURCE_MANIFEST.json").read_bytes() == b'{"files'
    assert not (destination / "AUDIT_SEAL.json").exists()
    terminal = json.loads((destination / "PUBLICATION_TERMINAL.json").read_text("ascii"))
    assert terminal["status"] == PUBLICATION_TERMINAL_STATUS
    assert terminal["go_authorization_valid"] is False
    assert terminal["retry_allowed"] is False
    monkeypatch.setattr(secure_publication, "_write_flush", original_write)
    with pytest.raises(PredictionFreezeAuditError, match="exact output root claim failed"):
        publication.publish_prediction_freeze_audit(**arguments)


def test_audit_core_reuses_held_outputs_identity_without_self_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    roots = {}
    for name in ("combined", "c1_binding", "c1_predictions", "c4", "common"):
        roots[name] = outputs / name
        roots[name].mkdir()
    original_capture = auditor_module.capture_identity

    def reject_outputs_reopen(path: Path, *, directory: bool):
        if Path(path) == outputs:
            raise AssertionError("held outputs parent must not be reopened")
        return original_capture(path, directory=directory)

    monkeypatch.setattr(auditor_module, "capture_identity", reject_outputs_reopen)
    with pytest.raises(PredictionFreezeAuditError, match="expected checksum authority"):
        auditor_module.audit_prediction_freeze(
            repository_root=project,
            combined_root=roots["combined"],
            c1_c3_binding_root=roots["c1_binding"],
            c1_c3_prediction_root=roots["c1_predictions"],
            c4_surface_root=roots["c4"],
            common_root=roots["common"],
            postgen_audit_path=outputs / "postgen" / "POSTGEN_AUDIT.json",
            postgen_seal_path=outputs / "postgen" / "AUDIT_SEAL.json",
            expected_combined_root_name="combined",
            expected_combined_checksums_raw_sha256="malformed",
            expected_common_checksums_raw_sha256="1" * 64,
            outputs_parent_identity={
                "volume_serial_number": "0" * 16,
                "file_id_128": "1" * 32,
            },
        )


def test_production_geometry_go_synthetic_uses_held_parent_and_seal_last(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    outputs = project / "outputs"
    outputs.mkdir(parents=True)
    source = project / "audit_source.py"
    source.write_text("SOURCE = 1\n", encoding="utf-8")
    monkeypatch.setattr(publication, "SOURCE_RELATIVES", ("audit_source.py",))
    roots = {}
    for name in ("combined", "c1_binding", "c1_predictions", "c4", "common"):
        roots[name] = outputs / name
        roots[name].mkdir()
    destination = outputs / "production_geometry_r3"
    monkeypatch.setattr(publication, "PRODUCTION_OUTPUT_ROOT_NAME", destination.name)
    committed: list[str] = []
    original_publish = publication.publish_leaf

    def recorded_publish(*, parent: HeldDirectory, final_leaf: str, raw: bytes):
        committed.append(final_leaf)
        return original_publish(parent=parent, final_leaf=final_leaf, raw=raw)

    def synthetic_production_audit(**arguments):
        assert arguments["outputs_parent_identity"] == {
            "volume_serial_number": arguments["outputs_parent_identity"][
                "volume_serial_number"
            ],
            "file_id_128": arguments["outputs_parent_identity"]["file_id_128"],
        }
        return {
            "schema_version": AUDIT_SCHEMA,
            "status": AUDIT_STATUS,
            "verdict": AUDIT_STATUS,
            "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
            "findings": [],
            "combined_root_name": "combined",
            "combined_root_identity": {
                "volume_serial_number": "a" * 16,
                "file_id_128": "b" * 32,
            },
            "combined_checksums_raw_sha256": "0" * 64,
            "target_binding_semantic_sha256": "2" * 64,
            "prediction_raw_sha256": "3" * 64,
            "prediction_semantic_sha256": "4" * 64,
            "input_binding_raw_sha256": "5" * 64,
            "input_binding_semantic_sha256": "6" * 64,
            "qualification_task_count": 50,
            "identity_count": 64_800,
            "prediction_row_count": 324_000,
            "prediction_before_truth": True,
            "access": {
                "truth_open_count": 0,
                "score_open_count": 0,
                "heldout_open_count": 0,
                "protected_namespace_open_count": 0,
            },
        }

    monkeypatch.setattr(publication, "publish_leaf", recorded_publish)
    monkeypatch.setattr(publication, "audit_prediction_freeze", synthetic_production_audit)
    report = publication.publish_prediction_freeze_audit(
        repository_root=project,
        output_root=destination,
        combined_root=roots["combined"],
        c1_c3_binding_root=roots["c1_binding"],
        c1_c3_prediction_root=roots["c1_predictions"],
        c4_surface_root=roots["c4"],
        common_root=roots["common"],
        postgen_audit_path=outputs / "postgen" / "POSTGEN_AUDIT.json",
        postgen_seal_path=outputs / "postgen" / "AUDIT_SEAL.json",
        expected_combined_root_name="combined",
        expected_combined_checksums_raw_sha256="0" * 64,
        expected_common_checksums_raw_sha256="1" * 64,
    )
    assert (
        report["qualification_task_count"],
        report["identity_count"],
        report["prediction_row_count"],
    ) == (50, 64_800, 324_000)
    assert committed[-1] == "AUDIT_SEAL.json"
    seal = json.loads((destination / "AUDIT_SEAL.json").read_text("ascii"))
    assert seal["status"] == SEAL_STATUS
    assert seal["terminal"] is False
    assert not (destination / "PUBLICATION_TERMINAL.json").exists()


def test_secure_publication_source_has_no_path_move_delete_or_recursive_cleanup() -> None:
    source = (
        Path("research/model_zoo/pe_five_model_qualification_prediction_auditor_v1")
        / "secure_publication.py"
    ).read_text("utf-8")
    assert "NtCreateFile" in source
    assert "_FILE_SHARE_READ" in source
    assert "os.replace(" not in source
    assert "shutil" not in source
    assert "rmtree" not in source
    assert ".unlink(" not in source


def test_auditor_has_no_producer_or_truth_imports() -> None:
    package = Path(
        "research/model_zoo/pe_five_model_qualification_prediction_auditor_v1"
    )
    source = "\n".join(path.read_text("utf-8") for path in package.glob("*.py"))
    assert "from research.model_zoo.pe_five_model_fresh_qualification_combiner_v1" not in source
    assert "import research.model_zoo.pe_five_model_fresh_qualification_combiner_v1" not in source
    assert "truth_vault" not in source
    assert tuple(IDENTITY_COLUMNS) == tuple(PREDICTION_COLUMNS[: len(IDENTITY_COLUMNS)])
