from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.publisher import (
    _reacquire_commit_directory_custody,
    _release_prefix_write_custody,
)
from research.model_zoo.pe_four_model_fresh_heldout_authority_v1.contracts import (
    HeldoutAuthorityError,
)
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.secure_publication import (
    HeldDirectory,
    HeldPublishedFile,
    SecurePublicationError,
    claim_output_root,
    publish_leaf,
    reconcile_tree,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
PREFIX_RAW = {
    "PREDICTIONS.csv": b"identity,model,prediction\n1,v04,20\n",
    "SOURCE_MANIFEST.json": b'{"source":"frozen"}\n',
    "PREDICTION_MANIFEST.json": b'{"prediction":"frozen"}\n',
    "HELDOUT_PREDICTION_FREEZE_RECEIPT.json": b'{"status":"PREFIX_ONLY"}\n',
}
COMMIT_LAST_NAMES = (
    "HELDOUT_PREDICTION_FREEZE_AUDIT.json",
    "CHECKSUMS.sha256",
    "AUDIT_SEAL.json",
)

_AUDITOR_SUBPROCESS = r"""
import json
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from research.model_zoo.pe_five_model_qualification_prediction_auditor_v1.filesystem import (
    capture_identity,
    stable_read,
)

specification = json.loads(sys.argv[2])
root = Path(specification["root"])
observed_root = capture_identity(root, directory=True)
if observed_root != specification["root_identity"]:
    raise RuntimeError("root FileId changed")
observed = []
for expected in specification["files"]:
    raw, record = stable_read(root / expected["relative_path"], relative_path=expected["relative_path"])
    actual = record.payload()
    if actual != expected:
        raise RuntimeError("leaf FileId/hash/size changed")
    observed.append({"relative_path": expected["relative_path"], "bytes_read": len(raw)})
sys.stdout.write(json.dumps({"status": "PASS", "files": observed}, sort_keys=True))
"""


def _file_record(published: HeldPublishedFile) -> dict[str, object]:
    published.assert_live()
    return {
        "relative_path": published.name,
        "raw_sha256": published.raw_sha256,
        "size_bytes": published.size_bytes,
        "volume_serial_number": published.volume_serial_number,
        "file_id_128": published.file_id_128,
    }


def _run_real_auditor(
    *, root: HeldDirectory, files: tuple[HeldPublishedFile, ...]
) -> subprocess.CompletedProcess[bytes]:
    specification = {
        "root": str(root.path),
        "root_identity": root.identity_payload(),
        "files": [_file_record(published) for published in files],
    }
    return subprocess.run(
        (
            sys.executable,
            "-I",
            "-B",
            "-c",
            _AUDITOR_SUBPROCESS,
            str(PROJECT_ROOT),
            json.dumps(specification, sort_keys=True, separators=(",", ":")),
        ),
        check=False,
        capture_output=True,
        cwd=PROJECT_ROOT,
        timeout=60,
    )


def _claim_prefix(
    tmp_path: Path,
) -> tuple[HeldDirectory, HeldDirectory, list[HeldPublishedFile]]:
    outputs_path = tmp_path / "outputs"
    outputs_path.mkdir()
    outputs = HeldDirectory.open_existing(outputs_path)
    root = claim_output_root(
        path=outputs_path / "r3_handle_lifecycle",
        project_root=tmp_path,
        outputs_parent=outputs,
    )
    files = [
        publish_leaf(parent=root, final_leaf=name, raw=raw) for name, raw in PREFIX_RAW.items()
    ]
    return outputs, root, files


@pytest.mark.skipif(os.name != "nt", reason="native Win32 sharing semantics required")
def test_windows_prefix_close_reopen_subprocess_hash_fileid_and_commit_last(
    tmp_path: Path,
) -> None:
    outputs, root, files = _claim_prefix(tmp_path)
    try:
        prefix = tuple(files)
        _release_prefix_write_custody(
            outputs=outputs,
            root=root,
            prefix_files=prefix,
        )

        assert all(not published.write_capable for published in prefix)
        assert root.write_capable is False
        assert outputs.write_capable is False

        completed = _run_real_auditor(root=root, files=prefix)
        assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
        report = json.loads(completed.stdout.decode("utf-8"))
        assert report == {
            "status": "PASS",
            "files": [
                {
                    "relative_path": published.name,
                    "bytes_read": published.size_bytes,
                }
                for published in prefix
            ],
        }

        with pytest.raises(OSError):
            (root.path / "PREDICTIONS.csv").write_bytes(b"tamper\n")
        with pytest.raises(SecurePublicationError, match="lacks write custody"):
            publish_leaf(
                parent=root,
                final_leaf=COMMIT_LAST_NAMES[0],
                raw=b'{"premature":true}\n',
            )
        assert not (root.path / COMMIT_LAST_NAMES[0]).exists()

        _reacquire_commit_directory_custody(
            outputs=outputs,
            root=root,
            prefix_files=prefix,
        )
        audit_file = publish_leaf(
            parent=root,
            final_leaf=COMMIT_LAST_NAMES[0],
            raw=b'{"status":"PASS"}\n',
        )
        files.append(audit_file)
        ledger = b"".join(
            f"{published.raw_sha256}  {published.name}\n".encode("ascii") for published in files
        )
        checksums_file = publish_leaf(
            parent=root,
            final_leaf=COMMIT_LAST_NAMES[1],
            raw=ledger,
        )
        files.append(checksums_file)
        seal_file = publish_leaf(
            parent=root,
            final_leaf=COMMIT_LAST_NAMES[2],
            raw=b'{"status":"SEALED_GO"}\n',
        )
        files.append(seal_file)
        reconcile_tree(
            outputs_parent=outputs,
            output_root=root,
            files=tuple(files),
            expected_names=tuple(PREFIX_RAW) + COMMIT_LAST_NAMES,
        )
        assert tuple(sorted(path.name for path in root.path.iterdir())) == tuple(
            sorted(tuple(PREFIX_RAW) + COMMIT_LAST_NAMES)
        )
    finally:
        for published in reversed(files):
            published.close()
        root.close()
        outputs.close()


@pytest.mark.skipif(os.name != "nt", reason="native Win32 sharing semantics required")
def test_publisher_refuses_nonexact_prefix_before_any_custody_release(
    tmp_path: Path,
) -> None:
    outputs, root, files = _claim_prefix(tmp_path)
    try:
        with pytest.raises(
            HeldoutAuthorityError,
            match="prediction audit prefix custody count differs",
        ):
            _release_prefix_write_custody(
                outputs=outputs,
                root=root,
                prefix_files=tuple(files[:3]),
            )
        assert all(published.write_capable for published in files)
        assert root.write_capable is True
        assert outputs.write_capable is True
        assert not any((root.path / name).exists() for name in COMMIT_LAST_NAMES)
    finally:
        for published in reversed(files):
            published.close()
        root.close()
        outputs.close()


@pytest.mark.skipif(os.name != "nt", reason="native Win32 sharing semantics required")
def test_windows_retained_write_handle_blocks_auditor_and_publishes_no_commit(
    tmp_path: Path,
) -> None:
    outputs, root, files = _claim_prefix(tmp_path)
    try:
        retained = files[-1]
        for published in files[:-1]:
            published.release_write_custody()
        root.release_write_custody()
        outputs.release_write_custody()

        completed = _run_real_auditor(root=root, files=(retained,))
        assert completed.returncode != 0
        assert b"identity handle open failed" in completed.stderr
        assert retained.write_capable is True
        assert not any((root.path / name).exists() for name in COMMIT_LAST_NAMES)

        with pytest.raises(SecurePublicationError, match="lacks write custody"):
            publish_leaf(
                parent=root,
                final_leaf=COMMIT_LAST_NAMES[0],
                raw=b'{"must_not_publish":true}\n',
            )
        assert not any((root.path / name).exists() for name in COMMIT_LAST_NAMES)
    finally:
        for published in reversed(files):
            published.close()
        root.close()
        outputs.close()
