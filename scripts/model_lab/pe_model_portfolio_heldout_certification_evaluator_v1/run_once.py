"""Externally anchored, source-pinned heldout certification CLI."""

# ruff: noqa: E402

from __future__ import annotations

import sys


if (
    sys.flags.isolated != 1
    or sys.flags.no_site != 1
    or sys.flags.ignore_environment != 1
    or not sys.dont_write_bytecode
):
    raise SystemExit("heldout evaluator requires exact python -I -S -B -E invocation")
_EXTERNAL_SHA = globals().get("_HELDOUT_VERIFIED_LAUNCHER_RAW_SHA256")
_EXTERNAL_HANDLE = globals().get("_HELDOUT_VERIFIED_LAUNCHER_HANDLE")
if (
    type(_EXTERNAL_SHA) is not str
    or len(_EXTERNAL_SHA) != 64
    or any(character not in "0123456789abcdef" for character in _EXTERNAL_SHA)
    or type(_EXTERNAL_HANDLE) is not int
    or _EXTERNAL_HANDLE <= 0
):
    raise SystemExit("heldout evaluator requires external held-byte launcher trust anchor")

import argparse
import base64
import ctypes
from ctypes import wintypes
import csv
import hashlib
import io
import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
PINNED_PYTHON = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_PYTHON_RAW_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
PINNED_PYTHON_SIZE_BYTES = 272_712
PINNED_PYTHON_VOLUME_SERIAL_NUMBER = 13_325_047_249_941_796_650
PINNED_PYTHON_FILE_ID_128 = "b70b1400000006000000000000000000"
PINNED_NUMPY_VERSION = "1.26.4"
PINNED_NUMPY_INIT = Path(
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Lib\site-packages\numpy\__init__.py"
)
PINNED_NUMPY_INIT_RAW_SHA256 = (
    "150b19558caf78c0e3cc6994ec652399e972595ca649cea1a69c801ef23e4b1c"
)
PINNED_NUMPY_INIT_SIZE_BYTES = 17_798
PINNED_SITE_PACKAGES = PINNED_NUMPY_INIT.parents[1]
PINNED_NUMPY_RECORD = (
    PINNED_SITE_PACKAGES / "numpy-1.26.4.dist-info" / "RECORD"
)
PINNED_NUMPY_RECORD_RAW_SHA256 = (
    "2d9f5542a92273f964a057bac6668547c7125fa616eef7a71b23f2e791d7b98f"
)
PINNED_NUMPY_RECORD_SIZE_BYTES = 117_202
PINNED_NUMPY_RECORD_ROW_COUNT = 1_426
PINNED_NUMPY_RECORD_HASHED_MEMBER_COUNT = 935
PINNED_VENV_ROOT = PINNED_PYTHON.parents[1]

# Recomputed only after evaluator source freeze.  The external anchor freezes this launcher's
# own raw SHA; this map freezes every repository source imported by the scoring process.
PINNED_SOURCE_SHA256: dict[str, str] = {
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/__init__.py": "a80deea74e49a8c162ec92efe399e1f5b6c10b668ecd3131fffea5ec3bfc0c8b",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/__main__.py": "7584ac12b89a27355cced834d431ea674eae4874f4f4b17b0840c0ceb229d3ec",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/audit.py": "39596e6353057e60f0079f4b869cf22961689252890b208485ca0deed51de9fe",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/canonical.py": "e551fddf2092f7d75c380802e47d82f613e3d9df10d3a71ed8a09f7e78457f84",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/constants.py": "1448cbca25991b4c51a4fbd7a84dd3a39e38d5364af9bc3b40e620c5528d508e",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/contracts.py": "fb7f1e255ffb4325a31ad410c0d2ab8ff9af8f0fbdb75b0b9942be8b43dbd566",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/metrics.py": "4a0684e1b372b65ab17ca71a029042e3524c4dd9dbf5b0d3fab64060c60be9d5",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/prediction.py": "9652bd70e1ddc167fdf2c7093470c8d52b2ae465c6842e59ef0b99bd8889cd32",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/publication.py": "7c72993f1f765c24b9ce9c6b1433784378fb2bd51db802a30cd40b1fd7c1a357",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/runner.py": "92653e42f7acb0090ae2a64f086a2e0202c72f50d07609cc4419192395935041",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_r8_r14_v1/truth.py": "512205b8b26da7f249593c7a85cdde59172ca6193af5dae79cf47a15b7df6510",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/__init__.py": "227e8bad516f08315e8fb164f571133c4a00b06dba8e9d279301b11247f42a9e",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/contract.py": "62131354aab94e1145572570c0ee99a9da7f1fad10d334c7c345e6f692eaf379",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v1/evaluator.py": "49e0d24fc87a9d1f2cc1d7026570252f768994927b8f023b1570075cee6bae26",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/__init__.py": "0538e6eeaf80134cb1d416e5799b23e774a9d36e46190c1bf2cf1905c8805153",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/__main__.py": "5739e769e467ae5ea7932f4dbb89abad4b86bf39a7e728e87fc38deef12c2c70",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/canonical.py": "09de1cc5384f4f2072f8dbd7d7dffe52e49966430f356dde655632495661e021",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/constants.py": "b8f10cf9b5f89260ed6c79cae84d080569081f43bee09965fec0298d9ceba77d",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/contracts.py": "bfd383542f706edd4efc4136c2afe7e4bab44b2aea70b1876d73aa0251ea2bfb",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/custody.py": "dae048d7e02789d421981faae021c36a8af6d17230d7bad7de8168b8b7df001c",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/metric_core.py": "beac82ac61a3dcbd85131e16a3868d0e5ddbe8675872266f4fee5a7dbd88ed0d",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/one_shot.py": "d5c71a7f4e2b3cbc24910ca8dd5eb52295038eeee6f9d09daa2e929268b98368",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/prediction.py": "a1ab62dc11a9a0083bcc135dd2742442aae225d8a97f3c25a88718070c9d1ccb",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/publication.py": "1bf5b8fa6ffcc43bfbcbfe01619144af193463e58c58d4c0ab4cc86171facca7",
    "research/model_zoo/pe_five_candidate_fresh_qualification_evaluator_v2/scorecard.py": "46cf5a192fe4c81d221e58ab4906e336939e3908458386873c9985f26dd92534",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/__init__.py": "ce872db508ffd29acf0e570d367c1e1c8261b1f061dae5bae57d828cc7e70fbb",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/audit.py": "9db517b83937b655b91ccda6f73ccee80fdab8ceae85977b5e41aa6fb1074d38",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/canonical.py": "6ef480ba279794c1d4a6cdb164d135ee79fac83d7f2e63cb6fb77180be1d0a37",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/constants.py": "414e3098f6c26bb532dd3485220d669c883ff32d8dc9791594c52f239e6dcaed",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/contracts.py": "7dac4d918793697f27b346482db8585af96fb57903b93e243c60e12dca0c46ea",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/custody.py": "ee616bd15c508a6c133fd098eeb820806a242b2f2a39a7ac1737e0b1343fe24e",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/metrics.py": "3e3b9f134c9fcdb1545a6e570d9b9c6ee9b3ed53548ed63ec2e9807b87aaf06d",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/prediction.py": "fca6e87d7544a58680851bf2b635ca70c3bc8340d303a46f6cc91458f2a042d1",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/runner.py": "3371afa3d2cd21644a0612a1f660e8f67604462848a7b2a3bcb7082a9f61ebe1",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/source_lock.py": "cdde787d7c37e4fddcbf464fcbdb35707808ec7384c06f9434ad9808712b0e0e",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/truth.py": "6274c57feab352c5fd46f4e93404b252b2c9d6e054eccef1214504883d1cad92",
    "research/model_zoo/pe_model_portfolio_heldout_certification_evaluator_v1/vault.py": "7eb428ba61e9962b5de5d738beeb082afdf614a19ca5368814d79c06a94fa2aa",
}

_GENERIC_READ = 0x80000000
_FILE_READ_ATTRIBUTES = 0x0080
_SYNCHRONIZE = 0x00100000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_ID_INFO_CLASS = 18
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FileId128(ctypes.Structure):
    _fields_ = (("identifier", ctypes.c_ubyte * 16),)


class _FileIdInfo(ctypes.Structure):
    _fields_ = (
        ("volume_serial_number", ctypes.c_ulonglong),
        ("file_id", _FileId128),
    )


class _FileAttributeTagInfo(ctypes.Structure):
    _fields_ = (
        ("file_attributes", wintypes.DWORD),
        ("reparse_tag", wintypes.DWORD),
    )


def _kernel32() -> ctypes.WinDLL:
    library = ctypes.WinDLL("kernel32", use_last_error=True)
    library.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    library.CreateFileW.restype = wintypes.HANDLE
    library.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    library.GetFileInformationByHandleEx.restype = wintypes.BOOL
    library.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    library.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    library.CloseHandle.argtypes = (wintypes.HANDLE,)
    library.CloseHandle.restype = wintypes.BOOL
    return library


def _path_key(value: str | Path) -> str:
    result = os.path.normcase(os.path.abspath(os.fspath(value)))
    if result.startswith("\\\\?\\"):
        result = result[4:]
    return result


def _identity(handle: int) -> tuple[int, str]:
    information = _FileIdInfo()
    if not _kernel32().GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ID_INFO_CLASS,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        raise SystemExit(f"source identity query failed: {ctypes.get_last_error()}")
    return (
        int(information.volume_serial_number),
        bytes(information.file_id.identifier).hex(),
    )


def _final_path(handle: int) -> str:
    size = _kernel32().GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), None, 0, 0
    )
    if size <= 0:
        raise SystemExit(f"source final-path query failed: {ctypes.get_last_error()}")
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = _kernel32().GetFinalPathNameByHandleW(
        wintypes.HANDLE(handle), buffer, len(buffer), 0
    )
    if written <= 0 or written >= len(buffer):
        raise SystemExit(f"source final-path read failed: {ctypes.get_last_error()}")
    return buffer.value


def _hold_exact(path: Path, *, expected_sha256: str, expected_size: int) -> tuple[int, bytes]:
    absolute = Path(os.path.abspath(path))
    handle = _kernel32().CreateFileW(
        str(absolute),
        _GENERIC_READ | _FILE_READ_ATTRIBUTES | _SYNCHRONIZE,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    numeric = int(handle or 0)
    if numeric in (0, _INVALID_HANDLE_VALUE):
        raise SystemExit(f"source held-open failed: {absolute}: {ctypes.get_last_error()}")
    try:
        tag = _FileAttributeTagInfo()
        if not _kernel32().GetFileInformationByHandleEx(
            wintypes.HANDLE(numeric),
            _FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(tag),
            ctypes.sizeof(tag),
        ):
            raise SystemExit(f"source attribute query failed: {absolute}")
        if (
            tag.file_attributes & _FILE_ATTRIBUTE_DIRECTORY
            or tag.file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or tag.reparse_tag != 0
            or _path_key(_final_path(numeric)) != _path_key(absolute)
        ):
            raise SystemExit(f"source path/kind differs: {absolute}")
        # The restrictive handle already denies write/delete/rename, so this path read is pinned
        # to the same name/inode for the remainder of the process.
        raw = absolute.read_bytes()
        if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise SystemExit(f"source raw identity differs: {absolute}")
        return numeric, raw
    except BaseException:
        _kernel32().CloseHandle(wintypes.HANDLE(numeric))
        raise


def _close(handles: list[int]) -> None:
    failure = False
    for handle in reversed(handles):
        if not _kernel32().CloseHandle(wintypes.HANDLE(handle)):
            failure = True
    handles.clear()
    if failure:
        raise SystemExit("held source cleanup failed")


def _record_digest_hex(value: str) -> str:
    if not value.startswith("sha256="):
        raise SystemExit("NumPy RECORD digest algorithm differs")
    encoded = value.removeprefix("sha256=")
    try:
        decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, TypeError) as exc:
        raise SystemExit("NumPy RECORD digest encoding differs") from exc
    if len(decoded) != 32:
        raise SystemExit("NumPy RECORD digest width differs")
    return decoded.hex()


def _hold_numpy_distribution() -> list[int]:
    """Hold every RECORD-hashed NumPy 1.26.4 member before importing NumPy."""

    handles: list[int] = []
    try:
        record_handle, record_raw = _hold_exact(
            PINNED_NUMPY_RECORD,
            expected_sha256=PINNED_NUMPY_RECORD_RAW_SHA256,
            expected_size=PINNED_NUMPY_RECORD_SIZE_BYTES,
        )
        handles.append(record_handle)
        try:
            rows = list(csv.reader(io.StringIO(record_raw.decode("utf-8"), newline="")))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise SystemExit("NumPy RECORD bytes differ") from exc
        if len(rows) != PINNED_NUMPY_RECORD_ROW_COUNT or any(
            len(row) != 3 for row in rows
        ):
            raise SystemExit("NumPy RECORD row geometry differs")
        seen: set[str] = set()
        hashed_count = 0
        init_bound = False
        record_relative = "numpy-1.26.4.dist-info/RECORD"
        for relative, encoded_digest, encoded_size in rows:
            if not relative or "\\" in relative:
                raise SystemExit("NumPy RECORD member path differs")
            # The caller supplies a new absent pycache prefix and ``-B``.  No package-local
            # pyc is importable; RECORD-listed pyc files are installation residue, and one
            # such row is hashed but legitimately drifts whenever that residue is regenerated.
            if relative.endswith(".pyc"):
                continue
            if not encoded_digest:
                if encoded_size or relative != record_relative:
                    raise SystemExit("NumPy RECORD unhashed member differs")
                continue
            try:
                size = int(encoded_size)
            except ValueError as exc:
                raise SystemExit("NumPy RECORD member size differs") from exc
            if str(size) != encoded_size or size < 0:
                raise SystemExit("NumPy RECORD member size differs")
            digest = _record_digest_hex(encoded_digest)
            path = (PINNED_SITE_PACKAGES / relative).resolve(strict=True)
            if path != PINNED_VENV_ROOT and PINNED_VENV_ROOT not in path.parents:
                raise SystemExit("NumPy RECORD member escaped pinned venv")
            key = _path_key(path)
            if key in seen or path == PINNED_NUMPY_RECORD:
                raise SystemExit("NumPy RECORD member duplicate differs")
            seen.add(key)
            member_handle, _ = _hold_exact(
                path,
                expected_sha256=digest,
                expected_size=size,
            )
            handles.append(member_handle)
            hashed_count += 1
            if path == PINNED_NUMPY_INIT:
                if (
                    digest != PINNED_NUMPY_INIT_RAW_SHA256
                    or size != PINNED_NUMPY_INIT_SIZE_BYTES
                ):
                    raise SystemExit("NumPy init differs from pinned RECORD")
                init_bound = True
        if (
            hashed_count != PINNED_NUMPY_RECORD_HASHED_MEMBER_COUNT
            or not init_bound
        ):
            raise SystemExit("NumPy RECORD hashed closure differs")
        return handles
    except BaseException:
        _close(handles)
        raise


def _bootstrap_source_custody() -> list[int]:
    if not PINNED_SOURCE_SHA256:
        raise SystemExit("heldout evaluator source closure is not frozen")
    prefix = sys.pycache_prefix
    if (
        type(prefix) is not str
        or not os.path.isabs(prefix)
        or Path(prefix).exists()
        or "heldout_eval_pycache_absent_" not in Path(prefix).name
    ):
        raise SystemExit("heldout evaluator requires one new absent pycache prefix")
    handles: list[int] = []
    try:
        executable_handle, _ = _hold_exact(
            PINNED_PYTHON,
            expected_sha256=PINNED_PYTHON_RAW_SHA256,
            expected_size=PINNED_PYTHON_SIZE_BYTES,
        )
        handles.append(executable_handle)
        if _path_key(sys.executable) != _path_key(PINNED_PYTHON) or _identity(
            executable_handle
        ) != (PINNED_PYTHON_VOLUME_SERIAL_NUMBER, PINNED_PYTHON_FILE_ID_128):
            raise SystemExit("heldout evaluator Python executable identity differs")
        handles.extend(_hold_numpy_distribution())
        for relative, expected_hash in PINNED_SOURCE_SHA256.items():
            path = PROJECT_ROOT / relative
            handle, _ = _hold_exact(
                path,
                expected_sha256=expected_hash,
                expected_size=path.stat().st_size,
            )
            handles.append(handle)
        if Path(prefix).exists():
            raise SystemExit("heldout evaluator pycache prefix appeared before imports")
        return handles
    except BaseException:
        _close(handles)
        raise


def main() -> int:
    held = _bootstrap_source_custody()
    try:
        sys.path.insert(0, str(PROJECT_ROOT))
        sys.path.append(str(PINNED_SITE_PACKAGES))
        import numpy

        if numpy.__version__ != PINNED_NUMPY_VERSION or _path_key(
            numpy.__file__
        ) != _path_key(PINNED_NUMPY_INIT):
            raise SystemExit("heldout evaluator NumPy runtime differs")
        from research.model_zoo.pe_model_portfolio_heldout_certification_evaluator_v1.runner import (
            run_once,
        )

        parser = argparse.ArgumentParser(
            description="One-shot four-model heldout portfolio certification evaluator"
        )
        parser.add_argument("--repository-root", type=Path, required=True)
        parser.add_argument("--activation", type=Path, required=True)
        parser.add_argument("--activation-raw-sha256", required=True)
        arguments = parser.parse_args()
        output = run_once(
            project_root=arguments.repository_root,
            activation_path=arguments.activation,
            expected_activation_raw_sha256=arguments.activation_raw_sha256,
        )
        print(output)
        return 0
    finally:
        _close(held)


if __name__ == "__main__":
    raise SystemExit(main())
