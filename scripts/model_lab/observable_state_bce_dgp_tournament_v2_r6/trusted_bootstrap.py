"""Hard-coded stdlib-only R6 pre-import verified-bytes bootstrap."""

from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile


PROJECT_TEXT = r"C:\Users\minsu\Documents\EPS\PE_Regime_Engine_v0.4.0_Bottleneck_Overlay"
SELF_TEXT = PROJECT_TEXT + (
    r"\scripts\model_lab\observable_state_bce_dgp_tournament_v2_r6"
    r"\trusted_bootstrap.py"
)
PACKAGE_TEXT = PROJECT_TEXT + (
    r"\research\model_zoo\observable_state_bce_dgp_tournament_v2_r6"
)
SCRIPT_DIRECTORY_TEXT = PROJECT_TEXT + (
    r"\scripts\model_lab\observable_state_bce_dgp_tournament_v2_r6"
)
PRECOMMIT_TEXT = PROJECT_TEXT + (
    r"\outputs\model_zoo_observable_state_bce_dgp_tournament_v2_"
    r"score_free_precommit_r6_20260821"
)
MANIFEST_TEXT = PRECOMMIT_TEXT + r"\EXECUTABLE_MANIFEST.json"
PINNED_LAUNCHER_TEXT = (
    r"C:\Users\minsu\Documents\EPS\.venv_pe_model_lab_py310\Scripts\python.exe"
)
PINNED_LAUNCHER_SHA256 = (
    "2de63ce9ee584123173a0c96e68b54be74f7ad17c21a343e63ac12a4790cb21d"
)
PINNED_BASE_TEXT = r"C:\Users\minsu\anaconda3\envs\myenv\python.exe"
PINNED_BASE_SHA256 = (
    "6671fe0d3220308f71ce7832cc0e48848160e4dc41b317a5c017c0f4c693ed2d"
)
RESERVATION_ACTIVATION = (
    "RESERVE_OBSERVABLE_STATE_BCE_DGP_TOURNAMENT_V2_R6_TRANSACTIONALLY_ONCE"
)
SOURCE_NAMES = {
    "__init__.py",
    "artifacts.py",
    "authority.py",
    "bootstrap_entry.py",
    "contracts.py",
    "design.py",
    "executable.py",
    "identity.py",
    "lineage.py",
    "path_guard.py",
    "precommit.py",
    "signature.py",
    "transaction.py",
}
SCRIPT_NAMES = {
    "freeze_r6_precommit.py",
    "transaction_fixture_worker.py",
    "trusted_bootstrap.py",
    "verify_r6_precommit.py",
}
REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


CHILD_CODE = r'''
import base64
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
stage = Path(os.environ["R6_STAGE_ROOT"])
manifest_path = stage / "EXECUTABLE_MANIFEST.json"
manifest_raw = manifest_path.read_bytes()
if hashlib.sha256(manifest_raw).hexdigest() != os.environ["R6_EXECUTABLE_MANIFEST_RAW_SHA256"]:
    raise RuntimeError("child manifest raw hash differs")
manifest = json.loads(manifest_raw.decode("utf-8"))
if not isinstance(manifest, dict):
    raise RuntimeError("child manifest root differs")

def walk_no_follow(root):
    files = set()
    directories = set()
    stack = [root]
    while stack:
        directory = stack.pop()
        metadata = os.lstat(directory)
        if int(getattr(metadata, "st_file_attributes", 0)) & REPARSE:
            raise RuntimeError("child stage directory is reparse")
        with os.scandir(directory) as entries:
            for entry in entries:
                item = Path(entry.path)
                meta = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or int(getattr(meta, "st_file_attributes", 0)) & REPARSE:
                    raise RuntimeError("child stage entry is reparse")
                relative = item.relative_to(root).as_posix()
                if stat.S_ISDIR(meta.st_mode):
                    directories.add(relative)
                    stack.append(item)
                elif stat.S_ISREG(meta.st_mode):
                    files.add(relative)
                else:
                    raise RuntimeError("child stage non-regular entry")
    return files, directories

expected_files = set(manifest["stage_files"]) | set(manifest["stage_control_files"])
actual_files, actual_directories = walk_no_follow(stage)
if actual_files != expected_files or actual_directories != set(manifest["stage_directories"]):
    raise RuntimeError("child pre-import stage universe differs")
bound = {}
for relative, record in manifest["stage_files"].items():
    path = stage / Path(relative.replace("/", "\\"))
    raw = path.read_bytes()
    if len(raw) != record["bytes"] or hashlib.sha256(raw).hexdigest() != record["raw_sha256"]:
        raise RuntimeError("child captured source differs: " + relative)
    bound[record["module"]] = (str(path), raw, relative.endswith("/__init__.py"))

class BoundSourceLoader(importlib.abc.Loader):
    def __init__(self, fullname, origin, raw, package):
        self.fullname = fullname
        self.origin = origin
        self.raw = raw
        self.package = package
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        code = compile(self.raw, self.origin, "exec", dont_inherit=True)
        exec(code, module.__dict__)

class BoundSourceFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        item = bound.get(fullname)
        if item is None:
            return None
        origin, raw, package = item
        loader = BoundSourceLoader(fullname, origin, raw, package)
        spec = importlib.util.spec_from_loader(fullname, loader, origin=origin, is_package=package)
        if spec is None:
            raise RuntimeError("bound module spec failed: " + fullname)
        if package:
            spec.submodule_search_locations = [str(Path(origin).parent)]
        return spec

finder = BoundSourceFinder()
sys.meta_path.insert(0, finder)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r6 import bootstrap_entry
bootstrap_entry.main(manifest)
'''


def _canonical(payload: object) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _raw_segments(text: str) -> tuple[str, ...]:
    if (
        not text
        or "/" in text
        or not (len(text) >= 3 and text[0].isupper() and text[1:3] == ":\\")
        or text.startswith(("\\\\", "\\?\\", "\\.\\"))
        or ":" in text[2:]
    ):
        raise RuntimeError("bootstrap raw path spelling differs")
    segments = tuple(text[3:].split("\\")) if len(text) > 3 else ()
    for segment in segments:
        if (
            segment in {"", ".", ".."}
            or segment.endswith((".", " "))
            or "~" in segment
        ):
            raise RuntimeError("bootstrap raw path segment differs")
    return segments


def _components(text: str) -> list[Path]:
    current = Path(text[:3])
    result = [current]
    for segment in _raw_segments(text):
        current /= segment
        result.append(current)
    return result


def _final_path(path: Path, *, directory: bool) -> str:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel32.CreateFileW
    create.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create.restype = wintypes.HANDLE
    final = kernel32.GetFinalPathNameByHandleW
    final.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    final.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    flags = 0x00200000 | (0x02000000 if directory else 0)
    handle = create(str(path), 0, 7, None, 3, flags, None)
    if handle == wintypes.HANDLE(-1).value:
        raise RuntimeError(f"bootstrap CreateFileW failed: {ctypes.get_last_error()}")
    try:
        needed = final(handle, None, 0, 0)
        buffer = ctypes.create_unicode_buffer(needed + 1)
        if not final(handle, buffer, len(buffer), 0):
            raise RuntimeError("bootstrap final path query failed")
        value = buffer.value
    finally:
        kernel32.CloseHandle(handle)
    return value[4:] if value.startswith("\\\\?\\") else value


def _exact_existing(text: str, expected: str, *, directory: bool) -> Path:
    _raw_segments(text)
    _raw_segments(expected)
    if text != expected:
        raise RuntimeError("bootstrap path is not the hard-coded exact spelling")
    path = Path(text)
    for component in _components(text):
        metadata = os.lstat(component)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or int(getattr(metadata, "st_file_attributes", 0)) & REPARSE
        ):
            raise RuntimeError(f"bootstrap reparse component: {component}")
    metadata = os.lstat(path)
    if directory != stat.S_ISDIR(metadata.st_mode):
        raise RuntimeError("bootstrap fixed path type differs")
    if _final_path(path, directory=directory) != expected:
        raise RuntimeError("bootstrap handle final path differs")
    return path


def _direct_tree(root: Path, expected: set[str]) -> None:
    observed: set[str] = set()
    with os.scandir(root) as entries:
        for entry in entries:
            metadata = entry.stat(follow_symlinks=False)
            if (
                entry.is_symlink()
                or int(getattr(metadata, "st_file_attributes", 0)) & REPARSE
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise RuntimeError(f"bootstrap live tree non-regular entry: {entry.name}")
            observed.add(entry.name)
    if observed != expected:
        raise RuntimeError(f"bootstrap live exact tree differs: {sorted(observed ^ expected)}")


def _load_manifest() -> tuple[dict[str, object], bytes]:
    if sys.argv[0] != SELF_TEXT or str(Path(__file__)) != SELF_TEXT:
        raise RuntimeError("bootstrap must be invoked by its exact absolute path")
    _exact_existing(PROJECT_TEXT, PROJECT_TEXT, directory=True)
    self_path = _exact_existing(SELF_TEXT, SELF_TEXT, directory=False)
    package = _exact_existing(PACKAGE_TEXT, PACKAGE_TEXT, directory=True)
    scripts = _exact_existing(SCRIPT_DIRECTORY_TEXT, SCRIPT_DIRECTORY_TEXT, directory=True)
    manifest_path = _exact_existing(MANIFEST_TEXT, MANIFEST_TEXT, directory=False)
    launcher = _exact_existing(PINNED_LAUNCHER_TEXT, PINNED_LAUNCHER_TEXT, directory=False)
    base = _exact_existing(PINNED_BASE_TEXT, PINNED_BASE_TEXT, directory=False)
    _direct_tree(package, SOURCE_NAMES)
    _direct_tree(scripts, SCRIPT_NAMES)
    if (
        sys.version.split()[0] != "3.10.19"
        or str(Path(sys.executable)) != PINNED_LAUNCHER_TEXT
        or str(Path(sys._base_executable)) != PINNED_BASE_TEXT
        or _hash(launcher) != PINNED_LAUNCHER_SHA256
        or _hash(base) != PINNED_BASE_SHA256
    ):
        raise RuntimeError("bootstrap pinned interpreter differs")
    raw = manifest_path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or raw != _canonical(payload):
        raise RuntimeError("executable manifest is not canonical")
    claimed = payload.get("executable_manifest_semantic_sha256")
    unsigned = dict(payload)
    unsigned.pop("executable_manifest_semantic_sha256", None)
    if hashlib.sha256(_canonical(unsigned).rstrip(b"\n")).hexdigest() != claimed:
        raise RuntimeError("executable manifest self seal differs")
    relative_self = self_path.relative_to(Path(PROJECT_TEXT)).as_posix()
    outer = payload.get("outer_bootstrap_files", {})
    if (
        set(Path(relative).name for relative in outer) != SCRIPT_NAMES
        or relative_self not in outer
        or _hash(self_path) != outer[relative_self]["raw_sha256"]
    ):
        raise RuntimeError("outer bootstrap/script universe is not manifest-bound")
    expected_stage_sources = {
        f"research/model_zoo/observable_state_bce_dgp_tournament_v2_r6/{name}"
        for name in SOURCE_NAMES
    } | {"research/__init__.py", "research/model_zoo/__init__.py"}
    if set(payload.get("stage_files", {})) != expected_stage_sources:
        raise RuntimeError("hard-coded stage source universe differs")
    return payload, raw


def _walk_stage(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    stack = [root]
    while stack:
        directory = stack.pop()
        metadata = os.lstat(directory)
        if int(getattr(metadata, "st_file_attributes", 0)) & REPARSE:
            raise RuntimeError("stage directory is a reparse point")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                item = entry.stat(follow_symlinks=False)
                if entry.is_symlink() or int(getattr(item, "st_file_attributes", 0)) & REPARSE:
                    raise RuntimeError("stage entry is a reparse point")
                relative = path.relative_to(root).as_posix()
                if stat.S_ISDIR(item.st_mode):
                    directories.add(relative)
                    stack.append(path)
                elif stat.S_ISREG(item.st_mode):
                    files.add(relative)
                else:
                    raise RuntimeError("stage entry is not regular")
    return files, directories


def _stage(manifest: dict[str, object], manifest_raw: bytes, root: Path) -> None:
    records = manifest["stage_files"]
    captured: dict[str, bytes] = {}
    for relative, record in records.items():
        if record["kind"] == "BOUND_SOURCE_COPY":
            source_text = PROJECT_TEXT + "\\" + record["source_relative_path"].replace("/", "\\")
            source = _exact_existing(source_text, source_text, directory=False)
            raw = source.read_bytes()
        else:
            raw = base64.b64decode(record["base64"], validate=True)
        if len(raw) != record["bytes"] or hashlib.sha256(raw).hexdigest() != record["raw_sha256"]:
            raise RuntimeError(f"bound source differs: {relative}")
        captured[relative] = raw
    for relative, raw in captured.items():
        target = root / Path(relative.replace("/", "\\"))
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    manifest_target = root / "EXECUTABLE_MANIFEST.json"
    with manifest_target.open("xb") as stream:
        stream.write(manifest_raw)
        stream.flush()
        os.fsync(stream.fileno())
    actual_files, actual_dirs = _walk_stage(root)
    expected_files = set(records) | {"EXECUTABLE_MANIFEST.json"}
    if actual_files != expected_files or actual_dirs != set(manifest["stage_directories"]):
        raise RuntimeError("stage exact file/directory universe differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=(
            "attest_import_only",
            "verify_precommit",
            "verify_authority_context",
            "reserve_authenticated",
        ),
    )
    args = parser.parse_args()
    manifest, manifest_raw = _load_manifest()
    with tempfile.TemporaryDirectory(prefix="r6_source_only_") as temporary:
        stage = Path(temporary)
        _exact_existing(str(stage), str(stage), directory=True)
        _stage(manifest, manifest_raw, stage)
        parent_environment = os.environ
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "R6_BOOTSTRAP_COMMAND": args.command,
            "R6_BOOTSTRAP_PARENT_NONCE": secrets.token_hex(32),
            "R6_EXECUTABLE_MANIFEST_RAW_SHA256": hashlib.sha256(manifest_raw).hexdigest(),
            "R6_STAGE_ROOT": str(stage),
            "SYSTEMROOT": parent_environment["SYSTEMROOT"],
            "TEMP": parent_environment["TEMP"],
            "TMP": parent_environment["TMP"],
            "WINDIR": parent_environment["WINDIR"],
        }
        if args.command == "reserve_authenticated":
            environment["R6_RESERVATION_ACTIVATION"] = RESERVATION_ACTIVATION
        completed = subprocess.run(
            [PINNED_LAUNCHER_TEXT, "-I", "-S", "-B", "-E", "-c", CHILD_CODE],
            cwd=stage,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr[-12000:])
        print(completed.stdout.strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
