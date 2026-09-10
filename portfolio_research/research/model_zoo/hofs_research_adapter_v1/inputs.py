"""Exact, allow-listed public R4 input and audited numeric-source closure."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import re
from typing import Any

from .contracts import (
    CANONICAL_INPUT_LEDGER_SHA256,
    DGPS,
    PUBLIC_CHECKSUMS_RAW_SHA256,
    PUBLIC_FREEZE_RAW_SHA256,
    PUBLIC_INPUT_ROOT,
    SEEDS,
    TASK_COUNT,
    V7_NUMERIC_SOURCE_SHA256,
    HofsResearchAdapterError,
    semantic_sha256,
)


_CANONICAL_PATTERN = re.compile(
    r"replays/pass_1/seed_(?P<seed>[0-9]+)/dgp_(?P<dgp>[A-J])/canonical150[.]csv"
)


@dataclass(frozen=True)
class TaskSpec:
    ordinal: int
    seed: int
    dgp: str
    canonical_relative_path: str
    canonical_raw_sha256: str

    def __post_init__(self) -> None:
        if type(self.ordinal) is not int or not 0 <= self.ordinal < TASK_COUNT:
            raise HofsResearchAdapterError("task ordinal drifted")
        if self.seed not in SEEDS or self.dgp not in DGPS:
            raise HofsResearchAdapterError("task identity drifted")
        expected = f"replays/pass_1/seed_{self.seed}/dgp_{self.dgp}/canonical150.csv"
        if self.canonical_relative_path != expected:
            raise HofsResearchAdapterError("task canonical path drifted")
        if not re.fullmatch(r"[0-9a-f]{64}", self.canonical_raw_sha256):
            raise HofsResearchAdapterError("task canonical hash is invalid")

    def payload(self) -> dict[str, Any]:
        return asdict(self)

    def ledger_payload(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "dgp": self.dgp,
            "relative_path": self.canonical_relative_path,
            "raw_sha256": self.canonical_raw_sha256,
        }


def project_root() -> Path:
    root = Path(__file__).resolve().parents[3]
    if not (root / "research" / "model_zoo").is_dir():
        raise HofsResearchAdapterError("project root discovery failed")
    return root


def _require_regular(path: Path, *, allowed_root: Path) -> bytes:
    resolved_root = allowed_root.resolve()
    resolved = path.resolve()
    if (
        path.is_symlink()
        or not path.is_file()
        or resolved == resolved_root
        or resolved_root not in resolved.parents
    ):
        raise HofsResearchAdapterError(f"path is not an allow-listed regular file: {path.name}")
    return path.read_bytes()


def verify_numeric_source_closure() -> dict[str, Any]:
    """Verify the exact audited V7 Python bytes before importing that package."""

    root = project_root()
    observed: dict[str, dict[str, Any]] = {}
    for relative, expected in V7_NUMERIC_SOURCE_SHA256.items():
        path = root / relative
        content = _require_regular(path, allowed_root=root)
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise HofsResearchAdapterError(f"audited V7 numeric source drifted: {relative}")
        observed[relative] = {"raw_sha256": actual, "bytes": len(content)}
    return {
        "file_count": len(observed),
        "files": observed,
        "semantic_sha256": semantic_sha256(observed),
        "status": "PASS_EXACT_AUDITED_V7_NUMERIC_SOURCE_CLOSURE",
    }


def build_public_task_plan() -> tuple[TaskSpec, ...]:
    """Build the immutable 50-task plan without opening any model payload."""

    root = project_root()
    public_root = (root / PUBLIC_INPUT_ROOT).resolve()
    if (
        public_root.is_symlink()
        or not public_root.is_dir()
        or public_root.parent != (root / "outputs").resolve()
    ):
        raise HofsResearchAdapterError("public R4 root custody drifted")

    freeze = _require_regular(public_root / "FREEZE_RECEIPT.json", allowed_root=public_root)
    checksums = _require_regular(public_root / "CHECKSUMS.sha256", allowed_root=public_root)
    if hashlib.sha256(freeze).hexdigest() != PUBLIC_FREEZE_RAW_SHA256:
        raise HofsResearchAdapterError("public R4 freeze receipt drifted")
    if hashlib.sha256(checksums).hexdigest() != PUBLIC_CHECKSUMS_RAW_SHA256:
        raise HofsResearchAdapterError("public R4 checksum ledger drifted")

    found: dict[tuple[int, str], tuple[str, str]] = {}
    for line in checksums.decode("ascii").splitlines():
        match = re.fullmatch(r"(?P<sha>[0-9a-f]{64})  (?P<path>[^\r\n]+)", line)
        if match is None:
            raise HofsResearchAdapterError("public checksum row syntax drifted")
        relative = match.group("path").replace("\\", "/")
        canonical = _CANONICAL_PATTERN.fullmatch(relative)
        if canonical is None:
            continue
        key = (int(canonical.group("seed")), canonical.group("dgp"))
        if key in found:
            raise HofsResearchAdapterError("public canonical task is duplicated")
        found[key] = (relative, match.group("sha"))

    expected_keys = [(seed, dgp) for seed in SEEDS for dgp in DGPS]
    if set(found) != set(expected_keys) or len(found) != TASK_COUNT:
        raise HofsResearchAdapterError("public canonical task universe drifted")
    tasks = tuple(
        TaskSpec(
            ordinal=ordinal,
            seed=seed,
            dgp=dgp,
            canonical_relative_path=found[(seed, dgp)][0],
            canonical_raw_sha256=found[(seed, dgp)][1],
        )
        for ordinal, (seed, dgp) in enumerate(expected_keys)
    )
    ledger = [task.ledger_payload() for task in tasks]
    if semantic_sha256(ledger) != CANONICAL_INPUT_LEDGER_SHA256:
        raise HofsResearchAdapterError("public canonical semantic ledger drifted")
    return tasks


def canonical_path(task: TaskSpec) -> Path:
    """Resolve one already-validated task to its fixed public canonical file."""

    if type(task) is not TaskSpec:
        raise HofsResearchAdapterError("canonical path requires an exact TaskSpec")
    root = project_root()
    public_root = (root / PUBLIC_INPUT_ROOT).resolve()
    path = (public_root / Path(task.canonical_relative_path)).resolve()
    if public_root not in path.parents:
        raise HofsResearchAdapterError("canonical task path escaped its public root")
    return path


def read_canonical_bytes(task: TaskSpec) -> bytes:
    """Open and hash exactly one allow-listed canonical payload."""

    root = project_root()
    public_root = (root / PUBLIC_INPUT_ROOT).resolve()
    path = canonical_path(task)
    content = _require_regular(path, allowed_root=public_root)
    if hashlib.sha256(content).hexdigest() != task.canonical_raw_sha256:
        raise HofsResearchAdapterError(f"public canonical bytes drifted: {task.ordinal}")
    return content


__all__ = [
    "TaskSpec",
    "build_public_task_plan",
    "canonical_path",
    "project_root",
    "read_canonical_bytes",
    "verify_numeric_source_closure",
]
