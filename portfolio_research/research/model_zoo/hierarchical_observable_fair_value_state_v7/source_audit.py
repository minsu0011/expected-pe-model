"""Static source-isolation and pinned-closure audit for H-OFS V7."""

from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path

from .contracts import (
    PARENT_RUNTIME_SOURCE_SHA256,
    V6_DESIGN_FREEZE_BINDING,
    V6_INDEPENDENT_AUDIT_BINDING,
    canonical_json_bytes,
)
from .validation import (
    require_exact_int,
    require_exact_str,
    require_exact_tuple,
    require_sha256,
)


DECLARED_SOURCE_PATHS = (
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/__init__.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/adapter.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/artifacts.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/contracts.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/custody.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/dgp_r4.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/estimator.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/features.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/runner.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/runtime.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/source_audit.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/validation.py",
    "research/model_zoo/hierarchical_observable_fair_value_state_v7/DESIGN.md",
    "scripts/model_lab/hierarchical_observable_fair_value_state_v7/freeze_design.py",
    "scripts/model_lab/hierarchical_observable_fair_value_state_v7/inference_launcher.py",
    "scripts/model_lab/hierarchical_observable_fair_value_state_v7/prediction_launcher.py",
    "tests/model_lab/test_hierarchical_observable_fair_value_state_v7.py",
)
_FROZEN_PREDICTION_PREFIX = "research.model_zoo.observable_state_bce_dgp_tournament"
_INCOMPLETE_PARTIAL_PREFIX = "research.model_zoo.hofs_v4_dgp_r4_prediction_lane_v1"
_FORBIDDEN_IMPORT_FRAGMENTS = (
    _FROZEN_PREDICTION_PREFIX,
    _INCOMPLETE_PARTIAL_PREFIX,
    "research.model_zoo.registry",
    "research.model_zoo.evaluator",
)
_FORBIDDEN_CALL_NAMES = frozenset(
    {
        "evaluate",
        "evaluate_predictions",
        "score",
        "score_predictions",
        "register",
        "register_candidate",
        "promote",
        "set_champion",
    }
)
_OBSOLETE_SINGLE_DATE_TOKENS = (
    "_".join(("frozen", "for", "decision", "date")),
    "_".join(("decision", "session", "v7")),
    "_".join(("decision", "membership", "sha256")),
)
_IO_METHODS = frozenset(
    {
        "open",
        "read_bytes",
        "read_text",
        "write_bytes",
        "write_text",
        "iterdir",
        "glob",
        "rglob",
    }
)
_ALLOWED_IO_FILES = frozenset(
    {
        "artifacts.py",
        "contracts.py",
        "dgp_r4.py",
        "estimator.py",
        "runtime.py",
        "source_audit.py",
        "freeze_design.py",
        "inference_launcher.py",
        "prediction_launcher.py",
        "test_hierarchical_observable_fair_value_state_v7.py",
    }
)


@dataclass(frozen=True)
class SourceAuditResultV7:
    status: str
    source_sha256: tuple[tuple[str, str], ...]
    parent_runtime_sha256: tuple[tuple[str, str], ...]
    v6_audit_raw_sha256: str
    v6_audit_semantic_sha256: str
    v6_audit_manifest_raw_sha256: str
    v6_audit_seal_raw_sha256: str
    v6_audit_checksums_raw_sha256: str
    v6_design_checksums_raw_sha256: str
    v6_design_source_closure_raw_sha256: str
    forbidden_import_hits: tuple[str, ...]
    frozen_prediction_import_hits: tuple[str, ...]
    obsolete_single_date_field_hits: tuple[str, ...]
    forbidden_call_hits: tuple[str, ...]
    unexpected_runtime_io_hits: tuple[str, ...]
    allowed_runtime_io_hits: tuple[str, ...]
    protected_payload_open_count: int
    frozen_prediction_open_count: int
    score_call_count: int
    registry_mutation_count: int

    def __post_init__(self) -> None:
        require_exact_str(self.status, label="source audit status")
        for label, values in (
            ("source hashes", self.source_sha256),
            ("parent hashes", self.parent_runtime_sha256),
        ):
            rows = require_exact_tuple(values, label=f"source audit {label}")
            seen: set[str] = set()
            for position, row in enumerate(rows):
                pair = require_exact_tuple(row, label=f"source audit {label}[{position}]", length=2)
                path = require_exact_str(pair[0], label=f"source audit {label}[{position}].path")
                require_sha256(pair[1], label=f"source audit {label}[{position}].sha256")
                if path in seen:
                    raise RuntimeError(f"source audit {label} path is duplicated")
                seen.add(path)
        if tuple(path for path, _ in self.source_sha256) != DECLARED_SOURCE_PATHS:
            raise RuntimeError("source audit declared-source receipt drifted")
        if dict(self.parent_runtime_sha256) != dict(sorted(PARENT_RUNTIME_SOURCE_SHA256.items())):
            raise RuntimeError("source audit parent-runtime receipt drifted")
        pinned = (
            (self.v6_audit_raw_sha256, "raw_sha256"),
            (self.v6_audit_semantic_sha256, "semantic_sha256"),
            (self.v6_audit_manifest_raw_sha256, "manifest_raw_sha256"),
            (self.v6_audit_seal_raw_sha256, "seal_raw_sha256"),
            (self.v6_audit_checksums_raw_sha256, "checksums_raw_sha256"),
        )
        for value, key in pinned:
            require_sha256(value, label=f"source audit V6 {key}")
            if value != V6_INDEPENDENT_AUDIT_BINDING[key]:
                raise RuntimeError(f"source audit V6 {key} drifted")
        require_sha256(
            self.v6_design_checksums_raw_sha256,
            label="source audit V6 design checksums",
        )
        require_sha256(
            self.v6_design_source_closure_raw_sha256,
            label="source audit V6 design source closure",
        )
        if (
            self.v6_design_checksums_raw_sha256 != V6_DESIGN_FREEZE_BINDING["checksums_raw_sha256"]
            or self.v6_design_source_closure_raw_sha256
            != V6_DESIGN_FREEZE_BINDING["source_closure_raw_sha256"]
        ):
            raise RuntimeError("source audit V6 design/source closure drifted")
        for label, values in (
            ("forbidden imports", self.forbidden_import_hits),
            ("frozen imports", self.frozen_prediction_import_hits),
            ("obsolete single-date fields", self.obsolete_single_date_field_hits),
            ("forbidden calls", self.forbidden_call_hits),
            ("unexpected I/O", self.unexpected_runtime_io_hits),
            ("allowed I/O", self.allowed_runtime_io_hits),
        ):
            items = require_exact_tuple(values, label=f"source audit {label}")
            if any(type(item) is not str or not item for item in items):
                raise RuntimeError(f"source audit {label} values drifted")
        for label, count in (
            ("protected payload opens", self.protected_payload_open_count),
            ("frozen prediction opens", self.frozen_prediction_open_count),
            ("score calls", self.score_call_count),
            ("registry mutations", self.registry_mutation_count),
        ):
            require_exact_int(count, label=f"source audit {label}", minimum=0)
        expected_status = (
            "PASS_HOFS_V7_SCORE_FREE_SOURCE_ISOLATION"
            if self.passed
            else "FAIL_HOFS_V7_SOURCE_ISOLATION"
        )
        if self.status != expected_status:
            raise RuntimeError("source audit status/semantics drifted")

    @property
    def passed(self) -> bool:
        return (
            not self.forbidden_import_hits
            and not self.frozen_prediction_import_hits
            and not self.obsolete_single_date_field_hits
            and not self.forbidden_call_hits
            and not self.unexpected_runtime_io_hits
            and self.protected_payload_open_count == 0
            and self.frozen_prediction_open_count == 0
            and self.score_call_count == 0
            and self.registry_mutation_count == 0
        )

    def payload(self) -> dict[str, object]:
        return {**asdict(self), "passed": self.passed}


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _imports(tree: ast.AST) -> list[str]:
    output: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            output.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            output.append(node.module)
    return output


def run_source_audit_v7(project_root: str | Path) -> SourceAuditResultV7:
    """Audit the explicit V7 closure and exact frozen V6 design/GO lineage."""

    root = Path(project_root).resolve()
    exact_directories = {
        "research/model_zoo/hierarchical_observable_fair_value_state_v7": {
            Path(path).name
            for path in DECLARED_SOURCE_PATHS
            if path.startswith("research/model_zoo/hierarchical_observable_fair_value_state_v7/")
        },
        "scripts/model_lab/hierarchical_observable_fair_value_state_v7": {
            Path(path).name
            for path in DECLARED_SOURCE_PATHS
            if path.startswith("scripts/model_lab/hierarchical_observable_fair_value_state_v7/")
        },
    }
    for relative_directory, expected_names in exact_directories.items():
        directory = root / relative_directory
        raw_children = tuple(directory.iterdir())
        cache_children = tuple(path for path in raw_children if path.name == "__pycache__")
        if any(path.is_symlink() or not path.is_dir() for path in cache_children):
            raise RuntimeError(f"H-OFS V7 source cache custody drifted: {relative_directory}")
        children = tuple(path for path in raw_children if path.name != "__pycache__")
        if any(path.is_symlink() or not path.is_file() for path in children):
            raise RuntimeError(f"H-OFS V7 source closure has non-file: {relative_directory}")
        if {path.name for path in children} != expected_names:
            raise RuntimeError(f"H-OFS V7 source closure universe drifted: {relative_directory}")
    source_hashes: list[tuple[str, str]] = []
    forbidden_import_hits: list[str] = []
    frozen_import_hits: list[str] = []
    obsolete_single_date_hits: list[str] = []
    forbidden_call_hits: list[str] = []
    unexpected_io_hits: list[str] = []
    allowed_io_hits: list[str] = []
    for relative_path in DECLARED_SOURCE_PATHS:
        path = root / relative_path
        if not path.is_file():
            raise FileNotFoundError(f"declared H-OFS V7 source missing: {relative_path}")
        content = path.read_bytes()
        source_hashes.append((relative_path, hashlib.sha256(content).hexdigest()))
        source_text = content.decode("utf-8")
        for token in _OBSOLETE_SINGLE_DATE_TOKENS:
            if token in source_text:
                obsolete_single_date_hits.append(f"{relative_path}:{token}")
        if path.suffix != ".py":
            continue
        tree = ast.parse(source_text, filename=relative_path)
        for imported in _imports(tree):
            if any(fragment in imported for fragment in _FORBIDDEN_IMPORT_FRAGMENTS):
                forbidden_import_hits.append(f"{relative_path}:{imported}")
            if imported.startswith(_FROZEN_PREDICTION_PREFIX):
                frozen_import_hits.append(f"{relative_path}:{imported}")
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node)
            location = f"{relative_path}:{getattr(node, 'lineno', 0)}:{name}"
            if name in _FORBIDDEN_CALL_NAMES:
                forbidden_call_hits.append(location)
            if name in _IO_METHODS:
                if path.name in _ALLOWED_IO_FILES:
                    allowed_io_hits.append(location)
                else:
                    unexpected_io_hits.append(location)

    parent_hashes: list[tuple[str, str]] = []
    for relative_path, expected_sha256 in sorted(PARENT_RUNTIME_SOURCE_SHA256.items()):
        actual = hashlib.sha256((root / relative_path).read_bytes()).hexdigest()
        if actual != expected_sha256:
            raise RuntimeError(f"parent runtime closure drifted: {relative_path}")
        parent_hashes.append((relative_path, actual))
    v6_audit_path = root / str(V6_INDEPENDENT_AUDIT_BINDING["path"])
    audit_root = v6_audit_path.parent
    expected_audit_universe = (
        "ACCESS_RECEIPT.json",
        "AUDIT.json",
        "CHECKSUMS.sha256",
        "MANIFEST.json",
        "PROBE_RECEIPT.json",
        "QUALITY_RECEIPT.json",
        "REPORT.md",
        "SEAL_RECEIPT.json",
        "build_audit.py",
        "independent_probe.py",
    )
    if tuple(sorted(path.name for path in audit_root.iterdir())) != expected_audit_universe:
        raise RuntimeError("bound H-OFS V6 audit file universe drifted")
    v6_audit_content = v6_audit_path.read_bytes()
    v6_audit_sha256 = hashlib.sha256(v6_audit_content).hexdigest()
    if v6_audit_sha256 != V6_INDEPENDENT_AUDIT_BINDING["raw_sha256"]:
        raise RuntimeError("bound H-OFS V6 independent audit drifted")
    v6_audit_payload = json.loads(v6_audit_content.decode("ascii"))
    recorded_semantic = v6_audit_payload.pop("manifest_sha256", None)
    v6_audit_semantic = hashlib.sha256(canonical_json_bytes(v6_audit_payload)).hexdigest()
    if (
        recorded_semantic != v6_audit_semantic
        or v6_audit_semantic != V6_INDEPENDENT_AUDIT_BINDING["semantic_sha256"]
    ):
        raise RuntimeError("bound H-OFS V6 independent audit semantic seal drifted")
    for key in ("verdict", "severity_counts", "finding_count"):
        if v6_audit_payload.get(key) != V6_INDEPENDENT_AUDIT_BINDING[key]:
            raise RuntimeError(f"bound H-OFS V6 independent audit finding drifted: {key}")
    pinned_audit_files = {
        "MANIFEST.json": "manifest_raw_sha256",
        "SEAL_RECEIPT.json": "seal_raw_sha256",
        "CHECKSUMS.sha256": "checksums_raw_sha256",
    }
    audit_hashes: dict[str, str] = {}
    for name, pin_name in pinned_audit_files.items():
        digest = hashlib.sha256((audit_root / name).read_bytes()).hexdigest()
        if digest != V6_INDEPENDENT_AUDIT_BINDING[pin_name]:
            raise RuntimeError(f"bound H-OFS V6 audit {name} drifted")
        audit_hashes[name] = digest
    checksum_lines = (audit_root / "CHECKSUMS.sha256").read_text(encoding="ascii").splitlines()
    expected_checksum_names = tuple(
        name for name in expected_audit_universe if name != "CHECKSUMS.sha256"
    )
    recorded_names: list[str] = []
    for line in checksum_lines:
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2:
            raise RuntimeError("bound H-OFS V6 audit checksum syntax drifted")
        digest, name = parts
        if name in recorded_names or name not in expected_checksum_names:
            raise RuntimeError("bound H-OFS V6 audit checksum universe drifted")
        if hashlib.sha256((audit_root / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"bound H-OFS V6 audit checksum drifted: {name}")
        recorded_names.append(name)
    if tuple(recorded_names) != tuple(sorted(expected_checksum_names)):
        raise RuntimeError("bound H-OFS V6 audit checksum coverage/order drifted")

    design_root = root / str(V6_DESIGN_FREEZE_BINDING["path"])
    design_checksums = hashlib.sha256((design_root / "CHECKSUMS.sha256").read_bytes()).hexdigest()
    design_source_closure = hashlib.sha256(
        (design_root / "SOURCE_CLOSURE.json").read_bytes()
    ).hexdigest()
    if (
        design_checksums != V6_DESIGN_FREEZE_BINDING["checksums_raw_sha256"]
        or design_source_closure != V6_DESIGN_FREEZE_BINDING["source_closure_raw_sha256"]
    ):
        raise RuntimeError("bound H-OFS V6 design/source closure drifted")

    passed = not (
        forbidden_import_hits
        or frozen_import_hits
        or obsolete_single_date_hits
        or forbidden_call_hits
        or unexpected_io_hits
    )
    return SourceAuditResultV7(
        status=(
            "PASS_HOFS_V7_SCORE_FREE_SOURCE_ISOLATION"
            if passed
            else "FAIL_HOFS_V7_SOURCE_ISOLATION"
        ),
        source_sha256=tuple(source_hashes),
        parent_runtime_sha256=tuple(parent_hashes),
        v6_audit_raw_sha256=v6_audit_sha256,
        v6_audit_semantic_sha256=v6_audit_semantic,
        v6_audit_manifest_raw_sha256=audit_hashes["MANIFEST.json"],
        v6_audit_seal_raw_sha256=audit_hashes["SEAL_RECEIPT.json"],
        v6_audit_checksums_raw_sha256=audit_hashes["CHECKSUMS.sha256"],
        v6_design_checksums_raw_sha256=design_checksums,
        v6_design_source_closure_raw_sha256=design_source_closure,
        forbidden_import_hits=tuple(sorted(forbidden_import_hits)),
        frozen_prediction_import_hits=tuple(sorted(frozen_import_hits)),
        obsolete_single_date_field_hits=tuple(sorted(obsolete_single_date_hits)),
        forbidden_call_hits=tuple(sorted(forbidden_call_hits)),
        unexpected_runtime_io_hits=tuple(sorted(unexpected_io_hits)),
        allowed_runtime_io_hits=tuple(sorted(allowed_io_hits)),
        protected_payload_open_count=0,
        frozen_prediction_open_count=0,
        score_call_count=0,
        registry_mutation_count=0,
    )


__all__ = ["DECLARED_SOURCE_PATHS", "SourceAuditResultV7", "run_source_audit_v7"]
