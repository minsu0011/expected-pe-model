from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import sys
from types import ModuleType
from typing import cast

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts/model_lab/pe_four_model_heldout_r2_repin_evaluator.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pe_r2_repin_evaluator_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _assignment(raw: bytes, name: str) -> object:
    tree = ast.parse(raw.decode("utf-8"))
    values = []
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
            value = node.value
        else:
            continue
        if name in names:
            values.append(ast.literal_eval(value))
    assert len(values) == 1
    return values[0]


def _synthetic_source_groups(module: ModuleType) -> list[list[dict[str, object]]]:
    groups: list[list[dict[str, object]]] = []
    ordinal = 1
    for group_index, count in enumerate(module.EXPECTED_SOURCE_GROUP_COUNTS):
        group = []
        for row_index in range(count):
            group.append(
                {
                    "relative_path": (f"research/synthetic/g{group_index:02d}/r{row_index:03d}.py"),
                    "raw_sha256": f"{ordinal:064x}",
                    "size_bytes": ordinal,
                }
            )
            ordinal += 1
        groups.append(group)
    return groups


def test_source_lock_render_is_deterministic_and_round_trips_137_records() -> None:
    module = _load()
    groups = _synthetic_source_groups(module)
    runtime = {
        "python_implementation": "CPython",
        "python_version": "3.10.19",
    }

    first = module.render_source_lock(groups, runtime)
    second = module.render_source_lock(groups, runtime)

    assert first == second
    locked_groups = cast(
        tuple[tuple[tuple[str, str, int], ...], ...],
        _assignment(first, "EXPECTED_SOURCE_RECORD_GROUPS"),
    )
    assert tuple(map(len, locked_groups)) == (74, 26, 34, 3)
    assert sum(map(len, locked_groups)) == 137
    assert _assignment(first, "EXPECTED_SOURCE_RECORD_COUNT") == 137
    assert (
        dict(cast(tuple[tuple[str, str], ...], _assignment(first, "EXPECTED_RUNTIME_VERSIONS")))
        == runtime
    )


def test_protocol_placeholder_rewrite_changes_only_two_zero_literals() -> None:
    module = _load()
    raw = (
        "from typing import Final\n"
        "R2_PROTOCOL_LOCK_RAW_SHA256: Final = (\n"
        f'    "{module.ZERO_SHA256}"\n'
        ")\n"
        "R2_PROTOCOL_BINDING_SEMANTIC_SHA256: Final = (\n"
        f'    "{module.ZERO_SHA256}"\n'
        ")\n"
    ).encode("utf-8")
    protocol_raw = "a" * 64
    protocol_semantic = "b" * 64

    planned = module.replace_protocol_placeholders(
        raw,
        protocol_raw_sha256=protocol_raw,
        protocol_semantic_sha256=protocol_semantic,
    )

    assert len(planned) == len(raw)
    assert _assignment(planned, "R2_PROTOCOL_LOCK_RAW_SHA256") == protocol_raw
    assert _assignment(planned, "R2_PROTOCOL_BINDING_SEMANTIC_SHA256") == protocol_semantic
    assert planned == raw.replace(b"0" * 64, b"a" * 64, 1).replace(b"0" * 64, b"b" * 64, 1)
    assert (
        module.replace_protocol_placeholders(
            planned,
            protocol_raw_sha256=protocol_raw,
            protocol_semantic_sha256=protocol_semantic,
        )
        == planned
    )
    attacked = planned.replace(b"b" * 64, b"c" * 64)
    with pytest.raises(module.EvaluatorRepinError):
        module.replace_protocol_placeholders(
            attacked,
            protocol_raw_sha256=protocol_raw,
            protocol_semantic_sha256=protocol_semantic,
        )


def test_launcher_discovers_exact_four_package_37_file_universe() -> None:
    module = _load()
    universe, counts = module.discover_launcher_source_universe(PROJECT_ROOT)

    assert counts == (11, 3, 11, 12)
    assert len(universe) == len(set(universe)) == 37
    assert all(relative.endswith(".py") and "\\" not in relative for relative in universe)
    assert {relative.rsplit("/", 1)[0] for relative in universe} == set(
        module.EVALUATOR_PACKAGE_RELATIVES
    )


def test_launcher_rewrite_uses_overlay_hashes_and_only_replaces_pin_assignment() -> None:
    module = _load()
    constants_overlay = b"synthetic future constants\n"
    source_lock_overlay = b"synthetic future source lock\n"
    pins, _ = module.build_launcher_pins(
        PROJECT_ROOT,
        overlays={
            module.CONSTANTS_RELATIVE: constants_overlay,
            module.SOURCE_LOCK_RELATIVE: source_lock_overlay,
        },
    )
    run_once = (PROJECT_ROOT / module.RUN_ONCE_RELATIVE).read_bytes()

    planned = module.replace_launcher_pin_assignment(run_once, pins)

    assert len(pins) == 37
    assert pins[module.CONSTANTS_RELATIVE] == hashlib.sha256(constants_overlay).hexdigest()
    assert pins[module.SOURCE_LOCK_RELATIVE] == hashlib.sha256(source_lock_overlay).hexdigest()
    assert _assignment(planned, "PINNED_SOURCE_SHA256") == pins
    before = ast.parse(run_once.decode("utf-8"))
    after = ast.parse(planned.decode("utf-8"))
    before.body = [
        node
        for node in before.body
        if not (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "PINNED_SOURCE_SHA256"
        )
    ]
    after.body = [
        node
        for node in after.body
        if not (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "PINNED_SOURCE_SHA256"
        )
    ]
    assert ast.dump(before, include_attributes=False) == ast.dump(after, include_attributes=False)


def test_cli_defaults_to_read_only_dry_run() -> None:
    module = _load()
    arguments = module.parser().parse_args(
        [
            "--execution-authority",
            "build/example.json",
            "--execution-authority-raw-sha256",
            "a" * 64,
        ]
    )
    assert arguments.apply is False
