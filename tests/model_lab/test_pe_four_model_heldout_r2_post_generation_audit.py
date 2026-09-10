from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (
    PROJECT_ROOT
    / "scripts"
    / "model_lab"
    / "pe_four_model_heldout_r2_post_generation_audit.py"
)


def _module():
    spec = importlib.util.spec_from_file_location("r2_post_generation_audit", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_auditor_is_stdlib_only_and_has_no_producer_import() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert imported <= {
        "__future__",
        "argparse",
        "csv",
        "hashlib",
        "io",
        "json",
        "os",
        "pathlib",
        "re",
        "stat",
        "sys",
        "typing",
    }
    assert "research.model_zoo" not in source
    assert ".read_bytes()" not in source[source.index("for ordinal, (seed, dgp)") : source.index("return manifest")]


def test_canonical_parser_and_self_seal_fail_closed() -> None:
    module = _module()
    state = module.State()
    payload = {"a": 1, "z": [True, None]}
    raw = module.compact_file_bytes(payload)
    assert module.parse_json(raw, pretty=False, state=state) == payload
    assert module.semantic_sha256(payload) == hashlib.sha256(raw[:-1]).hexdigest()
    noncanonical = json.dumps(payload, indent=1).encode("ascii")
    try:
        module.parse_json(noncanonical, pretty=False, state=state)
    except module.AuditFailure as failure:
        assert failure.code == "JSON_CANONICAL"
    else:  # pragma: no cover
        raise AssertionError("noncanonical bytes were accepted")


def test_public_protection_guard_rejects_path_or_access() -> None:
    module = _module()
    for payload in (
        {"truth_open_count": 1},
        {"protected_value_received": True},
        {"nested": ["outputs/heldout_vault_x/pass_1"]},
    ):
        try:
            module.scan_public_protection(payload, state=module.State())
        except module.AuditFailure:
            pass
        else:  # pragma: no cover
            raise AssertionError("protected public evidence was accepted")
