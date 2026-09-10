"""Independent byte audit of the terminally published R8-r8 static bundle."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r8_qualification_generation.static_builder import (  # noqa: E402
    DESIGN_FILE_UNIVERSE,
    build_source_lock_bytes,
    build_static_bundle_bytes,
    verify_static_bundle_bytes,
)


OUTPUT_ROOT = PROJECT_ROOT / (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r8_qualification_generation_design_source_freeze_v1_no_go_20260822"
)
CHILD_PREFIX = PROJECT_ROOT / "build/pc_r8r8_static_freeze_actual_once_20260822"
VERDICT = PROJECT_ROOT / "outputs/r8r8_static_freeze_independent_postaudit_20260823/VERDICT.json"
EXACT_ARGUMENT = "--audit-terminal-static-bundle-no-authority-no-generation-no-fresh"
ZERO_COUNTS = {
    "authority": 0,
    "fresh": 0,
    "generation": 0,
    "signer": 0,
    "truth": 0,
}


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main(arguments: list[str]) -> int:
    if arguments != [EXACT_ARGUMENT]:
        raise RuntimeError("exact independent post-freeze audit argument is required")
    if VERDICT.exists():
        raise RuntimeError("independent post-freeze verdict identity already exists")
    if not OUTPUT_ROOT.is_dir() or not CHILD_PREFIX.is_dir():
        raise RuntimeError("terminal static bundle or held child prefix is absent")
    names = tuple(sorted(path.name for path in OUTPUT_ROOT.iterdir() if path.is_file()))
    if names != DESIGN_FILE_UNIVERSE or len(names) != 19:
        raise RuntimeError("published static file universe drifted")

    source_lock = build_source_lock_bytes()
    expected = build_static_bundle_bytes(source_lock)
    verification = verify_static_bundle_bytes(expected)
    observed = {name: (OUTPUT_ROOT / name).read_bytes() for name in names}
    mismatches = [name for name in names if observed[name] != expected[name]]
    if mismatches:
        raise RuntimeError(f"published bytes differ from deterministic rebuild: {mismatches}")
    if observed["SOURCE_LOCK.json"] != source_lock:
        raise RuntimeError("published SOURCE_LOCK differs from live exact-source rebuild")

    seal = json.loads(observed["SEAL_RECEIPT.json"])
    manifest = json.loads(observed["MANIFEST.json"])
    authority = json.loads(observed["AUTHORITY_STATE.json"])
    audit_plan = json.loads(observed["INDEPENDENT_AUDIT_PLAN.json"])
    if (
        seal.get("status") != "SEALED_NO_GO_PENDING_INDEPENDENT_AUDIT"
        or manifest.get("status") != "PASS_EXACT_19_FILE_NO_GO_STATIC_BUNDLE"
        or authority.get("activation_authorized") is not False
        or authority.get("live_child_capability_present") is not False
        or audit_plan.get("production_callable") is not False
    ):
        raise RuntimeError("static bundle no-go semantics drifted")
    if any(
        payload.get("authority_generation_fresh_truth_signer_counts") != ZERO_COUNTS
        for payload in (seal, manifest, audit_plan)
    ):
        raise RuntimeError("static bundle sensitive counters drifted")
    if any(child.name for child in CHILD_PREFIX.iterdir()):
        raise RuntimeError("held no-bytecode child prefix is not empty")

    crlf_probe = subprocess.run(
        (sys.executable, "-I", "-S", "-B", "-E", "-c", "print('{}')"),
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if crlf_probe.returncode != 0 or crlf_probe.stderr != b"" or crlf_probe.stdout != b"{}\r\n":
        raise RuntimeError("Windows canonical stdout CRLF reproduction drifted")

    records = [
        [name, _sha256(observed[name]), len(observed[name])]
        for name in names
    ]
    verdict = {
        "authority_generation_fresh_truth_heldout_signer_counts": {
            **ZERO_COUNTS,
            "heldout": 0,
        },
        "child_prefix_empty": True,
        "deterministic_rebuild_file_count": len(expected),
        "file_records": records,
        "file_records_semantic_sha256": _sha256(
            json.dumps(records, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        ),
        "original_supervisor_terminal_failure": {
            "cause": "WINDOWS_CRLF_REJECTED_BY_LF_ONLY_RECEIPT_PARSER_AFTER_PUBLICATION",
            "freezer_reexecution_permitted": False,
            "reproduced_stdout_bytes_hex": crlf_probe.stdout.hex(),
        },
        "production_execution_authorized": False,
        "schema_version": "expected_pe.r8.r8.static_freeze.independent_postaudit.v1",
        "source_lock_raw_sha256": _sha256(source_lock),
        "status": "GO_STATIC_BUNDLE_AUTHENTIC_SEALED_NO_EXECUTION_AUTHORITY",
        "verification": verification,
    }
    encoded = json.dumps(
        verdict,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    with VERDICT.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
    print(encoded.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
