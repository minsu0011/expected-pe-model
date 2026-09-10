"""One exact stdin -> r5 signer -> in-memory isolated-launch path.

This entrypoint has no CLI options and never persists the activation token or
signed authority.  The production signer remains the only signing process.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from multiprocessing.connection import Client
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
from typing import Any, Mapping


PROJECT_ROOT = Path(__file__).resolve().parents[3]
ANCHOR_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_qualification_generation_external_anchor_r5_20260821.json"
)
ANCHOR = PROJECT_ROOT / ANCHOR_RELATIVE
SELF_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/issuance_launch.py"
)
EXTERNAL_LAUNCHER_RELATIVE = (
    "scripts/model_lab/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_qualification_generation/external_launcher.py"
)
SIGNER_READINESS_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_"
    "r8_r5_signer_service_20260821/READINESS.json"
)
SIGNER_READINESS_RAW_SHA256 = (
    "528ce7d457f9bf7f1d49e8912ccf4380c3ad177404e6aa86b36ee022d7a03133"
)
SIGNER_SERVICE_RELATIVE = (
    "research/model_zoo/observable_state_bce_dgp_tournament_v2_"
    "r8_r5_signer_service/custody_service.py"
)
SIGNER_SERVICE_RAW_SHA256 = (
    "295d0c5b17f7e2515ebc11819777f18900676393a43f17ce0da3c97b88538ef8"
)
SIGNER_KEY_ID = "7282e82347c420158799e7941db9b000f5b3db4fd5b10262cd9d533ab50e6431"
SIGNER_PUBLIC_KEY_HEX = (
    "98ad0326c8bcd90e3764105577297b73ab8653ef50f2cf6e700808e7ea46d179"
)
AUDIT_ROOT_RELATIVE = (
    "outputs/model_zoo_observable_state_bce_dgp_tournament_v2_r8_"
    "independent_qualification_pre_generation_audit_r5_20260821"
)
RUNTIME_PYTHON = Path(
    "C:/Users/minsu/Documents/EPS/.venv_pe_model_lab_py310/Scripts/python.exe"
)
BYTECODE_BLACKHOLE = (
    PROJECT_ROOT / "outputs/.expected_pe_r8_r5_bytecode_blackhole_DO_NOT_CREATE"
).resolve()


class IssuanceLaunchError(RuntimeError):
    """Fail-closed issuance/launch orchestration error."""


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_reparse(path: Path) -> bool:
    metadata = os.lstat(path)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        int(getattr(metadata, "st_file_attributes", 0)) & 0x400
    )


def _plain_project_file(relative: str) -> Path:
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise IssuanceLaunchError("fixed path escaped")
    root = PROJECT_ROOT.resolve(strict=True)
    path = (root / relative).resolve(strict=True)
    if root not in path.parents or not path.is_file() or _is_reparse(path):
        raise IssuanceLaunchError("fixed file is not a direct plain project file")
    return path


def _load_anchor() -> tuple[bytes, Mapping[str, Any]]:
    raw = _plain_project_file(ANCHOR_RELATIVE).read_bytes()
    try:
        anchor = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IssuanceLaunchError("r5 anchor is invalid JSON") from exc
    if (
        not isinstance(anchor, dict)
        or _canonical(anchor) != raw
        or anchor.get("schema_version") != "expected_pe.r8.r5.external_launcher_anchor.v1"
        or anchor.get("status") != "FROZEN_EXTERNAL_PIN_REPORT_HASH_OUT_OF_BAND"
        or anchor.get("issuance_launcher_relative") != SELF_RELATIVE
        or anchor.get("launcher_relative") != EXTERNAL_LAUNCHER_RELATIVE
    ):
        raise IssuanceLaunchError("r5 anchor identity drifted")
    if _sha256(_plain_project_file(SELF_RELATIVE).read_bytes()) != anchor.get(
        "issuance_launcher_raw_sha256"
    ):
        raise IssuanceLaunchError("issuance launcher self bytes drifted")
    if _sha256(_plain_project_file(EXTERNAL_LAUNCHER_RELATIVE).read_bytes()) != anchor.get(
        "launcher_raw_sha256"
    ):
        raise IssuanceLaunchError("external launcher bytes drifted")
    binding = anchor.get("r5_signer_service_binding")
    if binding != {
        "key_id": SIGNER_KEY_ID,
        "public_key_hex": SIGNER_PUBLIC_KEY_HEX,
        "readiness_raw_sha256": SIGNER_READINESS_RAW_SHA256,
        "readiness_root_relative": str(Path(SIGNER_READINESS_RELATIVE).parent).replace(
            "\\", "/"
        ),
        "service_source_raw_sha256": SIGNER_SERVICE_RAW_SHA256,
    }:
        raise IssuanceLaunchError("r5 signer binding drifted")
    if _sha256(_plain_project_file(SIGNER_READINESS_RELATIVE).read_bytes()) != (
        SIGNER_READINESS_RAW_SHA256
    ):
        raise IssuanceLaunchError("signer readiness bytes drifted")
    if _sha256(_plain_project_file(SIGNER_SERVICE_RELATIVE).read_bytes()) != (
        SIGNER_SERVICE_RAW_SHA256
    ):
        raise IssuanceLaunchError("signer service source bytes drifted")
    design = _plain_project_file(
        f"{anchor['design_root_relative']}/CHECKSUMS.sha256"
    ).read_bytes()
    if _sha256(design) != anchor.get("design_checksums_raw_sha256"):
        raise IssuanceLaunchError("frozen r5 design checksum drifted")
    return raw, anchor


def _read_token() -> str:
    line = sys.stdin.buffer.readline(66)
    if (
        len(line) != 65
        or line[-1:] != b"\n"
        or any(character not in b"0123456789abcdef" for character in line[:64])
        or sys.stdin.buffer.read(1) != b""
    ):
        raise IssuanceLaunchError("stdin must contain one fresh 64-lowercase-hex token line")
    return line[:64].decode("ascii")


def _build_claim(
    *, token: str, anchor_raw: bytes, anchor: Mapping[str, Any]
) -> Mapping[str, Any]:
    audit_root = PROJECT_ROOT / AUDIT_ROOT_RELATIVE
    audit_raw = _plain_project_file(f"{AUDIT_ROOT_RELATIVE}/AUDIT.json").read_bytes()
    seal_raw = _plain_project_file(f"{AUDIT_ROOT_RELATIVE}/SEAL.json").read_bytes()
    audit = json.loads(audit_raw)
    if (
        _canonical(audit) != audit_raw
        or audit.get("verdict") != "GO"
        or audit.get("finding_counts") != {"P0": 0, "P1": 0, "P2": 0}
        or audit.get("audit_root_relative") != AUDIT_ROOT_RELATIVE
        or audit_root.resolve(strict=True).parent != (PROJECT_ROOT / "outputs").resolve(
            strict=True
        )
    ):
        raise IssuanceLaunchError("future r5 audit is not an exact canonical zero-finding GO")
    return {
        "action": "ACTIVATE_ONCE",
        "activation_token_sha256": _sha256(token.encode("ascii")),
        "audit_json_raw_sha256": _sha256(audit_raw),
        "audit_seal_raw_sha256": _sha256(seal_raw),
        "authority_domain": "EXPECTED_PE_R8_R5_QUALIFICATION_AUTHORITY_V1",
        "custody_signer_key_id": SIGNER_KEY_ID,
        "design_checksums_raw_sha256": anchor["design_checksums_raw_sha256"],
        "dgp_ids": list("ABCDEFGHIJ"),
        "external_anchor_raw_sha256": _sha256(anchor_raw),
        "finding_counts": {"P0": 0, "P1": 0, "P2": 0},
        "heldout_seed_ids": [7603, 7607, 7621, 7639, 7643],
        "permissions": {
            "heldout_generation": False,
            "model_fit_prediction_evaluation_score": False,
            "production_promotion": False,
            "qualification_generation": True,
            "registry_mutation": False,
        },
        "qualification_seed_ids": [7573, 7577, 7583, 7589, 7591],
        "registry_raw_sha256": (
            "36ec508fff6affeb67b343dec522610e3bec914eae3ca2542495fdce8afbb941"
        ),
        "runtime_tcb_raw_sha256": anchor["runtime_tcb_raw_sha256"],
        "schema_version": "expected_pe.r8.r5.qualification.authority_claim.v1",
        "signer_readiness_raw_sha256": SIGNER_READINESS_RAW_SHA256,
        "source_archive_raw_sha256": anchor["source_archive_raw_sha256"],
        "source_lock_raw_sha256": anchor["source_lock_raw_sha256"],
        "stage": "QUALIFICATION",
    }


def _request_bound_authority_once(
    *, claim: Mapping[str, Any], token: str, anchor_raw: bytes, anchor: Mapping[str, Any]
) -> Mapping[str, Any]:
    # Refuse to become a caller-directed signing oracle: recompute the only
    # accepted claim from the fixed frozen artifacts and compare exact bytes.
    if _canonical(claim) != _canonical(_build_claim(token=token, anchor_raw=anchor_raw, anchor=anchor)):
        raise IssuanceLaunchError("caller-supplied claim differs from the sole bound r5 claim")
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.append(str(PROJECT_ROOT))
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_signer_service.custody_service import (
        MAX_FRAME_BYTES,
        SIGN_RESPONSE_SCHEMA,
        _transport_authkey,
        build_begin_request,
        build_sign_request,
        load_readiness,
        parse_canonical_json,
    )

    readiness_raw, readiness = load_readiness(PROJECT_ROOT / SIGNER_READINESS_RELATIVE)
    if _sha256(readiness_raw) != SIGNER_READINESS_RAW_SHA256:
        raise IssuanceLaunchError("reopened signer readiness hash drifted")
    public_key = bytes.fromhex(SIGNER_PUBLIC_KEY_HEX)
    with Client(
        readiness["endpoint"], family="AF_PIPE", authkey=_transport_authkey(public_key)
    ) as connection:
        begin_raw = build_begin_request(secrets.token_hex(32))
        connection.send_bytes(begin_raw)
        challenge_raw = connection.recv_bytes(MAX_FRAME_BYTES)
        challenge = parse_canonical_json(challenge_raw, code="R5_CHALLENGE_NON_CANONICAL")
        connection.send_bytes(
            build_sign_request(
                challenge=challenge,
                authority_claim=claim,
                activation_token=token,
            )
        )
        response_raw = connection.recv_bytes(MAX_FRAME_BYTES)
    response = parse_canonical_json(response_raw, code="R5_SIGN_RESPONSE_NON_CANONICAL")
    if (
        response.get("schema_version") != SIGN_RESPONSE_SCHEMA
        or response.get("status")
        != "PASS_EXACT_R8_R5_AUTHORITY_SIGNED_ONCE_SEED_ZEROIZED"
        or response.get("key_id") != SIGNER_KEY_ID
        or response.get("sign_request_count") != 1
        or response.get("signing_count") != 1
        or not isinstance(response.get("authority"), dict)
    ):
        raise IssuanceLaunchError("r5 signer did not return its sole exact success response")
    authority = response["authority"]
    if _sha256(_canonical(authority)) != response.get("authority_raw_sha256"):
        raise IssuanceLaunchError("r5 signed authority response hash drifted")
    return authority


def _child_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    environment.update(
        {
            "CUDA_VISIBLE_DEVICES": "-1",
            "MKL_NUM_THREADS": "1",
            "NVIDIA_VISIBLE_DEVICES": "void",
            "NUMEXPR_NUM_THREADS": "1",
            "OMP_NUM_THREADS": "1",
            "OPENBLAS_NUM_THREADS": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "VECLIB_MAXIMUM_THREADS": "1",
        }
    )
    return environment


def main() -> int:
    if len(sys.argv) != 1 or os.name != "nt":
        raise IssuanceLaunchError("r5 issuance launcher accepts no CLI arguments and requires Windows")
    if BYTECODE_BLACKHOLE.exists() or not RUNTIME_PYTHON.is_file():
        raise IssuanceLaunchError("fixed isolated runtime or absent bytecode blackhole precondition failed")
    anchor_raw, anchor = _load_anchor()
    token = _read_token()
    claim = _build_claim(token=token, anchor_raw=anchor_raw, anchor=anchor)
    authority = _request_bound_authority_once(
        claim=claim,
        token=token,
        anchor_raw=anchor_raw,
        anchor=anchor,
    )
    from research.model_zoo.observable_state_bce_dgp_tournament_v2_r8_r5_qualification_generation.authority import (
        authenticate_authority,
        derive_run_id,
    )

    run_id = derive_run_id(authority)
    authenticate_authority(
        authority,
        activation_token=token,
        run_id=run_id,
        design_checksums_raw_sha256=anchor["design_checksums_raw_sha256"],
        source_lock_raw_sha256=anchor["source_lock_raw_sha256"],
        runtime_tcb_raw_sha256=anchor["runtime_tcb_raw_sha256"],
        source_archive_raw_sha256=anchor["source_archive_raw_sha256"],
        external_anchor_raw_sha256=_sha256(anchor_raw),
        signer_readiness_raw_sha256=SIGNER_READINESS_RAW_SHA256,
        now=datetime.now(timezone.utc),
        reopen_audit=True,
    )
    envelope = _canonical(
        {
            "activation_token": token,
            "authority": authority,
            "schema_version": "expected_pe.r8.r5.in_memory_activation_envelope.v1",
        }
    )
    command = [
        str(RUNTIME_PYTHON),
        "-I",
        "-S",
        "-B",
        "-E",
        "-X",
        f"pycache_prefix={BYTECODE_BLACKHOLE}",
        str(PROJECT_ROOT / EXTERNAL_LAUNCHER_RELATIVE),
    ]
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=_child_environment(),
        input=envelope,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=14_400,
    )
    sys.stdout.buffer.write(completed.stdout)
    sys.stderr.buffer.write(completed.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
