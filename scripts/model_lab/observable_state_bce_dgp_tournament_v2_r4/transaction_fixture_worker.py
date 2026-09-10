"""Subprocess-only worker for isolated R4 transaction fault/race probes."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

from research.model_zoo.observable_state_bce_dgp_tournament_v2_r4.artifacts import (
    canonical_json_bytes,
    seal_payload,
)
from research.model_zoo.observable_state_bce_dgp_tournament_v2_r4.transaction import (
    R4TransactionError,
    TransactionPaths,
    TransactionRequest,
    execute_fixture_transaction,
    fixture_registry_payload,
)


def _legacy(root: Path, hold_seconds: float) -> int:
    marker = root / "fixture_registry.json.lock"
    try:
        descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        print(json.dumps({"error": "legacy-lock-busy"}, sort_keys=True), flush=True)
        return 3
    try:
        os.write(descriptor, f"pid={os.getpid()} lane=legacy\n".encode("ascii"))
        os.fsync(descriptor)
        print("LEGACY_READY", flush=True)
        time.sleep(hold_seconds)
        registry_path = root / "fixture_registry.json"
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        previous = registry["entries"][-1]["entry_sha256"] if registry["entries"] else "GENESIS"
        entry = seal_payload(
            {
                "sequence": len(registry["entries"]) + 1,
                "previous_entry_sha256": previous,
                "transaction_id": "legacy_transaction",
                "lane_id": "legacy_lane",
                "payload": {"fixed": "legacy"},
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            },
            "entry_sha256",
        )
        updated = fixture_registry_payload([*registry["entries"], entry])
        pending = root / ".legacy_registry.pending"
        with pending.open("xb") as stream:
            stream.write(canonical_json_bytes(updated))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, registry_path)
        print(json.dumps(entry, sort_keys=True, separators=(",", ":")), flush=True)
        return 0
    finally:
        os.close(descriptor)
        marker.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture_root")
    parser.add_argument("transaction_id")
    parser.add_argument("lane_id")
    parser.add_argument("registry_before_sha256")
    parser.add_argument("--legacy-hold-seconds", type=float)
    args = parser.parse_args()
    root = Path(args.fixture_root)
    if args.legacy_hold_seconds is not None:
        return _legacy(root, args.legacy_hold_seconds)
    paths = TransactionPaths(
        registry=root / "fixture_registry.json",
        runtime_root=root / f"runtime_{args.transaction_id}",
        journal=root / f"journal_{args.transaction_id}.json",
        os_lock=root / "fixture_registry.r4.oslock",
        legacy_lock=root / "fixture_registry.json.lock",
        fixture_root=root,
    )
    request = TransactionRequest(
        transaction_id=args.transaction_id,
        lane_id=args.lane_id,
        expected_registry_raw_sha256=args.registry_before_sha256,
        payload={"fixed": "fixture", "lane": args.lane_id},
    )
    try:
        receipt = execute_fixture_transaction(paths, request)
    except R4TransactionError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
