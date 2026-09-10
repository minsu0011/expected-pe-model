"""Reject new V5 smoke generation; the exact sealed V4 smoke is inherited."""

from __future__ import annotations

def main() -> int:
    raise SystemExit(
        "NEW_V5_GENERATOR_SMOKE_NOT_AUTHORIZED: use the byte-pinned inherited V4 smoke"
    )


if __name__ == "__main__":
    raise SystemExit(main())
