"""EXECUTION.pyz bootstrap; imports only the frozen archive package."""

from phase2_execution.archive_entry import main


if __name__ == "__main__":
    raise SystemExit(main())
