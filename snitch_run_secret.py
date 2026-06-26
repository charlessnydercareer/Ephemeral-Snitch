#!/usr/bin/env python3
"""Load Snitch database URLs from env or jarvis-secret, then exec snitch-run."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from snitch_config import ensure_snitch_database_env


def main() -> None:
    root = Path(__file__).resolve().parent
    snitch_run = root / "snitch-run"
    if not snitch_run.is_file():
        sys.stderr.write("CRITICAL: Snitch launcher script is unavailable.\n")
        raise SystemExit(1)

    try:
        ensure_snitch_database_env()
    except RuntimeError:
        sys.stderr.write(
            "CRITICAL: Snitch database configuration is unavailable.\n"
        )
        raise SystemExit(1) from None

    os.execv(str(snitch_run), [str(snitch_run), *sys.argv[1:]])


if __name__ == "__main__":
    main()
