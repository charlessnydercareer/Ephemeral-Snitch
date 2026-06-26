#!/usr/bin/env python3
"""Finalize one normalized Project Snitch session record."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from postgres_session_store import (
    SessionStoreError,
    persist_canonical_session_record,
)
from session_record import (
    SessionRecordError,
    build_record,
    write_session_artifacts,
)
from snitch_config import (
    default_audit_dir,
    default_records_dir,
    default_reservations_dir,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Agent claims JSON input")
    parser.add_argument(
        "--evidence",
        help="Verified observer evidence JSON input",
    )
    parser.add_argument("--repo", required=True, help="Observed Git repository")
    parser.add_argument("--commit-before")
    parser.add_argument(
        "--records-dir",
        default=str(default_records_dir()),
    )
    parser.add_argument(
        "--audit-dir",
        default=str(default_audit_dir()),
    )
    parser.add_argument(
        "--reservations-dir",
        default=str(default_reservations_dir()),
    )
    parser.add_argument(
        "--persist-postgres",
        action="store_true",
        help="Append the finalized record to the PostgreSQL session ledger",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        with Path(args.input).open("r", encoding="utf-8") as handle:
            claims = json.load(handle)
        evidence = None
        if args.evidence:
            with Path(args.evidence).open("r", encoding="utf-8") as handle:
                evidence = json.load(handle)
        record = build_record(
            claims,
            repo=args.repo,
            commit_before=args.commit_before,
            evidence=evidence,
        )
        result = write_session_artifacts(
            record,
            records_dir=args.records_dir,
            audit_dir=args.audit_dir,
            reservations_dir=args.reservations_dir,
        )
    except (OSError, json.JSONDecodeError, SessionRecordError) as exc:
        raise SystemExit(f"Snitch session finalization failed: {exc}") from exc

    if args.persist_postgres:
        try:
            result["postgres_event_id"] = persist_canonical_session_record(record)
        except SessionStoreError:
            sys.stderr.write(
                "CRITICAL: Session ledger persistence failed; "
                "local artifacts were preserved.\n"
            )
            return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
