#!/usr/bin/env python3
"""EVECOR-facing Snitch session finalizer with fixed audit and secret gates."""

from __future__ import annotations

import argparse
import json
import stat
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
    default_records_dir,
    default_reservations_dir,
    evecor_consumer_audit_dir,
    require_snitch_secrets_available,
    validate_evecor_consumer_audit_dir,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Finalize one Snitch session for EVECOR consumers. "
            "Audits are always written to the operator audit directory."
        )
    )
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
        "--reservations-dir",
        default=str(default_reservations_dir()),
    )
    parser.add_argument(
        "--persist-postgres",
        action="store_true",
        help="Append the finalized record to the PostgreSQL session ledger",
    )
    return parser.parse_args()


def _assert_private_audit_permissions(audit_path: Path) -> None:
    mode = audit_path.stat().st_mode
    if stat.S_IMODE(mode) != 0o600:
        raise SessionRecordError(
            f"audit artifact permissions must be 0600, got {stat.S_IMODE(mode):#04o}"
        )


def main() -> int:
    try:
        require_snitch_secrets_available()
    except RuntimeError as exc:
        sys.stderr.write(f"CRITICAL: {exc}\n")
        return 1

    args = parse_args()
    audit_dir = validate_evecor_consumer_audit_dir(evecor_consumer_audit_dir())

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
            audit_dir=audit_dir,
            reservations_dir=args.reservations_dir,
        )
        _assert_private_audit_permissions(Path(result["audit"]))
    except (OSError, json.JSONDecodeError, SessionRecordError, ValueError) as exc:
        raise SystemExit(f"Snitch EVECOR finalization failed: {exc}") from exc

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
