"""Insert-only PostgreSQL persistence for canonical Snitch session records."""

from __future__ import annotations

import json
import os
from typing import Any

from session_record import record_digest, validate_record


class SessionStoreError(RuntimeError):
    """Raised when a canonical session record cannot be persisted."""


class DuplicateSessionRecordError(SessionStoreError):
    """Raised when a request ID or record digest is already present."""


class SessionStorePermissionError(SessionStoreError):
    """Raised when the configured database role lacks INSERT permission."""


def persist_canonical_session_record(
    record: dict[str, Any],
    database_url: str | None = None,
) -> str:
    """Validate and append one canonical record using an insert-only connection."""
    canonical_record = validate_record(record)
    event_id = record_digest(canonical_record)
    connection_string = database_url or os.getenv("SNITCH_WRITER_DATABASE_URL")
    if not connection_string:
        raise SessionStoreError("SNITCH_WRITER_DATABASE_URL is required")

    try:
        import psycopg
        from psycopg import errors
        from psycopg.types.json import Jsonb
    except ImportError as exc:
        raise SessionStoreError(
            "psycopg is required; install the project dependencies first"
        ) from exc

    try:
        with psycopg.connect(connection_string) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO snitch.session_records (
                        event_id,
                        session_id,
                        request_id,
                        record_sha256,
                        payload
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        event_id,
                        canonical_record["session_id"],
                        canonical_record["request_id"],
                        event_id,
                        Jsonb(canonical_record, dumps=_canonical_json_text),
                    ),
                )
    except errors.UniqueViolation as exc:
        raise DuplicateSessionRecordError(
            "request_id or canonical record already exists"
        ) from exc
    except errors.InsufficientPrivilege as exc:
        raise SessionStorePermissionError(
            "configured database role cannot append session records"
        ) from exc
    except psycopg.Error as exc:
        raise SessionStoreError("PostgreSQL session record write failed") from exc

    return event_id


def _canonical_json_text(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
