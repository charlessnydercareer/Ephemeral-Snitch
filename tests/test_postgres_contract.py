from __future__ import annotations

import copy
import hashlib
import os
import unittest

import psycopg
from psycopg import errors
from psycopg.types.json import Jsonb

from postgres_session_store import (
    DuplicateSessionRecordError,
    persist_canonical_session_record,
)
from session_record import make_evidence_receipt, record_digest


WRITER_URL = os.getenv("SNITCH_TEST_WRITER_DATABASE_URL")
READER_URL = os.getenv("SNITCH_TEST_READER_DATABASE_URL")


@unittest.skipUnless(
    WRITER_URL and READER_URL,
    "disposable PostgreSQL contract URLs are not configured",
)
class PostgresLeastPrivilegeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = sample_record()
        identity = hashlib.sha256(self.id().encode("utf-8")).hexdigest()
        self.record["session_id"] = f"session-{identity[:16]}"
        self.record["request_id"] = f"req_{identity}"

    def test_writer_can_insert_canonical_record_without_select(self) -> None:
        event_id = persist_canonical_session_record(self.record, WRITER_URL)
        self.assertEqual(event_id, record_digest(self.record))

        with psycopg.connect(WRITER_URL) as connection:
            with connection.cursor() as cursor:
                with self.assertRaises(errors.InsufficientPrivilege):
                    cursor.execute("SELECT * FROM snitch.session_records")

    def test_duplicate_request_id_is_rejected(self) -> None:
        persist_canonical_session_record(self.record, WRITER_URL)
        duplicate = copy.deepcopy(self.record)
        duplicate["session_id"] = "session-duplicate"
        with self.assertRaises(DuplicateSessionRecordError):
            persist_canonical_session_record(duplicate, WRITER_URL)

    def test_writer_cannot_mutate_or_provision(self) -> None:
        event_id = persist_canonical_session_record(self.record, WRITER_URL)
        statements = (
            (
                "UPDATE snitch.session_records SET session_id = %s WHERE event_id = %s",
                ("changed", event_id),
            ),
            (
                "DELETE FROM snitch.session_records WHERE event_id = %s",
                (event_id,),
            ),
            ("TRUNCATE snitch.session_records", None),
            ("ALTER TABLE snitch.session_records ADD COLUMN forbidden TEXT", None),
            ("DROP TABLE snitch.session_records", None),
            ("CREATE TABLE snitch.forbidden (id INTEGER)", None),
        )
        for statement, parameters in statements:
            with self.subTest(statement=statement):
                with psycopg.connect(WRITER_URL) as connection:
                    with connection.cursor() as cursor:
                        with self.assertRaises(errors.InsufficientPrivilege):
                            cursor.execute(statement, parameters)

    def test_reader_can_select_but_cannot_write(self) -> None:
        event_id = persist_canonical_session_record(self.record, WRITER_URL)
        with psycopg.connect(READER_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT request_id FROM snitch.session_records WHERE event_id = %s",
                    (event_id,),
                )
                self.assertEqual(cursor.fetchone()[0], self.record["request_id"])

        with psycopg.connect(READER_URL) as connection:
            with connection.cursor() as cursor:
                with self.assertRaises(errors.InsufficientPrivilege):
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
                            self.record["session_id"],
                            self.record["request_id"],
                            event_id,
                            Jsonb(self.record),
                        ),
                    )

    def test_database_checks_reject_payload_identity_drift(self) -> None:
        event_id = record_digest(self.record)
        drifted = copy.deepcopy(self.record)
        drifted["session_id"] = "different-session"
        with psycopg.connect(WRITER_URL) as connection:
            with connection.cursor() as cursor:
                with self.assertRaises(errors.CheckViolation):
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
                            self.record["session_id"],
                            self.record["request_id"],
                            event_id,
                            Jsonb(drifted),
                        ),
                    )

    def test_trace_ledger_is_insert_only_and_rejects_duplicates(self) -> None:
        payload = {
            "seq_id": "trace-request-001",
            "event_hash": "sha256:" + ("a" * 64),
        }
        with psycopg.connect(WRITER_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO snitch.trace_records (
                        event_id,
                        request_id,
                        payload
                    ) VALUES (%s, %s, %s)
                    """,
                    (
                        payload["event_hash"],
                        payload["seq_id"],
                        Jsonb(payload),
                    ),
                )

        with psycopg.connect(WRITER_URL) as connection:
            with connection.cursor() as cursor:
                with self.assertRaises(errors.UniqueViolation):
                    cursor.execute(
                        """
                        INSERT INTO snitch.trace_records (
                            event_id,
                            request_id,
                            payload
                        ) VALUES (%s, %s, %s)
                        """,
                        (
                            "sha256:" + ("b" * 64),
                            payload["seq_id"],
                            Jsonb(
                                {
                                    **payload,
                                    "event_hash": "sha256:" + ("b" * 64),
                                }
                            ),
                        ),
                    )


def sample_record() -> dict[str, object]:
    return {
        "session_id": "session-postgres-contract",
        "request_id": "req_1234567890abcdef1234567890abcdef",
        "agent": "codex",
        "model_or_tool": "codex",
        "repo": "/workspace/ephemeral_snitch",
        "branch": "codex/postgres-contract",
        "commit_before": "",
        "commit_after": "",
        "files_changed": [],
        "commands_claimed": [],
        "commands_verified": [
            make_evidence_receipt(
                "test",
                {"command_sha256": "sha256:" + ("1" * 64), "exit_code": 0},
            )
        ],
        "tests_claimed": [],
        "tests_verified": [],
        "artifacts_written": [],
        "database_writes": [],
        "failures": [],
        "blockers": [],
        "deferred_work": [],
        "risk_flags": [],
        "redaction_applied": True,
        "content_capture": False,
    }


if __name__ == "__main__":
    unittest.main()
