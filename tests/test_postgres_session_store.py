from __future__ import annotations

import unittest
from unittest.mock import patch

import psycopg

from postgres_session_store import SessionStoreError, persist_canonical_session_record


class PostgresSessionStoreTests(unittest.TestCase):
    @patch("psycopg.connect")
    def test_connection_failure_is_mapped_without_sensitive_detail(
        self,
        connect,
    ) -> None:
        connect.side_effect = psycopg.OperationalError("sensitive connection detail")
        with self.assertRaisesRegex(
            SessionStoreError,
            "^PostgreSQL session record write failed$",
        ):
            persist_canonical_session_record(
                sample_record(),
                "host=example.invalid password=sensitive",
            )


def sample_record() -> dict[str, object]:
    return {
        "session_id": "store-error-session",
        "request_id": "req_6666666666666666",
        "agent": "test-agent",
        "model_or_tool": "test-tool",
        "repo": "repo",
        "branch": "main",
        "commit_before": "",
        "commit_after": "",
        "files_changed": [],
        "commands_claimed": [],
        "commands_verified": [],
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
