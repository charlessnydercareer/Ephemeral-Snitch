from __future__ import annotations

import os
import unittest

import psycopg

from snitch_launcher import LauncherValidationError, probe_database_privileges


WRITER_URL = os.getenv("SNITCH_TEST_WRITER_DATABASE_URL")
READER_URL = os.getenv("SNITCH_TEST_READER_DATABASE_URL")
ADMIN_URL = os.getenv("SNITCH_TEST_ADMIN_DATABASE_URL")


@unittest.skipUnless(
    WRITER_URL and READER_URL and ADMIN_URL,
    "disposable launcher database URLs are not configured",
)
class LauncherPostgresTests(unittest.TestCase):
    def environment(self) -> dict[str, str]:
        return {
            "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
            "SNITCH_READER_DATABASE_URL": READER_URL,
        }

    def execute_admin(self, statement: str) -> None:
        with psycopg.connect(ADMIN_URL, autocommit=True) as connection:
            with connection.cursor() as cursor:
                cursor.execute(statement)

    def test_valid_roles_pass_live_probe(self) -> None:
        probe_database_privileges(self.environment())

    def test_excess_writer_select_fails_live_probe(self) -> None:
        self.execute_admin("GRANT SELECT ON snitch.session_records TO snitch_writer")
        try:
            with self.assertRaises(LauncherValidationError):
                probe_database_privileges(self.environment())
        finally:
            self.execute_admin(
                "REVOKE SELECT ON snitch.session_records FROM snitch_writer"
            )

    def test_excess_reader_insert_fails_live_probe(self) -> None:
        self.execute_admin("GRANT INSERT ON snitch.session_records TO snitch_reader")
        try:
            with self.assertRaises(LauncherValidationError):
                probe_database_privileges(self.environment())
        finally:
            self.execute_admin(
                "REVOKE INSERT ON snitch.session_records FROM snitch_reader"
            )

    def test_excess_writer_select_on_trace_ledger_fails_live_probe(self) -> None:
        self.execute_admin("GRANT SELECT ON snitch.trace_records TO snitch_writer")
        try:
            with self.assertRaises(LauncherValidationError):
                probe_database_privileges(self.environment())
        finally:
            self.execute_admin(
                "REVOKE SELECT ON snitch.trace_records FROM snitch_writer"
            )


if __name__ == "__main__":
    unittest.main()
