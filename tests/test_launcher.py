from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import MagicMock, patch

from snitch_launcher import (
    LauncherValidationError,
    SAFE_PATH,
    build_child_environment,
    execute_downstream_target,
    main,
    probe_database_privileges,
)


WRITER_URL = "host=writer.invalid dbname=snitch"
READER_URL = "host=reader.invalid dbname=snitch"


def connection_with_results(results: list[bool]) -> MagicMock:
    connection_manager = MagicMock()
    connection = connection_manager.__enter__.return_value
    cursor_manager = connection.cursor.return_value
    cursor = cursor_manager.__enter__.return_value
    cursor.fetchone.side_effect = [(result,) for result in results]
    return connection_manager


def valid_role_results(required_privilege: str) -> list[bool]:
    privileges = (
        "SELECT",
        "INSERT",
        "UPDATE",
        "DELETE",
        "TRUNCATE",
        "REFERENCES",
        "TRIGGER",
    )
    return [
        True,
        *(
            privilege == required_privilege
            for _table in range(2)
            for privilege in privileges
        ),
        False,
        False,
        False,
        False,
    ]


class LauncherPrivilegeTests(unittest.TestCase):
    def test_identical_database_urls_fail_before_connecting(self) -> None:
        environment = {
            "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
            "SNITCH_READER_DATABASE_URL": WRITER_URL,
        }
        with patch("psycopg.connect") as connect:
            with self.assertRaises(LauncherValidationError):
                probe_database_privileges(environment)
        connect.assert_not_called()

    @patch("psycopg.connect")
    def test_valid_independent_roles_pass(self, connect: MagicMock) -> None:
        connect.side_effect = [
            connection_with_results(valid_role_results("INSERT")),
            connection_with_results(valid_role_results("SELECT")),
        ]
        probe_database_privileges(
            {
                "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                "SNITCH_READER_DATABASE_URL": READER_URL,
            }
        )
        self.assertEqual(connect.call_count, 2)

    @patch("psycopg.connect")
    def test_excess_writer_select_fails_closed(self, connect: MagicMock) -> None:
        results = valid_role_results("INSERT")
        results[1] = True
        connect.return_value = connection_with_results(results)
        with self.assertRaises(LauncherValidationError):
            probe_database_privileges(
                {
                    "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                    "SNITCH_READER_DATABASE_URL": READER_URL,
                }
            )
        self.assertEqual(connect.call_count, 1)

    @patch("psycopg.connect")
    def test_reader_schema_ownership_fails_closed(self, connect: MagicMock) -> None:
        reader_results = valid_role_results("SELECT")
        reader_results[-2] = True
        connect.side_effect = [
            connection_with_results(valid_role_results("INSERT")),
            connection_with_results(reader_results),
        ]
        with self.assertRaises(LauncherValidationError):
            probe_database_privileges(
                {
                    "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                    "SNITCH_READER_DATABASE_URL": READER_URL,
                }
            )


class LauncherExecutionTests(unittest.TestCase):
    def test_child_environment_is_an_allowlist(self) -> None:
        child = build_child_environment(
            "writer",
            {
                "PATH": "/untrusted",
                "HOME": "/private",
                "PYTHONPATH": "/inject",
                "TOKEN": "secret",
                "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                "SNITCH_READER_DATABASE_URL": READER_URL,
                "SNITCH_AUDIT_DIR": "/audits",
            },
        )
        self.assertEqual(
            child,
            {
                "PATH": SAFE_PATH,
                "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                "SNITCH_AUDIT_DIR": "/audits",
            },
        )

    def test_reader_child_does_not_receive_writer_url(self) -> None:
        child = build_child_environment(
            "reader",
            {
                "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                "SNITCH_READER_DATABASE_URL": READER_URL,
            },
        )
        self.assertNotIn("SNITCH_WRITER_DATABASE_URL", child)
        self.assertEqual(child["SNITCH_READER_DATABASE_URL"], READER_URL)

    @patch("os.execvpe")
    def test_explicit_boundary_executes_without_shell(self, execvpe: MagicMock) -> None:
        environment = {
            "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
            "SNITCH_READER_DATABASE_URL": READER_URL,
        }
        execute_downstream_target(
            ["--role", "writer", "--", "/usr/bin/python3", "-c", "pass"],
            environment,
        )
        execvpe.assert_called_once_with(
            "/usr/bin/python3",
            ["/usr/bin/python3", "-c", "pass"],
            {
                "PATH": SAFE_PATH,
                "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
            },
        )

    def test_missing_boundary_fails_closed(self) -> None:
        with self.assertRaises(LauncherValidationError):
            execute_downstream_target(
                ["--role", "writer", "python3", "-c", "pass"],
                {},
            )

    @patch("snitch_launcher.probe_database_privileges")
    def test_cli_error_does_not_expose_internal_detail(
        self,
        probe: MagicMock,
    ) -> None:
        probe.side_effect = LauncherValidationError("sensitive-internal-detail")
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            result = main(["--role", "writer", "--", "/usr/bin/true"])
        self.assertEqual(result, 1)
        self.assertEqual(
            stderr.getvalue(),
            "CRITICAL: Launcher verification failed; execution aborted.\n",
        )


if __name__ == "__main__":
    unittest.main()
