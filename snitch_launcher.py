"""Fail-closed launcher for privilege-validated Snitch processes."""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from typing import Any


WRITER_URL_VAR = "SNITCH_WRITER_DATABASE_URL"
READER_URL_VAR = "SNITCH_READER_DATABASE_URL"
SAFE_PATH = "/usr/local/bin:/usr/bin:/bin"
CHILD_CONFIG_VARS = (
    "SNITCH_RECORDS_DIR",
    "SNITCH_RESERVATIONS_DIR",
    "SNITCH_AUDIT_DIR",
)
TABLE_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)


class LauncherValidationError(RuntimeError):
    """Raised when launcher configuration or database authority is unsafe."""


def _fetch_boolean(cursor: Any, statement: str, parameters: tuple[Any, ...]) -> bool:
    cursor.execute(statement, parameters)
    row = cursor.fetchone()
    if row is None or len(row) != 1 or not isinstance(row[0], bool):
        raise LauncherValidationError("database probe returned an invalid result")
    return row[0]


def _probe_role(
    database_url: str,
    *,
    capability_role: str,
    required_privilege: str,
) -> None:
    try:
        import psycopg

        with psycopg.connect(database_url, connect_timeout=3) as connection:
            with connection.cursor() as cursor:
                if not _fetch_boolean(
                    cursor,
                    "SELECT pg_has_role(current_user, %s, 'member')",
                    (capability_role,),
                ):
                    raise LauncherValidationError("capability role is missing")

                for privilege in TABLE_PRIVILEGES:
                    granted = _fetch_boolean(
                        cursor,
                        """
                        SELECT has_table_privilege(
                            current_user,
                            'snitch.session_records',
                            %s
                        )
                        """,
                        (privilege,),
                    )
                    if granted != (privilege == required_privilege):
                        raise LauncherValidationError("table privileges are unsafe")

                if _fetch_boolean(
                    cursor,
                    "SELECT has_schema_privilege(current_user, 'snitch', 'CREATE')",
                    (),
                ):
                    raise LauncherValidationError("schema CREATE is forbidden")

                if _fetch_boolean(
                    cursor,
                    """
                    SELECT pg_catalog.pg_get_userbyid(n.nspowner) = current_user
                    FROM pg_catalog.pg_namespace AS n
                    WHERE n.nspname = 'snitch'
                    """,
                    (),
                ):
                    raise LauncherValidationError("runtime principal owns schema")

                if _fetch_boolean(
                    cursor,
                    """
                    SELECT pg_catalog.pg_get_userbyid(c.relowner) = current_user
                    FROM pg_catalog.pg_class AS c
                    JOIN pg_catalog.pg_namespace AS n
                      ON n.oid = c.relnamespace
                    WHERE n.nspname = 'snitch'
                      AND c.relname = 'session_records'
                      AND c.relkind IN ('r', 'p')
                    """,
                    (),
                ):
                    raise LauncherValidationError("runtime principal owns ledger")
    except LauncherValidationError:
        raise
    except Exception as exc:
        raise LauncherValidationError("database privilege probe failed") from exc


def probe_database_privileges(environ: dict[str, str] | None = None) -> None:
    """Validate writer and reader authority without exposing connection details."""
    source = os.environ if environ is None else environ
    writer_url = source.get(WRITER_URL_VAR, "").strip()
    reader_url = source.get(READER_URL_VAR, "").strip()

    if not writer_url or not reader_url:
        raise LauncherValidationError("database configuration is missing")
    if writer_url == reader_url:
        raise LauncherValidationError("writer and reader connections must differ")

    _probe_role(
        writer_url,
        capability_role="snitch_writer",
        required_privilege="INSERT",
    )
    _probe_role(
        reader_url,
        capability_role="snitch_reader",
        required_privilege="SELECT",
    )


def build_child_environment(
    role: str,
    environ: dict[str, str] | None = None,
) -> dict[str, str]:
    """Return the explicit environment passed to the downstream process."""
    if role not in {"writer", "reader"}:
        raise LauncherValidationError("target role is invalid")
    source = os.environ if environ is None else environ
    child = {"PATH": SAFE_PATH}
    database_variable = WRITER_URL_VAR if role == "writer" else READER_URL_VAR
    database_url = source.get(database_variable)
    if not database_url:
        raise LauncherValidationError("target database configuration is missing")
    child[database_variable] = database_url
    for name in CHILD_CONFIG_VARS:
        value = source.get(name)
        if value:
            child[name] = value
    return child


def execute_downstream_target(
    arguments: Sequence[str],
    environ: dict[str, str] | None = None,
) -> None:
    """Replace this process with an explicit, shell-free target command."""
    if len(arguments) < 4 or arguments[0] != "--role":
        raise LauncherValidationError("target role is required")
    role = arguments[1]
    if arguments[2] != "--":
        raise LauncherValidationError("target command must follow --")
    target = list(arguments[3:])
    if not target or not target[0]:
        raise LauncherValidationError("target command is missing")

    try:
        os.execvpe(target[0], target, build_child_environment(role, environ))
    except Exception as exc:
        raise LauncherValidationError("target execution failed") from exc


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        probe_database_privileges()
        execute_downstream_target(
            sys.argv[1:] if arguments is None else arguments,
        )
    except LauncherValidationError:
        sys.stderr.write("CRITICAL: Launcher verification failed; execution aborted.\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
