"""Small, explicit PostgreSQL adapter used by the Snitch prototypes.

The original Labs copy silently discarded every query. This adapter fails
closed when no database URL is configured and never embeds credentials.
"""

from __future__ import annotations

import os
from typing import Any, Iterable


class Pg0Error(RuntimeError):
    """Raised when the Snitch database contract is unavailable."""


class Pg0:
    def __init__(self, connection_string: str | None = None) -> None:
        self.connection_string = connection_string or os.getenv("SNITCH_DATABASE_URL")
        self._connection: Any = None

    def __enter__(self) -> "Pg0":
        if not self.connection_string:
            raise Pg0Error(
                "SNITCH_DATABASE_URL is required; no fallback credentials are used."
            )

        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise Pg0Error(
                "psycopg is required; install the project dependencies first."
            ) from exc

        self._connection = psycopg.connect(
            self.connection_string,
            row_factory=dict_row,
            autocommit=True,
        )
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if self._connection is None:
            return

        self._connection.close()
        self._connection = None

    def _require_connection(self) -> Any:
        if self._connection is None:
            raise Pg0Error("Pg0 must be used as an active context manager.")
        return self._connection

    def execute(
        self,
        statement: str,
        parameters: Iterable[Any] | None = None,
    ) -> int:
        connection = self._require_connection()
        with connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            return cursor.rowcount

    def query(
        self,
        statement: str,
        parameters: Iterable[Any] | None = None,
    ) -> list[dict[str, Any]]:
        connection = self._require_connection()
        with connection.cursor() as cursor:
            cursor.execute(statement, parameters)
            return list(cursor.fetchall())
