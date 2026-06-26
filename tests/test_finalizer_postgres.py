from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import psycopg


WRITER_URL = os.getenv("SNITCH_TEST_WRITER_DATABASE_URL")
READER_URL = os.getenv("SNITCH_TEST_READER_DATABASE_URL")
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    WRITER_URL and READER_URL,
    "disposable finalizer database URLs are not configured",
)
class FinalizerPostgresIntegrationTests(unittest.TestCase):
    def test_opt_in_finalizer_persists_after_local_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(
                ["git", "init", "-b", "main"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
            )
            (repo / "README.md").write_text("baseline\n", encoding="utf-8")
            git_environment = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Snitch Test",
                "GIT_AUTHOR_EMAIL": "snitch@example.invalid",
                "GIT_COMMITTER_NAME": "Snitch Test",
                "GIT_COMMITTER_EMAIL": "snitch@example.invalid",
            }
            subprocess.run(
                ["git", "add", "README.md"],
                cwd=repo,
                env=git_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "commit", "-m", "baseline"],
                cwd=repo,
                env=git_environment,
                check=True,
                capture_output=True,
                text=True,
            )
            claims = root / "claims.json"
            claims.write_text(
                json.dumps(
                    {
                        "session_id": "postgres-finalizer-session",
                        "request_id": "req_5555555555555555",
                        "agent": "test-agent",
                        "model_or_tool": "test-tool",
                    }
                ),
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
                "SNITCH_READER_DATABASE_URL": READER_URL,
                "SNITCH_RECORDS_DIR": str(root / "sessions"),
                "SNITCH_RESERVATIONS_DIR": str(root / "reservations"),
                "SNITCH_AUDIT_DIR": str(root / "audits"),
            }
            completed = subprocess.run(
                [
                    str(ROOT / "snitch-run"),
                    "writer",
                    str(ROOT / ".venv" / "bin" / "python"),
                    str(ROOT / "snitch_session.py"),
                    "--input",
                    str(claims),
                    "--repo",
                    str(repo),
                    "--persist-postgres",
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            output = json.loads(completed.stdout)
            self.assertEqual(len(output["postgres_event_id"]), 64)
            self.assertTrue(Path(output["record"]).exists())
            self.assertTrue(Path(output["digest"]).exists())
            self.assertTrue(Path(output["audit"]).exists())

            with psycopg.connect(READER_URL) as connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT event_id, request_id
                        FROM snitch.session_records
                        WHERE session_id = %s
                        """,
                        ("postgres-finalizer-session",),
                    )
                    self.assertEqual(
                        cursor.fetchone(),
                        (
                            output["postgres_event_id"],
                            "req_5555555555555555",
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
