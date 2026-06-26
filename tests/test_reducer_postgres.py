from __future__ import annotations

import json
import os
import stat
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
    "disposable reducer database URLs are not configured",
)
class ReducerPostgresIntegrationTests(unittest.TestCase):
    def run_reducer(self, source_dir: Path) -> subprocess.CompletedProcess[str]:
        environment = {
            **os.environ,
            "SNITCH_WRITER_DATABASE_URL": WRITER_URL,
            "SNITCH_READER_DATABASE_URL": READER_URL,
            "SNITCH_LOG_DIR": str(source_dir),
        }
        return subprocess.run(
            [str(ROOT / "run_session.sh"), "--once"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_real_launcher_reducer_quarantine_and_duplicate_flow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source_dir = Path(temp_dir)
            malformed = source_dir / "a.ready.json"
            valid = source_dir / "b.ready.json"
            malformed.write_text("{broken", encoding="utf-8")
            valid.write_text(
                json.dumps(
                    {
                        "seq_id": "integration-trace-001",
                        "timestamp": "2026-06-25T00:00:00+00:00",
                        "command_count": 1,
                    }
                ),
                encoding="utf-8",
            )

            first = self.run_reducer(source_dir)
            self.assertEqual(first.returncode, 0, first.stderr)
            malformed_quarantine = source_dir / "a.ready.json.malformed"
            self.assertTrue(malformed_quarantine.exists())
            self.assertEqual(
                stat.S_IMODE(malformed_quarantine.stat().st_mode),
                0o600,
            )
            self.assertFalse(valid.exists())

            duplicate = source_dir / "duplicate.ready.json"
            duplicate.write_text(
                json.dumps(
                    {
                        "seq_id": "integration-trace-001",
                        "timestamp": "2026-06-25T00:00:00+00:00",
                        "command_count": 1,
                    }
                ),
                encoding="utf-8",
            )
            second = self.run_reducer(source_dir)
            self.assertEqual(second.returncode, 0, second.stderr)
            duplicate_quarantine = source_dir / "duplicate.ready.json.duplicate"
            self.assertTrue(duplicate_quarantine.exists())
            self.assertEqual(
                stat.S_IMODE(duplicate_quarantine.stat().st_mode),
                0o600,
            )

        with psycopg.connect(READER_URL) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT count(*)
                    FROM snitch.trace_records
                    WHERE request_id = %s
                    """,
                    ("integration-trace-001",),
                )
                self.assertEqual(cursor.fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
