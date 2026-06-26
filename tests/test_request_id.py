from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from session_record import (
    RequestIdCollisionError,
    SessionRecordError,
    record_digest,
    reserve_request_id,
    validate_and_normalize_request_id,
)


class RequestIdContractTests(unittest.TestCase):
    def test_valid_formats_are_normalized_to_lowercase(self) -> None:
        uuid_value = "4A2B3C4D-5E6F-4A7B-8C9D-0E1F2A3B4C5D"
        req_value = "REQ_A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6"
        self.assertEqual(
            validate_and_normalize_request_id(uuid_value),
            uuid_value.lower(),
        )
        self.assertEqual(
            validate_and_normalize_request_id(req_value),
            req_value.lower(),
        )

    def test_invalid_formats_are_rejected(self) -> None:
        for value in (
            "",
            "invalid-uuid-format",
            "req_short",
            "req_not_hexadecimal",
            "4a2b3c4d-5e6f-3a7b-8c9d-0e1f2a3b4c5d",
            "4a2b3c4d-5e6f-4a7b-7c9d-0e1f2a3b4c5d",
        ):
            with self.subTest(value=value):
                with self.assertRaises(SessionRecordError):
                    validate_and_normalize_request_id(value)

    def test_persistent_cross_session_collision_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            request_id = "req_1234567890abcdef1234567890abcdef"
            first = reserve_request_id(
                temp_dir,
                request_id=request_id,
                session_id="session-001",
                record_sha256="a" * 64,
            )
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
            payload = json.loads(first.read_text(encoding="utf-8"))
            self.assertEqual(payload["session_id"], "session-001")

            with self.assertRaises(RequestIdCollisionError):
                reserve_request_id(
                    temp_dir,
                    request_id=request_id.upper(),
                    session_id="session-002",
                    record_sha256="b" * 64,
                )

    def test_request_id_changes_full_record_receipt(self) -> None:
        first = self._record("req_1111111111111111")
        second = self._record("req_2222222222222222")
        self.assertNotEqual(record_digest(first), record_digest(second))

    def _record(self, request_id: str) -> dict[str, object]:
        return {
            "session_id": "session-1",
            "request_id": request_id,
            "agent": "agent",
            "model_or_tool": "tool",
            "repo": "repo",
            "branch": "main",
            "commit_before": "a" * 40,
            "commit_after": "b" * 40,
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
