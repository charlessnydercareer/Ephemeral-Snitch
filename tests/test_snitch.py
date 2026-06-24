from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pg0 import Pg0, Pg0Error
from reduction_sweep import (
    MonoidReductionSweeper,
    TraceValidationError,
    validate_trace,
)
from snitch_daemon import (
    secure_jsonl_write,
    snapshot_events,
    validate_session_id as validate_daemon_session_id,
)
from snitch_processor import (
    payload_for_storage,
    provider_for_host,
    secure_json_write,
    validate_session_id as validate_processor_session_id,
)


class Pg0Tests(unittest.TestCase):
    def test_missing_database_url_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(Pg0Error, "SNITCH_DATABASE_URL"):
                with Pg0():
                    pass


class TraceTests(unittest.TestCase):
    def test_trace_normalization_is_deterministic(self) -> None:
        payload = {
            "seq_id": "session-1",
            "timestamp": "2026-06-24T12:00:00+00:00",
            "command_string": "git status",
            "affected_files_count": 2,
            "command_count": 1,
        }
        first = validate_trace(payload)
        second = validate_trace(dict(reversed(list(payload.items()))))
        self.assertEqual(first, second)
        self.assertRegex(first["event_hash"], r"^sha256:[a-f0-9]{64}$")
        self.assertRegex(first["command_hash"], r"^sha256:[a-f0-9]{64}$")
        self.assertNotIn("command_string", first)

    def test_trace_rejects_negative_counts(self) -> None:
        with self.assertRaises(TraceValidationError):
            validate_trace(
                {
                    "seq_id": "bad",
                    "timestamp": "now",
                    "affected_files_count": -1,
                }
            )

    def test_reducer_deletes_source_only_after_successful_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace.ready.json"
            trace_path.write_text(
                json.dumps(
                    {
                        "seq_id": "session-1",
                        "timestamp": "2026-06-24T12:00:00+00:00",
                        "command_count": 1,
                    }
                ),
                encoding="utf-8",
            )
            pool = FakePool()
            sweeper = MonoidReductionSweeper(
                "test-connection",
                temp_dir,
                pool_factory=lambda **_: pool,
            )
            sweeper.process_reduction_sweep()
            self.assertFalse(trace_path.exists())
            self.assertTrue(pool.connection_instance.transaction_committed)

    def test_reducer_retains_source_when_transaction_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            trace_path = Path(temp_dir) / "trace.ready.json"
            trace_path.write_text(
                json.dumps(
                    {
                        "seq_id": "session-1",
                        "timestamp": "2026-06-24T12:00:00+00:00",
                    }
                ),
                encoding="utf-8",
            )
            pool = FakePool(fail_insert=True)
            sweeper = MonoidReductionSweeper(
                "test-connection",
                temp_dir,
                pool_factory=lambda **_: pool,
            )
            sweeper.process_reduction_sweep()
            self.assertTrue(trace_path.exists())
            self.assertFalse(pool.connection_instance.transaction_committed)


class DaemonTests(unittest.TestCase):
    def test_session_id_rejects_path_traversal(self) -> None:
        for validator in (
            validate_daemon_session_id,
            validate_processor_session_id,
        ):
            with self.assertRaises(ValueError):
                validator("../../escape")

    def test_snapshot_events_detect_changes(self) -> None:
        previous = {"/a": (1, 1), "/b": (1, 1)}
        current = {"/a": (2, 1), "/c": (1, 1)}
        self.assertEqual(
            snapshot_events(previous, current),
            [
                ("CREATE", "/c"),
                ("DELETE", "/b"),
                ("MODIFY", "/a"),
            ],
        )

    def test_jsonl_export_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "export.jsonl"
            secure_jsonl_write(path, [{"session_id": "one"}])
            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"session_id": "one"},
            )


class ProcessorTests(unittest.TestCase):
    def test_provider_matching_rejects_substring_spoof(self) -> None:
        self.assertEqual(provider_for_host("api.openai.com"), "openai")
        self.assertEqual(
            provider_for_host("generativelanguage.googleapis.com"),
            "gemini",
        )
        self.assertIsNone(provider_for_host("openai.com.attacker.example"))
        self.assertIsNone(provider_for_host("notopenai.com"))

    def test_metadata_only_is_default_safe_shape(self) -> None:
        payload = {
            "model": "example-model",
            "messages": [
                {"role": "system", "content": "private policy"},
                {"role": "user", "content": "private prompt"},
            ],
            "api_key": "secret-value",
        }
        stored = payload_for_storage(payload, capture_content=False)
        self.assertEqual(stored["model"], "example-model")
        self.assertEqual(stored["message_count"], 2)
        self.assertNotIn("messages", stored)
        self.assertNotIn("api_key", stored)

    def test_content_capture_redacts_sensitive_fields_and_system_messages(self) -> None:
        payload = {
            "messages": [
                {"role": "system", "content": "private policy"},
                {"role": "user", "content": "allowed only with consent"},
            ],
            "authorization": "secret-value",
            "nested": {"access_token": "secret-value"},
        }
        stored = payload_for_storage(payload, capture_content=True)
        self.assertEqual(stored["authorization"], "[REDACTED]")
        self.assertEqual(stored["nested"]["access_token"], "[REDACTED]")
        self.assertEqual(len(stored["messages"]), 1)
        self.assertEqual(stored["messages"][0]["role"], "user")

    def test_json_export_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "export.json"
            secure_json_write(path, [{"safe": True}])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


class FakeCursor:
    def __init__(self, *, fail_insert: bool = False) -> None:
        self.fail_insert = fail_insert
        self.rowcount = 0

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object = None) -> None:
        if "INSERT INTO" in statement:
            if self.fail_insert:
                raise RuntimeError("simulated insert failure")
            self.rowcount = 1

    def fetchone(self) -> tuple[str] | None:
        return None


class FakeTransaction:
    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection

    def __enter__(self) -> "FakeTransaction":
        return self

    def __exit__(self, exc_type: object, *args: object) -> None:
        self.connection.transaction_committed = exc_type is None


class FakeConnection:
    def __init__(self, *, fail_insert: bool = False) -> None:
        self.fail_insert = fail_insert
        self.transaction_committed = False

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def transaction(self) -> FakeTransaction:
        return FakeTransaction(self)

    def cursor(self) -> FakeCursor:
        return FakeCursor(fail_insert=self.fail_insert)


class FakePool:
    def __init__(self, *, fail_insert: bool = False) -> None:
        self.connection_instance = FakeConnection(fail_insert=fail_insert)

    def connection(self) -> FakeConnection:
        return self.connection_instance

    def close(self) -> None:
        return None


if __name__ == "__main__":
    unittest.main()
