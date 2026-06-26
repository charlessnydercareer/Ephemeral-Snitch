from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from psycopg import errors

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from pg0 import Pg0, Pg0Error
from reduction_sweep import (
    MonoidReductionSweeper,
    TraceValidationError,
    validate_trace,
)
from session_record import (
    REQUIRED_FIELDS,
    RequestIdCollisionError,
    SessionRecordError,
    build_record,
    make_evidence_receipt,
    redact_value,
    record_digest,
    validate_record,
    verify_evidence_receipt,
    write_session_artifacts,
)
from snitch_daemon import (
    secure_jsonl_write,
    snapshot_events,
    validate_session_id as validate_daemon_session_id,
)
from snitch_processor import (
    provider_for_host,
    request_summary,
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

    def test_malformed_trace_is_private_and_does_not_block_valid_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            malformed = Path(temp_dir) / "a.ready.json"
            valid = Path(temp_dir) / "b.ready.json"
            malformed.write_text("{broken", encoding="utf-8")
            valid.write_text(
                json.dumps(
                    {
                        "seq_id": "session-valid",
                        "timestamp": "2026-06-24T12:00:00+00:00",
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

            quarantined = Path(temp_dir) / "a.ready.json.malformed"
            self.assertTrue(quarantined.exists())
            self.assertEqual(stat.S_IMODE(quarantined.stat().st_mode), 0o600)
            self.assertFalse(valid.exists())

    def test_duplicate_trace_is_quarantined_and_loop_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            duplicate = Path(temp_dir) / "a.ready.json"
            valid = Path(temp_dir) / "b.ready.json"
            for path, seq_id in (
                (duplicate, "duplicate"),
                (valid, "valid"),
            ):
                path.write_text(
                    json.dumps(
                        {
                            "seq_id": seq_id,
                            "timestamp": "2026-06-24T12:00:00+00:00",
                        }
                    ),
                    encoding="utf-8",
                )
            pool = FakePool(fail_once=errors.UniqueViolation("duplicate"))
            sweeper = MonoidReductionSweeper(
                "test-connection",
                temp_dir,
                pool_factory=lambda **_: pool,
            )

            sweeper.process_reduction_sweep()

            quarantined = Path(temp_dir) / "a.ready.json.duplicate"
            self.assertTrue(quarantined.exists())
            self.assertEqual(stat.S_IMODE(quarantined.stat().st_mode), 0o600)
            self.assertFalse(valid.exists())


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

    def test_proxy_only_exposes_metadata_summary(self) -> None:
        payload = {
            "model": "example-model",
            "messages": [
                {"role": "system", "content": "private policy"},
                {"role": "user", "content": "private prompt"},
            ],
            "api_key": "secret-value",
        }
        stored = request_summary(payload)
        self.assertEqual(stored["model"], "example-model")
        self.assertEqual(stored["message_count"], 2)
        self.assertNotIn("messages", stored)
        self.assertNotIn("api_key", stored)

    def test_json_export_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "export.json"
            secure_json_write(path, [{"safe": True}])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


class SessionRecordTests(unittest.TestCase):
    def test_public_schema_matches_required_contract(self) -> None:
        schema_path = (
            Path(__file__).resolve().parents[1]
            / "schemas"
            / "session_record.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(schema["required"], list(REQUIRED_FIELDS))
        self.assertEqual(schema["properties"]["content_capture"], {"const": False})
        for field in (
            "commands_verified",
            "tests_verified",
            "database_writes",
        ):
            self.assertEqual(
                schema["properties"][field]["items"]["$ref"],
                "#/$defs/evidenceReceipt",
            )

    def test_redaction_handles_keys_and_inline_secret_shapes(self) -> None:
        redacted = redact_value(
            {
                "token": "secret",
                "message": "Authorization: " + "Bearer " + "abc.def.ghi",
                "nested": {"database_url": "postgres" + "ql://user:pass@host/db"},
            }
        )
        self.assertEqual(redacted["token"], "[REDACTED]")
        self.assertNotIn("abc.def.ghi", redacted["message"])
        self.assertEqual(redacted["nested"]["database_url"], "[REDACTED]")

    def test_claims_cannot_supply_verified_evidence(self) -> None:
        with self.assertRaisesRegex(SessionRecordError, "unsupported fields"):
            build_record(
                {
                    "session_id": "session-1",
                    "request_id": "req_1111111111111111",
                    "agent": "agent",
                    "model_or_tool": "tool",
                    "tests_verified": ["fabricated"],
                },
                repo=Path(__file__).resolve().parents[1],
            )

    def test_build_record_separates_claims_from_evidence(self) -> None:
        command_receipt = make_evidence_receipt(
            "shell",
            {"command": "verified command", "exit": 0},
        )
        test_receipt = make_evidence_receipt(
            "test-runner",
            {"test": "verified test", "result": "passed"},
        )
        record = build_record(
            {
                "session_id": "session-1",
                "request_id": "req_1111111111111111",
                "agent": "agent",
                "model_or_tool": "tool",
                "commands_claimed": ["claimed command"],
                "tests_claimed": ["claimed test"],
            },
            repo=Path(__file__).resolve().parents[1],
            evidence={
                "commands_verified": [command_receipt],
                "tests_verified": [test_receipt],
            },
        )
        self.assertEqual(record["commands_claimed"], ["claimed command"])
        self.assertEqual(record["commands_verified"], [command_receipt])
        self.assertTrue(record["redaction_applied"])
        self.assertFalse(record["content_capture"])
        self.assertEqual(
            record["files_changed"],
            sorted(set(record["files_changed"])),
        )

    def test_unhashed_verified_evidence_is_rejected(self) -> None:
        with self.assertRaisesRegex(SessionRecordError, "receipt"):
            build_record(
                {
                    "session_id": "session-1",
                    "request_id": "req_1111111111111111",
                    "agent": "agent",
                    "model_or_tool": "tool",
                },
                repo=Path(__file__).resolve().parents[1],
                evidence={
                    "commands_verified": [
                        {"source": "shell", "observation": {"exit": 0}}
                    ]
                },
            )

    def test_tampered_evidence_receipt_is_rejected(self) -> None:
        receipt = make_evidence_receipt("shell", {"command": "safe", "exit": 0})
        receipt["observation"]["exit"] = 1
        with self.assertRaisesRegex(SessionRecordError, "does not match"):
            verify_evidence_receipt(receipt)

    def test_identical_claim_cannot_be_promoted_to_evidence(self) -> None:
        claim = {"command": "git status"}
        receipt = make_evidence_receipt("shell", dict(claim))
        with self.assertRaisesRegex(SessionRecordError, "canonically identical"):
            build_record(
                {
                    "session_id": "session-1",
                    "request_id": "req_1111111111111111",
                    "agent": "agent",
                    "model_or_tool": "tool",
                    "commands_claimed": [claim],
                },
                repo=Path(__file__).resolve().parents[1],
                evidence={"commands_verified": [receipt]},
            )

    def test_same_claim_object_cannot_be_reused_as_receipt(self) -> None:
        claim = make_evidence_receipt("shell", {"command": "git status"})
        with self.assertRaisesRegex(SessionRecordError, "reuses"):
            build_record(
                {
                    "session_id": "session-1",
                    "request_id": "req_1111111111111111",
                    "agent": "agent",
                    "model_or_tool": "tool",
                    "commands_claimed": [claim],
                },
                repo=Path(__file__).resolve().parents[1],
                evidence={"commands_verified": [claim]},
            )

    def test_record_digest_is_deterministic(self) -> None:
        record = self._record()
        self.assertEqual(
            record_digest(record),
            record_digest(dict(reversed(list(record.items())))),
        )

    def test_finalizer_cli_derives_git_evidence_and_refuses_overwrite(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            repo = root / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-b", "main"], cwd=repo, check=True)
            (repo / "tracked.txt").write_text("before\n", encoding="utf-8")
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Snitch Test",
                "GIT_AUTHOR_EMAIL": "snitch" + "@example.invalid",
                "GIT_COMMITTER_NAME": "Snitch Test",
                "GIT_COMMITTER_EMAIL": "snitch" + "@example.invalid",
            }
            subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True, env=env)
            subprocess.run(
                ["git", "commit", "-m", "baseline"],
                cwd=repo,
                check=True,
                env=env,
                stdout=subprocess.PIPE,
            )
            (repo / "tracked.txt").write_text("after\n", encoding="utf-8")

            claims_path = root / "claims.json"
            evidence_path = root / "evidence.json"
            claims_path.write_text(
                json.dumps(
                    {
                        "session_id": "cli-session",
                        "request_id": "REQ_2222222222222222",
                        "agent": "test-agent",
                        "model_or_tool": "test-tool",
                        "commands_claimed": ["claimed"],
                    }
                ),
                encoding="utf-8",
            )
            evidence_path.write_text(
                json.dumps(
                    {
                        "commands_verified": [
                            make_evidence_receipt(
                                "shell",
                                {"command": "verified", "exit_code": 0},
                            )
                        ]
                    }
                ),
                encoding="utf-8",
            )
            command = [
                sys.executable,
                str(project_root / "snitch_session.py"),
                "--input",
                str(claims_path),
                "--evidence",
                str(evidence_path),
                "--repo",
                str(repo),
                "--records-dir",
                str(root / "sessions"),
                "--audit-dir",
                str(root / "audits"),
                "--reservations-dir",
                str(root / "reservations"),
            ]
            first = subprocess.run(
                command,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            result = json.loads(first.stdout)
            record = json.loads(Path(result["record"]).read_text(encoding="utf-8"))
            self.assertEqual(record["files_changed"], ["tracked.txt"])
            self.assertEqual(record["branch"], "main")
            self.assertEqual(record["request_id"], "req_2222222222222222")
            self.assertEqual(len(record["commands_verified"]), 1)
            reservation = json.loads(
                Path(result["request_reservation"]).read_text(encoding="utf-8")
            )
            self.assertEqual(reservation["request_id"], record["request_id"])
            audit_text = Path(result["audit"]).read_text(encoding="utf-8")
            self.assertIn(
                "Request Correlation ID: `req_2222222222222222`",
                audit_text,
            )

            second = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("request_id collision", second.stderr)

    def test_validation_rejects_content_capture(self) -> None:
        record = self._record()
        record["content_capture"] = True
        with self.assertRaisesRegex(SessionRecordError, "content_capture"):
            validate_record(record)

    def test_persistence_failure_preserves_local_artifacts(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            claims_path = root / "claims.json"
            claims_path.write_text(
                json.dumps(
                    {
                        "session_id": "persist-failure",
                        "request_id": "req_3333333333333333",
                        "agent": "test-agent",
                        "model_or_tool": "test-tool",
                    }
                ),
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment.pop("SNITCH_WRITER_DATABASE_URL", None)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(project_root / "snitch_session.py"),
                    "--input",
                    str(claims_path),
                    "--repo",
                    str(project_root),
                    "--records-dir",
                    str(root / "sessions"),
                    "--audit-dir",
                    str(root / "audits"),
                    "--reservations-dir",
                    str(root / "reservations"),
                    "--persist-postgres",
                ],
                cwd=project_root,
                env=environment,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(
                completed.stderr,
                "CRITICAL: Session ledger persistence failed; "
                "local artifacts were preserved.\n",
            )
            self.assertTrue((root / "sessions" / "persist-failure.json").exists())
            self.assertTrue((root / "sessions" / "persist-failure.sha256").exists())
            self.assertTrue((root / "audits" / "snitch_persist-failure.md").exists())

    def test_artifact_write_is_private_and_refuses_overwrite(self) -> None:
        record = self._record()
        with tempfile.TemporaryDirectory() as temp_dir:
            result = write_session_artifacts(
                record,
                records_dir=Path(temp_dir) / "sessions",
                audit_dir=Path(temp_dir) / "audits",
            )
            for field in ("record", "digest", "audit"):
                path = Path(result[field])
                self.assertTrue(path.exists())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(RequestIdCollisionError):
                write_session_artifacts(
                    record,
                    records_dir=Path(temp_dir) / "sessions",
                    audit_dir=Path(temp_dir) / "audits",
                )

    def _record(self) -> dict[str, object]:
        return {
            "session_id": "session-1",
            "request_id": "req_1111111111111111",
            "agent": "agent",
            "model_or_tool": "tool",
            "repo": "repo",
            "branch": "main",
            "commit_before": "a" * 40,
            "commit_after": "b" * 40,
            "files_changed": ["README.md"],
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


class FakeCursor:
    def __init__(
        self,
        *,
        fail_insert: bool = False,
        fail_once: Exception | None = None,
    ) -> None:
        self.fail_insert = fail_insert
        self.fail_once = fail_once
        self.rowcount = 0

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, statement: str, parameters: object = None) -> None:
        if "INSERT INTO" in statement:
            if self.fail_once is not None:
                failure = self.fail_once
                self.fail_once = None
                raise failure
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
    def __init__(
        self,
        *,
        fail_insert: bool = False,
        fail_once: Exception | None = None,
    ) -> None:
        self.fail_insert = fail_insert
        self.fail_once = fail_once
        self.transaction_committed = False

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def transaction(self) -> FakeTransaction:
        return FakeTransaction(self)

    def cursor(self) -> FakeCursor:
        cursor = FakeCursor(
            fail_insert=self.fail_insert,
            fail_once=self.fail_once,
        )
        self.fail_once = None
        return cursor


class FakePool:
    def __init__(
        self,
        *,
        fail_insert: bool = False,
        fail_once: Exception | None = None,
    ) -> None:
        self.connection_instance = FakeConnection(
            fail_insert=fail_insert,
            fail_once=fail_once,
        )

    def connection(self) -> FakeConnection:
        return self.connection_instance

    def close(self) -> None:
        return None


if __name__ == "__main__":
    unittest.main()
