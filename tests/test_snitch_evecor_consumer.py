from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from snitch_config import (
    DEFAULT_AUDIT_DIR,
    READER_URL_VAR,
    WRITER_URL_VAR,
    evecor_consumer_audit_dir,
    require_snitch_secrets_available,
    validate_evecor_consumer_audit_dir,
)
from snitch_evecor_consumer import main as evecor_main


class EvecorConsumerConfigTests(unittest.TestCase):
    def test_evecor_consumer_audit_dir_is_fixed(self) -> None:
        with patch.dict(os.environ, {"SNITCH_AUDIT_DIR": "/tmp/elsewhere"}):
            self.assertEqual(evecor_consumer_audit_dir(), DEFAULT_AUDIT_DIR)

    def test_validate_evecor_consumer_audit_dir_rejects_override(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be written only to"):
            validate_evecor_consumer_audit_dir("/tmp/custom-audits")

    def test_validate_evecor_consumer_audit_dir_accepts_default(self) -> None:
        self.assertEqual(
            validate_evecor_consumer_audit_dir(DEFAULT_AUDIT_DIR),
            DEFAULT_AUDIT_DIR.resolve(),
        )

    def test_require_snitch_secrets_available_fails_closed(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("snitch_config.resolve_jarvis_secret_cmd", return_value=None),
        ):
            with self.assertRaisesRegex(RuntimeError, "jarvis-secret is unavailable"):
                require_snitch_secrets_available()

    def test_require_snitch_secrets_available_loads_both_urls(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with patch(
                "snitch_config.load_secret",
                side_effect=lambda name: f"loaded:{name}",
            ) as load_secret:
                require_snitch_secrets_available()
            self.assertEqual(load_secret.call_count, 2)
            load_secret.assert_any_call(WRITER_URL_VAR)
            load_secret.assert_any_call(READER_URL_VAR)


class EvecorConsumerFinalizeTests(unittest.TestCase):
    def _claims(self) -> dict[str, object]:
        return {
            "session_id": "evecor-consumer-001",
            "request_id": "req_b1c2d3e4f5061728394a5b6c7d8e9f01",
            "agent": "cursor",
            "model_or_tool": "auto",
            "commands_claimed": [],
            "tests_claimed": [],
            "artifacts_written": [],
            "failures": [],
            "blockers": [],
            "deferred_work": [],
            "risk_flags": [],
        }

    def test_finalize_writes_audit_with_0600_permissions(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            claims_path = Path(temp_dir) / "claims.json"
            claims_path.write_text(json.dumps(self._claims()), encoding="utf-8")
            records_dir = Path(temp_dir) / "records"
            reservations_dir = Path(temp_dir) / "reservations"
            audit_dir = Path(temp_dir) / "audits"
            argv = [
                "snitch_evecor_consumer.py",
                "--input",
                str(claims_path),
                "--repo",
                str(project_root),
                "--records-dir",
                str(records_dir),
                "--reservations-dir",
                str(reservations_dir),
            ]
            with (
                patch.dict(os.environ, {}, clear=True),
                patch(
                    "snitch_evecor_consumer.require_snitch_secrets_available",
                ),
                patch(
                    "snitch_evecor_consumer.evecor_consumer_audit_dir",
                    return_value=audit_dir,
                ),
                patch(
                    "snitch_evecor_consumer.validate_evecor_consumer_audit_dir",
                    return_value=audit_dir.resolve(),
                ),
                patch("sys.argv", argv),
            ):
                self.assertEqual(evecor_main(), 0)

            audit_path = audit_dir / "snitch_evecor-consumer-001.md"
            self.assertTrue(audit_path.is_file())
            self.assertEqual(stat.S_IMODE(audit_path.stat().st_mode), 0o600)

    def test_finalize_fails_closed_when_secrets_missing(self) -> None:
        with (
            patch(
                "snitch_evecor_consumer.require_snitch_secrets_available",
                side_effect=RuntimeError("missing"),
            ),
            patch("sys.argv", ["snitch_evecor_consumer.py"]),
        ):
            self.assertEqual(evecor_main(), 1)


if __name__ == "__main__":
    unittest.main()
