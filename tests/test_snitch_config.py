from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from snitch_config import (
    DEFAULT_AUDIT_DIR,
    READER_URL_VAR,
    WRITER_URL_VAR,
    default_audit_dir,
    ensure_snitch_database_env,
    load_secret,
)
from snitch_run_secret import main as run_secret_main


class SnitchConfigTests(unittest.TestCase):
    def test_load_secret_prefers_environment(self) -> None:
        with patch.dict(os.environ, {"SNITCH_WRITER_DATABASE_URL": "env-value"}):
            self.assertEqual(load_secret("SNITCH_WRITER_DATABASE_URL"), "env-value")

    def test_load_secret_uses_jarvis_secret_when_env_missing(self) -> None:
        js_cmd = Path("/tmp/jarvis-secret-test")
        with (
            patch.dict(os.environ, {}, clear=True),
            patch(
                "snitch_config.resolve_jarvis_secret_cmd",
                return_value=js_cmd,
            ),
            patch(
                "subprocess.check_output",
                return_value="secret-value\n",
            ) as check_output,
        ):
            self.assertEqual(load_secret("SNITCH_WRITER_DATABASE_URL"), "secret-value")
            check_output.assert_called_once_with(
                [str(js_cmd), "get", "SNITCH_WRITER_DATABASE_URL"],
                text=True,
            )

    def test_load_secret_fails_closed_without_env_or_jarvis_secret(self) -> None:
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("snitch_config.resolve_jarvis_secret_cmd", return_value=None),
        ):
            with self.assertRaisesRegex(RuntimeError, "jarvis-secret is unavailable"):
                load_secret("SNITCH_WRITER_DATABASE_URL")

    def test_ensure_snitch_database_env_populates_both_urls(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with patch(
                "snitch_config.load_secret",
                side_effect=lambda name: f"loaded:{name}",
            ):
                ensure_snitch_database_env()
            self.assertEqual(
                os.environ[WRITER_URL_VAR],
                f"loaded:{WRITER_URL_VAR}",
            )
            self.assertEqual(
                os.environ[READER_URL_VAR],
                f"loaded:{READER_URL_VAR}",
            )

    def test_ensure_snitch_database_env_preserves_existing_values(self) -> None:
        with patch.dict(
            os.environ,
            {
                WRITER_URL_VAR: "writer-existing",
                READER_URL_VAR: "reader-existing",
            },
            clear=True,
        ):
            with patch("snitch_config.load_secret") as load_secret:
                ensure_snitch_database_env()
            load_secret.assert_not_called()
            self.assertEqual(os.environ[WRITER_URL_VAR], "writer-existing")
            self.assertEqual(os.environ[READER_URL_VAR], "reader-existing")

    def test_default_audit_dir_uses_evecor_audits_path(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(default_audit_dir(), DEFAULT_AUDIT_DIR)

    def test_default_audit_dir_honors_override(self) -> None:
        with patch.dict(os.environ, {"SNITCH_AUDIT_DIR": "/tmp/custom-audits"}):
            self.assertEqual(default_audit_dir(), Path("/tmp/custom-audits"))


class SnitchRunSecretTests(unittest.TestCase):
    def test_run_secret_exits_when_database_configuration_unavailable(self) -> None:
        with (
            patch(
                "snitch_run_secret.ensure_snitch_database_env",
                side_effect=RuntimeError("missing"),
            ),
            self.assertRaises(SystemExit) as ctx,
        ):
            run_secret_main()
        self.assertEqual(ctx.exception.code, 1)

    def test_run_secret_execs_snitch_run_after_loading_env(self) -> None:
        with (
            patch("snitch_run_secret.ensure_snitch_database_env"),
            patch("os.execv") as execv,
        ):
            run_secret_main()
        snitch_run = Path(__file__).resolve().parents[1] / "snitch-run"
        execv.assert_called_once()
        self.assertEqual(execv.call_args.args[0], str(snitch_run))


if __name__ == "__main__":
    unittest.main()
