"""Shared Snitch configuration: secrets, paths, and jarvis-secret resolution."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

WRITER_URL_VAR = "SNITCH_WRITER_DATABASE_URL"
READER_URL_VAR = "SNITCH_READER_DATABASE_URL"
DATABASE_URL_VARS = (WRITER_URL_VAR, READER_URL_VAR)

DEFAULT_AUDIT_DIR = Path("/mnt/jarvis-data/projects/Audits/snitch")
DEFAULT_RECORDS_DIR = Path("artifacts/sessions")
DEFAULT_RESERVATIONS_DIR = Path("artifacts/reservations")


def resolve_jarvis_secret_cmd() -> Path | None:
    """Return the jarvis-secret executable when available."""
    candidates = (
        Path.home() / ".local/bin/jarvis-secret",
        Path("/mnt/jarvis-data/projects/nexus/scripts/jarvis-secret"),
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def load_secret(env_var: str) -> str:
    """Load a secret from the environment or jarvis-secret."""
    value = os.environ.get(env_var)
    if value:
        return value.strip()

    js_cmd = resolve_jarvis_secret_cmd()
    if js_cmd is None:
        raise RuntimeError(f"{env_var} is not set and jarvis-secret is unavailable")

    try:
        return subprocess.check_output(
            [str(js_cmd), "get", env_var],
            text=True,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"{env_var} is missing and jarvis-secret lookup failed"
        ) from exc


def ensure_snitch_database_env() -> None:
    """Populate writer and reader database URLs when absent."""
    for env_var in DATABASE_URL_VARS:
        if not os.environ.get(env_var, "").strip():
            os.environ[env_var] = load_secret(env_var)


def default_audit_dir() -> Path:
    """Operator audit directory for Snitch session summaries."""
    override = os.environ.get("SNITCH_AUDIT_DIR")
    if override:
        return Path(override).expanduser()
    return DEFAULT_AUDIT_DIR


def default_records_dir() -> Path:
    override = os.environ.get("SNITCH_RECORDS_DIR")
    if override:
        return Path(override).expanduser()
    return DEFAULT_RECORDS_DIR


def default_reservations_dir() -> Path:
    override = os.environ.get("SNITCH_RESERVATIONS_DIR")
    if override:
        return Path(override).expanduser()
    return DEFAULT_RESERVATIONS_DIR


def evecor_consumer_audit_dir() -> Path:
    """Fixed operator audit directory for EVECOR Snitch consumers."""
    return DEFAULT_AUDIT_DIR


def validate_evecor_consumer_audit_dir(path: str | Path) -> Path:
    """Reject audit destinations outside the EVECOR operator path."""
    resolved = Path(path).expanduser().resolve()
    expected = DEFAULT_AUDIT_DIR.resolve()
    if resolved != expected:
        raise ValueError(
            f"EVECOR Snitch audits must be written only to {expected}"
        )
    return expected


def require_snitch_secrets_available() -> None:
    """Fail closed when writer or reader database URLs cannot be resolved."""
    for env_var in DATABASE_URL_VARS:
        value = load_secret(env_var)
        if not value.strip():
            raise RuntimeError(f"{env_var} is empty")
