"""Mitmproxy addon that records privacy-preserving LLM request metadata."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from pg0 import Pg0

try:
    from mitmproxy import ctx
except ImportError:  # Allows static analysis and unit tests without mitmproxy.
    ctx = None  # type: ignore[assignment]


SESSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PROVIDER_SUFFIXES = {
    "openai": ("openai.com",),
    "anthropic": ("anthropic.com",),
    "gemini": ("generativelanguage.googleapis.com",),
    "google": ("googleapis.com", "google.com"),
}


def validate_session_id(session_id: str) -> str:
    if not SESSION_PATTERN.fullmatch(session_id):
        raise ValueError("invalid session_id")
    return session_id


def provider_for_host(host: str) -> str | None:
    normalized = host.lower().rstrip(".")
    for provider, suffixes in PROVIDER_SUFFIXES.items():
        if any(
            normalized == suffix or normalized.endswith("." + suffix)
            for suffix in suffixes
        ):
            return provider
    return None


def request_summary(payload: dict[str, Any]) -> dict[str, Any]:
    messages = payload.get("messages")
    if isinstance(messages, list):
        roles = [
            item.get("role")
            for item in messages
            if isinstance(item, dict) and isinstance(item.get("role"), str)
        ]
    else:
        roles = []

    model = payload.get("model")
    return {
        "model": model if isinstance(model, str) else None,
        "message_count": len(messages) if isinstance(messages, list) else 0,
        "roles": roles,
        "has_tools": isinstance(payload.get("tools"), list),
        "payload_sha256": hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest(),
    }


def secure_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, default=str, sort_keys=True)
            handle.write("\n")
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


class HindsightStyleSnitch:
    def __init__(self) -> None:
        self.session_id: str | None = None
        self.pg_server: Pg0 | None = None
        self.pg: Pg0 | None = None

    def load(self, loader: Any) -> None:
        loader.add_option(
            name="session_id",
            typespec=str,
            default="one_off_session",
            help="Session ID",
        )

    def configure(self, updated: set[str]) -> None:
        if "session_id" not in updated:
            return
        if ctx is None:
            raise RuntimeError("mitmproxy is required to run this addon")

        self.session_id = validate_session_id(ctx.options.session_id)
        self.pg_server = Pg0()
        self.pg = self.pg_server.__enter__()
        ctx.log.info("Snitch metadata tracking is active.")

    def request(self, flow: Any) -> None:
        if ctx is None or self.pg is None or self.session_id is None:
            return

        host = flow.request.pretty_host
        provider = provider_for_host(host)
        if provider is None:
            return

        try:
            raw = flow.request.get_text(strict=False)
            if len(raw.encode("utf-8")) > 1_000_000:
                raise ValueError("request payload exceeds 1 MB safety limit")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("request payload must be a JSON object")

            stored = request_summary(payload)
            self.pg.execute(
                """
                INSERT INTO public.snitch_intercepted_requests (
                    session_id,
                    provider,
                    host,
                    request_metadata
                ) VALUES (%s, %s, %s, %s)
                """,
                (
                    self.session_id,
                    provider,
                    host,
                    json.dumps(stored),
                ),
            )
            ctx.log.info("Recorded privacy-preserving request metadata.")
        except Exception as exc:
            ctx.log.error(f"Snitch request capture failed: {exc}")

    def done(self) -> None:
        try:
            if self.pg is None or self.session_id is None:
                return
            records = self.pg.query(
                """
                SELECT id, session_id, timestamp, provider, host, request_metadata
                FROM public.snitch_intercepted_requests
                WHERE session_id = %s
                ORDER BY id
                """,
                (self.session_id,),
            )
            export_path = (
                Path(tempfile.gettempdir())
                / f"snitch_telemetry_dump_{self.session_id}.json"
            )
            secure_json_write(export_path, records)
            if ctx is not None:
                ctx.log.info(f"Telemetry exported to {export_path}")
        except Exception as exc:
            if ctx is not None:
                ctx.log.error(f"Snitch export failed: {exc}")
        finally:
            if self.pg_server is not None:
                self.pg_server.__exit__(None, None, None)
            self.pg = None
            self.pg_server = None


addons = [HindsightStyleSnitch()]
