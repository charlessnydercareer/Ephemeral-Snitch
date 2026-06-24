"""Reduce completed Snitch trace files into an immutable PostgreSQL ledger."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from psycopg_pool import ConnectionPool
except ImportError:  # pragma: no cover - exercised by the CLI environment
    ConnectionPool = None  # type: ignore[assignment]


DEFAULT_LOG_DIR = Path(__file__).resolve().parent / "logs"
DEFAULT_SWEEP_INTERVAL_SEC = 1.0
HASH_PREFIX = "sha256:"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (reduction_sweep) %(message)s",
)
logger = logging.getLogger("snitch.reduction_sweep")


class TraceValidationError(ValueError):
    pass


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def validate_trace(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TraceValidationError("trace must be a JSON object")

    seq_id = payload.get("seq_id")
    if not isinstance(seq_id, str) or not seq_id.strip() or len(seq_id) > 256:
        raise TraceValidationError("seq_id must be a non-empty string <= 256 chars")

    command_string = payload.get("command_string")
    if command_string is not None and not isinstance(command_string, str):
        raise TraceValidationError("command_string must be a string or null")

    normalized: dict[str, Any] = {
        "seq_id": seq_id,
        "command_hash": (
            HASH_PREFIX + hashlib.sha256(command_string.encode("utf-8")).hexdigest()
            if command_string is not None
            else None
        ),
        "timestamp": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "affected_files_count": payload.get("affected_files_count", 0),
        "command_count": payload.get("command_count", 0),
    }

    for field in ("affected_files_count", "command_count"):
        value = normalized[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TraceValidationError(f"{field} must be a non-negative integer")

    timestamp = normalized["timestamp"]
    if not isinstance(timestamp, str) or not timestamp:
        raise TraceValidationError("timestamp must be a non-empty string")

    normalized["event_hash"] = (
        HASH_PREFIX + hashlib.sha256(canonical_json(normalized)).hexdigest()
    )
    return normalized


def quarantine(path: Path, suffix: str) -> Path:
    target = path.with_suffix(path.suffix + suffix)
    counter = 1
    while target.exists():
        target = path.with_suffix(path.suffix + f"{suffix}.{counter}")
        counter += 1
    path.replace(target)
    target.chmod(0o600)
    return target


class MonoidReductionSweeper:
    def __init__(
        self,
        connection_string: str,
        source_dir: str | Path,
        *,
        pool_factory: Any = None,
    ) -> None:
        if not connection_string:
            raise ValueError("SNITCH_DATABASE_URL is required")
        if ConnectionPool is None and pool_factory is None:
            raise RuntimeError(
                "psycopg_pool is required; install the project dependencies first."
            )

        self.source_dir = Path(source_dir).resolve()
        self.source_dir.mkdir(parents=True, exist_ok=True)
        self.source_dir.chmod(0o700)
        factory = pool_factory or ConnectionPool
        self.pool = factory(
            conninfo=connection_string,
            min_size=1,
            max_size=4,
        )

    def close(self) -> None:
        self.pool.close()

    def start_sync_loop(self, interval: float = DEFAULT_SWEEP_INTERVAL_SEC) -> None:
        logger.info("Starting immutable Snitch reduction loop.")
        try:
            while True:
                self.process_reduction_sweep()
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Termination signal received.")
        finally:
            self.close()

    def process_reduction_sweep(self) -> None:
        for file_path in sorted(self.source_dir.glob("*.ready.json")):
            self._process_file(file_path)

    def _process_file(self, file_path: Path) -> None:
        try:
            with file_path.open("r", encoding="utf-8") as handle:
                trace = validate_trace(json.load(handle))
        except (OSError, json.JSONDecodeError, TraceValidationError) as exc:
            target = quarantine(file_path, ".malformed")
            logger.error("Quarantined malformed trace %s: %s", target.name, exc)
            return

        try:
            with self.pool.connection() as connection:
                with connection.transaction():
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            INSERT INTO public.snitch_wal_ledger (
                                seq_id,
                                timestamp,
                                command_hash,
                                affected_files_count,
                                command_count,
                                event_hash
                            ) VALUES (%s, %s, %s, %s, %s, %s)
                            ON CONFLICT (seq_id) DO NOTHING
                            """,
                            (
                                trace["seq_id"],
                                trace["timestamp"],
                                trace["command_hash"],
                                trace["affected_files_count"],
                                trace["command_count"],
                                trace["event_hash"],
                            ),
                        )
                        inserted = cursor.rowcount == 1
                        if not inserted:
                            cursor.execute(
                                """
                                SELECT event_hash
                                FROM public.snitch_wal_ledger
                                WHERE seq_id = %s
                                """,
                                (trace["seq_id"],),
                            )
                            existing = cursor.fetchone()
                            if not existing or existing[0] != trace["event_hash"]:
                                raise RuntimeError(
                                    "seq_id collision with different trace content"
                                )
        except Exception as exc:
            logger.error("Trace %s was not committed: %s", file_path.name, exc)
            return

        try:
            file_path.unlink()
        except OSError as exc:
            logger.warning(
                "Trace committed but source cleanup failed for %s: %s",
                file_path.name,
                exc,
            )
            return

        action = "inserted" if inserted else "already present"
        logger.info("Trace %s: %s", file_path.name, action)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-dir",
        default=os.getenv("SNITCH_LOG_DIR", str(DEFAULT_LOG_DIR)),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=float(
            os.getenv(
                "SNITCH_SWEEP_INTERVAL_SEC",
                str(DEFAULT_SWEEP_INTERVAL_SEC),
            )
        ),
    )
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    connection_string = os.getenv("SNITCH_DATABASE_URL")
    if not connection_string:
        raise SystemExit("SNITCH_DATABASE_URL is required")

    sweeper = MonoidReductionSweeper(connection_string, args.source_dir)
    if args.once:
        try:
            sweeper.process_reduction_sweep()
        finally:
            sweeper.close()
        return 0

    sweeper.start_sync_loop(args.interval)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
