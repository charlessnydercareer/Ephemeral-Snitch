"""Record workspace file mutations for one explicitly named session."""

from __future__ import annotations

import argparse
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

from pg0 import Pg0

try:
    import inotify.adapters

    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False


SESSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
POLL_INTERVAL_SEC = 1.0


def validate_session_id(session_id: str) -> str:
    if not SESSION_PATTERN.fullmatch(session_id):
        raise ValueError(
            "session_id must use 1-128 letters, digits, dots, underscores, or dashes"
        )
    return session_id


def validate_workspace(workspace: str | Path) -> Path:
    path = Path(workspace).expanduser().resolve()
    if not path.is_dir():
        raise ValueError(f"workspace is not a directory: {path}")
    return path


def secure_jsonl_write(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, default=str, sort_keys=True) + "\n")
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def snapshot(workspace: Path) -> dict[str, tuple[int, int]]:
    state: dict[str, tuple[int, int]] = {}
    for root, directories, files in os.walk(workspace):
        directories[:] = [
            item
            for item in directories
            if item not in {".git", ".venv", "__pycache__", "node_modules"}
        ]
        for filename in files:
            path = Path(root) / filename
            try:
                stat = path.stat()
            except OSError:
                continue
            state[str(path)] = (stat.st_mtime_ns, stat.st_size)
    return state


def snapshot_events(
    previous: dict[str, tuple[int, int]],
    current: dict[str, tuple[int, int]],
) -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    for path in sorted(current.keys() - previous.keys()):
        events.append(("CREATE", path))
    for path in sorted(previous.keys() - current.keys()):
        events.append(("DELETE", path))
    for path in sorted(previous.keys() & current.keys()):
        if previous[path] != current[path]:
            events.append(("MODIFY", path))
    return events


def record_event(pg: Pg0, session_id: str, event_type: str, file_path: str) -> None:
    pg.execute(
        """
        INSERT INTO public.snitch_session_file_mutations (
            session_id,
            event_type,
            file_path,
            metadata
        ) VALUES (%s, %s, %s, %s)
        """,
        (
            session_id,
            event_type,
            file_path,
            json.dumps({"timestamp_ms": int(time.time() * 1000)}),
        ),
    )


def run_snitch(workspace: str, session_id: str) -> None:
    workspace_path = validate_workspace(workspace)
    safe_session_id = validate_session_id(session_id)
    dump_file = Path(tempfile.gettempdir()) / f"snitch_dump_{safe_session_id}.jsonl"

    print(f"Initializing file tracking for: {workspace_path}")

    with Pg0() as pg:

        def dump_logs() -> None:
            rows = pg.query(
                """
                SELECT id, session_id, timestamp, event_type, file_path, metadata
                FROM public.snitch_session_file_mutations
                WHERE session_id = %s
                ORDER BY id
                """,
                (safe_session_id,),
            )
            secure_jsonl_write(dump_file, rows)
            print(f"Session log exported to {dump_file}")

        try:
            if HAS_INOTIFY:
                watcher = inotify.adapters.InotifyTree(str(workspace_path))
                for event in watcher.event_gen(yield_nones=False):
                    _, type_names, path, filename = event
                    full_path = str(Path(path) / filename)
                    for event_type in type_names:
                        record_event(pg, safe_session_id, event_type, full_path)

            print("inotify is unavailable; using polling snapshots.")
            previous = snapshot(workspace_path)
            while True:
                time.sleep(POLL_INTERVAL_SEC)
                current = snapshot(workspace_path)
                for event_type, path in snapshot_events(previous, current):
                    record_event(pg, safe_session_id, event_type, path)
                previous = current
        except KeyboardInterrupt:
            return
        finally:
            dump_logs()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--session-id", required=True)
    args = parser.parse_args()

    try:
        run_snitch(args.workspace, args.session_id)
    except (ValueError, RuntimeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
