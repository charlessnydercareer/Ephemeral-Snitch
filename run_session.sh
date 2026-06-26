#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_DIR="${SNITCH_LOG_DIR:-${SCRIPT_DIR}/logs}"

if [[ -z "${SNITCH_WRITER_DATABASE_URL:-}" ]] ||
   [[ -z "${SNITCH_READER_DATABASE_URL:-}" ]]; then
    echo "Snitch database configuration is unavailable." >&2
    exit 2
fi

mkdir -p "${LOG_DIR}"
chmod 700 "${LOG_DIR}"

exec "${SCRIPT_DIR}/snitch-run" writer \
    "${SCRIPT_DIR}/.venv/bin/python" "${SCRIPT_DIR}/reduction_sweep.py" \
    --source-dir "${LOG_DIR}" \
    "$@"
