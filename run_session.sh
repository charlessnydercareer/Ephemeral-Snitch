#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
LOG_DIR="${SNITCH_LOG_DIR:-${SCRIPT_DIR}/logs}"

if [[ -z "${SNITCH_DATABASE_URL:-}" ]]; then
    echo "SNITCH_DATABASE_URL is required; load it from the approved secret store." >&2
    exit 2
fi

mkdir -p "${LOG_DIR}"
chmod 700 "${LOG_DIR}"

exec "${PYTHON_BIN}" "${SCRIPT_DIR}/reduction_sweep.py" \
    --source-dir "${LOG_DIR}" \
    "$@"
