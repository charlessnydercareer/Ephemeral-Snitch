#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
LOG_DIR="${SNITCH_LOG_DIR:-${SCRIPT_DIR}/logs}"

mkdir -p "${LOG_DIR}"
chmod 700 "${LOG_DIR}"

exec "${SCRIPT_DIR}/snitch-run-secret" writer \
    "${SCRIPT_DIR}/.venv/bin/python" "${SCRIPT_DIR}/reduction_sweep.py" \
    --source-dir "${LOG_DIR}" \
    "$@"
