#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/compose.postgres-test.yml"
PROJECT_NAME="snitch-contract-${$}"
PYTHON="$ROOT/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
    echo "Project virtual environment is missing; run setup from README.md." >&2
    exit 2
fi

random_secret() {
    "$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(32))'
}

export SNITCH_TEST_BOOTSTRAP_PASSWORD
SNITCH_TEST_BOOTSTRAP_PASSWORD="$(random_secret)"
writer_password="$(random_secret)"
reader_password="$(random_secret)"

cleanup() {
    docker compose \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose \
    --project-name "$PROJECT_NAME" \
    --file "$COMPOSE_FILE" \
    up --detach --wait postgres >/dev/null

host_port="$(
    docker compose \
        --project-name "$PROJECT_NAME" \
        --file "$COMPOSE_FILE" \
        port postgres 5432 |
        awk -F: 'END {print $NF}'
)"

bootstrap_url="host=127.0.0.1 port=${host_port} dbname=snitch_test user=snitch_bootstrap password=${SNITCH_TEST_BOOTSTRAP_PASSWORD}"

docker compose \
    --project-name "$PROJECT_NAME" \
    --file "$COMPOSE_FILE" \
    exec --no-TTY postgres \
    psql --username snitch_bootstrap --dbname snitch_test \
    --set ON_ERROR_STOP=1 \
    --file /dev/stdin < "$ROOT/sql/roles.sql" >/dev/null

docker compose \
    --project-name "$PROJECT_NAME" \
    --file "$COMPOSE_FILE" \
    exec --no-TTY postgres \
    psql --username snitch_bootstrap --dbname snitch_test \
    --set ON_ERROR_STOP=1 \
    --command "GRANT snitch_migrator TO snitch_bootstrap" >/dev/null

docker compose \
    --project-name "$PROJECT_NAME" \
    --file "$COMPOSE_FILE" \
    exec --no-TTY postgres \
    psql --username snitch_bootstrap --dbname snitch_test \
    --set ON_ERROR_STOP=1 \
    --file /dev/stdin < "$ROOT/sql/session_ledger.sql" >/dev/null

BOOTSTRAP_URL="$bootstrap_url" \
WRITER_PASSWORD="$writer_password" \
READER_PASSWORD="$reader_password" \
"$PYTHON" - <<'PY'
import os
import psycopg
from psycopg import sql

with psycopg.connect(os.environ["BOOTSTRAP_URL"], autocommit=True) as connection:
    with connection.cursor() as cursor:
        for role_name, password, capability in (
            ("snitch_test_writer", os.environ["WRITER_PASSWORD"], "snitch_writer"),
            ("snitch_test_reader", os.environ["READER_PASSWORD"], "snitch_reader"),
        ):
            cursor.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role_name),
                    sql.Literal(password),
                )
            )
            cursor.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(capability),
                    sql.Identifier(role_name),
                )
            )
PY

export SNITCH_TEST_WRITER_DATABASE_URL
export SNITCH_TEST_READER_DATABASE_URL
SNITCH_TEST_WRITER_DATABASE_URL="host=127.0.0.1 port=${host_port} dbname=snitch_test user=snitch_test_writer password=${writer_password}"
SNITCH_TEST_READER_DATABASE_URL="host=127.0.0.1 port=${host_port} dbname=snitch_test user=snitch_test_reader password=${reader_password}"

cd "$ROOT"
"$PYTHON" -m unittest tests.test_postgres_contract -v
