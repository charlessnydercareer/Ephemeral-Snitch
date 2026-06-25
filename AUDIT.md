# Project Snitch Audit Summary

Date: 2026-06-24
Status: repaired prototype; not production-ready

## Initial critical findings

The original prototype:

- silently discarded database operations through a no-op adapter;
- embedded a database connection fallback;
- stored raw LLM request payloads;
- used unsafe hostname substring matching;
- deleted trace files before durable commit;
- mutated duplicate events on replay;
- exported rows across sessions;
- allowed runtime code to provision tables;
- had no tests, dependency manifest, or operating documentation.

## Remediation completed

The current project:

- requires an explicit `SNITCH_DATABASE_URL`;
- uses a real psycopg adapter;
- stores metadata rather than prompts;
- has no raw-content capture path;
- redacts claims and evidence before persistence;
- hashes command text rather than storing it;
- validates session IDs and workspaces;
- writes private atomic exports;
- commits trace data before deleting source files;
- rejects conflicting duplicate events;
- quarantines malformed traces;
- keeps schema provisioning outside runtime code;
- structurally removes raw proxy content capture;
- separates claims from verified evidence receipts;
- derives Git facts independently;
- writes immutable JSON, SHA-256, and Markdown session artifacts;
- includes unit tests and public operating documentation.

## Verification

- 23 unit tests passed, including an end-to-end finalizer CLI test.
- Python compilation passed.
- Ruff lint and formatting checks passed.
- Shell syntax validation passed.
- Missing database configuration fails closed.
- Public-release secret-pattern scan passed.

No live database, proxy traffic, service deployment, or external interception
was used during remediation.

## Remaining blockers

- dedicated migration, writer, and reader database roles;
- PostgreSQL integration and permission tests;
- PostgreSQL persistence for normalized session records;
- request-ID correlation;
- retention, deletion, consent, and encrypted-export policies;
- reviewed dependency lock;
- sandboxed deployment and health contract.

Snitch remains an operator-controlled observability prototype until these
boundaries are proven.
