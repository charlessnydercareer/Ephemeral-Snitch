# Project Snitch Audit Summary

Date: 2026-06-24
Status: repaired prototype with disposable PostgreSQL validation; not production-ready

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

- requires explicit role-specific database configuration;
- uses a real psycopg adapter;
- stores metadata rather than prompts;
- has no raw-content capture path;
- redacts claims and evidence before persistence;
- hashes command text rather than storing it;
- validates session IDs and workspaces;
- writes private atomic exports;
- commits trace data before deleting source files;
- quarantines duplicate trace request IDs as infrastructure anomalies;
- quarantines malformed traces;
- keeps schema provisioning outside runtime code;
- structurally removes raw proxy content capture;
- separates claims from verified evidence receipts;
- derives Git facts independently;
- writes immutable JSON, SHA-256, and Markdown session artifacts;
- binds strict request IDs into records, receipts, and summaries;
- reserves request IDs durably to reject collisions;
- persists canonical session records through an insert-only psycopg store;
- defines non-login migration, writer, and reader capability roles;
- stores normalized records in a dedicated `snitch` schema;
- enforces request, session, digest, redaction, and content-capture constraints
  at the database boundary;
- verifies writer and reader privileges against disposable PostgreSQL 18.4;
- validates effective role membership, complete table privilege denial,
  schema ownership, and table ownership before target execution;
- launches targets without a shell through a strict role and command boundary;
- passes only the selected role credential to the child process;
- remains independent of any specific secret provider;
- routes the trace reducer through the validated writer launcher;
- persists traces to `snitch.trace_records` with INSERT-only authority;
- quarantines malformed and duplicate traces with mode `0600`;
- keeps the continuous loop alive after isolated malformed or duplicate input;
- retains source files after transient database failure;
- includes unit tests and public operating documentation.

## Verification

- 38 non-database unit tests passed.
- 7 disposable PostgreSQL ledger and permission tests passed.
- 4 disposable launcher privilege probes passed.
- 1 end-to-end launcher/reducer/quarantine integration test passed.
- 9 launcher unit tests passed.
- Python compilation passed.
- Ruff lint and formatting checks passed.
- Shell syntax validation passed.
- Missing database configuration fails closed.
- Public-release secret-pattern scan passed.

No live database, proxy traffic, service deployment, or external interception
was used during remediation. PostgreSQL validation used a loopback-only,
tmpfs-backed disposable container with transient credentials.

## Remaining blockers

- feature branch review and merge;
- deployment wiring from the finalizer command to the insert-only store;
- verification of the approved external secret-loader invocation;
- retention, deletion, consent, and encrypted-export policies;
- reviewed dependency lock;
- sandboxed deployment and health contract.

Snitch remains an operator-controlled observability prototype until these
boundaries are proven.
