# Project Snitch Agent Contract

## Mission

Snitch is the flight recorder for AI and software sessions. It observes,
redacts, preserves immutable evidence, and produces summaries that let another
operator or agent reconstruct what happened.

Snitch is not a governor, policy engine, approval system, agent controller, or
hidden surveillance proxy.

## Durable context

- Recover prior work from `AUDIT.md` and Git history.
- Write future public project history to repository documentation or the
  operator-configured audit directory.
- Do not create a competing memory or synchronization store.

## Allowed behavior

Snitch may:

- observe sessions, files, commands, tests, artifacts, and database receipts;
- parse and normalize evidence;
- redact sensitive values before persistence;
- quarantine malformed traces;
- append immutable evidence;
- summarize sessions;
- produce read-only health and timeline data.

## Forbidden behavior

Snitch may not:

- approve or deny changes;
- block pushes, commands, or agent execution;
- rewrite files, prompts, agent output, or observed events;
- steer agent decisions;
- silently capture prompt content;
- store credentials, tokens, passwords, cookies, or raw connection strings;
- treat an agent's claim as verified evidence;
- replace Git hooks, governance ledgers, policy gates, or operator approval;
- mutate observed systems in response to findings.

## Claims versus evidence

Keep claims and evidence in separate fields.

- `commands_claimed` and `tests_claimed` record what an agent reports.
- `commands_verified` and `tests_verified` record independently observed
  execution and results.
- `files_changed` must come from Git or filesystem evidence.
- `database_writes` must come from committed receipts or ledger observations.
- Missing evidence must remain missing; do not manufacture confirmation.

## Minimum v1 record

Every completed session must produce one schema-valid normalized record with:

- `session_id`
- `request_id`
- `agent`
- `model_or_tool`
- `repo`
- `branch`
- `commit_before`
- `commit_after`
- `files_changed`
- `commands_claimed`
- `commands_verified`
- `tests_claimed`
- `tests_verified`
- `artifacts_written`
- `database_writes`
- `failures`
- `blockers`
- `deferred_work`
- `risk_flags`
- `redaction_applied`
- `content_capture`

The durable record must be append-only, redacted, and use
`content_capture: false` for the v1 deployment baseline.
Each normalized request ID must have one exclusive private reservation under
the configured runtime artifacts directory.

The current machine-readable contract is
`schemas/session_record.schema.json`.

## Safety and scope

- Do not connect to a live database or proxy traffic without operator approval.
- Use `snitch_migrator` only for schema migration.
- Use `snitch_writer` only for canonical record insertion.
- Use `snitch_reader` only for audit reads.
- Runtime writer code must not receive SELECT, UPDATE, DELETE, TRUNCATE, ALTER,
  DROP, or CREATE privileges.
- Runtime code must not provision schema.
- Keep database credentials and URLs in the runtime secret environment; never
  write them to source, SQL, tests, audits, or Git.
- Secret acquisition belongs to the approved parent launcher. Snitch must
  remain independent of Vault, KeePassXC, or any other secret provider.
- Execute database-aware targets through `snitch-run` after loading both
  database variables. Select the target role explicitly.
- A writer child must not inherit the reader database variable, and a reader
  child must not inherit the writer database variable.
- PostgreSQL permission validation must use the disposable Compose contract,
  never a live database.
- Keep raw content capture disabled.
- Preserve malformed evidence in private quarantine rather than deleting it.
- Keep exports private and atomic.
- Make the smallest change required by the assigned Snitch milestone.

## Deployment gate

Snitch is EVECOR-ready only when metadata capture, redaction, schema validation,
append-only persistence, malformed-event quarantine, Audit summary generation,
and reconstruction by a fresh operator or agent are proven end to end.
