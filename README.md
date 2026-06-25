# Project Snitch

Project Snitch is an experimental, operator-controlled observability layer for
AI agents, software services, migrations, and development sessions.

Its best role is as the stack's **flight recorder**: quiet during normal
operation, but able to explain what changed, which system acted, what reached
durable storage, and what happened immediately before a failure.

Snitch is an evidence collector—not an enforcement authority. It must not
approve changes, mutate agent decisions, replace Git policy gates, or intercept
traffic without explicit authorization.

Final positioning:

```text
Snitch is not a governor.
Snitch is the flight recorder.
```

## What Snitch observes

Snitch currently provides three complementary capabilities:

### Workspace observation

Records file creation, modification, and deletion for an explicitly identified
session. This helps answer:

- Which files changed during an agent or operator session?
- When did a file appear, change, or disappear?
- Which session should be investigated after unexpected drift?

### Agent and API telemetry

Collects privacy-preserving metadata about explicitly proxied LLM requests,
including provider, model, message count, role distribution, tool presence, and
a deterministic payload digest.

Prompt content is not stored by default.

### Durable event reduction

Converts completed local trace files into immutable, deduplicated PostgreSQL
events. This helps distinguish:

- successfully committed events;
- duplicate delivery;
- conflicting replay;
- malformed trace input;
- database failure requiring retry.

## How Snitch improves the software stack

Properly integrated, Snitch can strengthen EVECOR, RouterCore, AgentCore,
deployment tooling, migration work, and autonomous coding sessions.

### Cross-agent accountability

Every event can eventually be correlated with an agent, session, repository,
branch, commit, and request ID. This reduces uncertainty when several agents
work across the same stack.

### Incident reconstruction

Snitch can provide a timeline of file mutations, model calls, trace delivery,
and database commits leading up to a failure.

### Migration and deployment evidence

Migration tools can emit trace events that prove which steps ran, whether they
committed, and whether a repeated execution was identical or conflicting.

### Drift and duplicate detection

Immutable event hashes make it easier to detect replay, inconsistent event
content, and differences between intended and observed changes.

### Debugging without chat history

Structured session evidence gives future agents and operators something more
reliable than conversational memory when diagnosing a problem.

### Read-only operational views

Snitch events could feed EVECOR dashboards, health reports, session timelines,
and audit summaries without granting those interfaces mutation authority.

## Intended architecture

```text
Agents, services, migrations, and operator sessions
                         |
                         v
                Snitch observation
                         |
                         v
              Immutable telemetry ledger
                         |
                         v
       Audits, debugging, health views, and review
```

Enforcement remains elsewhere:

- Git hooks and repository policy control source acceptance.
- Application gates control protected mutations.
- Database permissions control durable writes.
- Human operators authorize sensitive actions.

## Minimum v1 session record

Before EVECOR deployment, Snitch should reliably produce one normalized record
per AI or operator session:

```json
{
  "session_id": "",
  "request_id": "",
  "agent": "",
  "model_or_tool": "",
  "repo": "",
  "branch": "",
  "commit_before": "",
  "commit_after": "",
  "files_changed": [],
  "commands_claimed": [],
  "commands_verified": [],
  "tests_claimed": [],
  "tests_verified": [],
  "artifacts_written": [],
  "database_writes": [],
  "failures": [],
  "blockers": [],
  "deferred_work": [],
  "risk_flags": [],
  "redaction_applied": true,
  "content_capture": false
}
```

The record must be schema-valid, redacted before persistence, and append-only.
Unknown or unverified values must remain visibly unknown rather than being
inferred as facts.

## Claims and evidence

Snitch must keep reported claims separate from independently observed evidence.

Examples:

| Claim | Evidence |
|---|---|
| The agent says it edited file X. | Git diff or filesystem events show whether file X changed. |
| The agent says it ran test Y. | Process or shell evidence shows whether test Y ran and its result. |
| The agent says it wrote an audit. | Filesystem evidence confirms the artifact path and timestamp. |
| The agent says a database write succeeded. | The ledger contains the committed event or receipt. |

Claims may be preserved, but they must never be promoted to verified evidence
without an independent observation.

Verified evidence uses a receipt:

```json
{
  "source": "shell",
  "observation": {
    "command": "python -m unittest discover -s tests -v",
    "exit_code": 0
  },
  "evidence_sha256": "sha256:<digest>"
}
```

The finalizer recomputes each receipt hash and rejects unhashed, tampered,
object-reused, or claim-identical evidence.

## Hard boundaries

Snitch may:

- observe;
- parse;
- redact;
- write immutable evidence;
- quarantine malformed traces;
- summarize sessions;
- produce audit artifacts.

Snitch may not:

- approve changes;
- deny or block changes;
- rewrite files or agent output;
- steer agent behavior;
- silently capture prompts;
- store secrets;
- impersonate an enforcement gate;
- replace Git hooks, policy ledgers, or operator approval;
- mutate the systems it observes merely to repair or reconcile them.

## Safety defaults

- No database credentials are embedded in source.
- `SNITCH_DATABASE_URL` is required.
- Runtime processes do not create database tables.
- LLM request content is not stored by default.
- Command text is represented by a SHA-256 digest rather than stored raw.
- Provider matching uses exact domains and subdomains.
- Trace files are deleted only after a successful database transaction.
- Duplicate `seq_id` replay is immutable; conflicting content is rejected.
- Malformed traces are quarantined with private permissions.
- Export files are written atomically with mode `0600`.
- Log directories use mode `0700`.

## Current status

The original Labs prototype contained critical correctness and privacy defects.
The public project has been repaired and now passes its unit and static checks.

Current state:

- core safety repair: complete;
- metadata-only proxy boundary: structural;
- normalized session finalizer: implemented;
- claims/evidence receipt isolation: implemented;
- immutable JSON, SHA-256, and Markdown artifacts: implemented;
- non-database unit tests: 36 passing;
- disposable PostgreSQL integration tests: 8 passing;
- lint, formatting, compilation, and shell syntax: passing;
- secret-pattern scan: clean;
- disposable PostgreSQL 18.4 integration: passing;
- canonical session ledger roles: migration, insert-only writer, read-only reader;
- production readiness: no;
- governed Git repository: public on GitHub.

The repository audit and remediation record is available in
[`AUDIT.md`](AUDIT.md).

## Setup

Use a project virtual environment. Do not install dependencies globally.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

The dependency versions are a reviewed starting point, not a complete lock.
Optional mitmproxy and inotify dependencies must be tested and pinned before
deployment.

## Database

The legacy trace prototypes still use `schema_monoid.sql` and
`SNITCH_DATABASE_URL`. The normalized v1 session ledger uses a dedicated
`snitch` schema and three non-login capability roles:

- `snitch_migrator`: owns schema and DDL;
- `snitch_writer`: can only insert canonical session records;
- `snitch_reader`: can only select canonical session records.

Apply these role scripts only to a database dedicated to Snitch. The hardening
revokes default `PUBLIC` schema creation and is not intended for a shared
application database.

An infrastructure administrator creates login principals, injects their
credentials from the approved secret store, and grants the appropriate
capability role. Passwords and database URLs do not belong in SQL or source.

Apply the v1 ledger with a migration principal that is allowed to assume
`snitch_migrator`:

```bash
psql "$SNITCH_ADMIN_DATABASE_URL" -f sql/roles.sql
psql "$SNITCH_ADMIN_DATABASE_URL" \
  -c "GRANT snitch_migrator TO your_migration_principal"
psql "$SNITCH_MIGRATOR_DATABASE_URL" -f sql/session_ledger.sql
```

The finalizer store reads only `SNITCH_WRITER_DATABASE_URL` and performs one
validated `INSERT`; it does not provision, read, update, delete, truncate, or
drop ledger state.

### Provider-independent launcher

The approved secret loader must place distinct writer and reader database
values in the parent environment. Snitch does not retrieve secrets itself and
does not depend on a specific vault provider.

Run a writer target through the validated launcher:

```bash
./snitch-run writer .venv/bin/python snitch_session.py --help
```

Run a future read-only target with `reader` instead. Before execution, the
launcher verifies:

- membership in the appropriate non-login capability role;
- exactly one allowed table privilege (`INSERT` or `SELECT`);
- denial of all other table privileges;
- denial of schema `CREATE`;
- absence of schema or ledger ownership;
- distinct writer and reader connection values.

The target must follow an explicit `--` boundary internally and is executed
without a shell. A writer child receives only the writer database variable; a
reader child receives only the reader variable. Arbitrary parent variables,
`HOME`, and `PYTHONPATH` are not propagated.

Run the isolated permission suite against a temporary PostgreSQL 18.4
container:

```bash
./scripts/test-postgres-contract.sh
```

The script generates transient credentials, binds PostgreSQL to an
automatically assigned loopback port, stores its data in container tmpfs, and
removes only its uniquely named disposable Compose project on exit. It also
proves that the launcher accepts correct roles, rejects injected excess
privileges, and can transfer execution to a harmless writer target.

## Trace reducer

Only files ending in `.ready.json` are consumed. Writers should create a
mode-`0600` temporary file and atomically rename it after the JSON is complete.

```bash
SNITCH_DATABASE_URL=... ./run_session.sh --once
```

The continuous reducer can be started by omitting `--once`.

## File watcher

```bash
SNITCH_DATABASE_URL=... \
python snitch_daemon.py \
  --workspace /absolute/path \
  --session-id session-001
```

The daemon uses recursive inotify when available and a polling snapshot fallback
otherwise. It excludes `.git`, `.venv`, `node_modules`, and `__pycache__`.

## Proxy addon

Run this only with explicit authorization from the people and systems whose
traffic will be observed:

```bash
SNITCH_DATABASE_URL=... \
mitmdump -s snitch_processor.py \
  --set session_id=session-001
```

The default stores metadata and a content hash, not prompts.

Raw request-content capture is not implemented. The proxy has no content
capture option.

## Session finalizer

Prepare an agent claims file:

```json
{
  "session_id": "session-001",
  "request_id": "req_a1b2c3d4e5f607182930415263748596",
  "agent": "codex",
  "model_or_tool": "codex",
  "commands_claimed": [],
  "tests_claimed": [],
  "artifacts_written": [],
  "failures": [],
  "blockers": [],
  "deferred_work": [],
  "risk_flags": []
}
```

Verified observer evidence is supplied separately and must contain valid
evidence receipts. Git repository, branch, commits, and changed paths are
derived directly by the finalizer.

```bash
python snitch_session.py \
  --input claims.json \
  --evidence evidence.json \
  --repo /path/to/repository \
  --records-dir artifacts/sessions \
  --reservations-dir artifacts/reservations \
  --audit-dir artifacts/audits
```

The finalizer writes:

- an exclusive canonical JSON session record;
- a SHA-256 receipt;
- a private Markdown audit summary;
- a private request-ID reservation under `artifacts/reservations/`.

Existing artifacts are never overwritten.

`request_id` accepts:

- a strict RFC 4122 UUIDv4; or
- `req_` followed by 16–64 hexadecimal characters.

Accepted IDs are normalized to lowercase. A durable exclusive reservation
prevents the same request ID from being finalized again under another session.

## Verification

```bash
python -m unittest discover -s tests -v
python tests/test_snitch.py -v
python -m py_compile *.py tests/*.py
ruff check .
ruff format --check .
bash -n run_session.sh
python -m unittest tests.test_launcher -v
./scripts/test-postgres-contract.sh
```

## Recommended roadmap

1. Review and merge the session finalizer and PostgreSQL contract branches.
2. Wire the finalizer command to the insert-only session store at deployment.
3. Write one normalized session summary under
   the operator-configured audit directory.
4. Define retention, deletion, consent, and encrypted-export policies.
5. Add a read-only EVECOR health and timeline view later.

## EVECOR deployment gate

Snitch is EVECOR-ready only when this complete chain is proven:

```text
AI session happens
  -> Snitch captures metadata
  -> secrets are redacted
  -> claims and evidence remain distinct
  -> event is schema-valid
  -> event is written append-only
  -> malformed events are quarantined
  -> summary is written to Audits
  -> the next operator or agent can reconstruct what happened
```

Governance remains with hooks, ledgers, policies, and operator approval.

## Production blockers

- feature branches are not reviewed or merged into `main`;
- the approved external secret-loader invocation is not yet verified;
- the finalizer command is not yet wired to the insert-only session store;
- the continuous reducer still uses its legacy database contract;
- no retention, deletion, or consent policy;
- no encrypted durable export design;
- no reviewed dependency lock;
- no formal authorization model for proxy interception;
- no service sandbox, health contract, or deployment manifest;
- no PostgreSQL persistence for normalized session records.

Until these are resolved, Snitch should remain an operator-controlled
development and audit prototype.
