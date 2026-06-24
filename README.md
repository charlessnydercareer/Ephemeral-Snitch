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
The standalone Projects copy has been repaired and now passes its unit and
static checks.

Current state:

- core safety repair: complete;
- unit tests: 12 passing;
- lint, formatting, compilation, and shell syntax: passing;
- secret-pattern scan: clean;
- live PostgreSQL integration: not performed;
- production readiness: no;
- governed Git checkpoint: absent.

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

Load `SNITCH_DATABASE_URL` from the approved secret store, then apply the schema
with migration credentials:

```bash
psql "$SNITCH_DATABASE_URL" -v ON_ERROR_STOP=1 -f schema_monoid.sql
```

Use a dedicated least-privilege Snitch runtime role. Do not run Snitch with a
database owner or administrator account.

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

Setting `capture_content=true` stores request content after sensitive-key
redaction and system-message removal. That mode still handles sensitive data
and requires an explicit consent, retention, encryption, and deletion policy.
Removing content capture entirely should be considered before production use.

## Verification

```bash
python -m unittest discover -s tests -v
python tests/test_snitch.py -v
python -m py_compile *.py tests/*.py
ruff check pg0.py reduction_sweep.py snitch_daemon.py snitch_processor.py tests/test_snitch.py
ruff format --check pg0.py reduction_sweep.py snitch_daemon.py snitch_processor.py tests/test_snitch.py
bash -n run_session.sh
```

## Recommended roadmap

1. Place Snitch in a governed Git repository and commit the repaired baseline.
2. Remove or permanently disable raw content capture for the v1 deployment.
3. Apply redaction before every persistence boundary.
4. Add session, agent, repository, branch, commit, and request-ID correlation.
5. Add the normalized append-only session record schema.
6. Add migration-owner, insert-only writer, and read-only audit roles.
7. Test schema and permissions against disposable PostgreSQL.
8. Preserve deterministic reduction and malformed-trace quarantine.
9. Write one normalized session summary under
   the operator-configured audit directory.
10. Add a read-only EVECOR health and timeline view later.

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

- no dedicated database role migration or permission tests;
- no live PostgreSQL integration test;
- no retention, deletion, or consent policy;
- no encrypted durable export design;
- no reviewed dependency lock;
- no formal authorization model for proxy interception;
- no service sandbox, health contract, or deployment manifest;
- no independent governed Git checkpoint.
- no normalized v1 session-record producer;
- no automatic audit-summary artifact writer.

Until these are resolved, Snitch should remain an operator-controlled
development and audit prototype.
