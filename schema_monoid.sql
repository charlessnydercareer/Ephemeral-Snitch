BEGIN;

CREATE TABLE IF NOT EXISTS public.snitch_wal_ledger (
    seq_id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    command_hash TEXT
        CHECK (
            command_hash IS NULL
            OR command_hash ~ '^sha256:[a-f0-9]{64}$'
        ),
    affected_files_count INTEGER NOT NULL DEFAULT 0
        CHECK (affected_files_count >= 0),
    command_count INTEGER NOT NULL DEFAULT 0
        CHECK (command_count >= 0),
    event_hash TEXT NOT NULL UNIQUE
        CHECK (event_hash ~ '^sha256:[a-f0-9]{64}$')
);

CREATE TABLE IF NOT EXISTS public.snitch_session_file_mutations (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_snitch_file_mutations_session
    ON public.snitch_session_file_mutations (session_id, id);

CREATE TABLE IF NOT EXISTS public.snitch_intercepted_requests (
    id BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    provider TEXT NOT NULL,
    host TEXT NOT NULL,
    request_metadata JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snitch_requests_session
    ON public.snitch_intercepted_requests (session_id, id);

COMMIT;
