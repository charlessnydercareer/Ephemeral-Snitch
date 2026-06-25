\set ON_ERROR_STOP on

SET ROLE snitch_migrator;

CREATE SCHEMA IF NOT EXISTS snitch AUTHORIZATION snitch_migrator;

CREATE TABLE IF NOT EXISTS snitch.session_records (
    event_id TEXT PRIMARY KEY
        CHECK (event_id ~ '^[a-f0-9]{64}$'),
    session_id TEXT NOT NULL
        CHECK (session_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$'),
    request_id TEXT NOT NULL UNIQUE
        CHECK (
            request_id ~ '^req_[a-f0-9]{16,64}$'
            OR request_id ~
                '^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'
        ),
    record_sha256 TEXT NOT NULL UNIQUE
        CHECK (record_sha256 ~ '^[a-f0-9]{64}$'),
    payload JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (payload->>'session_id' = session_id),
    CHECK (payload->>'request_id' = request_id),
    CHECK (payload->>'redaction_applied' = 'true'),
    CHECK (payload->>'content_capture' = 'false')
);

CREATE TABLE IF NOT EXISTS snitch.trace_records (
    event_id TEXT PRIMARY KEY
        CHECK (event_id ~ '^sha256:[a-f0-9]{64}$'),
    request_id TEXT NOT NULL UNIQUE
        CHECK (length(request_id) BETWEEN 1 AND 256),
    payload JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (payload->>'seq_id' = request_id),
    CHECK (payload->>'event_hash' = event_id)
);

REVOKE ALL ON SCHEMA snitch FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA snitch FROM PUBLIC;

GRANT USAGE ON SCHEMA snitch TO snitch_writer, snitch_reader;
GRANT INSERT ON snitch.session_records, snitch.trace_records TO snitch_writer;
GRANT SELECT ON snitch.session_records, snitch.trace_records TO snitch_reader;

ALTER DEFAULT PRIVILEGES FOR ROLE snitch_migrator IN SCHEMA snitch
    REVOKE ALL ON TABLES FROM PUBLIC;

RESET ROLE;
