\set ON_ERROR_STOP on

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'snitch_migrator') THEN
        CREATE ROLE snitch_migrator NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'snitch_writer') THEN
        CREATE ROLE snitch_writer NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'snitch_reader') THEN
        CREATE ROLE snitch_reader NOLOGIN;
    END IF;
END
$roles$;

SELECT format(
    'GRANT CREATE ON DATABASE %I TO snitch_migrator',
    current_database()
)
\gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM snitch_writer, snitch_reader;
