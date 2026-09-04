-- 003_schema_migrations_rls.sql
-- Same exposure class as 002: public._schema_migrations had RLS disabled, so the
-- migration filenames and timestamps were readable by anyone with the anon key
-- through PostgREST. No client has any reason to read this table.
--
-- RLS is enabled with NO policies, which is default-deny for every client role.
-- The backend service account connects with a privileged role that carries
-- BYPASSRLS, so the migration runner itself is unaffected.

ALTER TABLE public._schema_migrations ENABLE ROW LEVEL SECURITY;
