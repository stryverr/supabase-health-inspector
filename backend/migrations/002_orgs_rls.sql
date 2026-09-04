-- 002_orgs_rls.sql
-- Closes the one table 001 left unprotected.
--
-- 001 enabled RLS on every table except public.orgs. On Supabase the public
-- schema is exposed through PostgREST, so a table with RLS disabled is readable
-- by anyone holding the anon key -- meaning every organisation's id and name was
-- world-readable. The nested policies on target_connections, scan_runs,
-- scan_results, chat_sessions and chat_messages all chain back through
-- profiles.org_id, so orgs was the one uncovered link in that chain.

ALTER TABLE public.orgs ENABLE ROW LEVEL SECURITY;

-- A member sees only the organisations they belong to, resolved through their
-- own profile row -- the same shape as every other policy in this schema.
DROP POLICY IF EXISTS "Members can view their own org" ON public.orgs;
CREATE POLICY "Members can view their own org"
    ON public.orgs
    FOR SELECT
    USING (
        id IN (
            SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
        )
    );

-- No INSERT/UPDATE/DELETE policies: orgs are provisioned by the backend service
-- account, which connects with a privileged role and is not subject to RLS.
-- Clients read; they never write.
