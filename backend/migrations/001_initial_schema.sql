-- 001_initial_schema.sql
-- Control-plane database schema with nested Row Level Security (RLS) policies.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enable Supabase Vault if available
CREATE SCHEMA IF NOT EXISTS vault;

-- Enums
DO $$ BEGIN
    CREATE TYPE scan_status AS ENUM ('running', 'completed', 'failed');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE diagnostic_module AS ENUM (
        'vacuum_wraparound',
        'rls_debug',
        'connection_health',
        'storage_audit',
        'slow_queries'
    );
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE issue_severity AS ENUM ('ok', 'info', 'warning', 'critical');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
    CREATE TYPE chat_role AS ENUM ('user', 'assistant', 'tool');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- 1. Organizations
CREATE TABLE IF NOT EXISTS public.orgs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Profiles (id references auth.users)
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY,
    org_id UUID NOT NULL REFERENCES public.orgs(id) ON DELETE CASCADE,
    email TEXT,
    role TEXT DEFAULT 'member',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Target Connections (Never plaintext password; secret_id references vault)
CREATE TABLE IF NOT EXISTS public.target_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.orgs(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    host TEXT NOT NULL,
    port INT DEFAULT 5432,
    db_name TEXT NOT NULL DEFAULT 'postgres',
    db_user TEXT NOT NULL DEFAULT 'postgres',
    secret_id UUID NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Scan Runs
CREATE TABLE IF NOT EXISTS public.scan_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_connection_id UUID NOT NULL REFERENCES public.target_connections(id) ON DELETE CASCADE,
    started_by UUID REFERENCES public.profiles(id),
    status scan_status NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

-- 5. Scan Results
CREATE TABLE IF NOT EXISTS public.scan_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id UUID NOT NULL REFERENCES public.scan_runs(id) ON DELETE CASCADE,
    module diagnostic_module NOT NULL,
    severity issue_severity NOT NULL DEFAULT 'ok',
    summary TEXT NOT NULL,
    raw_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    ai_explanation TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 6. Chat Sessions
CREATE TABLE IF NOT EXISTS public.chat_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.orgs(id) ON DELETE CASCADE,
    target_connection_id UUID REFERENCES public.target_connections(id) ON DELETE SET NULL,
    created_by UUID REFERENCES public.profiles(id),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. Chat Messages
CREATE TABLE IF NOT EXISTS public.chat_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID NOT NULL REFERENCES public.chat_sessions(id) ON DELETE CASCADE,
    role chat_role NOT NULL,
    content TEXT NOT NULL,
    tool_calls JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- =========================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =========================================================

-- Enable RLS on every table except orgs
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.target_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.chat_messages ENABLE ROW LEVEL SECURITY;

-- 1. profiles: visible only where id = auth.uid()
DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
CREATE POLICY "Users can view own profile"
    ON public.profiles
    FOR SELECT
    USING (id = auth.uid());

-- 2. target_connections: visible only to users within the same org
DROP POLICY IF EXISTS "Members can view org target connections" ON public.target_connections;
CREATE POLICY "Members can view org target connections"
    ON public.target_connections
    FOR SELECT
    USING (
        org_id IN (
            SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
        )
    );

-- 3. scan_runs: derived via target_connections -> org_id
DROP POLICY IF EXISTS "Members can view org scan runs" ON public.scan_runs;
CREATE POLICY "Members can view org scan runs"
    ON public.scan_runs
    FOR SELECT
    USING (
        target_connection_id IN (
            SELECT tc.id FROM public.target_connections tc
            WHERE tc.org_id IN (
                SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
            )
        )
    );

-- 4. scan_results: nested JOIN chain back to caller's org via scan_runs -> target_connections -> profiles
DROP POLICY IF EXISTS "Members can view org scan results" ON public.scan_results;
CREATE POLICY "Members can view org scan results"
    ON public.scan_results
    FOR SELECT
    USING (
        scan_run_id IN (
            SELECT sr.id FROM public.scan_runs sr
            WHERE sr.target_connection_id IN (
                SELECT tc.id FROM public.target_connections tc
                WHERE tc.org_id IN (
                    SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
                )
            )
        )
    );

-- 5. chat_sessions: visible to org members
DROP POLICY IF EXISTS "Members can view org chat sessions" ON public.chat_sessions;
CREATE POLICY "Members can view org chat sessions"
    ON public.chat_sessions
    FOR SELECT
    USING (
        org_id IN (
            SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
        )
    );

-- 6. chat_messages: nested via session -> org
DROP POLICY IF EXISTS "Members can view org chat messages" ON public.chat_messages;
CREATE POLICY "Members can view org chat messages"
    ON public.chat_messages
    FOR SELECT
    USING (
        session_id IN (
            SELECT cs.id FROM public.chat_sessions cs
            WHERE cs.org_id IN (
                SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
            )
        )
    );

-- Note: No client-writable policies on scan_results or scan_runs.
-- Backend service account bypasses RLS using privileged connection string.
