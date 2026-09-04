"""
Standalone Demo Provisioner Script (backend/app/seed/seed_demo.py).

Seeds a scratch Supabase/Postgres target database with the exact ground truth the
inspector is documented against:

1. `public.orders` -- 3 rows, RLS on, policy `user_id = auth.uid()::text`.
   The policy is CORRECT. The data is not: two rows carry a trailing space in
   user_id, so user 1111...1111 matches zero rows instead of two. This is the
   defect the RLS module exists to surface, and it is invisible to policy
   inspection alone -- only a data-shape check finds it.
2. Unindexed `events` table with a batch insert, forcing sequential scans.
3. Storage bucket marked public with zero `storage.objects` policies.

Note: wraparound cannot be simulated (it needs billions of real transactions);
see README.md.
"""

import asyncio
import os
import sys
import asyncpg

# The two user ids the README and the RLS walkthrough refer to. USER_A's rows
# carry a trailing space; USER_B's row is clean, which is what makes the failure
# look like a per-user problem rather than a broken policy.
USER_A = "11111111-1111-1111-1111-111111111111"
USER_B = "22222222-2222-2222-2222-222222222222"


async def seed_scratch_database(target_dsn: str):
    print(f"Connecting to scratch database: {target_dsn.split('@')[-1] if '@' in target_dsn else target_dsn}...")
    conn = await asyncpg.connect(target_dsn)
    try:
        print("\n[1/3] Creating 'orders' with a correct policy over malformed data...")
        await conn.execute(
            """
            DROP TABLE IF EXISTS public.orders CASCADE;
            CREATE TABLE public.orders (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id TEXT NOT NULL,
                amount NUMERIC(10, 2) NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY;

            -- This policy is correctly written: user_id is text, and auth.uid()
            -- (uuid) is explicitly cast to text. Nothing here is wrong.
            DROP POLICY IF EXISTS "Users can read own orders" ON public.orders;
            CREATE POLICY "Users can read own orders"
                ON public.orders
                FOR SELECT
                TO authenticated
                USING (user_id = auth.uid()::text);
            """
        )

        # Inserted as parameters rather than inline literals so the trailing space
        # survives review, copy-paste, and any editor that strips trailing
        # whitespace in .py/.sql source.
        await conn.executemany(
            "INSERT INTO public.orders (user_id, amount, status) VALUES ($1, $2, $3);",
            [
                (USER_A + " ", 99.50, "completed"),   # trailing space -- never matches
                (USER_A + " ", 1450.00, "pending"),   # trailing space -- never matches
                (USER_B, 320.00, "completed"),        # clean -- matches normally
            ],
        )

        seeded = await conn.fetch(
            "SELECT user_id, length(user_id) AS len FROM public.orders ORDER BY amount;"
        )
        print("  seeded rows (length reveals the trailing space):")
        for r in seeded:
            print(f"    user_id={r['user_id']!r} length={r['len']}")
        print(f"  {sum(1 for r in seeded if r['len'] != len(USER_A))} of {len(seeded)} row(s) are malformed.")

        # Deliberately NOT running ANALYZE. A never-analyzed table reports
        # pg_class.reltuples = -1, which is exactly the condition that used to make
        # the RLS module fall through and report OK on a table it could not read.
        # Analyzing here would mask the regression this fixture is meant to catch.
        reltuples = await conn.fetchval(
            "SELECT reltuples::bigint FROM pg_class WHERE oid = 'public.orders'::regclass;"
        )
        print(f"[ok] 'orders' seeded. pg_class.reltuples = {reltuples} (expected -1: never analyzed).")

        print("\n[2/3] Creating unindexed 'events' table for slow query profiling...")
        await conn.execute(
            """
            DROP TABLE IF EXISTS public.events CASCADE;
            CREATE TABLE public.events (
                id BIGSERIAL PRIMARY KEY,
                event_type VARCHAR(64) NOT NULL,
                payload JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            INSERT INTO public.events (event_type, payload, created_at)
            SELECT
                'audit_log_' || (g % 10),
                jsonb_build_object('client_ip', '192.168.1.' || (g % 255), 'action', 'user_login'),
                NOW() - (g || ' minutes')::interval
            FROM generate_series(1, 5000) AS g;
            """
        )
        print("[ok] 'events' seeded with 5,000 unindexed rows.")

        print("\n[3/3] Auditing / creating demo storage bucket...")
        try:
            await conn.execute(
                """
                CREATE SCHEMA IF NOT EXISTS storage;
                CREATE TABLE IF NOT EXISTS storage.buckets (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    public BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
                CREATE TABLE IF NOT EXISTS storage.objects (
                    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                    bucket_id TEXT REFERENCES storage.buckets(id),
                    name TEXT NOT NULL,
                    owner UUID,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );

                INSERT INTO storage.buckets (id, name, public)
                VALUES ('avatars_public', 'avatars_public', true)
                ON CONFLICT (id) DO UPDATE SET public = true;

                ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
                """
            )
            print("[ok] Storage bucket 'avatars_public' created with missing storage.objects policies.")
        except Exception as e:
            print(f"Note: storage schema setup skipped or already handled: {e}")

        print("\n[done] Scratch demo database provisioned.")
        print(f"   Expected inspector finding: 2 of 3 rows in public.orders.user_id hold")
        print(f"   untrimmed whitespace, so user {USER_A} sees 0 rows instead of 2.")
    finally:
        await conn.close()


if __name__ == "__main__":
    dsn = os.getenv("TARGET_DATABASE_URL")
    if not dsn and len(sys.argv) > 1:
        dsn = sys.argv[1]

    if not dsn:
        print("Error: Please provide TARGET_DATABASE_URL env var or as command line argument.")
        print("Example: python backend/app/seed/seed_demo.py postgresql://postgres:password@localhost:5432/postgres")
        sys.exit(1)

    asyncio.run(seed_scratch_database(dsn))
