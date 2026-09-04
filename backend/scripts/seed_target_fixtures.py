"""
Seeds the `events` and `profiles` fixtures on the target database (Project B).

Written to replace running app/seed/seed_demo.py against this project, which would
have been destructive here. seed_demo.py opens with:

    DROP TABLE IF EXISTS public.orders CASCADE;

`orders` on Project B was hand-created and holds the ground truth the RLS work is
verified against (3 rows, two with a trailing space in user_id, one policy targeting
`authenticated`, never analyzed so reltuples = -1). This script never writes to
`orders`; it only reads it, before and after, to prove it was untouched.

Also deliberately absent: ANALYZE. `reltuples = -1` on a never-analyzed table is the
condition the readability fix exists to handle, and analyzing would mask it.

Usage (needs a role that can CREATE in public -- NOT inspector_ro):

    .venv/Scripts/python.exe scripts/seed_target_fixtures.py "<privileged-dsn>" [rows]
"""

import asyncio
import pathlib
import sys
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncpg  # noqa: E402

DEFAULT_EVENT_ROWS = 500_000
BATCH = 50_000

# profiles fixture. The policy targets PUBLIC, so the read-only diagnostic role is
# covered by it and can actually read rows -- unlike orders, whose policy targets
# `authenticated` only. 'dave' carries a trailing space, so RLS hides that row from
# every unprivileged reader: the tool cannot see it without the elevated connection.
PROFILE_ROWS = [
    ("alice", "public"),
    ("bob", "public"),
    ("carol", "private"),
    ("dave", "public "),   # trailing space -- silently invisible
]


async def assert_orders_untouched(conn, label):
    """Reads orders and returns its fingerprint. Never writes."""
    exists = await conn.fetchval(
        "SELECT count(*) > 0 FROM information_schema.tables "
        "WHERE table_schema='public' AND table_name='orders';"
    )
    if not exists:
        raise SystemExit(f"ABORT ({label}): public.orders does not exist. Refusing to continue.")

    total = await conn.fetchval("SELECT count(*) FROM public.orders;")
    untrimmed = await conn.fetchval(
        "SELECT count(*) FROM public.orders WHERE user_id <> btrim(user_id);"
    )
    reltuples = await conn.fetchval(
        "SELECT reltuples::bigint FROM pg_class WHERE oid='public.orders'::regclass;"
    )
    policies = await conn.fetchval(
        "SELECT count(*) FROM pg_policies WHERE schemaname='public' AND tablename='orders';"
    )
    print(f"  [{label}] orders: rows={total} untrimmed={untrimmed} reltuples={reltuples} policies={policies}")
    return (total, untrimmed, reltuples, policies)


async def seed(dsn: str, event_rows: int):
    parsed = urlparse(dsn)
    if parsed.username == "inspector_ro":
        raise SystemExit(
            "ABORT: this DSN is the read-only diagnostic role, which cannot CREATE. "
            "Pass a privileged DSN; do not widen inspector_ro."
        )

    conn = await asyncpg.connect(dsn, timeout=30)
    try:
        print(f"Connected as {await conn.fetchval('SELECT current_user;')} "
              f"to {parsed.hostname}")

        print("\n[guard] fingerprinting orders before any write")
        before = await assert_orders_untouched(conn, "before")

        # ---- events -------------------------------------------------------
        print(f"\n[1/2] events: {event_rows:,} rows, no index beyond the primary key")
        await conn.execute(
            """
            DROP TABLE IF EXISTS public.events CASCADE;
            CREATE TABLE public.events (
                id BIGSERIAL PRIMARY KEY,
                event_type VARCHAR(64) NOT NULL,
                payload JSONB DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            """
        )
        # RLS intentionally NOT enabled: this is the fixture for the
        # "RLS is not enabled -- every row is exposed" verdict.

        done = 0
        while done < event_rows:
            n = min(BATCH, event_rows - done)
            await conn.execute(
                """
                INSERT INTO public.events (event_type, payload, created_at)
                SELECT 'audit_log_' || (g % 10),
                       jsonb_build_object('client_ip', '192.168.1.' || (g % 255),
                                          'action', 'user_login'),
                       NOW() - (g || ' seconds')::interval
                FROM generate_series($1::bigint, $2::bigint) AS g;
                """,
                done + 1,
                done + n,
            )
            done += n
            size = await conn.fetchval("SELECT pg_size_pretty(pg_total_relation_size('public.events'));")
            db = await conn.fetchval("SELECT pg_size_pretty(pg_database_size(current_database()));")
            print(f"    {done:,}/{event_rows:,} rows  events={size}  database={db}")

        # ---- profiles -----------------------------------------------------
        print("\n[2/2] profiles: RLS on, policy targeting PUBLIC")
        await conn.execute(
            """
            DROP TABLE IF EXISTS public.profiles CASCADE;
            CREATE TABLE public.profiles (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                username TEXT NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'private',
                created_at TIMESTAMPTZ DEFAULT NOW()
            );

            ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

            DROP POLICY IF EXISTS "Anyone can read public profiles" ON public.profiles;
            CREATE POLICY "Anyone can read public profiles"
                ON public.profiles
                FOR SELECT
                TO public
                USING (visibility = 'public');
            """
        )
        # Parameterised so the trailing space survives editors that strip it.
        await conn.executemany(
            "INSERT INTO public.profiles (username, visibility) VALUES ($1, $2);",
            PROFILE_ROWS,
        )

        seeded = await conn.fetch(
            "SELECT username, visibility, length(visibility) AS len "
            "FROM public.profiles ORDER BY username;"
        )
        for r in seeded:
            flag = "  <- trailing space" if r["len"] != len(r["visibility"].strip()) else ""
            print(f"    {r['username']:<6} visibility={r['visibility']!r} len={r['len']}{flag}")

        # ---- guard --------------------------------------------------------
        print("\n[guard] fingerprinting orders after all writes")
        after = await assert_orders_untouched(conn, "after")
        if before != after:
            raise SystemExit(f"ABORT: orders changed! before={before} after={after}")
        print("  orders fingerprint identical -- untouched.")

        print("\n[done] No ANALYZE was run on any table.")
    finally:
        await conn.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    rows = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_EVENT_ROWS
    asyncio.run(seed(sys.argv[1], rows))
