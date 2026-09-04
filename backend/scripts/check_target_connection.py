"""
Phase 1 connectivity check.

Proves the backend can reach the target database (Project B) and reports what the
connection actually is. Run this before trusting any diagnostic output:

    cd backend
    .venv/Scripts/python.exe scripts/check_target_connection.py     # Windows
    .venv/bin/python scripts/check_target_connection.py             # POSIX

Prints connection structure and role facts, never the DSN or the password.
Exits non-zero on failure so it can gate the later phases.
"""

import asyncio
import pathlib
import sys
from urllib.parse import urlparse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncpg  # noqa: E402
from app.config import ENV_FILE, settings  # noqa: E402


def report_settings() -> bool:
    print(f"env file: {ENV_FILE}")
    print(f"  exists: {ENV_FILE.exists()}")

    resolved = {
        "TARGET_DATABASE_URL": settings.target_database_url,
        "TARGET_ELEVATED_DATABASE_URL": settings.target_elevated_database_url,
        "CONTROL_PLANE_DB_URL": settings.control_plane_db_url,
        "SUPABASE_URL": settings.supabase_url,
        "SUPABASE_ANON_KEY": settings.supabase_anon_key,
        "SUPABASE_SERVICE_ROLE_KEY": settings.supabase_service_role_key,
        "GEMINI_API_KEY": settings.gemini_api_key,
    }
    print("\nresolved settings (names and set/unset only):")
    for name, value in resolved.items():
        print(f"  {name}: {'set' if value else 'UNSET'}")

    if not settings.target_database_url:
        print(
            "\nFAIL: TARGET_DATABASE_URL is unset.\n"
            f"  Put the value in {ENV_FILE} and save the file.\n"
            "  Note the exact variable names: CONTROL_PLANE_DB_URL, not\n"
            "  CONTROL_PLANE_DATABASE_URL -- a near-miss reads as unset with no error."
        )
        return False

    parsed = urlparse(settings.target_database_url)
    print("\nTARGET_DATABASE_URL structure (credential withheld):")
    print(f"  user:  {parsed.username}")
    print(f"  host:  {parsed.hostname}")
    print(f"  port:  {parsed.port}")
    print(f"  db:    {(parsed.path or '')[1:]}")
    print(f"  query: {parsed.query or '(none)'}")

    if parsed.username == "postgres":
        print(
            "\n  WARNING: connecting as 'postgres' (superuser) bypasses RLS and hides the\n"
            "  INDETERMINATE behavior this tool exists to report. Use inspector_ro."
        )
    return True


async def check_connection() -> int:
    conn = None
    try:
        conn = await asyncpg.connect(settings.target_database_url, timeout=15.0)
    except Exception as e:
        print(f"\nFAIL: could not connect to the target database.\n  {type(e).__name__}: {e}")
        return 1

    try:
        row = await conn.fetchrow("SELECT current_user, version();")
        print("\nSELECT current_user, version();")
        print(f"  current_user: {row['current_user']}")
        print(f"  version:      {row['version']}")

        db = await conn.fetchrow(
            "SELECT current_database() AS db, inet_server_addr()::text AS addr, "
            "current_setting('server_version_num') AS vnum;"
        )
        print(f"\n  current_database: {db['db']}")
        print(f"  server_version_num: {db['vnum']}")

        # Role facts that decide how every later diagnostic must be interpreted.
        attrs = await conn.fetchrow(
            "SELECT rolsuper, rolbypassrls, rolcanlogin FROM pg_roles WHERE rolname = current_user;"
        )
        print("\nrole attributes:")
        print(f"  superuser:   {attrs['rolsuper']}")
        print(f"  bypassrls:   {attrs['rolbypassrls']}")
        print(f"  canlogin:    {attrs['rolcanlogin']}")

        memberships = await conn.fetch(
            """
            SELECT r.rolname
            FROM pg_auth_members m
            JOIN pg_roles r ON r.oid = m.roleid
            WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
            ORDER BY r.rolname;
            """
        )
        names = [m["rolname"] for m in memberships]
        print(f"  member of:   {names or '(none)'}")

        is_authenticated = "authenticated" in names
        print(
            f"\n  member of 'authenticated': {is_authenticated}"
            f"{'  <- unexpected; the read-only design assumes NOT a member' if is_authenticated else '  <- expected; subject to RLS'}"
        )
        print(f"  pg_read_all_data:  {'pg_read_all_data' in names}")
        print(f"  pg_read_all_stats: {'pg_read_all_stats' in names}")

        print("\nOK: connected and queried the target database.")
        return 0
    except Exception as e:
        print(f"\nFAIL: connected, but a query failed.\n  {type(e).__name__}: {e}")
        return 1
    finally:
        if conn is not None and not conn.is_closed():
            await conn.close()


def main() -> int:
    if not report_settings():
        return 1
    return asyncio.run(check_connection())


if __name__ == "__main__":
    sys.exit(main())
