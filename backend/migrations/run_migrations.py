"""
Python Migration Runner (backend/migrations/run_migrations.py).
Reads and executes all .sql migration files in lexicographical order against the control-plane database.
"""

import asyncio
import glob
import os
import sys
import asyncpg


async def apply_migrations(db_url: str):
    print(f"Connecting to database to apply migrations...")
    conn = await asyncpg.connect(db_url)
    try:
        # Create migrations tracking table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS public._schema_migrations (
                filename TEXT PRIMARY KEY,
                applied_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)

        migrations_dir = os.path.dirname(os.path.abspath(__file__))
        sql_files = sorted(glob.glob(os.path.join(migrations_dir, "*.sql")))

        if not sql_files:
            print("No .sql migration files found.")
            return

        for sql_path in sql_files:
            filename = os.path.basename(sql_path)
            already_applied = await conn.fetchval(
                "SELECT count(*) > 0 FROM public._schema_migrations WHERE filename = $1;",
                filename,
            )

            if already_applied:
                print(f"  - [Skip] {filename} (already applied)")
                continue

            print(f"  + [Applying] {filename}...")
            with open(sql_path, "r", encoding="utf-8") as f:
                sql_content = f.read()

            async with conn.transaction():
                await conn.execute(sql_content)
                await conn.execute(
                    "INSERT INTO public._schema_migrations (filename) VALUES ($1);",
                    filename,
                )
            print(f"  [ok] [Applied] {filename}")

        print("All migrations successfully applied.")
    finally:
        await conn.close()


def _resolve_db_url() -> str:
    """
    CLI argument, then environment, then backend/.env via settings.

    The settings fallback matters because the credentials live in backend/.env, which
    a bare os.getenv() does not read -- without it this script reports "missing
    database URL" on a machine that is fully configured.
    """
    if len(sys.argv) > 1 and sys.argv[1]:
        return sys.argv[1]
    if os.getenv("CONTROL_PLANE_DB_URL"):
        return os.getenv("CONTROL_PLANE_DB_URL")

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app.config import settings  # noqa: E402

    return settings.control_plane_db_url or ""


if __name__ == "__main__":
    db_url = _resolve_db_url()

    if not db_url:
        print("Error: Missing database URL. Specify via CONTROL_PLANE_DB_URL or command-line argument.")
        print("Example: python backend/migrations/run_migrations.py postgresql://user:pass@host:5432/dbname")
        sys.exit(1)

    asyncio.run(apply_migrations(db_url))
