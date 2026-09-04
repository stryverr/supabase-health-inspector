"""
Registers the demo org and the Project B target connection in the control plane
(Project A), so scan runs have a valid target_connections row to reference.

Idempotent. Writes no password: the target credential stays in backend/.env, and
`secret_id` points at a Supabase Vault entry when Vault is available.

    cd backend
    .venv/Scripts/python.exe scripts/seed_control_plane.py
"""

import asyncio
import pathlib
import sys
from urllib.parse import urlparse
from uuid import UUID

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import asyncpg  # noqa: E402
from app.config import settings  # noqa: E402
from app.db.vault import store_secret_in_vault  # noqa: E402

# Fixed ids so the seeded rows are stable across runs. The connection id matches
# the one the frontend uses in frontend/static/app.js, so the UI works end to end
# against a freshly seeded control plane.
DEMO_ORG_ID = UUID("00000000-0000-0000-0000-000000000001")
DEMO_CONNECTION_ID = UUID("11111111-1111-1111-1111-111111111111")


async def main() -> int:
    if not settings.control_plane_db_url:
        print("FAIL: CONTROL_PLANE_DB_URL is unset in backend/.env.")
        return 1
    if not settings.target_database_url:
        print("FAIL: TARGET_DATABASE_URL is unset; nothing to register.")
        return 1

    target = urlparse(settings.target_database_url)
    conn = await asyncpg.connect(settings.control_plane_db_url, timeout=20.0)
    try:
        await conn.execute(
            """
            INSERT INTO public.orgs (id, name) VALUES ($1, $2)
            ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name;
            """,
            DEMO_ORG_ID,
            "Demo Org",
        )
        print(f"[ok] org {DEMO_ORG_ID} present")

        # Password is never written to target_connections; only a vault reference.
        secret_id = await store_secret_in_vault(
            conn,
            target.password or "",
            name=f"cred_target_{target.hostname}",
            description=f"Target database password for {target.hostname}",
        )

        await conn.execute(
            """
            INSERT INTO public.target_connections
                (id, org_id, label, host, port, db_name, db_user, secret_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
                label = EXCLUDED.label, host = EXCLUDED.host, port = EXCLUDED.port,
                db_name = EXCLUDED.db_name, db_user = EXCLUDED.db_user;
            """,
            DEMO_CONNECTION_ID,
            DEMO_ORG_ID,
            "Project B (target, read-only)",
            target.hostname,
            target.port or 5432,
            (target.path or "/postgres")[1:],
            target.username,
            secret_id,
        )
        print(f"[ok] target_connection {DEMO_CONNECTION_ID} -> {target.username}@{target.hostname}")

        stored = await conn.fetchrow(
            "SELECT label, host, db_user FROM public.target_connections WHERE id = $1;",
            DEMO_CONNECTION_ID,
        )
        print(f"[ok] verified: {stored['label']} ({stored['db_user']}@{stored['host']})")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
