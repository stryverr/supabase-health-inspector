"""
Connection Simulator (backend/app/seed/seed_connections.py).
Opens real connections and holds them in an uncommitted transaction (BEGIN, no COMMIT, sleep)
to demonstrate the connection_health diagnostic detecting real 'idle in transaction' PIDs.
"""

import asyncio
import os
import sys
import asyncpg


async def hold_idle_connection(dsn: str, conn_index: int, duration_seconds: int = 120):
    print(f"Holding connection #{conn_index} in 'idle in transaction' state for {duration_seconds}s...")
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("BEGIN;")
        await conn.execute("SELECT now();")
        # Sleep without committing or closing
        await asyncio.sleep(duration_seconds)
    finally:
        print(f"Rolling back and closing connection #{conn_index}...")
        await conn.execute("ROLLBACK;")
        await conn.close()


async def main():
    dsn = os.getenv("TARGET_DATABASE_URL")
    if not dsn and len(sys.argv) > 1:
        dsn = sys.argv[1]

    if not dsn:
        print("Usage: python backend/app/seed/seed_connections.py <TARGET_DATABASE_URL>")
        sys.exit(1)

    print("Launching 3 concurrent idle-in-transaction test connections...")
    tasks = [
        hold_idle_connection(dsn, 1, 90),
        hold_idle_connection(dsn, 2, 90),
        hold_idle_connection(dsn, 3, 90),
    ]
    await asyncio.gather(*tasks)
    print("Connection simulation complete.")


if __name__ == "__main__":
    asyncio.run(main())
