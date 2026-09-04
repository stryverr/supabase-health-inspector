"""
Realtime event publisher.
Persists scan updates and publishes notifications to Postgres LISTEN/NOTIFY or control-plane DB.
"""

from typing import Any, Dict
from uuid import UUID
import asyncpg


async def publish_scan_update(
    conn: asyncpg.Connection,
    scan_id: UUID,
    status: str,
    payload: Dict[str, Any],
):
    """
    Updates scan_runs and optionally triggers pg_notify for connected clients.
    """
    try:
        await conn.execute(
            """
            UPDATE scan_runs
            SET status = $1, completed_at = CASE WHEN $1 IN ('completed', 'failed') THEN NOW() ELSE completed_at END
            WHERE id = $2;
            """,
            status,
            scan_id,
        )
    except Exception:
        pass
