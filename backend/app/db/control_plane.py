"""
Control-plane PostgreSQL connection management using asyncpg.
Maintains an asyncpg connection pool for storing app state: orgs, profiles,
target connections, scan history, and chat messages.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
import asyncpg
from app.config import settings

_pool: Optional[asyncpg.Pool] = None


async def init_control_plane_pool():
    global _pool
    if settings.control_plane_db_url and _pool is None:
        try:
            _pool = await asyncpg.create_pool(
                dsn=settings.control_plane_db_url,
                min_size=2,
                max_size=10,
                timeout=15.0,
            )
        except Exception as e:
            print(f"[Warning] Could not initialize control-plane database pool: {e}")


async def close_control_plane_pool():
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


@asynccontextmanager
async def acquire_control_plane_conn() -> AsyncGenerator[Optional[asyncpg.Connection], None]:
    """
    Yields a pooled control-plane connection, or None when no control-plane
    database is configured.

    This is a context manager rather than a bare acquire() because the connection
    must return to the pool on every path. The previous accessor handed out
    connections that callers never released, exhausting the pool after ten
    requests.
    """
    if _pool is None:
        yield None
        return

    conn = await _pool.acquire()
    try:
        yield conn
    finally:
        await _pool.release(conn)
