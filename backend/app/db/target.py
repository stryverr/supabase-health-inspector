"""
Target PostgreSQL connection management using short-lived asyncpg connections.
Used exclusively for running read-only diagnostic inspections against external Supabase/Postgres instances.
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional
import asyncpg
from app.config import settings


@asynccontextmanager
async def get_target_connection(
    host: Optional[str] = None,
    port: int = 5432,
    db_name: str = "postgres",
    db_user: str = "postgres",
    password: Optional[str] = None,
    dsn: Optional[str] = None,
    timeout: float = 10.0,
) -> AsyncGenerator[asyncpg.Connection, None]:
    """
    Context manager that yields a short-lived asyncpg connection to the target database.
    Always cleans up and closes the connection when the diagnostic operation finishes.
    """
    conn: Optional[asyncpg.Connection] = None
    target_dsn = (
        dsn
        or settings.target_database_url
        or os.environ.get("TARGET_DATABASE_URL")
        or settings.default_target_db_url
    )

    try:
        if target_dsn:
            conn = await asyncpg.connect(target_dsn, timeout=timeout)
        elif host and password is not None:
            conn = await asyncpg.connect(
                host=host,
                port=port,
                database=db_name,
                user=db_user,
                password=password,
                timeout=timeout,
                ssl="require",
            )
        else:
            raise ValueError(
                "TARGET_DATABASE_URL environment variable is not configured. Please set TARGET_DATABASE_URL to connect to the target PostgreSQL database."
            )

        yield conn
    finally:
        if conn is not None and not conn.is_closed():
            await conn.close()


@asynccontextmanager
async def get_elevated_target_connection(
    timeout: float = 10.0,
) -> AsyncGenerator[Optional[asyncpg.Connection], None]:
    """
    Yields an elevated connection when TARGET_ELEVATED_DATABASE_URL is configured,
    or None when it is not.

    This deliberately never falls back to the read-only DSN. The absence of an
    elevated connection has to surface to the caller as "this check could not run",
    not as a silent downgrade that looks like a completed check.
    """
    dsn = settings.target_elevated_database_url or os.environ.get(
        "TARGET_ELEVATED_DATABASE_URL"
    )

    if not dsn:
        yield None
        return

    conn: Optional[asyncpg.Connection] = None
    try:
        conn = await asyncpg.connect(dsn, timeout=timeout)
        yield conn
    finally:
        if conn is not None and not conn.is_closed():
            await conn.close()
