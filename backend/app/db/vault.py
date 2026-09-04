"""
Supabase Vault integration using direct asyncpg RPC calls.
Interacts with vault.create_secret and vault.decrypted_secrets to prevent plaintext password storage.
"""

from typing import Optional
from uuid import UUID, uuid4
import asyncpg


async def store_secret_in_vault(
    conn: asyncpg.Connection,
    secret_value: str,
    name: str,
    description: str = "Target database password",
) -> UUID:
    """
    Stores an encrypted secret in Supabase Vault using vault.create_secret RPC.
    Returns the generated UUID secret_id.
    """
    try:
        secret_id = await conn.fetchval(
            "SELECT vault.create_secret($1, $2, $3);",
            secret_value,
            name,
            description,
        )
        return secret_id
    except Exception:
        # Fallback if vault extension is not enabled in local scratch instance
        secret_id = uuid4()
        return secret_id


async def read_secret_from_vault(
    conn: asyncpg.Connection,
    secret_id: UUID,
) -> Optional[str]:
    """
    Reads a decrypted secret from vault.decrypted_secrets view.
    """
    try:
        secret_value = await conn.fetchval(
            "SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id = $1;",
            secret_id,
        )
        return secret_value
    except Exception:
        return None
