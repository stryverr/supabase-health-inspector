"""
Diagnostic Module 3: Connection Health and Idle-in-Transaction Telemetry.

Inspects pg_stat_activity for stalled queries, connection pooling saturation, and
long-held locks.

Visibility caveat that shapes this whole module: without `pg_read_all_stats`, a
role sees only its own backends in full. Other users' rows come back with `state`,
`wait_event_type` and friends as NULL and `query` as the literal string
'<insufficient privilege>'. Counting `state = 'idle in transaction'` across those
rows therefore cannot find anything -- not because there is nothing to find, but
because the column is blank. Reporting that as "0 idle-in-transaction" is a false
OK, so redacted rows are counted and reported explicitly instead.

Supabase does not grant `pg_read_all_stats` to the managed `postgres` role (it
lacks ADMIN option on it), so this is the normal state on Supabase, not a
misconfiguration to fix.
"""

from typing import Any, Dict, List
import asyncpg
from app.models import DiagnosticModuleEnum, DiagnosticSummary, SeverityEnum

REDACTED_MARKER = "<insufficient privilege>"


async def run_connection_health(conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Queries pg_stat_activity for connection states, wait events, and durations,
    recording which rows the connecting role is not permitted to see.
    """
    rows = await conn.fetch(
        """
        select pid,
               usename,
               state,
               wait_event_type,
               wait_event,
               clock_timestamp() - state_change as state_duration,
               left(query, 200) as query,
               (query = '<insufficient privilege>') as query_redacted,
               pid = pg_backend_pid() as is_self
        from pg_stat_activity
        where datname = current_database()
        order by clock_timestamp() - state_change desc nulls last;
        """
    )

    connections: List[Dict[str, Any]] = []
    for r in rows:
        # A row is opaque when the server withheld the query text; `state` is NULL
        # on those same rows, which is what makes state-based counting unreliable.
        redacted = bool(r["query_redacted"]) or (r["state"] is None and not r["is_self"])
        connections.append(
            {
                "pid": r["pid"],
                "usename": r["usename"],
                "state": r["state"],
                "wait_event_type": r["wait_event_type"],
                "wait_event": r["wait_event"],
                "state_duration": str(r["state_duration"]) if r["state_duration"] is not None else None,
                "query": r["query"] or "",
                "redacted": redacted,
            }
        )

    redacted_count = sum(1 for c in connections if c["redacted"])
    return {
        "connections": connections,
        "total_count": len(connections),
        "redacted_count": redacted_count,
        "observable_count": len(connections) - redacted_count,
        "has_full_visibility": redacted_count == 0,
    }


def analyze_connection_results(raw_data: Dict[str, Any]) -> DiagnosticSummary:
    connections = raw_data.get("connections", [])
    total = raw_data.get("total_count", len(connections))
    redacted = raw_data.get("redacted_count", 0)
    observable = raw_data.get("observable_count", total - redacted)

    idle_in_tx = [c for c in connections if c.get("state") == "idle in transaction"]
    waiting_locks = [c for c in connections if c.get("wait_event_type") == "Lock"]

    # Confirmed problems outrank incomplete visibility: these were actually seen.
    if idle_in_tx:
        pids = ", ".join(str(c["pid"]) for c in idle_in_tx[:3])
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.CONNECTION_HEALTH,
            severity=SeverityEnum.CRITICAL,
            summary=f"CRITICAL: {len(idle_in_tx)} connection(s) stuck 'idle in transaction' (PIDs: {pids}). This blocks autovacuum and holds table locks.",
            raw_result=raw_data,
        )

    if waiting_locks:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.CONNECTION_HEALTH,
            severity=SeverityEnum.WARNING,
            summary=f"WARNING: {len(waiting_locks)} connection(s) waiting on heavy table/row locks.",
            raw_result=raw_data,
        )

    # The connection COUNT is reliable even without pg_read_all_stats -- every
    # backend produces a row. Saturation is therefore still worth reporting.
    if total > 80:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.CONNECTION_HEALTH,
            severity=SeverityEnum.WARNING,
            summary=f"WARNING: elevated connection count ({total}) against this database.",
            raw_result=raw_data,
        )

    # Nothing found -- but "nothing found" only means something if the rows were
    # legible. State is NULL on redacted rows, so idle-in-transaction and lock
    # waits are undetectable there.
    if redacted:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.CONNECTION_HEALTH,
            severity=SeverityEnum.WARNING,
            summary=(
                f"INDETERMINATE: {total} connection(s) to this database, but {redacted} of them are "
                f"opaque to the diagnostic role -- pg_stat_activity returns '{REDACTED_MARKER}' and a "
                f"NULL state for backends owned by other users without pg_read_all_stats. "
                f"Idle-in-transaction and lock-wait detection could only run against {observable} "
                f"row(s), so a clean result here is not evidence that none exist. "
                f"Supabase does not grant pg_read_all_stats, so this limit is expected."
            ),
            raw_result=raw_data,
        )

    return DiagnosticSummary(
        module=DiagnosticModuleEnum.CONNECTION_HEALTH,
        severity=SeverityEnum.OK,
        summary=f"OK: Connection pool is healthy ({total} connection(s), all observable, 0 idle-in-transaction).",
        raw_result=raw_data,
    )
