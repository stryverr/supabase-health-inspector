"""
Diagnostic Module 1: Vacuum & Transaction ID (XID) Wraparound Analyzer.
Calculates table XID age against Postgres 2-billion transaction wraparound horizon.
"""

from typing import Any, Dict, List
import asyncpg
from app.models import DiagnosticModuleEnum, DiagnosticSummary, SeverityEnum


async def run_vacuum_check(conn: asyncpg.Connection) -> List[Dict[str, Any]]:
    """
    Queries pg_class to evaluate frozen XID age and percent to wraparound.
    """
    rows = await conn.fetch("""
        select relname, age(relfrozenxid) as xid_age,
               round(age(relfrozenxid)::numeric / 2000000000 * 100, 2) as pct_to_wraparound
        from pg_class
        where relkind in ('r','m') and relnamespace = 'public'::regnamespace
        order by age(relfrozenxid) desc limit 20;
    """)
    return [dict(r) for r in rows]


def analyze_vacuum_results(raw_data: List[Dict[str, Any]]) -> DiagnosticSummary:
    """
    Evaluates severity based on max XID age and pct_to_wraparound.
    """
    if not raw_data:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.VACUUM_WRAPAROUND,
            severity=SeverityEnum.OK,
            summary="No user tables detected in public schema.",
            raw_result=raw_data,
        )

    max_pct = max(float(r.get("pct_to_wraparound", 0) or 0) for r in raw_data)
    max_age = max(int(r.get("xid_age", 0) or 0) for r in raw_data)

    if max_pct >= 80.0 or max_age > 1_600_000_000:
        severity = SeverityEnum.CRITICAL
        summary = (
            f"CRITICAL: highest frozen XID age is {max_age} — {max_pct}% of the 2-billion "
            f"transaction wraparound horizon, past which PostgreSQL refuses writes."
        )
    elif max_pct >= 50.0 or max_age > 1_000_000_000:
        severity = SeverityEnum.WARNING
        summary = (
            f"WARNING: elevated frozen XID age {max_age} — {max_pct}% of the 2-billion "
            f"wraparound horizon."
        )
    elif max_pct >= 20.0:
        severity = SeverityEnum.INFO
        summary = f"INFO: Moderate XID turnover observed ({max_pct}%). Well within safety bounds."
    else:
        severity = SeverityEnum.OK
        summary = f"OK: Transaction ID age healthy across all {len(raw_data)} public tables (Max: {max_pct}% to wraparound)."

    return DiagnosticSummary(
        module=DiagnosticModuleEnum.VACUUM_WRAPAROUND,
        severity=severity,
        summary=summary,
        raw_result=raw_data,
    )
