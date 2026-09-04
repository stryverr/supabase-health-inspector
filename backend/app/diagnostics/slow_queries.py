"""
Diagnostic Module 5: Slow Queries and pg_stat_statements Execution Profiler.

Profiles query execution latency, call frequency, and high-frequency queries.

Two things this module has to get right beyond the happy path:

1. **The view is not always on the search_path.** Supabase installs
   pg_stat_statements into the `extensions` schema, not `public`, so a bare
   `SELECT ... FROM pg_stat_statements` raises UndefinedTable even though the
   extension is installed and readable. The schema is resolved from pg_extension
   rather than assumed.
2. **"Installed but unreadable" is not "no slow queries."** An earlier version
   caught the read error, returned an empty query list alongside `installed: true`,
   and the analyzer turned that into `OK: No slow queries recorded` -- a pass on a
   check that never ran.
"""

from typing import Any, Dict, List, Optional
import asyncpg
from app.models import DiagnosticModuleEnum, DiagnosticSummary, SeverityEnum

REDACTED_MARKER = "<insufficient privilege>"


async def _resolve_view_schema(conn: asyncpg.Connection) -> Optional[str]:
    """Returns the schema pg_stat_statements is installed into, or None."""
    return await conn.fetchval(
        """
        SELECT n.nspname
        FROM pg_extension e
        JOIN pg_namespace n ON n.oid = e.extnamespace
        WHERE e.extname = 'pg_stat_statements';
        """
    )


async def run_slow_queries(conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Queries pg_stat_statements for the top 20 queries by mean execution time.
    """
    schema = await _resolve_view_schema(conn)

    if not schema:
        available = await conn.fetchval(
            "SELECT count(*) > 0 FROM pg_available_extensions WHERE name = 'pg_stat_statements';"
        )
        return {
            "installed": False,
            "readable": False,
            "available": bool(available),
            "schema": None,
            "queries": [],
            "message": (
                "pg_stat_statements is not installed on the target database. "
                + (
                    "It is present in pg_available_extensions."
                    if available
                    else "It is not present in pg_available_extensions on this instance."
                )
            ),
        }

    qualified = f'"{schema}".pg_stat_statements'

    try:
        rows = await conn.fetch(
            f"""
            select left(query, 200) as query,
                   calls,
                   round(mean_exec_time::numeric, 2) as mean_exec_time_ms,
                   round(total_exec_time::numeric, 2) as total_exec_time_ms,
                   rows
            from {qualified}
            where query not like '%pg_stat_statements%'
            order by mean_exec_time desc
            limit 20;
            """
        )
    except Exception as e:
        # Installed but unreadable. This is INDETERMINATE, never OK.
        return {
            "installed": True,
            "readable": False,
            "schema": schema,
            "queries": [],
            "error": str(e),
            "message": (
                f"pg_stat_statements is installed in schema '{schema}' but could not be read by the "
                f"connecting role: {e}"
            ),
        }

    queries = [dict(r) for r in rows]

    # Same pg_read_all_stats limitation as pg_stat_activity: the timings are real
    # for every statement, but the statement TEXT of other users' queries comes back
    # as '<insufficient privilege>'. Latency is measurable; the hotspot cannot be
    # named, which is the half a support engineer needs in order to act.
    redacted_count = sum(1 for q in queries if q.get("query") == REDACTED_MARKER)

    return {
        "installed": True,
        "readable": True,
        "schema": schema,
        "queries": queries,
        "redacted_count": redacted_count,
        "observable_count": len(queries) - redacted_count,
        "message": f"Retrieved top {len(queries)} slowest statements from {qualified}.",
    }


def analyze_slow_query_results(raw_data: Dict[str, Any]) -> DiagnosticSummary:
    if not raw_data.get("installed"):
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.SLOW_QUERIES,
            severity=SeverityEnum.INFO,
            summary=f"INFO: {raw_data.get('message', 'pg_stat_statements extension not installed.')} Query latency telemetry unavailable.",
            raw_result=raw_data,
        )

    # Installed but unreadable: the check could not run, so it does not pass.
    if not raw_data.get("readable"):
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.SLOW_QUERIES,
            severity=SeverityEnum.WARNING,
            summary=f"INDETERMINATE: {raw_data.get('message', 'pg_stat_statements could not be read.')}",
            raw_result=raw_data,
        )

    queries = raw_data.get("queries", [])
    if not queries:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.SLOW_QUERIES,
            severity=SeverityEnum.OK,
            summary="OK: pg_stat_statements was read successfully and recorded no statements above the reporting threshold.",
            raw_result=raw_data,
        )

    max_mean_ms = max(float(q.get("mean_exec_time_ms", 0) or 0) for q in queries)
    redacted = raw_data.get("redacted_count", 0)
    observable = raw_data.get("observable_count", len(queries) - redacted)

    # The timings are trustworthy regardless of redaction, so a genuinely slow
    # statement is still a confirmed finding and outranks the visibility caveat.
    redaction_note = (
        f" Statement text is redacted for {redacted} of {len(queries)} entries "
        f"('{REDACTED_MARKER}'), so the offending query cannot be named without "
        f"pg_read_all_stats, which Supabase does not grant."
        if redacted
        else ""
    )

    if max_mean_ms >= 5000.0:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.SLOW_QUERIES,
            severity=SeverityEnum.CRITICAL,
            summary=f"CRITICAL: statement with {max_mean_ms}ms mean execution time.{redaction_note}",
            raw_result=raw_data,
        )
    if max_mean_ms >= 1000.0:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.SLOW_QUERIES,
            severity=SeverityEnum.WARNING,
            summary=f"WARNING: High query latency detected (max mean: {max_mean_ms}ms).{redaction_note}",
            raw_result=raw_data,
        )

    # Latency is within thresholds, but if no statement can be identified the
    # module did not deliver what it exists for: naming the hotspot.
    if redacted and observable == 0:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.SLOW_QUERIES,
            severity=SeverityEnum.WARNING,
            summary=(
                f"INDETERMINATE: latency across {len(queries)} statements is within thresholds "
                f"(max mean: {max_mean_ms}ms), but the statement text of every one is redacted "
                f"('{REDACTED_MARKER}'). The timings are real; the queries behind them cannot be "
                f"identified without pg_read_all_stats, which Supabase does not grant. No hotspot "
                f"can be named from this data."
            ),
            raw_result=raw_data,
        )

    return DiagnosticSummary(
        module=DiagnosticModuleEnum.SLOW_QUERIES,
        severity=SeverityEnum.OK,
        summary=f"OK: Query execution times are fast across {len(queries)} analyzed statements (max mean: {max_mean_ms}ms).{redaction_note}",
        raw_result=raw_data,
    )
