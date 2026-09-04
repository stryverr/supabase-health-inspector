"""
Control-plane persistence for scan runs and their results.

Scans were previously held only in a process-local dict, so every result vanished
on restart and nothing in Project A ever recorded that a scan had happened. These
helpers write the run and its per-module results to the control-plane database and
read them back.

Writes go through the backend's privileged control-plane connection. The RLS
policies in 001_initial_schema.sql are SELECT-only by design: clients read their
own org's rows and never write, so a client cannot forge or tamper with a result.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID
import asyncpg
from app.models import DiagnosticSummary, ScanRunResponse, ScanStatusEnum

logger = logging.getLogger(__name__)


async def connection_exists(conn: asyncpg.Connection, target_connection_id: UUID) -> bool:
    return bool(
        await conn.fetchval(
            "SELECT count(*) > 0 FROM public.target_connections WHERE id = $1;",
            target_connection_id,
        )
    )


async def start_scan_run(
    conn: asyncpg.Connection,
    scan_id: UUID,
    target_connection_id: UUID,
    started_at: datetime,
    started_by: Optional[UUID] = None,
) -> None:
    """
    Records the run as 'running' before diagnostics execute, so a crash mid-scan
    leaves evidence that it was attempted rather than no trace at all.

    started_at is passed explicitly rather than left to the column default: NOW()
    is transaction time, so writing the row after the scan finished would record a
    start equal to the completion and report every run as taking zero seconds.
    """
    await conn.execute(
        """
        INSERT INTO public.scan_runs (id, target_connection_id, started_by, status, started_at)
        VALUES ($1, $2, $3, 'running', $4);
        """,
        scan_id,
        target_connection_id,
        started_by,
        started_at,
    )


async def save_scan_results(
    conn: asyncpg.Connection,
    scan_id: UUID,
    results: List[DiagnosticSummary],
) -> int:
    """Writes one row per diagnostic module. Returns the number of rows written."""
    if not results:
        return 0

    rows = [
        (
            scan_id,
            r.module.value if hasattr(r.module, "value") else str(r.module),
            r.severity.value if hasattr(r.severity, "value") else str(r.severity),
            r.summary,
            # raw_result is jsonb; asyncpg needs a JSON string, and diagnostic
            # payloads carry Decimal/datetime that json.dumps cannot encode natively.
            json.dumps(r.raw_result, default=str),
            r.ai_explanation,
            r.ai_provider,
        )
        for r in results
    ]

    await conn.executemany(
        """
        INSERT INTO public.scan_results
            (scan_run_id, module, severity, summary, raw_result, ai_explanation, ai_provider)
        VALUES ($1, $2::diagnostic_module, $3::issue_severity, $4, $5::jsonb, $6, $7);
        """,
        rows,
    )
    return len(rows)


async def finish_scan_run(
    conn: asyncpg.Connection,
    scan_id: UUID,
    status: ScanStatusEnum,
    completed_at: Optional[datetime] = None,
) -> None:
    await conn.execute(
        """
        UPDATE public.scan_runs
        SET status = $2::scan_status, completed_at = COALESCE($3, NOW())
        WHERE id = $1;
        """,
        scan_id,
        status.value,
        completed_at,
    )


async def load_scan_run(conn: asyncpg.Connection, scan_id: UUID) -> Optional[ScanRunResponse]:
    """Reads a persisted scan back, so results survive a restart."""
    run = await conn.fetchrow(
        """
        SELECT id, target_connection_id, status::text AS status, started_at, completed_at
        FROM public.scan_runs WHERE id = $1;
        """,
        scan_id,
    )
    if not run:
        return None

    result_rows = await conn.fetch(
        """
        SELECT module::text AS module, severity::text AS severity, summary,
               raw_result, ai_explanation, ai_provider, created_at
        FROM public.scan_results
        WHERE scan_run_id = $1
        ORDER BY created_at, module;
        """,
        scan_id,
    )

    results = [
        DiagnosticSummary(
            module=r["module"],
            severity=r["severity"],
            summary=r["summary"],
            raw_result=_decode_jsonb(r["raw_result"]),
            ai_explanation=r["ai_explanation"],
            ai_provider=r["ai_provider"],
            timestamp=r["created_at"],
        )
        for r in result_rows
    ]

    return ScanRunResponse(
        id=run["id"],
        target_connection_id=run["target_connection_id"],
        status=ScanStatusEnum(run["status"]),
        started_at=run["started_at"],
        completed_at=run["completed_at"],
        results=results,
        persisted=True,
    )


async def list_scan_runs(conn: asyncpg.Connection, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Index of past runs: when, against what, worst severity, how many modules.

    Worst severity is ranked in SQL so the index reflects what the report will show
    without loading every result row.
    """
    rows = await conn.fetch(
        """
        SELECT r.id,
               r.started_at,
               r.completed_at,
               r.status::text AS status,
               r.target_connection_id,
               tc.label AS target_label,
               tc.host  AS target_host,
               count(sr.id) AS module_count,
               (ARRAY_AGG(sr.severity::text ORDER BY CASE sr.severity::text
                    WHEN 'critical' THEN 0 WHEN 'warning' THEN 1
                    WHEN 'info' THEN 2 ELSE 3 END))[1] AS worst_severity
        FROM public.scan_runs r
        LEFT JOIN public.target_connections tc ON tc.id = r.target_connection_id
        LEFT JOIN public.scan_results sr ON sr.scan_run_id = r.id
        GROUP BY r.id, r.started_at, r.completed_at, r.status, r.target_connection_id,
                 tc.label, tc.host
        ORDER BY r.started_at DESC
        LIMIT $1;
        """,
        limit,
    )
    return [dict(r) for r in rows]


async def load_scan_run_header(
    conn: asyncpg.Connection, scan_id: UUID
) -> Optional[Dict[str, Any]]:
    """The index row for a single run, used as the report header."""
    row = await conn.fetchrow(
        """
        SELECT r.id, r.started_at, r.completed_at, r.status::text AS status,
               r.target_connection_id, tc.label AS target_label, tc.host AS target_host,
               count(sr.id) AS module_count,
               (ARRAY_AGG(sr.severity::text ORDER BY CASE sr.severity::text
                    WHEN 'critical' THEN 0 WHEN 'warning' THEN 1
                    WHEN 'info' THEN 2 ELSE 3 END))[1] AS worst_severity
        FROM public.scan_runs r
        LEFT JOIN public.target_connections tc ON tc.id = r.target_connection_id
        LEFT JOIN public.scan_results sr ON sr.scan_run_id = r.id
        WHERE r.id = $1
        GROUP BY r.id, r.started_at, r.completed_at, r.status, r.target_connection_id,
                 tc.label, tc.host;
        """,
        scan_id,
    )
    return dict(row) if row else None


async def load_scan_result_rows(
    conn: asyncpg.Connection, scan_id: UUID
) -> List[Dict[str, Any]]:
    rows = await conn.fetch(
        """
        SELECT module::text AS module, severity::text AS severity, summary,
               raw_result, ai_explanation, ai_provider, created_at
        FROM public.scan_results
        WHERE scan_run_id = $1
        ORDER BY created_at, module;
        """,
        scan_id,
    )
    return [
        {**dict(r), "raw_result": _decode_jsonb(r["raw_result"])} for r in rows
    ]


def _decode_jsonb(value: Any) -> Any:
    """asyncpg returns jsonb as str unless a codec is registered."""
    if isinstance(value, (str, bytes)):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value
