"""
Diagnostic Runner Orchestrator.
Runs all 5 diagnostic modules against the target Postgres instance in sequence,
evaluates severity, asks the active LLM provider for a short narration, and persists results.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4
from datetime import datetime
import asyncpg
from app.assistant.providers import provider_chain
from app.config import settings
from app.diagnostics.connections import analyze_connection_results, run_connection_health
from app.diagnostics.rls_debug import analyze_rls_debug_results, run_rls_debug
from app.diagnostics.slow_queries import analyze_slow_query_results, run_slow_queries
from app.diagnostics.storage_audit import analyze_storage_results, run_storage_audit
from app.diagnostics.vacuum import analyze_vacuum_results, run_vacuum_check
from app.models import DiagnosticSummary, ScanRunResponse, ScanStatusEnum

logger = logging.getLogger(__name__)


async def generate_ai_explanation(
    module_name: str, summary: str, raw_result: Any
) -> Tuple[Optional[str], Optional[str]]:
    """
    Generates a concise technical explanation via whichever LLM provider is active.

    Returns (text, provider_name). Both are None when no provider answers, rather
    than a canned string that restates the summary: a UI labelling such a string as
    an AI analysis is claiming an analysis that never happened. The provider name is
    returned so the UI can name the model that actually replied instead of assuming
    a vendor.
    """
    prompt = f"""
You are a senior PostgreSQL and Supabase database reliability engineer.
Write a 2-3 sentence technical explanation of the following diagnostic result for module '{module_name}'.
Be precise, professional, citing exact PostgreSQL internal behaviors and direct remediation steps.

If the summary is prefixed INDETERMINATE, explain that the check could not run. Do not
describe an INDETERMINATE result as healthy.

Explain only. Do NOT propose fixes, recommend actions, or write SQL of any kind, and
do not use code blocks. Remediation you compose reads as authoritative and has been
wrong: asked about a healthy wraparound result, a model recommended periodic
`VACUUM FULL`, which is not the remedy for XID age and takes an exclusive lock on the
table. State what the result means and stop.

Summary: {summary}
Raw Diagnostic Data: {str(raw_result)[:1000]}
"""

    for provider in provider_chain():
        try:
            text = (await provider.narrate(prompt)).strip()
            if text:
                return text, provider.name
            logger.info("Provider %s returned empty narration for %s.", provider.name, module_name)
        except Exception as e:
            # The diagnostic result itself is unaffected -- only narration failed.
            # Log for operators; never splice a provider error into user-facing
            # text, where a raw 401 reads as part of the finding.
            logger.warning(
                "Narration via %s unavailable for module %s: %s: %s",
                provider.name,
                module_name,
                type(e).__name__,
                e,
            )
    return None, None


async def run_full_scan(
    conn: asyncpg.Connection,
    target_connection_id: UUID,
    sample_table: str = "orders",
    elevated_conn: Optional[asyncpg.Connection] = None,
    scan_id: Optional[UUID] = None,
    started_at: Optional[datetime] = None,
) -> ScanRunResponse:
    """
    Executes all 5 diagnostics sequentially against an asyncpg connection.

    `elevated_conn` is the opt-in higher-privilege connection (None unless
    TARGET_ELEVATED_DATABASE_URL is configured); it is used only for data-shape
    checks that require reading rows.
    """
    # Caller may supply these so the row recorded before the scan started carries
    # the real start time rather than the time the results were written.
    scan_id = scan_id or uuid4()
    started_at = started_at or datetime.utcnow()
    results: List[DiagnosticSummary] = []

    # 1. Vacuum Wraparound
    try:
        raw_vacuum = await run_vacuum_check(conn)
        res_vacuum = analyze_vacuum_results(raw_vacuum)
        res_vacuum.ai_explanation, res_vacuum.ai_provider = await generate_ai_explanation(
            "vacuum_wraparound", res_vacuum.summary, res_vacuum.raw_result
        )
        results.append(res_vacuum)
    except Exception as e:
        results.append(
            DiagnosticSummary(
                module="vacuum_wraparound",
                severity="critical",
                summary=f"Failed to execute vacuum check: {str(e)}",
                raw_result={"error": str(e)},
            )
        )

    # 2. RLS Debug (centerpiece)
    try:
        # Check if sample table exists, otherwise pick first public table
        tables = await conn.fetch(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' LIMIT 5;"
        )
        tbl = sample_table
        if tables and not any(t["table_name"] == sample_table for t in tables):
            tbl = tables[0]["table_name"]

        if tables:
            raw_rls = await run_rls_debug(conn, tbl, elevated_conn=elevated_conn)
            res_rls = analyze_rls_debug_results(raw_rls)
            res_rls.ai_explanation, res_rls.ai_provider = await generate_ai_explanation(
                "rls_debug", res_rls.summary, res_rls.raw_result
            )
            results.append(res_rls)
        else:
            results.append(
                DiagnosticSummary(
                    module="rls_debug",
                    severity="info",
                    summary="No public tables found to evaluate RLS policies.",
                    raw_result={},
                    ai_explanation="The public schema has no tables yet. Create your schema and RLS policies to perform security analysis.",
                )
            )
    except Exception as e:
        results.append(
            DiagnosticSummary(
                module="rls_debug",
                severity="warning",
                summary=f"RLS evaluation error: {str(e)}",
                raw_result={"error": str(e)},
                ai_explanation=f"RLS policy query failed: {str(e)}",
            )
        )

    # 3. Connection Health
    try:
        raw_conn = await run_connection_health(conn)
        res_conn = analyze_connection_results(raw_conn)
        res_conn.ai_explanation, res_conn.ai_provider = await generate_ai_explanation(
            "connection_health", res_conn.summary, res_conn.raw_result
        )
        results.append(res_conn)
    except Exception as e:
        results.append(
            DiagnosticSummary(
                module="connection_health",
                severity="warning",
                summary=f"Failed to inspect pg_stat_activity: {str(e)}",
                raw_result={"error": str(e)},
            )
        )

    # 4. Storage Audit
    try:
        raw_storage = await run_storage_audit(conn)
        res_storage = analyze_storage_results(raw_storage)
        res_storage.ai_explanation, res_storage.ai_provider = await generate_ai_explanation(
            "storage_audit", res_storage.summary, res_storage.raw_result
        )
        results.append(res_storage)
    except Exception as e:
        results.append(
            DiagnosticSummary(
                module="storage_audit",
                severity="info",
                summary=f"Storage audit skipped: {str(e)}",
                raw_result={"error": str(e)},
            )
        )

    # 5. Slow Queries
    try:
        raw_slow = await run_slow_queries(conn)
        res_slow = analyze_slow_query_results(raw_slow)
        res_slow.ai_explanation, res_slow.ai_provider = await generate_ai_explanation(
            "slow_queries", res_slow.summary, res_slow.raw_result
        )
        results.append(res_slow)
    except Exception as e:
        results.append(
            DiagnosticSummary(
                module="slow_queries",
                severity="info",
                summary=f"Slow query check skipped: {str(e)}",
                raw_result={"error": str(e)},
            )
        )

    return ScanRunResponse(
        id=scan_id,
        target_connection_id=target_connection_id,
        status=ScanStatusEnum.COMPLETED,
        started_at=started_at,
        completed_at=datetime.utcnow(),
        results=results,
    )
