"""
Main FastAPI Application (backend/app/main.py).
Wires all diagnostic endpoints, authentication routes, Gemini assistant, and static frontend hosting.
"""

from contextlib import asynccontextmanager
import logging
import os
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from datetime import datetime
import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from app.assistant.agent import handle_assistant_message
from app.assistant.providers import (
    configured_provider_name,
    provider_statuses,
    set_runtime_provider,
)
from app.auth.jwt import demo_auth_enabled, get_current_user_claims
from app.auth.routes import router as auth_router
from app.config import ENV_FILE, settings
from app.db.control_plane import acquire_control_plane_conn, close_control_plane_pool, init_control_plane_pool
from app.db.persistence import (
    connection_exists,
    finish_scan_run,
    list_scan_runs,
    load_scan_result_rows,
    load_scan_run,
    load_scan_run_header,
    save_scan_results,
    start_scan_run,
)
from app.db.target import get_elevated_target_connection, get_target_connection
from app.db.vault import read_secret_from_vault, store_secret_in_vault
from app.diagnostics.rls_debug import analyze_rls_debug_results, run_rls_debug
from app.diagnostics.runner import run_full_scan
from app.reporting.findings import build_finding, sort_findings
from app.reporting.markdown import render_markdown
from app.models import (
    ChatMessageRequest,
    ChatMessageResponse,
    DataShapeSourceEnum,
    ProviderSelectionRequest,
    ProviderSelectionResponse,
    ProviderStatusResponse,
    ReportFinding,
    ScanReport,
    ScanRunSummary,
    RLSDebugRequest,
    RLSDebugResponse,
    RLSPolicyInfo,
    ScanRunResponse,
    ScanStatusEnum,
    TargetConnectionCreate,
    TargetConnectionResponse,
)
from app.scheduler.jobs import shutdown_scheduler, start_scheduler

logger = logging.getLogger(__name__)


def _runtime_override_active() -> bool:
    from app.assistant import providers

    return providers._runtime_override is not None

# In-memory store for scans and connections when control-plane DB is not attached
_in_memory_scans: Dict[UUID, ScanRunResponse] = {}
_in_memory_connections: List[TargetConnectionResponse] = []


def _report_resolved_settings() -> None:
    """
    Logs which settings actually resolved to a non-empty value at startup.

    Names only, never values. A variable named slightly wrong (e.g.
    CONTROL_PLANE_DATABASE_URL instead of CONTROL_PLANE_DB_URL) reads as unset
    with no error, so "the file exists" is not evidence that anything was loaded.
    """
    checks = {
        "TARGET_DATABASE_URL": settings.target_database_url,
        "TARGET_ELEVATED_DATABASE_URL": settings.target_elevated_database_url,
        "CONTROL_PLANE_DB_URL": settings.control_plane_db_url,
        "SUPABASE_URL": settings.supabase_url,
        "SUPABASE_ANON_KEY": settings.supabase_anon_key,
        "SUPABASE_SERVICE_ROLE_KEY": settings.supabase_service_role_key,
        "GEMINI_API_KEY": settings.gemini_api_key,
    }
    print(f"[startup] env file: {ENV_FILE} (exists: {ENV_FILE.exists()})")
    for name, value in checks.items():
        print(f"[startup]   {name}: {'set' if value else 'UNSET'}")

    print(f"[startup] environment: {settings.environment!r}")
    if demo_auth_enabled():
        banner = "!" * 78
        print(banner)
        print("!! DEMO AUTH IS ENABLED -- THIS DEPLOYMENT IS NOT SECURE")
        print("!!   - unauthenticated requests are answered as a hardcoded demo user")
        if not settings.supabase_url:
            print("!!   - SUPABASE_URL is unset, so token signatures are NOT verified")
        print(f"!!   because environment={settings.environment!r}.")
        print("!!   Set ENVIRONMENT=production in backend/.env to require real tokens.")
        print(banner)
    else:
        print("[startup] demo auth: DISABLED (production). Requests require a verified token.")
        if not settings.supabase_url:
            print("[startup] WARNING: SUPABASE_URL is unset; authenticated routes will return 503.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    _report_resolved_settings()
    await init_control_plane_pool()
    start_scheduler()
    yield
    # Shutdown
    shutdown_scheduler()
    await close_control_plane_pool()


app = FastAPI(
    title=settings.app_name,
    description="Postgres & Supabase Diagnostic Inspector: read-only RLS policy inspection, vacuum wraparound analysis, and a Gemini function-calling assistant",
    version="3.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Auth Router
app.include_router(auth_router)


# ---------------------------------------------------------
# Target Connections CRUD
# ---------------------------------------------------------
@app.get("/connections", response_model=List[TargetConnectionResponse])
async def list_connections(user: Dict[str, Any] = Depends(get_current_user_claims)):
    """
    Returns registered target connections for the user's organization.
    """
    async with acquire_control_plane_conn() as conn:
        if conn:
            rows = await conn.fetch("""
                SELECT id, org_id, label, host, port, db_name, db_user, secret_id, created_at
                FROM target_connections
                ORDER BY created_at DESC;
            """)
            return [TargetConnectionResponse(**dict(r)) for r in rows]

    # Return in-memory list or demo fallback
    if not _in_memory_connections:
        demo_conn = TargetConnectionResponse(
            id=UUID("11111111-1111-1111-1111-111111111111"),
            org_id=UUID("00000000-0000-0000-0000-000000000001"),
            label="Demo Supabase Scratch Instance (Seeded)",
            host="db.scratch-instance.supabase.co",
            port=5432,
            db_name="postgres",
            db_user="postgres_readonly",
            secret_id=uuid4(),
            created_at=datetime.utcnow(),
        )
        _in_memory_connections.append(demo_conn)
    return _in_memory_connections


@app.post("/connections", response_model=TargetConnectionResponse)
async def create_connection(
    payload: TargetConnectionCreate,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    Creates a target database connection, storing the password as an encrypted secret in Supabase Vault.
    Never stores plaintext password in target_connections.
    """
    org_id = UUID(user.get("org_id", "00000000-0000-0000-0000-000000000001"))
    secret_id = uuid4()

    async with acquire_control_plane_conn() as conn:
        if conn:
            secret_id = await store_secret_in_vault(
                conn,
                payload.password,
                name=f"cred_{payload.label}",
                description=f"Password for {payload.label} ({payload.host})",
            )
            row = await conn.fetchrow(
                """
                INSERT INTO target_connections (org_id, label, host, port, db_name, db_user, secret_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                RETURNING id, org_id, label, host, port, db_name, db_user, secret_id, created_at;
                """,
                org_id,
                payload.label,
                payload.host,
                payload.port,
                payload.db_name,
                payload.db_user,
                secret_id,
            )
            return TargetConnectionResponse(**dict(row))

    # In-memory store
    item = TargetConnectionResponse(
        id=uuid4(),
        org_id=org_id,
        label=payload.label,
        host=payload.host,
        port=payload.port,
        db_name=payload.db_name,
        db_user=payload.db_user,
        secret_id=secret_id,
        created_at=datetime.utcnow(),
    )
    _in_memory_connections.append(item)
    return item


# ---------------------------------------------------------
# Scan Execution & Polling Routes
# ---------------------------------------------------------
@app.post("/scans/{connection_id}/run", response_model=ScanRunResponse)
async def trigger_scan(
    connection_id: UUID,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    Kicks off run_full_scan() over a short-lived asyncpg connection to the real target DB.
    Runs all 5 diagnostics in sequence against the live PostgreSQL instance.
    """
    scan_id = uuid4()
    started_at = datetime.utcnow()

    async with acquire_control_plane_conn() as cp_conn:
        persisting = cp_conn is not None
        if persisting and not await connection_exists(cp_conn, connection_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Target connection {connection_id} is not registered in the control plane, "
                    f"so this scan cannot be persisted. Register it via POST /connections "
                    f"(or run backend/scripts/seed_control_plane.py) and retry."
                ),
            )

        # Record the attempt BEFORE running diagnostics. A crash mid-sweep then
        # leaves a 'running' row rather than no trace, and started_at reflects when
        # the scan actually began instead of when its results were written.
        if persisting:
            await start_scan_run(cp_conn, scan_id, connection_id, started_at)

        try:
            async with get_target_connection() as target_conn:
                # None unless TARGET_ELEVATED_DATABASE_URL is explicitly configured.
                async with get_elevated_target_connection() as elevated_conn:
                    scan_result = await run_full_scan(
                        target_conn,
                        connection_id,
                        elevated_conn=elevated_conn,
                        scan_id=scan_id,
                        started_at=started_at,
                    )
        except Exception as e:
            if persisting:
                try:
                    await finish_scan_run(cp_conn, scan_id, ScanStatusEnum.FAILED)
                except Exception:
                    logger.exception("Could not mark scan %s failed", scan_id)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Diagnostic sweep failed connecting to target database: {str(e)}",
            )

        if not persisting:
            logger.info("No control-plane database configured; scan %s held in memory only.", scan_id)
        else:
            # A persistence failure must not be silent: the diagnostics are real
            # either way, but the caller has to know the run was not recorded.
            try:
                async with cp_conn.transaction():
                    written = await save_scan_results(cp_conn, scan_id, scan_result.results)
                    await finish_scan_run(
                        cp_conn, scan_id, scan_result.status, scan_result.completed_at
                    )
                scan_result.persisted = True
                logger.info("Persisted scan %s with %d result row(s).", scan_id, written)
            except Exception as e:
                logger.exception("Failed to persist results for scan %s", scan_id)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=(
                        f"Diagnostics completed, but writing the results to the control plane "
                        f"failed: {e}. The run is recorded but its results were not saved."
                    ),
                )

    _in_memory_scans[scan_result.id] = scan_result
    return scan_result


@app.get("/scans/{scan_id}", response_model=ScanRunResponse)
async def get_scan(
    scan_id: UUID,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    Poll endpoint returning current scan status + results (frontend polls every 2 seconds).

    Reads the control plane first so results survive a process restart, and falls
    back to the in-memory store when no control-plane database is configured.
    """
    async with acquire_control_plane_conn() as cp_conn:
        if cp_conn is not None:
            persisted = await load_scan_run(cp_conn, scan_id)
            if persisted is not None:
                return persisted

    if scan_id in _in_memory_scans:
        return _in_memory_scans[scan_id]
    raise HTTPException(status_code=404, detail="Scan run not found")


# ---------------------------------------------------------
# RLS Debugger Route (The Centerpiece)
# ---------------------------------------------------------
@app.post("/rls-debug", response_model=RLSDebugResponse)
async def rls_debug_endpoint(
    payload: RLSDebugRequest,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    Inspects RLS policies on a table from pg_policies metadata and EXPLAIN output
    over a read-only connection without reading actual table rows.
    """
    try:
        async with get_target_connection() as target_conn:
            # None unless TARGET_ELEVATED_DATABASE_URL is explicitly configured.
            async with get_elevated_target_connection() as elevated_conn:
                res = await run_rls_debug(
                    target_conn,
                    payload.table_name,
                    elevated_conn=elevated_conn,
                )

            detected_issues = res.get("detected_issues", [])
            policies = res.get("policies", [])
            source = res.get("data_shape_source", DataShapeSourceEnum.NOT_RUN.value)

            if not res.get("rls_enabled"):
                explanation = f"Row Level Security is DISABLED on 'public.{payload.table_name}'. All data is exposed."
            elif not policies:
                explanation = f"RLS is enabled on '{payload.table_name}' but no policies exist. Postgres default-deny will reject all queries for table '{payload.table_name}'."
            elif detected_issues:
                explanation = f"RLS inspection identified {len(detected_issues)} finding(s): " + "; ".join(detected_issues)
            elif source == DataShapeSourceEnum.NOT_RUN.value:
                explanation = (
                    f"Policy metadata on '{payload.table_name}' is internally consistent, but no "
                    f"connection could read rows, so data-shape checks did not run. Row contents "
                    f"are unverified."
                )
            else:
                explanation = (
                    f"RLS is active with {len(policies)} policy(ies) on '{payload.table_name}'. "
                    f"Data-shape checks ran via the {source} connection and found no defects."
                )

            return RLSDebugResponse(
                table_name=payload.table_name,
                rls_enabled=bool(res.get("rls_enabled")),
                policies_found=[RLSPolicyInfo(**p) for p in policies],
                plan=res.get("plan"),
                has_select_privilege=bool(res.get("has_select_privilege")),
                row_visibility=res.get("row_visibility"),
                plan_proves_zero_rows=bool(res.get("plan_proves_zero_rows")),
                policy_roles=res.get("policy_roles", []),
                applicable_policy_count=res.get("applicable_policy_count", 0),
                readable_rows_count=res.get("readable_rows_count"),
                reltuples_estimate=res.get("reltuples_estimate"),
                data_shape_source=source,
                data_shape_checked_columns=res.get("data_shape_checked_columns", []),
                detected_issues=detected_issues,
                ai_explanation=explanation,
                execution_time_ms=res.get("execution_time_ms", 1.0),
            )
    except ValueError as e:
        # An unknown table is the caller's mistake, not a server fault. It was
        # returning 500, which reads as "the inspector broke" rather than
        # "that table does not exist here".
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"RLS diagnostic inspection failed: {str(e)}",
        )


# ---------------------------------------------------------
# Reports (rendered from control-plane scan_results)
# ---------------------------------------------------------
async def _require_control_plane(conn):
    if conn is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Reports read persisted scans from the control-plane database, but "
                "CONTROL_PLANE_DB_URL is not configured, so no run was ever stored."
            ),
        )


@app.get("/api/reports", response_model=List[ScanRunSummary])
async def api_list_reports(
    limit: int = 50,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """Index of persisted scan runs, newest first."""
    async with acquire_control_plane_conn() as conn:
        await _require_control_plane(conn)
        return [ScanRunSummary(**row) for row in await list_scan_runs(conn, limit)]


@app.get("/api/reports/{scan_run_id}", response_model=ScanReport)
async def api_get_report(
    scan_run_id: UUID,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    A persisted run as a structured report.

    Every field except `ai_explanation` is computed from the stored diagnostic data.
    Diagnosis only: findings.py strips remediation and SQL from stored text.
    """
    async with acquire_control_plane_conn() as conn:
        await _require_control_plane(conn)
        header = await load_scan_run_header(conn, scan_run_id)
        if header is None:
            raise HTTPException(status_code=404, detail=f"Scan run {scan_run_id} not found.")
        rows = await load_scan_result_rows(conn, scan_run_id)

    findings = sort_findings([
        build_finding(
            module=r["module"],
            severity=r["severity"],
            summary=r["summary"],
            raw_result=r["raw_result"],
            ai_explanation=r["ai_explanation"],
            ai_provider=r["ai_provider"],
        )
        for r in rows
    ])

    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    return ScanReport(
        run=ScanRunSummary(**header),
        findings=findings,
        severity_counts=counts,
    )


@app.get("/api/reports/{scan_run_id}/export.md")
async def api_export_report_markdown(
    scan_run_id: UUID,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """Markdown export, served as a file download."""
    report = await api_get_report(scan_run_id, user)
    body = render_markdown(report)
    filename = f"scan-report-{scan_run_id}.md"
    return Response(
        content=body,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------
# Target Schema Introspection
# ---------------------------------------------------------
@app.get("/target/tables", response_model=List[str])
async def list_target_tables(user: Dict[str, Any] = Depends(get_current_user_claims)):
    """
    Base tables in the target's `public` schema.

    Backs the RLS debugger's quick-select buttons, which used to be hardcoded to
    'orders', 'profiles' and 'events'. On a target where those do not exist, every
    button produced a 404 -- the tool should offer what is actually there, on
    whatever database it is pointed at.
    """
    try:
        async with get_target_connection() as conn:
            rows = await conn.fetch(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name;
                """
            )
            return [r["table_name"] for r in rows]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not list target tables: {str(e)}",
        )


# ---------------------------------------------------------
# LLM Provider Selection (Gemini / Ollama toggle)
# ---------------------------------------------------------
@app.get("/assistant/providers", response_model=ProviderSelectionResponse)
async def get_providers(user: Dict[str, Any] = Depends(get_current_user_claims)):
    """
    Live status of every LLM provider plus the current selection.

    Each provider is probed for real rather than reported from configuration, so
    "configured" and "available" can disagree -- which is exactly the case a
    rejected API key produces.
    """
    return ProviderSelectionResponse(
        selected=configured_provider_name(),
        source="runtime override" if _runtime_override_active() else "configuration",
        providers=[ProviderStatusResponse(**s) for s in await provider_statuses()],
    )


@app.put("/assistant/provider", response_model=ProviderSelectionResponse)
async def set_provider(
    payload: ProviderSelectionRequest,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    Switches provider for this process without a restart. Not persisted: a restart
    returns to LLM_PROVIDER in backend/.env.
    """
    try:
        selected = set_runtime_provider(payload.provider)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    return ProviderSelectionResponse(
        selected=selected,
        source="runtime override",
        providers=[ProviderStatusResponse(**s) for s in await provider_statuses()],
    )


# ---------------------------------------------------------
# Function-Calling Assistant Route
# ---------------------------------------------------------
@app.post("/chat/{session_id}/message", response_model=ChatMessageResponse)
async def chat_endpoint(
    session_id: UUID,
    payload: ChatMessageRequest,
    user: Dict[str, Any] = Depends(get_current_user_claims),
):
    """
    Function-calling assistant. Dispatches real asyncpg diagnostics against target DB
    when Gemini returns a tool call, captures trace, and returns response.
    """
    # An unreachable database and a failed assistant call are different faults with
    # different fixes. Only the first is a reason to degrade to offline mode; the
    # second has to reach the caller instead of masquerading as a demo response.
    connected = False
    try:
        async with get_target_connection() as conn:
            connected = True
            async with get_elevated_target_connection() as elevated_conn:
                return await handle_assistant_message(
                    conn, payload.content, elevated_conn=elevated_conn
                )
    except Exception as e:
        if connected:
            logger.exception("Assistant call failed against a live target connection")
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Assistant failed while the target database was reachable: {str(e)}",
            )
        logger.warning(
            "Target database unreachable (%s); answering without live diagnostics.", str(e)
        )
        return await handle_assistant_message(None, payload.content)


# ---------------------------------------------------------
# Static Frontend Serving (HTML/CSS/Vanilla JS)
# ---------------------------------------------------------
frontend_path = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
)
static_path = os.path.join(frontend_path, "static")

if os.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path), name="static")


@app.get("/")
async def serve_index():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({"status": "ok", "app": settings.app_name})


@app.get("/login")
async def serve_login():
    return FileResponse(os.path.join(frontend_path, "login.html"))


@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse(os.path.join(frontend_path, "dashboard.html"))


@app.get("/reports")
async def serve_reports_index():
    return FileResponse(os.path.join(frontend_path, "reports.html"))


@app.get("/reports/{scan_run_id}")
async def serve_report(scan_run_id: UUID):
    # One page for any run; the client reads the id from the path and calls
    # /api/reports/{id}. Declared after /reports so the index is not shadowed.
    return FileResponse(os.path.join(frontend_path, "report.html"))


@app.get("/rls-debugger")
async def serve_rls_debugger():
    return FileResponse(os.path.join(frontend_path, "rls-debugger.html"))


@app.get("/assistant")
async def serve_assistant():
    return FileResponse(os.path.join(frontend_path, "assistant.html"))
