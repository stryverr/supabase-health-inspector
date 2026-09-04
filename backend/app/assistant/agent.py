"""
Function-calling assistant agent loop.

Executes real asyncpg queries against the target database on each tool call, feeds
the real result back to the model, and returns structured traces with the final
response.

The model is pluggable (see providers.py): Gemini, Ollama, or none. Providers are
tried in order and a failure falls through to the next, ending at deterministic
keyword routing that still runs the real diagnostics. The reply always says which
provider answered -- or that none did -- so a degraded answer is never mistaken
for a model's reasoning.
"""

import logging
import re
from typing import Any, Dict, List, Optional
import asyncpg
from app.assistant.providers import (
    ProviderUnavailable,
    configured_provider_name,
    provider_chain,
)
from app.diagnostics.connections import analyze_connection_results, run_connection_health
from app.diagnostics.rls_debug import analyze_rls_debug_results, run_rls_debug
from app.diagnostics.slow_queries import analyze_slow_query_results, run_slow_queries
from app.diagnostics.storage_audit import analyze_storage_results, run_storage_audit
from app.diagnostics.vacuum import analyze_vacuum_results, run_vacuum_check
from app.models import ChatMessageResponse, ToolCallTrace

logger = logging.getLogger(__name__)

SYSTEM_INSTRUCTION = """
You are an expert PostgreSQL and Supabase Database Reliability Engineer Assistant.
You have access to 5 real diagnostic tools that run directly against the target database:
1. run_vacuum_check: Checks transaction ID wraparound horizon
2. run_rls_debug(table_name): Inspects RLS policy metadata, column type compatibility,
   query plan, and (where a connection can read rows) data-shape defects
3. run_connection_health: Inspects active connections and idle-in-transaction queries
4. run_storage_audit: Audits Supabase storage buckets and object policies
5. run_slow_queries: Analyzes pg_stat_statements

Always use these tools whenever a user asks about database health, RLS permissions,
slow queries, connections, or storage.

Critically: when a tool reports a finding prefixed INDETERMINATE, that check could not
run. Say so plainly. Never present an INDETERMINATE result as a clean bill of health,
and never infer that a table is fine because no defect was reported on a check that
did not execute.

Each tool result carries `severity` and `summary`, computed in Python from the raw
data. That verdict is authoritative -- do NOT second-guess it or derive your own.
If `severity` is "ok", the check passed: say so. Never describe an "ok" result as a
potential problem, and never manufacture a concern the summary does not state.

Ground every claim in the tool result you were given. In particular:
- If `has_select_privilege` is true, the SELECT grant already exists. Do NOT say the
  role is missing a privilege; the cause is row-level security.
- If `row_visibility` is "no_policy_applies", no policy targets the connecting role, so
  this is a property of the connection rather than a defect in the table's data.
- Do not invent column names, policy names, or values the tool result does not contain.

DO NOT PROPOSE FIXES. Not in SQL, and not in prose.

Explain what the finding means and why the database is behaving this way, then stop.
Do not write CREATE POLICY, GRANT, ALTER or any other statement, do not use code
blocks, and do not describe in words what a corrective statement would do. Do not
write "to fix this", "you need to", or "here is the remediation".

This is not a stylistic preference. Remediation you compose reads as authoritative
and has been wrong in ways a reader cannot check: proposing a policy on
`auth.uid()::text = user_id` for a role that never authenticated still matches zero
rows, because auth.uid() is NULL for that role. Remediation in this tool comes from
the diagnostic result, generated deterministically, and is already present in the
finding text where one applies.

Your job is explanation. Diagnosis and prescription are not yours.
"""

# Fenced code blocks and bare statements the model may emit despite the instruction
# above. A 3B model follows a negative instruction unreliably, so the rule is also
# enforced mechanically -- see _strip_sql.
_SQL_FENCE = re.compile(r"```[ \t]*(?:sql|postgresql|psql)?[ \t]*\r?\n.*?```", re.S | re.I)
_SQL_STATEMENT = re.compile(
    r"^[ \t]*(CREATE|ALTER|DROP|GRANT|REVOKE|UPDATE|DELETE|INSERT|TRUNCATE)\s+.*?;[ \t]*$",
    re.I | re.M,
)
# Lead-ins that introduce SQL. Removing the block alone leaves "Here is the
# remediation SQL:" pointing at nothing.
_SQL_LEADIN = re.compile(
    r"^[ \t]*(?:here(?:'s| is)|to fix|you (?:can|could|should|need to|will need to)|"
    r"(?:the )?remediation|run the following|use the following|try)\b[^\n]*:[ \t]*$",
    re.I | re.M,
)

_SQL_NOTICE = (
    "[Remediation from the model is suppressed. Its SQL and its prose descriptions of "
    "fixes have both been wrong here in ways that read as authoritative. The finding "
    "text and tool trace above carry deterministically generated remediation where one "
    "applies.]"
)


def _strip_sql(text: str) -> str:
    """
    Removes SQL the model emitted despite being told not to.

    The trigger: asked why a role sees zero rows, llama3.2 proposed
    `CREATE POLICY ... USING (auth.uid()::text = user_id)` targeting inspector_ro --
    which still matches nothing, because auth.uid() is NULL for a role that never
    authenticated. Confident, plausible, and wrong. The diagnostic verdict is
    trustworthy; the model's SQL is not, so it does not reach the user.
    """
    if not text:
        return text
    cleaned = _SQL_FENCE.sub("", text)
    cleaned = _SQL_STATEMENT.sub("", cleaned)
    cleaned = _SQL_LEADIN.sub("", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()
    if cleaned != text.strip():
        return f"{cleaned}\n\n{_SQL_NOTICE}" if cleaned else _SQL_NOTICE
    return text

# Mapping tool names to real asyncpg diagnostic implementations
TOOL_DISPATCH = {
    "run_vacuum_check": lambda conn, elevated_conn=None, **kwargs: run_vacuum_check(conn),
    "run_rls_debug": lambda conn, elevated_conn=None, **kwargs: run_rls_debug(
        conn, kwargs.get("table_name", "orders"), elevated_conn=elevated_conn
    ),
    "run_connection_health": lambda conn, elevated_conn=None, **kwargs: run_connection_health(conn),
    "run_storage_audit": lambda conn, elevated_conn=None, **kwargs: run_storage_audit(conn),
    "run_slow_queries": lambda conn, elevated_conn=None, **kwargs: run_slow_queries(conn),
}


# The analyzer that turns each tool's raw output into a severity and a summary.
# The model is handed that verdict alongside the raw rows, because asking it to
# derive severity itself is asking it to invent one: given only
# `pct_to_wraparound: 0.00`, llama3.2 reported "a potential issue with transaction
# ID wraparound" on a table that is perfectly healthy. The verdict is computed in
# Python from thresholds; the model's job is to explain it, not to reach it.
TOOL_ANALYZERS = {
    "run_vacuum_check": analyze_vacuum_results,
    "run_rls_debug": analyze_rls_debug_results,
    "run_connection_health": analyze_connection_results,
    "run_storage_audit": analyze_storage_results,
    "run_slow_queries": analyze_slow_query_results,
}


def _make_dispatcher(
    conn: Optional[asyncpg.Connection], elevated_conn: Optional[asyncpg.Connection]
):
    """Builds the callback a provider invokes when the model requests a tool."""

    async def dispatch(name: str, args: Dict[str, Any]) -> Any:
        if conn is None:
            return {"error": "No target database connection is available; this diagnostic could not run."}
        if name not in TOOL_DISPATCH:
            return {"error": f"Unknown tool '{name}'."}
        try:
            raw = await TOOL_DISPATCH[name](conn, elevated_conn=elevated_conn, **args)
        except Exception as e:
            return {"error": str(e)}

        analyzer = TOOL_ANALYZERS.get(name)
        if analyzer is None:
            return raw
        try:
            verdict = analyzer(raw)
            return {
                "severity": verdict.severity.value,
                "summary": verdict.summary,
                "raw_result": raw,
            }
        except Exception as e:
            logger.warning("Analyzer for %s failed: %s", name, e)
            return raw

    return dispatch


async def _deterministic_reply(
    conn: asyncpg.Connection,
    user_message: str,
    elevated_conn: Optional[asyncpg.Connection],
) -> ChatMessageResponse:
    """
    Keyword-routed fallback. Runs the real diagnostics; only the natural-language
    layer is missing, so the tool traces still carry the full evidence.
    """
    traces: List[ToolCallTrace] = []
    lower_msg = user_message.lower()

    if "vacuum" in lower_msg or "wraparound" in lower_msg:
        result = await run_vacuum_check(conn)
        traces.append(ToolCallTrace(tool_name="run_vacuum_check", arguments={}, result=result))
        reply = f"I ran the live `run_vacuum_check` diagnostic across {len(result)} public tables."
    elif "rls" in lower_msg or "policy" in lower_msg or "permission" in lower_msg:
        result = await run_rls_debug(conn, "orders", elevated_conn=elevated_conn)
        traces.append(
            ToolCallTrace(tool_name="run_rls_debug", arguments={"table_name": "orders"}, result=result)
        )
        issues = result.get("detected_issues", [])
        reply = (
            f"I inspected RLS metadata and the query plan for `orders`. "
            f"RLS enabled: {result.get('rls_enabled')}, policies: {len(result.get('policies', []))}, "
            f"findings: {len(issues)}, data-shape checks: {result.get('data_shape_source')}."
        )
    elif "connection" in lower_msg or "pool" in lower_msg:
        result = await run_connection_health(conn)
        traces.append(ToolCallTrace(tool_name="run_connection_health", arguments={}, result=result))
        reply = (
            f"I inspected `pg_stat_activity` on the target database: "
            f"{result.get('total_count', 0)} connection(s), of which "
            f"{result.get('observable_count', 0)} were legible to the diagnostic role and "
            f"{result.get('redacted_count', 0)} were redacted."
        )
    elif "storage" in lower_msg or "bucket" in lower_msg:
        result = await run_storage_audit(conn)
        traces.append(ToolCallTrace(tool_name="run_storage_audit", arguments={}, result=result))
        reply = (
            f"I audited Supabase Storage: {len(result.get('buckets', []))} bucket(s) visible, "
            f"{len(result.get('policies', []))} policy(ies) on storage.objects, listing "
            f"trustworthy: {result.get('listing_trustworthy')}."
        )
    elif "slow" in lower_msg or "query" in lower_msg or "latency" in lower_msg:
        result = await run_slow_queries(conn)
        traces.append(ToolCallTrace(tool_name="run_slow_queries", arguments={}, result=result))
        reply = (
            f"I profiled pg_stat_statements: installed={result.get('installed')}, "
            f"readable={result.get('readable')}, {len(result.get('queries', []))} statement(s) returned."
        )
    else:
        reply = (
            "I can inspect transaction wraparound, audit RLS policies from pg_policies metadata, "
            "audit storage buckets, check connection pool health, and profile slow queries. "
            "Ask about any of those and I will run the real diagnostic."
        )

    return ChatMessageResponse(role="assistant", content=reply, tool_calls=traces)


async def handle_assistant_message(
    conn: Optional[asyncpg.Connection],
    user_message: str,
    chat_history: Optional[List[Dict[str, Any]]] = None,
    elevated_conn: Optional[asyncpg.Connection] = None,
) -> ChatMessageResponse:
    """
    Tries each configured provider in turn, then falls back to deterministic
    routing. The reply names the provider that answered.
    """
    if conn is None:
        return ChatMessageResponse(
            role="assistant",
            content=(
                "The target database connection is not active (TARGET_DATABASE_URL is not "
                "reachable), so no diagnostic can run."
            ),
            tool_calls=[],
        )

    dispatch = _make_dispatcher(conn, elevated_conn)
    attempts: List[str] = []

    for provider in provider_chain():
        try:
            text, traces = await provider.chat_with_tools(
                user_message, SYSTEM_INSTRUCTION, dispatch
            )
            if not text:
                raise ProviderUnavailable("Provider returned an empty response.")
            return ChatMessageResponse(
                role="assistant",
                content=_strip_sql(text),
                tool_calls=traces,
                provider=provider.name,
            )
        except ProviderUnavailable as e:
            attempts.append(f"{provider.name}: {e}")
            logger.warning("Provider %s unavailable: %s", provider.name, e)
        except Exception as e:
            attempts.append(f"{provider.name}: {type(e).__name__}: {e}")
            logger.exception("Provider %s raised unexpectedly", provider.name)

    fallback = await _deterministic_reply(conn, user_message, elevated_conn)
    fallback.provider = "none"

    if attempts:
        detail = "; ".join(attempts)
        banner = (
            f"[No LLM provider answered ({detail}). The diagnostic below still ran "
            f"against the live database.]"
        )
    else:
        banner = (
            f"[LLM narration is disabled (llm_provider={configured_provider_name()!r}). "
            f"The diagnostic below still ran against the live database.]"
        )
    fallback.content = f"{banner}\n\n{fallback.content}"
    return fallback
