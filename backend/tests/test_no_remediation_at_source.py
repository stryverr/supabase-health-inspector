"""
Guards the scope rule at its source.

Remediation used to be baked into diagnostic text -- `Remediate with UPDATE ...;`,
`Grant SELECT to the diagnostic role`, `run 'CREATE EXTENSION ...'` -- which the
report then had to strip on read. It is now removed where it was written, so the
dashboard, the API and the report all carry the same scope.

The report's read-time sanitiser stays as defence in depth for rows already stored
(see test_reporting.py); this file asserts nothing new is written that needs it.
"""

import re
from unittest.mock import AsyncMock
import pytest

from app.diagnostics.connections import analyze_connection_results
from app.diagnostics.rls_debug import analyze_rls_debug_results, run_rls_debug
from app.diagnostics.slow_queries import analyze_slow_query_results, run_slow_queries
from app.diagnostics.storage_audit import analyze_storage_results
from app.diagnostics.vacuum import analyze_vacuum_results

# Imperatives and SQL. Deliberately excludes statements of fact that merely mention
# a privilege, e.g. "Supabase does not grant pg_read_all_stats" -- that reports the
# platform's behaviour, it does not tell anyone to do anything.
PRESCRIPTIVE = re.compile(
    r"\b(?:remediate|you should|you can|you must|you need to|please\s|"
    r"grant \w+ to|run '|recommended|advised|urgently needed|"
    r"configure TARGET_|compare uuid to uuid|use auth\.uid\(\)::text|"
    r"tuning|rewriting|freeze required)\b",
    re.I,
)
SQL = re.compile(
    r"\b(?:CREATE|ALTER|DROP|GRANT|REVOKE|UPDATE|DELETE|INSERT|TRUNCATE|VACUUM)\s+"
    r"[A-Za-z_\"][^;]*;",
    re.I,
)


def assert_clean(text, label):
    assert text, f"{label}: empty"
    m = PRESCRIPTIVE.search(text)
    assert not m, f"{label}: prescriptive text {m.group(0)!r} in {text!r}"
    m = SQL.search(text)
    assert not m, f"{label}: SQL {m.group(0)!r} in {text!r}"


def check_summary(analysis, label):
    assert_clean(analysis.summary, f"{label} summary")


# --- rls_debug ----------------------------------------------------------------

PLAN_CONST_FALSE = '[{"Plan": {"Node Type": "Result", "One-Time Filter": "false"}}]'
PLAN_SEQ_SCAN = '[{"Plan": {"Node Type": "Seq Scan"}}]'


def _conn(*, rls=True, priv=True, reltuples=-1, visible=0, policy_qual=None,
          policy_roles=None, col=("user_id", "text"), plan=PLAN_CONST_FALSE,
          role_applies=False, extra=None):
    c = AsyncMock()
    vals = [True, rls, plan, "inspector_ro", priv, reltuples]
    if priv:
        vals.append(visible)
    if extra:
        vals.extend(extra)
    c.fetchval.side_effect = vals
    policy = {
        "schemaname": "public", "tablename": "t",
        "policyname": "p", "permissive": "PERMISSIVE",
        "roles": policy_roles or ["authenticated"], "cmd": "SELECT",
        "qual": policy_qual or "(user_id = (auth.uid())::text)", "with_check": None,
    }
    fetches = [[policy], [{"column_name": col[0], "data_type": col[1], "udt_name": col[1]}]]
    fetches.append([{"rolname": r, "has_role": role_applies} for r in (policy_roles or ["authenticated"])])
    c.fetch.side_effect = fetches
    return c


@pytest.mark.asyncio
async def test_no_policy_applies_finding_is_purely_diagnostic():
    result = await run_rls_debug(_conn(), "orders")
    for issue in result["detected_issues"]:
        assert_clean(issue, "rls no_policy_applies")
    check_summary(analyze_rls_debug_results(result), "rls no_policy_applies")


@pytest.mark.asyncio
async def test_no_privilege_finding_drops_the_grant_instruction():
    result = await run_rls_debug(_conn(priv=False), "orders")
    joined = " ".join(result["detected_issues"])
    assert "no SELECT privilege" in joined          # the fact survives
    assert "Grant SELECT to" not in joined          # the instruction does not
    for issue in result["detected_issues"]:
        assert_clean(issue, "rls no_privilege")


@pytest.mark.asyncio
async def test_whitespace_defect_keeps_the_count_and_drops_the_update():
    """The example from the brief: keep '2 row(s) hold untrimmed whitespace'."""
    elevated = AsyncMock()
    elevated.fetchval.return_value = 2
    result = await run_rls_debug(_conn(plan=PLAN_SEQ_SCAN), "orders", elevated_conn=elevated)

    defect = next(i for i in result["detected_issues"] if "untrimmed whitespace" in i)
    assert "2 row(s) hold untrimmed whitespace" in defect
    assert "silently receive zero rows" in defect   # consequence survives
    assert "Remediate with" not in defect
    assert "UPDATE" not in defect
    assert_clean(defect, "rls whitespace defect")

    check_summary(analyze_rls_debug_results(result), "rls whitespace defect")


@pytest.mark.asyncio
async def test_type_mismatch_findings_state_the_mechanism_only():
    uuid_col = await run_rls_debug(
        _conn(col=("owner", "uuid"), policy_qual="(owner = (auth.uid())::text)"), "t"
    )
    text_col = await run_rls_debug(
        _conn(col=("user_id", "text"), policy_qual="(user_id = auth.uid())"), "t"
    )
    for result, label in ((uuid_col, "uuid column"), (text_col, "text column")):
        issue = next(i for i in result["detected_issues"] if i.startswith("Policy '"))
        assert "bypasses any index" in issue or "no text = uuid operator" in issue
        assert_clean(issue, f"rls type mismatch ({label})")


@pytest.mark.asyncio
async def test_readable_ok_summary_scope_note_is_not_an_instruction():
    result = await run_rls_debug(
        _conn(plan=PLAN_SEQ_SCAN, visible=2, role_applies=True, extra=[0]), "profiles"
    )
    analysis = analyze_rls_debug_results(result)
    assert "only the 2 row(s) visible" in analysis.summary   # scope survives
    check_summary(analysis, "rls readable OK")


# --- the other four modules ---------------------------------------------------

def test_vacuum_summaries_are_diagnostic_at_every_severity():
    cases = [
        [{"relname": "big", "xid_age": 1_900_000_000, "pct_to_wraparound": 95.0}],
        [{"relname": "mid", "xid_age": 1_100_000_000, "pct_to_wraparound": 55.0}],
        [{"relname": "low", "xid_age": 500_000_000, "pct_to_wraparound": 25.0}],
        [{"relname": "ok", "xid_age": 6, "pct_to_wraparound": 0.0}],
    ]
    for raw in cases:
        analysis = analyze_vacuum_results(raw)
        check_summary(analysis, f"vacuum {analysis.severity.value}")
        # The measurement itself must survive the edit.
        assert str(raw[0]["pct_to_wraparound"]) in analysis.summary


def test_connection_summaries_are_diagnostic():
    saturated = {"connections": [], "total_count": 120, "redacted_count": 0, "observable_count": 120}
    analysis = analyze_connection_results(saturated)
    assert "120" in analysis.summary
    check_summary(analysis, "connections saturated")

    redacted = {"connections": [], "total_count": 5, "redacted_count": 4, "observable_count": 1}
    check_summary(analyze_connection_results(redacted), "connections redacted")


@pytest.mark.asyncio
async def test_slow_queries_messages_are_diagnostic():
    conn = AsyncMock()
    conn.fetchval.side_effect = [None, True]          # not installed, but available
    raw = await run_slow_queries(conn)
    assert_clean(raw["message"], "slow_queries not installed")
    check_summary(analyze_slow_query_results(raw), "slow_queries not installed")

    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.side_effect = Exception("permission denied for view pg_stat_statements")
    raw = await run_slow_queries(conn)
    assert_clean(raw["message"], "slow_queries unreadable")
    check_summary(analyze_slow_query_results(raw), "slow_queries unreadable")

    critical = {"installed": True, "readable": True, "schema": "extensions",
                "queries": [{"mean_exec_time_ms": 9000.0}], "redacted_count": 0,
                "observable_count": 1}
    analysis = analyze_slow_query_results(critical)
    assert "9000.0ms" in analysis.summary
    check_summary(analysis, "slow_queries critical")


def test_storage_summaries_are_diagnostic():
    cases = [
        {"schema_present": False, "buckets": [], "policies": [], "listing_trustworthy": True},
        {"schema_present": True, "buckets": [{"name": "avatars", "public": True}],
         "policies": [], "listing_trustworthy": True, "can_select_buckets": True},
        {"schema_present": True, "buckets": [], "policies": [], "can_select_buckets": True,
         "buckets_rls_enabled": True, "bucket_policy_count": 0, "listing_trustworthy": False},
    ]
    for raw in cases:
        check_summary(analyze_storage_results(raw), "storage")
