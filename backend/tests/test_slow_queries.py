"""
Pytest suite for the Slow Queries diagnostic module.

Two failure modes matter more than the happy path:
  - the extension is installed in a non-default schema (Supabase uses `extensions`),
    so an unqualified query raises UndefinedTable;
  - the view is installed but unreadable, which is INDETERMINATE, not "no slow queries".
"""

from unittest.mock import AsyncMock
import pytest
from app.diagnostics.slow_queries import analyze_slow_query_results, run_slow_queries
from app.models import SeverityEnum


@pytest.mark.asyncio
async def test_missing_extension_is_reported_with_availability():
    conn = AsyncMock()
    conn.fetchval.side_effect = [None, True]  # no schema; available for install

    result = await run_slow_queries(conn)
    assert result["installed"] is False
    assert result["available"] is True
    # The availability fact survives; the "run CREATE EXTENSION ..." instruction
    # does not -- diagnostic text is diagnosis only.
    assert "pg_available_extensions" in result["message"]
    assert "CREATE EXTENSION" not in result["message"]

    analysis = analyze_slow_query_results(result)
    assert analysis.severity == SeverityEnum.INFO
    assert "not installed" in analysis.summary


@pytest.mark.asyncio
async def test_resolves_non_default_schema():
    """Supabase installs the view into `extensions`, not `public`."""
    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.return_value = [
        {"query": "select 1", "calls": 5, "mean_exec_time_ms": 0.4,
         "total_exec_time_ms": 2.0, "rows": 5},
    ]

    result = await run_slow_queries(conn)
    assert result["schema"] == "extensions"
    assert result["readable"] is True
    # The emitted SQL must be schema-qualified, or it raises UndefinedTable.
    executed = conn.fetch.await_args[0][0]
    assert '"extensions".pg_stat_statements' in executed

    assert analyze_slow_query_results(result).severity == SeverityEnum.OK


@pytest.mark.asyncio
async def test_installed_but_unreadable_is_indeterminate_not_ok():
    """
    The regression this guards: the read raised, the module returned
    installed=True with an empty list, and the analyzer said
    'OK: No slow queries recorded'.
    """
    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.side_effect = Exception('permission denied for view pg_stat_statements')

    result = await run_slow_queries(conn)
    assert result["installed"] is True
    assert result["readable"] is False
    assert result["queries"] == []

    analysis = analyze_slow_query_results(result)
    assert analysis.severity == SeverityEnum.WARNING
    assert "INDETERMINATE" in analysis.summary
    assert not analysis.summary.startswith("OK")


@pytest.mark.asyncio
async def test_readable_and_empty_says_so_explicitly():
    """An empty result is OK only because the read succeeded -- the summary says which."""
    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.return_value = []

    analysis = analyze_slow_query_results(await run_slow_queries(conn))
    assert analysis.severity == SeverityEnum.OK
    assert "read successfully" in analysis.summary


@pytest.mark.asyncio
async def test_fully_redacted_statement_text_is_indeterminate():
    """
    Timings are real without pg_read_all_stats, but every statement's text comes
    back redacted -- so no hotspot can be named, and that is not a clean OK.
    """
    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.return_value = [
        {"query": "<insufficient privilege>", "calls": 8, "mean_exec_time_ms": 814.81,
         "total_exec_time_ms": 6518.49, "rows": 9568},
        {"query": "<insufficient privilege>", "calls": 1, "mean_exec_time_ms": 363.0,
         "total_exec_time_ms": 363.0, "rows": 0},
    ]

    result = await run_slow_queries(conn)
    assert result["redacted_count"] == 2
    assert result["observable_count"] == 0

    analysis = analyze_slow_query_results(result)
    assert analysis.severity == SeverityEnum.WARNING
    assert "INDETERMINATE" in analysis.summary
    assert "pg_read_all_stats" in analysis.summary


@pytest.mark.asyncio
async def test_redaction_is_noted_even_when_a_statement_is_genuinely_slow():
    """A real latency finding still stands; the caveat is appended, not substituted."""
    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.return_value = [
        {"query": "<insufficient privilege>", "calls": 8, "mean_exec_time_ms": 2500.0,
         "total_exec_time_ms": 20000.0, "rows": 100},
    ]

    analysis = analyze_slow_query_results(await run_slow_queries(conn))
    assert analysis.severity == SeverityEnum.WARNING
    assert "High query latency" in analysis.summary
    assert "cannot be named" in analysis.summary


@pytest.mark.asyncio
async def test_slow_statement_escalates_to_critical():
    conn = AsyncMock()
    conn.fetchval.return_value = "extensions"
    conn.fetch.return_value = [
        {"query": "select pg_sleep(9)", "calls": 3, "mean_exec_time_ms": 9000.0,
         "total_exec_time_ms": 27000.0, "rows": 3},
    ]

    analysis = analyze_slow_query_results(await run_slow_queries(conn))
    assert analysis.severity == SeverityEnum.CRITICAL
