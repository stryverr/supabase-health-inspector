"""
Pytest suite for the Connection Health diagnostic module.

The central case: without pg_read_all_stats, pg_stat_activity returns
'<insufficient privilege>' and a NULL state for other users' backends. Counting
`state = 'idle in transaction'` across those rows finds nothing because the column
is blank, not because nothing is wrong. That must not be reported as OK.
"""

from unittest.mock import AsyncMock
import pytest
from app.diagnostics.connections import analyze_connection_results, run_connection_health
from app.models import SeverityEnum


def _row(pid, *, usename="app", state="active", wait_event_type=None, query="SELECT 1;",
         redacted=False, is_self=False, duration="00:00:01"):
    return {
        "pid": pid,
        "usename": usename,
        "state": state,
        "wait_event_type": wait_event_type,
        "wait_event": None,
        "state_duration": duration,
        "query": query,
        "query_redacted": redacted,
        "is_self": is_self,
    }


@pytest.mark.asyncio
async def test_detects_idle_in_transaction_when_visible():
    conn = AsyncMock()
    conn.fetch.return_value = [
        _row(3042, state="idle in transaction", wait_event_type="Client",
             query="SELECT * FROM orders FOR UPDATE;", is_self=True),
        _row(3043, is_self=True),
    ]

    result = await run_connection_health(conn)
    assert result["total_count"] == 2
    assert result["redacted_count"] == 0
    assert result["has_full_visibility"] is True

    analysis = analyze_connection_results(result)
    assert analysis.severity == SeverityEnum.CRITICAL
    assert "idle in transaction" in analysis.summary


@pytest.mark.asyncio
async def test_redacted_rows_are_counted_not_ignored():
    """Rows the role cannot see are identified by the marker string."""
    conn = AsyncMock()
    conn.fetch.return_value = [
        _row(1, usename="supabase_admin", state=None,
             query="<insufficient privilege>", redacted=True),
        _row(2, usename="authenticator", state=None,
             query="<insufficient privilege>", redacted=True),
        _row(3, usename="inspector_ro", is_self=True),
    ]

    result = await run_connection_health(conn)
    assert result["total_count"] == 3
    assert result["redacted_count"] == 2
    assert result["observable_count"] == 1
    assert result["has_full_visibility"] is False


@pytest.mark.asyncio
async def test_partial_visibility_is_indeterminate_not_ok():
    """
    The regression this guards: 4 of 5 rows opaque, no idle-in-transaction found,
    module reported 'OK: 0 idle-in-transaction'.
    """
    conn = AsyncMock()
    conn.fetch.return_value = [
        _row(i, usename="supabase_admin", state=None,
             query="<insufficient privilege>", redacted=True)
        for i in range(1, 5)
    ] + [_row(5, usename="inspector_ro", is_self=True)]

    result = await run_connection_health(conn)
    analysis = analyze_connection_results(result)

    assert analysis.severity == SeverityEnum.WARNING
    assert "INDETERMINATE" in analysis.summary
    assert "4 of them are opaque" in analysis.summary
    assert "pg_read_all_stats" in analysis.summary
    assert not analysis.summary.startswith("OK")


@pytest.mark.asyncio
async def test_full_visibility_and_clean_is_ok():
    """OK is reachable only when every row was legible."""
    conn = AsyncMock()
    conn.fetch.return_value = [_row(1, is_self=True), _row(2, is_self=True)]

    result = await run_connection_health(conn)
    analysis = analyze_connection_results(result)

    assert analysis.severity == SeverityEnum.OK
    assert "all observable" in analysis.summary


@pytest.mark.asyncio
async def test_null_state_on_another_users_backend_counts_as_redacted():
    """Even without the marker string, a NULL state on someone else's backend is opaque."""
    conn = AsyncMock()
    conn.fetch.return_value = [
        _row(1, usename="postgres", state=None, query="", redacted=False, is_self=False),
    ]

    result = await run_connection_health(conn)
    assert result["redacted_count"] == 1
