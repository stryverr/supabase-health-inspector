"""
Pytest suite for Vacuum and Wraparound diagnostic module (backend/tests/test_vacuum.py).
"""

from unittest.mock import AsyncMock
import pytest
from app.diagnostics.vacuum import analyze_vacuum_results, run_vacuum_check
from app.models import SeverityEnum


@pytest.mark.asyncio
async def test_run_vacuum_check_parsing():
    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [
        {"relname": "orders", "xid_age": 150000000, "pct_to_wraparound": 7.5},
        {"relname": "users", "xid_age": 1200000, "pct_to_wraparound": 0.06},
    ]

    result = await run_vacuum_check(mock_conn)
    assert len(result) == 2
    assert result[0]["relname"] == "orders"
    assert result[0]["pct_to_wraparound"] == 7.5


def test_analyze_vacuum_severity_critical():
    critical_data = [{"relname": "large_table", "xid_age": 1800000000, "pct_to_wraparound": 90.0}]
    analysis = analyze_vacuum_results(critical_data)
    assert analysis.severity == SeverityEnum.CRITICAL
    assert "CRITICAL" in analysis.summary


def test_analyze_vacuum_severity_healthy():
    healthy_data = [{"relname": "orders", "xid_age": 50000, "pct_to_wraparound": 0.002}]
    analysis = analyze_vacuum_results(healthy_data)
    assert analysis.severity == SeverityEnum.OK
