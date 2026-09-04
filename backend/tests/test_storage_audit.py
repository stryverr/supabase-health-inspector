"""
Pytest suite for the Storage Audit diagnostic module.

storage.buckets has RLS enabled on Supabase. A diagnostic role that no bucket
policy targets sees an empty list whether or not buckets exist, so an empty
listing cannot support the claim "no buckets are configured".
"""

from unittest.mock import AsyncMock
import pytest
from app.diagnostics.storage_audit import analyze_storage_results, run_storage_audit
from app.models import SeverityEnum


def _conn(*, schema_present=True, can_select=True, rls=True, bucket_policies=0,
          buckets=None, object_policies=None, read_error=None):
    conn = AsyncMock()
    conn.fetchval.side_effect = [schema_present, bucket_policies]
    conn.fetchrow.return_value = {"can_select": can_select, "rls_enabled": rls}

    fetches = []
    if can_select:
        if read_error:
            fetches.append(read_error)
        else:
            fetches.append(buckets or [])
    fetches.append(object_policies or [])
    conn.fetch.side_effect = fetches
    return conn


@pytest.mark.asyncio
async def test_empty_listing_under_rls_is_indeterminate_not_no_buckets():
    """
    The regression this guards: storage.buckets RLS-enabled with zero policies,
    zero rows visible, and the module announced 'No Supabase Storage buckets
    configured' -- a claim about the customer's project it had no standing to make.
    """
    conn = _conn(can_select=True, rls=True, bucket_policies=0, buckets=[])

    result = await run_storage_audit(conn)
    assert result["listing_trustworthy"] is False

    analysis = analyze_storage_results(result)
    assert analysis.severity == SeverityEnum.WARNING
    assert "INDETERMINATE" in analysis.summary
    assert "not evidence that none are configured" in analysis.summary
    assert "No Supabase Storage buckets are configured" not in analysis.summary


@pytest.mark.asyncio
async def test_empty_listing_without_rls_is_a_real_answer():
    """With RLS off, an empty list genuinely means no buckets."""
    conn = _conn(can_select=True, rls=False, bucket_policies=0, buckets=[])

    result = await run_storage_audit(conn)
    assert result["listing_trustworthy"] is True

    analysis = analyze_storage_results(result)
    assert analysis.severity == SeverityEnum.INFO
    assert "listing verified readable" in analysis.summary


@pytest.mark.asyncio
async def test_no_select_privilege_is_indeterminate():
    conn = _conn(can_select=False, rls=True)

    analysis = analyze_storage_results(await run_storage_audit(conn))
    assert analysis.severity == SeverityEnum.WARNING
    assert "no SELECT privilege" in analysis.summary


@pytest.mark.asyncio
async def test_public_bucket_without_object_policies_is_warned():
    """A confirmed exposure outranks any visibility caveat."""
    conn = _conn(
        can_select=True, rls=True, bucket_policies=1,
        buckets=[{"id": "avatars", "name": "avatars", "public": True}],
        object_policies=[],
    )

    analysis = analyze_storage_results(await run_storage_audit(conn))
    assert analysis.severity == SeverityEnum.WARNING
    assert "readable by anyone" in analysis.summary


@pytest.mark.asyncio
async def test_missing_storage_schema_is_info():
    conn = AsyncMock()
    conn.fetchval.return_value = False

    result = await run_storage_audit(conn)
    assert result["schema_present"] is False

    analysis = analyze_storage_results(result)
    assert analysis.severity == SeverityEnum.INFO
    assert "not present" in analysis.summary
