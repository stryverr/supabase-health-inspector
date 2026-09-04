"""
Diagnostic Module 4: Supabase Storage Bucket Security & RLS Policy Auditor.

Audits storage.buckets and storage.objects policies for unintentional public
exposure.

storage.buckets has RLS enabled on Supabase, so the same trap applies here as on
any user table: a diagnostic role that is not targeted by any policy sees zero
rows, and "zero buckets visible" is not the same claim as "no buckets configured."
An earlier version reported the latter, which is a statement about the customer's
project that this role has no standing to make.
"""

from typing import Any, Dict, List
import asyncpg
from app.models import DiagnosticModuleEnum, DiagnosticSummary, SeverityEnum


async def run_storage_audit(conn: asyncpg.Connection) -> Dict[str, Any]:
    """
    Audits storage.buckets and storage.objects policies, recording whether the
    bucket listing is trustworthy.
    """
    buckets_exist = await conn.fetchval(
        """
        SELECT count(*) > 0
        FROM information_schema.tables
        WHERE table_schema = 'storage' AND table_name = 'buckets';
        """
    )

    if not buckets_exist:
        return {
            "schema_present": False,
            "buckets": [],
            "policies": [],
            "listing_trustworthy": True,
            "note": "Supabase Storage schema (storage.buckets) not found in target database.",
        }

    # Can this role read the bucket list at all, and is RLS in play?
    meta = await conn.fetchrow(
        """
        SELECT has_table_privilege(current_user, 'storage.buckets', 'SELECT') AS can_select,
               c.relrowsecurity AS rls_enabled
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'storage' AND c.relname = 'buckets';
        """
    )
    can_select = bool(meta["can_select"]) if meta else False
    buckets_rls = bool(meta["rls_enabled"]) if meta else False

    bucket_policy_count = await conn.fetchval(
        "SELECT count(*) FROM pg_policies WHERE schemaname = 'storage' AND tablename = 'buckets';"
    )

    buckets: List[Dict[str, Any]] = []
    read_error = None
    if can_select:
        try:
            rows = await conn.fetch("SELECT id, name, public FROM storage.buckets;")
            buckets = [dict(b) for b in rows]
        except Exception as e:
            read_error = str(e)

    # An empty listing is only meaningful when RLS could not have hidden rows.
    listing_trustworthy = bool(
        can_select
        and read_error is None
        and (buckets or not buckets_rls or (bucket_policy_count or 0) > 0)
    )

    policy_rows = await conn.fetch(
        """
        SELECT schemaname, tablename, policyname, permissive, roles::text[] as roles, cmd, qual, with_check
        FROM pg_policies
        WHERE schemaname = 'storage' AND tablename = 'objects';
        """
    )

    return {
        "schema_present": True,
        "buckets": buckets,
        "policies": [dict(p) for p in policy_rows],
        "can_select_buckets": can_select,
        "buckets_rls_enabled": buckets_rls,
        "bucket_policy_count": bucket_policy_count or 0,
        "listing_trustworthy": listing_trustworthy,
        "read_error": read_error,
    }


def analyze_storage_results(raw_data: Dict[str, Any]) -> DiagnosticSummary:
    buckets = raw_data.get("buckets", [])
    policies = raw_data.get("policies", [])

    if not raw_data.get("schema_present", True):
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.STORAGE_AUDIT,
            severity=SeverityEnum.INFO,
            summary="INFO: Supabase Storage schema (storage.buckets) is not present in the target database.",
            raw_result=raw_data,
        )

    # Confirmed exposure outranks visibility gaps: these buckets were actually seen.
    public_buckets = [b for b in buckets if b.get("public") is True]
    if public_buckets and not policies:
        names = ", ".join(str(b["name"]) for b in public_buckets)
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.STORAGE_AUDIT,
            severity=SeverityEnum.WARNING,
            summary=f"WARNING: Public bucket(s) [{names}] exist with ZERO policies on storage.objects. Objects are readable by anyone.",
            raw_result=raw_data,
        )

    if not raw_data.get("listing_trustworthy", True):
        if not raw_data.get("can_select_buckets"):
            reason = "the diagnostic role holds no SELECT privilege on storage.buckets"
        elif raw_data.get("read_error"):
            reason = f"reading storage.buckets failed: {raw_data['read_error']}"
        else:
            reason = (
                f"storage.buckets has RLS enabled with {raw_data.get('bucket_policy_count', 0)} "
                f"policy(ies), so the diagnostic role sees an empty list whether or not buckets exist"
            )
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.STORAGE_AUDIT,
            severity=SeverityEnum.WARNING,
            summary=(
                f"INDETERMINATE: the storage bucket listing could not be trusted -- {reason}. "
                f"0 bucket(s) were visible, which is not evidence that none are configured. "
                f"Storage exposure could not be assessed."
            ),
            raw_result=raw_data,
        )

    if not buckets:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.STORAGE_AUDIT,
            severity=SeverityEnum.INFO,
            summary="INFO: No Supabase Storage buckets are configured in the target database (listing verified readable).",
            raw_result=raw_data,
        )

    if not policies:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.STORAGE_AUDIT,
            severity=SeverityEnum.WARNING,
            summary=f"WARNING: {len(buckets)} bucket(s) found but no RLS policies on storage.objects. Private uploads/downloads may be inaccessible.",
            raw_result=raw_data,
        )

    return DiagnosticSummary(
        module=DiagnosticModuleEnum.STORAGE_AUDIT,
        severity=SeverityEnum.OK,
        summary=f"OK: {len(buckets)} storage bucket(s) audited with {len(policies)} active object policies.",
        raw_result=raw_data,
    )
