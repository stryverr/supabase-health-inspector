"""
Tests for report construction.

Two invariants matter more than any single field:
  1. Diagnosis only -- no remediation, no suggested fixes, no SQL, anywhere.
  2. Every conclusion is computed from the diagnostic data, never from narration.
"""

import re
import pytest
from app.models import ScanReport, ScanRunSummary
from app.reporting.findings import build_finding, sanitize_observation, sort_findings
from app.reporting.markdown import render_markdown

SQL_PATTERN = re.compile(
    r"\b(CREATE|ALTER|DROP|GRANT|REVOKE|UPDATE|DELETE|INSERT|TRUNCATE)\s+[A-Za-z_\"]", re.I
)

# Mirrors the real stored payload for public.orders on Project B.
ORDERS_RAW = {
    "table_name": "orders",
    "rls_enabled": True,
    "policies": [{"policyname": "users see their own orders", "cmd": "SELECT",
                  "roles": ["authenticated"], "qual": "(user_id = (auth.uid())::text)"}],
    "has_select_privilege": True,
    "row_visibility": "no_policy_applies",
    "plan_proves_zero_rows": True,
    "policy_roles": ["authenticated"],
    "applicable_policy_count": 0,
    "current_role": "inspector_ro",
    "reltuples_estimate": None,
    "readable_rows_count": 0,
    "data_shape_source": "not_run",
    "data_shape_checked_columns": ["user_id"],
    "detected_issues": ["INDETERMINATE: no RLS policy on 'public.\"orders\"' applies..."],
}

PROFILES_RAW = {
    "table_name": "profiles",
    "rls_enabled": True,
    "policies": [{"policyname": "Anyone can read public profiles", "cmd": "SELECT",
                  "roles": ["public"], "qual": "(visibility = 'public'::text)"}],
    "has_select_privilege": True,
    "row_visibility": "readable",
    "plan_proves_zero_rows": False,
    "policy_roles": ["public"],
    "applicable_policy_count": 1,
    "current_role": "inspector_ro",
    "readable_rows_count": 2,
    "data_shape_source": "read_only",
    "data_shape_checked_columns": ["visibility"],
    "detected_issues": [],
}

EVENTS_RAW = {
    "table_name": "events",
    "rls_enabled": False,
    "policies": [],
    "has_select_privilege": True,
    "row_visibility": "readable",
    "policy_roles": [],
    "applicable_policy_count": 0,
    "current_role": "inspector_ro",
    "readable_rows_count": 500000,
    "data_shape_source": "read_only",
    "data_shape_checked_columns": [],
    "detected_issues": [],
}


# --- the no-remediation invariant --------------------------------------------

def test_sanitize_strips_remediation_sql():
    """
    rls_debug's whitespace finding ends with `Remediate with UPDATE ... btrim(...);`.
    A diagnosis-only report must not carry it.
    """
    text = (
        'Data-shape defect on \'public."orders".user_id\': 2 row(s) hold untrimmed '
        'whitespace. Remediate with UPDATE public."orders" SET "user_id" = btrim("user_id");'
    )
    out = sanitize_observation(text)

    assert "Remediate with" not in out
    assert "UPDATE" not in out
    assert "btrim" not in out or "untrimmed" in out
    assert "2 row(s) hold untrimmed whitespace" in out


def test_sanitize_strips_grant_suggestion():
    out = sanitize_observation(
        "INDETERMINATE: the role holds no SELECT privilege. Grant SELECT to the diagnostic role."
    )
    assert "Grant SELECT" not in out
    assert "no SELECT privilege" in out


def test_sanitize_leaves_pure_diagnosis_intact():
    text = "The connecting role is not a member of any policy target role."
    assert sanitize_observation(text) == text


def test_no_sql_survives_into_a_finding():
    raw = dict(ORDERS_RAW)
    raw["detected_issues"] = [
        'Defect found. Remediate with UPDATE public."orders" SET "user_id" = btrim("user_id");'
    ]
    f = build_finding("rls_debug", "critical", "CRITICAL: defect", raw, None, None)

    for text in [f.summary, f.probable_cause or "", f.scope_caveat or ""] + f.observations:
        assert not SQL_PATTERN.search(text), f"SQL leaked: {text!r}"


# --- computed cause: rls_debug ------------------------------------------------

def test_no_policy_applies_cause_names_role_policy_and_planner():
    f = build_finding("rls_debug", "warning", "INDETERMINATE: ...", ORDERS_RAW, None, None)

    assert f.affected["Table"] == "public.orders"
    assert f.affected["Policies"] == "users see their own orders"
    assert f.affected["Policy target roles"] == "authenticated"
    assert f.affected["Connecting role"] == "inspector_ro"

    cause = f.probable_cause
    assert "authenticated" in cause
    assert "inspector_ro" in cause
    assert "no policy applies" in cause
    assert "constant-false" in cause
    assert "property of the connection" in cause
    assert f.scope_caveat and "did not run" in f.scope_caveat


def test_rls_disabled_cause():
    f = build_finding("rls_debug", "critical", "CRITICAL: RLS not enabled", EVENTS_RAW, None, None)
    assert "not enabled" in f.probable_cause
    assert "public.events" in f.probable_cause


def test_readable_table_records_the_visible_row_scope():
    """profiles: 2 of 4 rows visible. The report must say the check was partial."""
    f = build_finding("rls_debug", "ok", "OK: ...", PROFILES_RAW, None, None)

    assert f.scope_caveat is not None
    assert "2 row(s)" in f.scope_caveat
    assert "hides" in f.scope_caveat or "hidden" in f.scope_caveat


def test_no_privilege_cause_is_distinct_from_rls_filtering():
    raw = dict(ORDERS_RAW, row_visibility="no_privilege", has_select_privilege=False,
               readable_rows_count=None)
    f = build_finding("rls_debug", "warning", "INDETERMINATE", raw, None, None)
    assert "no SELECT privilege" in f.probable_cause
    assert "grant-level" in f.probable_cause


def test_rls_filtered_cause_mentions_estimate_unavailable():
    raw = dict(ORDERS_RAW, row_visibility="rls_filtered", applicable_policy_count=1,
               reltuples_estimate=None)
    f = build_finding("rls_debug", "warning", "INDETERMINATE", raw, None, None)
    assert "never been analyzed" in f.probable_cause


# --- computed cause: other modules -------------------------------------------

def test_connection_health_cause_quantifies_redaction():
    raw = {"connections": [], "total_count": 5, "redacted_count": 4, "observable_count": 1}
    f = build_finding("connection_health", "warning", "INDETERMINATE", raw, None, None)

    assert f.affected["Redacted"] == "4"
    assert "pg_read_all_stats" in f.probable_cause
    assert "only" in f.scope_caveat


def test_slow_queries_cause_reports_redacted_statement_text():
    raw = {"installed": True, "readable": True, "schema": "extensions",
           "queries": [{"mean_exec_time_ms": 814.81}], "redacted_count": 1}
    f = build_finding("slow_queries", "ok", "OK", raw, None, None)

    assert f.affected["Schema"] == "extensions"
    assert "814.81ms" in f.probable_cause
    assert "cannot be identified" in f.scope_caveat


def test_vacuum_cause_names_the_oldest_table():
    raw = [{"relname": "orders", "xid_age": 6, "pct_to_wraparound": 0.0}]
    f = build_finding("vacuum_wraparound", "ok", "OK", raw, None, None)
    assert "public.orders" in f.probable_cause
    assert "2-billion" in f.probable_cause


def test_storage_cause_explains_untrustworthy_listing():
    raw = {"schema_present": True, "buckets": [], "policies": [],
           "can_select_buckets": True, "buckets_rls_enabled": True,
           "bucket_policy_count": 0, "listing_trustworthy": False}
    f = build_finding("storage_audit", "warning", "INDETERMINATE", raw, None, None)
    assert "row-level security" in f.probable_cause
    assert "not evidence" in f.scope_caveat


# --- narration provenance -----------------------------------------------------

def test_narration_is_carried_but_never_feeds_a_computed_field():
    misleading = "Everything looks perfectly healthy, no action needed."
    f = build_finding("rls_debug", "warning", "INDETERMINATE: ...", ORDERS_RAW,
                      misleading, "ollama")

    assert f.ai_explanation == misleading
    assert f.ai_provider == "ollama"
    # The computed cause contradicts the narration, which is the point.
    assert "no policy applies" in f.probable_cause
    assert "healthy" not in (f.probable_cause or "")


# --- ordering -----------------------------------------------------------------

def test_findings_sort_worst_severity_first():
    mk = lambda m, s: build_finding(m, s, "s", {"detected_issues": []}, None, None)
    ordered = sort_findings([mk("a", "ok"), mk("b", "critical"), mk("c", "info"), mk("d", "warning")])
    assert [f.severity for f in ordered] == ["critical", "warning", "info", "ok"]


# --- markdown export ----------------------------------------------------------

def _report():
    findings = sort_findings([
        build_finding("rls_debug", "warning", "INDETERMINATE: ...", ORDERS_RAW,
                      "Some narration.", "ollama"),
        build_finding("rls_debug", "critical", "CRITICAL: RLS not enabled", EVENTS_RAW, None, None),
    ])
    run = ScanRunSummary(
        id="11111111-1111-1111-1111-111111111111",
        started_at="2026-08-29T10:00:00Z",
        status="completed",
        target_connection_id="22222222-2222-2222-2222-222222222222",
        target_label="Project B", target_host="db.example.supabase.co",
        worst_severity="critical", module_count=2,
    )
    return ScanReport(run=run, findings=findings, severity_counts={"critical": 1, "warning": 1})


def test_markdown_contains_no_sql():
    md = render_markdown(_report())
    body = "\n".join(l for l in md.splitlines() if not l.strip().startswith(("{", '"', "}")))
    assert not SQL_PATTERN.search(body), "SQL leaked into the markdown export"


def test_markdown_groups_worst_severity_first():
    md = render_markdown(_report())
    assert md.index("## CRITICAL") < md.index("## WARNING")


def test_markdown_labels_narration_unverified():
    md = render_markdown(_report())
    assert "UNVERIFIED" in md
    assert "ollama" in md
    assert "not a diagnostic conclusion" in md


def test_markdown_includes_structured_fields_and_computed_cause():
    md = render_markdown(_report())
    assert "**Affected object**" in md
    assert "| Connecting role | `inspector_ro` |" in md
    assert "*(computed from the diagnostic data)*" in md
    assert "Scope of this check" in md


def test_markdown_states_the_diagnosis_only_scope():
    assert "contains no remediation" in render_markdown(_report())


# --- narration sanitisation (stored runs already contain remediation) ---------

from app.reporting.findings import sanitize_narration


def test_narration_sql_block_is_stripped():
    """
    Real stored narration from an earlier run. Before narration was constrained,
    the model emitted a fenced CREATE POLICY / GRANT pair into ai_explanation,
    which the report would otherwise render verbatim.
    """
    stored = (
        "The INDETERMINATE result indicates that the role 'inspector_ro' has no RLS "
        "policy on public.orders. To resolve this, create an RLS policy on "
        "public.orders that targets the 'inspector_ro' role.\n\n"
        "Example of a successful policy creation:\n"
        "```sql\n"
        "CREATE POLICY users_can_see_orders ON public.orders FOR SELECT USING (auth.uid()::text);\n"
        "GRANT EXECUTE ON POLICY users_can_see_orders TO public;\n"
        "```\n"
        "The planner returned zero rows without reading the heap."
    )
    out = sanitize_narration(stored)

    assert "CREATE POLICY" not in out
    assert "GRANT EXECUTE" not in out
    assert "To resolve this" not in out
    assert "Example of a successful policy creation" not in out
    # Diagnostic content survives.
    assert "no RLS policy on public.orders" in out
    assert "planner returned zero rows" in out
    assert "Remediation removed" in out


def test_narration_alter_table_advice_is_stripped():
    stored = (
        "The storage_audit module indicates RLS is enabled with no policies. "
        "To resolve this, RLS must be disabled on the storage.buckets table, which "
        "can be achieved by running ALTER TABLE storage.buckets DISABLE RLS; to allow "
        "the diagnostic role to trust the listing."
    )
    out = sanitize_narration(stored)
    assert "ALTER TABLE" not in out
    assert "must be disabled" not in out
    assert "RLS is enabled with no policies" in out


def test_narration_without_remediation_is_untouched():
    clean = (
        "The connecting role is not a member of the authenticated role, so no policy "
        "applies. The planner proved this statically."
    )
    assert sanitize_narration(clean) == clean


def test_narration_that_is_entirely_remediation_becomes_the_note():
    from app.reporting.findings import NARRATION_REDACTED_NOTE
    assert sanitize_narration("To fix this, you should grant SELECT.") == NARRATION_REDACTED_NOTE


def test_build_finding_sanitizes_narration():
    f = build_finding(
        "rls_debug", "warning", "INDETERMINATE", ORDERS_RAW,
        "No policy applies. To resolve this, you should create a policy.", "ollama",
    )
    assert "To resolve this" not in f.ai_explanation
    assert "No policy applies." in f.ai_explanation


def test_markdown_export_carries_no_remediation_from_narration():
    findings = [build_finding(
        "rls_debug", "warning", "INDETERMINATE: ...", ORDERS_RAW,
        "Cause explained.\n\n```sql\nCREATE POLICY p ON t FOR SELECT USING (true);\n```",
        "ollama",
    )]
    run = ScanRunSummary(
        id="11111111-1111-1111-1111-111111111111", started_at="2026-08-29T10:00:00Z",
        status="completed", target_connection_id="22222222-2222-2222-2222-222222222222",
        worst_severity="warning", module_count=1,
    )
    md = render_markdown(ScanReport(run=run, findings=findings, severity_counts={"warning": 1}))
    assert "CREATE POLICY" not in md


def test_narration_advisory_phrasing_is_stripped():
    """
    Remediation without the imperative mood. Real stored narration recommended
    periodic `VACUUM FULL` for XID age -- prescriptive, and wrong: FULL is not the
    remedy and takes an exclusive lock.
    """
    stored = (
        "The vacuum_wraparound result indicates that the transaction ID age of all public "
        "tables is within a healthy range. To maintain reliability, it is recommended to "
        "periodically run `VACUUM` with the `FULL` option on these tables."
    )
    out = sanitize_narration(stored)

    assert "recommended" not in out
    assert "VACUUM" not in out
    assert "within a healthy range" in out
    assert "Remediation removed" in out
