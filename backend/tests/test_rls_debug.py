"""
Unit tests for the RLS Debugger module.

The fixtures below mirror the real target table (see backend/app/seed/seed_demo.py):

    public.orders, user_id TEXT, RLS on,
    policy: FOR SELECT TO authenticated USING (user_id = auth.uid()::text)

That policy is CORRECT, so the type-mismatch heuristic must stay silent on it. The
defect lives in the data (trailing whitespace), which is only reachable by a
connection that can actually read rows. Everything here exists to pin down one
rule: a check that could not run is never reported as OK.
"""

import unittest
from unittest.mock import AsyncMock
from app.diagnostics.rls_debug import (
    _plan_proves_zero_rows,
    _references_column,
    analyze_rls_debug_results,
    run_rls_debug,
)
from app.models import DataShapeSourceEnum, RowVisibilityEnum, SeverityEnum

# The real policy shape: text column, auth.uid() explicitly cast to text, and note
# the parentheses -- pg_policies returns the deparsed expression, not source text.
CORRECT_POLICY_ROW = {
    "schemaname": "public",
    "tablename": "orders",
    "policyname": "users see their own orders",
    "permissive": "PERMISSIVE",
    "roles": ["authenticated"],
    "cmd": "SELECT",
    "qual": "(user_id = (auth.uid())::text)",
    "with_check": None,
}

USER_ID_TEXT_COLUMN = {"column_name": "user_id", "data_type": "text", "udt_name": "text"}

# A normal scan: the planner has a filter to apply and will read the heap.
PLAN_SEQ_SCAN = '[{"Plan": {"Node Type": "Seq Scan", "Filter": "(user_id = ...)"}}]'

# What Postgres emits when no policy targets the connecting role: it proves at plan
# time that nothing can match, with no heap access at all.
PLAN_CONST_FALSE = '[{"Plan": {"Node Type": "Result", "Plan Rows": 0, "One-Time Filter": "false"}}]'


def _mock_conn(
    *,
    rls_enabled=True,
    has_privilege=True,
    reltuples=-1,
    visible_rows=0,
    policy_rows=None,
    column_rows=None,
    plan=PLAN_SEQ_SCAN,
    role_applies=False,
    current_role="inspector_ro",
    extra_fetchvals=None,
):
    """
    Builds an AsyncMock following run_rls_debug's actual call order.

    fetchval: valid_table, rowsecurity, EXPLAIN, current_user, has_table_privilege,
              reltuples, [count(*) if privileged], [whitespace checks...]
    fetch:    policies, columns, [policy role applicability if any roles]
    """
    conn = AsyncMock()
    policy_rows = [CORRECT_POLICY_ROW] if policy_rows is None else policy_rows
    column_rows = [USER_ID_TEXT_COLUMN] if column_rows is None else column_rows

    fetchvals = [True, rls_enabled, plan, current_role, has_privilege, reltuples]
    if has_privilege:
        fetchvals.append(visible_rows)
    if extra_fetchvals:
        fetchvals.extend(extra_fetchvals)
    conn.fetchval.side_effect = fetchvals

    fetches = [policy_rows, column_rows]
    distinct_roles = sorted({r for p in policy_rows for r in (p.get("roles") or [])})
    if distinct_roles:
        fetches.append([{"rolname": r, "has_role": role_applies} for r in distinct_roles])
    conn.fetch.side_effect = fetches
    return conn


class TestPlanProvesZeroRows(unittest.TestCase):
    def test_detects_constant_false_result_node(self):
        self.assertTrue(_plan_proves_zero_rows([{"Plan": {"One-Time Filter": "false"}}]))

    def test_ordinary_scan_is_not_a_proof(self):
        self.assertFalse(_plan_proves_zero_rows([{"Plan": {"Node Type": "Seq Scan"}}]))

    def test_finds_nested_constant_false(self):
        plan = [{"Plan": {"Node Type": "Append", "Plans": [
            {"Node Type": "Seq Scan"},
            {"Node Type": "Result", "One-Time Filter": "false"},
        ]}}]
        self.assertTrue(_plan_proves_zero_rows(plan))

    def test_a_true_one_time_filter_is_not_a_proof(self):
        self.assertFalse(_plan_proves_zero_rows([{"Plan": {"One-Time Filter": "true"}}]))

    def test_tolerates_missing_or_malformed_plan(self):
        self.assertFalse(_plan_proves_zero_rows(None))
        self.assertFalse(_plan_proves_zero_rows({"error": "EXPLAIN failed"}))


class TestReferencesColumn(unittest.TestCase):
    def test_matches_whole_identifier_only(self):
        expr = "(user_id = (auth.uid())::text)"
        self.assertTrue(_references_column(expr, "user_id"))
        # The bug this replaced: substring matching found 'id' inside 'user_id'.
        self.assertFalse(_references_column(expr, "id"))

    def test_matches_quoted_identifier(self):
        self.assertTrue(_references_column('("user_id" = x)', "user_id"))

    def test_does_not_match_prefix_or_suffix(self):
        self.assertFalse(_references_column("(user_ident = x)", "user_id"))
        self.assertFalse(_references_column("(xuser_id = x)", "user_id"))


class TestRLSDebug(unittest.IsolatedAsyncioTestCase):
    async def test_table_validation_rejects_unknown_identifier(self):
        conn = AsyncMock()
        conn.fetchval.return_value = False
        with self.assertRaises(ValueError):
            await run_rls_debug(conn, "malicious_table; DROP TABLE users;")

    async def test_correct_policy_does_not_trigger_type_mismatch(self):
        """
        user_id TEXT against auth.uid()::text is correct. Flagging it would bury the
        real defect under a false positive -- and pg_policies returns the deparsed
        form '(auth.uid())::text', which a naive pattern misses.
        """
        conn = _mock_conn(plan=PLAN_CONST_FALSE)
        result = await run_rls_debug(conn, "orders")
        type_issues = [i for i in result["detected_issues"] if i.startswith("Policy '")]
        self.assertEqual(type_issues, [], f"unexpected type-mismatch findings: {type_issues}")

    async def test_no_policy_applies_is_distinguished_from_rls_filtering(self):
        """
        The Project B case: the only policy targets `authenticated`, inspector_ro is
        not a member, so it can never see any row. The planner proves this statically.
        """
        conn = _mock_conn(plan=PLAN_CONST_FALSE, role_applies=False)
        result = await run_rls_debug(conn, "orders")

        self.assertEqual(result["row_visibility"], RowVisibilityEnum.NO_POLICY_APPLIES.value)
        self.assertTrue(result["plan_proves_zero_rows"])
        self.assertEqual(result["applicable_policy_count"], 0)
        self.assertEqual(result["policy_roles"], ["authenticated"])

        issue = next(i for i in result["detected_issues"] if i.startswith("INDETERMINATE:"))
        self.assertIn("no RLS policy", issue)
        self.assertIn("One-Time Filter: false", issue)
        self.assertIn("property of the connection, not a defect in the table", issue)
        # Must NOT claim rows were filtered -- nothing was ever scanned.
        self.assertNotIn("every row was filtered out", issue)

        analysis = analyze_rls_debug_results(result)
        self.assertEqual(analysis.severity, SeverityEnum.WARNING)
        self.assertIn("no policy targets the connecting role", analysis.summary)

    async def test_rls_filtered_when_a_policy_does_apply(self):
        """
        The other zero-row state: a policy applies to this role and filtered every
        row. Same count(*) = 0, different problem, different message.
        """
        conn = _mock_conn(plan=PLAN_SEQ_SCAN, role_applies=True)
        result = await run_rls_debug(conn, "orders")

        self.assertEqual(result["row_visibility"], RowVisibilityEnum.RLS_FILTERED.value)
        self.assertFalse(result["plan_proves_zero_rows"])
        self.assertEqual(result["applicable_policy_count"], 1)

        issue = next(i for i in result["detected_issues"] if i.startswith("INDETERMINATE:"))
        self.assertIn("every row was filtered out", issue)
        self.assertNotIn("no RLS policy", issue)

        analysis = analyze_rls_debug_results(result)
        self.assertEqual(analysis.severity, SeverityEnum.WARNING)
        self.assertIn("RLS filtered every row", analysis.summary)

    async def test_never_analyzed_table_reports_estimate_unavailable_not_zero(self):
        """
        The original regression: reltuples is -1 on a never-analyzed table, so a
        `reltuples > 0` guard never fires and the module fell through to OK.
        """
        conn = _mock_conn(reltuples=-1, plan=PLAN_CONST_FALSE)
        result = await run_rls_debug(conn, "orders")

        self.assertIsNone(result["reltuples_estimate"], "reltuples -1 must read as 'unavailable'")
        self.assertTrue(result["has_select_privilege"])
        self.assertEqual(result["readable_rows_count"], 0)
        self.assertEqual(result["data_shape_source"], DataShapeSourceEnum.NOT_RUN.value)

        analysis = analyze_rls_debug_results(result)
        self.assertEqual(analysis.severity, SeverityEnum.WARNING)
        self.assertIn("INDETERMINATE", analysis.summary)

    async def test_missing_select_privilege_reports_differently(self):
        conn = _mock_conn(has_privilege=False)
        result = await run_rls_debug(conn, "orders")

        self.assertEqual(result["row_visibility"], RowVisibilityEnum.NO_PRIVILEGE.value)
        self.assertIsNone(result["readable_rows_count"])
        self.assertTrue(any("no SELECT privilege" in i for i in result["detected_issues"]))
        self.assertFalse(any("every row was filtered out" in i for i in result["detected_issues"]))
        self.assertEqual(analyze_rls_debug_results(result).severity, SeverityEnum.WARNING)

    async def test_elevated_connection_detects_trailing_whitespace(self):
        conn = _mock_conn(plan=PLAN_CONST_FALSE)
        elevated = AsyncMock()
        elevated.fetchval.return_value = 2  # two rows carry a trailing space

        result = await run_rls_debug(conn, "orders", elevated_conn=elevated)

        self.assertEqual(result["data_shape_source"], DataShapeSourceEnum.ELEVATED.value)
        whitespace = [i for i in result["detected_issues"] if "untrimmed whitespace" in i]
        self.assertEqual(len(whitespace), 1)
        self.assertIn("2 row(s)", whitespace[0])
        self.assertIn("elevated connection", whitespace[0])
        self.assertEqual(analyze_rls_debug_results(result).severity, SeverityEnum.CRITICAL)

    async def test_readable_and_clean_table_reports_ok(self):
        """A genuinely readable table with no defects is the only path to OK."""
        conn = _mock_conn(
            reltuples=3, visible_rows=3, role_applies=True, extra_fetchvals=[0]
        )
        result = await run_rls_debug(conn, "orders")

        self.assertEqual(result["row_visibility"], RowVisibilityEnum.READABLE.value)
        self.assertEqual(result["data_shape_source"], DataShapeSourceEnum.READ_ONLY.value)
        self.assertEqual(result["reltuples_estimate"], 3)
        self.assertEqual(result["detected_issues"], [])
        self.assertEqual(analyze_rls_debug_results(result).severity, SeverityEnum.OK)

    async def test_whitespace_check_error_is_captured_not_swallowed(self):
        conn = _mock_conn(
            reltuples=10,
            visible_rows=10,
            role_applies=True,
            extra_fetchvals=[Exception("permission denied for relation orders")],
        )
        result = await run_rls_debug(conn, "orders")

        self.assertTrue(any("whitespace check" in i for i in result["detected_issues"]))
        self.assertTrue(any("permission denied" in i for i in result["detected_issues"]))
        self.assertEqual(analyze_rls_debug_results(result).severity, SeverityEnum.WARNING)

    async def test_uuid_column_against_text_cast_is_flagged(self):
        conn = _mock_conn(
            policy_rows=[{**CORRECT_POLICY_ROW, "qual": "(owner = (auth.uid())::text)"}],
            column_rows=[{"column_name": "owner", "data_type": "uuid", "udt_name": "uuid"}],
            plan=PLAN_CONST_FALSE,
        )
        result = await run_rls_debug(conn, "orders")

        self.assertTrue(any("bypasses any index" in i for i in result["detected_issues"]))
        self.assertEqual(analyze_rls_debug_results(result).severity, SeverityEnum.CRITICAL)


class TestAnalyzeRLSResults(unittest.TestCase):
    def test_consistent_metadata_without_data_shape_checks_is_not_ok(self):
        analysis = analyze_rls_debug_results({
            "table_name": "orders",
            "rls_enabled": True,
            "policies": [CORRECT_POLICY_ROW],
            "detected_issues": [],
            "data_shape_source": DataShapeSourceEnum.NOT_RUN.value,
        })
        self.assertEqual(analysis.severity, SeverityEnum.WARNING)
        self.assertIn("INDETERMINATE", analysis.summary)

    def test_rls_disabled_is_critical(self):
        analysis = analyze_rls_debug_results({
            "table_name": "orders",
            "rls_enabled": False,
            "policies": [],
            "detected_issues": [],
            "data_shape_source": DataShapeSourceEnum.NOT_RUN.value,
        })
        self.assertEqual(analysis.severity, SeverityEnum.CRITICAL)


if __name__ == "__main__":
    unittest.main()
