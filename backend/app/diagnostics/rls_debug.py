"""
Diagnostic Module 2: Row Level Security (RLS) & Policy Metadata Inspector.

Inspects pg_policies metadata, table rowsecurity status, column data types,
read-access reality, and PostgreSQL query planner output.

Design constraint: this module runs as an unprivileged, read-only role that is
deliberately NOT a member of `authenticated`. It therefore sees zero rows on any
RLS-protected table. Every conclusion below is drawn from catalog metadata and
planner output, which require no access to customer data. Where a check genuinely
needs to read rows, the module reports INDETERMINATE rather than guessing --
unless an explicitly configured elevated connection is supplied (see
`TARGET_ELEVATED_DATABASE_URL`), in which case the finding records which
connection produced it.
"""

import json
import re
import time
from typing import Any, Dict, List, Optional
import asyncpg
from app.models import (
    DataShapeSourceEnum,
    DiagnosticModuleEnum,
    DiagnosticSummary,
    RLSPolicyInfo,
    RowVisibilityEnum,
    SeverityEnum,
)

TEXT_DATA_TYPES = {"text", "varchar", "character varying", "char", "bpchar", "citext"}

# auth.uid() returns uuid. These two forms are what the type-mismatch heuristic
# needs to tell apart; matching a bare "::text" anywhere in the expression is not
# good enough, because the cast may belong to an unrelated column.
#
# pg_policies.qual is the deparsed expression, not the source text: a policy
# written as `auth.uid()::text` reads back as `(auth.uid())::text`. The optional
# closing parens below absorb that wrapping, which a naive `auth\.uid\(\)::text`
# pattern misses -- and missing it inverts the verdict, flagging the correct
# policy as a type mismatch while letting the genuinely broken one through.
_AUTH_UID_WITH_TEXT_CAST = re.compile(r"auth\.uid\(\)\s*\)*\s*::\s*text", re.IGNORECASE)
_AUTH_UID = re.compile(r"auth\.uid\(\)", re.IGNORECASE)


def _references_column(expression: str, column_name: str) -> bool:
    """
    True when `expression` references `column_name` as a whole SQL identifier.

    Plain substring matching reports a false positive for every column whose name
    is contained in another: a column named `id` matches inside `user_id`. Double
    quotes are not identifier characters, so a quoted "user_id" still matches.
    """
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(column_name)}(?![A-Za-z0-9_])"
    return re.search(pattern, expression) is not None


def _quote_ident(identifier: str) -> str:
    """Escapes an identifier for interpolation inside a double-quoted SQL name."""
    return identifier.replace('"', '""')


def _plan_proves_zero_rows(plan: Any) -> bool:
    """
    True when the planner collapsed the query to a constant-false filter.

    When no RLS policy targets the connecting role, Postgres does not scan and
    discard -- it proves at plan time that nothing can match and emits a Result
    node carrying `"One-Time Filter": "false"`, with no heap access at all.

    That is a stronger and cheaper signal than `count(*) = 0`: a zero count could
    mean an empty table, or a policy that filtered these particular rows, whereas
    this means the role is structurally unable to see any row of the table.
    """

    def walk(node: Any) -> bool:
        if isinstance(node, list):
            return any(walk(item) for item in node)
        if not isinstance(node, dict):
            return False
        if str(node.get("One-Time Filter", "")).strip().lower() == "false":
            return True
        return any(walk(node[key]) for key in ("Plan", "Plans") if key in node)

    return walk(plan)


async def _policy_role_applicability(
    conn: asyncpg.Connection, policies: List[RLSPolicyInfo]
) -> tuple:
    """
    Returns (distinct_policy_roles, applicable_policy_count).

    A policy applies to the caller when it targets PUBLIC or a role the caller is a
    member of. This is an independent, metadata-side corroboration of what the
    planner proves, so the two signals can be cross-checked rather than trusted alone.
    """
    distinct_roles = sorted({r for p in policies for r in (p.roles or [])})
    if not distinct_roles:
        return [], 0

    rows = await conn.fetch(
        """
        SELECT r AS rolname,
               CASE
                   WHEN lower(r) = 'public' THEN true
                   WHEN to_regrole(r) IS NULL THEN false
                   ELSE pg_has_role(current_user, to_regrole(r), 'USAGE')
               END AS has_role
        FROM unnest($1::text[]) AS r;
        """,
        distinct_roles,
    )
    held = {r["rolname"] for r in rows if r["has_role"]}

    applicable = sum(
        1 for p in policies if any(role in held for role in (p.roles or []))
    )
    return distinct_roles, applicable


async def run_rls_debug(
    conn: asyncpg.Connection,
    table_name: str,
    elevated_conn: Optional[asyncpg.Connection] = None,
) -> Dict[str, Any]:
    """
    Analyzes RLS configuration for a table from catalog metadata and planner output.

    `conn` is the standard read-only diagnostic connection. `elevated_conn`, when
    supplied, is an explicitly opted-in higher-privilege connection used ONLY for
    data-shape checks that require reading rows; every such finding records which
    connection produced it.
    """
    start_time = time.perf_counter()

    # 1. Strictly validate table_name against information_schema.tables to prevent SQL injection
    is_valid_table = await conn.fetchval(
        """
        SELECT count(*) > 0
        FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = $1;
        """,
        table_name,
    )

    if not is_valid_table:
        raise ValueError(
            f"Table 'public.{table_name}' does not exist or is not accessible in information_schema.tables."
        )

    quoted = _quote_ident(table_name)
    qualified = f'public."{quoted}"'

    # 2. Query RLS status (rowsecurity) from pg_tables
    rls_enabled = await conn.fetchval(
        """
        SELECT rowsecurity
        FROM pg_tables
        WHERE schemaname = 'public' AND tablename = $1;
        """,
        table_name,
    )

    # 3. Query all active RLS policies on the table from pg_policies
    policy_rows = await conn.fetch(
        """
        SELECT schemaname, tablename, policyname, permissive, roles::text[] as roles,
               cmd, qual, with_check
        FROM pg_policies
        WHERE schemaname = 'public' AND tablename = $1;
        """,
        table_name,
    )

    policies = [
        RLSPolicyInfo(
            schemaname=r["schemaname"],
            tablename=r["tablename"],
            policyname=r["policyname"],
            permissive=r["permissive"],
            roles=r["roles"] or [],
            cmd=r["cmd"],
            qual=r["qual"],
            with_check=r["with_check"],
        )
        for r in policy_rows
    ]

    # 4. Query table column definitions to check column data types against policy expressions
    col_rows = await conn.fetch(
        """
        SELECT column_name, data_type, udt_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = $1;
        """,
        table_name,
    )
    columns_map = {
        r["column_name"]: {"data_type": r["data_type"], "udt_name": r["udt_name"]}
        for r in col_rows
    }

    # 5. Analyze policy expressions for type mismatches and identify candidate text columns
    detected_issues: List[str] = []
    checked_text_cols: set = set()

    for p in policies:
        qual_str = p.qual or ""
        with_check_str = p.with_check or ""
        full_expr = f"{qual_str} {with_check_str}"

        if _AUTH_UID.search(full_expr):
            casts_uid_to_text = bool(_AUTH_UID_WITH_TEXT_CAST.search(full_expr))

            for col_name, col_info in columns_map.items():
                if not _references_column(full_expr, col_name):
                    continue

                col_type = (col_info.get("udt_name") or "").lower()

                if col_type == "uuid" and casts_uid_to_text:
                    detected_issues.append(
                        f"Policy '{p.policyname}': column '{col_name}' is uuid, but the policy "
                        f"compares it against auth.uid()::text. The uuid side is cast to text for "
                        f"every row, which bypasses any index on '{col_name}' (Supabase issue #49106)."
                    )
                elif col_type in TEXT_DATA_TYPES and not casts_uid_to_text:
                    detected_issues.append(
                        f"Policy '{p.policyname}': column '{col_name}' is {col_type}, but auth.uid() "
                        f"returns uuid and is not cast. Postgres has no text = uuid operator, so this "
                        f"policy errors or silently filters every row."
                    )

        # Identify text columns referenced in policy quals for data-shape checking
        for col_name, col_info in columns_map.items():
            col_type = (col_info.get("udt_name") or "").lower()
            if col_type in TEXT_DATA_TYPES and _references_column(qual_str, col_name):
                checked_text_cols.add(col_name)

    # 6. Query planner output, captured BEFORE the read-access verdict because the
    # plan is evidence that verdict depends on.
    #
    # EXPLAIN without ANALYZE: ANALYZE would execute the query, and the plan alone
    # already shows what the planner derived from the policy. Note that when no
    # policy targets the connecting role there is no filter to show -- see
    # _plan_proves_zero_rows.
    captured_plan: Optional[Any] = None
    plan_error: Optional[str] = None
    try:
        raw_plan_str = await conn.fetchval(
            f"EXPLAIN (VERBOSE, FORMAT JSON) SELECT * FROM {qualified};"
        )
        if raw_plan_str:
            captured_plan = json.loads(raw_plan_str) if isinstance(raw_plan_str, str) else raw_plan_str
    except Exception as e:
        plan_error = str(e)
        detected_issues.append(
            f"INDETERMINATE: query planner EXPLAIN failed for '{qualified}': {plan_error}"
        )
        captured_plan = {"error": f"EXPLAIN error: {plan_error}"}

    plan_proves_zero_rows = _plan_proves_zero_rows(captured_plan)

    # 7. Whether any policy targets the connecting role at all -- the metadata-side
    # counterpart to what the planner proved.
    policy_roles, applicable_policy_count = await _policy_role_applicability(conn, policies)
    current_role = await conn.fetchval("SELECT current_user;")

    # 8. Read-access verification.
    #
    # Four states must be told apart, because only the last can support a
    # trustworthy "no data-shape problems" answer:
    #   (a) no SELECT privilege            -> INDETERMINATE, needs a GRANT
    #   (b) no policy targets this role    -> INDETERMINATE, structurally invisible
    #   (c) a policy applies, 0 rows left  -> INDETERMINATE, RLS filtered the rows
    #   (d) rows visible                   -> data-shape checks are meaningful
    #
    # (b) and (c) both show `count(*) = 0` and were previously reported identically,
    # but they are different problems: (b) means this role can never see any row of
    # the table no matter what it contains, while (c) means the policy ran and these
    # particular rows did not match.
    #
    # has_table_privilege separates (a) from the rest because it is a fact about a
    # GRANT, independent of RLS. reltuples is only corroborating evidence: it is -1
    # on a table that has never been analyzed, meaning "estimate unavailable", NOT
    # "zero rows". Treating -1 as a row count is what previously let this module
    # fall through and report OK on a table it could not read.
    has_select_privilege = await conn.fetchval(
        "SELECT has_table_privilege(current_user, $1, 'SELECT');",
        qualified,
    )

    reltuples_raw = await conn.fetchval(
        """
        SELECT reltuples::bigint
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relname = $1;
        """,
        table_name,
    )
    reltuples_estimate: Optional[int] = None
    if reltuples_raw is not None and int(reltuples_raw) >= 0:
        reltuples_estimate = int(reltuples_raw)
    estimate_note = (
        f"pg_class estimates ~{reltuples_estimate} row(s)"
        if reltuples_estimate is not None
        else "pg_class holds no row estimate for this table (never analyzed)"
    )

    readable_rows_count: Optional[int] = None
    if has_select_privilege:
        try:
            visible_val = await conn.fetchval(f"SELECT count(*) FROM {qualified};")
            readable_rows_count = int(visible_val) if visible_val is not None else 0
        except Exception as e:
            detected_issues.append(
                f"INDETERMINATE: SELECT on '{qualified}' failed for the diagnostic role despite "
                f"has_table_privilege reporting true: {str(e)}. Data-shape checks were skipped."
            )

    if not has_select_privilege:
        row_visibility = RowVisibilityEnum.NO_PRIVILEGE
    elif readable_rows_count is None:
        row_visibility = RowVisibilityEnum.UNKNOWN
    elif readable_rows_count > 0:
        row_visibility = RowVisibilityEnum.READABLE
    elif rls_enabled and policies and applicable_policy_count == 0:
        # No policy targets this role. The planner normally proves this statically;
        # the metadata check stands on its own if the plan was unavailable.
        row_visibility = RowVisibilityEnum.NO_POLICY_APPLIES
    elif plan_proves_zero_rows and rls_enabled and policies:
        row_visibility = RowVisibilityEnum.NO_POLICY_APPLIES
    else:
        row_visibility = RowVisibilityEnum.RLS_FILTERED

    # 9. Data-shape checks, run over whichever connection can actually see rows.
    data_shape_source = DataShapeSourceEnum.NOT_RUN
    shape_conn: Optional[asyncpg.Connection] = None

    if elevated_conn is not None:
        shape_conn = elevated_conn
        data_shape_source = DataShapeSourceEnum.ELEVATED
    elif readable_rows_count is not None and readable_rows_count > 0:
        shape_conn = conn
        data_shape_source = DataShapeSourceEnum.READ_ONLY

    if shape_conn is None:
        # No connection can read rows. Say precisely why -- the states have
        # different fixes, and none of them is "OK".
        cols_note = (
            f" Text column(s) the policy depends on that went unchecked: {sorted(checked_text_cols)}."
            if checked_text_cols
            else ""
        )
        if row_visibility == RowVisibilityEnum.NO_PRIVILEGE:
            detected_issues.append(
                f"INDETERMINATE: the diagnostic role holds no SELECT privilege on '{qualified}' "
                f"(has_table_privilege = false), so data-shape checks could not run.{cols_note}"
            )
        elif row_visibility == RowVisibilityEnum.NO_POLICY_APPLIES:
            proof = (
                " The planner proved this statically: the query collapses to a constant-false "
                "Result node (One-Time Filter: false), returning 0 rows without reading the heap."
                if plan_proves_zero_rows
                else ""
            )
            detected_issues.append(
                f"INDETERMINATE: no RLS policy on '{qualified}' applies to the connecting role "
                f"'{current_role}'. The {len(policies)} policy(ies) present target {policy_roles}, "
                f"and '{current_role}' is a member of none of them, so this role cannot see any row "
                f"of this table regardless of its contents.{proof} Data-shape checks could not run. "
                f"This is a property of the connection, not a defect in the table.{cols_note}"
            )
        elif row_visibility == RowVisibilityEnum.RLS_FILTERED:
            detected_issues.append(
                f"INDETERMINATE: {applicable_policy_count} policy(ies) on '{qualified}' apply to the "
                f"connecting role '{current_role}', and every row was filtered out — the table is not "
                f"necessarily empty ({estimate_note}). Data-shape checks could not run: row contents are "
                f"reachable only through the opt-in elevated connection, which is not configured.{cols_note}"
            )
        elif row_visibility == RowVisibilityEnum.UNKNOWN:
            # The SELECT raised; that error is already recorded above.
            pass
        else:
            detected_issues.append(
                f"INDETERMINATE: data-shape checks did not run on '{qualified}'.{cols_note}"
            )
    else:
        source_label = (
            "the opt-in elevated connection (TARGET_ELEVATED_DATABASE_URL)"
            if data_shape_source == DataShapeSourceEnum.ELEVATED
            else "the read-only diagnostic connection"
        )
        for col_name in sorted(checked_text_cols):
            col_q = _quote_ident(col_name)
            try:
                untrimmed_count = await shape_conn.fetchval(
                    f'SELECT count(*) FROM {qualified} WHERE "{col_q}" <> btrim("{col_q}");'
                )
                if untrimmed_count and untrimmed_count > 0:
                    detected_issues.append(
                        # The comparison value is whatever this policy's expression
                        # tests against -- naming auth.uid()::text here was wrong on
                        # any policy that compares against something else, e.g.
                        # profiles' `visibility = 'public'`.
                        f"Data-shape defect on '{qualified}.{col_name}' (observed via {source_label}): "
                        f"{untrimmed_count} row(s) hold untrimmed whitespace (column <> btrim(column)). "
                        f"The policy tests this column with an equality comparison, which those rows "
                        f"never satisfy, so the users they belong to silently receive zero rows."
                    )
            except Exception as e:
                detected_issues.append(
                    f"INDETERMINATE: whitespace check on '{qualified}.{col_name}' failed via "
                    f"{source_label}: {str(e)}."
                )

    duration_ms = (time.perf_counter() - start_time) * 1000.0

    return {
        "table_name": table_name,
        "rls_enabled": bool(rls_enabled),
        "policies": [p.model_dump() for p in policies],
        "columns": columns_map,
        "has_select_privilege": bool(has_select_privilege),
        "row_visibility": row_visibility.value,
        "plan_proves_zero_rows": plan_proves_zero_rows,
        "policy_roles": policy_roles,
        "applicable_policy_count": applicable_policy_count,
        "current_role": current_role,
        "reltuples_estimate": reltuples_estimate,
        "readable_rows_count": readable_rows_count,
        "data_shape_source": data_shape_source.value,
        "data_shape_checked_columns": sorted(checked_text_cols),
        "plan": captured_plan,
        "detected_issues": detected_issues,
        "metadata_only": elevated_conn is None,
        "execution_time_ms": round(duration_ms, 2),
    }


def analyze_rls_debug_results(raw_data: Dict[str, Any]) -> DiagnosticSummary:
    policies = raw_data.get("policies", [])
    rls_enabled = raw_data.get("rls_enabled", False)
    table_name = raw_data.get("table_name", "unknown")
    detected_issues = raw_data.get("detected_issues", [])
    data_shape_source = raw_data.get("data_shape_source", DataShapeSourceEnum.NOT_RUN.value)

    if not rls_enabled:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.RLS_DEBUG,
            severity=SeverityEnum.CRITICAL,
            summary=f"CRITICAL: Row Level Security is NOT enabled on 'public.{table_name}'. All table rows are publicly accessible.",
            raw_result=raw_data,
        )

    # Confirmed defects (type mismatch, or whitespace the module actually observed)
    # outrank everything else: these are things it saw, not things it inferred.
    critical_defects = [i for i in detected_issues if not i.startswith("INDETERMINATE:")]
    if critical_defects:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.RLS_DEBUG,
            severity=SeverityEnum.CRITICAL,
            summary=f"CRITICAL: Policy mismatch or data-shape defect detected on '{table_name}': "
                    + "; ".join(critical_defects),
            raw_result=raw_data,
        )

    if not policies:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.RLS_DEBUG,
            severity=SeverityEnum.WARNING,
            summary=f"WARNING: RLS is enabled on '{table_name}' but NO policies exist. PostgreSQL default-deny blocks all non-superuser queries.",
            raw_result=raw_data,
        )

    indeterminate_issues = [i for i in detected_issues if i.startswith("INDETERMINATE:")]
    if indeterminate_issues:
        # Lead with the reason so the dashboard card is scannable without expanding
        # the full finding text.
        reasons = {
            RowVisibilityEnum.NO_PRIVILEGE.value: "no SELECT privilege",
            RowVisibilityEnum.NO_POLICY_APPLIES.value: "no policy targets the connecting role",
            RowVisibilityEnum.RLS_FILTERED.value: "RLS filtered every row",
            RowVisibilityEnum.UNKNOWN.value: "the read could not be completed",
        }
        lead = reasons.get(raw_data.get("row_visibility", ""), "data-shape checks did not run")
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.RLS_DEBUG,
            severity=SeverityEnum.WARNING,
            summary=f"INDETERMINATE ({lead}): RLS analysis on '{table_name}' could not complete all "
                    f"data-shape checks: " + "; ".join(indeterminate_issues),
            raw_result=raw_data,
        )

    # Only reachable once the data-shape checks actually ran. A pass on checks that
    # never executed is not an OK.
    if data_shape_source == DataShapeSourceEnum.NOT_RUN.value:
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.RLS_DEBUG,
            severity=SeverityEnum.WARNING,
            summary=f"INDETERMINATE: policy metadata on '{table_name}' looks consistent, but data-shape "
                    f"checks did not run, so row contents are unverified.",
            raw_result=raw_data,
        )

    # A pass over the read-only connection covers only the rows RLS let through.
    # Rows the policy hides are exactly where a data-shape defect would sit
    # unnoticed, so the scope of the check is stated rather than implied.
    if data_shape_source == DataShapeSourceEnum.READ_ONLY.value:
        visible = raw_data.get("readable_rows_count")
        scope = (
            f" Note: only the {visible} row(s) visible to the diagnostic role were examined; "
            f"any row hidden by this policy was not inspected. Whole-table coverage is "
            f"reachable only through the opt-in elevated connection, which is not configured."
            if rls_enabled
            else ""
        )
        return DiagnosticSummary(
            module=DiagnosticModuleEnum.RLS_DEBUG,
            severity=SeverityEnum.OK,
            summary=f"OK: RLS is active on '{table_name}' with {len(policies)} policy(ies); "
                    f"data-shape checks ran via the read-only connection and found no "
                    f"defects.{scope}",
            raw_result=raw_data,
        )

    return DiagnosticSummary(
        module=DiagnosticModuleEnum.RLS_DEBUG,
        severity=SeverityEnum.OK,
        summary=f"OK: RLS is active on '{table_name}' with {len(policies)} policy(ies); data-shape "
                f"checks ran via the elevated connection and found no defects.",
        raw_result=raw_data,
    )
