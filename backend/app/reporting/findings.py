"""
Turns a persisted scan result into a structured report finding.

Two rules shape this module:

1. **Diagnosis only.** No remediation, no suggested fixes, no SQL, in any form.
   Some diagnostic messages carry remediation inline (`Remediate with UPDATE ...`,
   `run 'CREATE EXTENSION ...'`), so observation text is sanitised on the way in
   rather than trusted.
2. **Conclusions come from Python.** `probable_cause` is derived here from the
   diagnostic payload, never from an LLM. The narration is carried alongside,
   labelled unverified, and is never the source of a field.
"""

import re
from typing import Any, Dict, List, Optional

from app.models import ReportFinding, SeverityEnum

# Severity order for grouping: worst first.
SEVERITY_RANK = {
    SeverityEnum.CRITICAL.value: 0,
    SeverityEnum.WARNING.value: 1,
    SeverityEnum.INFO.value: 2,
    SeverityEnum.OK.value: 3,
}

# Remediation embedded in diagnostic text. Stripped so the report stays diagnostic.
# Each remediation clause needs its own terminator. A generic "up to the next dot"
# is wrong, because the SQL these clauses contain is full of dots
# (public."orders"), which left mangled fragments behind.
_REMEDIATION_CLAUSES = [
    re.compile(r"\s*Remediate with[^;]*;", re.I),          # ends at the statement's ;
    re.compile(r"\s*It is available;\s*run '[^']*'[^.]*\.", re.I),
    re.compile(r"\s*run '[^']*'[^.]*\.", re.I),
    re.compile(r"\s*Grant SELECT to[^.]*\.", re.I),        # prose, ends at the sentence
]
_SQL_STATEMENT = re.compile(
    r"\b(?:CREATE|ALTER|DROP|GRANT|REVOKE|UPDATE|DELETE|INSERT|TRUNCATE|VACUUM|ANALYZE)\s+"
    r"[A-Za-z_\"][^;]*;",
    re.I,
)


def sanitize_observation(text: str) -> str:
    """Removes remediation clauses and SQL statements from a diagnostic message."""
    if not text:
        return text
    # Remediation clauses first: they contain the SQL, and stripping the statement
    # on its own leaves a stranded "Remediate with" pointing at nothing.
    cleaned = text
    for pattern in _REMEDIATION_CLAUSES:
        cleaned = pattern.sub("", cleaned)
    cleaned = _SQL_STATEMENT.sub("", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()
    return cleaned


# Narration is free-form model output and the likeliest place for remediation to
# reappear. Runs stored before narration was constrained contain fenced SQL such as
# `CREATE POLICY ... ; GRANT EXECUTE ...`, so the report sanitises on read rather
# than trusting what is already in the database.
_NARRATION_FENCE = re.compile(r"```[ \t]*\w*[ \t]*\r?\n.*?```", re.S)

# Sentence boundary = a terminator followed by whitespace and something that starts
# a new sentence. Splitting on every "." would cut `public.orders` in half, which is
# how an earlier version left the fragment "orders that targets inspector_ro."
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\"'(\[])|\n{2,}")

# A sentence containing any of these is prescriptive, not diagnostic, and is dropped
# whole rather than trimmed -- partial removal is what produces fragments.
_REMEDIATION_TRIGGER = re.compile(
    r"\b(?:to (?:fix|resolve|address|correct) (?:this|it|the)|"
    r"(?:you|the (?:database )?administrator|one) (?:can|could|should|must|need to|will need to)|"
    r"should (?:be )?(?:grant|create|run|disable|enable|updat|add)|"
    r"must be (?:disabled|enabled|granted|updated|added)|"
    r"can be achieved by|would need to be|"
    r"remediat|the fix is|resolve this by|in order to (?:fix|resolve|allow)|"
    # Sentences describing an example that has itself been stripped, e.g.
    # "Note: In this example, we create a policy that grants SELECT..."
    r"in (?:this|the above) example|we (?:create|grant|add|update|enable|disable)|"
    r"this (?:example|policy|statement|command) (?:creates|grants|allows|would)|"
    # Advisory phrasing, which is remediation without the imperative mood. The
    # trigger case: "it is recommended to periodically run `VACUUM` with the `FULL`
    # option" -- prescriptive, and wrong (FULL is not the remedy for XID age).
    r"(?:is|are|it is) (?:recommended|advisable|advised|best)|"
    r"recommend(?:ed|s|ation)?\b|best practice|"
    r"periodically run|consider (?:running|adding|creating|enabling|disabling))\b",
    re.I,
)

# Lead-ins that introduced a block which has since been stripped, e.g.
# "Example of a successful policy creation:" left pointing at nothing.
_LEADIN_TRIGGER = re.compile(
    r"^\s*(?:here(?:'s| is)|example of|for example|the following|as follows|note)\b[^\n]*:\s*$",
    re.I,
)

NARRATION_REDACTED_NOTE = (
    "[Remediation removed: this report is diagnosis only, and narration is not a "
    "source of conclusions.]"
)


def sanitize_narration(text: Optional[str]) -> Optional[str]:
    """
    Strips SQL and prescriptive sentences from stored narration before display.

    Applied on read, not only on write: runs recorded before narration was
    constrained already sit in the control plane carrying fenced SQL.
    """
    if not text:
        return text

    cleaned = _NARRATION_FENCE.sub(" ", text)
    cleaned = _SQL_STATEMENT.sub(" ", cleaned)

    # Removing a fenced block leaves "\n \n" behind, which is not a paragraph break
    # to the splitter, so the lead-in that introduced it stayed glued to the next
    # sentence and escaped the lead-in filter.
    cleaned = re.sub(r"\n[ \t]+\n", "\n\n", cleaned)
    cleaned = re.sub(r":[ \t]*\n(?!\n)", ":\n\n", cleaned)

    kept = [
        s for s in _SENTENCE_SPLIT.split(cleaned)
        if s.strip()
        and not _REMEDIATION_TRIGGER.search(s)
        and not _LEADIN_TRIGGER.match(s)
    ]
    cleaned = " ".join(part.strip() for part in kept)

    for pattern in _REMEDIATION_CLAUSES:
        cleaned = pattern.sub("", cleaned)
    cleaned = re.sub(r"\s{2,}", " ", cleaned).strip()

    if cleaned != text.strip():
        return f"{cleaned}\n\n{NARRATION_REDACTED_NOTE}" if cleaned else NARRATION_REDACTED_NOTE
    return text


def _qualified(table: Optional[str]) -> Optional[str]:
    return f"public.{table}" if table else None


# ---------------------------------------------------------------------------
# Per-module extraction: affected object, probable cause, scope caveat
# ---------------------------------------------------------------------------
def _rls_debug(raw: Dict[str, Any], severity: str) -> Dict[str, Any]:
    table = raw.get("table_name")
    qualified = _qualified(table)
    policies = raw.get("policies") or []
    policy_names = [p.get("policyname") for p in policies if p.get("policyname")]
    role = raw.get("current_role")
    policy_roles = raw.get("policy_roles") or []
    columns = raw.get("data_shape_checked_columns") or []
    visibility = raw.get("row_visibility")
    visible = raw.get("readable_rows_count")

    affected = {
        "Table": qualified,
        "Policies": ", ".join(policy_names) if policy_names else "(none)",
        "Policy target roles": ", ".join(policy_roles) if policy_roles else "(none)",
        "Connecting role": role,
        "Columns examined": ", ".join(columns) if columns else "(none)",
    }

    cause = None
    caveat = None

    if raw.get("rls_enabled") is False:
        cause = (
            f"Row-level security is not enabled on {qualified}. Every role holding SELECT "
            f"reads every row; the policies that would constrain access are never consulted."
        )
    elif visibility == "no_policy_applies":
        roles_txt = ", ".join(f"`{r}`" for r in policy_roles) or "no role"
        one = len(policies) == 1
        plural = "policy" if one else "policies"
        verb = "targets" if one else "target"
        member = "is not that role" if one else "is a member of none of them"
        proof = (
            " The planner confirms this statically: the query collapses to a constant-false "
            "Result node, returning zero rows without reading the heap."
            if raw.get("plan_proves_zero_rows")
            else ""
        )
        cause = (
            f"The {'only' if one else len(policies)} {plural} on {qualified} {verb} {roles_txt}; "
            f"the connecting role `{role}` {member}, so no policy applies and the role cannot "
            f"see any row of this table regardless of its contents.{proof} This is a property "
            f"of the connection, not a defect in the table."
        )
        caveat = (
            f"Data-shape checks did not run: no row was readable. Column(s) the policy depends "
            f"on that went unexamined: {', '.join(columns) or 'none'}."
        )
    elif visibility == "no_privilege":
        cause = (
            f"The connecting role `{role}` holds no SELECT privilege on {qualified}, so the "
            f"table could not be read at all. This is a grant-level restriction, separate from "
            f"row-level security."
        )
        caveat = "Data-shape checks did not run: the table was unreadable."
    elif visibility == "rls_filtered":
        applicable = raw.get("applicable_policy_count", 0)
        estimate = raw.get("reltuples_estimate")
        est_txt = (
            f"pg_class estimates ~{estimate} row(s)"
            if estimate is not None
            else "pg_class holds no row estimate (the table has never been analyzed)"
        )
        cause = (
            f"{applicable} policy(ies) on {qualified} apply to the connecting role `{role}`, and "
            f"every row was filtered out by the policy expression. The table is not necessarily "
            f"empty: {est_txt}."
        )
        caveat = "Data-shape checks did not run: no row survived the policy."
    elif visibility == "readable":
        defects = [
            i for i in (raw.get("detected_issues") or [])
            if "untrimmed whitespace" in i
        ]
        if defects:
            cause = (
                f"Row contents in {qualified} do not match what the policy expression compares "
                f"against. One or more values in {', '.join(columns) or 'the examined column(s)'} "
                f"carry untrimmed whitespace, so those rows never satisfy an equality comparison "
                f"and the affected users silently receive zero rows."
            )
        else:
            cause = (
                f"{len(policies)} policy(ies) on {qualified} apply to the connecting role `{role}`, "
                f"{visible} row(s) were readable, and the examined column(s) contained no "
                f"data-shape defect."
            )
        if raw.get("rls_enabled") and raw.get("data_shape_source") == "read_only":
            caveat = (
                f"Only the {visible} row(s) visible to `{role}` were examined. Any row this policy "
                f"hides was not inspected, which is exactly where a defect of this kind would sit "
                f"unnoticed."
            )

    return {"affected": affected, "probable_cause": cause, "scope_caveat": caveat}


def _vacuum(raw: Any, severity: str) -> Dict[str, Any]:
    rows = raw if isinstance(raw, list) else []
    worst = None
    for r in rows:
        pct = float(r.get("pct_to_wraparound") or 0)
        if worst is None or pct > float(worst.get("pct_to_wraparound") or 0):
            worst = r

    affected = {
        "Tables examined": str(len(rows)),
        "Highest XID age": str(worst.get("xid_age")) if worst else "(none)",
        "Table": _qualified(worst.get("relname")) if worst else "(none)",
    }
    if not rows:
        cause = "No ordinary or materialized tables were found in the public schema to measure."
    else:
        cause = (
            f"The oldest unfrozen transaction ID belongs to "
            f"{_qualified(worst.get('relname'))}, at age {worst.get('xid_age')} — "
            f"{worst.get('pct_to_wraparound')}% of the 2-billion transaction horizon at which "
            f"PostgreSQL stops accepting writes."
        )
    return {"affected": affected, "probable_cause": cause, "scope_caveat": None}


def _connections(raw: Dict[str, Any], severity: str) -> Dict[str, Any]:
    total = raw.get("total_count", 0)
    redacted = raw.get("redacted_count", 0)
    observable = raw.get("observable_count", 0)
    idle = [c for c in (raw.get("connections") or []) if c.get("state") == "idle in transaction"]

    affected = {
        "Total backends": str(total),
        "Legible to the diagnostic role": str(observable),
        "Redacted": str(redacted),
        "Idle in transaction (among legible)": str(len(idle)),
    }
    if idle:
        pids = ", ".join(str(c["pid"]) for c in idle[:5])
        cause = (
            f"{len(idle)} backend(s) are held in the 'idle in transaction' state (PIDs {pids}). "
            f"An open transaction holds its snapshot, which prevents autovacuum from reclaiming "
            f"dead tuples newer than that snapshot."
        )
    elif redacted:
        cause = (
            f"{redacted} of {total} backends belong to other roles. Without pg_read_all_stats, "
            f"pg_stat_activity returns a NULL state and '<insufficient privilege>' for those rows, "
            f"so state-based detection could only inspect {observable}."
        )
    else:
        cause = f"All {total} backend(s) were legible and none was idle in transaction."

    caveat = (
        f"Idle-in-transaction and lock-wait detection covered only {observable} of {total} "
        f"backends; the rest were opaque to this role."
        if redacted
        else None
    )
    return {"affected": affected, "probable_cause": cause, "scope_caveat": caveat}


def _storage(raw: Dict[str, Any], severity: str) -> Dict[str, Any]:
    buckets = raw.get("buckets") or []
    policies = raw.get("policies") or []
    affected = {
        "Storage schema present": str(raw.get("schema_present", True)),
        "Buckets visible": str(len(buckets)),
        "Policies on storage.objects": str(len(policies)),
        "storage.buckets RLS": str(raw.get("buckets_rls_enabled")),
        "Policies on storage.buckets": str(raw.get("bucket_policy_count", 0)),
    }
    public_buckets = [b for b in buckets if b.get("public") is True]

    if not raw.get("schema_present", True):
        cause = "The Supabase Storage schema is not present in this database."
    elif public_buckets and not policies:
        names = ", ".join(str(b.get("name")) for b in public_buckets)
        cause = (
            f"Bucket(s) {names} are marked public while storage.objects carries no policies, "
            f"so object rows are constrained by nothing."
        )
    elif not raw.get("listing_trustworthy", True):
        cause = (
            f"storage.buckets has row-level security enabled with "
            f"{raw.get('bucket_policy_count', 0)} policy(ies), and the connecting role is not "
            f"covered by any of them. The listing therefore returns an empty set whether or not "
            f"buckets exist, so bucket exposure could not be assessed."
        )
    else:
        cause = f"{len(buckets)} bucket(s) were listed against {len(policies)} object policy(ies)."

    caveat = (
        "An empty bucket listing under RLS is not evidence that no buckets are configured."
        if not raw.get("listing_trustworthy", True)
        else None
    )
    return {"affected": affected, "probable_cause": cause, "scope_caveat": caveat}


def _slow_queries(raw: Dict[str, Any], severity: str) -> Dict[str, Any]:
    queries = raw.get("queries") or []
    redacted = raw.get("redacted_count", 0)
    max_mean = max((float(q.get("mean_exec_time_ms") or 0) for q in queries), default=0.0)

    affected = {
        "Extension installed": str(raw.get("installed")),
        "Schema": raw.get("schema") or "(not installed)",
        "Readable": str(raw.get("readable")),
        "Statements returned": str(len(queries)),
        "Statement text redacted": str(redacted),
    }
    if not raw.get("installed"):
        cause = "pg_stat_statements is not installed, so no statement-level timing exists to read."
    elif not raw.get("readable"):
        cause = (
            f"pg_stat_statements is installed in schema '{raw.get('schema')}' but could not be "
            f"read by the connecting role, so no timing data was retrieved."
        )
    elif not queries:
        cause = "pg_stat_statements was read successfully and held no statements above the reporting threshold."
    else:
        cause = (
            f"The slowest statement averages {max_mean}ms across {len(queries)} recorded "
            f"statements. Timings are recorded per normalised statement regardless of who ran it."
        )

    caveat = (
        f"Statement text is redacted for {redacted} of {len(queries)} entries; without "
        f"pg_read_all_stats the query behind a timing cannot be identified."
        if redacted
        else None
    )
    return {"affected": affected, "probable_cause": cause, "scope_caveat": caveat}


_EXTRACTORS = {
    "rls_debug": _rls_debug,
    "vacuum_wraparound": _vacuum,
    "connection_health": _connections,
    "storage_audit": _storage,
    "slow_queries": _slow_queries,
}


def build_finding(
    module: str,
    severity: str,
    summary: str,
    raw_result: Any,
    ai_explanation: Optional[str],
    ai_provider: Optional[str],
) -> ReportFinding:
    """Builds one report finding. Every conclusion here is computed, not narrated."""
    extractor = _EXTRACTORS.get(module)
    try:
        parts = extractor(raw_result, severity) if extractor else {}
    except Exception:
        parts = {}

    # vacuum_wraparound stores a list, not a dict, so guard before .get().
    issues = raw_result.get("detected_issues") or [] if isinstance(raw_result, dict) else []
    observations = [sanitize_observation(i) for i in issues]

    return ReportFinding(
        module=module,
        severity=severity,
        summary=sanitize_observation(summary),
        affected=_drop_empty(parts.get("affected") or {}),
        probable_cause=parts.get("probable_cause"),
        scope_caveat=parts.get("scope_caveat"),
        observations=[o for o in observations if o],
        raw_result=raw_result,
        ai_explanation=sanitize_narration(ai_explanation),
        ai_provider=ai_provider,
    )


def _drop_empty(d: Dict[str, Any]) -> Dict[str, str]:
    return {k: str(v) for k, v in d.items() if v not in (None, "", "None")}


def sort_findings(findings: List[ReportFinding]) -> List[ReportFinding]:
    """Worst severity first, then module name for a stable order within a group."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.module),
    )
