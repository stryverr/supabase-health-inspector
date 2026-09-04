"""
Renders a ScanReport as Markdown for download.

Same scope rule as the report page: diagnosis only. Findings arrive already
sanitised by findings.py, and nothing here reintroduces remediation. The narration
is included but explicitly labelled unverified, and it is never the source of a
heading, a field, or a cause.
"""

import json
from typing import List

from app.models import ScanReport

SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "warning": "WARNING",
    "info": "INFO",
    "ok": "OK",
}

MODULE_TITLE = {
    "vacuum_wraparound": "Vacuum & XID Wraparound",
    "rls_debug": "Row Level Security",
    "connection_health": "Connection Health",
    "storage_audit": "Storage Audit",
    "slow_queries": "Slow Queries",
}


def render_markdown(report: ScanReport, raw_char_limit: int = 4000) -> str:
    run = report.run
    out: List[str] = []

    out.append(f"# Diagnostic report — scan {run.id}")
    out.append("")
    out.append("| | |")
    out.append("|---|---|")
    out.append(f"| Target | {run.target_label or 'unknown'} |")
    out.append(f"| Host | `{run.target_host or 'unknown'}` |")
    out.append(f"| Started | {run.started_at} |")
    out.append(f"| Completed | {run.completed_at or '(not recorded)'} |")
    out.append(f"| Status | {run.status.value if hasattr(run.status, 'value') else run.status} |")
    out.append(f"| Modules | {run.module_count} |")
    out.append(f"| Worst severity | {SEVERITY_LABEL.get(run.worst_severity or '', run.worst_severity or '-')} |")
    out.append("")

    counts = " · ".join(
        f"{SEVERITY_LABEL.get(k, k)}: {v}" for k, v in report.severity_counts.items() if v
    )
    if counts:
        out.append(f"**Findings:** {counts}")
        out.append("")

    out.append(
        "> Scope: diagnosis only. This report states what was observed and the cause "
        "computed from that evidence. It contains no remediation."
    )
    out.append("")
    out.append("---")
    out.append("")

    current_severity = None
    for f in report.findings:
        if f.severity != current_severity:
            current_severity = f.severity
            out.append(f"## {SEVERITY_LABEL.get(f.severity, f.severity.upper())}")
            out.append("")

        out.append(f"### {MODULE_TITLE.get(f.module, f.module)}")
        out.append("")
        out.append(f"**Verdict:** {f.summary}")
        out.append("")

        if f.affected:
            out.append("**Affected object**")
            out.append("")
            out.append("| Field | Value |")
            out.append("|---|---|")
            for key, value in f.affected.items():
                out.append(f"| {key} | `{value}` |")
            out.append("")

        if f.probable_cause:
            out.append("**Probable cause** *(computed from the diagnostic data)*")
            out.append("")
            out.append(f.probable_cause)
            out.append("")

        if f.scope_caveat:
            out.append("**Scope of this check**")
            out.append("")
            out.append(f.scope_caveat)
            out.append("")

        if f.observations:
            out.append("**Observations**")
            out.append("")
            for o in f.observations:
                out.append(f"- {o}")
            out.append("")

        if f.ai_explanation:
            provider = f.ai_provider or "model"
            out.append(f"**Narration — {provider} — UNVERIFIED**")
            out.append("")
            out.append(
                "> The text below is generated commentary, not a diagnostic conclusion. "
                "Check it against the result below."
            )
            out.append(">")
            for line in f.ai_explanation.splitlines() or [""]:
                out.append(f"> {line}")
            out.append("")

        out.append("<details>")
        out.append("<summary>Raw query result</summary>")
        out.append("")
        out.append("```json")
        blob = json.dumps(f.raw_result, indent=2, default=str)
        if len(blob) > raw_char_limit:
            blob = blob[:raw_char_limit] + f"\n... truncated at {raw_char_limit} characters ..."
        out.append(blob)
        out.append("```")
        out.append("")
        out.append("</details>")
        out.append("")
        out.append("---")
        out.append("")

    return "\n".join(out)
