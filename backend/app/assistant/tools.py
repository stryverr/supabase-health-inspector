"""
Gemini function-calling tool schemas for the 5 PostgreSQL / Supabase diagnostics.

Schema `type` values are uppercase because google-genai parses these dicts into
`types.Schema`, whose Type enum members are uppercase; lowercase values fail
validation rather than being coerced.
"""

from typing import Any, Dict, List


def _lower_schema_types(node: Any) -> Any:
    """
    Recursively lowercases JSON-Schema `type` values.

    google-genai parses these dicts into `types.Schema`, whose Type enum members
    are uppercase. Ollama speaks plain JSON Schema and expects lowercase. Rather
    than maintain two copies of every tool definition, the Gemini-native form is
    the source of truth and this converts it for Ollama.
    """
    if isinstance(node, dict):
        out = {}
        for key, value in node.items():
            if key == "type" and isinstance(value, str):
                out[key] = value.lower()
            else:
                out[key] = _lower_schema_types(value)
        return out
    if isinstance(node, list):
        return [_lower_schema_types(item) for item in node]
    return node


def ollama_tool_schemas() -> List[Dict[str, Any]]:
    """DIAGNOSTIC_TOOLS in the OpenAI-style shape Ollama's /api/chat expects."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": _lower_schema_types(tool.get("parameters", {})),
            },
        }
        for tool in DIAGNOSTIC_TOOLS
    ]


DIAGNOSTIC_TOOLS = [
    {
        "name": "run_vacuum_check",
        "description": "Inspects PostgreSQL transaction ID (relfrozenxid) age and percentage towards the 2-billion wraparound horizon across public tables.",
        "parameters": {
            "type": "OBJECT",
            "properties": {},
        },
    },
    {
        "name": "run_rls_debug",
        "description": (
            "Inspects Row Level Security policies from pg_policies metadata, column data type "
            "compatibility, and PostgreSQL query planner EXPLAIN output. Reports INDETERMINATE "
            "for data-shape checks when no connection can read the table's rows."
        ),
        "parameters": {
            "type": "OBJECT",
            "properties": {
                "table_name": {
                    "type": "STRING",
                    "description": "The table name in the public schema to inspect (e.g. 'orders', 'profiles').",
                },
            },
            "required": ["table_name"],
        },
    },
    {
        "name": "run_connection_health",
        "description": "Checks pg_stat_activity for active connections, idle-in-transaction states, lock wait events, and query state durations.",
        "parameters": {
            "type": "OBJECT",
            "properties": {},
        },
    },
    {
        "name": "run_storage_audit",
        "description": "Audits Supabase Storage buckets (storage.buckets) and RLS security policies on storage.objects for public data leaks or missing rules.",
        "parameters": {
            "type": "OBJECT",
            "properties": {},
        },
    },
    {
        "name": "run_slow_queries",
        "description": "Queries pg_stat_statements to identify the slowest queries by mean and total execution time on the target database.",
        "parameters": {
            "type": "OBJECT",
            "properties": {},
        },
    },
]
