"""
Pytest suite for the assistant's function-calling loop and provider fallback.

The agent no longer talks to a vendor SDK directly: it walks `provider_chain()`
and hands each provider a dispatcher. These tests mock providers rather than HTTP,
so they cover the loop's contract -- correct tool, correct arguments, failures
captured not raised, and a fallback that says a model did not answer.
"""

import datetime
import decimal
from unittest.mock import AsyncMock, patch
import pytest
from app.assistant import agent as agent_mod
from app.assistant.agent import TOOL_DISPATCH, _make_dispatcher, handle_assistant_message
from app.assistant.providers import ProviderUnavailable, _json_safe


class _FakeProvider:
    """Requests one tool call, then answers with text."""

    def __init__(self, name, tool_name=None, tool_args=None, final_text="done", fail_with=None):
        self.name = name
        self._tool = (tool_name, tool_args or {}) if tool_name else None
        self._final_text = final_text
        self._fail_with = fail_with
        self.called = False

    async def chat_with_tools(self, user_message, system_instruction, dispatch):
        self.called = True
        if self._fail_with:
            raise self._fail_with
        traces = []
        if self._tool:
            from app.models import ToolCallTrace

            name, args = self._tool
            result = await dispatch(name, args)
            traces.append(ToolCallTrace(tool_name=name, arguments=args, result=result))
        return self._final_text, traces


def _use_providers(monkeypatch, *provs):
    monkeypatch.setattr(agent_mod, "provider_chain", lambda: list(provs))


# --- the function-calling loop ------------------------------------------------

@pytest.mark.asyncio
async def test_provider_tool_call_dispatches_the_right_diagnostic(monkeypatch):
    provider = _FakeProvider("gemini", "run_rls_debug", {"table_name": "profiles"},
                             final_text="Policy looks correct.")
    _use_providers(monkeypatch, provider)
    conn = AsyncMock()

    with patch.object(agent_mod, "run_rls_debug", new_callable=AsyncMock) as mock_rls:
        mock_rls.return_value = {"table_name": "profiles", "detected_issues": []}
        response = await handle_assistant_message(conn, "check RLS on profiles")

    mock_rls.assert_awaited_once_with(conn, "profiles", elevated_conn=None)
    assert response.content == "Policy looks correct."
    assert response.provider == "gemini"
    assert response.tool_calls[0].arguments == {"table_name": "profiles"}


@pytest.mark.asyncio
async def test_elevated_connection_is_threaded_through(monkeypatch):
    _use_providers(monkeypatch, _FakeProvider("ollama", "run_rls_debug", {"table_name": "orders"}))
    conn, elevated = AsyncMock(), AsyncMock()

    with patch.object(agent_mod, "run_rls_debug", new_callable=AsyncMock) as mock_rls:
        mock_rls.return_value = {}
        await handle_assistant_message(conn, "check rls", elevated_conn=elevated)

    mock_rls.assert_awaited_once_with(conn, "orders", elevated_conn=elevated)


@pytest.mark.asyncio
async def test_tool_failure_is_captured_in_the_trace_not_raised(monkeypatch):
    _use_providers(monkeypatch, _FakeProvider("gemini", "run_vacuum_check"))
    conn = AsyncMock()

    with patch.object(agent_mod, "run_vacuum_check", new_callable=AsyncMock) as mock_vac:
        mock_vac.side_effect = Exception("permission denied for pg_class")
        response = await handle_assistant_message(conn, "check wraparound")

    assert "permission denied" in response.tool_calls[0].result["error"]


@pytest.mark.asyncio
async def test_unknown_tool_name_does_not_crash_the_loop(monkeypatch):
    _use_providers(monkeypatch, _FakeProvider("gemini", "drop_all_tables"))
    response = await handle_assistant_message(AsyncMock(), "do something odd")
    assert "Unknown tool" in response.tool_calls[0].result["error"]


# --- provider fallback --------------------------------------------------------

@pytest.mark.asyncio
async def test_falls_through_to_the_next_provider(monkeypatch):
    """A rejected Gemini key must degrade to Ollama, not to nothing."""
    broken = _FakeProvider("gemini", fail_with=ProviderUnavailable("401 UNAUTHENTICATED"))
    working = _FakeProvider("ollama", "run_vacuum_check", final_text="All healthy.")
    _use_providers(monkeypatch, broken, working)
    conn = AsyncMock()

    with patch.object(agent_mod, "run_vacuum_check", new_callable=AsyncMock) as mock_vac:
        mock_vac.return_value = []
        response = await handle_assistant_message(conn, "check wraparound")

    assert broken.called and working.called
    assert response.provider == "ollama"
    assert response.content == "All healthy."


@pytest.mark.asyncio
async def test_all_providers_failing_falls_back_and_says_so(monkeypatch):
    _use_providers(
        monkeypatch,
        _FakeProvider("gemini", fail_with=ProviderUnavailable("401 UNAUTHENTICATED")),
        _FakeProvider("ollama", fail_with=ProviderUnavailable("connection refused")),
    )
    conn = AsyncMock()

    with patch.object(agent_mod, "run_rls_debug", new_callable=AsyncMock) as mock_rls:
        mock_rls.return_value = {"rls_enabled": True, "policies": [], "detected_issues": []}
        response = await handle_assistant_message(conn, "check rls policies")

    assert response.provider == "none"
    assert "No LLM provider answered" in response.content
    assert "401 UNAUTHENTICATED" in response.content
    assert "connection refused" in response.content
    # The diagnostic still ran.
    mock_rls.assert_awaited()
    assert response.tool_calls[0].tool_name == "run_rls_debug"


@pytest.mark.asyncio
async def test_no_providers_configured_still_runs_diagnostics(monkeypatch):
    _use_providers(monkeypatch)
    conn = AsyncMock()

    with patch.object(agent_mod, "run_vacuum_check", new_callable=AsyncMock) as mock_vac:
        mock_vac.return_value = [{"relname": "orders"}]
        response = await handle_assistant_message(conn, "check vacuum wraparound")

    assert response.provider == "none"
    assert "narration is disabled" in response.content
    mock_vac.assert_awaited()


@pytest.mark.asyncio
async def test_empty_provider_response_is_treated_as_failure(monkeypatch):
    """An empty string is not an answer; fall through rather than render blank."""
    _use_providers(
        monkeypatch,
        _FakeProvider("gemini", final_text=""),
        _FakeProvider("ollama", final_text="Real answer."),
    )
    response = await handle_assistant_message(AsyncMock(), "hello")
    assert response.provider == "ollama"
    assert response.content == "Real answer."


@pytest.mark.asyncio
async def test_no_database_connection_reports_plainly(monkeypatch):
    _use_providers(monkeypatch, _FakeProvider("gemini"))
    response = await handle_assistant_message(None, "check rls")
    assert "not active" in response.content
    assert response.tool_calls == []


# --- dispatcher ---------------------------------------------------------------

# --- SQL suppression ----------------------------------------------------------

def test_strip_sql_removes_fenced_blocks():
    """
    The trigger: llama3.2 proposed CREATE POLICY ... USING (auth.uid()::text = user_id)
    for inspector_ro, which still matches zero rows because auth.uid() is NULL for a
    role that never authenticated. Plausible, authoritative, wrong.
    """
    text = (
        "No policy targets the connecting role.\n\n"
        "```sql\n"
        "CREATE POLICY p ON public.orders TO inspector_ro\n"
        "  FOR SELECT USING (auth.uid()::text = user_id);\n"
        "```\n\n"
        "That is the cause."
    )
    out = agent_mod._strip_sql(text)

    assert "CREATE POLICY" not in out
    assert "auth.uid()" not in out
    assert "No policy targets the connecting role." in out
    assert "That is the cause." in out
    assert "suppressed" in out


def test_strip_sql_removes_bare_statements():
    out = agent_mod._strip_sql("Fix it:\nGRANT SELECT ON public.orders TO inspector_ro;\nDone.")
    assert "GRANT SELECT" not in out
    assert "Done." in out


def test_strip_sql_leaves_prose_untouched():
    prose = "The role is not a member of `authenticated`, so no policy applies to it."
    assert agent_mod._strip_sql(prose) == prose


def test_strip_sql_handles_empty_and_sql_only():
    assert agent_mod._strip_sql("") == ""
    only_sql = "```sql\nDROP TABLE orders;\n```"
    assert "DROP TABLE" not in agent_mod._strip_sql(only_sql)


@pytest.mark.asyncio
async def test_sql_is_stripped_from_the_assistant_response(monkeypatch):
    """End to end: SQL a provider emits must not reach the caller."""
    _use_providers(
        monkeypatch,
        _FakeProvider("ollama", final_text="Cause explained.\n\n```sql\nGRANT ALL ON x TO y;\n```"),
    )
    response = await handle_assistant_message(AsyncMock(), "why zero rows?")

    assert "GRANT ALL" not in response.content
    assert "Cause explained." in response.content


@pytest.mark.asyncio
async def test_dispatcher_hands_the_model_the_computed_verdict():
    """
    Severity is computed in Python and passed to the model. Given only raw rows,
    llama3.2 read `pct_to_wraparound: 0.00` as "a potential wraparound issue" --
    inventing a finding on a healthy table.
    """
    conn = AsyncMock()
    dispatch = _make_dispatcher(conn, None)

    with patch.object(agent_mod, "run_vacuum_check", new_callable=AsyncMock) as mock_vac:
        mock_vac.return_value = [{"relname": "orders", "xid_age": 6, "pct_to_wraparound": 0.0}]
        result = await dispatch("run_vacuum_check", {})

    assert result["severity"] == "ok"
    assert result["summary"].startswith("OK:")
    assert result["raw_result"][0]["relname"] == "orders"


@pytest.mark.asyncio
async def test_dispatcher_reports_critical_severity_when_earned():
    conn = AsyncMock()
    dispatch = _make_dispatcher(conn, None)

    with patch.object(agent_mod, "run_vacuum_check", new_callable=AsyncMock) as mock_vac:
        mock_vac.return_value = [
            {"relname": "big", "xid_age": 1_800_000_000, "pct_to_wraparound": 90.0}
        ]
        result = await dispatch("run_vacuum_check", {})

    assert result["severity"] == "critical"


@pytest.mark.asyncio
async def test_dispatcher_falls_back_to_raw_when_analyzer_fails():
    """A broken analyzer must not lose the diagnostic output."""
    conn = AsyncMock()
    dispatch = _make_dispatcher(conn, None)

    with patch.object(agent_mod, "run_vacuum_check", new_callable=AsyncMock) as mock_vac:
        mock_vac.return_value = [{"unexpected": "shape"}]
        with patch.dict(
            agent_mod.TOOL_ANALYZERS,
            {"run_vacuum_check": lambda raw: (_ for _ in ()).throw(ValueError("boom"))},
        ):
            result = await dispatch("run_vacuum_check", {})

    assert result == [{"unexpected": "shape"}]


def test_every_tool_has_an_analyzer():
    assert set(agent_mod.TOOL_ANALYZERS) == set(TOOL_DISPATCH)


@pytest.mark.asyncio
async def test_dispatcher_defaults_table_name_when_model_omits_it():
    conn = AsyncMock()
    dispatch = _make_dispatcher(conn, None)
    with patch.object(agent_mod, "run_rls_debug", new_callable=AsyncMock) as mock_rls:
        mock_rls.return_value = {}
        await dispatch("run_rls_debug", {})
    mock_rls.assert_awaited_once_with(conn, "orders", elevated_conn=None)


def test_every_declared_tool_has_a_dispatch_entry():
    """A tool the model can call but the backend cannot dispatch is a dead end."""
    from app.assistant.tools import DIAGNOSTIC_TOOLS

    declared = {t["name"] for t in DIAGNOSTIC_TOOLS}
    assert declared == set(TOOL_DISPATCH), declared.symmetric_difference(set(TOOL_DISPATCH))


# --- serialization ------------------------------------------------------------

def test_json_safe_coerces_types_asyncpg_returns():
    """
    Decimal (numeric) and datetime (timestamptz) come straight out of asyncpg and
    break both the protobuf encoder and json.dumps.
    """
    payload = {
        "pct": decimal.Decimal("0.05"),
        "when": datetime.datetime(2026, 8, 26, 12, 0, 0),
        "delta": datetime.timedelta(seconds=90),
        "nested": [{"amount": decimal.Decimal("1450.00")}],
        "plain": ["a", 1, True, None],
    }
    safe = _json_safe(payload)

    assert safe["pct"] == 0.05
    assert isinstance(safe["when"], str)
    assert safe["nested"][0]["amount"] == 1450.0
    assert safe["plain"] == ["a", 1, True, None]

    import json
    json.dumps(safe)  # must not raise


def test_strip_sql_removes_dangling_leadins():
    """Removing the block alone left 'Here is the remediation SQL:' pointing at nothing."""
    text = (
        "The role cannot see rows.\n"
        "Here is the remediation SQL:\n"
        "```sql\nCREATE POLICY p ON t FOR SELECT USING (true);\n```\n"
        "Done."
    )
    out = agent_mod._strip_sql(text)
    assert "remediation SQL:" not in out
    assert "CREATE POLICY" not in out
    assert "The role cannot see rows." in out
    assert "Done." in out
