"""
Tests for the pluggable LLM provider layer.

Ollama is exercised against a mocked HTTP transport rather than a live daemon, so
these pin the request/response contract: the tool schema shape Ollama expects, the
tool-call round trip, and the two argument encodings different models emit.
"""

import json
import httpx
import pytest
from app.assistant import providers as providers_mod
from app.assistant.providers import (
    GeminiProvider,
    OllamaProvider,
    ProviderUnavailable,
    configured_provider_name,
    provider_chain,
    set_runtime_provider,
)
from app.assistant.tools import DIAGNOSTIC_TOOLS, ollama_tool_schemas


@pytest.fixture(autouse=True)
def _reset_override():
    set_runtime_provider(None)
    yield
    set_runtime_provider(None)


def _mock_transport(handler):
    """Patches httpx.AsyncClient so OllamaProvider talks to `handler` instead of the network."""
    transport = httpx.MockTransport(handler)
    original = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = transport
        return original(*args, **kwargs)

    return factory


# --- tool schema translation --------------------------------------------------

def test_ollama_schemas_lowercase_types():
    """
    google-genai needs uppercase Type enum values; Ollama needs plain JSON Schema.
    Sending uppercase to Ollama is silently ignored or rejected by the model.
    """
    schemas = ollama_tool_schemas()
    assert len(schemas) == len(DIAGNOSTIC_TOOLS)

    rls = next(s for s in schemas if s["function"]["name"] == "run_rls_debug")
    assert rls["type"] == "function"
    params = rls["function"]["parameters"]
    assert params["type"] == "object"
    assert params["properties"]["table_name"]["type"] == "string"
    assert params["required"] == ["table_name"]


def test_gemini_schemas_are_left_uppercase():
    """The source-of-truth definitions stay in the shape google-genai parses."""
    rls = next(t for t in DIAGNOSTIC_TOOLS if t["name"] == "run_rls_debug")
    assert rls["parameters"]["type"] == "OBJECT"


# --- selection ----------------------------------------------------------------

def test_auto_prefers_gemini_then_ollama(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "llm_provider", "auto")
    chain = [p.name for p in provider_chain()]
    assert chain == ["gemini", "ollama"]


def test_explicit_selection_uses_only_that_provider(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "llm_provider", "ollama")
    assert [p.name for p in provider_chain()] == ["ollama"]


def test_none_disables_all_providers(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "llm_provider", "none")
    assert provider_chain() == []


def test_runtime_override_wins_over_settings(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "llm_provider", "gemini")
    set_runtime_provider("ollama")
    assert configured_provider_name() == "ollama"
    assert [p.name for p in provider_chain()] == ["ollama"]


def test_runtime_override_rejects_unknown_provider():
    with pytest.raises(ValueError, match="Unknown provider"):
        set_runtime_provider("chatgpt")


def test_clearing_override_returns_to_settings(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "llm_provider", "gemini")
    set_runtime_provider("ollama")
    set_runtime_provider(None)
    assert configured_provider_name() == "gemini"


# --- ollama: narration --------------------------------------------------------

@pytest.mark.asyncio
async def test_ollama_narrate_returns_message_content(monkeypatch):
    def handler(request):
        assert request.url.path == "/api/chat"
        body = json.loads(request.content)
        assert body["stream"] is False
        return httpx.Response(200, json={"message": {"role": "assistant", "content": " autovacuum is fine  "}})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_transport(handler))
    assert await OllamaProvider().narrate("explain") == "autovacuum is fine"


@pytest.mark.asyncio
async def test_ollama_http_error_becomes_provider_unavailable(monkeypatch):
    monkeypatch.setattr(
        httpx, "AsyncClient", _mock_transport(lambda r: httpx.Response(500, text="model not loaded"))
    )
    with pytest.raises(ProviderUnavailable, match="Ollama HTTP 500"):
        await OllamaProvider().narrate("explain")


@pytest.mark.asyncio
async def test_ollama_connection_refused_becomes_provider_unavailable(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_transport(handler))
    with pytest.raises(ProviderUnavailable, match="Ollama request failed"):
        await OllamaProvider().narrate("explain")


# --- ollama: tool calling -----------------------------------------------------

@pytest.mark.asyncio
async def test_ollama_tool_call_round_trip(monkeypatch):
    """Model asks for a tool, gets the result back as a `tool` message, then answers."""
    seen = {"turns": 0, "tool_message": None}

    def handler(request):
        body = json.loads(request.content)
        seen["turns"] += 1
        if seen["turns"] == 1:
            assert any(t["function"]["name"] == "run_rls_debug" for t in body["tools"])
            return httpx.Response(200, json={"message": {
                "role": "assistant", "content": "",
                "tool_calls": [{"function": {"name": "run_rls_debug",
                                             "arguments": {"table_name": "orders"}}}],
            }})
        seen["tool_message"] = body["messages"][-1]
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "No policy applies."}})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_transport(handler))

    async def dispatch(name, args):
        assert name == "run_rls_debug"
        assert args == {"table_name": "orders"}
        return {"row_visibility": "no_policy_applies"}

    text, traces = await OllamaProvider().chat_with_tools("why zero rows?", "system", dispatch)

    assert text == "No policy applies."
    assert len(traces) == 1
    assert traces[0].tool_name == "run_rls_debug"
    assert traces[0].result["row_visibility"] == "no_policy_applies"
    assert seen["tool_message"]["role"] == "tool"
    assert "no_policy_applies" in seen["tool_message"]["content"]


@pytest.mark.asyncio
async def test_ollama_accepts_json_string_arguments(monkeypatch):
    """Some models return `arguments` as a JSON string rather than an object."""
    turns = {"n": 0}

    def handler(request):
        turns["n"] += 1
        if turns["n"] == 1:
            return httpx.Response(200, json={"message": {
                "role": "assistant", "content": "",
                "tool_calls": [{"function": {"name": "run_rls_debug",
                                             "arguments": '{"table_name": "profiles"}'}}],
            }})
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "done"}})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_transport(handler))

    captured = {}

    async def dispatch(name, args):
        captured.update(args)
        return {}

    await OllamaProvider().chat_with_tools("check profiles", "system", dispatch)
    assert captured == {"table_name": "profiles"}


@pytest.mark.asyncio
async def test_ollama_malformed_arguments_do_not_crash(monkeypatch):
    turns = {"n": 0}

    def handler(request):
        turns["n"] += 1
        if turns["n"] == 1:
            return httpx.Response(200, json={"message": {
                "role": "assistant", "content": "",
                "tool_calls": [{"function": {"name": "run_vacuum_check", "arguments": "not json{"}}],
            }})
        return httpx.Response(200, json={"message": {"role": "assistant", "content": "ok"}})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_transport(handler))

    async def dispatch(name, args):
        assert args == {}
        return []

    text, traces = await OllamaProvider().chat_with_tools("vacuum?", "system", dispatch)
    assert text == "ok"
    assert traces[0].arguments == {}


# --- status probes ------------------------------------------------------------

@pytest.mark.asyncio
async def test_ollama_status_reports_missing_daemon(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_transport(handler))
    status = await OllamaProvider().status()

    assert status.configured is True
    assert status.available is False
    assert "ollama serve" in status.detail


@pytest.mark.asyncio
async def test_ollama_status_reports_missing_model(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "ollama_model", "llama3.1")
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _mock_transport(lambda r: httpx.Response(200, json={"models": [{"name": "mistral:latest"}]})),
    )
    status = await OllamaProvider().status()

    assert status.available is False
    assert "ollama pull llama3.1" in status.detail


@pytest.mark.asyncio
async def test_ollama_status_matches_model_with_tag(monkeypatch):
    """`ollama pull llama3.1` installs it as "llama3.1:latest"; a bare name must match."""
    monkeypatch.setattr(providers_mod.settings, "ollama_model", "llama3.1")
    monkeypatch.setattr(
        httpx, "AsyncClient",
        _mock_transport(lambda r: httpx.Response(200, json={"models": [{"name": "llama3.1:latest"}]})),
    )
    assert (await OllamaProvider().status()).available is True


@pytest.mark.asyncio
async def test_gemini_status_reports_unconfigured(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "gemini_api_key", None)
    status = await GeminiProvider().status()

    assert status.configured is False
    assert status.available is False
    assert "GEMINI_API_KEY" in status.detail


@pytest.mark.asyncio
async def test_gemini_narrate_without_key_raises_provider_unavailable(monkeypatch):
    monkeypatch.setattr(providers_mod.settings, "gemini_api_key", None)
    with pytest.raises(ProviderUnavailable, match="GEMINI_API_KEY"):
        await GeminiProvider().narrate("explain")


# --- narration provenance -----------------------------------------------------

@pytest.mark.asyncio
async def test_narration_returns_the_provider_that_answered(monkeypatch):
    """
    The UI labelled every narration block "GEMINI DIAGNOSTIC ANALYSIS" while Gemini
    was 401ing and Ollama was answering. The provider name has to travel with the text.
    """
    from app.diagnostics import runner

    class _P:
        name = "ollama"

        async def narrate(self, prompt):
            return "  healthy  "

    monkeypatch.setattr(runner, "provider_chain", lambda: [_P()])
    text, provider = await runner.generate_ai_explanation("vacuum_wraparound", "OK: fine", [])

    assert text == "healthy"
    assert provider == "ollama"


@pytest.mark.asyncio
async def test_narration_reports_none_when_every_provider_fails(monkeypatch):
    from app.diagnostics import runner

    class _Broken:
        name = "gemini"

        async def narrate(self, prompt):
            raise RuntimeError("401 UNAUTHENTICATED")

    monkeypatch.setattr(runner, "provider_chain", lambda: [_Broken()])
    text, provider = await runner.generate_ai_explanation("vacuum_wraparound", "OK: fine", [])

    assert text is None and provider is None


@pytest.mark.asyncio
async def test_narration_falls_through_and_names_the_second_provider(monkeypatch):
    from app.diagnostics import runner

    class _Broken:
        name = "gemini"

        async def narrate(self, prompt):
            raise RuntimeError("401")

    class _Works:
        name = "ollama"

        async def narrate(self, prompt):
            return "explanation"

    monkeypatch.setattr(runner, "provider_chain", lambda: [_Broken(), _Works()])
    text, provider = await runner.generate_ai_explanation("rls_debug", "INDETERMINATE: ...", {})

    assert text == "explanation"
    assert provider == "ollama"
