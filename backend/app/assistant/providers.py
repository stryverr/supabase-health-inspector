"""
LLM provider abstraction for narration and the function-calling assistant.

Two providers are supported, and neither is required: the diagnostics are the
product, and the model only puts words around them. When no provider works the
caller falls back to deterministic keyword routing, which still executes the real
queries.

  gemini  - hosted, needs GEMINI_API_KEY
  ollama  - local HTTP on :11434, no API key, needs a tool-calling model
  none    - deterministic routing only

Selection comes from `settings.llm_provider`, overridable at runtime via
PUT /assistant/provider so a broken hosted key does not require a redeploy.
"""

import json
import logging
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
from app.assistant.tools import DIAGNOSTIC_TOOLS, ollama_tool_schemas
from app.config import settings
from app.models import ToolCallTrace

logger = logging.getLogger(__name__)

MAX_TOOL_TURNS = 3
PROVIDER_NAMES = ("gemini", "ollama")


class ProviderUnavailable(RuntimeError):
    """Raised when a provider cannot serve a request; the caller may try another."""


@dataclass
class ProviderStatus:
    name: str
    configured: bool          # has the settings it needs
    available: bool           # actually answered a probe just now
    model: Optional[str]
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# A dispatcher runs one tool by name and returns its raw result.
ToolDispatcher = Callable[[str, Dict[str, Any]], Any]


class LLMProvider:
    name = "base"

    async def status(self) -> ProviderStatus:
        raise NotImplementedError

    async def narrate(self, prompt: str) -> str:
        """One-shot completion used for diagnostic narration."""
        raise NotImplementedError

    async def chat_with_tools(
        self,
        user_message: str,
        system_instruction: str,
        dispatch: ToolDispatcher,
    ) -> Tuple[str, List[ToolCallTrace]]:
        """Runs the function-calling loop, returning (final_text, traces)."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------
class GeminiProvider(LLMProvider):
    name = "gemini"

    def __init__(self) -> None:
        self.model = settings.gemini_model

    def _client(self):
        if not settings.gemini_api_key:
            raise ProviderUnavailable("GEMINI_API_KEY is not set.")
        from google import genai

        return genai.Client(api_key=settings.gemini_api_key)

    async def status(self) -> ProviderStatus:
        if not settings.gemini_api_key:
            return ProviderStatus(self.name, False, False, self.model, "GEMINI_API_KEY is not set.")
        try:
            client = self._client()
            await client.aio.models.generate_content(model=self.model, contents="ping")
            return ProviderStatus(self.name, True, True, self.model, "Responded to a probe request.")
        except Exception as e:
            return ProviderStatus(
                self.name, True, False, self.model, f"{type(e).__name__}: {str(e)[:220]}"
            )

    async def narrate(self, prompt: str) -> str:
        try:
            client = self._client()
            response = await client.aio.models.generate_content(
                model=self.model, contents=prompt
            )
            return (response.text or "").strip()
        except ProviderUnavailable:
            raise
        except Exception as e:
            raise ProviderUnavailable(f"Gemini narration failed: {type(e).__name__}: {e}") from e

    async def chat_with_tools(self, user_message, system_instruction, dispatch):
        from google.genai import types

        traces: List[ToolCallTrace] = []
        try:
            client = self._client()
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                tools=[types.Tool(function_declarations=DIAGNOSTIC_TOOLS)],
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            )
            chat = client.aio.chats.create(model=self.model, config=config)
            response = await chat.send_message(user_message)

            for _ in range(MAX_TOOL_TURNS):
                calls = response.function_calls or []
                if not calls:
                    break
                call = calls[0]
                args = dict(call.args or {})
                result = await dispatch(call.name, args)
                traces.append(
                    ToolCallTrace(tool_name=call.name, arguments=args, result=result)
                )
                response = await chat.send_message(
                    types.Part.from_function_response(
                        name=call.name, response={"result": _json_safe(result)}
                    )
                )

            return (response.text or "").strip(), traces
        except ProviderUnavailable:
            raise
        except Exception as e:
            raise ProviderUnavailable(f"Gemini chat failed: {type(e).__name__}: {e}") from e


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self) -> None:
        self.base_url = (settings.ollama_base_url or "").rstrip("/")
        self.model = settings.ollama_model

    async def status(self) -> ProviderStatus:
        if not self.base_url:
            return ProviderStatus(self.name, False, False, self.model, "OLLAMA_BASE_URL is not set.")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                tags = resp.json().get("models", [])
        except Exception as e:
            return ProviderStatus(
                self.name, True, False, self.model,
                f"No Ollama at {self.base_url} ({type(e).__name__}). Install from ollama.com and run `ollama serve`.",
            )

        installed = [m.get("name", "") for m in tags]
        # Ollama tags are "name:tag"; a bare model name should still match.
        if not any(n == self.model or n.split(":")[0] == self.model for n in installed):
            return ProviderStatus(
                self.name, True, False, self.model,
                f"Ollama is running but model {self.model!r} is not installed. "
                f"Run `ollama pull {self.model}`. Installed: {installed or 'none'}.",
            )
        return ProviderStatus(
            self.name, True, True, self.model, f"Ollama reachable with {len(installed)} model(s) installed."
        )

    async def _chat(self, payload: Dict[str, Any], timeout: float = 120.0) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(f"{self.base_url}/api/chat", json=payload)
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as e:
            body = e.response.text[:200] if e.response is not None else ""
            raise ProviderUnavailable(f"Ollama HTTP {e.response.status_code}: {body}") from e
        except Exception as e:
            raise ProviderUnavailable(f"Ollama request failed: {type(e).__name__}: {e}") from e

    async def narrate(self, prompt: str) -> str:
        data = await self._chat(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
        )
        return (data.get("message", {}).get("content") or "").strip()

    async def chat_with_tools(self, user_message, system_instruction, dispatch):
        traces: List[ToolCallTrace] = []
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_message},
        ]
        tools = ollama_tool_schemas()

        for _ in range(MAX_TOOL_TURNS):
            data = await self._chat(
                {"model": self.model, "messages": messages, "tools": tools, "stream": False}
            )
            message = data.get("message", {}) or {}
            calls = message.get("tool_calls") or []
            messages.append(message)

            if not calls:
                return (message.get("content") or "").strip(), traces

            for call in calls:
                fn = call.get("function", {}) or {}
                name = fn.get("name", "")
                raw_args = fn.get("arguments", {})
                # Ollama returns a dict for most models, a JSON string for some.
                if isinstance(raw_args, str):
                    try:
                        raw_args = json.loads(raw_args)
                    except Exception:
                        raw_args = {}
                args = dict(raw_args or {})

                result = await dispatch(name, args)
                traces.append(ToolCallTrace(tool_name=name, arguments=args, result=result))
                messages.append(
                    {
                        "role": "tool",
                        "content": json.dumps(_json_safe(result), default=str)[:12000],
                    }
                )

        # Tool budget exhausted: ask once more for a plain answer.
        data = await self._chat(
            {"model": self.model, "messages": messages, "stream": False}
        )
        return (data.get("message", {}).get("content") or "").strip(), traces


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
_runtime_override: Optional[str] = None


def _build(name: str) -> LLMProvider:
    return {"gemini": GeminiProvider, "ollama": OllamaProvider}[name]()


def configured_provider_name() -> str:
    """The provider selection in force: runtime override, else settings."""
    return (_runtime_override or settings.llm_provider or "auto").strip().lower()


def set_runtime_provider(name: Optional[str]) -> str:
    """
    Overrides the configured provider for this process. Pass None to clear.
    Does not persist -- a restart returns to LLM_PROVIDER in backend/.env.
    """
    global _runtime_override
    if name is not None:
        normalized = name.strip().lower()
        if normalized not in PROVIDER_NAMES + ("auto", "none"):
            raise ValueError(
                f"Unknown provider {name!r}. Expected one of: "
                f"{', '.join(PROVIDER_NAMES + ('auto', 'none'))}."
            )
        _runtime_override = normalized
    else:
        _runtime_override = None
    logger.info("LLM provider override set to %r", _runtime_override)
    return configured_provider_name()


def provider_chain() -> List[LLMProvider]:
    """
    Providers to try, in order. "auto" prefers Gemini and falls back to Ollama,
    so a rejected hosted key degrades to a local model rather than to nothing.
    """
    selection = configured_provider_name()
    if selection == "none":
        return []
    if selection == "auto":
        return [_build("gemini"), _build("ollama")]
    if selection in PROVIDER_NAMES:
        return [_build(selection)]
    logger.warning("Unknown llm_provider %r; falling back to auto.", selection)
    return [_build("gemini"), _build("ollama")]


async def provider_statuses() -> List[Dict[str, Any]]:
    """Live status of every provider, for the UI toggle."""
    out = []
    for name in PROVIDER_NAMES:
        try:
            out.append((await _build(name).status()).to_dict())
        except Exception as e:
            out.append(
                ProviderStatus(name, False, False, None, f"{type(e).__name__}: {e}").to_dict()
            )
    return out


def _json_safe(value: Any) -> Any:
    """Coerces asyncpg output (Decimal, datetime, UUID) into JSON-encodable types."""
    import datetime
    import decimal
    import uuid

    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, decimal.Decimal):
        return float(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time, datetime.timedelta)):
        return str(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
