"""
Configuration settings for Supabase Health Inspector backend.
Loaded via pydantic-settings from environment variables.
"""

from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

# Resolved from this module's location, not the process working directory, so the
# file is found no matter where uvicorn is launched from. A CWD-relative ".env"
# silently reads as "everything unset" when the server starts from the repo root.
ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    # App config
    app_name: str = "Supabase Health Inspector"
    environment: str = "production"
    debug: bool = False
    frontend_dir: str = "../frontend"
    session_cookie_name: str = "shi_session"

    # Control-plane Postgres (Stores orgs, profiles, scans, chats)
    control_plane_db_url: Optional[str] = None

    # Supabase Auth REST & JWKS settings
    supabase_url: Optional[str] = None
    supabase_anon_key: Optional[str] = None
    supabase_service_role_key: Optional[str] = None

    # Gemini AI SDK
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-2.5-flash"

    # Which LLM backs narration and the function-calling assistant.
    #   "auto"   - prefer Gemini, fall back to Ollama, then to deterministic routing
    #   "gemini" - Gemini only
    #   "ollama" - Ollama only
    #   "none"   - no LLM; deterministic routing only
    # Overridable at runtime via PUT /assistant/provider without a restart.
    llm_provider: str = "auto"

    # Ollama runs locally and needs no API key, which makes it a usable fallback
    # when a hosted key is rejected. Tool calling requires a model that supports
    # it (llama3.1, qwen2.5, mistral-nemo and similar).
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"

    # Target Database Connection URL for Live Diagnostics.
    # Expected to be an unprivileged, read-only role (e.g. inspector_ro) that is NOT
    # a member of `authenticated`. Connecting as a superuser would defeat the
    # read-only design and hide the INDETERMINATE results this tool exists to report.
    target_database_url: Optional[str] = None
    default_target_db_url: Optional[str] = None

    # Optional, opt-in elevated connection used ONLY for data-shape checks that
    # require reading rows. Unset by default; when unset, those checks report
    # INDETERMINATE rather than being silently skipped.
    target_elevated_database_url: Optional[str] = None

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE),
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
