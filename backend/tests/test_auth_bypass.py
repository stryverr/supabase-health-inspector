"""
Tests for the three auth bypasses that used to be unconditional.

Each one is now gated on `settings.environment != "production"`. These tests pin
the production behaviour, because the failure mode is silent: a deployment that
waves every request through looks exactly like one that works.
"""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from app.auth import jwt as auth_jwt
from app.auth.jwt import (
    ALLOWED_ALGORITHMS,
    demo_auth_enabled,
    get_current_user_claims,
    verify_supabase_jwt,
)


class _Req:
    """Minimal stand-in for fastapi.Request as get_current_user_claims uses it."""

    def __init__(self, cookies=None, path="/connections", method="GET"):
        self.cookies = cookies or {}
        self.method = method
        self.url = type("U", (), {"path": path})()


@pytest.fixture
def production(monkeypatch):
    monkeypatch.setattr(auth_jwt.settings, "environment", "production")


@pytest.fixture
def development(monkeypatch):
    monkeypatch.setattr(auth_jwt.settings, "environment", "development")


# --- bypass 1: unauthenticated requests answered as a demo user ---------------

@pytest.mark.asyncio
async def test_production_rejects_unauthenticated_request(production):
    with pytest.raises(HTTPException) as exc:
        await get_current_user_claims(_Req(), None)
    assert exc.value.status_code == 401
    assert exc.value.headers.get("WWW-Authenticate") == "Bearer"


@pytest.mark.asyncio
async def test_non_production_still_allows_demo_claims(development):
    claims = await get_current_user_claims(_Req(), None)
    assert claims["_demo"] is True
    assert claims["role"] == "authenticated"


# --- bypass 2: unsigned tokens accepted when SUPABASE_URL is unset ------------

@pytest.mark.asyncio
async def test_production_refuses_to_verify_without_supabase_url(production, monkeypatch):
    monkeypatch.setattr(auth_jwt, "get_jwk_client", lambda: None)
    # An unsigned token that the old code would have decoded and trusted.
    import jwt as pyjwt
    forged = pyjwt.encode({"sub": "attacker", "role": "service_role"}, "not-the-real-secret", algorithm="HS256")

    with pytest.raises(HTTPException) as exc:
        verify_supabase_jwt(forged)
    assert exc.value.status_code == 503
    assert "Refusing to accept unverified tokens" in exc.value.detail


def test_non_production_accepts_unverified_token_when_unconfigured(development, monkeypatch):
    monkeypatch.setattr(auth_jwt, "get_jwk_client", lambda: None)
    import jwt as pyjwt
    token = pyjwt.encode({"sub": "dev-user"}, "any-secret", algorithm="HS256")

    claims = verify_supabase_jwt(token)
    assert claims["sub"] == "dev-user"


# --- bypass 3: the HS256 fallback -------------------------------------------

def test_hs256_is_not_an_accepted_algorithm():
    """
    Removed entirely. Every key in this path comes from JWKS and is public, so
    permitting a symmetric algorithm alongside it is the algorithm-confusion
    attack: sign with the public key as an HMAC secret and the token verifies.
    """
    assert "HS256" not in ALLOWED_ALGORITHMS
    assert ALLOWED_ALGORITHMS == ["ES256", "RS256"]


def test_service_role_key_is_no_longer_used_as_a_signing_secret():
    """The old fallback fed a JWT in as an HMAC secret; it could never verify."""
    import inspect
    source = inspect.getsource(auth_jwt)
    assert "supabase_service_role_key" not in source


# --- token sources -----------------------------------------------------------

@pytest.mark.asyncio
async def test_session_cookie_is_accepted_as_a_token_source(production, monkeypatch):
    """The HTTP-only cookie set by /auth/callback authenticates too."""
    seen = {}

    def fake_verify(token):
        seen["token"] = token
        return {"sub": "cookie-user"}

    monkeypatch.setattr(auth_jwt, "verify_supabase_jwt", fake_verify)
    req = _Req(cookies={auth_jwt.settings.session_cookie_name: "cookie-token"})

    claims = await get_current_user_claims(req, None)
    assert claims["sub"] == "cookie-user"
    assert seen["token"] == "cookie-token"


@pytest.mark.asyncio
async def test_bearer_header_takes_precedence_over_cookie(production, monkeypatch):
    seen = {}

    def fake_verify(token):
        seen["token"] = token
        return {"sub": "header-user"}

    monkeypatch.setattr(auth_jwt, "verify_supabase_jwt", fake_verify)
    req = _Req(cookies={auth_jwt.settings.session_cookie_name: "cookie-token"})
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="header-token")

    await get_current_user_claims(req, creds)
    assert seen["token"] == "header-token"


def test_demo_auth_flag_tracks_environment(monkeypatch):
    for env, expected in [("production", False), ("PRODUCTION", False),
                          ("development", True), ("staging", True), ("", True)]:
        monkeypatch.setattr(auth_jwt.settings, "environment", env)
        assert demo_auth_enabled() is expected, env
