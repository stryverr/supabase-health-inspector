"""
Pytest suite for Supabase JWT verification.

The case that matters: this project's JWKS serves an ES256 (EC P-256) key, which
is what current Supabase projects issue. An allow-list of ["RS256", "HS256"]
rejects those tokens with InvalidAlgorithmError even though they are valid and
correctly signed.
"""

import datetime
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from app.auth import jwt as auth_jwt
from app.auth.jwt import ALLOWED_ALGORITHMS, verify_supabase_jwt


class _FakeSigningKey:
    def __init__(self, key):
        self.key = key


class _FakeJWKClient:
    def __init__(self, public_key):
        self._public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return _FakeSigningKey(self._public_key)


def _es256_token(private_key, **overrides):
    claims = {
        "sub": "11111111-1111-1111-1111-111111111111",
        "email": "user@example.com",
        "role": "authenticated",
        "aud": "authenticated",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="ES256")


def test_es256_is_allowed():
    """Supabase's current signing algorithm must be in the allow-list."""
    assert "ES256" in ALLOWED_ALGORITHMS


def test_verifies_a_real_es256_token(monkeypatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    token = _es256_token(private_key)

    monkeypatch.setattr(
        auth_jwt, "get_jwk_client", lambda: _FakeJWKClient(private_key.public_key())
    )

    claims = verify_supabase_jwt(token)
    assert claims["sub"] == "11111111-1111-1111-1111-111111111111"
    assert claims["role"] == "authenticated"


def test_rejects_token_signed_by_a_different_key(monkeypatch):
    """A valid-looking ES256 token signed by the wrong key must not verify."""
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    real_key = ec.generate_private_key(ec.SECP256R1())
    token = _es256_token(attacker_key)

    monkeypatch.setattr(
        auth_jwt, "get_jwk_client", lambda: _FakeJWKClient(real_key.public_key())
    )

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        verify_supabase_jwt(token)
    assert exc.value.status_code == 401


def test_rejects_expired_token(monkeypatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    token = _es256_token(
        private_key,
        exp=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1),
    )

    monkeypatch.setattr(
        auth_jwt, "get_jwk_client", lambda: _FakeJWKClient(private_key.public_key())
    )

    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        verify_supabase_jwt(token)
    assert exc.value.status_code == 401


def test_rejects_wrong_audience(monkeypatch):
    private_key = ec.generate_private_key(ec.SECP256R1())
    token = _es256_token(private_key, aud="some-other-service")

    monkeypatch.setattr(
        auth_jwt, "get_jwk_client", lambda: _FakeJWKClient(private_key.public_key())
    )

    from fastapi import HTTPException

    with pytest.raises(HTTPException):
        verify_supabase_jwt(token)


def test_empty_token_is_rejected():
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        verify_supabase_jwt("")
    assert exc.value.status_code == 401
