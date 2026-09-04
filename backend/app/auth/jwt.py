"""
Supabase Auth JWT verification using PyJWT and the project's published JWKS.

No Supabase JS client is used; keys and claims are validated against the standard
JWKS endpoint.

Security posture: this module used to accept unauthenticated requests as a
hardcoded demo user, accept unsigned tokens whenever SUPABASE_URL happened to be
unset, and fall back to an HS256 check that could never succeed. Those paths are
now either removed or gated behind a non-production environment, and every use of
them logs a warning naming the request that took it.
"""

import logging
from typing import Any, Dict, Optional
import jwt
from jwt import PyJWKClient
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from app.config import settings

logger = logging.getLogger(__name__)

security_bearer = HTTPBearer(auto_error=False)
_jwk_client: Optional[PyJWKClient] = None

# Supabase signs project JWTs with an asymmetric key published via JWKS. Current
# projects use ES256 (EC P-256) -- verified against this project's
# /auth/v1/.well-known/jwks.json. Older projects use RS256.
#
# HS256 is deliberately absent. Every key this list is applied to comes from JWKS
# and is therefore a PUBLIC key; also allowing a symmetric algorithm is the classic
# algorithm-confusion setup, where an attacker signs a token using the public key
# as an HMAC secret and the verifier accepts it. Legacy HS256 projects would need
# the shared JWT secret configured explicitly, on a separate code path.
ALLOWED_ALGORITHMS = ["ES256", "RS256"]

# Claims handed to unauthenticated callers in non-production environments only.
DEMO_CLAIMS: Dict[str, Any] = {
    "sub": "00000000-0000-0000-0000-000000000001",
    "email": "demo@inspector.internal",
    "role": "authenticated",
    "org_id": "00000000-0000-0000-0000-000000000001",
    "_demo": True,
}


def demo_auth_enabled() -> bool:
    """
    True only outside production. Read at call time rather than import time so a
    test or a redeploy that changes `environment` takes effect immediately.
    """
    return (settings.environment or "").strip().lower() != "production"


def get_jwk_client() -> Optional[PyJWKClient]:
    global _jwk_client
    if _jwk_client is None and settings.supabase_url:
        jwks_url = f"{settings.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"
        _jwk_client = PyJWKClient(jwks_url)
    return _jwk_client


def verify_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Verifies a Supabase access token against the project's JWKS.

    Raises 401 for anything that does not verify, and 503 when the service is not
    configured to verify at all -- never silently accepts an unverified token in
    production.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
        )

    jwk_client = get_jwk_client()

    if jwk_client is None:
        # No SUPABASE_URL: signatures cannot be checked at all.
        if demo_auth_enabled():
            logger.warning(
                "DEMO AUTH: accepting an UNVERIFIED token because SUPABASE_URL is unset "
                "and environment=%r. Signature, expiry and audience were NOT checked.",
                settings.environment,
            )
            try:
                return jwt.decode(token, options={"verify_signature": False})
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid JWT structure",
                )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Authentication is not configured: SUPABASE_URL must be set so tokens can be "
                "verified against the project's JWKS. Refusing to accept unverified tokens."
            ),
        )

    try:
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            signing_key.key,
            algorithms=ALLOWED_ALGORITHMS,
            audience="authenticated",
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired JWT token: {str(e)}",
        )


def _token_from_request(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials],
) -> Optional[str]:
    """
    Bearer header first, then the HTTP-only session cookie set by /auth/callback.

    Supporting the cookie means the browser never has to hold the token in
    JavaScript-readable storage, while the header keeps API clients simple.
    """
    if credentials and credentials.credentials:
        return credentials.credentials
    return request.cookies.get(settings.session_cookie_name)


async def get_current_user_claims(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> Dict[str, Any]:
    """
    Resolves the caller's verified claims, or rejects the request.

    In a non-production environment an unauthenticated request is answered with
    DEMO_CLAIMS so the UI is usable without a login; in production it is a 401.
    """
    token = _token_from_request(request, credentials)

    if not token:
        if demo_auth_enabled():
            logger.warning(
                "DEMO AUTH: unauthenticated %s %s answered with demo claims because "
                "environment=%r. Set ENVIRONMENT=production to require real tokens.",
                request.method,
                request.url.path,
                settings.environment,
            )
            return dict(DEMO_CLAIMS)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Supply a Supabase access token as a Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return verify_supabase_jwt(token)
