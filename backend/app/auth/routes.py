"""
Authentication routes calling Supabase Auth REST API via httpx.
Zero Supabase JS dependencies.
"""

from typing import Dict
import httpx
from fastapi import APIRouter, HTTPException, Response, status
from app.auth.jwt import verify_supabase_jwt
from app.config import settings
from app.models import AuthCallbackResponse, MagicLinkRequest, MagicLinkResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/magic-link", response_model=MagicLinkResponse)
async def send_magic_link(payload: MagicLinkRequest):
    """
    Calls Supabase Auth REST API directly (POST /auth/v1/magiclink).
    """
    if not settings.supabase_url or not settings.supabase_anon_key:
        # Development simulation response
        return MagicLinkResponse(
            status="sent",
            message=f"[Demo Mode] Simulated magic link sent to {payload.email}. Use local testing token.",
        )

    url = f"{settings.supabase_url.rstrip('/')}/auth/v1/magiclink"
    headers = {
        "apikey": settings.supabase_anon_key,
        "Content-Type": "application/json",
    }
    body = {"email": payload.email}

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code >= 400:
                raise HTTPException(
                    status_code=resp.status_code,
                    detail=f"Supabase Auth Error: {resp.text}",
                )
            return MagicLinkResponse(
                status="sent",
                message=f"Magic link successfully dispatched to {payload.email}",
            )
        except httpx.RequestError as e:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"Failed to communicate with Supabase Auth: {str(e)}",
            )


@router.get("/callback", response_model=AuthCallbackResponse)
async def auth_callback(access_token: str, response: Response):
    """
    Verifies the JWT against Supabase's published JWKS and establishes an HTTP-only session cookie.
    """
    claims = verify_supabase_jwt(access_token)
    user_id = claims.get("sub", "")
    email = claims.get("email")

    # Set secure HTTP-only session cookie
    response.set_cookie(
        key=settings.session_cookie_name,
        value=access_token,
        httponly=True,
        secure=settings.environment == "production",
        samesite="lax",
        max_age=86400 * 7,  # 7 days
    )

    return AuthCallbackResponse(
        user_id=user_id,
        email=email,
        org_id=claims.get("org_id", "00000000-0000-0000-0000-000000000001"),
        token=access_token,
    )
