"""Password and Google authentication routes with JWT session handling."""
from datetime import datetime
import base64
import hashlib
import logging
import secrets
import uuid
from fastapi import APIRouter, HTTPException, Depends, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from core.database import get_db
from core.models import User
from core.rbac import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    record_audit_log,
)
from integrations.gmail.oauth import (
    create_google_identity_state,
    verify_google_identity_state,
)
from core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# ── Demo User Fallbacks ───────────────────────────────────────────────────────
DEMO_USERS = {
    "admin@forensics.local": {
        "id": "u-001",
        "name": "Admin User",
        "role": "admin",
        "password_hash": hash_password("admin123"),
    },
    "analyst@forensics.local": {
        "id": "u-002",
        "name": "Demo Analyst",
        "role": "analyst",
        "password_hash": hash_password("analyst123"),
    },
    "investigator@forensics.local": {
        "id": "u-003",
        "name": "IR Investigator",
        "role": "investigator",
        "password_hash": hash_password("ir2026"),
    },
}


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


@router.post("/auth/register", summary="Create a Forensic AI email/password account")
async def register(
    payload: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    name = payload.name.strip()
    email = str(payload.email).lower().strip()
    if not name:
        raise HTTPException(422, "Name is required.")
    if len(payload.password) < 8:
        raise HTTPException(422, "Password must be at least 8 characters.")

    existing = (
        await db.execute(select(User.id).where(User.email == email))
    ).scalar_one_or_none()
    if existing:
        raise HTTPException(409, "An account with this email is already registered.")

    user = User(
        email=email,
        name=name,
        role="analyst",
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    try:
        await db.commit()
        await db.refresh(user)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "An account with this email is already registered.") from exc
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            503,
            "Account service is temporarily unavailable. Please try again.",
        ) from exc

    return await _issue_token(user, request, db, "LOGIN")


@router.post("/auth/login", summary="Login with Forensic AI email and password")
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    email = str(payload.email).lower().strip()
    client_ip = request.client.host if request.client else "127.0.0.1"

    user_data = None

    # 1. Query Database first
    try:
        user = (
            await db.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
    except SQLAlchemyError as exc:
        await db.rollback()
        raise HTTPException(
            503,
            "Authentication service is temporarily unavailable. Please try again.",
        ) from exc

    if user:
        if not verify_password(payload.password, user.hashed_password):
            raise HTTPException(401, "Invalid email or password.")
        if not user.is_active:
            raise HTTPException(403, "This Forensic AI account is inactive.")
        user_data = {
            "id": str(user.id),
            "name": user.name,
            "email": user.email,
            "role": user.role,
            "_db_user": user,
        }

    # 2. Fall back to demo users if not found in DB
    if not user_data and email in DEMO_USERS:
        demo = DEMO_USERS[email]
        if verify_password(payload.password, demo["password_hash"]):
            user_data = {
                "id": demo["id"],
                "name": demo["name"],
                "email": email,
                "role": demo["role"],
            }

    if not user_data:
        raise HTTPException(401, "Invalid email or password.")

    # Update last_login for DB users
    if "_db_user" in user_data:
        db_user = user_data.pop("_db_user")
        db_user.last_login = datetime.utcnow()
        try:
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()

    data = {k: v for k, v in user_data.items()}
    token = create_access_token({"sub": data["id"], "email": data["email"], "name": data["name"], "role": data["role"]})
    await record_audit_log(
        db=db, action="LOGIN", analyst_id=data["id"], resource_type="auth",
        resource_id=data["id"], ip_address=client_ip,
        detail=f"User {data['email']} authenticated",
    )
    return {"access_token": token, "token_type": "bearer", "user": data}


@router.get("/auth/google")
async def google_login():
    if not settings.google_client_id or not settings.google_client_secret:
        raise HTTPException(503, "Google authentication is not configured.")
    from google_auth_oauthlib.flow import Flow
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    flow = Flow.from_client_config({"web": {
        "client_id": settings.google_client_id, "client_secret": settings.google_client_secret,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [settings.google_auth_redirect_uri]}},
        scopes=["openid", "email", "profile"],
        autogenerate_code_verifier=False)
    flow.redirect_uri = settings.google_auth_redirect_uri
    logger.debug(
        "OAuth flow=Google Login requested_scopes=%s",
        sorted(flow.oauth2session.scope or []),
    )
    url, _ = flow.authorization_url(
        access_type="offline",
        prompt="select_account",
        state=create_google_identity_state(code_verifier),
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    return {"authorization_url": url}


@router.get("/auth/google/callback")
async def google_callback(code: str, state: str, request: Request, db: AsyncSession = Depends(get_db)):
    code_verifier = verify_google_identity_state(state)
    if not code_verifier:
        raise HTTPException(400, "Invalid or expired Google OAuth state.")
    from google_auth_oauthlib.flow import Flow
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    flow = Flow.from_client_config({"web": {
        "client_id": settings.google_client_id, "client_secret": settings.google_client_secret,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [settings.google_auth_redirect_uri]}},
        scopes=["openid", "email", "profile"],
        autogenerate_code_verifier=False)
    flow.redirect_uri = settings.google_auth_redirect_uri
    try:
        flow.fetch_token(code=code, code_verifier=code_verifier)
        logger.debug(
            "OAuth flow=Google Login returned_scopes=%s",
            sorted(flow.credentials.scopes or []),
        )
        info = id_token.verify_oauth2_token(flow.credentials.id_token, google_requests.Request(),
                                            settings.google_client_id)
    except Exception as exc:
        raise HTTPException(400, f"Google authentication failed: {exc}") from exc
    email = info.get("email", "").lower()
    if not email or not info.get("email_verified"):
        raise HTTPException(400, "Google account has no verified email.")
    google_id = info.get("sub")
    if not google_id:
        raise HTTPException(400, "Google account did not provide a stable identity.")

    user = (
        await db.execute(select(User).where(User.google_id == google_id))
    ).scalar_one_or_none()
    if not user:
        user = (
            await db.execute(select(User).where(User.email == email))
        ).scalar_one_or_none()
    if not user:
        user = User(email=email, name=info.get("name") or email.split("@")[0],
                    role="analyst", hashed_password=hash_password(str(uuid.uuid4())),
                    google_id=google_id, profile_picture=info.get("picture"))
        db.add(user)
    else:
        if not user.is_active:
            raise HTTPException(403, "This Forensic AI account is inactive.")
        user.google_id = google_id
        user.profile_picture = info.get("picture") or user.profile_picture
        user.name = info.get("name") or user.name
    user.last_login = datetime.utcnow()
    await db.commit()
    await db.refresh(user)
    result = await _issue_token(user, request, db, "LOGIN")
    # Frontend consumes the token and clears it from the URL.
    return RedirectResponse(
        f"{settings.frontend_url}/?auth_token={result['access_token']}"
    )


async def _issue_token(user: User, request: Request, db: AsyncSession, action: str = "LOGIN"):
    data = {"id": str(user.id), "name": user.name, "email": user.email, "role": user.role}
    token = create_access_token({"sub": data["id"], **{k: data[k] for k in ("email", "name", "role")}})
    await record_audit_log(db=db, action=action, analyst_id=data["id"], resource_type="auth",
                           resource_id=data["id"],
                           ip_address=request.client.host if request.client else "127.0.0.1",
                           detail=f"User {data['email']} authenticated")
    return {"access_token": token, "token_type": "bearer", "user": data}


@router.post("/auth/logout")
async def logout(user=Depends(get_current_user)):
    # JWTs are stateless; the client removes its token. Endpoint exists for a
    # consistent API and future token revocation support.
    return {"logged_out": True}


@router.get("/auth/me", summary="Get current user info from token")
async def me(user=Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
    }
