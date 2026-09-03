"""
Auth routes — JWT-based authentication & RBAC user login.
Supports DB user authentication with fallbacks to demo accounts.
No plaintext passwords stored. Records LOGIN audit logs.
"""
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from core.models import User
from core.rbac import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    get_current_user,
    record_audit_log,
    security
)

router = APIRouter()

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


@router.post("/auth/login", summary="Login and receive JWT token")
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    email_clean = payload.email.lower().strip()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # 1. Query Database first
    stmt = select(User).where(User.email == email_clean)
    db_res = await db.execute(stmt)
    db_user = db_res.scalar_one_or_none()

    user_data = None
    if db_user:
        if verify_password(payload.password, db_user.hashed_password):
            user_data = {
                "id": str(db_user.id),
                "name": db_user.name,
                "email": db_user.email,
                "role": db_user.role,
            }
    else:
        # 2. Check Demo Users Fallback
        demo = DEMO_USERS.get(email_clean)
        if demo and verify_password(payload.password, demo["password_hash"]):
            user_data = {
                "id": demo["id"],
                "name": demo["name"],
                "email": email_clean,
                "role": demo["role"],
            }

    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    exp = datetime.utcnow() + timedelta(hours=8)
    token = create_access_token({
        "sub": user_data["id"],
        "email": user_data["email"],
        "name": user_data["name"],
        "role": user_data["role"],
    })

    # Mandatory Audit Logging for LOGIN
    await record_audit_log(
        db=db,
        action="LOGIN",
        analyst_id=user_data["id"],
        resource_type="auth",
        resource_id=user_data["id"],
        ip_address=client_ip,
        detail=f"User {user_data['email']} logged in with role {user_data['role'].upper()}"
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user_data,
        "expires_at": exp.isoformat(),
    }


@router.get("/auth/me", summary="Get current user info from token")
async def me(user=Depends(get_current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
    }


@router.get("/auth/users", summary="List demo users (dev helper)")
async def list_demo_users():
    return [
        {"email": "admin@forensics.local",        "password": "admin123",  "role": "ADMIN"},
        {"email": "analyst@forensics.local",       "password": "analyst123","role": "ANALYST"},
        {"email": "investigator@forensics.local",  "password": "ir2026",    "role": "INVESTIGATOR"},
    ]
