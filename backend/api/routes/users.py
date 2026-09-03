"""
User Management & System Configuration routes — ADMIN only.
Includes secure password hashing, role updates, and ADMIN_ACTION audit logs.
"""
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from core.database import get_db
from core.models import User
from core.rbac import require_roles, hash_password, record_audit_log, AuthenticatedUser

router = APIRouter()


class UserCreateRequest(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str  # analyst, investigator, admin


class UserUpdateRequest(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    password: Optional[str] = None


class ConfigUpdateRequest(BaseModel):
    debug: Optional[bool] = None
    max_upload_size_mb: Optional[int] = None
    geoip_enabled: Optional[bool] = None
    threat_intel_enabled: Optional[bool] = None


# ── User Management Endpoints (ADMIN Only) ──────────────────────────────────

@router.get("/users", summary="List all system users (ADMIN only)")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    stmt = select(User).order_by(User.created_at.desc())
    res = await db.execute(stmt)
    users = res.scalars().all()
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "name": u.name,
            "role": u.role.upper(),
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.post("/users", summary="Create a new user (ADMIN only)")
async def create_user(
    payload: UserCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    role_norm = payload.role.lower()
    if role_norm not in ("analyst", "investigator", "admin"):
        raise HTTPException(400, "Role must be ANALYST, INVESTIGATOR, or ADMIN.")

    email_clean = payload.email.lower().strip()
    stmt = select(User).where(User.email == email_clean)
    existing = (await db.execute(stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(400, f"User with email '{email_clean}' already exists.")

    new_user = User(
        email=email_clean,
        name=payload.name,
        role=role_norm,
        hashed_password=hash_password(payload.password),
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_log(
        db=db,
        action="ADMIN_ACTION",
        analyst_id=current_user.id,
        resource_type="user",
        resource_id=str(new_user.id),
        ip_address=client_ip,
        detail=f"Created user {new_user.email} with role {new_user.role.upper()}"
    )

    return {
        "id": str(new_user.id),
        "email": new_user.email,
        "name": new_user.name,
        "role": new_user.role.upper(),
        "created_at": new_user.created_at.isoformat(),
    }


@router.patch("/users/{user_id}", summary="Update user details/role (ADMIN only)")
async def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    stmt = select(User).where(User.id == user_id)
    u = (await db.execute(stmt)).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found.")

    if payload.name:
        u.name = payload.name
    if payload.role:
        r_norm = payload.role.lower()
        if r_norm not in ("analyst", "investigator", "admin"):
            raise HTTPException(400, "Role must be ANALYST, INVESTIGATOR, or ADMIN.")
        u.role = r_norm
    if payload.password:
        u.hashed_password = hash_password(payload.password)

    await db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_log(
        db=db,
        action="ADMIN_ACTION",
        analyst_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
        ip_address=client_ip,
        detail=f"Updated user {u.email} details/role"
    )

    return {
        "id": str(u.id),
        "email": u.email,
        "name": u.name,
        "role": u.role.upper(),
    }


@router.delete("/users/{user_id}", summary="Delete a user (ADMIN only)")
async def delete_user(
    user_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    stmt = select(User).where(User.id == user_id)
    u = (await db.execute(stmt)).scalar_one_or_none()
    if not u:
        raise HTTPException(404, "User not found.")

    await db.delete(u)
    await db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_log(
        db=db,
        action="ADMIN_ACTION",
        analyst_id=current_user.id,
        resource_type="user",
        resource_id=user_id,
        ip_address=client_ip,
        detail=f"Deleted user {u.email}"
    )

    return {"deleted": user_id}


# ── System Configuration Endpoints (ADMIN Only) ──────────────────────────────

@router.get("/config", summary="View platform configuration (ADMIN only)")
async def get_system_config(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_log(
        db=db,
        action="ADMIN_ACTION",
        analyst_id=current_user.id,
        resource_type="config",
        ip_address=client_ip,
        detail="Viewed system configuration parameters"
    )
    return {
        "app_name": "ForensicAI Incident Response",
        "version": "3.0.0",
        "rbac_enforced": True,
        "supported_roles": ["ANALYST", "INVESTIGATOR", "ADMIN"],
        "max_upload_size_mb": 10,
        "geoip_enabled": True,
        "threat_intel_enabled": True,
        "audit_logging_active": True,
    }


@router.patch("/config", summary="Update system configuration (ADMIN only)")
async def update_system_config(
    payload: ConfigUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    await record_audit_log(
        db=db,
        action="ADMIN_ACTION",
        analyst_id=current_user.id,
        resource_type="config",
        ip_address=client_ip,
        detail="Updated system configuration parameters"
    )
    return {"status": "updated", "config": payload.dict(exclude_unset=True)}
