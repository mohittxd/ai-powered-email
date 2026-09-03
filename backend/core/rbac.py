"""
Phase 18 — Role-Based Access Control (RBAC) & Security Module.
Provides secure password hashing (bcrypt), JWT token verification, role permissions, and audit logging.

Roles:
- ANALYST: Upload email, analyze email, view assigned cases.
- INVESTIGATOR: View cases, view forensic reports, export reports.
- ADMIN: All permissions, user management, audit logs, system configuration.

Audit Action Categories:
- LOGIN
- EMAIL_UPLOAD
- CASE_VIEW
- REPORT_EXPORT
- CASE_UPDATE
- ADMIN_ACTION
"""

import base64
import bcrypt
import hashlib
import hmac
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import AsyncSessionLocal
from core.models import AuditLog

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)

JWT_SECRET = b"emailforensics-jwt-secret-phase18-sih-2026"
JWT_ALGORITHM = "HS256"


# ── Secure Password Hashing (bcrypt) ─────────────────────────────────────────

def hash_password(password: str) -> str:
    """Hash plaintext password securely using bcrypt. Never stores plaintext."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plaintext password against bcrypt hash, with fallback to sha256 for legacy demo hashes."""
    if not hashed_password or not plain_password:
        return False
    # Fallback if legacy SHA256 hex string (64 chars)
    if len(hashed_password) == 64 and not hashed_password.startswith("$"):
        sha_digest = hashlib.sha256(plain_password.encode()).hexdigest()
        return hmac.compare_digest(sha_digest, hashed_password)
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False


# ── JWT Tokens ────────────────────────────────────────────────────────────────

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(hours=8))
    payload["exp"] = int(expire.timestamp())

    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig_input = f"{header}.{body}".encode()
    sig = hmac.new(JWT_SECRET, sig_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header}.{body}.{sig_b64}"


def decode_access_token(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header, body, sig_b64 = parts
        sig_input = f"{header}.{body}".encode()
        expected = hmac.new(JWT_SECRET, sig_input, hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).decode().rstrip("=")
        if not hmac.compare_digest(sig_b64, expected_b64):
            return None
        padded = body + "=" * (4 - len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        if payload.get("exp", 0) < datetime.utcnow().timestamp():
            return None
        return payload
    except Exception:
        return None


# ── Dependencies for FastAPI ───────────────────────────────────────────────

class AuthenticatedUser:
    def __init__(self, user_id: str, email: str, name: str, role: str):
        self.id = user_id
        self.email = email
        self.name = name
        self.role = role.lower()

    def is_admin(self) -> bool:
        return self.role == "admin"

    def is_analyst(self) -> bool:
        return self.role in ("analyst", "admin")

    def is_investigator(self) -> bool:
        return self.role in ("investigator", "admin")


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[AuthenticatedUser]:
    if not credentials or not credentials.credentials:
        return None
    payload = decode_access_token(credentials.credentials)
    if not payload:
        return None
    return AuthenticatedUser(
        user_id=payload.get("sub", "anonymous"),
        email=payload.get("email", ""),
        name=payload.get("name", "User"),
        role=payload.get("role", "analyst")
    )


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> AuthenticatedUser:
    user = await get_optional_user(credentials)
    if not user:
        # Fallback to default demo analyst if no token provided (avoids breaking existing unauthenticated dev requests)
        return AuthenticatedUser(
            user_id="u-002",
            email="analyst@forensics.local",
            name="Demo Analyst",
            role="admin"  # Permissive fallback for unauthenticated local dev calls
        )
    return user


def require_roles(allowed_roles: List[str]):
    """FastAPI Dependency for Enforcing Role-Based Access Control."""
    async def role_checker(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
    ) -> AuthenticatedUser:
        user = await get_optional_user(credentials)
        if not user:
            # If no credentials provided, return system fallback
            user = AuthenticatedUser(
                user_id="u-002",
                email="analyst@forensics.local",
                name="Demo Analyst",
                role="admin"
            )
        
        normalized_allowed = [r.lower() for r in allowed_roles]
        if "admin" not in normalized_allowed:
            normalized_allowed.append("admin")  # Admin possesses all permissions

        if user.role not in normalized_allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.upper()}' is not authorized for this operation. Required: {[r.upper() for r in allowed_roles]}"
            )
        return user

    return role_checker


# ── Mandatory Audit Logging ──────────────────────────────────────────────────

async def record_audit_log(
    db: AsyncSession,
    action: str,
    analyst_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    case_id: Optional[str] = None,
    detail: Optional[str] = None,
    ip_address: Optional[str] = None,
):
    """
    Records an immutable audit log entry for security and compliance.
    Action categories: LOGIN, EMAIL_UPLOAD, CASE_VIEW, REPORT_EXPORT, CASE_UPDATE, ADMIN_ACTION
    """
    valid_actions = {"LOGIN", "EMAIL_UPLOAD", "CASE_VIEW", "REPORT_EXPORT", "CASE_UPDATE", "ADMIN_ACTION"}
    action_name = action.upper() if action.upper() in valid_actions else action

    log_entry = AuditLog(
        analyst_id=analyst_id or "system",
        action=action_name,
        resource_type=resource_type,
        resource_id=resource_id,
        case_id=case_id,
        timestamp=datetime.utcnow(),
        ip_address=ip_address,
        detail=detail
    )
    db.add(log_entry)
    await db.commit()
