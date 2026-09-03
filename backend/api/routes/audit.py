"""
Audit Log routes — immutable chain-of-custody action log.
Protected by ADMIN role permissions; logs ADMIN_ACTION.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from core.database import get_db
from core.models import AuditLog
from core.rbac import require_roles, record_audit_log, AuthenticatedUser

router = APIRouter()


@router.get("/audit", summary="List audit log entries (ADMIN only)")
async def list_audit(
    skip: int = 0,
    limit: int = 100,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    logs = result.scalars().all()

    client_ip = request.client.host if request and request.client else "127.0.0.1"
    await record_audit_log(
        db=db,
        action="ADMIN_ACTION",
        analyst_id=current_user.id,
        resource_type="audit",
        ip_address=client_ip,
        detail=f"Retrieved audit log entries (limit={limit}, skip={skip})"
    )

    return [
        {
            "id": str(l.id),
            "analyst_id": l.analyst_id,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "ip_address": l.ip_address,
            "detail": l.detail,
        }
        for l in logs
    ]


@router.get("/audit/stats", summary="Audit log statistics (ADMIN only)")
async def audit_stats(
    db: AsyncSession = Depends(get_db),
    current_user: AuthenticatedUser = Depends(require_roles(["ADMIN"]))
):
    total_result = await db.execute(select(func.count()).select_from(AuditLog))
    total = total_result.scalar() or 0

    action_result = await db.execute(
        select(AuditLog.action, func.count().label("cnt"))
        .group_by(AuditLog.action)
        .order_by(func.count().desc())
    )
    by_action = [{"action": row.action, "count": row.cnt} for row in action_result]

    return {"total": total, "by_action": by_action}
