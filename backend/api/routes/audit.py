"""
Audit Log routes — immutable chain-of-custody action log.
All authenticated users may view the audit log; admins may also
query statistics.  Viewing does not create a recursive audit entry.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from core.database import get_db
from core.models import AuditLog
from core.rbac import get_current_user

router = APIRouter()


@router.get("/audit", summary="List audit log entries")
async def list_audit(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    result = await db.execute(
        select(AuditLog)
        .order_by(AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    logs = result.scalars().all()

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


@router.get("/audit/stats", summary="Audit log statistics")
async def audit_stats(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
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
