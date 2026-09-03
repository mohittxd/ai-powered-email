"""
IOC Database routes — list, search, and aggregate statistics.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from core.database import get_db
from core.models import IOC

router = APIRouter()


@router.get("/iocs", summary="List all IOCs with optional filter")
async def list_iocs(
    ioc_type: str | None = None,
    risk_level: str | None = None,
    skip: int = 0,
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(IOC)
    if ioc_type:
        stmt = stmt.where(IOC.ioc_type == ioc_type)
    if risk_level:
        stmt = stmt.where(IOC.risk_level == risk_level)
    stmt = stmt.order_by(IOC.id.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    iocs = result.scalars().all()
    return [
        {
            "id": i.id,
            "email_id": i.email_id,
            "type": i.ioc_type,
            "value": i.value,
            "risk_level": i.risk_level,
            "context": i.context,
        }
        for i in iocs
    ]


@router.get("/iocs/stats", summary="Aggregate IOC statistics")
async def ioc_stats(db: AsyncSession = Depends(get_db)):
    # Total count
    total_result = await db.execute(select(func.count()).select_from(IOC))
    total = total_result.scalar() or 0

    # By type
    type_result = await db.execute(
        select(IOC.ioc_type, func.count().label("cnt"))
        .group_by(IOC.ioc_type)
        .order_by(func.count().desc())
    )
    by_type = [{"type": row.ioc_type, "count": row.cnt} for row in type_result]

    # By risk
    risk_result = await db.execute(
        select(IOC.risk_level, func.count().label("cnt"))
        .group_by(IOC.risk_level)
        .order_by(func.count().desc())
    )
    by_risk = [{"risk": row.risk_level, "count": row.cnt} for row in risk_result]

    # Critical count
    crit_result = await db.execute(
        select(func.count()).select_from(IOC).where(IOC.risk_level == "critical")
    )
    critical = crit_result.scalar() or 0

    return {
        "total": total,
        "critical": critical,
        "by_type": by_type,
        "by_risk": by_risk,
    }


@router.get("/iocs/search", summary="Search IOCs by value")
async def search_iocs(
    q: str = Query(..., min_length=2),
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(IOC)
        .where(IOC.value.contains(q))
        .order_by(IOC.id.desc())
        .limit(limit)
    )
    iocs = result.scalars().all()
    return [
        {
            "id": i.id,
            "email_id": i.email_id,
            "type": i.ioc_type,
            "value": i.value,
            "risk_level": i.risk_level,
            "context": i.context,
        }
        for i in iocs
    ]
