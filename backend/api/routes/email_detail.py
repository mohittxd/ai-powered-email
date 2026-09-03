"""
GET /api/v1/emails/{id} — retrieve full email analysis record from DB.
Also exposes a search endpoint across all emails.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, func
from datetime import datetime
from core.database import get_db
from core.models import Email, TraceHop, IOC, AuditLog

router = APIRouter()


@router.get("/emails", summary="Search all analyzed emails")
async def list_emails(
    q: str | None = Query(None, description="Search in subject, from_address"),
    classification: str | None = Query(None),
    min_score: int = Query(0, ge=0, le=100),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Email).order_by(Email.analyzed_at.desc()).offset(offset).limit(limit)

    if q:
        stmt = stmt.where(
            or_(
                Email.from_address.ilike(f"%{q}%"),
                Email.subject.ilike(f"%{q}%"),
                Email.from_display_name.ilike(f"%{q}%"),
            )
        )
    if classification:
        stmt = stmt.where(Email.classification == classification)
    if min_score:
        stmt = stmt.where(Email.fraud_score >= min_score / 100)

    result = await db.execute(stmt)
    emails = result.scalars().all()

    # Count total
    count_stmt = select(func.count()).select_from(Email)
    total = (await db.execute(count_stmt)).scalar() or 0

    return {
        "total": total,
        "emails": [
            {
                "id": e.id,
                "sha256_hash": e.sha256_hash,
                "from_address": e.from_address,
                "from_display_name": e.from_display_name,
                "subject": e.subject,
                "date_sent": e.date_sent.isoformat() if e.date_sent else None,
                "fraud_score": round((e.fraud_score or 0) * 100),
                "classification": e.classification,
                "spf_result": e.spf_result,
                "dkim_result": e.dkim_result,
                "dmarc_result": e.dmarc_result,
                "analyzed_at": e.analyzed_at.isoformat() if e.analyzed_at else None,
                "case_id": e.case_id,
            }
            for e in emails
        ],
    }


@router.get("/emails/{email_id}", summary="Get full email analysis detail")
async def get_email(email_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Email).where(Email.id == email_id))
    em = result.scalar_one_or_none()
    if not em:
        raise HTTPException(404, "Email not found")

    hops = (await db.execute(
        select(TraceHop).where(TraceHop.email_id == email_id).order_by(TraceHop.hop_index)
    )).scalars().all()

    iocs = (await db.execute(
        select(IOC).where(IOC.email_id == email_id)
    )).scalars().all()

    return {
        "id": em.id,
        "sha256_hash": em.sha256_hash,
        "from_address": em.from_address,
        "from_display_name": em.from_display_name,
        "reply_to": em.reply_to,
        "return_path": em.return_path,
        "message_id": em.message_id,
        "subject": em.subject,
        "date_sent": em.date_sent.isoformat() if em.date_sent else None,
        "body_text": em.body_text,
        "fraud_score": round((em.fraud_score or 0) * 100),
        "classification": em.classification,
        "spf_result": em.spf_result,
        "dkim_result": em.dkim_result,
        "dmarc_result": em.dmarc_result,
        "analyzed_at": em.analyzed_at.isoformat() if em.analyzed_at else None,
        "case_id": em.case_id,
        "received_hops": [
            {
                "hop_index": h.hop_index,
                "ip_address": h.ip_address,
                "from_host": h.from_host,
                "by_host": h.by_host,
                "country": h.country,
                "city": h.city,
                "isp": h.isp,
                "asn": h.asn,
                "is_private": h.is_private,
                "is_vpn_tor": h.is_vpn_tor,
                "is_hosting": h.is_hosting,
                "threat_flags": h.threat_flags,
                "lat": h.lat,
                "lon": h.lon,
                "timestamp": h.timestamp.isoformat() if h.timestamp else None,
            }
            for h in hops
        ],
        "iocs": [
            {
                "ioc_type": i.ioc_type,
                "value": i.value,
                "risk_level": i.risk_level,
                "context": i.context,
                "metadata": i.metadata_,
            }
            for i in iocs
        ],
    }
