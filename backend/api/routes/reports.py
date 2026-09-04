"""
Report export routes — JSON forensic report, PDF, and platform statistics.
"""
import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from core.database import get_db
from core.models import Email, TraceHop, IOC, AuditLog, Case, AnalysisResult

router = APIRouter()


async def _build_full_report(email_id: str, db: AsyncSession) -> dict:
    result = await db.execute(select(Email).where(Email.id == email_id))
    em = result.scalar_one_or_none()
    if not em:
        raise HTTPException(404, "Email not found")

    analysis_res = await db.execute(
        select(AnalysisResult).where(AnalysisResult.email_id == email_id).order_by(AnalysisResult.analyzed_at.desc())
    )
    ar = analysis_res.scalars().first()

    hops_result = await db.execute(
        select(TraceHop).where(TraceHop.email_id == email_id).order_by(TraceHop.hop_index)
    )
    hops = hops_result.scalars().all()

    iocs_result = await db.execute(select(IOC).where(IOC.email_id == email_id))
    iocs = iocs_result.scalars().all()

    final_score = round(em.fraud_score) if (em.fraud_score and em.fraud_score > 1.0) else round((em.fraud_score or 0) * 100)
    
    features_meta = (ar.features if ar and isinstance(ar.features, dict) else {})
    rule_score = features_meta.get("rule_based_score", final_score)
    ml_score = features_meta.get("ml_score", None)

    return {
        "report_metadata": {
            "generated_at": datetime.utcnow().isoformat(),
            "email_id": email_id,
            "sha256_hash": em.sha256_hash,
            "platform": "EmailForensics v3.0.0 (Phase 14 AI)",
        },
        "email": {
            "case_id": em.case_id,
            "from_address": em.from_address,
            "from_display_name": em.from_display_name,
            "subject": em.subject,
            "date_sent": em.date_sent.isoformat() if em.date_sent else None,
            "message_id": em.message_id,
        },
        "analysis": {
            "rule_based_score": rule_score,
            "ml_score": ml_score,
            "final_risk_score": final_score,
            "fraud_score": final_score,
            "classification": em.classification,
            "spf_result": em.spf_result,
            "dkim_result": em.dkim_result,
            "dmarc_result": em.dmarc_result,
            "calibration_note": "The ML score is an uncalibrated heuristic feature model output, not a statistically validated probability.",
            "analyzed_at": em.analyzed_at.isoformat() if em.analyzed_at else None,
        },
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
                "timestamp": h.timestamp.isoformat() if h.timestamp else None,
            }
            for h in hops
        ],
        "iocs": [
            {
                "type": i.ioc_type,
                "value": i.value,
                "risk_level": i.risk_level,
                "context": i.context,
            }
            for i in iocs
        ],
    }


@router.get("/emails/{email_id}/report.json", summary="Export forensic report as JSON")
async def export_json_report(email_id: str, analyst_id: str | None = None, db: AsyncSession = Depends(get_db)):
    report = await _build_full_report(email_id, db)

    # Audit
    db.add(AuditLog(
        analyst_id=analyst_id,
        action="REPORT_EXPORT",
        resource_type="email",
        resource_id=email_id,
        case_id=report["email"].get("case_id"),
    ))
    await db.commit()

    return JSONResponse(content=report, media_type="application/json")


from services.pdf_generator import generate_forensic_pdf


@router.get("/emails/{email_id}/report.pdf", summary="Export forensic report as PDF")
async def export_pdf_report(email_id: str, analyst_id: str | None = None, db: AsyncSession = Depends(get_db)):
    """Generate a professional PDF forensic report using ReportLab."""
    report = await _build_full_report(email_id, db)
    pdf_bytes = generate_forensic_pdf(report)

    db.add(AuditLog(
        analyst_id=analyst_id,
        action="REPORT_EXPORT",
        resource_type="email",
        resource_id=email_id,
        case_id=report["email"].get("case_id"),
    ))
    await db.commit()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="forensic_report_{email_id[:8]}.pdf"'},
    )



@router.get("/stats/overview", summary="Platform-wide statistics")
async def stats_overview(db: AsyncSession = Depends(get_db)):
    total_emails = (await db.execute(select(func.count()).select_from(Email))).scalar() or 0
    total_iocs = (await db.execute(select(func.count()).select_from(IOC))).scalar() or 0
    total_cases = (await db.execute(select(func.count()).select_from(Case))).scalar() or 0
    total_audits = (await db.execute(select(func.count()).select_from(AuditLog))).scalar() or 0

    critical_iocs = (
        await db.execute(
            select(func.count()).select_from(IOC).where(IOC.risk_level == "critical")
        )
    ).scalar() or 0

    # Average fraud score
    avg_result = await db.execute(select(func.avg(Email.fraud_score)))
    raw_avg_score = avg_result.scalar() or 0

    # Database may contain either 0–1 or 0–100 scores.
    avg_score = (
        raw_avg_score * 100
        if raw_avg_score <= 1
        else raw_avg_score
    )

    # Always keep the displayed score within 0–100.
    avg_score = round(max(0, min(avg_score, 100)), 1)
    # Classification distribution
    class_result = await db.execute(
        select(Email.classification, func.count().label("cnt"))
        .where(Email.classification.isnot(None))
        .group_by(Email.classification)
        .order_by(func.count().desc())
    )
    by_class = [{"classification": r.classification, "count": r.cnt} for r in class_result]

    return {
        "total_emails": total_emails,
        "total_iocs": total_iocs,
        "total_cases": total_cases,
        "total_audit_entries": total_audits,
        "critical_iocs": critical_iocs,
        "avg_fraud_score": avg_score,
        "by_classification": by_class,
    }
