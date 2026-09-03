"""
Case management CRUD routes.
"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, cast, String
from core.database import get_db
from core.models import Case, Email, TraceHop, AuditLog
from api.schemas import CaseCreate, CaseResponse

# Import pipelines for report generation
import os
from services.email_ingestor import ingest_email, parse_eml
from services.header_forensics import analyze_header_forensics
from services.email_auth import analyze_authentication
from services.ioc_analysis import extract_all_iocs
from services.geoip import get_geolocation
from services.threat_intel import get_threat_intel
from services.risk_engine import calculate_risk_score

from services.ai_classifier import run_ai_classification
from services.pdf_generator import generate_forensic_pdf
from fastapi.responses import Response

router = APIRouter()


@router.post("/cases", response_model=CaseResponse, summary="Create a new investigation case")
async def create_case(payload: CaseCreate, db: AsyncSession = Depends(get_db)):
    case = Case(
        id=str(uuid.uuid4()),
        title=payload.title,
        analyst_id=payload.analyst_id,
        status="open",
        created_at=datetime.utcnow(),
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "created_at": case.created_at.isoformat(),
        "analyst_id": case.analyst_id,
        "email_count": 0,
    }


from typing import Optional

@router.get("/cases", summary="List all cases")
async def list_cases(
    q: Optional[str] = None,
    sender: Optional[str] = None,
    domain: Optional[str] = None,
    ip: Optional[str] = None,
    date: Optional[str] = None,
    classification: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Case)
    
    if any([sender, domain, ip, classification]):
        stmt = stmt.outerjoin(Email, Email.case_id == Case.id)
    
    if ip:
        stmt = stmt.outerjoin(TraceHop, TraceHop.email_id == Email.id)
        stmt = stmt.where(TraceHop.ip_address.ilike(f"%{ip}%"))
        
    if q:
        stmt = stmt.where(or_(Case.id.ilike(f"%{q}%"), Case.title.ilike(f"%{q}%")))
        
    if sender:
        stmt = stmt.where(Email.from_address.ilike(f"%{sender}%"))
        
    if domain:
        stmt = stmt.where(Email.from_address.ilike(f"%@{domain}%"))
        
    if date:
        stmt = stmt.where(cast(Case.created_at, String).like(f"{date}%"))
        
    if classification:
        stmt = stmt.where(Email.classification == classification)
        
    stmt = stmt.order_by(Case.created_at.desc()).distinct()
    
    result = await db.execute(stmt)
    cases = result.scalars().all()
    out = []
    for c in cases:
        emails_result = await db.execute(
            select(func.count()).select_from(Email).where(Email.case_id == c.id)
        )
        count = emails_result.scalar() or 0
        out.append({
            "id": c.id,
            "title": c.title,
            "status": c.status,
            "created_at": c.created_at.isoformat(),
            "analyst_id": c.analyst_id,
            "email_count": count,
        })
    return out


@router.get("/cases/{case_id}", summary="Get a single case with its emails")
async def get_case(case_id: str, analyst_id: str | None = None, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")

    emails_result = await db.execute(
        select(Email).where(Email.case_id == case_id).order_by(Email.analyzed_at.desc())
    )
    emails = emails_result.scalars().all()
    
    db.add(AuditLog(
        analyst_id=analyst_id,
        action="CASE_VIEW",
        resource_type="case",
        resource_id=case_id,
        case_id=case_id,
    ))
    await db.commit()

    return {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "created_at": case.created_at.isoformat(),
        "emails": [
            {
                "id": e.id,
                "subject": e.subject,
                "from_address": e.from_address,
                "fraud_score": round((e.fraud_score or 0) * 100),
                "classification": e.classification,
                "analyzed_at": e.analyzed_at.isoformat() if e.analyzed_at else None,
            }
            for e in emails
        ],
    }


@router.patch("/cases/{case_id}/status", summary="Update case status")
async def update_case_status(case_id: str, status: str, db: AsyncSession = Depends(get_db)):
    valid = {"open", "closed", "escalated"}
    if status not in valid:
        raise HTTPException(400, f"Status must be one of {valid}")
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    case.status = status
    db.add(AuditLog(
        action="CASE_UPDATE",
        resource_type="case",
        resource_id=case_id,
        case_id=case_id,
        detail=f"Updated status to {status}"
    ))
    await db.commit()
    return {"id": case_id, "status": status}


@router.delete("/cases/{case_id}", summary="Delete a case")
async def delete_case(case_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    await db.delete(case)
    await db.commit()
    return {"deleted": case_id}


@router.post("/cases/{case_id}/emails/{email_id}", summary="Link an email to a case")
async def link_email_to_case(case_id: str, email_id: str, db: AsyncSession = Depends(get_db)):
    case_result = await db.execute(select(Case).where(Case.id == case_id))
    case = case_result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    email_result = await db.execute(select(Email).where(Email.id == email_id))
    email = email_result.scalar_one_or_none()
    if not email:
        raise HTTPException(404, "Email not found")
    email.case_id = case_id
    await db.commit()
    return {"case_id": case_id, "email_id": email_id, "linked": True}


@router.get("/cases/{case_id}/report", summary="Generate a comprehensive forensic report JSON")
async def generate_case_report(case_id: str, db: AsyncSession = Depends(get_db)):
    """Phase 8 — Complete forensic report generation."""
    case_result = await db.execute(select(Case).where(Case.id == case_id))
    case = case_result.scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")

    email_result = await db.execute(
        select(Email).where(Email.case_id == case_id).order_by(Email.analyzed_at.desc())
    )
    email = email_result.scalars().first()
    if not email or not email.raw_storage_path:
        raise HTTPException(404, "No email evidence found for this case")
        
    if not os.path.exists(email.raw_storage_path):
        raise HTTPException(500, "Evidence file missing from disk")
        
    with open(email.raw_storage_path, "rb") as f:
        raw_bytes = f.read()
        
    # Re-run pipeline deterministically
    parsed = parse_eml(raw_bytes)
    forensics = analyze_header_forensics(parsed)
    earliest_ip = forensics.get("earliest_observed_public_sender_ip")
    
    authentication = analyze_authentication(raw_bytes, parsed, earliest_ip)
    iocs = extract_all_iocs(parsed, email_id=email.id)
    
    geo_info = get_geolocation(earliest_ip)
    threat_info = get_threat_intel(earliest_ip)
    
    rule_risk = calculate_risk_score(
        parsed=parsed,
        auth_result=authentication,
        forensics=forensics,
        iocs=iocs,
        threat_intel=threat_info,
    )

    ai_risk = run_ai_classification(
        parsed=parsed,
        auth_result=authentication,
        forensics=forensics,
        iocs=iocs,
        threat_intel=threat_info,
        rule_based_result=rule_risk
    )
    
    # Augment received_chain with geolocation for Phase 10
    for hop in forensics.get("received_chain", []):
        ip = hop.get("source_ip")
        if ip:
            g = get_geolocation(ip)
            if g.get("status") == "success":
                hop["geolocation"] = g
    
    return {
        "case_id": case_id,
        "analysis_timestamp": datetime.utcnow().isoformat(),
        "evidence": {
            "email_id": email.id,
            "sha256": email.sha256_hash,
            "filename": os.path.basename(email.raw_storage_path),
            "size_bytes": len(raw_bytes),
        },
        "email": {
            "from": parsed.get("from_address"),
            "to": parsed.get("to"),
            "subject": parsed.get("subject"),
            "reply_to": parsed.get("reply_to"),
            "date": parsed.get("date"),
            "message_id": parsed.get("message_id"),
        },
        "authentication": authentication,
        "header_analysis": {
            "earliest_observed_public_ip": earliest_ip,
            "anomalies": forensics.get("anomalies", []),
            "summary": forensics.get("summary", ""),
        },
        "origin_trace": forensics.get("received_chain", []),
        "geolocation": [geo_info] if geo_info.get("status") == "success" else [],
        "threat_intelligence": [threat_info] if threat_info.get("status") == "success" else [],
        "iocs": iocs.get("urls", []) + iocs.get("domains", []) + iocs.get("ips", []) + iocs.get("email_addresses", []) + iocs.get("attachments", []),
        "risk_assessment": ai_risk,
        "limitations": [
            "This report is generated dynamically and may change if threat intelligence feeds update.",
            "Authentication results rely on SMTP envelope headers, which may be incomplete in .eml files.",
            "Attribution to a specific person or organization cannot be made definitively from an IP address alone.",
            rule_risk.get("note", "")
        ]
    }


@router.get("/cases/{case_id}/report/pdf", summary="Generate a professional PDF forensic report for a case")
async def generate_case_report_pdf(case_id: str, analyst_id: str | None = None, db: AsyncSession = Depends(get_db)):
    """Phase 17 — Professional forensic PDF report generation."""
    report_dict = await generate_case_report(case_id, db)
    pdf_bytes = generate_forensic_pdf(report_dict)

    db.add(AuditLog(
        analyst_id=analyst_id,
        action="REPORT_EXPORT",
        resource_type="case",
        resource_id=case_id,
        case_id=case_id,
    ))
    await db.commit()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="forensic_report_case_{case_id[:8]}.pdf"'},
    )

