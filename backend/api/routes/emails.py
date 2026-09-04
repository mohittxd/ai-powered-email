"""
Phase 2–4 — POST /api/v1/analyze-email
Ingestion, parsing, header forensics, and authentication analysis.
"""
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.models import AuditLog, Email, IOC, TraceHop, AuthenticationResult, AnalysisResult
from services.email_ingestor import ingest_email, validate_eml_upload
from services.header_forensics import analyze_header_forensics
from services.email_auth import analyze_authentication
from services.ioc_analysis import extract_all_iocs, LOW, MEDIUM, HIGH, CRITICAL
from services.geoip import get_geolocation
from services.threat_intel import get_threat_intel
from services.risk_engine import calculate_risk_score
from services.ai_classifier import run_ai_classification
from services.timeline import build_email_timeline

router = APIRouter()
logger = logging.getLogger(__name__)


MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # Phase 2: hard 10 MB cap


@router.post(
    "/analyze-email",
    summary="Ingest and parse email evidence",
)
async def analyze_email(
  file: UploadFile = File(..., description="Raw email evidence file"),
    case_id: str | None = Form(default=None),
    analyst_id: str | None = Form(default=None),
    db: AsyncSession = Depends(get_db),
):
    # ── 1. Read ───────────────────────────────────────────────────────────────
    raw_bytes = await file.read()

    # ── 2. Validate ───────────────────────────────────────────────────────────
    try:
        validate_eml_upload(
            filename=file.filename or "",
            content_type=file.content_type or "",
            data=raw_bytes,
            max_size_bytes=MAX_UPLOAD_BYTES,
        )
    except ValueError as exc:
        logger.warning("Rejected upload: %s (analyst=%s)", exc, analyst_id)
        raise HTTPException(status_code=400, detail=str(exc))

    # ── 3. Ingest (hash → parse → extract → store) ────────────────────────────
    try:
        result = ingest_email(
            raw_bytes=raw_bytes,
            original_filename=file.filename or "upload.eml",
            upload_dir=settings.upload_dir,
        )
    except Exception as exc:
        logger.exception("Ingestion pipeline failed")
        raise HTTPException(status_code=500, detail=f"Ingestion error: {exc}")

    email_id = result["email_id"]
    parsed   = result["parsed"]
    iocs     = result["iocs"]

    # ── 3b. Phase 3 — header forensics ───────────────────────────────────────
    forensics = analyze_header_forensics(parsed)
    earliest_ip = forensics.get("earliest_observed_public_sender_ip")

    # ── 3c. Phase 4 — authentication (SPF / DKIM / DMARC) ────────────────────
    authentication = analyze_authentication(
        raw_bytes=raw_bytes,
        parsed=parsed,
        earliest_public_sender_ip=earliest_ip,
    )

    # ── 3d. Phase 5 — comprehensive IOC extraction ────────────────────────────
    ioc_result = extract_all_iocs(parsed, email_id=email_id)

    # ── 3e. Phase 6 — IP Intelligence ─────────────────────────────────────────
    geo_info = get_geolocation(earliest_ip)
    threat_info = get_threat_intel(earliest_ip)
    
    # ── 3f. Phase 7 & 14 — Risk Engine & AI Classification ──────────────
    rule_risk = calculate_risk_score(
        parsed=parsed,
        auth_result=authentication,
        forensics=forensics,
        iocs=ioc_result,
        threat_intel=threat_info,
    )
    risk = run_ai_classification(
        parsed=parsed,
        auth_result=authentication,
        forensics=forensics,
        iocs=ioc_result,
        threat_intel=threat_info,
        rule_based_result=rule_risk,
    )

    # Augment received_chain with geolocation for Phase 10
    for hop in forensics.get("received_chain", []):
        ip = hop.get("source_ip")
        if ip:
            g = get_geolocation(ip)
            if g.get("status") == "success":
                hop["geolocation"] = g

    # ── 4. Persist ────────────────────────────────────────────────────────────
    db_email = Email(
        id=email_id,
        case_id=case_id,
        sha256_hash=result["sha256"],
        raw_storage_path=result["storage_path"],
        from_address=parsed.get("from_address"),
        from_display_name=parsed.get("from_display_name"),
        reply_to=parsed.get("reply_to"),
        return_path=parsed.get("return_path"),
        message_id=parsed.get("message_id"),
        subject=parsed.get("subject"),
        body_text=(parsed.get("body_text") or "")[:65535],
        body_html=(parsed.get("body_html") or "")[:65535],
        analyzed_at=datetime.utcnow(),
        spf_result=authentication["spf"]["status"],
        dkim_result=authentication["dkim"]["status"],
        dmarc_result=authentication["dmarc"]["status"],
        fraud_score=risk["risk_score"],
    )
    db.add(db_email)

    # Persist Phase 5 IOCs (with severity mapped to risk_level)
    _SEVERITY_MAP = {LOW: "low", MEDIUM: "medium", HIGH: "high", CRITICAL: "critical"}
    _TYPE_MAP = {
        "url": "url", "domain": "domain",
        "ipv4": "ip", "ipv6": "ip",
        "email_address": "email_addr", "attachment": "attachment",
    }
    all_phase5_iocs = (
        ioc_result["urls"] + ioc_result["domains"] +
        ioc_result["ips"]  + ioc_result["email_addresses"] +
        ioc_result["attachments"]
    )
    for p5ioc in all_phase5_iocs:
        db_type = _TYPE_MAP.get(p5ioc["type"], "url")
        db.add(IOC(
            email_id=email_id,
            ioc_type=db_type,
            value=p5ioc["value"][:1000],
            risk_level=_SEVERITY_MAP.get(p5ioc["severity"], "low"),
            context=";".join(p5ioc.get("tags", []))[:500],
        ))

    # Persist TraceHops
    for idx, hop in enumerate(forensics.get("received_chain", [])):
        geo = hop.get("geolocation", {})
        db.add(TraceHop(
            email_id=email_id,
            hop_index=idx,
            from_host=hop.get("source_hostname"),
            by_host=hop.get("receiving_hostname"),
            ip_address=hop.get("source_ip"),
            timestamp=None, # Cannot easily parse all formats here, skipping
            country=geo.get("country"),
            city=geo.get("city"),
            region=geo.get("region"),
            isp=geo.get("isp"),
            asn=geo.get("asn"),
            lat=geo.get("latitude"),
            lon=geo.get("longitude"),
            is_private=not bool(hop.get("source_ip"))
        ))

    # Persist Auth Results
    for proto in ["spf", "dkim", "dmarc"]:
        res = authentication.get(proto, {})
        db.add(AuthenticationResult(
            email_id=email_id,
            protocol=proto,
            status=res.get("status", "UNKNOWN"),
            reason=res.get("reason"),
        ))

    # Persist Analysis Result
    db.add(AnalysisResult(
        email_id=email_id,
        risk_score=risk.get("final_risk_score", 0),
        classification=risk.get("classification", "LEGITIMATE"),
        confidence=risk.get("confidence", "low"),
        reasons=risk.get("reasons", []),
        features=risk,
    ))

    db.add(AuditLog(
        analyst_id=analyst_id,
        action="EMAIL_UPLOAD",
        resource_type="email",
        resource_id=email_id,
        case_id=case_id,
        detail=f"sha256={result['sha256'][:16]}… size={result['size']}B",
    ))
    await db.commit()

    logger.info("Ingested id=%s sha256=%.12s size=%d", email_id, result["sha256"], result["size"])

    # ── 5. Response ───────────────────────────────────────────────────────────
    return {
        "email_id":    email_id,
        "case_id":     case_id,
        "ingested_at": result["ingested_at"],
        "evidence": {
            "filename": result["filename"],
            "sha256":   result["sha256"],
            "size":     result["size"],
        },
        "email": {
            "from":        parsed.get("from_address"),
            "from_name":   parsed.get("from_display_name"),
            "to":          parsed.get("to"),
            "cc":          parsed.get("cc"),
            "subject":     parsed.get("subject"),
            "date":        parsed.get("date"),
            "reply_to":    parsed.get("reply_to"),
            "sender":      parsed.get("sender"),
            "return_path": parsed.get("return_path"),
            "message_id":  parsed.get("message_id"),
            "mime_version":parsed.get("mime_version"),
            "content_type":parsed.get("content_type"),
            "auth_results":parsed.get("auth_results"),
        },
        "headers":        parsed.get("headers", {}),
        "received_chain": parsed.get("received_headers", []),
        "iocs": {
            "urls":    iocs.get("urls", []),
            "ips":     iocs.get("ips", []),
            "domains": iocs.get("domains", []),
        },
        "attachments":       parsed.get("attachments", []),
        "header_forensics":  forensics,
        "authentication":    authentication,
        "iocs":              ioc_result,
        "ip_intelligence": {
            "geolocation": geo_info,
            "threat_intel": threat_info,
        },
        "risk_analysis":     risk,
    }


@router.get("/emails/{email_id}/timeline", summary="Get Phase 22 Interactive Investigation Timeline")
async def get_email_timeline(email_id: str, db: AsyncSession = Depends(get_db)):
    """
    Returns an 11-step interactive investigation timeline for an ingested email.
    """
    timeline = await build_email_timeline(email_id, db)
    if not timeline.get("events"):
        raise HTTPException(status_code=404, detail=f"Email ID '{email_id}' not found or has no timeline events.")
    return timeline

