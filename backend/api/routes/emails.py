"""
Phase 2–4 — POST /api/v1/analyze-email
Ingestion, parsing, header forensics, and authentication analysis.
"""
import logging
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pathlib import Path
from core.config import settings
from core.database import get_db
from core.models import AuditLog, Email, IOC, TraceHop, AuthenticationResult, AnalysisResult, Case
from core.rbac import get_current_user
from services.email_ingestor import ingest_email, validate_eml_upload, parse_eml
from services.header_forensics import analyze_header_forensics
from services.email_auth import analyze_authentication
from services.ioc_analysis import extract_all_iocs, LOW, MEDIUM, HIGH, CRITICAL
from services.geolocation import trace_origin
from services.threat_intel import get_threat_intel
from services.risk_engine import calculate_risk_score
from services.ai_classifier import run_ai_classification
from services.timeline import build_email_timeline
import bleach as _bleach

router = APIRouter()
logger = logging.getLogger(__name__)


MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # Phase 2: hard 10 MB cap


@router.post(
    "/analyze-email",
    summary="Ingest and parse email evidence",
)
async def analyze_email(
  file: UploadFile = File(default=None, description="Raw email evidence file (.eml/.msg)"),
  raw_headers: str | None = Form(default=None, description="Pasted raw email body text"),
  case_id: str | None = Form(default=None),
  user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if case_id:
        case_result = await db.execute(
            select(Case).where(Case.id == case_id, Case.analyst_id == user.id)
        )
        if not case_result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Case not found")

    # Determine input mode: file upload OR pasted body text
    is_body_mode = raw_headers is not None and not file
    if not file and not raw_headers:
        raise HTTPException(status_code=400, detail="Provide either a .eml file or pasted email body text.")

    if is_body_mode:
        # ── Body-only mode: construct minimal RFC-5322 email from pasted text ──
        # Sanitize: strip HTML/script tags, keep plain text
        clean_body = _bleach.clean(raw_headers, tags=[], strip=True)
        if len(clean_body.strip()) < 10:
            raise HTTPException(status_code=400, detail="Pasted body is too short for meaningful analysis.")

        # Build a minimal .eml envelope so the existing pipeline can process it
        minimal_eml = (
            "From: unavailable@pasted-body.local\r\n"
            "To: analyst@forensics.local\r\n"
            f"Subject: [Pasted Body] {clean_body[:60].replace(chr(10), ' ').strip()}\r\n"
            "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            "Message-ID: <pasted-body@forensics.local>\r\n"
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "Content-Transfer-Encoding: 7bit\r\n"
            "X-ForensicAI-Input-Mode: pasted-body\r\n"
            "\r\n"
            f"{clean_body}"
        )
        raw_bytes = minimal_eml.encode("utf-8")
        original_filename = "pasted-body.eml"
    else:
        # ── File upload mode (existing behavior) ────────────────────────────────
        raw_bytes = await file.read()

        try:
            validate_eml_upload(
                filename=file.filename or "",
                content_type=file.content_type or "",
                data=raw_bytes,
                max_size_bytes=MAX_UPLOAD_BYTES,
            )
        except ValueError as exc:
            logger.warning("Rejected upload for user %s: %s", user.id, exc)
            raise HTTPException(status_code=400, detail=str(exc))
        original_filename = file.filename or "upload.eml"

    # ── 3. Ingest (hash → parse → extract → store) ────────────────────────────
    try:
        result = ingest_email(
            raw_bytes=raw_bytes,
            original_filename=original_filename,
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

    # ── 3e. Phase 6 — IP Intelligence & Origin Trace ───────────────────────────
    # Build trace input from header forensics (received_chain uses source_ip)
    trace_hops_input = []
    for idx, hop in enumerate(forensics.get("received_chain", [])):
        trace_hops_input.append({
            "ip_address": hop.get("source_ip"),
            "hop_index": idx,
            "source_hostname": hop.get("source_hostname"),
            "receiving_hostname": hop.get("receiving_hostname"),
        })

    origin_trace = await trace_origin(
        parsed,
        {**authentication, "received_hops": trace_hops_input},
    )

    # Merge enriched hop info back into forensics.received_chain for persistence/response
    enriched_map = {h.get("hop_index"): h for h in origin_trace.get("hops", [])}
    for idx, hop in enumerate(forensics.get("received_chain", [])):
        enriched = enriched_map.get(idx)
        if enriched:
            hop["geolocation"] = {
                "country": enriched.get("country"),
                "city": enriched.get("city"),
                "region": enriched.get("region"),
                "isp": enriched.get("isp"),
                "asn": enriched.get("asn"),
                "lat": enriched.get("lat"),
                "lon": enriched.get("lon"),
                "is_private": enriched.get("is_private"),
                "is_vpn_tor": enriched.get("is_vpn_tor"),
                "is_hosting": enriched.get("is_hosting"),
                "threat_flags": enriched.get("threat_flags", []),
            }

    geo_info = origin_trace.get("origin_hop") or {}
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

    # # Augment received_chain with geolocation for Phase 10
    # for hop in forensics.get("received_chain", []):
    #     ip = hop.get("source_ip")
    #     if ip:
    #         g = get_geolocation(ip)
    #         if g.get("status") == "success":
    #             hop["geolocation"] = g

    # ── 4. Persist ────────────────────────────────────────────────────────────
    db_email = Email(
        id=email_id,
        owner_id=user.id,
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
            lat=geo.get("lat"),
            lon=geo.get("lon"),
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
        analyst_id=user.id,
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
        "input_mode":  "pasted_body" if is_body_mode else "file_upload",
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
        "origin_trace": origin_trace,
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

@router.post(
    "/emails/{email_id}/analyze",
    summary="Run full forensic analysis on an existing email",
)
async def analyze_existing_email(
    email_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Re-run the complete forensic analysis pipeline against an email
    already stored in the database.

    Unlike POST /analyze-email, this does not create a new Email record.
    It updates the existing record and returns the same rich analysis
    structure used by the Analyzer frontend.
    """

    # ── 1. Load existing email ───────────────────────────────────────────────
    result = await db.execute(
        select(Email).where(Email.id == email_id)
    )
    db_email = result.scalar_one_or_none()

    if not db_email:
        raise HTTPException(
            status_code=404,
            detail=f"Email ID '{email_id}' not found.",
        )

    # ── 2. Locate original evidence ─────────────────────────────────────────
    if not db_email.raw_storage_path:
        raise HTTPException(
            status_code=404,
            detail="Original email evidence is not available.",
        )

    evidence_path = Path(db_email.raw_storage_path)

    # ./uploads inside the backend container is /app/uploads.
    if not evidence_path.is_absolute():
        evidence_path = Path("/app") / evidence_path

    if not evidence_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Original evidence file not found: {evidence_path}",
        )

    try:
        raw_bytes = evidence_path.read_bytes()
    except Exception as exc:
        logger.exception("Could not read evidence for email %s", email_id)
        raise HTTPException(
            status_code=500,
            detail=f"Could not read original evidence: {exc}",
        )

    # ── 3. Re-parse original evidence ───────────────────────────────────────
    try:
        parsed = ingest_email(
            raw_bytes=raw_bytes,
            original_filename=evidence_path.name,
            upload_dir=settings.upload_dir,
        )["parsed"]
    except Exception as exc:
        logger.exception("Could not parse existing email %s", email_id)
        raise HTTPException(
            status_code=500,
            detail=f"Email parsing failed: {exc}",
        )

    # ── 4. Header forensics ─────────────────────────────────────────────────
    forensics = analyze_header_forensics(parsed)
    earliest_ip = forensics.get(
        "earliest_observed_public_sender_ip"
    )

    # ── 5. Authentication ──────────────────────────────────────────────────
    authentication = analyze_authentication(
        raw_bytes=raw_bytes,
        parsed=parsed,
        earliest_public_sender_ip=earliest_ip,
    )

    # ── 6. Comprehensive IOC extraction ─────────────────────────────────────
    ioc_result = extract_all_iocs(
        parsed,
        email_id=email_id,
    )

    # ── 7. IP intelligence ──────────────────────────────────────────────────
    # Use trace_origin to geolocate received hops and determine origin hop
    trace_hops_input = []
    for idx, hop in enumerate(forensics.get("received_chain", [])):
        trace_hops_input.append({
            "ip_address": hop.get("source_ip"),
            "hop_index": idx,
            "source_hostname": hop.get("source_hostname"),
            "receiving_hostname": hop.get("receiving_hostname"),
        })

    origin_trace = await trace_origin(
        parsed,
        {**authentication, "received_hops": trace_hops_input},
    )

    # Merge enriched hop info back into forensics.received_chain for persistence/response
    enriched_map = {h.get("hop_index"): h for h in origin_trace.get("hops", [])}
    for idx, hop in enumerate(forensics.get("received_chain", [])):
        enriched = enriched_map.get(idx)
        if enriched:
            hop["geolocation"] = {
                "country": enriched.get("country"),
                "city": enriched.get("city"),
                "region": enriched.get("region"),
                "isp": enriched.get("isp"),
                "asn": enriched.get("asn"),
                "lat": enriched.get("lat"),
                "lon": enriched.get("lon"),
                "is_private": enriched.get("is_private"),
                "is_vpn_tor": enriched.get("is_vpn_tor"),
                "is_hosting": enriched.get("is_hosting"),
                "threat_flags": enriched.get("threat_flags", []),
            }

    geo_info = origin_trace.get("origin_hop") or {}
    threat_info = get_threat_intel(earliest_ip)

    # ── 8. Risk engine + AI classification ──────────────────────────────────
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

    # ── 9. Received chain already enriched by trace_origin above ───────────

    # ── 10. Update existing Email record ────────────────────────────────────
    db_email.sha256_hash = db_email.sha256_hash or ""
    db_email.raw_storage_path = str(evidence_path)

    db_email.from_address = parsed.get("from_address")
    db_email.from_display_name = parsed.get("from_display_name")
    db_email.reply_to = parsed.get("reply_to")
    db_email.return_path = parsed.get("return_path")
    db_email.message_id = parsed.get("message_id")
    db_email.subject = parsed.get("subject")

    db_email.body_text = (parsed.get("body_text") or "")[:65535]
    db_email.body_html = (parsed.get("body_html") or "")[:65535]

    db_email.analyzed_at = datetime.utcnow()

    db_email.spf_result = authentication["spf"]["status"]
    db_email.dkim_result = authentication["dkim"]["status"]
    db_email.dmarc_result = authentication["dmarc"]["status"]

    db_email.fraud_score = risk.get(
        "risk_score",
        risk.get("final_risk_score", 0),
    )

    db_email.classification = (
        str(risk.get("classification", "legitimate")).lower()
    )

    # ── 11. Remove previous derived analysis ─────────────────────────────────
    from sqlalchemy import delete

    await db.execute(
        delete(IOC).where(IOC.email_id == email_id)
    )

    await db.execute(
        delete(TraceHop).where(TraceHop.email_id == email_id)
    )

    await db.execute(
        delete(AuthenticationResult).where(
            AuthenticationResult.email_id == email_id
        )
    )

    await db.execute(
        delete(AnalysisResult).where(
            AnalysisResult.email_id == email_id
        )
    )

    # ── 12. Persist Phase 5 IOCs ─────────────────────────────────────────────
    _SEVERITY_MAP = {
        LOW: "low",
        MEDIUM: "medium",
        HIGH: "high",
        CRITICAL: "critical",
    }

    _TYPE_MAP = {
        "url": "url",
        "domain": "domain",
        "ipv4": "ip",
        "ipv6": "ip",
        "email_address": "email_addr",
        "attachment": "attachment",
    }

    all_phase5_iocs = (
        ioc_result["urls"]
        + ioc_result["domains"]
        + ioc_result["ips"]
        + ioc_result["email_addresses"]
        + ioc_result["attachments"]
    )

    for p5ioc in all_phase5_iocs:
        db_type = _TYPE_MAP.get(
            p5ioc["type"],
            "url",
        )

        db.add(
            IOC(
                email_id=email_id,
                ioc_type=db_type,
                value=p5ioc["value"][:1000],
                risk_level=_SEVERITY_MAP.get(
                    p5ioc["severity"],
                    "low",
                ),
                context=";".join(
                    p5ioc.get("tags", [])
                )[:500],
            )
        )

    # ── 13. Persist trace hops ──────────────────────────────────────────────
    for idx, hop in enumerate(
        forensics.get("received_chain", [])
    ):
        geo = hop.get("geolocation", {})

        db.add(
            TraceHop(
                email_id=email_id,
                hop_index=idx,
                from_host=hop.get("source_hostname"),
                by_host=hop.get("receiving_hostname"),
                ip_address=hop.get("source_ip"),
                timestamp=None,
                country=geo.get("country"),
                city=geo.get("city"),
                region=geo.get("region"),
                isp=geo.get("isp"),
                asn=geo.get("asn"),
                lat=geo.get("lat"),
                lon=geo.get("lon"),
                is_private=not bool(
                    hop.get("source_ip")
                ),
            )
        )

    # ── 14. Persist authentication results ──────────────────────────────────
    for proto in ["spf", "dkim", "dmarc"]:
        res = authentication.get(proto, {})

        db.add(
            AuthenticationResult(
                email_id=email_id,
                protocol=proto,
                status=res.get("status", "UNKNOWN"),
                reason=res.get("reason"),
            )
        )

    # ── 15. Persist analysis result ──────────────────────────────────────────
    db.add(
        AnalysisResult(
            email_id=email_id,
            risk_score=risk.get(
                "final_risk_score",
                risk.get("risk_score", 0),
            ),
            classification=risk.get(
                "classification",
                "LEGITIMATE",
            ),
            confidence=risk.get(
                "confidence",
                "low",
            ),
            reasons=risk.get("reasons", []),
            features=risk,
        )
    )

    await db.commit()

    logger.info(
        "Re-analyzed existing email id=%s",
        email_id,
    )

    # ── 16. Return same rich structure as upload analysis ───────────────────
    return {
        "email_id": email_id,
        "case_id": db_email.case_id,
        "ingested_at": (
            db_email.analyzed_at.isoformat()
            if db_email.analyzed_at
            else None
        ),
        "evidence": {
            "filename": evidence_path.name,
            "sha256": db_email.sha256_hash,
            "size": len(raw_bytes),
        },
        "email": {
            "from": parsed.get("from_address"),
            "from_name": parsed.get("from_display_name"),
            "to": parsed.get("to"),
            "cc": parsed.get("cc"),
            "subject": parsed.get("subject"),
            "date": parsed.get("date"),
            "reply_to": parsed.get("reply_to"),
            "sender": parsed.get("sender"),
            "return_path": parsed.get("return_path"),
            "message_id": parsed.get("message_id"),
            "mime_version": parsed.get("mime_version"),
            "content_type": parsed.get("content_type"),
            "auth_results": parsed.get("auth_results"),
        },
        "headers": parsed.get("headers", {}),
        "received_chain": parsed.get(
            "received_headers",
            [],
        ),
        "attachments": parsed.get(
            "attachments",
            [],
        ),
        "header_forensics": forensics,
        "authentication": authentication,
        "iocs": ioc_result,
        "ip_intelligence": {
            "geolocation": geo_info,
            "threat_intel": threat_info,
        },
        "origin_trace": origin_trace,
        "risk_analysis": risk,
    }