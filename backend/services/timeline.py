"""
Phase 22 — Interactive Investigation Timeline Service.

Constructs a precise chronological timeline of forensic discovery events:
1. Email Received
2. Header Hop (Origin Received Header)
3. Relay (Intermediate MTA Relays)
4. Origin Infrastructure (Public IP, Country, ISP, ASN)
5. Authentication Analysis (SPF, DKIM, DMARC)
6. IOC Extraction (URLs, Domains, Attachments)
7. GeoIP Lookup (Coordinates & ISP Details)
8. Threat Intelligence (AbuseIPDB Reputation)
9. ML Analysis (NLP Intent & Transformer Classification)
10. Final Risk Assessment (Ensemble Score & Threat Category)
11. Report Generated (Forensic Report Artifact)
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from core.models import Email, TraceHop, IOC, AuthenticationResult, AnalysisResult

logger = logging.getLogger(__name__)


def _iso_format(dt: Optional[datetime]) -> str:
    if not dt:
        return datetime.now(timezone.utc).isoformat()
    return dt.isoformat()


async def build_email_timeline(email_id: str, db) -> Dict[str, Any]:
    """
    Queries PostgreSQL for an email record and its associated hops, IOCs,
    auth, and analysis results, constructing an interactive 11-step timeline.
    """
    stmt = (
        select(Email)
        .where(Email.id == email_id)
        .options(
            selectinload(Email.trace_hops),
            selectinload(Email.iocs),
            selectinload(Email.auth_results),
            selectinload(Email.analysis_results),
        )
    )
    res = await db.execute(stmt)
    email = res.scalar_one_or_none()

    if not email:
        return {"email_id": email_id, "total_events": 0, "events": []}

    events = []
    step_num = 1
    base_time = email.date_sent or email.analyzed_at or datetime.now(timezone.utc)

    # 1. Email Received
    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "EMAIL_RECEIVED",
        "title": "Email Evidence Ingested",
        "timestamp": _iso_format(email.date_sent or base_time),
        "source": "MTA Envelope / EML Ingestion",
        "status": "COMPLETED",
        "summary": f"Ingested message '{email.subject or 'No Subject'}' from {email.from_address or 'Unknown'}",
        "relevant_evidence": {
            "sha256_hash": email.sha256_hash,
            "from_address": email.from_address,
            "from_display_name": email.from_display_name,
            "reply_to": email.reply_to,
            "subject": email.subject,
            "message_id": email.message_id,
            "date_sent": _iso_format(email.date_sent),
        }
    })
    step_num += 1

    # Sort trace hops
    hops = sorted(email.trace_hops, key=lambda h: h.hop_index)

    # 2. Header Hop (Earliest Hop)
    earliest_hop = hops[0] if hops else None
    if earliest_hop:
        events.append({
            "id": f"evt-{step_num:02d}",
            "step_number": step_num,
            "event_type": "HEADER_HOP",
            "title": "Earliest Received Header Hop Identified",
            "timestamp": _iso_format(earliest_hop.timestamp or base_time),
            "source": "Received Header #1 (Earliest)",
            "status": "COMPLETED",
            "summary": f"Parsed hop from host '{earliest_hop.from_host or 'Unknown'}' by '{earliest_hop.by_host or 'Unknown'}'",
            "relevant_evidence": {
                "hop_index": earliest_hop.hop_index,
                "from_host": earliest_hop.from_host,
                "by_host": earliest_hop.by_host,
                "ip_address": earliest_hop.ip_address,
                "timestamp": _iso_format(earliest_hop.timestamp),
            }
        })
        step_num += 1

    # 3. Relay (Intermediate Relays)
    relay_hops = hops[1:] if len(hops) > 1 else []
    if relay_hops:
        relay_chain = [
            {"hop": h.hop_index, "from": h.from_host, "by": h.by_host, "ip": h.ip_address}
            for h in relay_hops
        ]
        events.append({
            "id": f"evt-{step_num:02d}",
            "step_number": step_num,
            "event_type": "RELAY",
            "title": "MTA Relay Chain Traversal",
            "timestamp": _iso_format(relay_hops[0].timestamp or base_time),
            "source": "Intermediate Received Headers",
            "status": "COMPLETED",
            "summary": f"Traversed {len(relay_hops)} intermediate MTA relay hop(s)",
            "relevant_evidence": {
                "total_relays": len(relay_hops),
                "relay_chain": relay_chain,
            }
        })
        step_num += 1

    # 4. Origin Infrastructure
    public_hops = [h for h in hops if h.ip_address and not h.is_private]
    origin_hop = public_hops[0] if public_hops else earliest_hop

    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "ORIGIN_INFRASTRUCTURE",
        "title": "Originating Network Infrastructure Resolved",
        "timestamp": _iso_format(base_time),
        "source": "BGP / Public IP Resolution Engine",
        "status": "COMPLETED" if origin_hop else "WARNING",
        "summary": f"Origin IP: {origin_hop.ip_address if origin_hop else 'Unavailable'} ({origin_hop.country if origin_hop else 'Unknown'})",
        "relevant_evidence": {
            "origin_ip": origin_hop.ip_address if origin_hop else "N/A",
            "country": origin_hop.country if origin_hop else "N/A",
            "city": origin_hop.city if origin_hop else "N/A",
            "isp": origin_hop.isp if origin_hop else "N/A",
            "asn": origin_hop.asn if origin_hop else "N/A",
            "is_hosting": origin_hop.is_hosting if origin_hop else False,
            "is_vpn_tor": origin_hop.is_vpn_tor if origin_hop else False,
        }
    })
    step_num += 1

    # 5. Authentication Analysis
    auth_summary = {
        "spf": email.spf_result or "UNKNOWN",
        "dkim": email.dkim_result or "UNKNOWN",
        "dmarc": email.dmarc_result or "UNKNOWN",
    }
    auth_failed = any(v in ("FAIL", "SOFTFAIL") for v in auth_summary.values())

    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "AUTHENTICATION_ANALYSIS",
        "title": "Email Authentication Verification (SPF / DKIM / DMARC)",
        "timestamp": _iso_format(base_time),
        "source": "DNS & Cryptographic Verification Engine",
        "status": "WARNING" if auth_failed else "COMPLETED",
        "summary": f"SPF: {auth_summary['spf']} | DKIM: {auth_summary['dkim']} | DMARC: {auth_summary['dmarc']}",
        "relevant_evidence": auth_summary
    })
    step_num += 1

    # 6. IOC Extraction
    urls = [i.value for i in email.iocs if i.ioc_type == "url"]
    domains = [i.value for i in email.iocs if i.ioc_type == "domain"]
    ips = [i.value for i in email.iocs if i.ioc_type == "ip"]

    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "IOC_EXTRACTION",
        "title": "Indicators of Compromise (IOC) Extracted",
        "timestamp": _iso_format(base_time),
        "source": "Lexical Parser & Body Extractor",
        "status": "COMPLETED",
        "summary": f"Extracted {len(urls)} URL(s), {len(domains)} domain(s), {len(ips)} IP(s)",
        "relevant_evidence": {
            "total_iocs": len(email.iocs),
            "urls": urls[:10],
            "domains": domains[:10],
            "ips": ips[:10],
        }
    })
    step_num += 1

    # 7. GeoIP Lookup
    geo_data = {
        "ip": origin_hop.ip_address if origin_hop else None,
        "latitude": origin_hop.lat if origin_hop else None,
        "longitude": origin_hop.lon if origin_hop else None,
        "city": origin_hop.city if origin_hop else None,
        "country": origin_hop.country if origin_hop else None,
        "country_code": origin_hop.country_code if origin_hop else None,
    }
    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "GEOIP_LOOKUP",
        "title": "GeoIP Physical Location Mapping",
        "timestamp": _iso_format(base_time),
        "source": "MaxMind GeoIP2 Database",
        "status": "COMPLETED" if geo_data["ip"] else "INFO",
        "summary": f"Mapped origin to {geo_data['city'] or 'Unknown City'}, {geo_data['country'] or 'Unknown Country'}",
        "relevant_evidence": geo_data
    })
    step_num += 1

    # 8. Threat Intelligence
    threat_flags = origin_hop.threat_flags if origin_hop and origin_hop.threat_flags else {}
    threat_status = threat_flags.get("status", "completed")

    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "THREAT_INTELLIGENCE",
        "title": "Threat Intelligence Reputation Query",
        "timestamp": _iso_format(base_time),
        "source": "AbuseIPDB API & Threat Feeds",
        "status": "WARNING" if threat_flags.get("reputation") == "malicious" else "COMPLETED",
        "summary": f"Reputation: {threat_flags.get('reputation', 'Clean')} (Abuse score: {threat_flags.get('abuse_score', 0)}%)",
        "relevant_evidence": {
            "reputation": threat_flags.get("reputation", "clean"),
            "abuse_confidence_score": threat_flags.get("abuse_score", 0),
            "total_reports": threat_flags.get("total_reports", 0),
            "last_reported": threat_flags.get("last_reported"),
        }
    })
    step_num += 1

    # 9. ML Analysis
    analysis = email.analysis_results[0] if email.analysis_results else None
    ml_details = analysis.result_data.get("ai_analysis", {}) if analysis and isinstance(analysis.result_data, dict) else {}

    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "ML_ANALYSIS",
        "title": "AI/NLP Threat Feature Classification",
        "timestamp": _iso_format(base_time),
        "source": "Transformer NLP Pipeline & XGBoost Engine",
        "status": "COMPLETED",
        "summary": f"ML Score: {ml_details.get('ml_score', 'N/A')} | Primary Category: {email.classification or 'LEGITIMATE'}",
        "relevant_evidence": {
            "ml_score": ml_details.get("ml_score"),
            "model_version": ml_details.get("model_version", "v1.0.0-defensive"),
            "urgency_score": ml_details.get("urgency_score", 0),
            "phishing_intent_score": ml_details.get("phishing_intent_score", 0),
            "credential_harvest_score": ml_details.get("credential_harvest_score", 0),
        }
    })
    step_num += 1

    # 10. Final Risk Assessment
    fraud_pct = round((email.fraud_score or 0) * 100) if email.fraud_score <= 1.0 else round(email.fraud_score or 0)

    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "FINAL_RISK_ASSESSMENT",
        "title": "Ensemble Fraud Risk Assessment Calculated",
        "timestamp": _iso_format(email.analyzed_at or base_time),
        "source": "ForensicAI Risk Engine",
        "status": "WARNING" if fraud_pct >= 50 else "COMPLETED",
        "summary": f"Final Risk Score: {fraud_pct}/100 | Category: {email.classification or 'LEGITIMATE'}",
        "relevant_evidence": {
            "final_risk_score": fraud_pct,
            "classification": email.classification or "LEGITIMATE",
            "confidence": "HIGH" if auth_summary["dmarc"] != "UNKNOWN" else "MEDIUM",
        }
    })
    step_num += 1

    # 11. Report Generated
    events.append({
        "id": f"evt-{step_num:02d}",
        "step_number": step_num,
        "event_type": "REPORT_GENERATED",
        "title": "Forensic Case Report Artifact Generated",
        "timestamp": _iso_format(email.analyzed_at or base_time),
        "source": "ReportLab PDF & JSON Generator",
        "status": "COMPLETED",
        "summary": f"Generated forensic report artifact for case ID {email.case_id or 'Standalone'}",
        "relevant_evidence": {
            "case_id": email.case_id,
            "sha256_hash": email.sha256_hash,
            "pdf_report_url": f"/api/v1/cases/{email.case_id}/report/pdf" if email.case_id else None,
            "json_report_url": f"/api/v1/emails/{email.id}/report",
        }
    })

    return {
        "email_id": email.id,
        "case_id": email.case_id,
        "subject": email.subject,
        "total_events": len(events),
        "events": events
    }
