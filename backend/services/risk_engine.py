"""
Phase 7 — Explainable Email Fraud-Risk Engine.
Calculates a heuristic risk score (0-100) based on forensic, authentication,
IOC, and lexical body features.

Note: This score is a heuristic risk indicator based on common threat behaviors,
not a statistically validated probability model.
"""
import re
from typing import Any

# Classification boundaries
CL_LEGITIMATE    = "LEGITIMATE"      # 0-24
CL_SUSPICIOUS    = "SUSPICIOUS"      # 25-49
CL_IMPERSONATION = "IMPERSONATION"   # 50-69
CL_PHISHING      = "PHISHING"        # 70-84
CL_CRITICAL      = "CRITICAL/BEC"    # 85-100


# Heuristic Regex Patterns
_URGENCY_RE = re.compile(
    r'\b(urgent|immediate action required|action required|overdue|suspended|terminated|'
    r'expires? in|warning|alert|act now|immediately|attention|important update)\b',
    re.IGNORECASE
)

_CREDENTIAL_RE = re.compile(
    r'\b(login|verify account|update billing|validate|confirm identity|'
    r'password reset|reset password|verify email|access account)\b',
    re.IGNORECASE
)

_FINANCIAL_RE = re.compile(
    r'\b(invoice|payment|transfer|wire funds|wire transfer|billing|'
    r'bank account|deposit|swift|routing number|ach|remittance)\b',
    re.IGNORECASE
)

_EXEC_IMPERSONATION_RE = re.compile(
    r'\b(are you available|are you at your desk|need a favor|need you to handle this|'
    r'discreet|confidential|wire me|send gift cards|i am in a meeting)\b',
    re.IGNORECASE
)


def _detect_body_features(body_text: str, body_html: str) -> list[tuple[str, int, str]]:
    """Scan body text/html for lexical indicators of BEC, phishing, urgency."""
    features = []
    combined = (body_text + " " + body_html).lower()
    if not combined.strip():
        return features

    # Urgency
    if _URGENCY_RE.search(combined):
        features.append(("Urgency indicators detected", 5, "urgency_indicators"))
    
    # Credential request
    if _CREDENTIAL_RE.search(combined):
        features.append(("Credential-request indicators detected", 10, "credential_request"))
    
    # Financial / Invoice
    if _FINANCIAL_RE.search(combined):
        features.append(("Payment/invoice indicators detected", 8, "financial_indicators"))
    
    # Executive Impersonation
    if _EXEC_IMPERSONATION_RE.search(combined):
        features.append(("Executive impersonation indicators detected", 10, "exec_impersonation"))
        
    return features


def calculate_risk_score(
    parsed: dict,
    auth_result: dict,
    forensics: dict,
    iocs: dict,
    threat_intel: dict,
) -> dict:
    """
    Calculate risk score from available data context.
    Max score is 100.
    """
    score = 0
    reasons = []
    features = []

    def _add(points: int, description: str, feature_id: str):
        nonlocal score
        score += points
        reasons.append(description)
        features.append(feature_id)

    # 1. Authentication (SPF, DKIM, DMARC)
    # Only penalize explicit FAIL or SOFTFAIL. Do not penalize UNAVAILABLE or NONE.
    spf_status = auth_result.get("spf", {}).get("status")
    if spf_status in ("FAIL", "SOFTFAIL"):
        _add(15, f"SPF evaluation failed ({spf_status})", "spf_failure")

    dkim_status = auth_result.get("dkim", {}).get("status")
    if dkim_status == "FAIL":
        _add(15, "DKIM cryptographic verification failed", "dkim_failure")

    dmarc_status = auth_result.get("dmarc", {}).get("status")
    if dmarc_status == "FAIL":
        _add(15, "DMARC alignment failed", "dmarc_failure")

    # 2. Header Forensics (Anomalies)
    anomalies = forensics.get("anomalies", [])
    anomaly_types = {a.get("type") for a in anomalies}
    
    if "reply_to_mismatch" in anomaly_types:
        _add(10, "Reply-To mismatch detected", "reply_to_mismatch")
        
    if "from_sender_mismatch" in anomaly_types or "return_path_mismatch" in anomaly_types:
        _add(8, "From/Sender/Return-Path inconsistency", "sender_inconsistency")
        
    if "malformed_received_header" in anomaly_types or "no_public_ip_in_chain" in anomaly_types or "no_received_headers" in anomaly_types:
        _add(10, "Suspicious or malformed Received chain", "suspicious_received_chain")
        
    if "timestamp_regression" in anomaly_types or "timestamp_gap" in anomaly_types:
        _add(5, "Timestamp anomaly in Received chain", "timestamp_anomaly")

    # 3. IOCs (URLs and Attachments)
    urls = iocs.get("urls", [])
    attachments = iocs.get("attachments", [])
    
    has_high_url = False
    has_shortener = False
    for u in urls:
        if isinstance(u, dict):
            severity = u.get("severity")
            tags = u.get("tags", [])
        else:
            severity = "high" if "http://" in str(u).lower() else "low"
            tags = ["url_shortener"] if any(s in str(u).lower() for s in ["bit.ly", "tinyurl", "t.co"]) else []

        if severity in ("high", "critical"):
            has_high_url = True
        if "url_shortener" in tags:
            has_shortener = True
            
    if has_high_url:
        _add(10, "Suspicious URL detected", "suspicious_url")
    if has_shortener:
        _add(5, "URL shortener detected", "url_shortener")
        
    has_high_attachment = False
    for a in attachments:
        if isinstance(a, dict):
            if a.get("severity") in ("high", "critical"):
                has_high_attachment = True
        elif isinstance(a, str):
            if any(ext in a.lower() for ext in [".exe", ".scr", ".iso", ".vbs", ".js", ".bat", ".docm", ".xlsm"]):
                has_high_attachment = True

    if has_high_attachment:
        _add(10, "Suspicious attachment detected", "suspicious_attachment")

    # 4. Lexical Content Features (Body)
    body_text = parsed.get("body_text", "")
    body_html = parsed.get("body_html", "")
    lexical_features = _detect_body_features(body_text, body_html)
    for desc, pts, f_id in lexical_features:
        _add(pts, desc, f_id)

    # 5. Threat Intel (AbuseIPDB)
    if threat_intel.get("status") == "success" and threat_intel.get("reputation") == "malicious":
        _add(20, "Sender IP flagged as malicious by threat intelligence", "malicious_ip")

    # Cap score at 100
    capped_score = min(score, 100)

    # Determine Classification
    if capped_score <= 24:
        classification = CL_LEGITIMATE
    elif capped_score <= 49:
        classification = CL_SUSPICIOUS
    elif capped_score <= 69:
        classification = CL_IMPERSONATION
    elif capped_score <= 84:
        classification = CL_PHISHING
    else:
        classification = CL_CRITICAL

    # Determine Confidence in the score (based on data availability)
    # High confidence if DMARC is evaluated and GeoIP/Intel succeeded.
    confidence = "medium"
    if dmarc_status in ("PASS", "FAIL") and threat_intel.get("status") == "success":
        confidence = "high"
    elif dmarc_status in ("UNKNOWN", "UNAVAILABLE") and threat_intel.get("status") in ("unavailable", "invalid_ip"):
        confidence = "low"

    return {
        "risk_score": capped_score,
        "classification": classification,
        "confidence": confidence,
        "reasons": reasons,
        "features": features,
        "note": "This is a heuristic risk score based on rule-based feature extraction, not a statistically validated probability.",
    }
