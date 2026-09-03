"""
NLP / Rule-based Fraud Classifier.

Produces a fraud score 0–100 and a classification label.
Uses weighted heuristic rules — fast, explainable, no model download.
"""
import re
import math
from urllib.parse import urlparse
from typing import Optional


# ─────────────────────────── Keyword dictionaries ─────────────────────────────

URGENCY_KEYWORDS = {
    "immediately", "urgent", "asap", "right away", "right now", "time sensitive",
    "action required", "act now", "expire", "expiring", "last chance", "limited time",
    "within 24 hours", "within 48 hours", "final notice", "respond today",
    "important notice", "account suspended", "account locked", "verify now",
    "confirm immediately", "critical alert", "security alert", "warning",
}

CREDENTIAL_HARVEST_KEYWORDS = {
    "enter your password", "verify your account", "confirm your credentials",
    "update your details", "click here to verify", "login to confirm",
    "validate your email", "reset your password immediately",
    "your account has been compromised", "unusual sign-in activity",
    "we noticed a login", "confirm your identity",
}

PAYMENT_DIVERSION_KEYWORDS = {
    "wire transfer", "bank transfer", "change of bank", "new account details",
    "updated payment details", "invoice attached", "payment overdue",
    "remit payment", "ach transfer", "routing number", "account number",
    "bitcoin", "crypto", "gift card", "itunes", "google play card",
    "western union", "moneygram",
}

EXECUTIVE_IMPERSONATION = {
    "ceo", "cfo", "cto", "president", "managing director", "vp of finance",
    "chief executive", "chief financial", "board of directors",
}

BRAND_IMPERSONATION = {
    "paypal", "amazon", "apple", "microsoft", "google", "netflix", "facebook",
    "instagram", "bank of america", "chase", "wells fargo", "citibank",
    "irs", "fedex", "ups", "dhl", "usps", "linkedin", "dropbox",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "tiny.cc", "is.gd", "cli.gs", "rebrand.ly", "cutt.ly",
    "shorte.st", "bc.vc", "lnkd.in",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".loan", ".online", ".site", ".work", ".win", ".click",
}


# ─────────────────────────── Scoring helpers ──────────────────────────────────

def _keyword_score(text: str, keywords: set, weight: float) -> float:
    """Count matching keywords and return a capped weighted score."""
    if not text:
        return 0.0
    text_lower = text.lower()
    hits = sum(1 for kw in keywords if kw in text_lower)
    return min(hits * weight, weight * 5)  # cap at 5 hits


def _url_entropy(url: str) -> float:
    """Shannon entropy of the URL path — high entropy suggests obfuscation."""
    path = urlparse(url).path + urlparse(url).query
    if not path:
        return 0.0
    freq = {}
    for c in path:
        freq[c] = freq.get(c, 0) + 1
    n = len(path)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _score_urls(urls: list[str]) -> tuple[float, list[str]]:
    """Score URL-based risk factors. Returns (score, flags)."""
    score = 0.0
    flags = []

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            continue

        # Shortened URL
        if any(s in hostname for s in URL_SHORTENERS):
            score += 15
            flags.append(f"url_shortener:{hostname}")

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 10
                flags.append(f"suspicious_tld:{tld}")
                break

        # High entropy (obfuscated path)
        entropy = _url_entropy(url)
        if entropy > 4.0:
            score += 8
            flags.append(f"high_entropy_url:{hostname}")

        # IP address in URL
        if re.match(r'^\d{1,3}\.\d{1,3}', hostname):
            score += 12
            flags.append(f"ip_in_url:{hostname}")

        # HTTP (not HTTPS)
        if parsed.scheme == "http":
            score += 3
            flags.append("unencrypted_http_url")

        # Brand name in subdomain/path but wrong domain
        url_lower = url.lower()
        for brand in BRAND_IMPERSONATION:
            if brand in url_lower and brand not in hostname.split(".")[-2:]:
                score += 10
                flags.append(f"brand_in_url_path:{brand}")
                break

    return min(score, 40), flags  # cap at 40 pts


def _score_display_name_mismatch(
    display_name: str, from_addr: str, reply_to: str, return_path: str
) -> tuple[float, list[str]]:
    """Detect From display-name vs. address mismatches."""
    score = 0.0
    flags = []

    if not from_addr:
        return score, flags

    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    # Check if display name contains a different email address
    if display_name and "@" in display_name:
        name_domain = display_name.split("@")[-1].rstrip(">").lower()
        if name_domain and name_domain != from_domain:
            score += 15
            flags.append("display_name_contains_different_email")

    # Check for brand impersonation in display name
    if display_name:
        name_lower = display_name.lower()
        for brand in BRAND_IMPERSONATION:
            if brand in name_lower:
                # Is the actual sending domain the real brand domain?
                if brand not in from_domain:
                    score += 20
                    flags.append(f"brand_impersonation:{brand}")
                break

    # Reply-To domain mismatch
    if reply_to and from_domain:
        rt_domain = reply_to.split("@")[-1].rstrip(">").lower() if "@" in reply_to else ""
        if rt_domain and rt_domain != from_domain:
            score += 10
            flags.append("reply_to_domain_mismatch")

    return score, flags


def _score_auth(spf_result: str, dkim_result: str, dmarc_result: str) -> tuple[float, list[str]]:
    """Score authentication failures."""
    score = 0.0
    flags = []

    if spf_result in ("fail", "error"):
        score += 15
        flags.append(f"spf_{spf_result}")
    elif spf_result in ("none",):
        score += 8
        flags.append("spf_none")

    if dkim_result in ("fail", "none"):
        score += 12
        flags.append(f"dkim_{dkim_result}")

    if dmarc_result in ("fail",):
        score += 15
        flags.append("dmarc_fail")
    elif dmarc_result == "none":
        score += 5
        flags.append("dmarc_none")

    return score, flags


def _score_geo(geo_trace: dict) -> tuple[float, list[str]]:
    """Score geolocation risk signals."""
    score = 0.0
    flags = []

    origin = geo_trace.get("origin_hop") or {}
    threat_flags = origin.get("threat_flags", [])

    if "tor_exit_node" in threat_flags:
        score += 20
        flags.append("origin_tor_exit")
    if "vpn_provider" in threat_flags:
        score += 10
        flags.append("origin_vpn")
    if "known_hosting_provider" in threat_flags:
        score += 5
        flags.append("origin_hosting_infra")

    return score, flags


def _score_attachments(attachments: list[dict]) -> tuple[float, list[str]]:
    """Score risky attachment types."""
    score = 0.0
    flags = []
    for att in attachments:
        if att.get("is_suspicious"):
            score += 15
            flags.append(f"suspicious_attachment:{att.get('filename', 'unknown')}")
    return min(score, 25), flags


def _classify(score: float) -> str:
    if score < 20:
        return "legitimate"
    elif score < 40:
        return "suspicious"
    elif score < 60:
        return "impersonation"
    elif score < 75:
        return "phishing"
    else:
        return "bec_fraud"


# ─────────────────────────── Main scorer ──────────────────────────────────────

def classify_email(
    parsed_email: dict,
    auth_analysis: dict,
    geo_trace: dict,
) -> dict:
    """
    Compute fraud score and classification for a parsed email.

    Returns:
      {fraud_score, classification, confidence, score_breakdown, flags}
    """
    body_text = parsed_email.get("body_text", "") or ""
    body_combined = body_text + " " + (parsed_email.get("subject", "") or "")
    urls = parsed_email.get("embedded_urls", [])
    attachments = parsed_email.get("attachments", [])

    all_flags = []
    total_score = 0.0

    # 1. Urgency language
    s = _keyword_score(body_combined, URGENCY_KEYWORDS, 3.0)
    if s > 0:
        all_flags.append(f"urgency_language({s:.0f}pts)")
    total_score += s

    # 2. Credential harvesting
    s = _keyword_score(body_combined, CREDENTIAL_HARVEST_KEYWORDS, 4.0)
    if s > 0:
        all_flags.append(f"credential_harvest({s:.0f}pts)")
    total_score += s

    # 3. Payment diversion
    s = _keyword_score(body_combined, PAYMENT_DIVERSION_KEYWORDS, 4.0)
    if s > 0:
        all_flags.append(f"payment_diversion({s:.0f}pts)")
    total_score += s

    # 4. Executive impersonation in subject/body
    s = _keyword_score(body_combined, EXECUTIVE_IMPERSONATION, 5.0)
    if s > 0:
        all_flags.append(f"executive_impersonation({s:.0f}pts)")
    total_score += s

    # 5. URL analysis
    url_score, url_flags = _score_urls(urls)
    all_flags.extend(url_flags)
    total_score += url_score

    # 6. Display name / From mismatch
    mismatch_score, mismatch_flags = _score_display_name_mismatch(
        parsed_email.get("from_display_name", ""),
        parsed_email.get("from_address", ""),
        parsed_email.get("reply_to", ""),
        parsed_email.get("return_path", ""),
    )
    all_flags.extend(mismatch_flags)
    total_score += mismatch_score

    # 7. Auth failures
    spf = auth_analysis.get("spf", {}).get("result", "none")
    dkim = auth_analysis.get("dkim", {}).get("result", "none")
    dmarc = auth_analysis.get("dmarc", {}).get("result", "none")
    auth_score, auth_flags = _score_auth(spf, dkim, dmarc)
    all_flags.extend(auth_flags)
    total_score += auth_score

    # 8. Geolocation risk
    geo_score, geo_flags = _score_geo(geo_trace)
    all_flags.extend(geo_flags)
    total_score += geo_score

    # 9. Header anomalies
    anomaly_count = len(auth_analysis.get("header_anomalies", []))
    anomaly_score = min(anomaly_count * 5, 20)
    if anomaly_score:
        all_flags.append(f"header_anomalies({anomaly_count})")
    total_score += anomaly_score

    # 10. Risky attachments
    att_score, att_flags = _score_attachments(attachments)
    all_flags.extend(att_flags)
    total_score += att_score

    # Clamp to 0–100
    fraud_score = min(round(total_score), 100)
    classification = _classify(fraud_score)

    # Confidence: more flags → higher confidence
    confidence = min(0.5 + len(all_flags) * 0.05, 0.99)

    return {
        "fraud_score": fraud_score,
        "classification": classification,
        "confidence": round(confidence, 2),
        "flags": all_flags,
        "score_breakdown": {
            "urgency": round(_keyword_score(body_combined, URGENCY_KEYWORDS, 3.0), 1),
            "credential_harvest": round(_keyword_score(body_combined, CREDENTIAL_HARVEST_KEYWORDS, 4.0), 1),
            "payment_diversion": round(_keyword_score(body_combined, PAYMENT_DIVERSION_KEYWORDS, 4.0), 1),
            "executive_impersonation": round(_keyword_score(body_combined, EXECUTIVE_IMPERSONATION, 5.0), 1),
            "url_risk": round(url_score, 1),
            "display_name_mismatch": round(mismatch_score, 1),
            "auth_failure": round(auth_score, 1),
            "geo_risk": round(geo_score, 1),
            "header_anomalies": round(anomaly_score, 1),
            "attachment_risk": round(att_score, 1),
        },
    }
