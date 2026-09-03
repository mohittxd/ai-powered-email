"""
IOC Extractor — pulls Indicators of Compromise from a parsed email.
"""
import re
import math
from urllib.parse import urlparse
from typing import Optional


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "tiny.cc", "is.gd", "cli.gs", "rebrand.ly", "cutt.ly",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".loan", ".online", ".site", ".work", ".win", ".click",
}

SUSPICIOUS_ATTACHMENT_EXTS = {
    ".exe", ".js", ".vbs", ".bat", ".ps1", ".hta", ".msi",
    ".docm", ".xlsm", ".pptm", ".iso", ".img", ".scr", ".jar",
    ".cmd", ".com", ".reg",
}

EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _url_entropy(url: str) -> float:
    path = urlparse(url).path + urlparse(url).query
    if not path:
        return 0.0
    freq = {}
    for c in path:
        freq[c] = freq.get(c, 0) + 1
    n = len(path)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _classify_url_risk(url: str) -> str:
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return "medium"

    if any(s in hostname for s in URL_SHORTENERS):
        return "critical"
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            return "high"
    if re.match(r'^\d{1,3}\.\d{1,3}', hostname):
        return "high"
    if _url_entropy(url) > 4.0:
        return "high"
    if parsed.scheme == "http":
        return "medium"
    return "low"


def extract_iocs(parsed_email: dict) -> list[dict]:
    """
    Extract all IOCs from a parsed email document.

    Returns list of dicts:
      {ioc_type, value, risk_level, context, metadata}
    """
    iocs = []
    body_text = parsed_email.get("body_text", "") or ""
    body_html = parsed_email.get("body_html", "") or ""
    combined = body_text + " " + body_html

    # ── URLs ──────────────────────────────────────────────────────────────────
    for url in parsed_email.get("embedded_urls", []):
        risk = _classify_url_risk(url)
        try:
            hostname = urlparse(url).hostname or ""
        except Exception:
            hostname = ""

        iocs.append({
            "ioc_type": "url",
            "value": url[:500],
            "risk_level": risk,
            "context": f"Found in email body",
            "metadata": {
                "hostname": hostname,
                "entropy": round(_url_entropy(url), 2),
                "is_shortener": any(s in hostname for s in URL_SHORTENERS),
            },
        })

    # ── Domain IOCs (from URLs) ───────────────────────────────────────────────
    seen_domains = set()
    for url in parsed_email.get("embedded_urls", []):
        try:
            hostname = urlparse(url).hostname or ""
            domain = ".".join(hostname.split(".")[-2:]) if hostname else ""
        except Exception:
            domain = ""
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            risk = "high" if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else "medium"
            iocs.append({
                "ioc_type": "domain",
                "value": domain,
                "risk_level": risk,
                "context": f"Domain extracted from URL: {url[:100]}",
                "metadata": {"source_url": url[:200]},
            })

    # ── Email addresses in body (not the sender) ─────────────────────────────
    found_emails = set(EMAIL_RE.findall(combined))
    sender = parsed_email.get("from_address", "")
    for addr in found_emails:
        if addr == sender:
            continue
        iocs.append({
            "ioc_type": "email_addr",
            "value": addr,
            "risk_level": "medium",
            "context": "Email address found in body",
            "metadata": {},
        })

    # ── Raw IPs in body ───────────────────────────────────────────────────────
    for ip in set(IP_RE.findall(combined)):
        # skip private ranges trivially
        parts = ip.split(".")
        if parts[0] in ("10", "127", "192", "172"):
            continue
        iocs.append({
            "ioc_type": "ip",
            "value": ip,
            "risk_level": "high",
            "context": "Raw IP address found in email body",
            "metadata": {},
        })

    # ── Attachments ────────────────────────────────────────────────────────────
    for att in parsed_email.get("attachments", []):
        if att.get("is_suspicious"):
            iocs.append({
                "ioc_type": "attachment",
                "value": att.get("filename", "unknown"),
                "risk_level": "critical",
                "context": f"Suspicious attachment type: {att.get('extension')}",
                "metadata": {
                    "content_type": att.get("content_type"),
                    "size_bytes": att.get("size_bytes"),
                    "extension": att.get("extension"),
                },
            })

    return iocs
