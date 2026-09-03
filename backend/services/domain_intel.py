"""
Domain Intelligence — WHOIS + DNS MX lookup.
"""
import re
import dns.resolver
import dns.exception
from datetime import datetime


def _safe_txt_lookup(domain: str, record_type: str = "TXT") -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def _safe_mx_lookup(domain: str) -> list[dict]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return [{"preference": r.preference, "exchange": str(r.exchange)} for r in answers]
    except Exception:
        return []


def _safe_ns_lookup(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def get_domain_intel(domain: str) -> dict:
    """
    Fetch basic domain intelligence via DNS.
    Returns a dict with mx_records, nameservers, spf_txt, dmarc_txt.
    WHOIS is omitted in MVP to avoid heavy dependencies — can be added via python-whois.
    """
    if not domain:
        return {"domain": domain, "error": "No domain provided"}

    mx = _safe_mx_lookup(domain)
    ns = _safe_ns_lookup(domain)
    txt = _safe_txt_lookup(domain)

    spf_records = [t for t in txt if "v=spf1" in t.lower()]
    dmarc_txt = _safe_txt_lookup(f"_dmarc.{domain}")

    # Heuristic: newly registered domains often have numeric/random nameservers
    is_suspicious_ns = any(
        re.search(r'\d{4,}', n) or "parking" in n.lower()
        for n in ns
    ) if ns else False

    return {
        "domain": domain,
        "mx_records": mx,
        "nameservers": ns,
        "spf_txt": spf_records,
        "dmarc_txt": dmarc_txt,
        "is_suspicious_nameservers": is_suspicious_ns,
        "has_mx": len(mx) > 0,
        "has_spf": len(spf_records) > 0,
        "has_dmarc": len(dmarc_txt) > 0,
        "checked_at": datetime.utcnow().isoformat(),
    }
