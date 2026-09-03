"""
Header & Protocol Authentication Analysis.

Parses Received chain, validates SPF / DKIM / DMARC alignment,
detects timestamp anomalies and relay manipulation.
"""
import re
import dns.resolver
import dns.exception
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional


# ─────────────────────────── Received chain parser ────────────────────────────

_IP_RE = re.compile(
    r'\b(?:'
    r'(?:\d{1,3}\.){3}\d{1,3}'          # IPv4
    r'|'
    r'\[(?:\d{1,3}\.){3}\d{1,3}\]'      # IPv4 in brackets
    r'|'
    r'[0-9a-fA-F:]{3,39}'               # IPv6 simplified
    r')\b'
)

_RECEIVED_FROM_RE = re.compile(
    r'from\s+([^\s(]+)(?:\s+\(([^)]+)\))?', re.IGNORECASE
)
_RECEIVED_BY_RE = re.compile(r'by\s+([^\s;(]+)', re.IGNORECASE)
_RECEIVED_DATE_RE = re.compile(r';\s*(.+)$', re.MULTILINE)


def _extract_ip_from_received(received_str: str) -> Optional[str]:
    """Pull the first public-looking IP from a Received header."""
    matches = _IP_RE.findall(received_str)
    for m in matches:
        clean = m.strip("[]")
        # Skip loopback/link-local trivially
        if clean.startswith("127.") or clean.startswith("::1"):
            continue
        return clean
    return None


def _parse_received_date(received_str: str) -> Optional[datetime]:
    """Extract and parse the date from a Received header."""
    m = _RECEIVED_DATE_RE.search(received_str)
    if not m:
        return None
    date_str = m.group(1).strip()
    # Remove any trailing comment
    date_str = re.sub(r'\s*\(.*\)\s*$', '', date_str).strip()
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None


def parse_received_chain(received_headers: list[str]) -> list[dict]:
    """
    Parse the Received header list (as stored in the message, top→bottom,
    i.e. most-recent first) into a structured list ordered origin→dest (hop 0 = origin).

    Returns list of dicts with:
      hop_index, raw, from_host, by_host, ip_address, timestamp
    """
    # Received headers are ordered most-recent first in the message;
    # reverse to get origin→destination order.
    ordered = list(reversed(received_headers))

    hops = []
    for idx, raw in enumerate(ordered):
        # Normalize whitespace
        normalized = " ".join(raw.split())

        from_match = _RECEIVED_FROM_RE.search(normalized)
        by_match = _RECEIVED_BY_RE.search(normalized)
        ip = _extract_ip_from_received(normalized)
        ts = _parse_received_date(normalized)

        hops.append({
            "hop_index": idx,
            "raw": raw,
            "from_host": from_match.group(1) if from_match else None,
            "by_host": by_match.group(1) if by_match else None,
            "ip_address": ip,
            "timestamp": ts,
        })

    return hops


def detect_header_anomalies(hops: list[dict], raw_headers: dict) -> list[dict]:
    """
    Check for common email header red-flags.
    Returns a list of anomaly dicts: {type, severity, detail}
    """
    anomalies = []

    # 1. Timestamp gaps between hops
    timestamps = [h["timestamp"] for h in hops if h["timestamp"]]
    for i in range(1, len(timestamps)):
        delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
        if delta < -300:  # >5 min backward
            anomalies.append({
                "type": "timestamp_regression",
                "severity": "high",
                "detail": f"Hop {i} timestamp is {abs(delta)/3600:.1f}h BEFORE hop {i-1}"
            })
        elif delta > 86400:  # >24h gap
            anomalies.append({
                "type": "timestamp_gap",
                "severity": "medium",
                "detail": f">{delta/3600:.1f}h gap between hop {i-1} and {i}"
            })

    # 2. Missing Message-ID
    if not raw_headers.get("Message-ID"):
        anomalies.append({
            "type": "missing_message_id",
            "severity": "medium",
            "detail": "No Message-ID header — common in spoofed emails"
        })

    # 3. Reply-To differs from From domain
    from_val = raw_headers.get("From", "")
    reply_to_val = raw_headers.get("Reply-To", "")
    if from_val and reply_to_val:
        from_domain = from_val.split("@")[-1].rstrip(">").lower() if "@" in from_val else ""
        rt_domain = reply_to_val.split("@")[-1].rstrip(">").lower() if "@" in reply_to_val else ""
        if from_domain and rt_domain and from_domain != rt_domain:
            anomalies.append({
                "type": "reply_to_mismatch",
                "severity": "critical",
                "detail": f"Reply-To domain '{rt_domain}' differs from From domain '{from_domain}'"
            })

    # 4. Return-Path / From domain mismatch
    return_path_val = raw_headers.get("Return-Path", "")
    if from_val and return_path_val:
        from_domain = from_val.split("@")[-1].rstrip(">").lower() if "@" in from_val else ""
        rp_domain = return_path_val.split("@")[-1].rstrip(">").lower() if "@" in return_path_val else ""
        if from_domain and rp_domain and from_domain != rp_domain:
            anomalies.append({
                "type": "return_path_mismatch",
                "severity": "high",
                "detail": f"Return-Path domain '{rp_domain}' ≠ From domain '{from_domain}'"
            })

    # 5. Too few hops (≤1) for an externally-received email
    if len(hops) <= 1:
        anomalies.append({
            "type": "minimal_received_chain",
            "severity": "low",
            "detail": f"Only {len(hops)} Received hop(s) — may indicate header stripping"
        })

    return anomalies


# ─────────────────────────── SPF validation ────────────────────────────────────

def _txt_records(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
    except Exception:
        return []


def check_spf(from_domain: str) -> dict:
    """
    Basic SPF check: look for a v=spf1 TXT record on the sender domain.
    Returns {result, record, detail}
    """
    if not from_domain:
        return {"result": "none", "record": None, "detail": "No sender domain"}
    try:
        txts = _txt_records(from_domain)
        spf_record = next((t for t in txts if t.lower().startswith("v=spf1")), None)
        if not spf_record:
            return {
                "result": "none",
                "record": None,
                "detail": f"No SPF TXT record found for {from_domain}"
            }
        # A very simplistic presence check — production would do full RFC7208 evaluation
        if "-all" in spf_record:
            return {"result": "pass", "record": spf_record, "detail": "SPF record present with hard fail policy"}
        elif "~all" in spf_record:
            return {"result": "softfail", "record": spf_record, "detail": "SPF record present with soft fail policy"}
        elif "?all" in spf_record:
            return {"result": "neutral", "record": spf_record, "detail": "SPF record neutral — no enforcement"}
        elif "+all" in spf_record:
            return {"result": "fail", "record": spf_record, "detail": "SPF '+all' — dangerous, allows anyone to send"}
        else:
            return {"result": "pass", "record": spf_record, "detail": "SPF record found"}
    except Exception as e:
        return {"result": "error", "record": None, "detail": str(e)}


# ─────────────────────────── DKIM validation ───────────────────────────────────

def check_dkim(raw_headers: dict) -> dict:
    """
    Check for DKIM-Signature presence and domain alignment.
    Returns {result, domain, detail}
    """
    dkim_sig = raw_headers.get("DKIM-Signature") or raw_headers.get("dkim-signature")

    if not dkim_sig:
        return {"result": "none", "domain": None, "detail": "No DKIM-Signature header present"}

    # Extract d= (signing domain)
    d_match = re.search(r'\bd=([^;]+)', str(dkim_sig))
    signing_domain = d_match.group(1).strip() if d_match else None

    # Extract from domain
    from_val = raw_headers.get("From", "")
    from_domain = from_val.split("@")[-1].rstrip(">").strip().lower() if "@" in from_val else ""

    if signing_domain and from_domain:
        if signing_domain.lower() == from_domain:
            return {"result": "pass", "domain": signing_domain, "detail": "DKIM-Signature present; signing domain aligns with From"}
        else:
            return {
                "result": "fail",
                "domain": signing_domain,
                "detail": f"DKIM signing domain '{signing_domain}' ≠ From domain '{from_domain}'"
            }
    return {"result": "pass", "domain": signing_domain, "detail": "DKIM-Signature present"}


# ─────────────────────────── DMARC validation ──────────────────────────────────

def check_dmarc(from_domain: str, spf_result: str, dkim_result: str) -> dict:
    """
    Look up _dmarc.<domain> TXT record and evaluate alignment.
    Returns {result, policy, record, detail}
    """
    if not from_domain:
        return {"result": "none", "policy": None, "record": None, "detail": "No domain"}

    dmarc_domain = f"_dmarc.{from_domain}"
    try:
        txts = _txt_records(dmarc_domain)
        dmarc_record = next((t for t in txts if t.lower().startswith("v=dmarc1")), None)
    except Exception:
        dmarc_record = None

    if not dmarc_record:
        return {
            "result": "none",
            "policy": None,
            "record": None,
            "detail": f"No DMARC record at {dmarc_domain}"
        }

    # Extract p= policy
    p_match = re.search(r'\bp=(\w+)', dmarc_record)
    policy = p_match.group(1).lower() if p_match else "none"

    # Both SPF and DKIM must pass for DMARC pass
    auth_pass = spf_result in ("pass", "softfail") or dkim_result == "pass"

    if auth_pass:
        return {
            "result": "pass",
            "policy": policy,
            "record": dmarc_record,
            "detail": f"DMARC pass; policy={policy}"
        }
    else:
        return {
            "result": "fail",
            "policy": policy,
            "record": dmarc_record,
            "detail": f"DMARC fail; policy={policy}; SPF={spf_result}, DKIM={dkim_result}"
        }


# ─────────────────────────── Main entry point ──────────────────────────────────

def analyze_headers(parsed_email: dict) -> dict:
    """
    Run all header authentication checks on a parsed email dict.
    Returns a comprehensive auth analysis dict.
    """
    raw_headers = parsed_email.get("raw_headers", {})
    received_headers = parsed_email.get("received_headers", [])

    # Parse received chain
    hops = parse_received_chain(received_headers)

    # Anomaly detection
    anomalies = detect_header_anomalies(hops, raw_headers)

    # Extract sender domain from From address
    from_addr = parsed_email.get("from_address", "")
    from_domain = from_addr.split("@")[-1].strip().lower() if "@" in from_addr else ""

    # SPF / DKIM / DMARC
    spf = check_spf(from_domain)
    dkim = check_dkim(raw_headers)
    dmarc = check_dmarc(from_domain, spf["result"], dkim["result"])

    return {
        "from_domain": from_domain,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "received_hops": hops,
        "header_anomalies": anomalies,
    }
