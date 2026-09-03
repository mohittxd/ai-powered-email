"""
Phase 3 — Email Header Forensics Service.

Analyzes the structural integrity of email headers:
  - Received chain parsing (origin→destination order)
  - Earliest observed public sender IP identification
  - Anomaly detection (spoofing indicators, timestamp issues, field mismatches)

Does NOT perform active network scanning or connect to any external host.
Does NOT claim IP addresses identify an attacker; uses the term
"earliest_observed_public_sender_ip" for the oldest public IP in the chain.
"""
import ipaddress
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ── IP filtering ───────────────────────────────────────────────────────────────
# All ranges that must be excluded from "public sender" candidates.
_EXCLUDED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),   # Shared address space
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),     # Multicast
    ipaddress.ip_network("240.0.0.0/4"),     # Reserved
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_public_ip(ip_str: str) -> bool:
    """Return True only if ip_str is a syntactically valid, globally routable IP."""
    ip_str = ip_str.strip("[]")
    try:
        addr = ipaddress.ip_address(ip_str)
        return not any(addr in net for net in _EXCLUDED_NETWORKS)
    except ValueError:
        return False


# ── Received header regex patterns ─────────────────────────────────────────────

# Matches: from <source_host> (<comment> [<ip>]) by <dest_host> ...
_FROM_RE = re.compile(
    r'from\s+(\S+)'                         # source hostname
    r'(?:\s+\(([^)]*)\))?',                 # optional (comment [ip])
    re.IGNORECASE,
)
_BY_RE   = re.compile(r'by\s+(\S+)', re.IGNORECASE)
_WITH_RE = re.compile(r'with\s+([A-Za-z0-9\-]+)', re.IGNORECASE)
_FOR_RE  = re.compile(r'for\s+(\S+)', re.IGNORECASE)
_DATE_RE = re.compile(r';\s*(.+)$', re.DOTALL)
_IP4_RE  = re.compile(r'(?:^|\s|\[)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\]|\s|$)')
_IP6_RE  = re.compile(r'\[([0-9a-fA-F:]{3,39})\]')


def _extract_ips_from_text(text: str) -> list[str]:
    """Extract all IP addresses (v4 and v6) from a string."""
    ips = []
    for m in _IP4_RE.finditer(text):
        ips.append(m.group(1))
    for m in _IP6_RE.finditer(text):
        ips.append(m.group(1))
    return ips


def _parse_hop(raw: str, index: int) -> dict:
    """
    Parse a single Received header string into a structured hop dict.
    Never raises — returns what it can, marks malformed=True when parsing fails.
    """
    normalized = " ".join(raw.split())  # collapse whitespace

    from_m  = _FROM_RE.search(normalized)
    by_m    = _BY_RE.search(normalized)
    with_m  = _WITH_RE.search(normalized)
    date_m  = _DATE_RE.search(normalized)

    source_host = from_m.group(1) if from_m else None
    dest_host   = by_m.group(1)   if by_m   else None
    protocol    = with_m.group(1) if with_m  else None

    # Extract source IP: prefer IP inside parenthetical comment, then any IP in the from-clause
    source_ip: Optional[str] = None
    if from_m:
        comment = from_m.group(2) or ""
        candidate_ips = _extract_ips_from_text(comment) or _extract_ips_from_text(from_m.group(0))
        source_ip = candidate_ips[0] if candidate_ips else None

    # Parse timestamp
    timestamp: Optional[str] = None
    timestamp_dt: Optional[datetime] = None
    if date_m:
        raw_date = re.sub(r'\s*\(.*?\)\s*$', '', date_m.group(1)).strip()
        timestamp = raw_date
        try:
            timestamp_dt = parsedate_to_datetime(raw_date)
        except Exception:
            pass

    malformed = source_host is None and dest_host is None

    return {
        "hop_index":   index,
        "raw":         raw,
        "source_host": source_host,
        "source_ip":   source_ip,
        "dest_host":   dest_host,
        "protocol":    protocol,
        "timestamp":   timestamp,
        "timestamp_dt": timestamp_dt,   # internal — stripped before JSON response
        "is_public":   _is_public_ip(source_ip) if source_ip else False,
        "malformed":   malformed,
    }


# ── Received chain ─────────────────────────────────────────────────────────────

def parse_received_chain(received_headers: list[str]) -> list[dict]:
    """
    Parse the Received header list into chronological order (oldest first).
    Email clients store Received headers newest-first, so we reverse.
    """
    ordered = list(reversed(received_headers))   # origin → destination
    hops = [_parse_hop(raw, i) for i, raw in enumerate(ordered)]
    return hops


def find_earliest_public_sender_ip(chain: list[dict]) -> Optional[str]:
    """
    Return the source IP of the first hop in the chain that has a public IP.
    This is the "earliest observed public sender IP" — NOT necessarily the attacker.
    Hops are already in chronological order (index 0 = origin).
    """
    for hop in chain:
        if hop.get("is_public") and hop.get("source_ip"):
            return hop["source_ip"]
    return None


# ── Anomaly detection ──────────────────────────────────────────────────────────

def _extract_domain(addr: str) -> str:
    """Pull the domain portion from an email address string."""
    if "@" in addr:
        return addr.split("@")[-1].strip(" <>\"'").lower()
    return ""


def detect_anomalies(parsed: dict, chain: list[dict]) -> list[dict]:
    """
    Inspect parsed email headers for forensic red-flags.
    Returns list of {type, severity, detail} dicts.
    """
    anomalies: list[dict] = []
    headers = parsed.get("headers", {})

    # ── 1. No Received headers ────────────────────────────────────────────────
    if not chain:
        anomalies.append({
            "type":     "no_received_headers",
            "severity": "high",
            "detail":   "Email contains no Received headers — may be locally injected or headers stripped.",
        })

    # ── 2. Only one Received hop ──────────────────────────────────────────────
    elif len(chain) == 1:
        anomalies.append({
            "type":     "minimal_received_chain",
            "severity": "low",
            "detail":   "Only 1 Received hop — legitimate external email typically traverses multiple relays.",
        })

    # ── 3. Malformed Received headers ─────────────────────────────────────────
    malformed = [h for h in chain if h["malformed"]]
    for hop in malformed:
        anomalies.append({
            "type":     "malformed_received_header",
            "severity": "medium",
            "detail":   f"Hop {hop['hop_index']} could not be parsed (no 'from' or 'by' clause).",
        })

    # ── 4. Timestamp regression (clock goes backward) ────────────────────────
    timed = [h for h in chain if h["timestamp_dt"]]
    for i in range(1, len(timed)):
        delta = (timed[i]["timestamp_dt"] - timed[i-1]["timestamp_dt"]).total_seconds()
        if delta < -300:   # >5 min backward
            anomalies.append({
                "type":     "timestamp_regression",
                "severity": "high",
                "detail":   (
                    f"Hop {timed[i]['hop_index']} timestamp is "
                    f"{abs(delta)/60:.0f} minutes BEFORE hop {timed[i-1]['hop_index']}. "
                    "Possible header injection or clock manipulation."
                ),
            })
        elif delta > 86400:  # >24 h gap
            anomalies.append({
                "type":     "timestamp_gap",
                "severity": "medium",
                "detail":   (
                    f">{delta/3600:.1f}h gap between hop {timed[i-1]['hop_index']} "
                    f"and hop {timed[i]['hop_index']}."
                ),
            })

    # ── 5. Missing Message-ID ────────────────────────────────────────────────
    if not parsed.get("message_id", "").strip():
        anomalies.append({
            "type":     "missing_message_id",
            "severity": "medium",
            "detail":   "No Message-ID header — legitimate MTA-generated email always includes one.",
        })

    # ── 6. Reply-To mismatch ─────────────────────────────────────────────────
    from_domain    = _extract_domain(parsed.get("from_address", ""))
    reply_to_raw   = parsed.get("reply_to", "") or headers.get("reply-to", "")
    reply_to_domain = _extract_domain(reply_to_raw)
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        anomalies.append({
            "type":     "reply_to_mismatch",
            "severity": "critical",
            "detail":   (
                f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'. "
                "Replies will be redirected to a different organisation."
            ),
        })

    # ── 7. From / Sender mismatch ────────────────────────────────────────────
    sender_raw    = parsed.get("sender", "") or headers.get("sender", "")
    sender_domain = _extract_domain(sender_raw)
    if from_domain and sender_domain and from_domain != sender_domain:
        anomalies.append({
            "type":     "from_sender_mismatch",
            "severity": "high",
            "detail":   (
                f"Sender domain '{sender_domain}' differs from From domain '{from_domain}'. "
                "Indicates the stated sender did not submit this email."
            ),
        })

    # ── 8. Return-Path mismatch ───────────────────────────────────────────────
    return_path_raw    = parsed.get("return_path", "") or headers.get("return-path", "")
    return_path_domain = _extract_domain(return_path_raw)
    if from_domain and return_path_domain and from_domain != return_path_domain:
        anomalies.append({
            "type":     "return_path_mismatch",
            "severity": "high",
            "detail":   (
                f"Return-Path domain '{return_path_domain}' differs from From domain '{from_domain}'. "
                "Bounce messages will go to a different domain."
            ),
        })

    # ── 9. No public IP in chain ─────────────────────────────────────────────
    if chain and not any(h["is_public"] for h in chain):
        anomalies.append({
            "type":     "no_public_ip_in_chain",
            "severity": "medium",
            "detail":   "No public IP address found in any Received header — all hops appear internal or IPs are absent.",
        })

    return anomalies


# ── Summary builder ────────────────────────────────────────────────────────────

def _build_summary(chain: list[dict], earliest_ip: Optional[str], anomalies: list[dict]) -> str:
    hop_count   = len(chain)
    anom_count  = len(anomalies)
    critical    = [a for a in anomalies if a["severity"] == "critical"]
    high        = [a for a in anomalies if a["severity"] == "high"]

    parts = [f"Received chain contains {hop_count} hop(s)."]

    if earliest_ip:
        parts.append(f"Earliest observed public sender IP: {earliest_ip}.")
    else:
        parts.append("No public sender IP could be identified in the Received chain.")

    if anom_count == 0:
        parts.append("No header anomalies detected.")
    else:
        parts.append(
            f"{anom_count} anomaly/anomalies detected "
            f"({len(critical)} critical, {len(high)} high)."
        )
        if critical:
            parts.append("Critical: " + "; ".join(a["type"] for a in critical) + ".")

    return " ".join(parts)


# ── Main entry point ───────────────────────────────────────────────────────────

def analyze_header_forensics(parsed: dict) -> dict:
    """
    Run Phase 3 header forensics on a parsed email dict (from email_ingestor.parse_eml).

    Returns:
      received_chain                  — list of parsed hops (chronological)
      earliest_observed_public_sender_ip — oldest public IP in chain (or None)
      anomalies                       — list of detected red-flags
      summary                         — human-readable forensic summary
    """
    received_headers = parsed.get("received_headers", [])
    chain = parse_received_chain(received_headers)
    earliest_ip = find_earliest_public_sender_ip(chain)
    anomalies   = detect_anomalies(parsed, chain)
    summary     = _build_summary(chain, earliest_ip, anomalies)

    # Strip internal datetime objects before returning (not JSON-serialisable)
    serialisable_chain = []
    for hop in chain:
        h = {k: v for k, v in hop.items() if k != "timestamp_dt"}
        serialisable_chain.append(h)

    logger.debug(
        "Header forensics: %d hops, earliest_ip=%s, %d anomalies",
        len(chain), earliest_ip, len(anomalies),
    )

    return {
        "received_chain":                     serialisable_chain,
        "earliest_observed_public_sender_ip": earliest_ip,
        "anomalies":                          anomalies,
        "summary":                            summary,
    }
