"""
Phase 5 — Indicator of Compromise (IOC) Analysis Service.

Extracts and classifies IOCs from a parsed email:
  URLs, domains, IPv4/IPv6, email addresses, attachments.

IMPORTANT:
  - No URLs are visited, downloaded, or resolved.
  - No attachments are opened or executed.
  - Analysis is purely structural/lexical.

IOC data model fields:
  id          — UUID
  email_id    — set by caller when persisting
  type        — url | domain | ipv4 | ipv6 | email_address | attachment
  value       — extracted value
  severity    — low | medium | high | critical
  source      — where extracted (body_text, body_html, headers, attachment)
  tags        — list of characteristics detected (e.g. ['url_shortener', 'encoded_params'])
  created_at  — ISO 8601 timestamp
"""
import ipaddress
import logging
import math
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

logger = logging.getLogger(__name__)

# ── Severity constants ─────────────────────────────────────────────────────────
LOW      = "low"
MEDIUM   = "medium"
HIGH     = "high"
CRITICAL = "critical"

# ── IOC type constants ─────────────────────────────────────────────────────────
T_URL        = "url"
T_DOMAIN     = "domain"
T_IPV4       = "ipv4"
T_IPV6       = "ipv6"
T_EMAIL_ADDR = "email_address"
T_ATTACHMENT = "attachment"

# ── Known sets ─────────────────────────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "adf.ly", "tiny.cc", "is.gd", "cli.gs", "rebrand.ly", "cutt.ly",
    "short.link", "lnkd.in", "tr.im", "v.gd", "youtu.be", "qr.io",
    "qr.ae", "bl.ink", "bitly.com",
}

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".loan", ".online", ".site", ".work", ".win", ".click",
    ".pw", ".cc", ".su", ".ws", ".biz", ".info",
}

SAFE_PORTS = {80, 443, 25, 587, 465, 21, 22, 8080, 8443}

# extension → (severity, tags)
RISKY_EXTENSIONS: dict[str, tuple[str, list[str]]] = {
    ".exe":  (CRITICAL, ["executable"]),
    ".dll":  (CRITICAL, ["executable"]),
    ".scr":  (CRITICAL, ["executable"]),
    ".com":  (CRITICAL, ["executable"]),
    ".bat":  (CRITICAL, ["script"]),
    ".cmd":  (CRITICAL, ["script"]),
    ".ps1":  (CRITICAL, ["script", "powershell"]),
    ".vbs":  (CRITICAL, ["script"]),
    ".js":   (HIGH,     ["script"]),
    ".hta":  (CRITICAL, ["script"]),
    ".msi":  (HIGH,     ["installer"]),
    ".jar":  (HIGH,     ["java"]),
    ".docm": (HIGH,     ["macro_enabled"]),
    ".xlsm": (HIGH,     ["macro_enabled"]),
    ".pptm": (HIGH,     ["macro_enabled"]),
    ".xlsb": (HIGH,     ["macro_enabled"]),
    ".iso":  (HIGH,     ["disk_image"]),
    ".img":  (HIGH,     ["disk_image"]),
    ".vhd":  (HIGH,     ["disk_image"]),
    ".zip":  (MEDIUM,   ["archive"]),
    ".rar":  (MEDIUM,   ["archive"]),
    ".7z":   (MEDIUM,   ["archive"]),
    ".tar":  (MEDIUM,   ["archive"]),
    ".gz":   (MEDIUM,   ["archive"]),
    ".reg":  (HIGH,     ["registry"]),
    ".lnk":  (HIGH,     ["lnk_shortcut"]),
    ".py":   (MEDIUM,   ["script"]),
    ".sh":   (MEDIUM,   ["script"]),
}

RISKY_MIMES: dict[str, tuple[str, list[str]]] = {
    "application/x-msdownload":   (CRITICAL, ["executable"]),
    "application/x-msdos-program":(CRITICAL, ["executable"]),
    "application/x-sh":           (HIGH,     ["script"]),
    "application/x-powershell":   (CRITICAL, ["script"]),
    "application/vnd.ms-excel.sheet.macroenabled.12": (HIGH, ["macro_enabled"]),
    "application/vnd.ms-word.document.macroenabled.12": (HIGH, ["macro_enabled"]),
    "application/java-archive":   (HIGH,     ["java"]),
    "application/x-iso9660-image":(HIGH,     ["disk_image"]),
    "application/zip":            (MEDIUM,   ["archive"]),
    "application/x-rar-compressed":(MEDIUM,  ["archive"]),
    "application/x-7z-compressed":(MEDIUM,   ["archive"]),
}

# ── Regex patterns ─────────────────────────────────────────────────────────────
_URL_RE = re.compile(
    r'https?://[^\s\'"<>)(\\]{3,}|www\.[^\s\'"<>)(\\]{3,}',
    re.IGNORECASE,
)
_IPV4_RE = re.compile(
    r'\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)
_IPV6_RE = re.compile(
    r'\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|::(?:ffff(?::0{1,4})?::)?\d{1,3}(?:\.\d{1,3}){3}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}:\d{1,3}(?:\.\d{1,3}){3})\b'
)
_EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
)
_DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
)
# Match href="..." or href='...'
_HREF_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
# Match link text between > and </a>
_ANCHOR_RE = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _is_private_ipv4(ip: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip).is_private
    except ValueError:
        return False


def _is_valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except ValueError:
        return False


def _path_entropy(url: str) -> float:
    """Shannon entropy of URL path + query (high entropy = random/obfuscated)."""
    try:
        p = urlparse(url)
        text = (p.path or "") + (p.query or "")
        if not text:
            return 0.0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        n = len(text)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())
    except Exception:
        return 0.0


def _make_ioc(ioc_type: str, value: str, severity: str, source: str, tags: list[str]) -> dict:
    return {
        "id":         str(uuid.uuid4()),
        "email_id":   None,  # filled by caller
        "type":       ioc_type,
        "value":      value,
        "severity":   severity,
        "source":     source,
        "tags":       tags,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


# ── URL analysis ───────────────────────────────────────────────────────────────

def _analyze_url(url: str) -> tuple[str, list[str]]:
    """
    Structural/lexical analysis only — no network requests.
    Returns (severity, tags).
    """
    tags: list[str] = []
    try:
        p = urlparse(url)
        hostname = (p.hostname or "").lower()
        port     = p.port
        path     = p.path or ""
        query    = p.query or ""
    except Exception:
        return HIGH, ["malformed_url"]

    # URL shortener
    if any(hostname == s or hostname.endswith("." + s) for s in URL_SHORTENERS):
        tags.append("url_shortener")

    # Unusual port
    if port and port not in SAFE_PORTS:
        tags.append(f"unusual_port:{port}")

    # Excessive subdomains (>3 labels)
    labels = hostname.split(".")
    if len(labels) > 4:
        tags.append("excessive_subdomains")

    # Encoded URL components
    if "%" in path or "%" in query:
        tags.append("encoded_components")
        try:
            decoded = unquote(path + query)
            if decoded != (path + query):
                tags.append("url_decoded_content")
        except Exception:
            pass

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            tags.append("suspicious_tld")
            break

    # IP address used as host
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        tags.append("ip_as_host")

    # High entropy path (possible DGA or token)
    entropy = _path_entropy(url)
    if entropy > 4.5:
        tags.append("high_entropy_path")

    # HTTP (not HTTPS)
    if url.lower().startswith("http://"):
        tags.append("unencrypted_http")

    # Double-extension style (evil.com.attacker.net)
    if labels[:-2]:  # has subdomains
        subdomain_str = ".".join(labels[:-2])
        if re.search(r'\.(com|net|org|gov|edu|co)$', subdomain_str, re.I):
            tags.append("lookalike_subdomain")

    # Severity scoring
    if "url_shortener" in tags:
        return CRITICAL, tags
    if any(t in tags for t in ["ip_as_host", "suspicious_tld", "lookalike_subdomain"]):
        return HIGH, tags
    if any(t in tags for t in ["encoded_components", "unusual_port:*", "high_entropy_path"]):
        # Check for actual unusual port tag
        if any(t.startswith("unusual_port:") for t in tags) or "encoded_components" in tags:
            return HIGH, tags
    if "unencrypted_http" in tags or "excessive_subdomains" in tags:
        return MEDIUM, tags
    return LOW, tags


def _extract_display_domain_mismatches(html: str) -> list[dict]:
    """
    Detect anchors where the link text appears to be a URL/domain but the href
    points to a different domain. Pure HTML parsing — no network calls.
    """
    mismatches = []
    for m in _ANCHOR_RE.finditer(html):
        href_url   = m.group(1).strip()
        link_text  = re.sub(r'<[^>]+>', '', m.group(2)).strip()  # strip inner HTML tags

        # Only check when link_text looks like a URL
        if not re.match(r'https?://', link_text, re.I) and "." not in link_text:
            continue

        try:
            href_host = urlparse(href_url).hostname or ""
            text_host = urlparse(link_text).hostname if re.match(r'https?://', link_text, re.I) else link_text.split("/")[0]
        except Exception:
            continue

        if href_host and text_host and href_host.lower() != text_host.lower():
            mismatches.append({
                "href":       href_url,
                "displayed":  link_text,
                "href_host":  href_host,
                "text_host":  text_host,
            })

    return mismatches


# ── Extractors ─────────────────────────────────────────────────────────────────

def _extract_urls(body_text: str, body_html: str) -> list[dict]:
    iocs: list[dict] = []
    seen: set[str] = set()

    # Collect all raw URLs from both text and HTML
    candidates: list[tuple[str, str]] = []
    for u in _URL_RE.findall(body_text):
        candidates.append((u.rstrip(".,;)>\"'"), "body_text"))
    for u in _URL_RE.findall(body_html):
        candidates.append((u.rstrip(".,;)>\"'"), "body_html"))
    for m in _HREF_RE.findall(body_html):
        if m.startswith(("http://", "https://")):
            candidates.append((m, "body_html_href"))

    for url, source in candidates:
        if not url or url in seen:
            continue
        seen.add(url)
        severity, tags = _analyze_url(url)
        iocs.append(_make_ioc(T_URL, url[:500], severity, source, tags))

    # Display-domain mismatches
    if body_html:
        for mm in _extract_display_domain_mismatches(body_html):
            tag_list = ["display_domain_mismatch"]
            ioc = _make_ioc(T_URL, mm["href"][:500], HIGH, "body_html", tag_list)
            ioc["display_mismatch"] = mm
            if mm["href"] not in seen:
                seen.add(mm["href"])
                iocs.append(ioc)

    return iocs


def _extract_domains(body_text: str, body_html: str, url_hostnames: set[str]) -> list[dict]:
    iocs: list[dict] = []
    seen: set[str] = set()
    combined = body_text + " " + body_html

    for dom in _DOMAIN_RE.findall(combined):
        dom = dom.lower()
        if dom in seen:
            continue
        # Skip if it's already captured as part of a URL
        if any(dom in h for h in url_hostnames):
            continue
        # Skip if it looks like an IP
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', dom):
            continue
        seen.add(dom)

        tags: list[str] = []
        severity = LOW

        for tld in SUSPICIOUS_TLDS:
            if dom.endswith(tld):
                tags.append("suspicious_tld")
                severity = HIGH
                break

        labels = dom.split(".")
        if len(labels) > 4:
            tags.append("excessive_subdomains")
            if severity == LOW:
                severity = MEDIUM

        iocs.append(_make_ioc(T_DOMAIN, dom, severity, "body_text", tags))

    return iocs[:100]


def _extract_ips(body_text: str, body_html: str, received_headers: list[str]) -> list[dict]:
    iocs: list[dict] = []
    seen: set[str] = set()
    combined = body_text + " " + body_html + " " + " ".join(received_headers)

    # IPv4
    for ip in _IPV4_RE.findall(combined):
        if ip in seen or _is_private_ipv4(ip):
            continue
        seen.add(ip)
        iocs.append(_make_ioc(T_IPV4, ip, HIGH, "body_or_headers", ["ipv4_in_body"]))

    # IPv6
    for ip in _IPV6_RE.findall(combined):
        if ip in seen or not _is_valid_ipv6(ip):
            continue
        try:
            if ipaddress.IPv6Address(ip).is_private or ipaddress.IPv6Address(ip).is_loopback:
                continue
        except ValueError:
            continue
        seen.add(ip)
        iocs.append(_make_ioc(T_IPV6, ip, MEDIUM, "body_or_headers", ["ipv6_address"]))

    return iocs[:50]


def _extract_email_addresses(body_text: str, body_html: str, headers: dict) -> list[dict]:
    iocs: list[dict] = []
    seen: set[str] = set()
    combined = body_text + " " + body_html

    # Known header addresses to skip (not IOCs per se)
    skip = {
        (headers.get("from", "") or "").lower(),
        (headers.get("to", "") or "").lower(),
        (headers.get("reply-to", "") or "").lower(),
    }

    for addr in _EMAIL_RE.findall(combined):
        addr_lower = addr.lower()
        if addr_lower in seen or addr_lower in skip:
            continue
        seen.add(addr_lower)

        tags: list[str] = []
        severity = MEDIUM

        domain = addr.split("@")[-1].lower()
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                tags.append("suspicious_tld")
                severity = HIGH
                break

        iocs.append(_make_ioc(T_EMAIL_ADDR, addr, severity, "body_text", tags))

    return iocs[:50]


def _extract_attachment_iocs(attachments: list[dict]) -> list[dict]:
    iocs: list[dict] = []
    seen: set[str] = set()

    for att in attachments:
        filename  = att.get("filename", "unknown") or "unknown"
        mime_type = (att.get("content_type", "") or "").lower()
        ext       = (att.get("extension", "") or "").lower()
        size      = att.get("size_bytes", 0)

        if filename in seen:
            continue
        seen.add(filename)

        tags: list[str] = []
        severity = LOW

        # Extension-based risk
        if ext in RISKY_EXTENSIONS:
            sev, ext_tags = RISKY_EXTENSIONS[ext]
            severity = sev
            tags.extend(ext_tags)

        # MIME-based risk (may escalate or add tags)
        for risky_mime, (msev, mtags) in RISKY_MIMES.items():
            if risky_mime in mime_type:
                if _sev_rank(msev) > _sev_rank(severity):
                    severity = msev
                for t in mtags:
                    if t not in tags:
                        tags.append(t)
                break

        if not tags:
            tags.append("attachment")

        # Double-extension trick (.pdf.exe)
        parts = filename.rsplit(".", 2)
        if len(parts) >= 3:
            tags.append("double_extension")
            if severity == LOW:
                severity = MEDIUM

        ioc = _make_ioc(T_ATTACHMENT, filename, severity, "attachment", tags)
        ioc["attachment_meta"] = {
            "content_type": mime_type,
            "size_bytes":   size,
            "extension":    ext,
        }
        iocs.append(ioc)

    return iocs


def _sev_rank(s: str) -> int:
    return {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}.get(s, 0)


# ── Deduplication ──────────────────────────────────────────────────────────────

def deduplicate(iocs: list[dict]) -> list[dict]:
    """
    Merge duplicate (type, value) pairs — keep highest severity
    and union of tags from all occurrences.
    """
    best: dict[tuple, dict] = {}
    for ioc in iocs:
        key = (ioc["type"], ioc["value"])
        if key not in best:
            best[key] = dict(ioc)
        else:
            existing = best[key]
            # Keep highest severity
            if _sev_rank(ioc["severity"]) > _sev_rank(existing["severity"]):
                existing["severity"] = ioc["severity"]
            # Union tags
            for t in ioc.get("tags", []):
                if t not in existing["tags"]:
                    existing["tags"].append(t)
    return list(best.values())


# ── Main entry point ───────────────────────────────────────────────────────────

def extract_all_iocs(parsed: dict, email_id: str = "") -> dict:
    """
    Phase 5 IOC extraction pipeline.
    Analyzes the already-parsed email — no network calls.

    Args:
      parsed    — output of email_ingestor.parse_eml()
      email_id  — set on all returned IOC records

    Returns:
      {urls, domains, ips, email_addresses, attachments, summary}
    """
    body_text  = parsed.get("body_text", "")  or ""
    body_html  = parsed.get("body_html", "")  or ""
    attachments = parsed.get("attachments", []) or []
    headers    = parsed.get("headers", {}) or {}
    received   = parsed.get("received_headers", []) or []

    url_iocs    = deduplicate(_extract_urls(body_text, body_html))
    url_hostnames = set()
    for u in url_iocs:
        try:
            h = urlparse(u["value"]).hostname or ""
            url_hostnames.add(h.lower())
        except Exception:
            pass

    domain_iocs = deduplicate(_extract_domains(body_text, body_html, url_hostnames))
    ip_iocs     = deduplicate(_extract_ips(body_text, body_html, received))
    email_iocs  = deduplicate(_extract_email_addresses(body_text, body_html, headers))
    att_iocs    = deduplicate(_extract_attachment_iocs(attachments))

    # Assign email_id to all records
    all_iocs = url_iocs + domain_iocs + ip_iocs + email_iocs + att_iocs
    for ioc in all_iocs:
        ioc["email_id"] = email_id

    critical_count = sum(1 for i in all_iocs if i["severity"] == CRITICAL)
    high_count     = sum(1 for i in all_iocs if i["severity"] == HIGH)

    summary = (
        f"{len(all_iocs)} IOC(s) extracted: "
        f"{len(url_iocs)} URL(s), {len(domain_iocs)} domain(s), "
        f"{len(ip_iocs)} IP(s), {len(email_iocs)} email address(es), "
        f"{len(att_iocs)} attachment(s). "
        f"Severity: {critical_count} critical, {high_count} high."
    )

    logger.debug("IOC extraction complete: %s", summary)

    return {
        "urls":            url_iocs,
        "domains":         domain_iocs,
        "ips":             ip_iocs,
        "email_addresses": email_iocs,
        "attachments":     att_iocs,
        "summary":         summary,
        "counts": {
            "total":    len(all_iocs),
            "critical": critical_count,
            "high":     high_count,
        },
    }
