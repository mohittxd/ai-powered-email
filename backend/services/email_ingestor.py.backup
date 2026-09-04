"""
Phase 2 — Secure email ingestion and parsing service.
Nothing here executes HTML, JS, attachments, or follows URLs.
"""
import email
import email.policy
import hashlib
import ipaddress
import logging
import os
import re
import uuid
from datetime import datetime
from email import message_from_bytes
from email.header import decode_header, make_header
from pathlib import Path
import bleach

logger = logging.getLogger(__name__)

# ── Allowed types ──────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".eml", ""}          # empty = no extension provided
SUSPICIOUS_EXTS = {
    ".exe", ".js", ".vbs", ".bat", ".ps1", ".hta",
    ".msi", ".docm", ".xlsm", ".pptm", ".iso", ".img", ".scr",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────
_URL_RE = re.compile(r'https?://[^\s\'"<>)(\\]+|www\.[^\s\'"<>)(\\]+', re.I)
_IP_RE  = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_DOM_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')


# ── Helpers ────────────────────────────────────────────────────────────────────

def _decode(value: str) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _addr(field: str) -> tuple[str, str]:
    """Return (display_name, address)."""
    if not field:
        return "", ""
    field = field.strip()
    # Format: 'Display Name <addr@domain>' or '"Name" <addr>'
    m = re.match(r'^"?([^"<]*)"?\s*<([^>]*)>\s*$', field)
    if m:
        return m.group(1).strip().strip('"'), m.group(2).strip()
    # Bare address with no angle brackets
    return "", field


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


# ── Public API ─────────────────────────────────────────────────────────────────

def compute_sha256(data: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def validate_eml_upload(
    filename: str,
    content_type: str,
    data: bytes,
    max_size_bytes: int = 10 * 1024 * 1024,
) -> None:
    """
    Raise ValueError if the upload is invalid.
    Checks: size limit, file extension, and RFC-5322 header presence.
    """
    if len(data) > max_size_bytes:
        raise ValueError(
            f"File too large: {len(data):,} bytes (max {max_size_bytes // 1024 // 1024} MB)"
        )

    ext = Path(filename).suffix.lower() if filename else ""
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Invalid file extension '{ext}'. Expected .eml")

    # Must look like an RFC-5322 email (has at least one header line)
    try:
        sample = data[:512].decode("utf-8", errors="replace").lstrip()
    except Exception:
        raise ValueError("File is not readable as text")

    if not re.search(r'^[A-Za-z][A-Za-z0-9\-]+:\s', sample, re.MULTILINE):
        raise ValueError("File does not appear to be a valid RFC-5322 email")


def parse_eml(raw_bytes: bytes) -> dict:
    """
    Parse raw .eml bytes into a structured dict.
    Extracts headers, body (text + HTML), attachments.
    Never executes content.
    """
    msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)

    from_raw = _decode(msg.get("From", ""))
    from_name, from_addr = _addr(from_raw)
    _, reply_to  = _addr(_decode(msg.get("Reply-To", "")))
    _, sender    = _addr(_decode(msg.get("Sender", "")))
    _, ret_path  = _addr(_decode(msg.get("Return-Path", "")))

    # Build flat headers dict (multi-value → list)
    headers: dict = {}
    for key in msg.keys():
        k = key.lower()
        val = _decode(msg.get(key, ""))
        if k in headers:
            existing = headers[k]
            headers[k] = existing + [val] if isinstance(existing, list) else [existing, val]
        else:
            headers[k] = val

    body_text, body_html = _extract_body(msg)

    return {
        "from_address":      from_addr,
        "from_display_name": from_name,
        "to":                _decode(msg.get("To", "")),
        "cc":                _decode(msg.get("Cc", "")),
        "subject":           _decode(msg.get("Subject", "")),
        "date":              msg.get("Date", ""),
        "reply_to":          reply_to,
        "sender":            sender,
        "return_path":       ret_path,
        "message_id":        msg.get("Message-ID", ""),
        "mime_version":      msg.get("MIME-Version", ""),
        "content_type":      msg.get_content_type(),
        "auth_results":      msg.get("Authentication-Results", ""),
        "received_headers":  msg.get_all("Received") or [],
        "headers":           headers,
        "body_text":         body_text,
        "body_html":         body_html,
        "attachments":       _extract_attachments(msg),
    }


def _extract_body(msg) -> tuple[str, str]:
    text, html = "", ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if "attachment" in str(part.get("Content-Disposition", "")):
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                decoded = payload.decode(charset, errors="replace")
                if ct == "text/plain" and not text:
                    text = decoded
                elif ct == "text/html" and not html:
                    html = bleach.clean(decoded, tags=list(bleach.ALLOWED_TAGS) + ['p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'table', 'tr', 'td', 'th', 'img', 'a', 'style', 'ul', 'ol', 'li', 'html', 'body'], attributes={'*': ['style', 'class'], 'a': ['href', 'target'], 'img': ['src', 'alt']}, strip=True)
            except Exception:
                pass
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                decoded = payload.decode(charset, errors="replace")
                if msg.get_content_type() == "text/html":
                    html = bleach.clean(decoded, tags=list(bleach.ALLOWED_TAGS) + ['p', 'br', 'div', 'span', 'h1', 'h2', 'h3', 'table', 'tr', 'td', 'th', 'img', 'a', 'style', 'ul', 'ol', 'li', 'html', 'body'], attributes={'*': ['style', 'class'], 'a': ['href', 'target'], 'img': ['src', 'alt']}, strip=True)
                else:
                    text = decoded
        except Exception:
            pass
    return text, html


def _extract_attachments(msg) -> list[dict]:
    result = []
    if not msg.is_multipart():
        return result
    for part in msg.walk():
        if "attachment" not in str(part.get("Content-Disposition", "")):
            continue
        filename = _decode(part.get_filename() or "unknown")
        payload = part.get_payload(decode=True)
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
        result.append({
            "filename":     filename,
            "content_type": part.get_content_type(),
            "size_bytes":   len(payload) if payload else 0,
            "extension":    ext,
            "is_suspicious": ext in SUSPICIOUS_EXTS,
        })
    return result


def extract_iocs(parsed: dict) -> dict:
    """
    Extract URLs, public IPs, and domains from body and headers.
    No external requests or URL execution.
    """
    body = (parsed.get("body_text", "") or "") + "\n" + (parsed.get("body_html", "") or "")
    recv  = " ".join(parsed.get("received_headers", []))
    full  = body + "\n" + recv + "\n" + (parsed.get("auth_results", "") or "")

    urls    = list({u.rstrip(".,;)>\"'") for u in _URL_RE.findall(body)})
    ips     = list({ip for ip in _IP_RE.findall(full) if not _is_private(ip)})
    domains = list({
        d.lower() for d in _DOM_RE.findall(body + " " + recv)
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', d)
    })

    return {
        "urls":    urls[:100],
        "ips":     ips[:50],
        "domains": domains[:100],
    }


def store_evidence(email_id: str, raw_bytes: bytes, upload_dir: str) -> str:
    """Write the original .eml to disk unmodified. Returns storage path."""
    os.makedirs(upload_dir, exist_ok=True)
    path = os.path.join(upload_dir, f"{email_id}.eml")
    with open(path, "wb") as f:
        f.write(raw_bytes)
    logger.debug("Evidence stored: %s (%d bytes)", path, len(raw_bytes))
    return path


def ingest_email(
    raw_bytes: bytes,
    original_filename: str,
    upload_dir: str,
) -> dict:
    """
    Full Phase 2 ingestion pipeline:
      1. SHA-256 (immediately after read)
      2. Parse all headers and MIME body
      3. Extract IOCs (URLs, IPs, domains)
      4. Store original .eml as evidence (unmodified)
    """
    email_id = str(uuid.uuid4())
    sha256   = compute_sha256(raw_bytes)      # Step 1 — hash first
    parsed   = parse_eml(raw_bytes)           # Step 2 — parse
    iocs     = extract_iocs(parsed)           # Step 3 — IOC extraction
    path     = store_evidence(email_id, raw_bytes, upload_dir)  # Step 4

    return {
        "email_id":     email_id,
        "sha256":       sha256,
        "size":         len(raw_bytes),
        "filename":     original_filename,
        "storage_path": path,
        "parsed":       parsed,
        "iocs":         iocs,
        "ingested_at":  datetime.utcnow().isoformat(),
    }
