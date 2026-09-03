"""
Email ingestion — parses raw .eml bytes or header strings into a structured dict.
"""
import email
import email.policy
import hashlib
import re
from email import message_from_bytes, message_from_string
from email.header import decode_header, make_header
from typing import Union
from bs4 import BeautifulSoup


def _decode_header_value(value: str) -> str:
    """Decode RFC2047-encoded header values."""
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _extract_email_address(field: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a From/To field."""
    if not field:
        return ("", "")
    match = re.match(r'^"?([^"<]*)"?\s*<?([^>]*)>?$', field.strip())
    if match:
        name = match.group(1).strip().strip('"')
        addr = match.group(2).strip()
        return (name, addr)
    return ("", field.strip())


def _extract_urls_from_text(text: str) -> list[str]:
    """Simple regex URL extractor for plain text."""
    if not text:
        return []
    pattern = r'https?://[^\s\'"<>)(\]]+|www\.[^\s\'"<>)(\]]+|ftp://[^\s\'"<>)(\]]+'
    return list(set(re.findall(pattern, text)))


def _extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from anchor href and img src in HTML."""
    if not html:
        return []
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    urls = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"]
        if href.startswith(("http", "ftp", "www")):
            urls.add(href)
    for tag in soup.find_all("img", src=True):
        src = tag["src"]
        if src.startswith(("http", "ftp")):
            urls.add(src)
    return list(urls)


def _get_body(msg) -> tuple[str, str]:
    """Walk MIME parts and return (body_text, body_html)."""
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if "attachment" in disposition:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(charset, errors="replace")
                if ct == "text/plain" and not body_text:
                    body_text = text
                elif ct == "text/html" and not body_html:
                    body_html = text
            except Exception:
                pass
    else:
        charset = msg.get_content_charset() or "utf-8"
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(charset, errors="replace")
                ct = msg.get_content_type()
                if ct == "text/html":
                    body_html = text
                else:
                    body_text = text
        except Exception:
            pass

    # If we have HTML but no plain text, strip tags for text version
    if body_html and not body_text:
        try:
            soup = BeautifulSoup(body_html, "lxml")
            body_text = soup.get_text(separator="\n", strip=True)
        except Exception:
            pass

    return body_text, body_html


def _get_attachments(msg) -> list[dict]:
    """Extract attachment metadata (no file write in prototype)."""
    attachments = []
    if not msg.is_multipart():
        return attachments
    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" in disposition:
            filename = part.get_filename() or "unknown"
            filename = _decode_header_value(filename)
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            # Flag suspicious extensions
            suspicious_exts = {
                ".exe", ".js", ".vbs", ".bat", ".ps1", ".hta", ".msi",
                ".docm", ".xlsm", ".pptm", ".iso", ".img", ".scr"
            }
            ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": size,
                "is_suspicious": ext in suspicious_exts,
                "extension": ext,
            })
    return attachments


def _compute_hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def parse_eml(raw: Union[bytes, str]) -> dict:
    """
    Parse a raw .eml (bytes or string) into a structured document dict.

    Returns a dict with keys:
      sha256_hash, raw_bytes, from_address, from_display_name, reply_to,
      return_path, message_id, subject, date_sent, body_text, body_html,
      attachments, embedded_urls, raw_headers, received_headers
    """
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
        msg = message_from_string(raw, policy=email.policy.compat32)
    else:
        raw_bytes = raw
        msg = message_from_bytes(raw, policy=email.policy.compat32)

    sha256 = _compute_hash(raw_bytes)

    # --- Core headers ---
    from_raw = _decode_header_value(msg.get("From", ""))
    from_name, from_addr = _extract_email_address(from_raw)

    reply_to_raw = _decode_header_value(msg.get("Reply-To", ""))
    _, reply_to = _extract_email_address(reply_to_raw)

    return_path_raw = _decode_header_value(msg.get("Return-Path", ""))
    _, return_path = _extract_email_address(return_path_raw)

    subject = _decode_header_value(msg.get("Subject", ""))
    date_sent = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")

    # --- Body ---
    body_text, body_html = _get_body(msg)

    # --- URLs ---
    urls_text = _extract_urls_from_text(body_text)
    urls_html = _extract_urls_from_html(body_html)
    embedded_urls = list(set(urls_text + urls_html))

    # --- Attachments ---
    attachments = _get_attachments(msg)

    # --- Received chain (raw strings, in order top→bottom) ---
    received_headers = msg.get_all("Received") or []

    # --- All headers as dict ---
    raw_headers = {}
    for key in set(msg.keys()):
        vals = msg.get_all(key)
        raw_headers[key] = vals if len(vals) > 1 else vals[0]

    return {
        "sha256_hash": sha256,
        "raw_bytes": raw_bytes,
        "from_address": from_addr,
        "from_display_name": from_name,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "subject": subject,
        "date_sent": date_sent,
        "body_text": body_text,
        "body_html": body_html,
        "attachments": attachments,
        "embedded_urls": embedded_urls,
        "raw_headers": raw_headers,
        "received_headers": received_headers,
    }
