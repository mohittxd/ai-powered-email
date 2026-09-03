"""
Unit tests — Phase 2: email ingestion and parsing.
Run with: pytest tests/test_ingestion.py -v
"""
import hashlib
import os
import sys
import tempfile

import pytest

# Make sure backend root is on path when running from backend/
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.email_ingestor import (
    compute_sha256,
    extract_iocs,
    ingest_email,
    parse_eml,
    validate_eml_upload,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

SIMPLE_EML = b"""\
From: Alice <alice@example.com>
To: Bob <bob@example.org>
Cc: Charlie <charlie@example.net>
Subject: Hello World
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <simple001@example.com>
Reply-To: noreply@example.com
Return-Path: <bounce@example.com>
Sender: alice@example.com
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Plain text body. Visit http://example.com/path?q=1 for info.
Also see www.another.org/page here.
"""

MULTIPART_EML = b"""\
From: sender@test.com
To: recv@test.com
Subject: Multipart Test
Date: Tue, 02 Jan 2024 09:00:00 +0000
Message-ID: <multi001@test.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"
Authentication-Results: mx.google.com; spf=pass

--BOUND
Content-Type: text/plain; charset=utf-8

This is the text part.

--BOUND
Content-Type: text/html; charset=utf-8

<html><body><a href="http://malicious.io/phish">Click</a></body></html>

--BOUND
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="payload.exe"

MZFAKEEXEDATA

--BOUND--
"""

PHISHING_EML = b"""\
From: "PayPal" <security@paypa1.net>
To: victim@corp.com
Subject: URGENT: Verify your account
Date: Wed, 03 Jan 2024 08:00:00 +0000
Message-ID: <ph1sh@paypa1.net>
Received: from 91.108.4.1 (evil.host) by mx.corp.com
Received: from 77.88.21.3 by 91.108.4.1
Content-Type: text/plain; charset=utf-8

Click http://paypa1-verify.evil.ru/secure?token=abc123 now!
Also visit www.fake-bank.xyz/login
"""


# ── SHA-256 ───────────────────────────────────────────────────────────────────

class TestComputeSHA256:
    def test_known_value(self):
        assert compute_sha256(b"hello") == hashlib.sha256(b"hello").hexdigest()

    def test_empty_bytes(self):
        result = compute_sha256(b"")
        assert result == hashlib.sha256(b"").hexdigest()
        assert len(result) == 64

    def test_returns_lowercase_hex(self):
        result = compute_sha256(b"test")
        assert isinstance(result, str)
        assert result == result.lower()
        assert all(c in "0123456789abcdef" for c in result)

    def test_different_input_different_hash(self):
        assert compute_sha256(b"aaa") != compute_sha256(b"bbb")

    def test_deterministic(self):
        data = b"reproducible content"
        assert compute_sha256(data) == compute_sha256(data)

    def test_length_always_64(self):
        for payload in [b"x", b"x" * 1000, b"\x00\xff"]:
            assert len(compute_sha256(payload)) == 64


# ── Validation ────────────────────────────────────────────────────────────────

class TestValidateEmlUpload:
    MAX = 10 * 1024 * 1024

    def test_valid_eml(self):
        validate_eml_upload("email.eml", "message/rfc822", SIMPLE_EML, self.MAX)

    def test_no_extension_allowed(self):
        # No extension is accepted (client may omit it)
        validate_eml_upload("email", "message/rfc822", SIMPLE_EML, self.MAX)

    def test_too_large_raises(self):
        big = b"From: x\r\n\r\n" + b"a" * (self.MAX + 1)
        with pytest.raises(ValueError, match="too large"):
            validate_eml_upload("big.eml", "message/rfc822", big, self.MAX)

    def test_wrong_extension_raises(self):
        with pytest.raises(ValueError, match="extension"):
            validate_eml_upload("virus.exe", "application/octet-stream", SIMPLE_EML, self.MAX)

    def test_pdf_extension_raises(self):
        with pytest.raises(ValueError, match="extension"):
            validate_eml_upload("doc.pdf", "application/pdf", SIMPLE_EML, self.MAX)

    def test_binary_garbage_raises(self):
        garbage = bytes(range(256)) * 20  # no RFC-5322 headers
        with pytest.raises(ValueError):
            validate_eml_upload("bad.eml", "application/octet-stream", garbage, self.MAX)

    def test_exactly_at_limit_passes(self):
        # Build an eml that is exactly MAX bytes
        header = b"From: x@x.com\r\n\r\n"
        body = b"x" * (self.MAX - len(header))
        validate_eml_upload("exact.eml", "message/rfc822", header + body, self.MAX)


# ── Parsing ───────────────────────────────────────────────────────────────────

class TestParseEml:
    def setup_method(self):
        self.simple  = parse_eml(SIMPLE_EML)
        self.multi   = parse_eml(MULTIPART_EML)
        self.phish   = parse_eml(PHISHING_EML)

    # Headers
    def test_from_address(self):
        assert self.simple["from_address"] == "alice@example.com"

    def test_from_display_name(self):
        assert self.simple["from_display_name"] == "Alice"

    def test_to(self):
        assert "bob@example.org" in self.simple["to"]

    def test_cc(self):
        assert "charlie@example.net" in self.simple["cc"]

    def test_subject(self):
        assert self.simple["subject"] == "Hello World"

    def test_message_id(self):
        assert self.simple["message_id"] == "<simple001@example.com>"

    def test_reply_to(self):
        assert self.simple["reply_to"] == "noreply@example.com"

    def test_return_path(self):
        assert self.simple["return_path"] == "bounce@example.com"

    def test_mime_version(self):
        assert self.simple["mime_version"] == "1.0"

    def test_content_type(self):
        assert "text/plain" in self.simple["content_type"]

    def test_auth_results(self):
        assert "spf=pass" in self.multi["auth_results"]

    def test_received_headers_extracted(self):
        assert len(self.phish["received_headers"]) == 2

    def test_headers_dict_has_from(self):
        assert "from" in self.simple["headers"]

    def test_headers_dict_has_subject(self):
        assert "subject" in self.simple["headers"]

    # Body
    def test_plain_body(self):
        assert "Plain text body" in self.simple["body_text"]

    def test_multipart_text_body(self):
        assert "text part" in self.multi["body_text"]

    def test_multipart_html_body(self):
        assert "malicious.io" in self.multi["body_html"]

    def test_html_not_executed(self):
        # body_html is raw string, no side-effects
        assert isinstance(self.multi["body_html"], str)

    # Attachments
    def test_attachment_detected(self):
        assert len(self.multi["attachments"]) == 1

    def test_attachment_filename(self):
        assert self.multi["attachments"][0]["filename"] == "payload.exe"

    def test_attachment_flagged_suspicious(self):
        assert self.multi["attachments"][0]["is_suspicious"] is True

    def test_no_attachments_simple(self):
        assert self.simple["attachments"] == []


# ── IOC extraction ────────────────────────────────────────────────────────────

class TestExtractIOCs:
    def test_url_extracted(self):
        result = extract_iocs(parse_eml(SIMPLE_EML))
        assert any("example.com" in u for u in result["urls"])

    def test_multiple_urls(self):
        result = extract_iocs(parse_eml(PHISHING_EML))
        assert len(result["urls"]) >= 1

    def test_public_ip_extracted(self):
        result = extract_iocs(parse_eml(PHISHING_EML))
        # 203.0.113.42 and 198.51.100.5 are TEST-NET, not private
        assert len(result["ips"]) >= 1

    def test_private_ips_excluded(self):
        eml_with_private = PHISHING_EML + b"\nReceived: from 192.168.1.1 by mail.local\n"
        result = extract_iocs(parse_eml(eml_with_private))
        assert "192.168.1.1" not in result["ips"]

    def test_domains_extracted(self):
        result = extract_iocs(parse_eml(PHISHING_EML))
        assert len(result["domains"]) > 0

    def test_no_urls_in_plain_text_without_urls(self):
        eml = b"From: a@b.com\r\nSubject: hi\r\n\r\nNo links here."
        result = extract_iocs(parse_eml(eml))
        assert result["urls"] == []

    def test_url_trailing_punctuation_stripped(self):
        eml = b"From: a@b.com\r\nSubject: x\r\n\r\nSee http://test.io/path."
        result = extract_iocs(parse_eml(eml))
        assert all(not u.endswith(".") for u in result["urls"])


# ── Full ingestion pipeline ───────────────────────────────────────────────────

class TestIngestEmail:
    def test_returns_email_id(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert isinstance(result["email_id"], str)
        assert len(result["email_id"]) == 36  # UUID4

    def test_sha256_correct(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert result["sha256"] == hashlib.sha256(SIMPLE_EML).hexdigest()

    def test_size_correct(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert result["size"] == len(SIMPLE_EML)

    def test_evidence_file_written(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert os.path.exists(result["storage_path"])

    def test_evidence_file_unmodified(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        with open(result["storage_path"], "rb") as f:
            stored = f.read()
        assert stored == SIMPLE_EML  # byte-for-byte identical

    def test_evidence_sha256_matches(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        with open(result["storage_path"], "rb") as f:
            stored = f.read()
        assert hashlib.sha256(stored).hexdigest() == result["sha256"]

    def test_parsed_present(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert result["parsed"]["from_address"] == "alice@example.com"

    def test_iocs_present(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert "urls" in result["iocs"]
        assert "ips" in result["iocs"]
        assert "domains" in result["iocs"]

    def test_different_files_different_ids(self, tmp_path):
        r1 = ingest_email(SIMPLE_EML,   "a.eml", str(tmp_path))
        r2 = ingest_email(MULTIPART_EML,"b.eml", str(tmp_path))
        assert r1["email_id"] != r2["email_id"]
        assert r1["sha256"]   != r2["sha256"]

    def test_ingested_at_timestamp(self, tmp_path):
        result = ingest_email(SIMPLE_EML, "test.eml", str(tmp_path))
        assert "T" in result["ingested_at"]  # ISO format
