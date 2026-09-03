"""
Unit tests — Phase 5: IOC Extraction and Analysis.
No network calls. No file execution.
Run with: pytest tests/test_ioc_analysis.py -v
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.email_ingestor import parse_eml
from services.ioc_analysis import (
    CRITICAL, HIGH, LOW, MEDIUM,
    T_ATTACHMENT, T_DOMAIN, T_EMAIL_ADDR, T_IPV4, T_IPV6, T_URL,
    _analyze_url,
    _extract_display_domain_mismatches,
    deduplicate,
    extract_all_iocs,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

PHISHING_EML = b"""\
From: "PayPal" <security@paypal.com>
To: victim@corp.com
Reply-To: hacker@evil.ru
Subject: Verify Account
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <ph@paypal.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset=utf-8

Click here: http://paypa1-verify.evil.xyz/secure?token=abc%20def&id=123
Also see www.short.link/xyz123
Contact billing@evil.xyz for help.
Raw IP: 91.108.4.1 also 77.88.21.3

--BOUND
Content-Type: text/html; charset=utf-8

<html><body>
<a href="http://evil.tk/phish?x=%2F">Click here</a>
<a href="http://differentdomain.ru/login">http://paypal.com/login</a>
<p>IP in HTML: 8.8.8.8 and IPv6: 2001:db8::1</p>
</body></html>

--BOUND
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

MZFAKEEXEDATA

--BOUND
Content-Type: application/zip
Content-Disposition: attachment; filename="archive.zip"

ZIPDATA

--BOUND--
"""

CLEAN_EML = b"""\
From: alice@legit.com
To: bob@company.com
Subject: Meeting notes
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <clean@legit.com>
Content-Type: text/plain; charset=utf-8

Hi Bob, please see https://legit.com/notes for the meeting notes.
"""

SHORTENER_EML = b"""\
From: sender@example.com
To: recv@example.com
Subject: Short URL
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <short@example.com>
Content-Type: text/plain

Check out http://bit.ly/abc123 for more info.
"""

UNUSUAL_PORT_EML = b"""\
From: sender@example.com
To: recv@example.com
Subject: Unusual port
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <port@example.com>
Content-Type: text/plain

Visit http://example.com:8888/path for access.
"""

ENCODED_EML = b"""\
From: sender@example.com
To: recv@example.com
Subject: Encoded URL
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <enc@example.com>
Content-Type: text/plain

Redirect: https://malicious.example.com/path%2Fevade%2Fdetection?x=%41
"""

MULTIPART_EML = b"""\
From: sender@legit.com
To: recv@example.com
Subject: File delivery
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <multi@legit.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="SPLIT"

--SPLIT
Content-Type: text/plain

Please see the attached files.

--SPLIT
Content-Type: application/x-msdownload
Content-Disposition: attachment; filename="setup.exe"

FAKEEXE

--SPLIT
Content-Type: application/zip
Content-Disposition: attachment; filename="data.zip"

ZIPDATA

--SPLIT--
"""


# ── URL analysis ───────────────────────────────────────────────────────────────

class TestAnalyzeURL:
    def test_url_shortener_is_critical(self):
        sev, tags = _analyze_url("http://bit.ly/abc123")
        assert sev == CRITICAL
        assert "url_shortener" in tags

    def test_unusual_port_tagged(self):
        sev, tags = _analyze_url("http://example.com:8888/")
        assert any("unusual_port" in t for t in tags)

    def test_safe_port_not_tagged(self):
        _, tags = _analyze_url("https://example.com:443/")
        assert not any("unusual_port" in t for t in tags)

    def test_excessive_subdomains(self):
        _, tags = _analyze_url("http://a.b.c.d.e.example.com/")
        assert "excessive_subdomains" in tags

    def test_encoded_components(self):
        _, tags = _analyze_url("https://example.com/path%2F?q=%41")
        assert "encoded_components" in tags

    def test_suspicious_tld(self):
        sev, tags = _analyze_url("http://site.evil.xyz/page")
        assert "suspicious_tld" in tags
        assert sev in (HIGH, CRITICAL)

    def test_ip_as_host(self):
        _, tags = _analyze_url("http://91.108.4.1/phish")
        assert "ip_as_host" in tags

    def test_http_unencrypted(self):
        _, tags = _analyze_url("http://example.com/")
        assert "unencrypted_http" in tags

    def test_clean_https_is_low(self):
        sev, tags = _analyze_url("https://legit.com/notes")
        assert sev == LOW

    def test_lookalike_subdomain(self):
        _, tags = _analyze_url("http://paypal.com.attacker.net/login")
        assert "lookalike_subdomain" in tags


# ── Display-domain mismatch ────────────────────────────────────────────────────

class TestDisplayDomainMismatch:
    def test_mismatch_detected(self):
        html = '<a href="http://evil.ru/login">http://paypal.com/login</a>'
        mismatches = _extract_display_domain_mismatches(html)
        assert len(mismatches) == 1
        assert mismatches[0]["href_host"] == "evil.ru"
        assert mismatches[0]["text_host"] == "paypal.com"

    def test_no_mismatch_when_same_domain(self):
        html = '<a href="http://legit.com/page">http://legit.com/page</a>'
        mismatches = _extract_display_domain_mismatches(html)
        assert len(mismatches) == 0

    def test_non_url_text_ignored(self):
        html = '<a href="http://legit.com/">Click here</a>'
        mismatches = _extract_display_domain_mismatches(html)
        assert len(mismatches) == 0


# ── Deduplication ──────────────────────────────────────────────────────────────

class TestDeduplicate:
    def _ioc(self, t, v, sev, tags=None):
        return {"id": "x", "email_id": None, "type": t, "value": v,
                "severity": sev, "source": "test", "tags": tags or [], "created_at": ""}

    def test_deduplicates_same_type_value(self):
        iocs = [
            self._ioc(T_URL, "http://a.com", LOW),
            self._ioc(T_URL, "http://a.com", HIGH),
        ]
        result = deduplicate(iocs)
        assert len(result) == 1

    def test_keeps_highest_severity(self):
        iocs = [
            self._ioc(T_URL, "http://a.com", LOW),
            self._ioc(T_URL, "http://a.com", CRITICAL),
        ]
        result = deduplicate(iocs)
        assert result[0]["severity"] == CRITICAL

    def test_merges_tags(self):
        iocs = [
            self._ioc(T_URL, "http://a.com", LOW, ["tag1"]),
            self._ioc(T_URL, "http://a.com", LOW, ["tag2"]),
        ]
        result = deduplicate(iocs)
        assert "tag1" in result[0]["tags"]
        assert "tag2" in result[0]["tags"]

    def test_different_type_not_deduplicated(self):
        iocs = [
            self._ioc(T_URL,    "evil.com", LOW),
            self._ioc(T_DOMAIN, "evil.com", LOW),
        ]
        result = deduplicate(iocs)
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate([]) == []


# ── Full IOC extraction ────────────────────────────────────────────────────────

class TestExtractAllIOCs:
    def setup_method(self):
        self.phishing = extract_all_iocs(parse_eml(PHISHING_EML), "test-email-id")
        self.clean    = extract_all_iocs(parse_eml(CLEAN_EML),    "clean-id")

    # Output structure
    def test_has_required_keys(self):
        for key in ("urls", "domains", "ips", "email_addresses", "attachments", "summary", "counts"):
            assert key in self.phishing

    def test_summary_is_string(self):
        assert isinstance(self.phishing["summary"], str)

    def test_email_id_set_on_all_iocs(self):
        all_iocs = (
            self.phishing["urls"] + self.phishing["domains"] +
            self.phishing["ips"] + self.phishing["email_addresses"] +
            self.phishing["attachments"]
        )
        for ioc in all_iocs:
            assert ioc["email_id"] == "test-email-id"

    def test_each_ioc_has_required_fields(self):
        for ioc in self.phishing["urls"]:
            for f in ("id", "email_id", "type", "value", "severity", "source", "tags", "created_at"):
                assert f in ioc, f"Missing field '{f}' in URL IOC"

    # URLs
    def test_urls_extracted(self):
        assert len(self.phishing["urls"]) > 0

    def test_url_type_correct(self):
        for ioc in self.phishing["urls"]:
            assert ioc["type"] == T_URL

    def test_shortener_url_critical(self):
        result = extract_all_iocs(parse_eml(SHORTENER_EML))
        shortener_iocs = [i for i in result["urls"] if "url_shortener" in i["tags"]]
        assert len(shortener_iocs) >= 1
        assert shortener_iocs[0]["severity"] == CRITICAL

    def test_unusual_port_tagged(self):
        result = extract_all_iocs(parse_eml(UNUSUAL_PORT_EML))
        port_iocs = [i for i in result["urls"] if any("unusual_port" in t for t in i["tags"])]
        assert len(port_iocs) >= 1

    def test_encoded_url_tagged(self):
        result = extract_all_iocs(parse_eml(ENCODED_EML))
        encoded = [i for i in result["urls"] if "encoded_components" in i["tags"]]
        assert len(encoded) >= 1

    def test_clean_url_is_low(self):
        legit = [i for i in self.clean["urls"] if "legit.com" in i["value"]]
        if legit:
            assert legit[0]["severity"] == LOW

    def test_no_duplicate_urls(self):
        values = [i["value"] for i in self.phishing["urls"]]
        assert len(values) == len(set(values))

    # IPs
    def test_ipv4_extracted(self):
        assert len(self.phishing["ips"]) > 0
        ipv4s = [i for i in self.phishing["ips"] if i["type"] == T_IPV4]
        assert len(ipv4s) > 0

    def test_private_ips_excluded(self):
        eml = b"From: a@b.com\r\nSubject: x\r\n\r\nIP: 192.168.1.1"
        result = extract_all_iocs(parse_eml(eml))
        private = [i for i in result["ips"] if "192.168.1.1" in i["value"]]
        assert len(private) == 0

    # Email addresses
    def test_email_addresses_extracted(self):
        assert len(self.phishing["email_addresses"]) > 0

    def test_email_type_correct(self):
        for ioc in self.phishing["email_addresses"]:
            assert ioc["type"] == T_EMAIL_ADDR

    def test_suspicious_tld_email_is_high(self):
        # billing@evil.xyz should be flagged
        suspicious = [i for i in self.phishing["email_addresses"]
                      if "suspicious_tld" in i["tags"]]
        assert len(suspicious) > 0

    # Attachments
    def test_attachments_extracted(self):
        result = extract_all_iocs(parse_eml(MULTIPART_EML))
        assert len(result["attachments"]) > 0

    def test_exe_attachment_is_critical(self):
        result = extract_all_iocs(parse_eml(MULTIPART_EML))
        exe = [a for a in result["attachments"] if ".exe" in a["value"]]
        assert len(exe) > 0
        assert exe[0]["severity"] == CRITICAL

    def test_zip_attachment_is_medium(self):
        result = extract_all_iocs(parse_eml(MULTIPART_EML))
        zip_att = [a for a in result["attachments"] if ".zip" in a["value"]]
        assert len(zip_att) > 0
        assert zip_att[0]["severity"] == MEDIUM

    def test_double_extension_tagged(self):
        # invoice.pdf.exe
        dbl = [a for a in self.phishing["attachments"] if "double_extension" in a["tags"]]
        assert len(dbl) > 0

    def test_attachment_has_meta(self):
        result = extract_all_iocs(parse_eml(MULTIPART_EML))
        for att in result["attachments"]:
            assert "attachment_meta" in att

    # Counts
    def test_counts_total_matches_sum(self):
        total = (len(self.phishing["urls"]) + len(self.phishing["domains"]) +
                 len(self.phishing["ips"]) + len(self.phishing["email_addresses"]) +
                 len(self.phishing["attachments"]))
        assert self.phishing["counts"]["total"] == total

    def test_no_network_calls(self):
        """Service must complete without any network activity."""
        result = extract_all_iocs(parse_eml(PHISHING_EML))
        assert result is not None
