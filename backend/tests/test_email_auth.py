"""
Unit tests — Phase 4: Email Authentication Analysis (SPF, DKIM, DMARC).
DNS calls are mocked throughout. No real network requests are made.
Run with: pytest tests/test_email_auth.py -v
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.email_ingestor import parse_eml
from services.email_auth import (
    FAIL, NONE_STATUS, PASS, SOFTFAIL, NEUTRAL, UNAVAILABLE, UNKNOWN,
    _domains_aligned, _evaluate_spf_record, _parse_dkim_signature,
    _parse_dmarc_tags, analyze_authentication, analyze_dkim, analyze_dmarc,
    analyze_spf,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────

LEGIT_EML = b"""\
From: alice@legit.com
To: bob@company.com
Subject: Quarterly Report
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <legit001@legit.com>
DKIM-Signature: v=1; a=rsa-sha256; d=legit.com; s=mail2024;
 h=from:to:subject:date; bh=abc123==; b=FAKESIG==
Content-Type: text/plain

Body text here.
"""

PHISHING_EML = b"""\
From: "PayPal" <security@paypal.com>
To: victim@corp.com
Reply-To: hacker@evil.ru
Subject: Urgent
Date: Mon, 01 Jan 2024 08:00:00 +0000
Message-ID: <ph@paypal.com>
Content-Type: text/plain
Authentication-Results: mx.corp.com; spf=fail; dkim=none; dmarc=fail

Click to verify.
"""

NO_DKIM_EML = b"""\
From: sender@nodkim.com
To: recv@example.com
Subject: No DKIM
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <nodkim001@nodkim.com>
Content-Type: text/plain

No DKIM-Signature header.
"""

AUTH_RESULTS_EML = b"""\
From: alice@legit.com
To: bob@company.com
Subject: With Auth Results
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <auth001@legit.com>
Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=legit.com;
 dkim=pass header.d=legit.com; dmarc=pass
Content-Type: text/plain

Body.
"""


# ── SPF helpers ────────────────────────────────────────────────────────────────

class TestEvaluateSPFRecord:
    def test_ip4_exact_match(self):
        status, _ = _evaluate_spf_record("v=spf1 ip4:1.2.3.4 -all", "1.2.3.4")
        assert status == PASS

    def test_ip4_cidr_match(self):
        status, _ = _evaluate_spf_record("v=spf1 ip4:1.2.3.0/24 -all", "1.2.3.99")
        assert status == PASS

    def test_ip4_no_match_hard_fail(self):
        status, _ = _evaluate_spf_record("v=spf1 ip4:1.2.3.0/24 -all", "9.9.9.9")
        assert status == FAIL

    def test_ip4_no_match_soft_fail(self):
        status, _ = _evaluate_spf_record("v=spf1 ip4:1.2.3.0/24 ~all", "9.9.9.9")
        assert status == SOFTFAIL

    def test_neutral_all(self):
        status, _ = _evaluate_spf_record("v=spf1 ip4:1.2.3.0/24 ?all", "9.9.9.9")
        assert status == NEUTRAL

    def test_plus_all(self):
        status, _ = _evaluate_spf_record("v=spf1 +all", "1.2.3.4")
        assert status == PASS

    def test_no_sender_ip(self):
        status, detail = _evaluate_spf_record("v=spf1 ip4:1.2.3.4 -all", None)
        assert status == UNKNOWN
        assert "no sender ip" in detail.lower()

    def test_complex_mechanisms_unknown(self):
        # include: requires recursive DNS — must return UNKNOWN not FAIL
        status, detail = _evaluate_spf_record("v=spf1 include:_spf.google.com -all", "9.9.9.9")
        assert status == UNKNOWN
        assert "include" in detail.lower() or "recursive" in detail.lower()


class TestAnalyzeSPF:
    def test_no_spf_record(self):
        with patch("services.email_auth._get_spf_record", return_value=None):
            result = analyze_spf("example.com", "1.2.3.4")
        assert result["status"] == NONE_STATUS
        assert result["record"] is None

    def test_spf_pass(self):
        with patch("services.email_auth._get_spf_record", return_value="v=spf1 ip4:1.2.3.4 -all"):
            result = analyze_spf("example.com", "1.2.3.4")
        assert result["status"] == PASS

    def test_spf_fail(self):
        with patch("services.email_auth._get_spf_record", return_value="v=spf1 ip4:1.2.3.4 -all"):
            result = analyze_spf("example.com", "9.9.9.9")
        assert result["status"] == FAIL

    def test_no_domain(self):
        result = analyze_spf("", "1.2.3.4")
        assert result["status"] == NONE_STATUS

    def test_record_in_result(self):
        record = "v=spf1 ip4:1.0.0.0/8 -all"
        with patch("services.email_auth._get_spf_record", return_value=record):
            result = analyze_spf("example.com", "1.2.3.4")
        assert result["record"] == record

    def test_mta_reported_extracted(self):
        with patch("services.email_auth._get_spf_record", return_value=None):
            result = analyze_spf("example.com", "1.2.3.4", "mx.example.com; spf=pass")
        assert result["mta_reported"] == "PASS"

    def test_note_is_present(self):
        with patch("services.email_auth._get_spf_record", return_value=None):
            result = analyze_spf("example.com")
        assert "note" in result
        assert len(result["note"]) > 0

    def test_domain_in_result(self):
        with patch("services.email_auth._get_spf_record", return_value=None):
            result = analyze_spf("target.com")
        assert result["domain"] == "target.com"


# ── DKIM ───────────────────────────────────────────────────────────────────────

class TestParseDKIMSignature:
    def test_extracts_d(self):
        sig = "v=1; a=rsa-sha256; d=example.com; s=mail;"
        tags = _parse_dkim_signature(sig)
        assert tags["d"] == "example.com"

    def test_extracts_s(self):
        sig = "v=1; a=rsa-sha256; d=example.com; s=selector1;"
        tags = _parse_dkim_signature(sig)
        assert tags["s"] == "selector1"

    def test_empty_string(self):
        assert _parse_dkim_signature("") == {}


class TestAnalyzeDKIM:
    def test_no_dkim_signature(self):
        parsed = parse_eml(NO_DKIM_EML)
        result = analyze_dkim(NO_DKIM_EML, parsed)
        assert result["status"] == NONE_STATUS
        assert result["signing_domain"] is None

    def test_dkim_signature_detected(self):
        parsed = parse_eml(LEGIT_EML)
        with patch("services.email_auth._get_dkim_pubkey_record", return_value=None):
            result = analyze_dkim(LEGIT_EML, parsed)
        assert result["signing_domain"] == "legit.com"
        assert result["selector"] == "mail2024"

    def test_no_pubkey_returns_unavailable_not_fail(self):
        parsed = parse_eml(LEGIT_EML)
        with patch("services.email_auth._get_dkim_pubkey_record", return_value=None):
            result = analyze_dkim(LEGIT_EML, parsed)
        assert result["status"] == UNAVAILABLE
        assert result["status"] != FAIL   # critical: must not be FAIL

    def test_pubkey_found_dkimpy_pass(self):
        parsed = parse_eml(LEGIT_EML)
        with patch("services.email_auth._get_dkim_pubkey_record", return_value="p=FAKEKEY"):
            with patch("dkim.verify", return_value=True):
                result = analyze_dkim(LEGIT_EML, parsed)
        assert result["status"] == PASS
        assert result["pubkey_found"] is True

    def test_pubkey_found_dkimpy_fail(self):
        parsed = parse_eml(LEGIT_EML)
        with patch("services.email_auth._get_dkim_pubkey_record", return_value="p=FAKEKEY"):
            with patch("dkim.verify", return_value=False):
                result = analyze_dkim(LEGIT_EML, parsed)
        assert result["status"] == FAIL

    def test_dkimpy_exception_returns_unavailable(self):
        parsed = parse_eml(LEGIT_EML)
        with patch("services.email_auth._get_dkim_pubkey_record", return_value="p=FAKEKEY"):
            with patch("dkim.verify", side_effect=Exception("DNS timeout")):
                result = analyze_dkim(LEGIT_EML, parsed)
        assert result["status"] == UNAVAILABLE
        assert result["status"] != FAIL

    def test_mta_reported_extracted(self):
        parsed = parse_eml(AUTH_RESULTS_EML)
        with patch("services.email_auth._get_dkim_pubkey_record", return_value=None):
            result = analyze_dkim(AUTH_RESULTS_EML, parsed)
        assert result["mta_reported"] == "PASS"

    def test_result_has_required_keys(self):
        parsed = parse_eml(NO_DKIM_EML)
        result = analyze_dkim(NO_DKIM_EML, parsed)
        for key in ("status", "signing_domain", "selector", "detail", "mta_reported", "pubkey_found"):
            assert key in result


# ── DMARC ──────────────────────────────────────────────────────────────────────

class TestParseDMARCTags:
    def test_parses_policy(self):
        record = "v=DMARC1; p=reject; adkim=s; aspf=r;"
        tags = _parse_dmarc_tags(record)
        assert tags["p"] == "reject"

    def test_parses_adkim(self):
        record = "v=DMARC1; p=quarantine; adkim=s;"
        tags = _parse_dmarc_tags(record)
        assert tags["adkim"] == "s"


class TestDomainsAligned:
    def test_strict_exact_match(self):
        assert _domains_aligned("legit.com", "legit.com", strict=True) is True

    def test_strict_subdomain_fails(self):
        assert _domains_aligned("mail.legit.com", "legit.com", strict=True) is False

    def test_relaxed_subdomain_passes(self):
        assert _domains_aligned("mail.legit.com", "legit.com", strict=False) is True

    def test_relaxed_different_domains(self):
        assert _domains_aligned("evil.com", "legit.com", strict=False) is False

    def test_none_domain_false(self):
        assert _domains_aligned(None, "legit.com", strict=False) is False


class TestAnalyzeDMARC:
    def test_no_dmarc_record(self):
        with patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_dmarc("example.com", PASS, "example.com", PASS, "example.com")
        assert result["status"] == NONE_STATUS

    def test_dmarc_pass_both_aligned(self):
        record = "v=DMARC1; p=reject; adkim=r; aspf=r;"
        with patch("services.email_auth._get_dmarc_record", return_value=record):
            result = analyze_dmarc(
                from_domain="legit.com",
                spf_status=PASS, spf_domain="legit.com",
                dkim_status=PASS, dkim_signing_domain="legit.com",
            )
        assert result["status"] == PASS

    def test_dmarc_fail_no_alignment(self):
        record = "v=DMARC1; p=reject;"
        with patch("services.email_auth._get_dmarc_record", return_value=record):
            result = analyze_dmarc(
                from_domain="legit.com",
                spf_status=FAIL, spf_domain=None,
                dkim_status=FAIL, dkim_signing_domain="evil.com",
            )
        assert result["status"] == FAIL

    def test_unavailable_when_both_unknown(self):
        record = "v=DMARC1; p=quarantine;"
        with patch("services.email_auth._get_dmarc_record", return_value=record):
            result = analyze_dmarc(
                from_domain="legit.com",
                spf_status=UNAVAILABLE, spf_domain=None,
                dkim_status=UNAVAILABLE, dkim_signing_domain="legit.com",
            )
        assert result["status"] == UNAVAILABLE

    def test_policy_parsed(self):
        record = "v=DMARC1; p=quarantine; adkim=r;"
        with patch("services.email_auth._get_dmarc_record", return_value=record):
            result = analyze_dmarc("legit.com", PASS, "legit.com", PASS, "legit.com")
        assert result["policy"] == "quarantine"

    def test_mta_reported_extracted(self):
        with patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_dmarc(
                from_domain="legit.com",
                spf_status=PASS, spf_domain="legit.com",
                dkim_status=PASS, dkim_signing_domain="legit.com",
                auth_results_header="mx.example.com; dmarc=pass",
            )
        assert result["mta_reported"] == "PASS"

    def test_note_is_present(self):
        with patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_dmarc("legit.com", NONE_STATUS, None, NONE_STATUS, None)
        assert "note" in result and len(result["note"]) > 0

    def test_result_has_required_keys(self):
        with patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_dmarc("legit.com", PASS, "legit.com", PASS, "legit.com")
        for key in ("status", "policy", "record", "domain", "spf_aligned", "dkim_aligned", "detail", "note"):
            assert key in result


# ── Full authentication pipeline ──────────────────────────────────────────────

class TestAnalyzeAuthentication:
    def test_output_has_required_keys(self):
        parsed = parse_eml(NO_DKIM_EML)
        with patch("services.email_auth._get_spf_record", return_value=None), \
             patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_authentication(NO_DKIM_EML, parsed)
        for key in ("spf", "dkim", "dmarc", "summary"):
            assert key in result

    def test_summary_is_string(self):
        parsed = parse_eml(NO_DKIM_EML)
        with patch("services.email_auth._get_spf_record", return_value=None), \
             patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_authentication(NO_DKIM_EML, parsed)
        assert isinstance(result["summary"], str)

    def test_mta_reported_surfaced(self):
        parsed = parse_eml(AUTH_RESULTS_EML)
        with patch("services.email_auth._get_spf_record", return_value=None), \
             patch("services.email_auth._get_dmarc_record", return_value=None), \
             patch("services.email_auth._get_dkim_pubkey_record", return_value=None):
            result = analyze_authentication(AUTH_RESULTS_EML, parsed)
        # MTA reported pass for all three — should be surfaced
        assert result["spf"]["mta_reported"] == "PASS"
        assert result["dkim"]["mta_reported"] == "PASS"
        assert result["dmarc"]["mta_reported"] == "PASS"

    def test_phishing_spf_fail_in_auth_results(self):
        parsed = parse_eml(PHISHING_EML)
        with patch("services.email_auth._get_spf_record", return_value=None), \
             patch("services.email_auth._get_dmarc_record", return_value=None):
            result = analyze_authentication(PHISHING_EML, parsed)
        assert result["spf"]["mta_reported"] == "FAIL"

    def test_no_network_calls_when_mocked(self):
        """Verify the pipeline completes with only mocked DNS."""
        parsed = parse_eml(LEGIT_EML)
        with patch("services.email_auth._get_spf_record", return_value="v=spf1 ip4:91.0.0.0/8 -all"), \
             patch("services.email_auth._get_dmarc_record", return_value="v=DMARC1; p=reject;"), \
             patch("services.email_auth._get_dkim_pubkey_record", return_value="p=FAKEKEY"), \
             patch("dkim.verify", return_value=True):
            result = analyze_authentication(LEGIT_EML, parsed, earliest_public_sender_ip="91.108.4.1")
        assert result["spf"]["status"]  == PASS
        assert result["dkim"]["status"] == PASS
        assert result["dmarc"]["status"] == PASS
        assert "PASS" in result["summary"]
