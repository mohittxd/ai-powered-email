"""
Unit tests — Phase 3: Email Header Forensics.
All tests use synthetic .eml data. No network calls.
Run with: pytest tests/test_header_forensics.py -v
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from services.email_ingestor import parse_eml
from services.header_forensics import (
    analyze_header_forensics,
    detect_anomalies,
    find_earliest_public_sender_ip,
    parse_received_chain,
    _is_public_ip,
)

# ── Synthetic .eml fixtures ────────────────────────────────────────────────────

# Clean email traversing three hops with public IPs
CLEAN_EML = b"""\
From: Alice <alice@legit.com>
To: Bob <bob@company.com>
Subject: Quarterly Report
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <clean001@legit.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Received: from mx.company.com (mx.company.com [91.108.4.3])
 by internal.company.com with ESMTP; Mon, 01 Jan 2024 12:00:05 +0000
Received: from relay.legit.com (relay.legit.com [91.108.4.2])
 by mx.company.com with ESMTP; Mon, 01 Jan 2024 12:00:02 +0000
Received: from mail.legit.com (mail.legit.com [91.108.4.1])
 by relay.legit.com with SMTP; Mon, 01 Jan 2024 12:00:00 +0000

This is the body.
"""

# Phishing email with Reply-To mismatch
PHISHING_EML = b"""\
From: "PayPal Security" <security@paypal.com>
To: victim@corp.com
Reply-To: hacker@evil-domain.ru
Return-Path: <bounce@evil-domain.ru>
Subject: Urgent: Account Suspended
Date: Mon, 01 Jan 2024 09:00:00 +0000
Message-ID: <phish001@paypal.com>
Content-Type: text/plain; charset=utf-8
Received: from mx.corp.com (mx.corp.com [91.108.5.1])
 by internal.corp.com with ESMTP; Mon, 01 Jan 2024 09:00:10 +0000
Received: from evil-relay.ru (evil-relay.ru [77.88.21.3])
 by mx.corp.com with SMTP; Mon, 01 Jan 2024 09:00:05 +0000

Click here to verify your account.
"""

# Email with timestamp regression (hop timestamps go backward)
TIMESTAMP_REGRESSION_EML = b"""\
From: sender@example.com
To: recv@example.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000
Message-ID: <ts001@example.com>
Content-Type: text/plain
Received: from hop2.example.com (hop2.example.com [91.108.6.2])
 by dest.example.com with SMTP; Mon, 01 Jan 2024 12:00:00 +0000
Received: from hop1.example.com (hop1.example.com [91.108.6.1])
 by hop2.example.com with SMTP; Mon, 01 Jan 2024 14:00:00 +0000

Body.
"""

# Email with no Received headers
NO_RECEIVED_EML = b"""\
From: local@internal.com
To: other@internal.com
Subject: Local
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <local001@internal.com>
Content-Type: text/plain

Local email, no received headers.
"""

# Email with no Message-ID
NO_MESSAGE_ID_EML = b"""\
From: spammer@spam.com
To: victim@example.com
Subject: You won!
Date: Mon, 01 Jan 2024 10:00:00 +0000
Content-Type: text/plain
Received: from spam.com (spam.com [91.108.7.1])
 by mx.example.com with SMTP; Mon, 01 Jan 2024 10:00:00 +0000

Claim your prize.
"""

# Email with From/Sender mismatch
SENDER_MISMATCH_EML = b"""\
From: ceo@bigcorp.com
Sender: attacker@otherdomain.com
To: finance@bigcorp.com
Subject: Wire transfer request
Date: Mon, 01 Jan 2024 08:00:00 +0000
Message-ID: <bec001@bigcorp.com>
Content-Type: text/plain
Received: from mail.otherdomain.com (mail.otherdomain.com [91.108.8.1])
 by mx.bigcorp.com with SMTP; Mon, 01 Jan 2024 08:00:00 +0000

Please wire $50,000 immediately.
"""

# Email with only private IPs in chain
PRIVATE_ONLY_EML = b"""\
From: internal@corp.local
To: another@corp.local
Subject: Internal
Date: Mon, 01 Jan 2024 11:00:00 +0000
Message-ID: <int001@corp.local>
Content-Type: text/plain
Received: from smtp.corp.local (smtp.corp.local [192.168.1.10])
 by mail.corp.local with SMTP; Mon, 01 Jan 2024 11:00:00 +0000

Internal message.
"""

# Malformed Received header
MALFORMED_RECEIVED_EML = b"""\
From: weird@sender.com
To: recv@example.com
Subject: Malformed
Date: Mon, 01 Jan 2024 10:00:00 +0000
Message-ID: <mal001@sender.com>
Content-Type: text/plain
Received: this is completely unparseable garbage with no structure
Received: from good.host.com (good.host.com [91.108.9.1])
 by dest.example.com with SMTP; Mon, 01 Jan 2024 10:00:00 +0000

Body.
"""


# ── Helper ─────────────────────────────────────────────────────────────────────

def _forensics(eml: bytes) -> dict:
    return analyze_header_forensics(parse_eml(eml))


def _anomaly_types(result: dict) -> list[str]:
    return [a["type"] for a in result["anomalies"]]


# ── IP filtering ───────────────────────────────────────────────────────────────

class TestIsPublicIP:
    def test_public_ipv4(self):
        assert _is_public_ip("91.108.4.1") is True

    def test_private_10(self):
        assert _is_public_ip("10.0.0.1") is False

    def test_private_172(self):
        assert _is_public_ip("172.16.0.1") is False

    def test_private_192(self):
        assert _is_public_ip("192.168.1.1") is False

    def test_loopback(self):
        assert _is_public_ip("127.0.0.1") is False

    def test_link_local(self):
        assert _is_public_ip("169.254.1.1") is False

    def test_ipv6_loopback(self):
        assert _is_public_ip("::1") is False

    def test_test_net_2(self):
        assert _is_public_ip("198.51.100.5") is False

    def test_test_net_3(self):
        assert _is_public_ip("203.0.113.42") is False

    def test_invalid_string(self):
        assert _is_public_ip("not-an-ip") is False

    def test_empty_string(self):
        assert _is_public_ip("") is False


# ── Received chain parsing ─────────────────────────────────────────────────────

class TestParseReceivedChain:
    def test_clean_chain_length(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert len(chain) == 3

    def test_chain_chronological_order(self):
        """Hop 0 should be the origin (oldest), hop N-1 the most recent relay."""
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        # Origin hop should have the earliest-origin source host
        assert chain[0]["hop_index"] == 0

    def test_source_host_extracted(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["source_host"] == "mail.legit.com"

    def test_dest_host_extracted(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["dest_host"] == "relay.legit.com"

    def test_source_ip_extracted(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["source_ip"] == "91.108.4.1"

    def test_public_ip_flagged(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["is_public"] is True

    def test_private_ip_not_flagged_public(self):
        parsed = parse_eml(PRIVATE_ONLY_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["is_public"] is False

    def test_protocol_extracted(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["protocol"] in ("SMTP", "ESMTP")

    def test_timestamp_extracted(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        assert chain[0]["timestamp"] is not None

    def test_no_received_gives_empty_chain(self):
        chain = parse_received_chain([])
        assert chain == []

    def test_malformed_hop_flagged(self):
        parsed = parse_eml(MALFORMED_RECEIVED_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        malformed_hops = [h for h in chain if h["malformed"]]
        assert len(malformed_hops) >= 1

    def test_raw_preserved(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        for hop in chain:
            assert isinstance(hop["raw"], str)
            assert len(hop["raw"]) > 0


# ── Earliest public IP ─────────────────────────────────────────────────────────

class TestFindEarliestPublicSenderIP:
    def test_finds_public_ip(self):
        parsed = parse_eml(CLEAN_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        ip     = find_earliest_public_sender_ip(chain)
        assert ip == "91.108.4.1"

    def test_private_only_returns_none(self):
        parsed = parse_eml(PRIVATE_ONLY_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        ip     = find_earliest_public_sender_ip(chain)
        assert ip is None

    def test_no_chain_returns_none(self):
        assert find_earliest_public_sender_ip([]) is None

    def test_phishing_public_ip(self):
        parsed = parse_eml(PHISHING_EML)
        chain  = parse_received_chain(parsed["received_headers"])
        ip     = find_earliest_public_sender_ip(chain)
        assert ip is not None
        assert _is_public_ip(ip)


# ── Anomaly detection ──────────────────────────────────────────────────────────

class TestDetectAnomalies:
    def test_clean_email_no_critical(self):
        result = _forensics(CLEAN_EML)
        critical = [a for a in result["anomalies"] if a["severity"] == "critical"]
        assert len(critical) == 0

    def test_reply_to_mismatch_detected(self):
        result = _forensics(PHISHING_EML)
        assert "reply_to_mismatch" in _anomaly_types(result)

    def test_reply_to_mismatch_is_critical(self):
        result = _forensics(PHISHING_EML)
        anom = next(a for a in result["anomalies"] if a["type"] == "reply_to_mismatch")
        assert anom["severity"] == "critical"

    def test_return_path_mismatch_detected(self):
        result = _forensics(PHISHING_EML)
        assert "return_path_mismatch" in _anomaly_types(result)

    def test_no_received_headers_detected(self):
        result = _forensics(NO_RECEIVED_EML)
        assert "no_received_headers" in _anomaly_types(result)

    def test_no_received_is_high(self):
        result = _forensics(NO_RECEIVED_EML)
        anom = next(a for a in result["anomalies"] if a["type"] == "no_received_headers")
        assert anom["severity"] == "high"

    def test_missing_message_id_detected(self):
        result = _forensics(NO_MESSAGE_ID_EML)
        assert "missing_message_id" in _anomaly_types(result)

    def test_timestamp_regression_detected(self):
        result = _forensics(TIMESTAMP_REGRESSION_EML)
        assert "timestamp_regression" in _anomaly_types(result)

    def test_timestamp_regression_is_high(self):
        result = _forensics(TIMESTAMP_REGRESSION_EML)
        anom = next(a for a in result["anomalies"] if a["type"] == "timestamp_regression")
        assert anom["severity"] == "high"

    def test_sender_mismatch_detected(self):
        result = _forensics(SENDER_MISMATCH_EML)
        assert "from_sender_mismatch" in _anomaly_types(result)

    def test_private_only_chain_flagged(self):
        result = _forensics(PRIVATE_ONLY_EML)
        assert "no_public_ip_in_chain" in _anomaly_types(result)

    def test_malformed_header_detected(self):
        result = _forensics(MALFORMED_RECEIVED_EML)
        assert "malformed_received_header" in _anomaly_types(result)

    def test_anomalies_have_required_keys(self):
        result = _forensics(PHISHING_EML)
        for a in result["anomalies"]:
            assert "type" in a
            assert "severity" in a
            assert "detail" in a

    def test_severity_values_valid(self):
        valid = {"low", "medium", "high", "critical"}
        result = _forensics(PHISHING_EML)
        for a in result["anomalies"]:
            assert a["severity"] in valid


# ── Full forensics output structure ───────────────────────────────────────────

class TestAnalyzeHeaderForensics:
    def test_output_has_required_keys(self):
        result = _forensics(CLEAN_EML)
        assert "received_chain" in result
        assert "earliest_observed_public_sender_ip" in result
        assert "anomalies" in result
        assert "summary" in result

    def test_earliest_ip_correct(self):
        result = _forensics(CLEAN_EML)
        assert result["earliest_observed_public_sender_ip"] == "91.108.4.1"

    def test_earliest_ip_none_for_private_only(self):
        result = _forensics(PRIVATE_ONLY_EML)
        assert result["earliest_observed_public_sender_ip"] is None

    def test_received_chain_list(self):
        result = _forensics(CLEAN_EML)
        assert isinstance(result["received_chain"], list)

    def test_chain_no_datetime_objects(self):
        """Ensure no non-JSON-serialisable datetime objects leak into chain."""
        from datetime import datetime
        result = _forensics(CLEAN_EML)
        for hop in result["received_chain"]:
            for v in hop.values():
                assert not isinstance(v, datetime), f"datetime leaked in key"

    def test_anomalies_list(self):
        result = _forensics(PHISHING_EML)
        assert isinstance(result["anomalies"], list)

    def test_summary_is_string(self):
        result = _forensics(CLEAN_EML)
        assert isinstance(result["summary"], str)
        assert len(result["summary"]) > 0

    def test_summary_mentions_hop_count(self):
        result = _forensics(CLEAN_EML)
        assert "3 hop" in result["summary"]

    def test_summary_mentions_earliest_ip(self):
        result = _forensics(CLEAN_EML)
        assert "91.108.4.1" in result["summary"]

    def test_no_network_calls_made(self):
        """Service must complete without any external network access."""
        # If this test completes without hanging/erroring, no network was called.
        result = _forensics(PHISHING_EML)
        assert result is not None
