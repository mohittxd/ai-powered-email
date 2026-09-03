"""
Tests for Phase 17: Professional Forensic PDF Report Generation.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from main import app
from core.database import Base, engine
from services.pdf_generator import generate_forensic_pdf


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def test_pdf_generator_directly():
    sample_report = {
        "case_id": "test-case-12345",
        "analysis_timestamp": "2026-09-02T20:00:00Z",
        "evidence": {
            "filename": "phishing_sample.eml",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "size_bytes": 4096
        },
        "email": {
            "from": "attacker@fake-paypal.com",
            "to": "victim@corporate.com",
            "subject": "URGENT: Verify Your Billing Information Immediately",
            "reply_to": "scammer@gmail.com",
            "date": "Wed, 02 Sep 2026 12:00:00 -0400",
            "message_id": "<abcdef123456@mail.attacker.com>"
        },
        "authentication": {
            "spf": {"mta_reported": "FAIL", "domain": "fake-paypal.com"},
            "dkim": {"mta_reported": "FAIL"},
            "dmarc": {"mta_reported": "FAIL"}
        },
        "header_analysis": {
            "earliest_observed_public_ip": "185.220.101.5",
            "anomalies": [{"type": "REPLY_TO_MISMATCH", "detail": "Reply-To domain differs from From domain"}]
        },
        "geolocation": [{
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Tor Exit Node Network",
            "asn": "AS205100"
        }],
        "threat_intelligence": [{
            "abuse_score": 95,
            "status": "complete"
        }],
        "iocs": [
            {"type": "url", "value": "http://fake-paypal.com/verify?id=123", "severity": "critical"},
            {"type": "domain", "value": "fake-paypal.com", "severity": "high"}
        ],
        "risk_assessment": {
            "rule_based_score": 35,
            "ml_score": 95,
            "final_risk_score": 75,
            "classification": "IMPERSONATION",
            "confidence": "HIGH",
            "reasons": [
                "DMARC authentication failed for sender domain.",
                "Reply-To header mismatches envelope From address."
            ]
        },
        "limitations": [
            "This report is generated dynamically and may change if threat intelligence feeds update.",
            "Authentication results rely on SMTP envelope headers, which may be incomplete in .eml files."
        ]
    }

    pdf_bytes = generate_forensic_pdf(sample_report)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000
    print("✅ Direct PDF generation validated successfully.")


@pytest.mark.asyncio
async def test_case_pdf_report_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Create a case
        c_resp = await client.post("/api/v1/cases", json={"title": "PDF Test Case", "analyst_id": "analyst-001"})
        assert c_resp.status_code == 200
        case_id = c_resp.json()["id"]

        # Ingest an email
        eml_payload = (
            b"From: billing@paypal-update.com\r\n"
            b"To: target@company.com\r\n"
            b"Subject: URGENT Account Security Alert\r\n"
            b"Message-ID: <12345@phish.net>\r\n"
            b"Received: from mail.attacker.com (103.14.5.6) by mx.company.com; Wed, 02 Sep 2026 12:00:00 -0700\r\n\r\n"
            b"Please click http://bit.ly/login to restore access."
        )
        ingest_resp = await client.post(
            "/api/v1/analyze-email",
            files={"file": ("phish.eml", eml_payload, "message/rfc822")},
            data={"case_id": case_id}
        )
        assert ingest_resp.status_code == 200

        # Request Case PDF Report
        pdf_resp = await client.get(f"/api/v1/cases/{case_id}/report/pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
        assert pdf_resp.content.startswith(b"%PDF-")
        print("✅ Case PDF report endpoint GET /api/v1/cases/{case_id}/report/pdf validated!")


@pytest.mark.asyncio
async def test_email_pdf_report_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Ingest an email
        eml_payload = (
            b"From: support@bank-alert.com\r\n"
            b"To: target@company.com\r\n"
            b"Subject: Action Required\r\n\r\n"
            b"Check your account now."
        )
        ingest_resp = await client.post(
            "/api/v1/analyze-email",
            files={"file": ("test.eml", eml_payload, "message/rfc822")}
        )
        assert ingest_resp.status_code == 200
        email_id = ingest_resp.json()["email_id"]

        # Request Email PDF Report
        pdf_resp = await client.get(f"/api/v1/emails/{email_id}/report.pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers["content-type"] == "application/pdf"
        assert pdf_resp.content.startswith(b"%PDF-")
        print("✅ Email PDF report endpoint GET /api/v1/emails/{email_id}/report.pdf validated!")
