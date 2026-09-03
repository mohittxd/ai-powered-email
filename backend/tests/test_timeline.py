"""
Tests for Phase 22: Interactive Investigation Timeline.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from main import app
from core.database import Base, engine, AsyncSessionLocal
from core.models import Email, TraceHop, IOC, AuthenticationResult, AnalysisResult
from services.timeline import build_email_timeline


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_build_email_timeline():
    async with AsyncSessionLocal() as db:
        # Create Email sample with hops, iocs, auth
        e = Email(
            id="email-timeline-001",
            sha256_hash="e" * 64,
            from_address="spoofer@example.org",
            reply_to="stealer@example.net",
            subject="Urgent Payroll Account Update",
            fraud_score=0.88,
            classification="bec_fraud",
            spf_result="FAIL",
            dkim_result="FAIL",
            dmarc_result="FAIL"
        )
        db.add(e)

        h1 = TraceHop(
            email_id="email-timeline-001",
            hop_index=0,
            from_host="mail.example.org",
            by_host="mta.target.com",
            ip_address="198.51.100.25",
            country="United States",
            city="New York",
            isp="ExampleISP",
            asn="AS65534"
        )
        h2 = TraceHop(
            email_id="email-timeline-001",
            hop_index=1,
            from_host="relay.target.com",
            by_host="smtp.target.com",
            ip_address="198.51.100.26",
            country="United States",
            city="New York",
            isp="ExampleISP",
            asn="AS65534"
        )
        db.add_all([h1, h2])


        ioc1 = IOC(email_id="email-timeline-001", ioc_type="url", value="http://phish-site.example.net/login")
        db.add(ioc1)

        await db.commit()

        # Build timeline
        timeline = await build_email_timeline("email-timeline-001", db)

        assert timeline["email_id"] == "email-timeline-001"
        assert timeline["total_events"] == 11

        event_types = [evt["event_type"] for evt in timeline["events"]]
        expected_types = [
            "EMAIL_RECEIVED",
            "HEADER_HOP",
            "ORIGIN_INFRASTRUCTURE",
            "AUTHENTICATION_ANALYSIS",
            "IOC_EXTRACTION",
            "GEOIP_LOOKUP",
            "THREAT_INTELLIGENCE",
            "ML_ANALYSIS",
            "FINAL_RISK_ASSESSMENT",
            "REPORT_GENERATED"
        ]

        for etype in expected_types:
            assert etype in event_types, f"Missing event type: {etype}"

        # Verify evidence structure of authentication event
        auth_evt = next(evt for evt in timeline["events"] if evt["event_type"] == "AUTHENTICATION_ANALYSIS")
        assert auth_evt["status"] == "WARNING"
        assert auth_evt["relevant_evidence"]["spf"] == "FAIL"

        print("✅ Investigation timeline service test passed.")


@pytest.mark.asyncio
async def test_email_timeline_api_endpoint():
    async with AsyncSessionLocal() as db:
        e = Email(
            id="email-timeline-002",
            sha256_hash="f" * 64,
            from_address="user@example.com",
            subject="API Timeline Test Email",
            fraud_score=0.1,
            classification="legitimate"
        )
        db.add(e)
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        res = await client.get("/api/v1/emails/email-timeline-002/timeline")
        assert res.status_code == 200
        data = res.json()
        assert data["email_id"] == "email-timeline-002"
        assert len(data["events"]) >= 8
        assert "relevant_evidence" in data["events"][0]


        print("✅ Investigation timeline API endpoint test passed.")
