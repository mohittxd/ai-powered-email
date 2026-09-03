"""
Tests for Phase 21: NetworkX Campaign Correlation & Shared Infrastructure Graph.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
import networkx as nx

from main import app
from core.database import Base, engine, AsyncSessionLocal
from core.models import Email, TraceHop, IOC
from services.campaign_graph import build_global_campaign_graph, compute_campaign_correlation, ATTRIBUTION_DISCLAIMER


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_networkx_campaign_correlation_engine():
    async with AsyncSessionLocal() as db:
        # Create Email A
        e1 = Email(
            id="email-a",
            sha256_hash="a" * 64,
            from_address="attacker@example.com",
            reply_to="suspicious@example.net",
            subject="Phishing Campaign Email A",
            fraud_score=0.85,
            classification="phishing"
        )
        db.add(e1)

        # Create Email B sharing same IP and domain
        e2 = Email(
            id="email-b",
            sha256_hash="b" * 64,
            from_address="another@example.com",
            reply_to="suspicious@example.net",
            subject="Phishing Campaign Email B",
            fraud_score=0.90,
            classification="bec_fraud"
        )
        db.add(e2)

        # Trace hops sharing IP 203.0.113.50 and ASN AS13335
        h1 = TraceHop(email_id="email-a", ip_address="203.0.113.50", asn="AS13335 Cloudflare", isp="Cloudflare Inc")
        h2 = TraceHop(email_id="email-b", ip_address="203.0.113.50", asn="AS13335 Cloudflare", isp="Cloudflare Inc")
        db.add_all([h1, h2])

        # IOCs sharing URL
        i1 = IOC(email_id="email-a", ioc_type="url", value="http://login-phish.example.net/auth")
        i2 = IOC(email_id="email-b", ioc_type="url", value="http://login-phish.example.net/auth")
        db.add_all([i1, i2])

        await db.commit()

        # Build NetworkX graph
        G = await build_global_campaign_graph(db)

        # Verify NetworkX Graph instance
        assert isinstance(G, nx.Graph)
        assert G.number_of_nodes() > 5
        assert G.number_of_edges() > 5

        # Compute correlation clusters
        campaigns = compute_campaign_correlation(G)
        assert len(campaigns) >= 1

        camp = campaigns[0]
        assert camp["email_count"] == 2
        assert camp["correlation_score"] > 50
        assert "203.0.113.50" in camp["shared_ips"]
        assert "example.net" in camp["shared_domains"]
        assert "http://login-phish.example.net/auth" in camp["shared_urls"]
        assert any("AS13335" in infra or "Cloudflare" in infra for infra in camp["shared_infrastructure"])

        # Check attribution disclaimer
        assert "human authorship" in camp["attribution_disclaimer"].lower() or "structural correlations" in camp["attribution_disclaimer"].lower()
        print("✅ NetworkX campaign graph correlation engine passed.")


@pytest.mark.asyncio
async def test_campaign_correlation_api_endpoints():
    async with AsyncSessionLocal() as db:
        # Seed 2 correlated emails
        e1 = Email(id="e-001", sha256_hash="1" * 64, from_address="user1@campaign-phish.example.org", fraud_score=0.8)
        e2 = Email(id="e-002", sha256_hash="2" * 64, from_address="user2@campaign-phish.example.org", fraud_score=0.85)
        db.add_all([e1, e2])

        h1 = TraceHop(email_id="e-001", ip_address="198.51.100.99", asn="AS15169 Google")
        h2 = TraceHop(email_id="e-002", ip_address="198.51.100.99", asn="AS15169 Google")
        db.add_all([h1, h2])

        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. GET /api/v1/campaigns
        res = await client.get("/api/v1/campaigns")
        assert res.status_code == 200
        data = res.json()
        assert data["total_campaigns"] >= 1
        camp_id = data["campaigns"][0]["campaign_id"]
        assert "disclaimer" in data

        # 2. GET /api/v1/campaigns/summary
        sum_res = await client.get("/api/v1/campaigns/summary")
        assert sum_res.status_code == 200
        assert sum_res.json()["total_campaigns"] >= 1

        # 3. GET /api/v1/campaigns/{id}
        dtl_res = await client.get(f"/api/v1/campaigns/{camp_id}")
        assert dtl_res.status_code == 200
        camp_dtl = dtl_res.json()
        assert camp_dtl["campaign_id"] == camp_id
        assert len(camp_dtl["related_emails"]) == 2
        assert "graph_representation" in camp_dtl

        print("✅ Campaign correlation API endpoints verified.")
