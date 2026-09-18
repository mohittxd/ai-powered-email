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
from core.rbac import hash_password
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
    from core.models import User

    async with AsyncSessionLocal() as db:
        # Seed a test user
        user = User(
            id="campaign-test-user",
            email="campaign_test@example.com",
            name="Campaign Test User",
            role="analyst",
            hashed_password=hash_password("testpass123"),
        )
        db.add(user)

        # Seed 2 correlated emails
        e1 = Email(id="e-001", sha256_hash="1" * 64, from_address="user1@campaign-phish.example.org", fraud_score=0.8, owner_id="campaign-test-user")
        e2 = Email(id="e-002", sha256_hash="2" * 64, from_address="user2@campaign-phish.example.org", fraud_score=0.85, owner_id="campaign-test-user")
        db.add_all([e1, e2])

        h1 = TraceHop(email_id="e-001", ip_address="198.51.100.99", asn="AS15169 Google")
        h2 = TraceHop(email_id="e-002", ip_address="198.51.100.99", asn="AS15169 Google")
        db.add_all([h1, h2])

        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Login to get auth token
        login_resp = await client.post("/api/v1/auth/register", json={
            "name": "Campaign Test User",
            "email": "campaign_test@example.com",
            "password": "testpass123",
        })
        if login_resp.status_code == 409:
            login_resp = await client.post("/api/v1/auth/login", json={
                "email": "campaign_test@example.com",
                "password": "testpass123",
            })
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. GET /api/v1/campaigns
        res = await client.get("/api/v1/campaigns", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["total_campaigns"] >= 1
        camp_id = data["campaigns"][0]["campaign_id"]
        assert "disclaimer" in data

        # 2. GET /api/v1/campaigns/summary
        sum_res = await client.get("/api/v1/campaigns/summary", headers=headers)
        assert sum_res.status_code == 200
        assert sum_res.json()["total_campaigns"] >= 1

        # 3. GET /api/v1/campaigns/{id}
        dtl_res = await client.get(f"/api/v1/campaigns/{camp_id}", headers=headers)
        assert dtl_res.status_code == 200
        camp_dtl = dtl_res.json()
        assert camp_dtl["campaign_id"] == camp_id
        assert len(camp_dtl["related_emails"]) == 2
        assert "graph_representation" in camp_dtl

        print("✅ Campaign correlation API endpoints verified.")


@pytest.mark.asyncio
async def test_campaign_correlation_handles_none_fraud_score():
    """Emails with fraud_score=None must not crash the graph builder."""
    async with AsyncSessionLocal() as db:
        e1 = Email(
            id="email-nfs-1",
            sha256_hash="n" * 64,
            from_address="sender1@example.com",
            fraud_score=None,
        )
        e2 = Email(
            id="email-nfs-2",
            sha256_hash="f" * 64,
            from_address="sender2@example.com",
            fraud_score=None,
        )
        db.add_all([e1, e2])

        i1 = IOC(
            email_id="email-nfs-1",
            ioc_type="domain",
            value="shared-phish.example.com",
        )
        i2 = IOC(
            email_id="email-nfs-2",
            ioc_type="domain",
            value="shared-phish.example.com",
        )
        db.add_all([i1, i2])

        await db.commit()

        G = await build_global_campaign_graph(db)
        assert isinstance(G, nx.Graph)
        assert G.number_of_nodes() > 0

        campaigns = compute_campaign_correlation(G)
        assert len(campaigns) >= 1
        assert campaigns[0]["email_count"] == 2
        print("✅ Campaign correlation handles None fraud_score without crashing.")


@pytest.mark.asyncio
async def test_unrelated_emails_not_grouped():
    """Emails with no shared infrastructure must not be grouped together."""
    async with AsyncSessionLocal() as db:
        e1 = Email(id="unrel-1", sha256_hash="u" * 64, from_address="alice@completely-different-a.com")
        e2 = Email(id="unrel-2", sha256_hash="n" * 64, from_address="bob@completely-different-b.com")
        db.add_all([e1, e2])

        h1 = TraceHop(email_id="unrel-1", ip_address="10.0.0.1", asn="AS11111 ISP_A")
        h2 = TraceHop(email_id="unrel-2", ip_address="10.0.0.2", asn="AS22222 ISP_B")
        db.add_all([h1, h2])

        i1 = IOC(email_id="unrel-1", ioc_type="url", value="http://a-only.example.com/phish")
        i2 = IOC(email_id="unrel-2", ioc_type="url", value="http://b-only.example.com/phish")
        db.add_all([i1, i2])

        await db.commit()

        G = await build_global_campaign_graph(db)
        campaigns = compute_campaign_correlation(G)

        for camp in campaigns:
            email_ids = {e["id"] for e in camp["related_emails"]}
            assert not ({"unrel-1"} <= email_ids and {"unrel-2"} <= email_ids), \
                "Unrelated emails were incorrectly grouped into the same campaign"

        print("✅ Unrelated emails with no shared IOCs are not grouped together.")


@pytest.mark.asyncio
async def test_owner_isolation():
    """Emails from different owners must not appear in the same campaign."""
    async with AsyncSessionLocal() as db:
        e1 = Email(id="own-1", sha256_hash="o1" * 32, from_address="x@shared-domain.com", owner_id="owner-A")
        e2 = Email(id="own-2", sha256_hash="o2" * 32, from_address="y@shared-domain.com", owner_id="owner-B")
        db.add_all([e1, e2])

        i1 = IOC(email_id="own-1", ioc_type="domain", value="shared-domain.com")
        i2 = IOC(email_id="own-2", ioc_type="domain", value="shared-domain.com")
        db.add_all([i1, i2])

        await db.commit()

        G_a = await build_global_campaign_graph(db, owner_id="owner-A")
        campaigns_a = compute_campaign_correlation(G_a)
        all_ids_a = {e["id"] for c in campaigns_a for e in c["related_emails"]}
        assert "own-2" not in all_ids_a

        G_b = await build_global_campaign_graph(db, owner_id="owner-B")
        campaigns_b = compute_campaign_correlation(G_b)
        all_ids_b = {e["id"] for c in campaigns_b for e in c["related_emails"]}
        assert "own-1" not in all_ids_b

        print("✅ Owner isolation verified — cross-owner emails never share campaigns.")


@pytest.mark.asyncio
async def test_campaign_endpoint_requires_auth():
    """Campaign endpoints must return 401 without a valid token."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        res = await client.get("/api/v1/campaigns")
        assert res.status_code == 401

        res = await client.get("/api/v1/campaigns/summary")
        assert res.status_code == 401

        res = await client.get("/api/v1/campaigns/CAMP-001")
        assert res.status_code == 401

        print("✅ Campaign endpoints reject unauthenticated requests.")


@pytest.mark.asyncio
async def test_campaign_response_schema():
    """Verify the campaign API response matches the schema expected by CampaignView.jsx."""
    from core.models import User

    async with AsyncSessionLocal() as db:
        user = User(
            id="schema-test-user",
            email="schema_test@example.com",
            name="Schema Test",
            role="analyst",
            hashed_password=hash_password("testpass123"),
        )
        db.add(user)

        e1 = Email(id="sch-1", sha256_hash="s1" * 32, from_address="a@test.com", owner_id="schema-test-user", fraud_score=0.7)
        e2 = Email(id="sch-2", sha256_hash="s2" * 32, from_address="b@test.com", owner_id="schema-test-user", fraud_score=0.9)
        db.add_all([e1, e2])

        h1 = TraceHop(email_id="sch-1", ip_address="192.0.2.1")
        h2 = TraceHop(email_id="sch-2", ip_address="192.0.2.1")
        db.add_all([h1, h2])

        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login_resp = await client.post("/api/v1/auth/register", json={
            "name": "Schema Test", "email": "schema_test@example.com", "password": "testpass123"
        })
        if login_resp.status_code == 409:
            login_resp = await client.post("/api/v1/auth/login", json={
                "email": "schema_test@example.com", "password": "testpass123"
            })
        token = login_resp.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}

        res = await client.get("/api/v1/campaigns", headers=h)
        assert res.status_code == 200
        data = res.json()

        # Top-level schema
        assert "total_campaigns" in data
        assert "campaigns" in data
        assert "disclaimer" in data
        assert isinstance(data["campaigns"], list)

        if data["campaigns"]:
            camp = data["campaigns"][0]
            # Required campaign fields per CampaignView.jsx
            for key in ("campaign_id", "campaign_name", "correlation_score",
                        "correlation_level", "avg_fraud_score", "email_count",
                        "related_emails", "shared_domains", "shared_ips",
                        "shared_urls", "shared_infrastructure", "graph_representation",
                        "attribution_disclaimer"):
                assert key in camp, f"Missing campaign field: {key}"

            # related_emails schema
            if camp["related_emails"]:
                re = camp["related_emails"][0]
                for key in ("id", "subject", "from_address", "fraud_score",
                            "classification", "analyzed_at"):
                    assert key in re, f"Missing related_email field: {key}"

            # graph_representation only has counts now (no full nodes/edges)
            gr = camp["graph_representation"]
            assert "node_count" in gr
            assert "edge_count" in gr
            assert isinstance(gr["node_count"], int)
            assert isinstance(gr["edge_count"], int)

        print("✅ Campaign response schema matches CampaignView.jsx expectations.")


@pytest.mark.asyncio
async def test_empty_campaign_result():
    """A single email with no peers must return zero campaigns, not crash."""
    async with AsyncSessionLocal() as db:
        e1 = Email(id="solo-1", sha256_hash="solo" * 16, from_address="lonely@example.com")
        db.add(e1)
        await db.commit()

        G = await build_global_campaign_graph(db)
        campaigns = compute_campaign_correlation(G)
        assert campaigns == []
        print("✅ Single email returns empty campaign list without crashing.")


@pytest.mark.asyncio
async def test_campaign_performance_regression():
    """Verify the optimized algorithm handles a representative 50-email fixture
    in under 5 seconds (old algorithm took minutes on this size)."""
    import time

    async with AsyncSessionLocal() as db:
        for i in range(50):
            e = Email(
                id=f"perf-{i}",
                sha256_hash=f"p{i:04d}".ljust(64, "x"),
                from_address=f"user{i}@shared-perf-domain.com",
                fraud_score=0.5,
                owner_id="perf-owner",
            )
            db.add(e)

        for i in range(50):
            h = TraceHop(email_id=f"perf-{i}", ip_address=f"10.0.{i // 10}.{i % 10}")
            db.add(h)
            ioc = IOC(email_id=f"perf-{i}", ioc_type="domain", value="shared-perf-domain.com")
            db.add(ioc)

        await db.commit()

        G = await build_global_campaign_graph(db, owner_id="perf-owner")
        assert G.number_of_nodes() > 50

        start = time.monotonic()
        campaigns = compute_campaign_correlation(G)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"Performance regression: took {elapsed:.1f}s for 50 emails (should be <5s)"
        assert len(campaigns) >= 1
        assert campaigns[0]["email_count"] == 50
        print(f"✅ Performance test passed: 50 emails clustered in {elapsed:.2f}s.")


@pytest.mark.asyncio
async def test_campaign_error_handling_returns_500_not_empty():
    """If the computation fails, the API should return 500, not silently return []."""
    from unittest.mock import AsyncMock, patch

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        login_resp = await client.post("/api/v1/auth/register", json={
            "name": "Err Test", "email": "err_test@example.com", "password": "testpass123"
        })
        if login_resp.status_code == 409:
            login_resp = await client.post("/api/v1/auth/login", json={
                "email": "err_test@example.com", "password": "testpass123"
            })
        token = login_resp.json()["access_token"]
        h = {"Authorization": f"Bearer {token}"}

        with patch("api.routes.campaigns.cluster_emails_by_iocs", side_effect=RuntimeError("DB connection lost")):
            res = await client.get("/api/v1/campaigns", headers=h)
            assert res.status_code == 500
            assert "detail" in res.json()

        print("✅ Campaign API returns 500 on internal error, not silent empty list.")
