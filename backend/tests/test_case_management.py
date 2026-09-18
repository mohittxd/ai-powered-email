import pytest
from httpx import AsyncClient, ASGITransport
from main import app
from core.database import Base, engine, AsyncSessionLocal
from core.models import Case, Email, TraceHop
from core.rbac import hash_password
import uuid

import pytest_asyncio

@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

@pytest.mark.asyncio
async def test_case_creation_and_search(client):
    from core.models import User

    async with AsyncSessionLocal() as db:
        user = User(
            id="case-test-user",
            email="case_test@example.com",
            name="Case Test User",
            role="analyst",
            hashed_password=hash_password("testpass123"),
        )
        db.add(user)
        await db.commit()

    login_resp = await client.post("/api/v1/auth/register", json={
        "name": "Case Test User",
        "email": "case_test@example.com",
        "password": "testpass123",
    })
    if login_resp.status_code == 409:
        login_resp = await client.post("/api/v1/auth/login", json={
            "email": "case_test@example.com",
            "password": "testpass123",
        })
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create Case
    res = await client.post("/api/v1/cases", json={"title": "Test BEC Case"}, headers=headers)
    assert res.status_code == 200
    case_id = res.json()["id"]

    # Insert an email with trace hops via direct DB insert to test filtering
    async with AsyncSessionLocal() as db:
        new_case = Case(id=str(uuid.uuid4()), title="Phishing Campaign", analyst_id="case-test-user")
        db.add(new_case)
        
        email = Email(
            id=str(uuid.uuid4()),
            case_id=new_case.id,
            sha256_hash="abcdef",
            from_address="attacker@evil.com",
            classification="phishing"
        )
        db.add(email)
        
        hop = TraceHop(
            id=str(uuid.uuid4()),
            email_id=email.id,
            ip_address="8.8.8.8"
        )
        db.add(hop)
        await db.commit()

    # Search by Title/ID (q)
    res = await client.get("/api/v1/cases?q=Phishing", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) == 1
    assert data[0]["title"] == "Phishing Campaign"

    # Search by sender
    res = await client.get("/api/v1/cases?sender=attacker@evil.com", headers=headers)
    assert len(res.json()) == 1
    
    # Search by domain
    res = await client.get("/api/v1/cases?domain=evil.com", headers=headers)
    assert len(res.json()) == 1
    
    # Search by IP
    res = await client.get("/api/v1/cases?ip=8.8.8.8", headers=headers)
    assert len(res.json()) == 1
    
    # Search by classification
    res = await client.get("/api/v1/cases?classification=phishing", headers=headers)
    assert len(res.json()) == 1

    # Search by classification (no match)
    res = await client.get("/api/v1/cases?classification=legitimate", headers=headers)
    assert len(res.json()) == 0

    # Get Single Case
    res = await client.get(f"/api/v1/cases/{case_id}", headers=headers)
    assert res.status_code == 200
    assert res.json()["title"] == "Test BEC Case"
