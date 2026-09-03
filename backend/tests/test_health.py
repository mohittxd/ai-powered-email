"""
Deployment Health Check Tests for ForensicAI.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from main import app
from core.database import Base, engine


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.mark.asyncio
async def test_health_check_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok" or data["status"] == "healthy"
        assert "version" in data or "app" in data
        print("✅ Health check endpoint verified.")
