import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from core.database import AsyncSessionLocal, Base, engine
from core.models import User
from core.rbac import hash_password
from main import app


@pytest_asyncio.fixture(autouse=True)
async def db_schema():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def local_user(db_schema):
    async with AsyncSessionLocal() as db:
        user = User(
            email="login-test@forensicai.com",
            name="Login Test",
            role="analyst",
            hashed_password=hash_password("correct-password"),
        )
        db.add(user)
        await db.commit()
    yield user


@pytest.mark.asyncio
async def test_password_login_success(local_user):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": local_user.email, "password": "correct-password"},
        )

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert response.json()["user"]["email"] == local_user.email


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {"email": "login-test@forensicai.com", "password": "wrong-password"},
        {"email": "unknown@forensicai.com", "password": "correct-password"},
    ],
)
async def test_password_login_rejects_invalid_credentials(local_user, payload):
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/api/v1/auth/login", json=payload)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


@pytest.mark.asyncio
async def test_password_login_validates_required_fields():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post("/api/v1/auth/login", json={"email": "bad"})

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_registration_creates_account_and_rejects_duplicate():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "New User",
                "email": "new-user@forensicai.com",
                "password": "correct-password",
            },
        )
        duplicate = await client.post(
            "/api/v1/auth/register",
            json={
                "name": "New User",
                "email": "new-user@forensicai.com",
                "password": "correct-password",
            },
        )

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert duplicate.status_code == 409
