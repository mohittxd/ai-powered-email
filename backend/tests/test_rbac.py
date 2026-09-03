"""
Tests for Phase 18: Role-Based Access Control (RBAC), Authentication, and Mandatory Audit Logging.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from main import app
from core.database import Base, engine, AsyncSessionLocal
from core.models import AuditLog, User
from core.rbac import hash_password, verify_password


@pytest_asyncio.fixture(autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def test_password_hashing_security():
    plain = "SuperSecretPass123!"
    hashed = hash_password(plain)

    # Never store plaintext
    assert hashed != plain
    assert len(hashed) > 20
    assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    # Verification checks
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword", hashed) is False
    print("✅ Secure password hashing (bcrypt) validated.")


@pytest.mark.asyncio
async def test_role_based_logins_and_tokens():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. Login ANALYST
        res = await client.post("/api/v1/auth/login", json={"email": "analyst@forensics.local", "password": "analyst123"})
        assert res.status_code == 200
        analyst_token = res.json()["access_token"]
        assert res.json()["user"]["role"] == "analyst"

        # 2. Login INVESTIGATOR
        res = await client.post("/api/v1/auth/login", json={"email": "investigator@forensics.local", "password": "ir2026"})
        assert res.status_code == 200
        investigator_token = res.json()["access_token"]
        assert res.json()["user"]["role"] == "investigator"

        # 3. Login ADMIN
        res = await client.post("/api/v1/auth/login", json={"email": "admin@forensics.local", "password": "admin123"})
        assert res.status_code == 200
        admin_token = res.json()["access_token"]
        assert res.json()["user"]["role"] == "admin"

        # 4. Verify /auth/me with tokens
        me_analyst = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {analyst_token}"})
        assert me_analyst.status_code == 200
        assert me_analyst.json()["role"] == "analyst"

        me_admin = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {admin_token}"})
        assert me_admin.status_code == 200
        assert me_admin.json()["role"] == "admin"

        print("✅ Multi-role authentication & token validation passed.")


@pytest.mark.asyncio
async def test_permission_enforcement_and_admin_management():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # Login Analyst & Admin
        a_resp = await client.post("/api/v1/auth/login", json={"email": "analyst@forensics.local", "password": "analyst123"})
        analyst_hdr = {"Authorization": f"Bearer {a_resp.json()['access_token']}"}

        ad_resp = await client.post("/api/v1/auth/login", json={"email": "admin@forensics.local", "password": "admin123"})
        admin_hdr = {"Authorization": f"Bearer {ad_resp.json()['access_token']}"}

        # Analyst tries admin operation -> 403 Forbidden
        u_create_fail = await client.post(
            "/api/v1/users",
            json={"email": "newuser@corp.com", "name": "New User", "password": "Password123!", "role": "ANALYST"},
            headers=analyst_hdr
        )
        assert u_create_fail.status_code == 403

        # Admin performs user creation
        u_create_ok = await client.post(
            "/api/v1/users",
            json={"email": "newuser@corp.com", "name": "New User", "password": "Password123!", "role": "ANALYST"},
            headers=admin_hdr
        )
        assert u_create_ok.status_code == 200
        user_id = u_create_ok.json()["id"]

        # Admin lists users
        u_list = await client.get("/api/v1/users", headers=admin_hdr)
        assert u_list.status_code == 200
        assert len(u_list.json()) >= 1

        # Admin deletes user
        u_del = await client.delete(f"/api/v1/users/{user_id}", headers=admin_hdr)
        assert u_del.status_code == 200

        print("✅ RBAC permission enforcement and Admin User Management verified.")


@pytest.mark.asyncio
async def test_all_six_mandatory_audit_logs():
    """
    Verify audit logging for:
    - LOGIN
    - EMAIL_UPLOAD
    - CASE_VIEW
    - REPORT_EXPORT
    - CASE_UPDATE
    - ADMIN_ACTION
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        # 1. LOGIN
        l_resp = await client.post("/api/v1/auth/login", json={"email": "admin@forensics.local", "password": "admin123"})
        admin_hdr = {"Authorization": f"Bearer {l_resp.json()['access_token']}"}

        # 2. EMAIL_UPLOAD
        eml_bytes = b"From: attacker@bad.com\r\nTo: user@corp.com\r\nSubject: Test Phish\r\n\r\nClick link."
        ingest_resp = await client.post(
            "/api/v1/analyze-email",
            files={"file": ("sample.eml", eml_bytes, "message/rfc822")},
            headers=admin_hdr
        )
        assert ingest_resp.status_code == 200
        email_id = ingest_resp.json()["email_id"]

        # Create a case
        c_resp = await client.post("/api/v1/cases", json={"title": "Audit Test Case", "analyst_id": "u-001"}, headers=admin_hdr)
        case_id = c_resp.json()["id"]

        # 3. CASE_VIEW
        v_resp = await client.get(f"/api/v1/cases/{case_id}", headers=admin_hdr)
        assert v_resp.status_code == 200

        # 4. CASE_UPDATE
        u_resp = await client.patch(f"/api/v1/cases/{case_id}/status?status=escalated", headers=admin_hdr)
        assert u_resp.status_code == 200

        # 5. REPORT_EXPORT
        exp_resp = await client.get(f"/api/v1/emails/{email_id}/report.pdf", headers=admin_hdr)
        assert exp_resp.status_code == 200

        # 6. ADMIN_ACTION
        cfg_resp = await client.get("/api/v1/config", headers=admin_hdr)
        assert cfg_resp.status_code == 200

        # Check Audit Database Records
        async with AsyncSessionLocal() as db:
            audit_res = await db.execute(Base.metadata.tables["audit_log"].select())
            records = audit_res.fetchall()
            recorded_actions = {r.action for r in records}

            expected_actions = {"LOGIN", "EMAIL_UPLOAD", "CASE_VIEW", "REPORT_EXPORT", "CASE_UPDATE", "ADMIN_ACTION"}
            for act in expected_actions:
                assert act in recorded_actions, f"Expected action '{act}' not found in audit logs!"

        print("✅ All 6 mandatory audit log actions (LOGIN, EMAIL_UPLOAD, CASE_VIEW, REPORT_EXPORT, CASE_UPDATE, ADMIN_ACTION) verified in DB!")
