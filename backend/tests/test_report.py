"""
Unit tests — Phase 8: Forensic Report Generation.
"""
import os
import sys
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from main import app
from core.database import get_db
from core.models import Case, Email


# Basic dummy file
DUMMY_EML = b"""\
From: alice@legit.com
To: bob@legit.com
Subject: Test
Date: Mon, 01 Jan 2024 12:00:00 +0000

Hello
"""

@pytest.mark.anyio
async def test_generate_case_report(tmp_path):
    # Setup test DB and file
    case_id = str(uuid.uuid4())
    email_id = str(uuid.uuid4())
    
    eml_path = tmp_path / "test.eml"
    eml_path.write_bytes(DUMMY_EML)
    
    # We need a mock db session. Since we are using FastAPI dependency override,
    # we can use the test client. But since we need DB access in the test, we'll
    # just create a mock dependency.
    
    class MockResult:
        def __init__(self, item):
            self.item = item
        def scalar_one_or_none(self):
            return self.item
        def scalars(self):
            return self
        def first(self):
            return self.item
        def all(self):
            return [self.item] if self.item else []

    class MockSession:
        async def execute(self, stmt):
            stmt_str = str(stmt).lower()
            if "cases" in stmt_str:
                case = Case(id=case_id, title="Test Case")
                return MockResult(case)
            if "emails" in stmt_str:
                email = Email(
                    id=email_id,
                    case_id=case_id,
                    sha256_hash="dummyhash",
                    raw_storage_path=str(eml_path)
                )
                return MockResult(email)
            return MockResult(None)
            
    async def override_get_db():
        yield MockSession()
        
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get(f"/api/v1/cases/{case_id}/report")
        
    app.dependency_overrides.clear()
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["case_id"] == case_id
    assert "analysis_timestamp" in data
    assert data["evidence"]["email_id"] == email_id
    assert data["email"]["subject"] == "Test"
    assert "authentication" in data
    assert "header_analysis" in data
    assert "origin_trace" in data
    assert "geolocation" in data
    assert "threat_intelligence" in data
    assert "iocs" in data
    assert "risk_assessment" in data
    assert "limitations" in data
    assert isinstance(data["limitations"], list)
    
    # Check deterministic components
    assert data["risk_assessment"]["classification"] in ("LEGITIMATE", "SUSPICIOUS", "IMPERSONATION", "PHISHING", "CRITICAL/BEC")
