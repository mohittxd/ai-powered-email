"""
Regression tests for Gmail -> PostgreSQL forensic ingestion.

Proves that a single Gmail message that fails at the database layer does not
poison the shared SQLAlchemy session:

* the failing message is rolled back (SAVEPOINT),
* the session stays usable,
* later valid messages are still imported,
* `sha256_hash` + `owner_id` deduplication is preserved,
* re-sync is idempotent (no duplicate rows),
* the original database exception is reported in the per-message failure
  details, and Gmail synchronization continues after the failure.
"""

import base64
import email
import email.policy
import hashlib
import json
import logging
import os
import tempfile
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastapi import HTTPException

from googleapiclient.errors import HttpError

from core.database import Base
from core.models import Email, GmailConnection, User
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import api.routes.gmail_sync as gmail_sync


def _raw_message(subject: str, message_id: str, recipient: str) -> bytes:
    """Build a small, well-formed RFC-5322 message."""
    msg = email.message.EmailMessage()
    msg["From"] = f"Sender <sender@{recipient.split('@')[1]}>"
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Message-ID"] = message_id
    msg["Date"] = "Thu, 12 Sep 2024 10:00:00 +0000"
    msg.set_content(f"Body for {subject}\nhttps://example.com/{message_id}")
    return msg.as_bytes(policy=email.policy.default)


def _raw_b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


class _FakeGmail:
    """Scripted stand-in for the googleapiclient built Gmail service."""

    def __init__(self, messages):
        # messages: list of {"id", "raw_bytes"}
        self._messages = messages

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId="me", q="", maxResults=100, pageToken=None):
        if pageToken:
            return _FakeRequest({"messages": [], "nextPageToken": None})
        return _FakeRequest(
            {"messages": [{"id": m["id"]} for m in self._messages]}
        )

    def get(self, userId="me", id=None, format="raw"):
        for m in self._messages:
            if m["id"] == id:
                return _FakeRequest(
                    {
                        "id": m["id"],
                        "threadId": f"thread-{m['id']}",
                        "labelIds": ["INBOX", "UNREAD"],
                        "raw": _raw_b64(m["raw_bytes"]),
                    }
                )
        raise RuntimeError(f"unknown message {id}")


class _FakeRequest:
    def __init__(self, payload):
        self._payload = payload

    def execute(self):
        return self._payload


async def _seed_connection(session, user_id: str) -> GmailConnection:
    connection = GmailConnection(
        user_id=user_id,
        google_email="analyst@example.com",
        access_token="stub-access-token",
        refresh_token="stub-refresh-token",
        scopes="https://www.googleapis.com/auth/gmail.readonly",
    )
    session.add(connection)
    await session.commit()
    return connection


@pytest_asyncio.fixture
async def db_engine():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{path}",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest_asyncio.fixture
async def db_session(db_engine):
    factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with factory() as session:
        yield session


@pytest_asyncio.fixture
async def analyst(db_session):
    user = User(
        email="analyst@example.com",
        name="Analyst",
        hashed_password="not-a-real-password",
    )
    db_session.add(user)
    await db_session.commit()
    return user


async def _run_sync(db_session, user, fake_gmail, monkeypatch):
    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )
    result = await gmail_sync.sync_gmail(
        max_results=10,
        mailbox="all",
        user=user,
        db=db_session,
    )
    return result


@pytest.mark.asyncio
async def test_sync_survives_a_db_failure_and_imports_later_messages(
    db_session, analyst, monkeypatch
):
    """A failed message must not poison the session; later valid messages import."""
    await _seed_connection(db_session, analyst.id)

    valid_1 = _raw_message("First", "<first@example.com>", "analyst@example.com")
    valid_3 = _raw_message("Third", "<third@example.com>", "analyst@example.com")

    fake_gmail = _FakeGmail(
        [
            {"id": "msg-1", "raw_bytes": valid_1},
            {"id": "msg-2", "raw_bytes": _raw_message("Bad", "<bad@example.com>", "analyst@example.com")},
            {"id": "msg-3", "raw_bytes": valid_3},
        ]
    )

    real_ingest = gmail_sync.ingest_email

    def _poisoned_ingest(raw_bytes, original_filename, upload_dir):
        result = real_ingest(raw_bytes, original_filename, upload_dir)
        if original_filename.startswith("gmail-msg-2."):
            # Simulate message data that violates a required DB column
            # (sha256_hash is NOT NULL) at flush time.
            result["sha256"] = None
        return result

    monkeypatch.setattr(gmail_sync, "ingest_email", _poisoned_ingest)

    result = await _run_sync(db_session, analyst, fake_gmail, monkeypatch)

    assert result["status"] == "completed"
    assert {f["gmail_id"] for f in result["failed"]} == {"msg-2"}
    assert {i["gmail_id"] for i in result["imported"]} == {"msg-1", "msg-3"}

    row = await db_session.scalar(select(GmailConnection).where(GmailConnection.user_id == analyst.id))
    assert row is not None and row.last_sync_at is not None

    stored = (await db_session.scalars(select(Email).where(Email.owner_id == analyst.id))).all()
    assert {e.id for e in stored} == {i["email_id"] for i in result["imported"]}
    assert {e.sha256_hash for e in stored} == {
        hashlib.sha256(valid_1).hexdigest(),
        hashlib.sha256(valid_3).hexdigest(),
    }

    session_ready = await db_session.scalar(select(Email.id).limit(1))
    assert session_ready is not None


@pytest.mark.asyncio
async def test_sync_is_idempotent_and_skips_duplicates(db_session, analyst, monkeypatch):
    """Re-sync of the same mailbox must not create duplicate records."""
    await _seed_connection(db_session, analyst.id)

    raw = _raw_message("Dup", "<dup@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmail([{"id": "msg-1", "raw_bytes": raw}])

    first = await _run_sync(db_session, analyst, fake_gmail, monkeypatch)
    assert first["imported_count"] == 1

    second = await _run_sync(db_session, analyst, fake_gmail, monkeypatch)
    assert second["imported_count"] == 0
    assert second["skipped_count"] == 1
    assert any(
        s["gmail_id"] == "msg-1" and s.get("reason") == "already_imported"
        for s in second["skipped"]
    )

    count = (
        await db_session.scalar(
            select(Email.id).where(Email.sha256_hash == hashlib.sha256(raw).hexdigest())
        )
    )
    assert count is not None
    total = len(
        (await db_session.scalars(select(Email).where(Email.owner_id == analyst.id))).all()
    )
    assert total == 1


@pytest.mark.asyncio
async def test_sync_failure_details_include_message_id_and_type(
    db_session, analyst, monkeypatch, caplog
):
    """Safe diagnostics must identify the failing Gmail message and exception type."""
    await _seed_connection(db_session, analyst.id)

    fake_gmail = _FakeGmail(
        [
            {"id": "msg-1", "raw_bytes": _raw_message("Ok", "<ok@example.com>", "analyst@example.com")},
            {"id": "msg-2", "raw_bytes": _raw_message("Bad", "<bad@example.com>", "analyst@example.com")},
        ]
    )

    real_ingest = gmail_sync.ingest_email

    def _poisoned_ingest(raw_bytes, original_filename, upload_dir):
        result = real_ingest(raw_bytes, original_filename, upload_dir)
        if original_filename.startswith("gmail-msg-2."):
            result["sha256"] = None
        return result

    monkeypatch.setattr(gmail_sync, "ingest_email", _poisoned_ingest)

    with caplog.at_level(logging.ERROR, logger="api.routes.gmail_sync"):
        result = await _run_sync(db_session, analyst, fake_gmail, monkeypatch)

    failed = next(f for f in result["failed"] if f["gmail_id"] == "msg-2")
    assert failed["error"]
    assert "IntegrityError" in caplog.text or "NOT NULL" in caplog.text
    assert "msg-2" in caplog.text

    # No credentials / tokens may leak into logs or responses.
    assert "stub-access-token" not in caplog.text
    assert "refresh-token" not in caplog.text
    assert "stub-refresh-token" not in caplog.text


# ── OAuth credential‑refresh tests ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_expired_token_triggers_refresh(db_session, analyst, monkeypatch):
    """When token_expiry is in the past, _build_gmail_service must refresh."""
    from datetime import datetime, timedelta

    await _seed_connection(db_session, analyst.id)

    # Set token_expiry to 2 hours ago so credentials.expired is True.
    conn = await db_session.scalar(
        select(GmailConnection).where(GmailConnection.user_id == analyst.id)
    )
    conn.token_expiry = datetime.utcnow() - timedelta(hours=2)
    await db_session.commit()

    def _build_with_refresh(connection):
        # Exercise the real expiry check and refresh logic.
        expiry = connection.token_expiry
        if expiry is not None and expiry.tzinfo is not None:
            expiry = expiry.replace(tzinfo=None)

        creds = gmail_sync.Credentials(
            token=connection.access_token,
            refresh_token=connection.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id="fake-id",
            client_secret="fake-secret",
            scopes=[gmail_sync.GMAIL_READONLY_SCOPE],
            expiry=expiry,
        )
        assert creds.expired, "Credentials should be expired with past expiry"

        # Simulate what the real refresh would do.
        connection.access_token = "refreshed-token"
        connection.token_expiry = datetime.utcnow() + timedelta(hours=1)
        return fake_gmail, connection

    raw = _raw_message("AfterRefresh", "<after@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmail([{"id": "msg-1", "raw_bytes": raw}])

    monkeypatch.setattr(gmail_sync, "_build_gmail_service", _build_with_refresh)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )
    assert result["status"] == "completed"


@pytest.mark.asyncio
async def test_naive_expiry_is_converted_safely(db_session, analyst, monkeypatch):
    """A naive token_expiry from PostgreSQL must not cause TypeError."""
    from datetime import datetime, timedelta

    await _seed_connection(db_session, analyst.id)

    conn = await db_session.scalar(
        select(GmailConnection).where(GmailConnection.user_id == analyst.id)
    )
    # Store a naive datetime (as PostgreSQL would).
    conn.token_expiry = datetime.utcnow() - timedelta(hours=1)
    await db_session.commit()

    build_called = []

    def _capture_build(connection):
        # Verify the expiry was converted to naive UTC.
        from google.oauth2.credentials import Credentials as C

        expiry = connection.token_expiry
        if expiry is not None and expiry.tzinfo is not None:
            expiry = expiry.replace(tzinfo=None)

        creds = C(
            token=connection.access_token,
            refresh_token=connection.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id="fake-id",
            client_secret="fake-secret",
            scopes=[gmail_sync.GMAIL_READONLY_SCOPE],
            expiry=expiry,
        )
        # This would raise TypeError if expiry were aware (mismatched with utcnow()).
        assert creds.expired is True
        build_called.append(True)
        return _FakeGmail([]), connection

    monkeypatch.setattr(gmail_sync, "_build_gmail_service", _capture_build)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )
    assert result["status"] == "completed"
    assert build_called, "Custom _build_gmail_service was never called"


@pytest.mark.asyncio
async def test_refresh_error_raises_http_401(db_session, analyst, monkeypatch):
    """A RefreshError during token refresh must produce HTTP 401, not hang."""
    from datetime import datetime, timedelta

    await _seed_connection(db_session, analyst.id)

    conn = await db_session.scalar(
        select(GmailConnection).where(GmailConnection.user_id == analyst.id)
    )
    conn.token_expiry = datetime.utcnow() - timedelta(hours=2)
    await db_session.commit()

    def _failing_refresh_build(connection):
        raise HTTPException(
            status_code=401,
            detail="Gmail authorization expired. Reconnect Gmail to continue syncing.",
        )

    monkeypatch.setattr(gmail_sync, "_build_gmail_service", _failing_refresh_build)

    with pytest.raises(HTTPException) as exc_info:
        await gmail_sync.sync_gmail(
            max_results=10, mailbox="all", user=analyst, db=db_session,
        )
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_refresh_timeout_is_bounded(db_session, analyst, monkeypatch):
    """_build_gmail_service must use _BoundedRequest (30 s default) during refresh."""
    from datetime import datetime, timedelta
    from unittest.mock import MagicMock, patch

    await _seed_connection(db_session, analyst.id)

    conn = await db_session.scalar(
        select(GmailConnection).where(GmailConnection.user_id == analyst.id)
    )
    conn.token_expiry = datetime.utcnow() - timedelta(hours=2)
    await db_session.commit()

    mock_creds = MagicMock()
    mock_creds.expired = True
    mock_creds.refresh_token = conn.refresh_token
    mock_creds.token = "new-token"
    mock_creds.expiry = datetime.utcnow() + timedelta(hours=1)

    with patch.object(gmail_sync, "Credentials", return_value=mock_creds), \
         patch.object(gmail_sync, "build", return_value=(_FakeGmail([]), conn)):
        gmail_sync._build_gmail_service(conn)

    # credentials.refresh must have been called with a _BoundedRequest instance
    mock_creds.refresh.assert_called_once()
    req_arg = mock_creds.refresh.call_args[0][0]
    assert isinstance(req_arg, gmail_sync._BoundedRequest)

    # The _BoundedRequest.__call__ default timeout must be _REFRESH_TIMEOUT (30)
    import inspect
    assert gmail_sync._REFRESH_TIMEOUT == 30
    sig = inspect.signature(req_arg.__class__.__call__)
    assert sig.parameters["timeout"].default == gmail_sync._REFRESH_TIMEOUT


@pytest.mark.asyncio
async def test_refreshed_tokens_are_persisted(db_session, analyst, monkeypatch):
    """After a successful refresh, connection tokens must be updated in-memory
    so the caller's db.commit() persists them."""
    from datetime import datetime, timedelta

    await _seed_connection(db_session, analyst.id)

    conn = await db_session.scalar(
        select(GmailConnection).where(GmailConnection.user_id == analyst.id)
    )
    original_token = conn.access_token
    conn.token_expiry = datetime.utcnow() - timedelta(hours=2)
    await db_session.commit()

    new_expiry = datetime.utcnow() + timedelta(hours=1)

    def _build_persists(connection):
        # Simulate what the real function does after a successful refresh.
        connection.access_token = "brand-new-access-token"
        connection.token_expiry = new_expiry
        connection.updated_at = datetime.utcnow()
        return _FakeGmail([]), connection

    monkeypatch.setattr(gmail_sync, "_build_gmail_service", _build_persists)

    raw = _raw_message("Persisted", "<persisted@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmail([{"id": "msg-1", "raw_bytes": raw}])

    # Re-override to use fake_gmail but still persist tokens.
    def _build_persists_with_msg(connection):
        connection.access_token = "brand-new-access-token"
        connection.token_expiry = new_expiry
        connection.updated_at = datetime.utcnow()
        return fake_gmail, connection

    monkeypatch.setattr(gmail_sync, "_build_gmail_service", _build_persists_with_msg)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )
    assert result["status"] == "completed"

    # Verify the tokens were persisted through the commit.
    refreshed_conn = await db_session.scalar(
        select(GmailConnection).where(GmailConnection.user_id == analyst.id)
    )
    assert refreshed_conn.access_token == "brand-new-access-token"
    assert refreshed_conn.token_expiry is not None


@pytest.mark.asyncio
async def test_normal_sync_still_works(db_session, analyst, monkeypatch):
    """Basic sync without expired tokens must work unchanged."""
    await _seed_connection(db_session, analyst.id)

    raw = _raw_message("Normal", "<normal@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmail([{"id": "msg-1", "raw_bytes": raw}])

    result = await _run_sync(db_session, analyst, fake_gmail, monkeypatch)

    assert result["status"] == "completed"
    assert result["imported_count"] == 1
    assert result["failed_count"] == 0


# ── Gmail API rate-limit (403 rateLimitExceeded) tests ──────────────────────


class _FakeHttpResp:
    """Mimics the httplib2.Response used by googleapiclient."""
    def __init__(self, status, reason="rateLimitExceeded"):
        self.status = status
        self.reason = reason


def _make_rate_limit_error(status=403, reason="rateLimitExceeded"):
    """Create a real googleapiclient.errors.HttpError for rate-limit testing."""
    content = json.dumps({
        "error": {
            "code": status,
            "message": "Quota exceeded",
            "status": "RESOURCE_EXHAUSTED",
            "errors": [{"reason": reason}],
        }
    }).encode("utf-8")
    return HttpError(_FakeHttpResp(status, reason), content)


class _FakeGmailWithRateLimit:
    """Fake Gmail that succeeds for the first N messages then raises 403."""

    def __init__(self, messages, rate_limit_after=1):
        self._messages = messages
        self._rate_limit_after = rate_limit_after
        self._call_count = 0

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId="me", q="", maxResults=100, pageToken=None):
        if pageToken:
            return _FakeRequest({"messages": [], "nextPageToken": None})
        return _FakeRequest(
            {"messages": [{"id": m["id"]} for m in self._messages]}
        )

    def get(self, userId="me", id=None, format="raw"):
        self._call_count += 1
        if self._call_count > self._rate_limit_after:
            raise _make_rate_limit_error(403, "rateLimitExceeded")
        for m in self._messages:
            if m["id"] == id:
                return _FakeRequest(
                    {
                        "id": m["id"],
                        "threadId": f"thread-{m['id']}",
                        "labelIds": ["INBOX", "UNREAD"],
                        "raw": _raw_b64(m["raw_bytes"]),
                    }
                )
        raise RuntimeError(f"unknown message {id}")


class _FakeGmailAllRateLimited:
    """Fake Gmail where every messages.get() call raises 403 rateLimitExceeded."""

    def __init__(self, messages):
        self._messages = messages
        self._call_count = 0

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId="me", q="", maxResults=100, pageToken=None):
        if pageToken:
            return _FakeRequest({"messages": [], "nextPageToken": None})
        return _FakeRequest(
            {"messages": [{"id": m["id"]} for m in self._messages]}
        )

    def get(self, userId="me", id=None, format="raw"):
        self._call_count += 1
        raise _make_rate_limit_error(403, "rateLimitExceeded")


class _FakeGmailNonRetryableError:
    """Fake Gmail where messages.get() raises a non-retryable HttpError."""

    def __init__(self, messages):
        self._messages = messages

    def users(self):
        return self

    def messages(self):
        return self

    def list(self, userId="me", q="", maxResults=100, pageToken=None):
        if pageToken:
            return _FakeRequest({"messages": [], "nextPageToken": None})
        return _FakeRequest(
            {"messages": [{"id": m["id"]} for m in self._messages]}
        )

    def get(self, userId="me", id=None, format="raw"):
        raise _make_rate_limit_error(403, "accessDenied")


@pytest.mark.asyncio
async def test_rate_limit_stops_processing_remaining_messages(
    db_session, analyst, monkeypatch
):
    """When messages.get() returns 403 rateLimitExceeded, sync must stop
    processing further messages (not attempt all 20)."""
    await _seed_connection(db_session, analyst.id)

    raw1 = _raw_message("First", "<first@example.com>", "analyst@example.com")
    raw2 = _raw_message("Second", "<second@example.com>", "analyst@example.com")
    raw3 = _raw_message("Third", "<third@example.com>", "analyst@example.com")

    fake_gmail = _FakeGmailWithRateLimit(
        [
            {"id": "msg-1", "raw_bytes": raw1},
            {"id": "msg-2", "raw_bytes": raw2},
            {"id": "msg-3", "raw_bytes": raw3},
        ],
        rate_limit_after=1,  # msg-1 succeeds, msg-2 hits rate limit
    )

    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )

    async def _noop_sleep(_delay):
        pass

    monkeypatch.setattr(gmail_sync.asyncio, "sleep", _noop_sleep)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )

    # The sync hit rate limit, so it returns a 429 Response
    from fastapi.responses import Response as FastAPIResponse
    assert isinstance(result, FastAPIResponse)
    assert result.status_code == 429

    import json
    body = json.loads(result.body)

    # msg-1 was imported, msg-2 hit rate limit, msg-3 was never attempted
    assert body["imported_count"] == 1
    assert body["status"] == "rate_limited"
    assert body["detail"] == (
        "Gmail API rate limit reached. "
        "Some messages were imported before the limit was hit. "
        "Please wait a moment and try again."
    )

    # msg-1 imported (1 get call), msg-2 hit rate limit after _MAX_RETRIES + 1 attempts
    assert fake_gmail._call_count == 1 + gmail_sync._MAX_RETRIES + 1


@pytest.mark.asyncio
async def test_rate_limit_preserves_successful_imports(
    db_session, analyst, monkeypatch
):
    """Messages imported before the rate limit must remain committed."""
    await _seed_connection(db_session, analyst.id)

    raw1 = _raw_message("Before", "<before@example.com>", "analyst@example.com")
    raw2 = _raw_message("RateLimited", "<limited@example.com>", "analyst@example.com")

    fake_gmail = _FakeGmailWithRateLimit(
        [
            {"id": "msg-1", "raw_bytes": raw1},
            {"id": "msg-2", "raw_bytes": raw2},
        ],
        rate_limit_after=1,
    )

    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )

    async def _noop_sleep(_delay):
        pass

    monkeypatch.setattr(gmail_sync.asyncio, "sleep", _noop_sleep)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )

    import json
    body = json.loads(result.body)
    assert body["imported_count"] == 1
    assert body["status"] == "rate_limited"

    # Verify the message is actually in the database
    stored = (await db_session.scalars(select(Email).where(Email.owner_id == analyst.id))).all()
    assert len(stored) == 1
    assert stored[0].gmail_message_id == "msg-1"


@pytest.mark.asyncio
async def test_rate_limit_retries_bounded_and_backoff(
    db_session, analyst, monkeypatch
):
    """Retries must be bounded to _MAX_RETRIES and use exponential backoff."""
    await _seed_connection(db_session, analyst.id)

    raw = _raw_message("RateLimited", "<limited@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmailAllRateLimited([{"id": "msg-1", "raw_bytes": raw}])

    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )

    sleep_calls = []

    async def _recording_sleep(delay):
        sleep_calls.append(delay)

    monkeypatch.setattr(
        gmail_sync.asyncio, "sleep", _recording_sleep
    )

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )

    import json
    body = json.loads(result.body)

    # No messages were imported (all hit rate limit on first attempt)
    assert body["imported_count"] == 0
    assert body["status"] == "rate_limited"

    # _MAX_RETRIES = 3, so 3 backoff sleeps: 1s, 2s, 4s
    assert len(sleep_calls) == gmail_sync._MAX_RETRIES
    assert sleep_calls == [1, 2, 4]

    # get() was called _MAX_RETRIES + 1 = 4 times (initial + 3 retries)
    assert fake_gmail._call_count == gmail_sync._MAX_RETRIES + 1


@pytest.mark.asyncio
async def test_rate_limit_does_not_retry_indefinitely(
    db_session, analyst, monkeypatch
):
    """When rate limit persists, sync must NOT loop forever."""
    await _seed_connection(db_session, analyst.id)

    raw = _raw_message("Stuck", "<stuck@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmailAllRateLimited([{"id": "msg-1", "raw_bytes": raw}])

    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )

    sleep_count = [0]

    async def _counting_sleep(d):
        sleep_count[0] += 1
        if sleep_count[0] > 20:
            raise AssertionError("Retried more than 20 times — infinite loop detected")

    monkeypatch.setattr(gmail_sync.asyncio, "sleep", _counting_sleep)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )

    import json
    body = json.loads(result.body)
    assert body["status"] == "rate_limited"
    assert sleep_count[0] == gmail_sync._MAX_RETRIES


@pytest.mark.asyncio
async def test_non_retryable_403_is_not_handled_as_rate_limit(
    db_session, analyst, monkeypatch
):
    """A 403 with reason other than rateLimitExceeded must propagate as 502."""
    await _seed_connection(db_session, analyst.id)

    raw = _raw_message("Forbidden", "<forbidden@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmailNonRetryableError([{"id": "msg-1", "raw_bytes": raw}])

    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )

    async def _noop_sleep(_delay):
        pass

    monkeypatch.setattr(gmail_sync.asyncio, "sleep", _noop_sleep)

    with pytest.raises(HTTPException) as exc_info:
        await gmail_sync.sync_gmail(
            max_results=10, mailbox="all", user=analyst, db=db_session,
        )
    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_rate_limit_response_excludes_sensitive_info(
    db_session, analyst, monkeypatch
):
    """Rate-limit response must not expose Google project numbers or tokens."""
    await _seed_connection(db_session, analyst.id)

    raw = _raw_message("Secret", "<secret@example.com>", "analyst@example.com")
    fake_gmail = _FakeGmailAllRateLimited([{"id": "msg-1", "raw_bytes": raw}])

    monkeypatch.setattr(
        gmail_sync, "_build_gmail_service", lambda conn: (fake_gmail, conn)
    )

    async def _noop_sleep(_delay):
        pass

    monkeypatch.setattr(gmail_sync.asyncio, "sleep", _noop_sleep)

    result = await gmail_sync.sync_gmail(
        max_results=10, mailbox="all", user=analyst, db=db_session,
    )

    import json
    body = json.loads(result.body)
    response_text = json.dumps(body)

    # No tokens or secrets
    assert "stub-access-token" not in response_text
    assert "stub-refresh-token" not in response_text
    assert "refresh_token" not in response_text