"""
Gmail -> PostgreSQL forensic ingestion.

Uses the existing GmailConnection created by the OAuth flow.

Each Gmail message is imported inside its own SAVEPOINT
(``db.begin_nested()``). If a single message fails at the database layer its
SAVEPOINT is rolled back, the shared session stays usable, and later valid
messages continue to import without corrupting the batch.
"""

import asyncio
import base64
import hashlib
import json
import logging
from datetime import datetime

from email.utils import parsedate_to_datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.models import Email, IOC, GmailConnection
from core.rbac import get_current_user
from services.email_ingestor import ingest_email
from integrations.gmail.oauth import GMAIL_READONLY_SCOPE, has_gmail_readonly_scope

from google.oauth2.credentials import Credentials
from google.auth.exceptions import RefreshError
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.auth.transport.requests import Request

# Timeout (seconds) for the OAuth token-refresh HTTP request.
# google-auth 2.x Request.__init__ only accepts a session; the timeout is
# applied per-call via __call__.  Subclassing lets us lower the default
# from 120 s to 30 s so a flaky Google endpoint cannot hang the request.
_REFRESH_TIMEOUT = 30


class _BoundedRequest(Request):
    """google-auth Request adapter that enforces a bounded HTTP timeout.

    ``google.auth.transport.requests.Request.__init__`` does not accept a
    *timeout* argument — the timeout is a per-call parameter on
    ``__call__`` (default 120 s).  Subclassing lets us inject a tighter
    default so a hung Google token-refresh endpoint cannot block the
    FastAPI/uvicorn worker indefinitely.
    """

    def __call__(self, url, method="GET", body=None, headers=None,
                 timeout=_REFRESH_TIMEOUT, **kwargs):
        return super().__call__(
            url, method=method, body=body, headers=headers,
            timeout=timeout, **kwargs,
        )


# Gmail API rate-limit retry configuration.
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1  # seconds; exponential backoff: 1, 2, 4


def _is_rate_limited(exc: HttpError) -> bool:
    """Return True if *exc* is a Gmail API ``rateLimitExceeded`` (HTTP 403).

    ``HttpError.error_details`` is a list of dicts parsed from the JSON
    response body.  A rate-limit error contains
    ``{"reason": "rateLimitExceeded"}``.
    """
    if exc.resp.status != 403:
        return False
    for detail in exc.error_details:
        if isinstance(detail, dict) and detail.get("reason") == "rateLimitExceeded":
            return True
    # Fallback: check the plain-text reason string.
    return "rateLimitExceeded" in (exc.reason or "")


router = APIRouter(prefix="/integrations/gmail")
logger = logging.getLogger(__name__)


def _safe_db_summary(exc: Exception) -> str:
    """Short, safe, single-line summary of a database exception.

    Only the exception type and the first line of the message are kept so a
    traceback never dumps message bodies or other sensitive content into the
    API response.
    """
    name = type(exc).__name__
    text = str(exc).strip()
    first_line = text.splitlines()[0] if text else name
    if len(first_line) > 500:
        first_line = first_line[:500] + "..."
    return f"{name}: {first_line}"


def _decode_gmail_raw(raw_message: str) -> bytes:
    """Decode Gmail URL-safe base64 MIME data."""
    padding = "=" * (-len(raw_message) % 4)
    return base64.urlsafe_b64decode(raw_message + padding)


def _parse_email_date(value: str | None):
    """Convert RFC-5322 date to naive UTC datetime for PostgreSQL."""
    if not value:
        return None

    try:
        dt = parsedate_to_datetime(value)

        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)

        return dt

    except Exception:
        return None


async def _get_gmail_connection(
    user_id: str,
    db: AsyncSession,
) -> GmailConnection:
    result = await db.execute(
        select(GmailConnection).where(
            GmailConnection.user_id == user_id
        )
    )

    connection = result.scalar_one_or_none()

    if not connection:
        raise HTTPException(
            status_code=400,
            detail="Gmail is not connected. Connect Gmail first.",
        )

    if not connection.access_token:
        raise HTTPException(
            status_code=400,
            detail="Gmail connection has no access token.",
        )

    return connection


def _build_gmail_service(connection: GmailConnection):
    """Build and refresh Google Gmail credentials.

    Returns (gmail_service, connection) so the caller can persist any
    refreshed tokens through the existing DB session.
    """

    scopes = (
        connection.scopes.split()
        if connection.scopes
        else [GMAIL_READONLY_SCOPE]
    )

    if not has_gmail_readonly_scope(scopes):
        raise HTTPException(
            status_code=401,
            detail="Gmail authorization lacks the required read-only permission. Reconnect Gmail.",
        )

    # Normalize expiry to naive UTC so Credentials.expired can compare
    # without TypeError.  google-auth's internal utcnow() returns naive
    # datetimes, and mixing aware/naive raises TypeError.
    expiry = connection.token_expiry
    if expiry is not None:
        if expiry.tzinfo is not None:
            expiry = expiry.replace(tzinfo=None)

    credentials = Credentials(
        token=connection.access_token,
        refresh_token=connection.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        scopes=scopes,
        expiry=expiry,
    )

    if credentials.expired:
        if not credentials.refresh_token:
            raise HTTPException(
                status_code=401,
                detail="Gmail authorization expired. Reconnect Gmail to continue syncing.",
            )
        try:
            credentials.refresh(_BoundedRequest())
        except RefreshError as exc:
            logger.warning(
                "Gmail token refresh failed for user %s: %s",
                connection.user_id,
                type(exc).__name__,
            )
            raise HTTPException(
                status_code=401,
                detail="Gmail authorization expired. Reconnect Gmail to continue syncing.",
            ) from exc

        connection.access_token = credentials.token
        connection.token_expiry = credentials.expiry
        connection.updated_at = datetime.utcnow()

    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    ), connection


@router.post("/sync")
async def sync_gmail(
    max_results: int = 20,
    mailbox: str = "all",
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Import recent Gmail inbox messages into the forensic database.
    """

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    if max_results < 1 or max_results > 100:
        raise HTTPException(
            status_code=400,
            detail="max_results must be between 1 and 100.",
        )
    if mailbox not in {"all", "inbox"}:
        raise HTTPException(status_code=400, detail="mailbox must be 'all' or 'inbox'.")

    connection = await _get_gmail_connection(user.id, db)

    try:
        gmail_service, connection = _build_gmail_service(connection)

        query = "in:anywhere -in:sent -in:spam -in:trash" if mailbox == "all" else "in:inbox"
        messages = []
        page_token = None
        rate_limited = False

        for _attempt in range(_MAX_RETRIES + 1):
            try:
                while len(messages) < settings.gmail_sync_max_messages:
                    request = gmail_service.users().messages().list(
                        userId="me",
                        q=query,
                        maxResults=min(max_results, settings.gmail_sync_max_messages - len(messages)),
                        pageToken=page_token,
                    )
                    response = request.execute()
                    messages.extend(response.get("messages", []))
                    page_token = response.get("nextPageToken")
                    if not page_token or not response.get("messages"):
                        break
                break  # success — exit retry loop

            except HttpError as exc:
                if _is_rate_limited(exc) and _attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * (2 ** _attempt)
                    logger.warning(
                        "Gmail API rate limit on messages.list(), "
                        "retrying in %ss (attempt %d/%d)",
                        delay, _attempt + 1, _MAX_RETRIES,
                    )
                    await asyncio.sleep(delay)
                    continue
                raise
        has_more = bool(page_token)

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to access Gmail")

        raise HTTPException(
            status_code=502,
            detail="Unable to access Gmail. Check the Gmail connection and try again.",
        )

    imported = []
    skipped = []
    failed = []
    rate_limited = False

    try:
      for message_ref in messages:
        gmail_id = message_ref.get("id")

        if not gmail_id:
            continue

        stage = "gmail_message_retrieval"

        # ── Bounded retry with exponential backoff for rate limits ────
        gmail_message = None
        for _attempt in range(_MAX_RETRIES + 1):
            try:
                gmail_message = (
                    gmail_service.users()
                    .messages()
                    .get(userId="me", id=gmail_id, format="raw")
                    .execute()
                )
                break  # success
            except HttpError as exc:
                if _is_rate_limited(exc) and _attempt < _MAX_RETRIES:
                    delay = _RETRY_BASE_DELAY * (2 ** _attempt)
                    logger.warning(
                        "Gmail API rate limit on messages.get() for %s, "
                        "retrying in %ss (attempt %d/%d)",
                        gmail_id, delay, _attempt + 1, _MAX_RETRIES,
                    )
                    await asyncio.sleep(delay)
                    continue
                if _is_rate_limited(exc):
                    # Retries exhausted for rate limit — stop cleanly
                    logger.warning(
                        "Gmail API rate limit retries exhausted for %s",
                        gmail_id,
                    )
                    break
                # Non-retryable error — propagate
                raise

        if gmail_message is None:
            # Retries exhausted without success
            rate_limited = True
            break

        raw_b64 = gmail_message.get("raw")

        if not raw_b64:
            failed.append({
                "gmail_id": gmail_id,
                "error": "Gmail returned no raw MIME data.",
            })
            continue

        raw_bytes = _decode_gmail_raw(raw_b64)

        # ---------------------------------------------------------
        # Each message is isolated in its own SAVEPOINT. If one
        # message fails at the database layer, its savepoint is
        # rolled back and the outer transaction remains usable for
        # the next message.
        # ---------------------------------------------------------
        try:
            async with db.begin_nested():
                # -----------------------------------------------------
                # First check: SHA-256 duplicate detection scoped to the
                # authenticated owner.
                # -----------------------------------------------------
                sha256 = hashlib.sha256(raw_bytes).hexdigest()
                stage = "duplicate_check"

                existing = await db.scalar(
                    select(Email)
                    .where(Email.sha256_hash == sha256, Email.owner_id == user.id)
                    .limit(1)
                )

                if existing:
                    skipped.append({
                        "gmail_id": gmail_id,
                        "email_id": existing.id,
                        "sha256": sha256,
                        "reason": "already_imported",
                    })
                    continue

                # -----------------------------------------------------
                # Existing forensic ingestion pipeline
                # -----------------------------------------------------
                stage = "email_parse_and_evidence"
                result = ingest_email(
                    raw_bytes=raw_bytes,
                    original_filename=f"gmail-{gmail_id}.eml",
                    upload_dir=settings.upload_dir,
                )

                parsed = result["parsed"]

                email_id = result["email_id"]

                stage = "database_insert_email"
                db_email = Email(
                    id=email_id,
                    owner_id=user.id,
                    sha256_hash=result["sha256"],
                    raw_storage_path=result["storage_path"],

                    from_address=parsed.get("from_address"),
                    from_display_name=parsed.get("from_display_name"),
                    reply_to=parsed.get("reply_to"),
                    return_path=parsed.get("return_path"),
                    message_id=parsed.get("message_id"),
                    subject=parsed.get("subject"),

                    date_sent=_parse_email_date(
                        parsed.get("date")
                    ),

                    body_text=(
                        parsed.get("body_text") or ""
                    )[:65535],

                    body_html=(
                        parsed.get("body_html") or ""
                    )[:65535],
                    gmail_message_id=gmail_id,
                    gmail_thread_id=gmail_message.get("threadId"),
                    gmail_labels=gmail_message.get("labelIds", []),
                )

                db.add(db_email)

                # -----------------------------------------------------
                # Save extracted IOCs
                # -----------------------------------------------------
                stage = "database_insert_iocs"
                for url in result["iocs"].get("urls", []):
                    db.add(
                        IOC(
                            email_id=email_id,
                            ioc_type="url",
                            value=str(url)[:1000],
                            risk_level="low",
                            context="gmail_sync",
                        )
                    )

                for domain in result["iocs"].get("domains", []):
                    db.add(
                        IOC(
                            email_id=email_id,
                            ioc_type="domain",
                            value=str(domain)[:1000],
                            risk_level="low",
                            context="gmail_sync",
                        )
                    )

                for ip in result["iocs"].get("ips", []):
                    db.add(
                        IOC(
                            email_id=email_id,
                            ioc_type="ip",
                            value=str(ip)[:1000],
                            risk_level="low",
                            context="gmail_sync",
                        )
                    )

                # Force the INSERT now while still inside the SAVEPOINT so
                # a database failure is isolated to this single message.
                stage = "database_flush"
                await db.flush()

            imported.append({
                "gmail_id": gmail_id,
                "email_id": email_id,
                "sha256": result["sha256"],
                "subject": parsed.get("subject"),
                "from_address": parsed.get("from_address"),
            })

        except Exception as exc:
            logger.exception(
                "Gmail sync: message=%s failed during=%s error_type=%s "
                "rollback_performed=True (SAVEPOINT rolled back)",
                gmail_id,
                stage,
                type(exc).__name__,
            )

            failed.append({
                "gmail_id": gmail_id,
                "error": _safe_db_summary(exc),
                "stage": stage,
            })

    except HttpError as exc:
        if _is_rate_limited(exc):
            rate_limited = True
        else:
            logger.exception("Gmail sync: non-retryable API error")
            raise HTTPException(
                status_code=502,
                detail="Unable to access Gmail. Check the Gmail connection and try again.",
            )

    status = "rate_limited" if rate_limited else "completed"

    stats = {
        "status": status,
        "scanned": len(messages),
        "imported": len(imported),
        "skipped": len(skipped),
        "failed": len(failed),
        "has_more": has_more,
    }
    connection.last_sync_at = datetime.utcnow()
    connection.last_sync_stats = stats

    try:
        await db.commit()
    except SQLAlchemyError as exc:
        logger.error(
            "Gmail sync: final commit failed error_type=%s rollback_performed=True",
            type(exc).__name__,
            exc_info=True,
        )
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Gmail sync completed with errors and could not be finalized.",
        ) from exc

    body = {
        **stats,
        "gmail_messages_found": len(messages),
        "requested": max_results,
        "imported_count": len(imported),
        "skipped_count": len(skipped),
        "failed_count": len(failed),
        "imported": imported,
        "skipped": skipped,
        "failed": failed,
    }

    if rate_limited:
        body["detail"] = (
            "Gmail API rate limit reached. "
            "Some messages were imported before the limit was hit. "
            "Please wait a moment and try again."
        )
        return Response(
            content=json.dumps(body),
            status_code=429,
            media_type="application/json",
        )

    return body
