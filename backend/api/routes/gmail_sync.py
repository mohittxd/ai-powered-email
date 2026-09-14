"""
Gmail -> PostgreSQL forensic ingestion.

Uses the existing GmailConnection created by the OAuth flow.
"""

import base64
import logging
from datetime import datetime

from email.utils import parsedate_to_datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from core.database import get_db
from core.models import Email, IOC, GmailConnection
from core.rbac import get_current_user
from services.email_ingestor import ingest_email

from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request


router = APIRouter(prefix="/integrations/gmail")
logger = logging.getLogger(__name__)


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

    if not connection.refresh_token:
        raise HTTPException(
            status_code=400,
            detail=(
                "Gmail connection has no refresh token. "
                "Reconnect Gmail with consent."
            ),
        )

    return connection


def _build_gmail_service(connection: GmailConnection):
    """Build and refresh Google Gmail credentials."""

    scopes = (
        connection.scopes.split()
        if connection.scopes
        else [settings.google_gmail_scopes]
    )

    credentials = Credentials(
        token=connection.access_token,
        refresh_token=connection.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        scopes=scopes,
    )

    if credentials.expired and credentials.refresh_token:
        credentials.refresh(Request())

        connection.access_token = credentials.token
        connection.token_expiry = credentials.expiry
        connection.updated_at = datetime.utcnow()

    return build(
        "gmail",
        "v1",
        credentials=credentials,
        cache_discovery=False,
    )


@router.post("/sync")
async def sync_gmail(
    max_results: int = 20,
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

    connection = await _get_gmail_connection(user.id, db)

    try:
        gmail_service = _build_gmail_service(connection)

        response = (
            gmail_service.users()
            .messages()
            .list(
                userId="me",
                labelIds=["INBOX"],
                maxResults=max_results,
            )
            .execute()
        )

    except Exception as exc:
        logger.exception("Failed to access Gmail")

        raise HTTPException(
            status_code=502,
            detail=f"Unable to access Gmail: {exc}",
        )

    messages = response.get("messages", [])

    imported = []
    skipped = []
    failed = []

    for message_ref in messages:
        gmail_id = message_ref.get("id")

        if not gmail_id:
            continue

        try:
            gmail_message = (
                gmail_service.users()
                .messages()
                .get(
                    userId="me",
                    id=gmail_id,
                    format="raw",
                )
                .execute()
            )

            raw_b64 = gmail_message.get("raw")

            if not raw_b64:
                failed.append({
                    "gmail_id": gmail_id,
                    "error": "Gmail returned no raw MIME data.",
                })
                continue

            raw_bytes = _decode_gmail_raw(raw_b64)

            # ---------------------------------------------------------
            # First check: SHA-256 duplicate detection
            # ---------------------------------------------------------
            import hashlib

            sha256 = hashlib.sha256(raw_bytes).hexdigest()

            existing = await db.scalar(
                select(Email)
                .where(Email.sha256_hash == sha256)
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

            # ---------------------------------------------------------
            # Existing forensic ingestion pipeline
            # ---------------------------------------------------------
            result = ingest_email(
                raw_bytes=raw_bytes,
                original_filename=f"gmail-{gmail_id}.eml",
                upload_dir=settings.upload_dir,
            )

            parsed = result["parsed"]

            email_id = result["email_id"]

            db_email = Email(
                id=email_id,
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
            )

            db.add(db_email)

            # ---------------------------------------------------------
            # Save extracted IOCs
            # ---------------------------------------------------------
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

            imported.append({
                "gmail_id": gmail_id,
                "email_id": email_id,
                "sha256": result["sha256"],
                "subject": parsed.get("subject"),
                "from_address": parsed.get("from_address"),
            })

        except Exception as exc:
            logger.exception(
                "Failed to import Gmail message %s",
                gmail_id,
            )

            failed.append({
                "gmail_id": gmail_id,
                "error": str(exc),
            })

    await db.commit()

    return {
        "status": "sync_complete",
        "gmail_messages_found": len(messages),
        "requested": max_results,
        "imported_count": len(imported),
        "skipped_count": len(skipped),
        "failed_count": len(failed),
        "imported": imported,
        "skipped": skipped,
        "failed": failed,
    }
