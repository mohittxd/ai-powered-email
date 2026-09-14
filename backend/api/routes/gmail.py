"""
Gmail OAuth routes for ForensicAI.
"""

from datetime import datetime, timezone
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.models import GmailConnection
from core.rbac import get_current_user
from integrations.gmail.oauth import (
    create_oauth_state,
    get_google_flow,
    verify_oauth_state,
)

router = APIRouter(prefix="/integrations/gmail")


@router.get("/connect")
async def gmail_connect(user=Depends(get_current_user)):
    """
    Start Google Gmail OAuth for the currently authenticated
    ForensicAI user.
    """

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    flow = get_google_flow()

    state = create_oauth_state(user.id)

    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )

    return {
        "authorization_url": authorization_url,
    }


@router.get("/callback")
async def gmail_callback(
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle Google's OAuth callback.

    The signed OAuth state determines which ForensicAI user
    owns the resulting Gmail connection.
    """

    if not code:
        raise HTTPException(
            status_code=400,
            detail="Missing authorization code.",
        )

    if not state:
        raise HTTPException(
            status_code=400,
            detail="Missing OAuth state.",
        )

    user_id = verify_oauth_state(state)

    if not user_id:
        raise HTTPException(
            status_code=400,
            detail="Invalid or expired OAuth state.",
        )

    flow = get_google_flow()

    try:
        flow.fetch_token(code=code)
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Google OAuth token exchange failed: {exc}",
        ) from exc

    credentials = flow.credentials

    if not credentials.token:
        raise HTTPException(
            status_code=400,
            detail="Google did not return an access token.",
        )

    # Get the connected Gmail account's actual email address.
    google_email = None

    try:
        from googleapiclient.discovery import build

        gmail_service = build(
            "gmail",
            "v1",
            credentials=credentials,
            cache_discovery=False,
        )

        profile = (
            gmail_service.users()
            .getProfile(userId="me")
            .execute()
        )

        google_email = profile.get("emailAddress")

    except Exception:
        # The OAuth connection itself is still valid even if
        # profile lookup fails. Email can be populated later.
        google_email = None

    # Google may not return a refresh token if the account
    # already granted consent previously. Preserve the existing
    # refresh token in that case.
    result = await db.execute(
        select(GmailConnection).where(
            GmailConnection.user_id == user_id
        )
    )

    connection = result.scalar_one_or_none()

    if connection:
        connection.access_token = credentials.token

        if credentials.refresh_token:
            connection.refresh_token = credentials.refresh_token

        connection.token_expiry = credentials.expiry

        if credentials.scopes:
            connection.scopes = " ".join(credentials.scopes)

        if google_email:
            connection.google_email = google_email

        connection.updated_at = datetime.utcnow()

    else:
        connection = GmailConnection(
            user_id=user_id,
            google_email=google_email,
            access_token=credentials.token,
            refresh_token=credentials.refresh_token,
            token_expiry=credentials.expiry,
            scopes=(
                " ".join(credentials.scopes)
                if credentials.scopes
                else None
            ),
        )

        db.add(connection)

    await db.commit()

    return {
        "status": "oauth_success",
        "connected": True,
        "google_email": google_email,
        "scopes": list(credentials.scopes or []),
    }


@router.get("/status")
async def gmail_status(
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the Gmail connection status for the current
    ForensicAI user.
    """

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
        )

    result = await db.execute(
        select(GmailConnection).where(
            GmailConnection.user_id == user.id
        )
    )

    connection = result.scalar_one_or_none()

    if not connection:
        return {
            "connected": False,
            "google_email": None,
            "message": "Gmail is not connected.",
        }

    return {
        "connected": True,
        "google_email": connection.google_email,
        "scopes": (
            connection.scopes.split()
            if connection.scopes
            else []
        ),
        "token_expiry": (
            connection.token_expiry.isoformat()
            if connection.token_expiry
            else None
        ),
    }