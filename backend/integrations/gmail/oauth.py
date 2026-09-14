"""
Gmail OAuth helpers for ForensicAI.
"""

import base64
import hashlib
import hmac
import json
import time

from google_auth_oauthlib.flow import Flow

from core.config import settings


def get_google_flow() -> Flow:
    """
    Create a Google OAuth flow using the configured web application
    credentials.
    """

    client_config = {
        "web": {
            "client_id": settings.google_client_id,
            "client_secret": settings.google_client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [settings.google_redirect_uri],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=settings.google_gmail_scopes.split(),
        autogenerate_code_verifier=False,
    )

    flow.redirect_uri = settings.google_redirect_uri

    return flow


def create_oauth_state(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": int(time.time()) + 600,
    }

    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
    ).encode("utf-8")

    payload_b64 = base64.urlsafe_b64encode(
        payload_bytes
    ).decode("utf-8").rstrip("=")

    signature = hmac.new(
        settings.secret_key.encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    signature_b64 = base64.urlsafe_b64encode(
        signature
    ).decode("utf-8").rstrip("=")

    return f"{payload_b64}.{signature_b64}"


def verify_oauth_state(state: str) -> str | None:
    try:
        parts = state.split(".")

        if len(parts) != 2:
            return None

        payload_b64, signature_b64 = parts

        expected_signature = hmac.new(
            settings.secret_key.encode("utf-8"),
            payload_b64.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        expected_b64 = base64.urlsafe_b64encode(
            expected_signature
        ).decode("utf-8").rstrip("=")

        if not hmac.compare_digest(
            signature_b64,
            expected_b64,
        ):
            return None

        padded = payload_b64 + "=" * (
            4 - len(payload_b64) % 4
        )

        payload = json.loads(
            base64.urlsafe_b64decode(padded)
        )

        if payload.get("exp", 0) < int(time.time()):
            return None

        user_id = payload.get("user_id")

        if not user_id:
            return None

        return user_id

    except Exception:
        return None
