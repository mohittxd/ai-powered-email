"""
Gmail OAuth helpers for ForensicAI.
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time

from cryptography.fernet import Fernet, InvalidToken
from google_auth_oauthlib.flow import Flow

from core.config import settings

logger = logging.getLogger(__name__)

GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
_GOOGLE_IDENTITY_SCOPES = {
    "openid",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
}


def _identity_state_cipher() -> Fernet:
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    )
    return Fernet(key)


def create_google_identity_state(code_verifier: str) -> str:
    """Encrypt the short-lived identity OAuth transaction state."""
    payload = {
        "user_id": "google-login",
        "provider": "google",
        "code_verifier": code_verifier,
        "nonce": secrets.token_urlsafe(24),
        "exp": int(time.time()) + 600,
    }
    return _identity_state_cipher().encrypt(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def verify_google_identity_state(state: str) -> str | None:
    """Return the PKCE verifier from a valid, unexpired identity state."""
    try:
        payload = json.loads(
            _identity_state_cipher().decrypt(state.encode("ascii"))
        )
        if payload.get("provider") != "google":
            return None
        if payload.get("user_id") != "google-login":
            return None
        if payload.get("exp", 0) < int(time.time()):
            return None
        verifier = payload.get("code_verifier")
        return verifier if isinstance(verifier, str) and verifier else None
    except (InvalidToken, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        return None


def get_gmail_flow() -> Flow:
    """
    Create the dedicated Gmail OAuth flow.
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
        scopes=[GMAIL_READONLY_SCOPE],
        autogenerate_code_verifier=False,
    )

    flow.redirect_uri = settings.google_redirect_uri
    flow.oauth2session.register_compliance_hook(
        "access_token_response",
        _normalize_gmail_token_scope,
    )
    logger.debug(
        "OAuth flow=Gmail requested_scopes=%s",
        sorted({GMAIL_READONLY_SCOPE}),
    )

    return flow


def _normalize_gmail_token_scope(response):
    """
    Handle Google's documented scope expansion for a shared OAuth client.

    OAuthLib compares the token response scope to the requested scope as an
    exact string set. Google can return previously granted identity scopes
    alongside Gmail when the same client is also used for Google login. Only
    those known identity scopes are normalized away, and only after the
    required Gmail scope is present. Missing Gmail or unknown scopes are left
    untouched so OAuthLib still rejects them.
    """
    try:
        token = response.json()
    except ValueError:
        return response

    if not isinstance(token, dict):
        return response

    returned_scope = token.get("scope")
    if not isinstance(returned_scope, str):
        logger.debug(
            "OAuth flow=Gmail requested_scopes=%s returned_scopes=[] gmail_readonly=%s",
            sorted({GMAIL_READONLY_SCOPE}),
            False,
        )
        return response

    granted_scopes = set(returned_scope.split())
    logger.debug(
        "OAuth flow=Gmail requested_scopes=%s returned_scopes=%s gmail_readonly=%s",
        sorted({GMAIL_READONLY_SCOPE}),
        sorted(granted_scopes),
        GMAIL_READONLY_SCOPE in granted_scopes,
    )
    if GMAIL_READONLY_SCOPE not in granted_scopes:
        return response

    unexpected_scopes = (
        granted_scopes
        - {GMAIL_READONLY_SCOPE}
        - _GOOGLE_IDENTITY_SCOPES
    )
    if unexpected_scopes:
        return response

    if granted_scopes != {GMAIL_READONLY_SCOPE}:
        token["scope"] = GMAIL_READONLY_SCOPE
        response._content = json.dumps(token).encode("utf-8")

    return response


def has_gmail_readonly_scope(scopes: set[str] | list[str] | tuple[str, ...] | None) -> bool:
    """Return whether a token or persisted connection can access Gmail."""
    return GMAIL_READONLY_SCOPE in (set(scopes) if scopes else set())


def create_oauth_state(user_id: str, provider: str = "gmail") -> str:
    payload = {
        "user_id": user_id,
        "provider": provider,
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


def verify_oauth_state(state: str, expected_provider: str = "gmail") -> str | None:
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

        if payload.get("provider", "gmail") != expected_provider:
            return None
        return user_id

    except Exception:
        return None
