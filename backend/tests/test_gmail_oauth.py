import json
from urllib.parse import parse_qs, urlparse

import pytest
from requests import PreparedRequest, Response

import api.routes.gmail_sync as gmail_sync
from integrations.gmail.oauth import (
    GMAIL_READONLY_SCOPE,
    get_gmail_flow,
    has_gmail_readonly_scope,
)


IDENTITY_SCOPES = (
    "openid "
    "https://www.googleapis.com/auth/userinfo.profile "
    "https://www.googleapis.com/auth/userinfo.email"
)


def _token_response(scope: str) -> Response:
    response = Response()
    response.status_code = 200
    response._content = json.dumps(
        {
            "access_token": "gmail-access-token",
            "expires_in": 3600,
            "scope": scope,
            "token_type": "Bearer",
        }
    ).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    request = PreparedRequest()
    request.prepare(method="POST", url="https://oauth2.googleapis.com/token")
    response.request = request
    return response


def test_gmail_flow_accepts_google_identity_scope_expansion():
    flow = get_gmail_flow()
    authorization_url, _ = flow.authorization_url(state="state")
    assert parse_qs(urlparse(authorization_url).query)["scope"] == [
        GMAIL_READONLY_SCOPE
    ]

    flow.oauth2session.request = lambda **_: _token_response(
        f"{IDENTITY_SCOPES} {GMAIL_READONLY_SCOPE}"
    )

    flow.fetch_token(code="authorization-code")

    assert flow.credentials.token == "gmail-access-token"
    assert has_gmail_readonly_scope(flow.credentials.scopes)
    assert flow.credentials.scopes == [GMAIL_READONLY_SCOPE]


def test_gmail_flow_rejects_response_without_gmail_scope():
    flow = get_gmail_flow()
    flow.oauth2session.request = lambda **_: _token_response(
        IDENTITY_SCOPES
    )

    with pytest.raises(Warning, match="Scope has changed"):
        flow.fetch_token(code="authorization-code")


def test_gmail_sync_accepts_connection_with_identity_scope_expansion(monkeypatch):
    connection = type(
        "Connection",
        (),
        {
            "access_token": "gmail-access-token",
            "refresh_token": "refresh-token",
            "token_expiry": None,
            "scopes": f"{GMAIL_READONLY_SCOPE} {IDENTITY_SCOPES}",
            "user_id": "user-id",
        },
    )()
    expected_service = object()
    def fake_build(*args, **kwargs):
        assert args[:2] == ("gmail", "v1")
        assert kwargs["cache_discovery"] is False
        return expected_service

    monkeypatch.setattr(gmail_sync, "build", fake_build)

    service, returned_conn = gmail_sync._build_gmail_service(connection)
    assert service is expected_service
    assert returned_conn is connection
