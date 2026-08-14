"""End-to-end tests for the stateless OAuth layer.

Drives the real ASGI app: register a client, walk the authorize → Google →
callback → token round-trip, and check the resulting access token opens the MCP
endpoint. Google's token endpoint is the only thing stubbed out.
"""
import base64
import hashlib
import json
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

import config
import oauth
import server

BASE = "https://mcp.example.com"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "a" * 64
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip("=")


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("PUBLIC_BASE_URL", BASE)
    monkeypatch.setenv("JWT_SIGNING_KEY", "test-signing-key-that-is-long-enough-for-hs256")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-cid")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "google-secret")
    monkeypatch.delenv("LOCAL_USER_EMAIL", raising=False)


@pytest.fixture
def client():
    with TestClient(server.build_app(), follow_redirects=False) as c:
        yield c


@pytest.fixture
def google(monkeypatch):
    """Stub Google's token endpoint: return an id_token for a fixed user."""
    claims = base64.urlsafe_b64encode(
        json.dumps({"sub": "google-sub-1", "email": "me@example.com"}).encode()
    ).decode().rstrip("=")

    async def fake_exchange(code):
        return {"id_token": f"header.{claims}.signature"}

    monkeypatch.setattr(oauth, "_exchange_google_code", fake_exchange)


def register(client, redirect_uris=(REDIRECT,)):
    r = client.post("/register", json={
        "redirect_uris": list(redirect_uris),
        "client_name": "Claude",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })
    assert r.status_code == 201, r.text
    return r.json()["client_id"]


def authorize(client, client_id, state="claude-state"):
    r = client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "code_challenge": CHALLENGE, "code_challenge_method": "S256", "state": state,
    })
    assert r.status_code == 302, r.text
    return parse_qs(urlparse(r.headers["location"]).query)["state"][0]


def callback(client, google_state):
    r = client.get("/google/callback", params={"code": "google-code", "state": google_state})
    assert r.status_code == 302, r.text
    return parse_qs(urlparse(r.headers["location"]).query)


def full_flow(client):
    client_id = register(client)
    params = callback(client, authorize(client, client_id))
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": params["code"][0],
        "redirect_uri": REDIRECT, "client_id": client_id, "code_verifier": VERIFIER,
    })
    assert r.status_code == 200, r.text
    return client_id, r.json()


# ── discovery ───────────────────────────────────────────────────────
def test_authorization_server_metadata(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"].rstrip("/") == BASE
    assert meta["authorization_endpoint"] == f"{BASE}/authorize"
    assert meta["token_endpoint"] == f"{BASE}/token"
    assert meta["registration_endpoint"] == f"{BASE}/register"
    assert meta["code_challenge_methods_supported"] == ["S256"]


def test_protected_resource_metadata(client):
    meta = client.get("/.well-known/oauth-protected-resource").json()
    assert meta["resource"].rstrip("/") == BASE


# ── registration is stateless ───────────────────────────────────────
def test_registration_encodes_the_client_in_its_id(client):
    """No storage: the client_id itself carries the redirect_uris, so a restarted
    container still recognises a client registered before the restart."""
    client_id = register(client)
    claims = oauth._decode(client_id, "client")
    assert claims is not None
    assert claims["c"]["redirect_uris"] == [REDIRECT]


def test_unknown_client_rejected(client):
    r = client.get("/authorize", params={
        "response_type": "code", "client_id": "not-a-token", "redirect_uri": REDIRECT,
        "code_challenge": CHALLENGE, "code_challenge_method": "S256",
    })
    assert r.status_code == 400


def test_unregistered_redirect_uri_rejected(client):
    client_id = register(client)
    r = client.get("/authorize", params={
        "response_type": "code", "client_id": client_id,
        "redirect_uri": "https://evil.example.com/cb",
        "code_challenge": CHALLENGE, "code_challenge_method": "S256",
    })
    assert r.status_code == 400


# ── the round-trip through Google ───────────────────────────────────
def test_authorize_redirects_to_google(client):
    client_id = register(client)
    r = client.get("/authorize", params={
        "response_type": "code", "client_id": client_id, "redirect_uri": REDIRECT,
        "code_challenge": CHALLENGE, "code_challenge_method": "S256", "state": "s",
    })
    assert r.status_code == 302
    url = urlparse(r.headers["location"])
    assert url.netloc == "accounts.google.com"
    q = parse_qs(url.query)
    assert q["scope"] == ["openid email"]          # identity only, no spreadsheet scope
    assert "access_type" not in q                   # no Google refresh token wanted
    assert q["redirect_uri"] == [f"{BASE}/google/callback"]


def test_callback_returns_code_and_preserves_state(client, google):
    client_id = register(client)
    params = callback(client, authorize(client, client_id, state="claude-state"))
    assert params["state"] == ["claude-state"]
    code = oauth._decode(params["code"][0], "code")
    assert code["email"] == "me@example.com"
    assert code["cid"] == client_id


def test_callback_with_expired_state(client, google):
    r = client.get("/google/callback", params={"code": "x", "state": "garbage"})
    assert r.status_code == 400
    assert "expired" in r.text.lower()


def test_callback_passes_google_error_back_to_client(client, google):
    client_id = register(client)
    state = authorize(client, client_id)
    r = client.get("/google/callback", params={"error": "access_denied", "state": state})
    assert r.status_code == 302
    assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["access_denied"]


# ── /token ──────────────────────────────────────────────────────────
def test_authorization_code_grant(client, google):
    _, tokens = full_flow(client)
    assert tokens["token_type"] == "Bearer"
    assert tokens["expires_in"] == oauth.ACCESS_TTL
    access = oauth._decode(tokens["access_token"], "access", audience=BASE)
    assert access["email"] == "me@example.com"
    assert access["sub"] == "google-sub-1"


def test_wrong_pkce_verifier_rejected(client, google):
    client_id = register(client)
    params = callback(client, authorize(client, client_id))
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": params["code"][0],
        "redirect_uri": REDIRECT, "client_id": client_id, "code_verifier": "b" * 64,
    })
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_code_from_another_client_rejected(client, google):
    """A code minted for one client must not be redeemable by another."""
    victim = register(client)
    attacker = register(client, redirect_uris=[REDIRECT])
    params = callback(client, authorize(client, victim))
    r = client.post("/token", data={
        "grant_type": "authorization_code", "code": params["code"][0],
        "redirect_uri": REDIRECT, "client_id": attacker, "code_verifier": VERIFIER,
    })
    assert r.status_code == 400


def test_refresh_grant(client, google):
    client_id, tokens = full_flow(client)
    r = client.post("/token", data={
        "grant_type": "refresh_token", "refresh_token": tokens["refresh_token"],
        "client_id": client_id,
    })
    assert r.status_code == 200, r.text
    refreshed = r.json()
    access = oauth._decode(refreshed["access_token"], "access", audience=BASE)
    assert access["email"] == "me@example.com"


def test_tokens_are_not_interchangeable(client, google):
    """The `typ` claim stops a refresh token being presented as an access token."""
    _, tokens = full_flow(client)
    assert oauth._decode(tokens["refresh_token"], "access", audience=BASE) is None
    assert oauth._decode(tokens["access_token"], "refresh") is None


def test_token_signed_with_another_key_rejected(client, google, monkeypatch):
    _, tokens = full_flow(client)
    monkeypatch.setenv("JWT_SIGNING_KEY", "a-different-key-that-is-also-long-enough-here")
    assert oauth._decode(tokens["access_token"], "access", audience=BASE) is None


# ── the MCP endpoint is actually protected ──────────────────────────
INITIALIZE = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
               "clientInfo": {"name": "test", "version": "1"}},
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


def test_mcp_endpoint_requires_a_token(client):
    r = client.post("/", json=INITIALIZE, headers=MCP_HEADERS)
    assert r.status_code == 401
    # This header is what makes Claude start the OAuth flow instead of giving up.
    assert "resource_metadata=" in r.headers["www-authenticate"]


def test_mcp_endpoint_accepts_an_issued_token(client, google):
    _, tokens = full_flow(client)
    r = client.post("/", json=INITIALIZE, headers={
        **MCP_HEADERS, "Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200, r.text


def test_health_needs_no_token(client):
    assert client.get("/health").json() == {"ok": True}


def test_cors_headers_on_the_mcp_endpoint(client):
    """claude.ai's web client is a browser origin, so preflight has to pass."""
    r = client.options("/", headers={
        "Origin": "https://claude.ai",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type",
    })
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "*"
