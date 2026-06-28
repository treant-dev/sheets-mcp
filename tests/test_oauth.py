"""Tests for the OAuth AS discovery + DCR endpoints (Step C2).

Drives oauth.lambda_handler with API-Gateway-proxy events; the DynamoDB layer is
the same in-memory fake used by test_store.
"""
import base64
import json
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlparse

import jwt
import pytest

import oauth
import store
from test_store import _FakeDynamo

HOST = "abc123.execute-api.eu-central-1.amazonaws.com"
BASE = f"https://{HOST}/prod"
JWT_KEY = "test-signing-key"


@pytest.fixture(autouse=True)
def fake_dynamo(monkeypatch):
    for env, name in [
        ("SHEETS_MCP_USERS_TABLE", "sheets_mcp_users"),
        ("SHEETS_MCP_OAUTH_CLIENTS_TABLE", "sheets_mcp_oauth_clients"),
        ("SHEETS_MCP_AUTH_CODES_TABLE", "sheets_mcp_auth_codes"),
        ("SHEETS_MCP_REFRESH_TOKENS_TABLE", "sheets_mcp_refresh_tokens"),
    ]:
        monkeypatch.setenv(env, name)
    monkeypatch.setenv("JWT_SIGNING_KEY", JWT_KEY)
    # Google client creds (local env mode — no SSM). No KMS_KEY_ID → crypto passes through.
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "google-client-id.apps.googleusercontent.com")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "google-client-secret")
    monkeypatch.setattr(store, "_dynamo", _FakeDynamo())
    # secret_store caches via lru_cache — clear so JWT_SIGNING_KEY is re-read each test
    import secret_store
    secret_store.get_secret.cache_clear()


def _event(method, path, body=None):
    return {
        "httpMethod": method,
        "path": path,
        "headers": {"Host": HOST},
        "requestContext": {"stage": "prod", "domainName": HOST},
        "body": json.dumps(body) if body is not None else None,
    }


def _call(method, path, body=None):
    resp = oauth.lambda_handler(_event(method, path, body), None)
    return resp["statusCode"], json.loads(resp["body"])


def test_as_metadata_urls_include_stage():
    st, doc = _call("GET", "/prod/.well-known/oauth-authorization-server")
    base = f"https://{HOST}/prod"
    assert st == 200
    assert doc["issuer"] == base
    assert doc["authorization_endpoint"] == f"{base}/authorize"
    assert doc["token_endpoint"] == f"{base}/token"
    assert doc["registration_endpoint"] == f"{base}/register"
    assert doc["code_challenge_methods_supported"] == ["S256"]
    assert doc["token_endpoint_auth_methods_supported"] == ["none"]


def test_pr_metadata_points_at_mcp_and_as():
    st, doc = _call("GET", "/prod/.well-known/oauth-protected-resource")
    base = f"https://{HOST}/prod"
    assert st == 200
    assert doc["resource"] == base
    assert doc["authorization_servers"] == [base]


def test_register_persists_and_returns_public_client():
    st, doc = _call("POST", "/prod/register",
                    {"redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
                     "client_name": "Claude"})
    assert st == 201
    assert doc["client_id"] and doc["token_endpoint_auth_method"] == "none"
    assert "client_secret" not in doc
    # persisted and retrievable
    saved = store.get_client(doc["client_id"])
    assert saved["redirect_uris"] == ["https://claude.ai/api/mcp/auth_callback"]


def test_register_rejects_missing_redirect_uris():
    st, doc = _call("POST", "/prod/register", {"client_name": "NoRedirect"})
    assert st == 400 and doc["error"] == "invalid_redirect_uri"


def test_register_rejects_non_https_redirect():
    st, doc = _call("POST", "/prod/register", {"redirect_uris": ["http://evil.test/cb"]})
    assert st == 400 and doc["error"] == "invalid_redirect_uri"


def test_unknown_route_404():
    st, doc = _call("GET", "/prod/nope")
    assert st == 404 and doc["error"] == "not_found"


# ── Phase 3: Google-leg flow ────────────────────────────────────────
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "a" * 64                      # the PKCE code_verifier the client keeps
CHALLENGE = oauth._pkce_s256(VERIFIER)   # what the client sends to /authorize


def _setup_client():
    store.put_client("client-1", [REDIRECT], "Claude")


def _authorize_params(state="xyz"):
    return {"response_type": "code", "client_id": "client-1", "redirect_uri": REDIRECT,
            "code_challenge": CHALLENGE, "code_challenge_method": "S256",
            "scope": "sheets", "state": state}


def _authorize_get(params):
    return oauth.lambda_handler(
        {"httpMethod": "GET", "path": "/prod/authorize", "headers": {"Host": HOST},
         "requestContext": {"stage": "prod", "domainName": HOST},
         "queryStringParameters": params}, None)


def _callback_get(params):
    return oauth.lambda_handler(
        {"httpMethod": "GET", "path": "/prod/google/callback", "headers": {"Host": HOST},
         "requestContext": {"stage": "prod", "domainName": HOST},
         "queryStringParameters": params}, None)


def _token_post(params):
    resp = oauth.lambda_handler(
        {"httpMethod": "POST", "path": "/prod/token", "headers": {"Host": HOST},
         "requestContext": {"stage": "prod", "domainName": HOST},
         "body": urlencode(params)}, None)
    return resp["statusCode"], json.loads(resp["body"])


def _query(resp):
    assert resp["statusCode"] == 302
    return parse_qs(urlparse(resp["headers"]["Location"]).query)


def _fake_id_token(sub, email):
    """A JWT-shaped string with an unsigned, decodable payload — Google's id_token
    is trusted via the TLS channel, so the callback only base64-decodes it."""
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": sub, "email": email}).encode()).rstrip(b"=").decode()
    return f"header.{payload}.sig"


def _issue_our_code(user_id="google-sub-1"):
    """Mint a valid auth code directly (bypassing the Google leg) so /token tests
    run in isolation — equivalent to what _issue_code does on a real callback."""
    code = secrets.token_urlsafe(16)
    store.put_auth_code(oauth._sha256_hex(code), "client-1", user_id, CHALLENGE, REDIRECT,
                        ttl=int(time.time()) + 300)
    return code


# ── /authorize → Google hand-off ────────────────────────────────────
def test_authorize_get_redirects_to_google():
    _setup_client()
    resp = _authorize_get(_authorize_params())
    assert resp["statusCode"] == 302
    loc = urlparse(resp["headers"]["Location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == oauth._GOOGLE_AUTH
    q = parse_qs(loc.query)
    assert q["redirect_uri"] == [f"{BASE}/google/callback"]
    assert q["access_type"] == ["offline"] and q["prompt"] == ["consent"]
    assert "spreadsheets" in q["scope"][0] and "openid" in q["scope"][0]
    # the signed state round-trips Claude's original request
    txn = jwt.decode(q["state"][0], JWT_KEY, algorithms=["HS256"])
    assert txn["cid"] == "client-1" and txn["ruri"] == REDIRECT
    assert txn["cc"] == CHALLENGE and txn["cs"] == "xyz"


def test_authorize_get_unregistered_redirect_is_400_not_redirect():
    _setup_client()
    p = _authorize_params(); p["redirect_uri"] = "https://evil.test/cb"
    assert _authorize_get(p)["statusCode"] == 400  # must NOT redirect to an unregistered uri


def test_authorize_get_missing_pkce_redirects_error():
    _setup_client()
    p = _authorize_params(); del p["code_challenge"]
    q = _query(_authorize_get(p))
    assert q["error"] == ["invalid_request"] and q["state"] == ["xyz"]


# ── /google/callback → provision user + mint our code ───────────────
def test_google_callback_provisions_user_and_issues_our_code(monkeypatch):
    _setup_client()
    state = oauth._encode_txn("client-1", REDIRECT, "xyz", CHALLENGE)
    monkeypatch.setattr(oauth, "_exchange_google_code", lambda code, ru: {
        "refresh_token": "google-refresh-tok",
        "scope": "openid email https://www.googleapis.com/auth/spreadsheets",
        "id_token": _fake_id_token("google-sub-1", "k@mu.se"),
    })
    q = _query(_callback_get({"code": "google-code", "state": state}))
    assert q["state"] == ["xyz"]
    our_code = q["code"][0]
    # user provisioned, refresh token stored (pass-through "ciphertext", no KMS)
    u = store.get_user("google-sub-1")
    assert u["email"] == "k@mu.se" and bytes(u["refresh_token_ct"]) == b"google-refresh-tok"
    # our code exchanges for a JWT whose sub == the Google sub
    st, tok = _token_post({"grant_type": "authorization_code", "code": our_code,
                           "client_id": "client-1", "redirect_uri": REDIRECT,
                           "code_verifier": VERIFIER})
    assert st == 200
    claims = jwt.decode(tok["access_token"], JWT_KEY, algorithms=["HS256"], audience=BASE)
    assert claims["sub"] == "google-sub-1"


def test_google_callback_user_denied_bounces_to_claude():
    state = oauth._encode_txn("client-1", REDIRECT, "xyz", CHALLENGE)
    q = _query(_callback_get({"error": "access_denied", "state": state}))
    assert q["error"] == ["access_denied"] and q["state"] == ["xyz"]


def test_google_callback_bad_state_is_400():
    assert _callback_get({"code": "x", "state": "garbage"})["statusCode"] == 400


# ── /token grants (exercised via a directly-minted code) ─────────────
def test_token_exchange_and_jwt_claims():
    _setup_client()
    code = _issue_our_code("google-sub-9")
    st, tok = _token_post({"grant_type": "authorization_code", "code": code,
                           "client_id": "client-1", "redirect_uri": REDIRECT,
                           "code_verifier": VERIFIER})
    assert st == 200 and tok["token_type"] == "Bearer" and tok["refresh_token"]
    claims = jwt.decode(tok["access_token"], JWT_KEY, algorithms=["HS256"], audience=BASE)
    assert claims["sub"] == "google-sub-9" and claims["iss"] == BASE
    assert claims["aud"] == BASE and claims["scope"] == "sheets"


def test_pkce_mismatch_rejected():
    _setup_client()
    code = _issue_our_code()
    st, tok = _token_post({"grant_type": "authorization_code", "code": code,
                           "client_id": "client-1", "redirect_uri": REDIRECT,
                           "code_verifier": "b" * 64})   # wrong verifier
    assert st == 400 and tok["error"] == "invalid_grant"


def test_auth_code_is_single_use_at_token():
    _setup_client()
    code = _issue_our_code()
    args = {"grant_type": "authorization_code", "code": code, "client_id": "client-1",
            "redirect_uri": REDIRECT, "code_verifier": VERIFIER}
    assert _token_post(args)[0] == 200
    assert _token_post(args)[1]["error"] == "invalid_grant"   # replay fails


def test_redirect_uri_mismatch_at_token_rejected():
    _setup_client()
    code = _issue_our_code()
    st, tok = _token_post({"grant_type": "authorization_code", "code": code,
                           "client_id": "client-1", "redirect_uri": "https://claude.ai/other",
                           "code_verifier": VERIFIER})
    assert st == 400 and tok["error"] == "invalid_grant"


def test_refresh_grant_rotates():
    _setup_client()
    code = _issue_our_code()
    _, tok = _token_post({"grant_type": "authorization_code", "code": code,
                          "client_id": "client-1", "redirect_uri": REDIRECT,
                          "code_verifier": VERIFIER})
    rt = tok["refresh_token"]

    st, tok2 = _token_post({"grant_type": "refresh_token", "refresh_token": rt,
                            "client_id": "client-1"})
    assert st == 200 and tok2["refresh_token"] != rt   # rotated
    # the old refresh token is now invalid
    assert _token_post({"grant_type": "refresh_token", "refresh_token": rt,
                        "client_id": "client-1"})[1]["error"] == "invalid_grant"
    # the new one works
    assert _token_post({"grant_type": "refresh_token", "refresh_token": tok2["refresh_token"],
                        "client_id": "client-1"})[0] == 200


def test_unsupported_grant_type():
    st, tok = _token_post({"grant_type": "password", "username": "x"})
    assert st == 400 and tok["error"] == "unsupported_grant_type"
