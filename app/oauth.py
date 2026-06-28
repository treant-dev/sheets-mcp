"""OAuth 2.1 Authorization Server (Phase 2 Step C).

A separate Lambda from the MCP handler, mounted on extra API Gateway routes.
Dispatches by path/method:

  GET  /.well-known/oauth-authorization-server  — AS metadata (RFC 8414)
  GET  /.well-known/oauth-protected-resource    — PR metadata (RFC 9728)
  POST /register                                — Dynamic Client Registration
  GET  /authorize                               — redirect to Google consent      [Phase 3]
  GET  /google/callback                         — Google returns → mint our code   [Phase 3]
  POST /token                                   — auth_code + refresh grants → JWT

Claude is a **public client** (PKCE S256, no client secret). Access tokens are
stateless HS256 JWTs; refresh tokens are random, stored hashed, and revocable.

Phase 3 — Google is the identity provider. /authorize hands the user off to
Google consent, carrying Claude's request (client/redirect/state/PKCE) across the
round-trip in a signed, short-lived ``state`` JWT (no server-side storage). On the
callback we exchange Google's code, derive the user's identity (Google ``sub``),
store the encrypted Google refresh token, then mint our own auth code for Claude.
``store.py`` is pure persistence — all hashing / PKCE / JWT work lives here.
"""
import base64
import hashlib
import json
import os
import secrets
import time
from urllib.parse import parse_qs, urlencode

import httpx
import jwt

import crypto
import secret_store
import store

_SCOPES = ["sheets"]
_ACCESS_TTL = 1800   # access-token lifetime, seconds (30 min)
_CODE_TTL = 300      # authorization-code lifetime, seconds (5 min)
_TXN_TTL = 600       # /authorize→Google→callback round-trip window, seconds (10 min)

# Google OAuth endpoints + the scopes we request: identity (openid/email) to key
# the user by Google `sub`, plus spreadsheets (read+write) for the actual work.
_GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
_GOOGLE_SCOPES = "openid email https://www.googleapis.com/auth/spreadsheets"
_GOOGLE_TIMEOUT = 15


# ── small HTTP helpers ──────────────────────────────────────────────
_CORS = {"Access-Control-Allow-Origin": "*"}  # browser-based claude.ai web needs this


def _json(status, body, extra_headers=None):
    headers = {"Content-Type": "application/json", **_CORS}
    if extra_headers:
        headers.update(extra_headers)
    return {"statusCode": status, "headers": headers, "body": json.dumps(body)}


def _html(status, markup):
    return {"statusCode": status,
            "headers": {"Content-Type": "text/html; charset=utf-8", **_CORS},
            "body": markup}


def _redirect(location):
    return {"statusCode": 302, "headers": {"Location": location, **_CORS}, "body": ""}


def _base_url(event):
    """This server's externally-visible base URL.

    Prefer an explicit PUBLIC_BASE_URL (set once we're behind the custom domain
    https://sheets-mcp.treant.dev — no stage in the path). Otherwise derive from
    the request, which on a raw execute-api URL includes the /{stage} segment."""
    explicit = os.environ.get("PUBLIC_BASE_URL")
    if explicit:
        return explicit.rstrip("/")
    rc = event.get("requestContext", {}) or {}
    host = (event.get("headers") or {}).get("Host") or rc.get("domainName")
    stage = rc.get("stage")
    base = f"https://{host}"
    if stage and stage != "$default":
        base += f"/{stage}"
    return base


def _form(event):
    """Parse an application/x-www-form-urlencoded body into a flat dict."""
    body = event.get("body") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode()
    return {k: v[0] for k, v in parse_qs(body).items()}


def _sha256_hex(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _pkce_s256(verifier):
    """BASE64URL(SHA256(verifier)) without padding — the S256 transform."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _with_query(url, params):
    sep = "&" if "?" in url else "?"
    return url + sep + urlencode(params)


# ── discovery (C2) ──────────────────────────────────────────────────
def _as_metadata(event):
    base = _base_url(event)
    return _json(200, {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": _SCOPES,
    })


def _pr_metadata(event):
    # Resource identifier = the bare origin (MCP served at POST /). Must be
    # byte-identical to the minted JWT `aud` and the authorizer's expected audience.
    base = _base_url(event)
    return _json(200, {"resource": base, "authorization_servers": [base]})


# ── DCR (C2) ────────────────────────────────────────────────────────
def _register(event):
    try:
        body = json.loads(event.get("body") or "{}")
    except ValueError:
        return _json(400, {"error": "invalid_client_metadata",
                           "error_description": "request body is not valid JSON"})
    redirect_uris = body.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return _json(400, {"error": "invalid_redirect_uri",
                           "error_description": "redirect_uris (non-empty array) is required"})
    if not all(isinstance(u, str) and u.startswith("https://") for u in redirect_uris):
        return _json(400, {"error": "invalid_redirect_uri",
                           "error_description": "every redirect_uri must be an https URL"})
    client_id = secrets.token_urlsafe(24)
    client_name = body.get("client_name", "")
    store.put_client(client_id, redirect_uris, client_name)
    return _json(201, {
        "client_id": client_id, "redirect_uris": redirect_uris, "client_name": client_name,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"],
    })


# ── /authorize (C3) ─────────────────────────────────────────────────
def _check_client_redirect(params):
    """Validate client_id + redirect_uri. Returns (client, redirect_uri) on success,
    or (None, error_response). These two are validated *before* any redirect — a bad
    redirect_uri must never be redirected to (anti-hijack)."""
    client_id = params.get("client_id", "")
    redirect_uri = params.get("redirect_uri", "")
    client = store.get_client(client_id) if client_id else None
    if not client:
        return None, _json(400, {"error": "invalid_client",
                                 "error_description": "unknown client_id"})
    if redirect_uri not in client.get("redirect_uris", []):
        return None, _json(400, {"error": "invalid_request",
                                 "error_description": "redirect_uri not registered for this client"})
    return client, redirect_uri


def _err_params(error, p):
    params = {"error": error}
    if p.get("state"):
        params["state"] = p["state"]
    return params


def _issue_code(client_id, redirect_uri, code_challenge, state, user_id):
    """Mint a single-use auth code bound to (client, user, redirect, PKCE) and
    302-redirect back to the client with `code` (+ `state` if present)."""
    code = secrets.token_urlsafe(32)
    store.put_auth_code(_sha256_hex(code), client_id, user_id,
                        code_challenge, redirect_uri, ttl=int(time.time()) + _CODE_TTL)
    out = {"code": code}
    if state:
        out["state"] = state
    return _redirect(_with_query(redirect_uri, out))


# ── cross-leg state: a signed, short-lived JWT carried through Google ───
# Claude's request (client/redirect/state/PKCE) round-trips through Google in the
# `state` param. Signed with our JWT key → tamper-proof; expires in _TXN_TTL → no
# server-side storage, and any container can validate it (key lives in SSM).
def _encode_txn(client_id, redirect_uri, claude_state, code_challenge):
    now = int(time.time())
    payload = {"cid": client_id, "ruri": redirect_uri, "cs": claude_state or "",
               "cc": code_challenge, "iat": now, "exp": now + _TXN_TTL}
    return jwt.encode(payload, secret_store.get_secret("jwt_signing_key"), algorithm="HS256")


def _decode_txn(state):
    try:
        return jwt.decode(state or "", secret_store.get_secret("jwt_signing_key"),
                          algorithms=["HS256"], options={"require": ["exp"]})
    except Exception:
        return None


def _authorize_get(event):
    """Leg 1: validate Claude's request, then hand off to Google consent."""
    p = event.get("queryStringParameters") or {}
    client, redirect_uri_or_err = _check_client_redirect(p)
    if client is None:
        return redirect_uri_or_err
    redirect_uri = redirect_uri_or_err
    # Post-redirect-uri-validation errors are reported by redirecting with ?error=.
    if p.get("response_type") != "code":
        return _redirect(_with_query(redirect_uri, _err_params("unsupported_response_type", p)))
    if not p.get("code_challenge") or p.get("code_challenge_method") != "S256":
        return _redirect(_with_query(redirect_uri, _err_params("invalid_request", p)))
    state = _encode_txn(client["client_id"], redirect_uri, p.get("state"), p["code_challenge"])
    return _redirect(_with_query(_GOOGLE_AUTH, {
        "client_id": secret_store.get_secret("google_oauth_client_id"),
        "redirect_uri": f"{_base_url(event)}/google/callback",
        "response_type": "code",
        "scope": _GOOGLE_SCOPES,
        "access_type": "offline",   # ask Google for a refresh_token
        "prompt": "consent",        # force consent → always returns a refresh_token
        "include_granted_scopes": "true",
        "state": state,
    }))


# ── /google/callback (Phase 3) ──────────────────────────────────────
def _exchange_google_code(code, redirect_uri):
    """Exchange Google's authorization code for tokens, or None on failure."""
    try:
        r = httpx.post(_GOOGLE_TOKEN, timeout=_GOOGLE_TIMEOUT, data={
            "code": code,
            "client_id": secret_store.get_secret("google_oauth_client_id"),
            "client_secret": secret_store.get_secret("google_oauth_client_secret"),
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        })
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def _identity_from_id_token(id_token):
    """(sub, email) from Google's id_token, WITHOUT signature verification — it
    came straight from Google's token endpoint over TLS (OIDC permits trusting
    tokens obtained directly via a secure channel). Returns (None, None) on error."""
    if not id_token:
        return None, None
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # restore base64url padding
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims.get("sub"), claims.get("email")
    except Exception:
        return None, None


def _google_callback(event):
    """Leg 2: Google returns here. Verify the state, exchange the code, provision
    the user, then mint our own auth code back to Claude."""
    p = event.get("queryStringParameters") or {}
    txn = _decode_txn(p.get("state"))
    if not txn:
        return _html(400, "<!doctype html><meta charset=utf-8><h1>Authorization expired</h1>"
                          "<p>This sign-in link is invalid or expired. Please reconnect.</p>")
    redirect_uri, claude_state = txn["ruri"], txn["cs"]

    def _bounce(error):
        out = {"error": error}
        if claude_state:
            out["state"] = claude_state
        return _redirect(_with_query(redirect_uri, out))

    if p.get("error"):                       # user denied at Google's consent screen
        return _bounce(p["error"])
    code = p.get("code")
    if not code:
        return _bounce("invalid_request")

    tok = _exchange_google_code(code, f"{_base_url(event)}/google/callback")
    if not tok:
        return _bounce("server_error")
    sub, email = _identity_from_id_token(tok.get("id_token"))
    if not sub:
        return _bounce("server_error")

    # prompt=consent guarantees a refresh_token on every pass; if Google still
    # omits it (edge case), keep whatever we already stored for this user.
    refresh = tok.get("refresh_token")
    if refresh:
        store.upsert_google_user(sub, email, crypto.encrypt_refresh_token(refresh),
                                 tok.get("scope", ""))

    return _issue_code(txn["cid"], redirect_uri, txn["cc"], claude_state, sub)


# ── /token (C3) ─────────────────────────────────────────────────────
def _mint_access_token(user_id, base):
    now = int(time.time())
    payload = {
        "sub": user_id, "iss": base, "aud": base,
        "iat": now, "exp": now + _ACCESS_TTL, "scope": "sheets",
    }
    return jwt.encode(payload, secret_store.get_secret("jwt_signing_key"), algorithm="HS256")


def _token_response(user_id, base, refresh_token):
    return _json(200, {
        "access_token": _mint_access_token(user_id, base),
        "token_type": "Bearer",
        "expires_in": _ACCESS_TTL,
        "refresh_token": refresh_token,
        "scope": "sheets",
    }, extra_headers={"Cache-Control": "no-store"})


def _grant_auth_code(f, base):
    code = f.get("code")
    client_id = f.get("client_id")
    redirect_uri = f.get("redirect_uri")
    verifier = f.get("code_verifier")
    if not (code and client_id and redirect_uri and verifier):
        return _json(400, {"error": "invalid_request",
                           "error_description": "code, client_id, redirect_uri, code_verifier required"})
    item = store.pop_auth_code(_sha256_hex(code))   # single-use + expiry-checked
    if not item:
        return _json(400, {"error": "invalid_grant", "error_description": "code invalid or expired"})
    if item["client_id"] != client_id or item["redirect_uri"] != redirect_uri:
        return _json(400, {"error": "invalid_grant", "error_description": "code/client/redirect mismatch"})
    if _pkce_s256(verifier) != item["code_challenge"]:
        return _json(400, {"error": "invalid_grant", "error_description": "PKCE verification failed"})

    refresh = secrets.token_urlsafe(32)
    store.put_refresh_token(_sha256_hex(refresh), item["user_id"], client_id)
    return _token_response(item["user_id"], base, refresh)


def _grant_refresh(f, base):
    refresh = f.get("refresh_token")
    client_id = f.get("client_id")
    if not (refresh and client_id):
        return _json(400, {"error": "invalid_request",
                           "error_description": "refresh_token and client_id required"})
    row = store.get_refresh_token(_sha256_hex(refresh))
    if not row or row["client_id"] != client_id:
        return _json(400, {"error": "invalid_grant", "error_description": "unknown refresh token"})
    # Rotation: invalidate the used token, issue a fresh one (limits replay).
    store.delete_refresh_token(_sha256_hex(refresh))
    new_refresh = secrets.token_urlsafe(32)
    store.put_refresh_token(_sha256_hex(new_refresh), row["user_id"], client_id)
    return _token_response(row["user_id"], base, new_refresh)


def _token(event):
    f = _form(event)
    base = _base_url(event)
    grant = f.get("grant_type")
    if grant == "authorization_code":
        return _grant_auth_code(f, base)
    if grant == "refresh_token":
        return _grant_refresh(f, base)
    return _json(400, {"error": "unsupported_grant_type",
                       "error_description": f"unsupported grant_type: {grant!r}"})


# ── router ──────────────────────────────────────────────────────────
def lambda_handler(event, context):
    method = event.get("httpMethod", "")
    path = event.get("path", "") or ""
    if method == "GET" and path.endswith("/.well-known/oauth-authorization-server"):
        return _as_metadata(event)
    if method == "GET" and path.endswith("/.well-known/oauth-protected-resource"):
        return _pr_metadata(event)
    if method == "POST" and path.endswith("/register"):
        return _register(event)
    if method == "GET" and path.endswith("/authorize"):
        return _authorize_get(event)
    if method == "GET" and path.endswith("/google/callback"):
        return _google_callback(event)
    if method == "POST" and path.endswith("/token"):
        return _token(event)
    return _json(404, {"error": "not_found", "error_description": f"{method} {path}"})
