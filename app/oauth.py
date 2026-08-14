"""OAuth 2.1 authorization server — stateless, backed by signed JWTs.

The MCP SDK already implements the protocol surface: discovery metadata, dynamic
client registration, ``/authorize``, ``/token``, PKCE verification, and the 401 +
``WWW-Authenticate`` response that makes Claude start the flow. All it needs is a
provider that can persist and load four things: clients, authorization codes,
refresh tokens and access tokens.

We persist none of them. Each one is an HS256 JWT signed with ``JWT_SIGNING_KEY``
that carries its own contents, so "loading" is just verifying a signature. That
means no database, no volume, and no state to lose when the container restarts.
The trade-offs of going stateless, deliberately accepted here:

  - authorization codes cannot be marked single-use; they expire in five minutes
    and are bound to a PKCE challenge, so replaying one requires the verifier that
    only the legitimate client holds;
  - refresh tokens cannot be revoked individually — rotating ``JWT_SIGNING_KEY``
    revokes everything at once.

Google is only an identity provider here: we ask for ``openid email`` and nothing
else, because the actual spreadsheet access uses the server's service account. No
Google refresh token is requested, so there is nothing to encrypt or store.
"""
import base64
import json
import time
from urllib.parse import urlencode

import httpx
import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.responses import HTMLResponse, RedirectResponse

import config

ACCESS_TTL = 1800            # access token, seconds (30 min)
CODE_TTL = 300               # authorization code (5 min)
TXN_TTL = 600                # /authorize → Google → callback round-trip (10 min)
REFRESH_TTL = 30 * 24 * 3600  # refresh token (30 days)
SCOPES = ["sheets"]

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_SCOPES = "openid email"   # identity only — sheets are read via the service account
GOOGLE_TIMEOUT = 15
GOOGLE_CALLBACK_PATH = "/google/callback"


# ── JWT helpers ─────────────────────────────────────────────────────
def _encode(typ, payload, ttl=None):
    body = {**payload, "typ": typ, "iat": int(time.time())}
    if ttl is not None:
        body["exp"] = int(time.time()) + ttl
    return jwt.encode(body, config.jwt_signing_key(), algorithm="HS256")


def _decode(token, typ, audience=None):
    """Verify and decode one of our tokens, or return None. The algorithm is
    pinned to HS256 — accepting the token's own ``alg`` is the classic JWT
    confusion bug. ``typ`` keeps the four token kinds from being used in each
    other's place."""
    try:
        claims = jwt.decode(
            token or "",
            config.jwt_signing_key(),
            algorithms=["HS256"],
            audience=audience,
            options={"verify_aud": audience is not None},
        )
    except Exception:
        return None
    return claims if claims.get("typ") == typ else None


def google_redirect_uri():
    return config.public_base_url() + GOOGLE_CALLBACK_PATH


# ── code / token models carrying the user's identity ────────────────
class _Code(AuthorizationCode):
    email: str
    sub: str


class _Refresh(RefreshToken):
    email: str
    sub: str


class StatelessProvider(OAuthAuthorizationServerProvider):
    """Implements the SDK's provider protocol with signed tokens instead of storage."""

    # ── clients ─────────────────────────────────────────────────────
    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Registration with nowhere to register to: we fold the client's metadata
        into its own ``client_id``. The SDK generated a random id and will echo
        back whatever this leaves on the object, so replacing it here is what makes
        ``get_client`` work later without a lookup table.

        The SDK's random id is kept inside the token: without it two registrations
        sharing the same metadata would encode to the same string and become the
        same client."""
        metadata = client_info.model_dump(mode="json", exclude_none=True)
        generated_id = metadata.pop("client_id", None)
        metadata.pop("client_id_issued_at", None)
        client_info.client_id = _encode("client", {"c": metadata, "n": generated_id})

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        claims = _decode(client_id, "client")
        if not claims:
            return None
        try:
            return OAuthClientInformationFull.model_validate({**claims["c"], "client_id": client_id})
        except Exception:
            return None

    # ── /authorize: hand off to Google ──────────────────────────────
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        """Leg 1. Claude's request round-trips through Google inside the ``state``
        parameter, signed so it cannot be tampered with and short-lived so it needs
        no server-side record."""
        state = _encode("txn", {
            "cid": client.client_id,
            "ruri": str(params.redirect_uri),
            "expl": params.redirect_uri_provided_explicitly,
            "cc": params.code_challenge,
            "cs": params.state or "",
            "sc": params.scopes or list(SCOPES),
            "res": params.resource,
        }, ttl=TXN_TTL)
        return GOOGLE_AUTH + "?" + urlencode({
            "client_id": config.google_client_id(),
            "redirect_uri": google_redirect_uri(),
            "response_type": "code",
            "scope": GOOGLE_SCOPES,
            "include_granted_scopes": "true",
            "state": state,
        })

    # ── /token: authorization_code grant ────────────────────────────
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> _Code | None:
        claims = _decode(authorization_code, "code")
        if not claims:
            return None
        return _Code(
            code=authorization_code,
            scopes=claims["sc"],
            expires_at=claims["exp"],
            client_id=claims["cid"],
            code_challenge=claims["cc"],
            redirect_uri=claims["ruri"],
            redirect_uri_provided_explicitly=claims["expl"],
            resource=claims.get("res"),
            subject=claims["email"],
            email=claims["email"],
            sub=claims["sub"],
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: _Code
    ) -> OAuthToken:
        # The SDK has already checked expiry, redirect_uri and the PKCE verifier.
        return self._tokens(authorization_code.sub, authorization_code.email,
                            client.client_id, authorization_code.scopes)

    # ── /token: refresh_token grant ─────────────────────────────────
    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> _Refresh | None:
        claims = _decode(refresh_token, "refresh")
        if not claims:
            return None
        return _Refresh(
            token=refresh_token,
            client_id=claims["cid"],
            scopes=claims["sc"],
            expires_at=claims["exp"],
            subject=claims["email"],
            email=claims["email"],
            sub=claims["sub"],
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: _Refresh, scopes: list[str]
    ) -> OAuthToken:
        return self._tokens(refresh_token.sub, refresh_token.email,
                            client.client_id, scopes or refresh_token.scopes)

    # ── resource-server side ────────────────────────────────────────
    async def load_access_token(self, token: str) -> AccessToken | None:
        claims = _decode(token, "access", audience=config.public_base_url())
        if not claims:
            return None
        return AccessToken(
            token=token,
            client_id=claims["cid"],
            scopes=(claims.get("scope") or "").split(),
            expires_at=claims.get("exp"),
            resource=claims.get("aud"),
            subject=claims.get("sub"),
            claims={"email": claims.get("email"), "iss": claims.get("iss")},
        )

    async def revoke_token(self, token) -> None:
        """No-op: nothing is stored, so there is nothing to delete. Tokens expire on
        their own; rotating JWT_SIGNING_KEY invalidates all of them at once."""

    # ── minting ─────────────────────────────────────────────────────
    def _tokens(self, sub, email, client_id, scopes):
        base = config.public_base_url()
        access = _encode("access", {
            "sub": sub, "email": email, "cid": client_id,
            "scope": " ".join(scopes), "iss": base, "aud": base,
        }, ttl=ACCESS_TTL)
        refresh = _encode("refresh", {
            "sub": sub, "email": email, "cid": client_id, "sc": scopes,
        }, ttl=REFRESH_TTL)
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )


# ── /google/callback ────────────────────────────────────────────────
def _identity_from_id_token(id_token):
    """(sub, email) from Google's id_token, WITHOUT signature verification — it came
    straight from Google's token endpoint over TLS, which OIDC permits trusting.
    Returns (None, None) on error."""
    if not id_token:
        return None, None
    try:
        payload = id_token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # restore base64url padding
        claims = json.loads(base64.urlsafe_b64decode(payload))
        return claims.get("sub"), claims.get("email")
    except Exception:
        return None, None


async def _exchange_google_code(code):
    try:
        async with httpx.AsyncClient(timeout=GOOGLE_TIMEOUT) as http:
            r = await http.post(GOOGLE_TOKEN, data={
                "code": code,
                "client_id": config.google_client_id(),
                "client_secret": config.google_client_secret(),
                "redirect_uri": google_redirect_uri(),
                "grant_type": "authorization_code",
            })
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


async def google_callback(request):
    """Leg 2. Google sends the user back here; we turn their identity into an
    authorization code for Claude and bounce to the client's redirect_uri."""
    params = request.query_params
    txn = _decode(params.get("state"), "txn")
    if not txn:
        return HTMLResponse(
            "<!doctype html><meta charset=utf-8><h1>Sign-in expired</h1>"
            "<p>This link is invalid or expired. Please reconnect.</p>", status_code=400)

    def bounce(error):
        return RedirectResponse(
            construct_redirect_uri(txn["ruri"], error=error, state=txn["cs"] or None),
            status_code=302)

    if params.get("error"):          # user declined at Google's consent screen
        return bounce(params["error"])
    code = params.get("code")
    if not code:
        return bounce("invalid_request")

    tok = await _exchange_google_code(code)
    if not tok:
        return bounce("server_error")
    sub, email = _identity_from_id_token(tok.get("id_token"))
    if not sub or not email:
        return bounce("server_error")

    mcp_code = _encode("code", {
        "cid": txn["cid"], "ruri": txn["ruri"], "expl": txn["expl"], "cc": txn["cc"],
        "sc": txn["sc"], "res": txn.get("res"), "sub": sub, "email": email,
    }, ttl=CODE_TTL)
    return RedirectResponse(
        construct_redirect_uri(txn["ruri"], code=mcp_code, state=txn["cs"] or None),
        status_code=302)
