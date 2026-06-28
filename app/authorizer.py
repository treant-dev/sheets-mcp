"""API Gateway Lambda Authorizer for /mcp (Phase 2 Step C4).

A REQUEST-type authorizer. Validates the Bearer JWT minted by oauth.py:
  - signature, with the algorithm **pinned to HS256** (reject `none`/others —
    the classic JWT-confusion bug);
  - `exp` (not expired);
  - `aud` == this server's resource URI (the bare origin; MCP served at POST /).

On success → an Allow policy with `user_id` as the principal and in the context
(so /mcp can scope to the user). Any failure → ``raise Exception("Unauthorized")``,
which API Gateway renders as **401** — and the UNAUTHORIZED GatewayResponse in
template.yaml adds the `WWW-Authenticate` header that tells Claude to begin OAuth.
"""
import os

import jwt

import secret_store


def _base_url(event):
    # Must match how oauth.py builds the base (so the JWT `aud` lines up).
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


def _bearer(event):
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    return auth[7:].strip() if auth.startswith("Bearer ") else None


def _policy(principal, effect, resource, ctx=None):
    out = {
        "principalId": principal,
        "policyDocument": {"Version": "2012-10-17", "Statement": [
            {"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}]},
    }
    if ctx:
        out["context"] = ctx
    return out


def lambda_handler(event, context):
    token = _bearer(event)
    if not token:
        raise Exception("Unauthorized")
    try:
        claims = jwt.decode(
            token,
            secret_store.get_secret("jwt_signing_key"),
            algorithms=["HS256"],                 # pin alg — reject `none`/others
            audience=_base_url(event),             # bare origin — must match the token's `aud`
            options={"require": ["exp", "sub", "aud"]},
        )
    except Exception:
        raise Exception("Unauthorized")

    user_id = claims.get("sub")
    if not user_id:
        raise Exception("Unauthorized")
    # Allow on the whole API for this caller (single /mcp route); user_id → context.
    return _policy(user_id, "Allow", event["methodArn"], {"user_id": user_id})
