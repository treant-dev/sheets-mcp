"""DynamoDB access for the OAuth 2.1 AS (Phase 2 Step C).

Four tables, keyed and TTL'd per PHASE2-PLAN.md. This module is pure
persistence — callers (oauth.py) pass already-hashed secrets; we never hash or
mint here. Mirrors the sibling treant-calories-bot's ``dynamo.py`` idioms
(lazy module-level resource + env-var table names) so tests can swap ``_dynamo``.

Tables (env var → name):
  SHEETS_MCP_USERS_TABLE          → sheets_mcp_users          (PK user_id)
  SHEETS_MCP_OAUTH_CLIENTS_TABLE  → sheets_mcp_oauth_clients  (PK client_id)
  SHEETS_MCP_AUTH_CODES_TABLE     → sheets_mcp_auth_codes     (PK code_hash, TTL ttl)
  SHEETS_MCP_REFRESH_TOKENS_TABLE → sheets_mcp_refresh_tokens (PK token_hash)
"""
import os
import time

import boto3

_dynamo = None  # tests replace this with a fake resource


def _table(env_var):
    global _dynamo
    if _dynamo is None:
        _dynamo = boto3.resource("dynamodb")
    return _dynamo.Table(os.environ[env_var])


def _now():
    return int(time.time())


# ── users (per-user Google identities — Phase 3) ───────────────────
def get_user(user_id):
    """The user record, or None. ``user_id`` is the Google ``sub``."""
    return _table("SHEETS_MCP_USERS_TABLE").get_item(Key={"user_id": user_id}).get("Item")


def upsert_google_user(user_id, email, refresh_token_ct, granted_scopes):
    """Create or update a per-user Google identity (keyed by Google ``sub``).

    ``refresh_token_ct`` is the KMS ciphertext (bytes) of the Google refresh
    token, stored as a Binary attribute. ``created_at`` is preserved across
    re-consent (read-then-write — provisioning is rare and single-flow, so the
    non-atomicity is immaterial)."""
    table = _table("SHEETS_MCP_USERS_TABLE")
    existing = table.get_item(Key={"user_id": user_id}).get("Item")
    now = _now()
    table.put_item(Item={
        "user_id": user_id,
        "email": email,
        "refresh_token_ct": refresh_token_ct,
        "granted_scopes": granted_scopes,
        "status": "active",
        "created_at": existing["created_at"] if existing else now,
        "updated_at": now,
    })


# ── oauth_clients (Dynamic Client Registration) ───────────────────
def get_client(client_id):
    return _table("SHEETS_MCP_OAUTH_CLIENTS_TABLE").get_item(
        Key={"client_id": client_id}).get("Item")


def put_client(client_id, redirect_uris, client_name=""):
    """Register a client (DCR). ``redirect_uris`` is a list."""
    _table("SHEETS_MCP_OAUTH_CLIENTS_TABLE").put_item(Item={
        "client_id": client_id,
        "redirect_uris": list(redirect_uris),
        "client_name": client_name,
        "created_at": _now(),
    })


# ── auth_codes (short-lived PKCE codes, single-use) ────────────────
def put_auth_code(code_hash, client_id, user_id, code_challenge, redirect_uri, ttl):
    """Store an authorization code bound to its client/user/PKCE challenge.
    ``ttl`` is an absolute epoch second; DynamoDB TTL reaps it."""
    _table("SHEETS_MCP_AUTH_CODES_TABLE").put_item(Item={
        "code_hash": code_hash,
        "client_id": client_id,
        "user_id": user_id,
        "code_challenge": code_challenge,
        "redirect_uri": redirect_uri,
        "ttl": int(ttl),
    })


def pop_auth_code(code_hash):
    """Atomically fetch-and-delete a code (single-use). Returns the item or None.

    ``delete_item`` with ALL_OLD returns the row as it was before deletion; a
    second racing delete gets nothing, so a replay within the TTL fails. The
    caller must still check ``ttl`` against now (TTL reaping isn't instant).
    """
    old = _table("SHEETS_MCP_AUTH_CODES_TABLE").delete_item(
        Key={"code_hash": code_hash}, ReturnValues="ALL_OLD").get("Attributes")
    if not old:
        return None
    if int(old.get("ttl", 0)) < _now():
        return None  # expired but not yet reaped
    return old


# ── refresh_tokens (revocable) ─────────────────────────────────────
def put_refresh_token(token_hash, user_id, client_id):
    _table("SHEETS_MCP_REFRESH_TOKENS_TABLE").put_item(Item={
        "token_hash": token_hash,
        "user_id": user_id,
        "client_id": client_id,
        "created_at": _now(),
    })


def get_refresh_token(token_hash):
    return _table("SHEETS_MCP_REFRESH_TOKENS_TABLE").get_item(
        Key={"token_hash": token_hash}).get("Item")


def delete_refresh_token(token_hash):
    """Revoke a refresh token (per-user kill switch)."""
    _table("SHEETS_MCP_REFRESH_TOKENS_TABLE").delete_item(Key={"token_hash": token_hash})
