"""Unit tests for the OAuth DynamoDB data layer (app/store.py).

No AWS / moto: a tiny in-memory fake stands in for the boto3 resource, exercising
the behaviour we actually depend on (single-use code pop, invite-code lookup,
refresh-token lifecycle). Table names come from env vars, set in conftest-free
fashion here.
"""
import time

import pytest

import store


class _FakeTable:
    def __init__(self, key_name):
        self._key = key_name
        self._items = {}

    def put_item(self, Item):
        self._items[Item[self._key]] = dict(Item)

    def get_item(self, Key):
        item = self._items.get(Key[self._key])
        return {"Item": dict(item)} if item else {}

    def delete_item(self, Key, ReturnValues=None):
        old = self._items.pop(Key[self._key], None)
        if ReturnValues == "ALL_OLD" and old is not None:
            return {"Attributes": dict(old)}
        return {}


class _FakeDynamo:
    def __init__(self):
        self._tables = {
            "sheets_mcp_users": _FakeTable("user_id"),
            "sheets_mcp_oauth_clients": _FakeTable("client_id"),
            "sheets_mcp_auth_codes": _FakeTable("code_hash"),
            "sheets_mcp_refresh_tokens": _FakeTable("token_hash"),
        }

    def Table(self, name):
        return self._tables[name]


@pytest.fixture(autouse=True)
def fake_dynamo(monkeypatch):
    monkeypatch.setenv("SHEETS_MCP_USERS_TABLE", "sheets_mcp_users")
    monkeypatch.setenv("SHEETS_MCP_OAUTH_CLIENTS_TABLE", "sheets_mcp_oauth_clients")
    monkeypatch.setenv("SHEETS_MCP_AUTH_CODES_TABLE", "sheets_mcp_auth_codes")
    monkeypatch.setenv("SHEETS_MCP_REFRESH_TOKENS_TABLE", "sheets_mcp_refresh_tokens")
    monkeypatch.setattr(store, "_dynamo", _FakeDynamo())


def test_google_user_upsert_roundtrip():
    store.upsert_google_user("google-sub-1", "k@mu.se", b"ciphertext", "scope-a")
    u = store.get_user("google-sub-1")
    assert u["email"] == "k@mu.se"
    assert bytes(u["refresh_token_ct"]) == b"ciphertext"
    assert u["granted_scopes"] == "scope-a" and u["status"] == "active"
    assert u["created_at"] == u["updated_at"]   # first write


def test_google_user_upsert_preserves_created_at():
    store.upsert_google_user("google-sub-2", "a@mu.se", b"ct1", "scope-a")
    created = store.get_user("google-sub-2")["created_at"]
    # re-consent: new token/email, but created_at must be preserved
    store.upsert_google_user("google-sub-2", "a2@mu.se", b"ct2", "scope-b")
    u = store.get_user("google-sub-2")
    assert u["created_at"] == created
    assert u["email"] == "a2@mu.se" and bytes(u["refresh_token_ct"]) == b"ct2"
    assert u["updated_at"] >= u["created_at"]


def test_client_roundtrip():
    store.put_client("c1", ["https://claude.ai/cb"], client_name="Claude")
    c = store.get_client("c1")
    assert c["redirect_uris"] == ["https://claude.ai/cb"]


def test_auth_code_is_single_use():
    store.put_auth_code("code-h", "c1", "u1", "challenge", "https://claude.ai/cb",
                        ttl=int(time.time()) + 300)
    first = store.pop_auth_code("code-h")
    assert first and first["user_id"] == "u1" and first["code_challenge"] == "challenge"
    # second use (replay) must fail
    assert store.pop_auth_code("code-h") is None


def test_expired_auth_code_rejected():
    store.put_auth_code("old-h", "c1", "u1", "ch", "https://claude.ai/cb",
                        ttl=int(time.time()) - 1)  # already expired
    assert store.pop_auth_code("old-h") is None


def test_refresh_token_lifecycle():
    store.put_refresh_token("tok-h", "u1", "c1")
    assert store.get_refresh_token("tok-h")["user_id"] == "u1"
    store.delete_refresh_token("tok-h")  # revoke
    assert store.get_refresh_token("tok-h") is None
