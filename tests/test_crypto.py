"""Unit tests for crypto (KMS refresh-token encryption).

Two paths: a fake KMS client (cloud mode) and the env-driven local pass-through.
No real AWS.
"""
import crypto


def test_local_passthrough_roundtrip(monkeypatch):
    monkeypatch.delenv("KMS_KEY_ID", raising=False)
    ct = crypto.encrypt_refresh_token("refresh-token-123")
    assert ct == b"refresh-token-123"                 # no KMS → utf-8 bytes
    assert crypto.decrypt_refresh_token(ct) == "refresh-token-123"


def test_uses_kms_when_key_id_set(monkeypatch):
    monkeypatch.setenv("KMS_KEY_ID", "alias/sheets-mcp-refresh-token")
    calls = {}

    class _FakeKms:
        def encrypt(self, KeyId, Plaintext):
            calls["encrypt"] = (KeyId, Plaintext)
            return {"CiphertextBlob": b"WRAPPED:" + Plaintext}

        def decrypt(self, CiphertextBlob):
            calls["decrypt"] = CiphertextBlob
            return {"Plaintext": CiphertextBlob[len(b"WRAPPED:"):]}

    monkeypatch.setattr(crypto, "_kms", _FakeKms())
    ct = crypto.encrypt_refresh_token("tok")
    assert ct == b"WRAPPED:tok"
    assert calls["encrypt"][0] == "alias/sheets-mcp-refresh-token"
    assert crypto.decrypt_refresh_token(ct) == "tok"
