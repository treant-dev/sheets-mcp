"""KMS encryption for the per-user Google refresh token (Phase 3).

**Direct** ``kms:Encrypt`` / ``kms:Decrypt`` — the refresh token is well under the
4 KB plaintext limit, so envelope encryption (data-key indirection) buys nothing
and only adds local-AES surface. The CMK is referenced by ``KMS_KEY_ID`` (its
ARN/alias) for encrypt; decrypt needs no key id — it's embedded in the ciphertext.

Locally / in tests (no ``KMS_KEY_ID``), this is a pass-through: the "ciphertext"
is just the UTF-8 bytes of the token, so dev and tests need no AWS. This mirrors
``secret_store``'s env-driven local mode.
"""
import os

_kms = None  # tests replace this with a fake client


def _client():
    global _kms
    if _kms is None:
        import boto3

        _kms = boto3.client("kms")
    return _kms


def encrypt_refresh_token(plaintext):
    """str token -> ciphertext bytes (stored as a DynamoDB Binary attribute)."""
    key_id = os.environ.get("KMS_KEY_ID")
    if not key_id:
        return plaintext.encode()  # local/dev pass-through
    return _client().encrypt(KeyId=key_id, Plaintext=plaintext.encode())["CiphertextBlob"]


def decrypt_refresh_token(ciphertext):
    """ciphertext bytes (or boto3 Binary) -> str token."""
    ciphertext = bytes(ciphertext)  # boto3 returns a Binary wrapper; normalise
    if not os.environ.get("KMS_KEY_ID"):
        return ciphertext.decode()  # local/dev pass-through
    return _client().decrypt(CiphertextBlob=ciphertext)["Plaintext"].decode()
