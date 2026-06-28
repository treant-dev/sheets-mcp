"""Tests for the /mcp Lambda Authorizer (Step C4).

Covers the security-critical checks: valid token → Allow + user_id context;
missing/bad-signature/wrong-aud/expired/`alg:none` tokens → Unauthorized.
"""
import base64
import json
import time

import jwt
import pytest

import authorizer

HOST = "abc123.execute-api.eu-central-1.amazonaws.com"
BASE = f"https://{HOST}/prod"
AUD = BASE   # resource id = bare origin (MCP served at POST /)
JWT_KEY = "test-signing-key-at-least-32-bytes-long!!"
METHOD_ARN = "arn:aws:execute-api:eu-central-1:123456789012:abc123/prod/POST/mcp"


@pytest.fixture(autouse=True)
def jwt_key(monkeypatch):
    monkeypatch.setenv("JWT_SIGNING_KEY", JWT_KEY)
    import secret_store
    secret_store.get_secret.cache_clear()


def _event(auth_header):
    headers = {"Host": HOST}
    if auth_header is not None:
        headers["Authorization"] = auth_header
    return {"headers": headers, "methodArn": METHOD_ARN,
            "requestContext": {"stage": "prod", "domainName": HOST}}


def _token(claims, key=JWT_KEY, alg="HS256"):
    return jwt.encode(claims, key, algorithm=alg)


def _valid_claims(**over):
    now = int(time.time())
    c = {"sub": "user-42", "iss": BASE, "aud": AUD, "iat": now, "exp": now + 1800,
         "scope": "sheets"}
    c.update(over)
    return c


def test_valid_token_allows_with_user_context():
    res = authorizer.lambda_handler(_event(f"Bearer {_token(_valid_claims())}"), None)
    assert res["principalId"] == "user-42"
    assert res["context"]["user_id"] == "user-42"
    stmt = res["policyDocument"]["Statement"][0]
    assert stmt["Effect"] == "Allow" and stmt["Resource"] == METHOD_ARN


def test_missing_header_unauthorized():
    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(_event(None), None)


def test_non_bearer_unauthorized():
    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(_event("Basic abc"), None)


def test_bad_signature_unauthorized():
    bad = _token(_valid_claims(), key="some-other-key")
    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(_event(f"Bearer {bad}"), None)


def test_wrong_audience_unauthorized():
    tok = _token(_valid_claims(aud="https://evil.test/mcp"))
    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(_event(f"Bearer {tok}"), None)


def test_expired_unauthorized():
    tok = _token(_valid_claims(exp=int(time.time()) - 10))
    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(_event(f"Bearer {tok}"), None)


def test_alg_none_attack_rejected():
    # A forged unsigned token with alg=none must be rejected (alg is pinned to HS256).
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    forged = b64({"alg": "none", "typ": "JWT"}) + "." + b64(_valid_claims()) + "."
    with pytest.raises(Exception, match="Unauthorized"):
        authorizer.lambda_handler(_event(f"Bearer {forged}"), None)
