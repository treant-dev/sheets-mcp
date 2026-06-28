"""Secret loading (mirrors the sibling treant-calories-bot).

In Lambda, secrets live in SSM Parameter Store as SecureString parameters under
a prefix (env var ``SSM_PREFIX``, e.g. ``/sheets-mcp``), fetched once per cold
start and cached. Locally they come from environment variables (loaded from
``.env``) — no AWS calls.

Named ``secret_store`` rather than ``secrets`` so it doesn't shadow Python's
stdlib ``secrets`` module.
"""
import functools
import os

_SSM_PREFIX = os.environ.get("SSM_PREFIX")  # e.g. "/sheets-mcp"; unset locally

# logical name -> (SSM param suffix, local env var or None)
_SECRETS = {
    "jwt_signing_key": ("jwt-signing-key", "JWT_SIGNING_KEY"),
    # Phase 3: per-user Google OAuth. client_id is a String param, client_secret a
    # SecureString — both read the same way (WithDecryption is a no-op on String).
    "google_oauth_client_id": ("google-oauth-client-id", "GOOGLE_OAUTH_CLIENT_ID"),
    "google_oauth_client_secret": ("google-oauth-client-secret", "GOOGLE_OAUTH_CLIENT_SECRET"),
}


@functools.lru_cache(maxsize=None)
def get_secret(name):
    """Return a secret value, raising if it can't be found."""
    suffix, env_var = _SECRETS[name]
    if env_var and os.environ.get(env_var):
        return os.environ[env_var]
    if _SSM_PREFIX:
        return _ssm_get(f"{_SSM_PREFIX}/{suffix}")
    raise RuntimeError(f"Secret {name!r} unavailable: no {env_var} env var and no SSM_PREFIX")


@functools.lru_cache(maxsize=None)
def _ssm_get(param_name):
    import boto3

    ssm = boto3.client("ssm")
    resp = ssm.get_parameter(Name=param_name, WithDecryption=True)
    return resp["Parameter"]["Value"]
