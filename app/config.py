"""Configuration — everything comes from environment variables.

In Docker these are supplied by ``env_file: .env``; locally by the shell or a
``.env`` you source yourself. There is no secret manager and no config file: the
server keeps no state, so its whole configuration is a handful of env vars.

Values are read lazily through functions rather than at import time, so tests
can monkeypatch the environment and importing a module never fails just because
a variable is missing.
"""
import os


def _required(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"required environment variable {name} is not set")
    return value


def public_base_url():
    """The externally visible origin, e.g. https://sheets-mcp.treant.dev.

    Used as the OAuth issuer, the resource identifier (``aud`` of our tokens) and
    the base of the Google redirect URI, so it must match exactly what clients
    see — including scheme and any port.
    """
    return _required("PUBLIC_BASE_URL").rstrip("/")


def jwt_signing_key():
    """HS256 key that signs every token this server issues. All OAuth state lives
    inside these tokens, so rotating this key invalidates every existing client
    registration, code and refresh token."""
    return _required("JWT_SIGNING_KEY")


def google_client_id():
    return _required("GOOGLE_OAUTH_CLIENT_ID")


def google_client_secret():
    return _required("GOOGLE_OAUTH_CLIENT_SECRET")


def transport():
    """``http`` (default) or ``stdio``."""
    return os.environ.get("MCP_TRANSPORT", "http").strip().lower()


def mcp_path():
    """Path the MCP endpoint is served on. The root by default, so the connector
    URL is just the domain."""
    return os.environ.get("MCP_PATH", "/")


def host():
    return os.environ.get("HOST", "0.0.0.0")


def port():
    return int(os.environ.get("PORT", "8000"))


def local_user_email():
    """Caller identity for the stdio transport, which has no OAuth layer."""
    return os.environ.get("LOCAL_USER_EMAIL")
