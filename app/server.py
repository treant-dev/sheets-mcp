"""Entry point for both transports.

``MCP_TRANSPORT=http`` (the default) serves Streamable HTTP on ``MCP_PATH`` — the
root by default, so the connector URL is just the domain — with the OAuth layer
from oauth.py in front of it. ``MCP_TRANSPORT=stdio`` runs the same tools over
stdin/stdout for local use, with no OAuth at all; there the caller is whoever
``LOCAL_USER_EMAIL`` says they are.

The SDK builds the app: given an authorization-server provider it mounts the
discovery documents, ``/register``, ``/authorize`` and ``/token``, and wraps the
MCP endpoint in the 401 + ``WWW-Authenticate`` response that starts the flow in
Claude. We add two routes of our own — the Google callback and a health check —
and CORS, which the MCP endpoint needs because claude.ai calls it from a browser.
"""
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

import config
import oauth
import tools


async def health(request):
    return JSONResponse({"ok": True})


def build_server(with_auth=True):
    """The FastMCP server with all tools registered."""
    kwargs = {}
    if with_auth:
        base = config.public_base_url()
        kwargs = {
            "auth_server_provider": oauth.StatelessProvider(),
            "auth": AuthSettings(
                issuer_url=base,
                resource_server_url=base,
                client_registration_options=ClientRegistrationOptions(
                    enabled=True,
                    valid_scopes=oauth.SCOPES,
                    default_scopes=oauth.SCOPES,
                ),
            ),
        }
    mcp = FastMCP(
        "treant-sheets-mcp",
        host=config.host(),
        port=config.port(),
        streamable_http_path=config.mcp_path(),
        stateless_http=True,   # a tools-only server keeps no per-session state
        **kwargs,
    )
    for fn in tools.ALL:
        mcp.add_tool(fn)
    mcp.custom_route("/health", methods=["GET"])(health)
    if with_auth:
        mcp.custom_route(oauth.GOOGLE_CALLBACK_PATH, methods=["GET"])(oauth.google_callback)
    return mcp


def build_app():
    """The ASGI application served over HTTP."""
    app = build_server().streamable_http_app()
    # claude.ai's web client is a browser origin, so the MCP endpoint itself needs
    # CORS. The SDK only adds it to the OAuth endpoints.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id", "Mcp-Protocol-Version", "WWW-Authenticate"],
    )
    return app


def main():
    if config.transport() == "stdio":
        build_server(with_auth=False).run()
        return
    import uvicorn

    uvicorn.run(build_app(), host=config.host(), port=config.port())


if __name__ == "__main__":
    main()
