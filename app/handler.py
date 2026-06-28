"""Lambda entry for the remote MCP server (Phase 2).

Registers the SAME tool functions as the stdio entry (``tools.ALL``) with AWS
Labs' ``mcp-lambda-handler``, served over HTTP at ``POST /`` (root). The tool
functions and the ``sheets_client_for(user_id)`` credential seam are shared
verbatim with ``stdio.py`` — only the registration framework differs. This is
the Phase 2 Step-A "tool-definition reuse" proof.

Session store: NoOp / stateless (the ``session_store=None`` default). A
tools-only server keeps no per-session state, so Lambda's statelessness is a
non-issue. Flip to the library's DynamoDB store only if persistent sessions are
ever needed.
"""
import functools
import json

from awslabs.mcp_lambda_handler import MCPLambdaHandler

import tools

mcp = MCPLambdaHandler(name="treant-sheets-mcp", version="0.1.0")  # NoOp session store


def _json_tool(fn):
    """Adapt a tool to emit JSON text on Lambda.

    ``mcp-lambda-handler`` renders a tool's return value with ``str()``, so a
    ``dict`` would come back as a Python repr (``{'a': 1}``, single quotes) —
    not valid JSON. The stdio/FastMCP path JSON-serializes dict returns, so we
    match it here by returning a JSON string. ``functools.wraps`` preserves the
    name, docstring, and type hints the schema is derived from, so the tool
    *definition* is unchanged — only the transport-level serialization differs,
    which is where it belongs.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return json.dumps(fn(*args, **kwargs), default=str)

    return wrapper


# Reuse Phase 1's tool functions unchanged (``tools.ALL``). The schema for each
# comes from the same type hints + docstrings the stdio SDK reads; only the
# JSON-serialization adapter is added at this transport boundary.
for fn in tools.ALL:
    mcp.tool()(_json_tool(fn))


def lambda_handler(event, context):
    # The authorizer (Step C4) verified the JWT and passed the user_id through.
    authz = (event.get("requestContext", {}) or {}).get("authorizer") or {}
    tools.set_current_user(authz.get("user_id"))
    resp = mcp.handle_request(event, context)
    if isinstance(resp, dict):  # CORS for browser-based claude.ai web
        resp.setdefault("headers", {})["Access-Control-Allow-Origin"] = "*"
    return resp
