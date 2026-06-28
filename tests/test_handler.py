"""Test that the MCP handler threads the authorizer's user_id into the tool layer."""
import json

import handler
import tools


def _mcp_event(body, authorizer_ctx=None):
    rc = {"stage": "prod"}
    if authorizer_ctx is not None:
        rc["authorizer"] = authorizer_ctx
    return {"httpMethod": "POST", "path": "/prod/",
            "headers": {"Content-Type": "application/json", "Accept": "application/json"},
            "requestContext": rc, "body": json.dumps(body)}


def test_handler_sets_current_user_from_authorizer():
    # a request the handler can serve without calling Google
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    handler.lambda_handler(_mcp_event(body, {"user_id": "user-9"}), None)
    assert tools._current_user == "user-9"


def test_handler_defaults_user_when_no_authorizer():
    tools.set_current_user("leftover")   # simulate a prior invocation
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    handler.lambda_handler(_mcp_event(body, None), None)
    assert tools._current_user == "default"
