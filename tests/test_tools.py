"""Tests for the tool layer: who the caller is, and the ownership check that keeps
one user out of another's spreadsheets."""
import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

import tools

SID = "sid"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    tools._owners.clear()
    monkeypatch.delenv("LOCAL_USER_EMAIL", raising=False)


@pytest.fixture
def signed_in():
    """Put a verified access token in the request context, as the auth middleware does."""
    token = AccessToken(token="t", client_id="c", scopes=["sheets"],
                        subject="google-sub", claims={"email": "me@example.com"})
    reset = auth_context_var.set(AuthenticatedUser(token))
    yield
    auth_context_var.reset(reset)


class FakeClient:
    def __init__(self, owners=("me@example.com",)):
        self.owners = list(owners)
        self.owner_calls = 0
        self.read_calls = []

    def owner_emails(self, spreadsheet_id):
        self.owner_calls += 1
        return self.owners

    def read_range(self, spreadsheet_id, a1_range):
        self.read_calls.append((spreadsheet_id, a1_range))
        return {"range": a1_range, "rows": []}

    def list_spreadsheets(self, owner_email):
        return {"spreadsheets": [{"spreadsheet_id": "a", "title": owner_email}]}

    def __getattr__(self, name):
        """Any other Sheets call succeeds — these tests are about the access check."""
        return lambda *a, **kw: {"ok": True}


@pytest.fixture
def fake(monkeypatch):
    client = FakeClient()
    monkeypatch.setattr(tools.sheets, "client", lambda: client)
    return client


# ── caller identity ─────────────────────────────────────────────────
def test_caller_email_from_access_token(signed_in):
    assert tools.caller_email() == "me@example.com"


def test_caller_email_falls_back_to_local_user(monkeypatch):
    monkeypatch.setenv("LOCAL_USER_EMAIL", "local@example.com")
    assert tools.caller_email() == "local@example.com"


def test_caller_email_without_identity_is_an_error():
    with pytest.raises(tools.NotAuthorized):
        tools.caller_email()


# ── the ownership check ─────────────────────────────────────────────
def test_owner_may_read(signed_in, fake):
    tools.read_range(SID, "A1:B2")
    assert fake.read_calls == [(SID, "A1:B2")]


def test_non_owner_is_refused(signed_in, fake):
    fake.owners = ["someone-else@example.com"]
    with pytest.raises(tools.NotAuthorized):
        tools.read_range(SID, "A1:B2")
    assert fake.read_calls == []   # the Sheets call never happened


def test_owner_match_is_case_insensitive(signed_in, fake):
    fake.owners = ["Me@Example.com"]
    tools.read_range(SID, "A1:B2")
    assert fake.read_calls


def test_ownership_is_looked_up_once_per_spreadsheet(signed_in, fake):
    tools.read_range(SID, "A1")
    tools.read_range(SID, "A2")
    tools.list_sheets(SID)
    assert fake.owner_calls == 1


def test_every_spreadsheet_tool_checks_ownership(signed_in, fake):
    """A tool added without the check would silently expose other users' sheets."""
    fake.owners = ["someone-else@example.com"]
    calls = [
        lambda: tools.read_range(SID, "A1"),
        lambda: tools.write_range(SID, "A1", [["x"]]),
        lambda: tools.append_rows(SID, "Sheet1", [["x"]]),
        lambda: tools.clear_range(SID, "A1"),
        lambda: tools.list_sheets(SID),
    ]
    for call in calls:
        with pytest.raises(tools.NotAuthorized):
            call()


def test_list_spreadsheets_scoped_to_the_caller(signed_in, fake):
    out = tools.list_spreadsheets()
    assert out["spreadsheets"][0]["title"] == "me@example.com"


def test_all_tools_are_registered():
    assert [f.__name__ for f in tools.ALL] == [
        "list_spreadsheets", "read_range", "write_range",
        "append_rows", "clear_range", "list_sheets",
    ]
