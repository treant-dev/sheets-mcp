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
        self.updates = []
        self.batches = []

    def owner_emails(self, spreadsheet_id):
        self.owner_calls += 1
        return self.owners

    def values_get(self, spreadsheet_id, a1_range):
        self.read_calls.append((spreadsheet_id, a1_range))
        return {"range": a1_range, "values": []}

    def values_update(self, spreadsheet_id, a1_range, values, value_input_option):
        self.updates.append((a1_range, values, value_input_option))
        return {"updatedCells": 1}

    def batch_update(self, spreadsheet_id, requests):
        self.batches.append(requests)
        return {"replies": []}

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
    tools.get_values(SID, "A1:B2")
    assert fake.read_calls == [(SID, "A1:B2")]


def test_non_owner_is_refused(signed_in, fake):
    fake.owners = ["someone-else@example.com"]
    with pytest.raises(tools.NotAuthorized):
        tools.get_values(SID, "A1:B2")
    assert fake.read_calls == []   # the Sheets call never happened


def test_owner_match_is_case_insensitive(signed_in, fake):
    fake.owners = ["Me@Example.com"]
    tools.get_values(SID, "A1:B2")
    assert fake.read_calls


def test_ownership_is_looked_up_once_per_spreadsheet(signed_in, fake):
    tools.get_values(SID, "A1")
    tools.get_values(SID, "A2")
    tools.get_spreadsheet(SID)
    assert fake.owner_calls == 1


SPREADSHEET_TOOL_CALLS = [
    lambda: tools.get_values(SID, "A1"),
    lambda: tools.get_spreadsheet(SID),
    lambda: tools.update_values(SID, "A1", [["x"]]),
    lambda: tools.update_formulas(SID, "A1", [["=1+1"]]),
    lambda: tools.update_spreadsheet(SID, [{"addSheet": {}}]),
    lambda: tools.insert_dimension(SID, 0, "ROWS", 0, 1),
    lambda: tools.append_values(SID, "Sheet1", [["x"]]),
    lambda: tools.clear_values(SID, "A1"),
]


def test_every_spreadsheet_tool_checks_ownership(signed_in, fake):
    """A tool added without the check would silently expose other users' sheets."""
    fake.owners = ["someone-else@example.com"]
    for call in SPREADSHEET_TOOL_CALLS:
        with pytest.raises(tools.NotAuthorized):
            call()


def test_every_spreadsheet_tool_is_covered_by_that_check():
    """Guards the test above: a new tool taking spreadsheetId must be listed there."""
    import inspect
    take_id = {f.__name__ for f in tools.ALL
               if "spreadsheetId" in inspect.signature(f).parameters}
    assert len(SPREADSHEET_TOOL_CALLS) == len(take_id)


# ── the two tools that differ only in how input is parsed ───────────
def test_update_values_writes_literally(signed_in, fake):
    tools.update_values(SID, "A1", [["=1+1"]])
    assert fake.updates == [("A1", [["=1+1"]], "RAW")]


def test_update_formulas_is_evaluated(signed_in, fake):
    tools.update_formulas(SID, "A1", [["=1+1"]])
    assert fake.updates == [("A1", [["=1+1"]], "USER_ENTERED")]


def test_insert_dimension_builds_the_request(signed_in, fake):
    tools.insert_dimension(SID, 3, "ROWS", 0, 2, inheritFromBefore=True)
    assert fake.batches == [[{"insertDimension": {
        "range": {"sheetId": 3, "dimension": "ROWS", "startIndex": 0, "endIndex": 2},
        "inheritFromBefore": True,
    }}]]


def test_update_spreadsheet_passes_requests_through(signed_in, fake):
    reqs = [{"mergeCells": {"range": {"sheetId": 0}, "mergeType": "MERGE_ALL"}}]
    tools.update_spreadsheet(SID, reqs)
    assert fake.batches == [reqs]


def test_list_spreadsheets_scoped_to_the_caller(signed_in, fake):
    out = tools.list_spreadsheets()
    assert out["spreadsheets"][0]["title"] == "me@example.com"


def test_all_tools_are_registered():
    assert [f.__name__ for f in tools.ALL] == [
        "list_spreadsheets",
        "get_values", "get_spreadsheet", "update_values", "update_formulas",
        "update_spreadsheet", "insert_dimension",
        "append_values", "clear_values",
    ]
