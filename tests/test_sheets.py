"""Unit tests for SheetsClient — mocks the Sheets and Drive REST APIs via
httpx.MockTransport. No credentials or network."""
import json

import httpx
import pytest

import sheets
from sheets import SheetsClient

SID = "sid"


def make_client(handler):
    return SheetsClient(creds=None, http=httpx.Client(transport=httpx.MockTransport(handler)))


def test_values_get_passes_the_api_shape_through():
    """Responses are not re-mapped: the tools mirror Google's own MCP server,
    which returns the REST shapes verbatim."""
    def handler(request):
        assert request.method == "GET"
        return httpx.Response(200, json={
            "range": "Sheet1!A1:B2",
            "values": [["Name", "Role"], ["Ada", "Eng"]],
        })

    out = make_client(handler).values_get(SID, "A1:B2")
    assert out == {"range": "Sheet1!A1:B2", "values": [["Name", "Role"], ["Ada", "Eng"]]}


def test_values_get_range_is_url_encoded():
    captured = {}

    def handler(request):
        captured["path"] = request.url.raw_path.decode()   # .path is decoded again
        return httpx.Response(200, json={})

    make_client(handler).values_get(SID, "Sheet 1!A1:B2")
    assert captured["path"].endswith("/values/Sheet%201%21A1%3AB2")


def test_spreadsheets_get_metadata_only_by_default():
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"properties": {"title": "test mcp"}})

    out = make_client(handler).spreadsheets_get(SID)
    assert captured["params"]["fields"] == "spreadsheetId,properties.title,sheets.properties"
    assert "includeGridData" not in captured["params"]
    assert out["properties"]["title"] == "test mcp"


def test_spreadsheets_get_with_grid_data():
    captured = {}

    def handler(request):
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"sheets": [{"data": []}]})

    make_client(handler).spreadsheets_get(SID, include_grid_data=True)
    assert captured["params"]["includeGridData"] == "true"
    # `fields` would restrict the response and defeat the flag
    assert "fields" not in captured["params"]


def test_values_update_sends_the_given_input_option():
    captured = {}

    def handler(request):
        captured["method"] = request.method
        captured["vio"] = request.url.params.get("valueInputOption")
        return httpx.Response(200, json={"updatedRange": "Sheet1!E1:F2", "updatedCells": 4})

    out = make_client(handler).values_update(SID, "E1:F2", [["a", "b"]], "RAW")
    assert captured["method"] == "PUT"
    assert captured["vio"] == "RAW"
    assert out["updatedCells"] == 4


def test_values_append():
    def handler(request):
        assert request.method == "POST"
        assert ":append" in request.url.path
        assert request.url.params.get("insertDataOption") == "INSERT_ROWS"
        return httpx.Response(200, json={"updates": {"updatedRange": "Sheet1!E3:F3"}})

    out = make_client(handler).values_append(SID, "E1:F2", [["x", "y"]])
    assert out["updates"]["updatedRange"] == "Sheet1!E3:F3"


def test_values_clear():
    def handler(request):
        assert request.method == "POST"
        assert ":clear" in request.url.path
        return httpx.Response(200, json={"clearedRange": "Sheet1!E1:F10"})

    assert make_client(handler).values_clear(SID, "E1:F10")["clearedRange"] == "Sheet1!E1:F10"


def test_batch_update():
    captured = {}

    def handler(request):
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"replies": [{"addSheet": {"properties": {"sheetId": 7}}}]})

    reqs = [{"addSheet": {"properties": {"title": "New"}}}]
    out = make_client(handler).batch_update(SID, reqs)
    assert captured["method"] == "POST"
    assert captured["path"].endswith(f"/{SID}:batchUpdate")
    assert captured["body"] == {"requests": reqs}
    assert out["replies"][0]["addSheet"]["properties"]["sheetId"] == 7


# ── Drive: the user ↔ spreadsheets link ─────────────────────────────
def test_list_spreadsheets_filters_by_owner():
    captured = {}

    def handler(request):
        captured["q"] = request.url.params.get("q")
        return httpx.Response(200, json={"files": [
            {"id": "a", "name": "Budget", "modifiedTime": "2026-08-01T10:00:00Z"},
        ]})

    out = make_client(handler).list_spreadsheets("me@example.com")
    assert "'me@example.com' in owners" in captured["q"]
    assert "mimeType='application/vnd.google-apps.spreadsheet'" in captured["q"]
    assert out["spreadsheets"] == [
        {"spreadsheet_id": "a", "title": "Budget", "modified_time": "2026-08-01T10:00:00Z"},
    ]


def test_list_spreadsheets_escapes_quotes():
    """A quote in the address must not break out of the Drive query string."""
    captured = {}

    def handler(request):
        captured["q"] = request.url.params.get("q")
        return httpx.Response(200, json={"files": []})

    make_client(handler).list_spreadsheets("o'brien@example.com")
    assert "\\'brien" in captured["q"]


def test_owner_emails():
    def handler(request):
        assert request.url.params.get("fields") == "owners(emailAddress)"
        return httpx.Response(200, json={"owners": [{"emailAddress": "me@example.com"}]})

    assert make_client(handler).owner_emails(SID) == ["me@example.com"]


# ── the service-account credential seam ─────────────────────────────
def test_client_requires_credentials(monkeypatch):
    monkeypatch.delenv("GOOGLE_SERVICE_ACCOUNT_JSON", raising=False)
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    sheets.reset_client()
    with pytest.raises(sheets.NoCredentials):
        sheets.client()


def test_client_rejects_malformed_json(monkeypatch):
    monkeypatch.setenv("GOOGLE_SERVICE_ACCOUNT_JSON", "{not json")
    sheets.reset_client()
    with pytest.raises(sheets.NoCredentials):
        sheets.client()


def test_client_is_a_singleton(monkeypatch):
    """Built once per process, from the service-account key — no per-user lookup."""
    made = []

    def fake_credentials():
        made.append(1)
        return None

    monkeypatch.setattr(sheets, "_service_account_credentials", fake_credentials)
    sheets.reset_client()
    first = sheets.client()
    assert sheets.client() is first
    assert len(made) == 1
