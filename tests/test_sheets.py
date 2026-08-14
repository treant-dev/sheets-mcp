"""Unit tests for SheetsClient — mocks the Sheets and Drive REST APIs via
httpx.MockTransport. No credentials or network."""
import httpx
import pytest

import sheets
from sheets import SheetsClient

SID = "sid"


def make_client(handler):
    return SheetsClient(creds=None, http=httpx.Client(transport=httpx.MockTransport(handler)))


def test_read_range():
    def handler(request):
        assert request.method == "GET"
        return httpx.Response(200, json={
            "range": "Sheet1!A1:B2",
            "values": [["Name", "Role"], ["Ada", "Eng"]],
        })

    out = make_client(handler).read_range(SID, "A1:B2")
    assert out["range"] == "Sheet1!A1:B2"
    assert out["rows"][1][0] == "Ada"


def test_read_range_empty():
    def handler(request):
        return httpx.Response(200, json={"range": "Sheet1!A1:Z100"})  # no "values"

    out = make_client(handler).read_range(SID, "A1:Z100")
    assert out["rows"] == []


def test_list_sheets():
    def handler(request):
        return httpx.Response(200, json={
            "properties": {"title": "test mcp"},
            "sheets": [{"properties": {
                "sheetId": 0, "title": "Sheet1", "index": 0,
                "gridProperties": {"rowCount": 1000, "columnCount": 26},
            }}],
        })

    out = make_client(handler).list_sheets(SID)
    assert out["title"] == "test mcp"
    assert out["tabs"][0] == {
        "title": "Sheet1", "sheet_id": 0, "index": 0, "row_count": 1000, "col_count": 26,
    }


def test_write_range_defaults_user_entered():
    captured = {}

    def handler(request):
        captured["method"] = request.method
        captured["vio"] = request.url.params.get("valueInputOption")
        return httpx.Response(200, json={
            "updatedRange": "Sheet1!E1:F2", "updatedRows": 2,
            "updatedColumns": 2, "updatedCells": 4,
        })

    out = make_client(handler).write_range(SID, "E1:F2", [["a", "b"], ["c", "d"]])
    assert captured["method"] == "PUT"
    assert captured["vio"] == "USER_ENTERED"  # the default
    assert out["updated_cells"] == 4
    assert out["updated_range"] == "Sheet1!E1:F2"


def test_write_range_raw_honored():
    captured = {}

    def handler(request):
        captured["vio"] = request.url.params.get("valueInputOption")
        return httpx.Response(200, json={"updatedRange": "Sheet1!A1", "updatedCells": 1})

    make_client(handler).write_range(SID, "A1", [["=1+1"]], value_input_option="RAW")
    assert captured["vio"] == "RAW"


def test_append_rows():
    def handler(request):
        assert request.method == "POST"
        assert ":append" in request.url.path
        return httpx.Response(200, json={"updates": {
            "updatedRange": "Sheet1!E3:F3", "updatedRows": 1, "updatedCells": 2,
        }})

    out = make_client(handler).append_rows(SID, "E1:F2", [["x", "y"]])
    assert out == {"updated_range": "Sheet1!E3:F3", "updated_rows": 1, "updated_cells": 2}


def test_clear_range():
    def handler(request):
        assert request.method == "POST"
        assert ":clear" in request.url.path
        return httpx.Response(200, json={"clearedRange": "Sheet1!E1:F10"})

    out = make_client(handler).clear_range(SID, "E1:F10")
    assert out["cleared_range"] == "Sheet1!E1:F10"


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
