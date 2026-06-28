"""Unit tests for SheetsClient — mocks the Sheets REST API via httpx.MockTransport.
No credentials or network. Mirrors the Go prototype's tool tests."""
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


# ── the per-user credential seam (Phase 3) ──────────────────────────
def test_sheets_client_for_builds_per_user_client(monkeypatch):
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "cid")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "csecret")
    monkeypatch.delenv("KMS_KEY_ID", raising=False)   # crypto pass-through
    import secret_store
    secret_store.get_secret.cache_clear()
    sheets._clients.clear()
    # the stored "ciphertext" is the plain token under pass-through crypto
    monkeypatch.setattr(sheets.store, "get_user",
                        lambda uid: {"refresh_token_ct": b"refresh-xyz"} if uid == "u1" else None)

    c = sheets.sheets_client_for("u1")
    assert isinstance(c, SheetsClient)
    assert c._creds.refresh_token == "refresh-xyz"
    assert sheets.sheets_client_for("u1") is c   # cached per container


def test_sheets_client_for_raises_without_credentials(monkeypatch):
    sheets._clients.clear()
    monkeypatch.setattr(sheets.store, "get_user", lambda uid: None)
    with pytest.raises(sheets.NoCredentials):
        sheets.sheets_client_for("nobody")
