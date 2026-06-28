"""Google Sheets access via the REST API, authed per-user (Phase 3).

Credential seam: tools call ``sheets_client_for(user_id)`` to get an authed
client. ``user_id`` is the Google ``sub``; we look up that user's stored Google
refresh token, decrypt it (KMS), and build an auto-refreshing OAuth client. The
tools are unchanged across this swap from the Phase 1/2 service-account stub.

REST + httpx + google-auth, mirroring the sibling treant-calories-bot.
"""
from urllib.parse import quote

import httpx
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

import crypto
import store
from secret_store import get_secret

_SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]  # read + write
_BASE = "https://sheets.googleapis.com/v4/spreadsheets"
_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
_TIMEOUT = 15


class SheetsClient:
    """Thin wrapper over the Sheets REST API. ``creds``/``http`` are injectable
    for tests (pass ``creds=None`` to skip token refresh and use a fixed token)."""

    def __init__(self, creds=None, http=None, base=_BASE):
        self._creds = creds
        self._http = http or httpx.Client(timeout=_TIMEOUT)
        self._base = base

    def _token(self):
        if self._creds is None:
            return "test-token"
        if not self._creds.valid:
            self._creds.refresh(Request())
        return self._creds.token

    def _hdr(self):
        return {"Authorization": f"Bearer {self._token()}"}

    def _values_url(self, spreadsheet_id, a1_range):
        return f"{self._base}/{spreadsheet_id}/values/{quote(a1_range, safe='')}"

    def read_range(self, spreadsheet_id, a1_range):
        r = self._http.get(self._values_url(spreadsheet_id, a1_range), headers=self._hdr())
        r.raise_for_status()
        d = r.json()
        return {"range": d.get("range", a1_range), "rows": d.get("values", [])}

    def write_range(self, spreadsheet_id, a1_range, values, value_input_option="USER_ENTERED"):
        r = self._http.put(
            self._values_url(spreadsheet_id, a1_range),
            headers=self._hdr(),
            params={"valueInputOption": value_input_option or "USER_ENTERED"},
            json={"values": values},
        )
        r.raise_for_status()
        d = r.json()
        return {
            "updated_range": d.get("updatedRange"),
            "updated_rows": d.get("updatedRows", 0),
            "updated_columns": d.get("updatedColumns", 0),
            "updated_cells": d.get("updatedCells", 0),
        }

    def append_rows(self, spreadsheet_id, a1_range, values, value_input_option="USER_ENTERED"):
        r = self._http.post(
            self._values_url(spreadsheet_id, a1_range) + ":append",
            headers=self._hdr(),
            params={
                "valueInputOption": value_input_option or "USER_ENTERED",
                "insertDataOption": "INSERT_ROWS",
            },
            json={"values": values},
        )
        r.raise_for_status()
        up = r.json().get("updates", {})
        return {
            "updated_range": up.get("updatedRange"),
            "updated_rows": up.get("updatedRows", 0),
            "updated_cells": up.get("updatedCells", 0),
        }

    def clear_range(self, spreadsheet_id, a1_range):
        r = self._http.post(
            self._values_url(spreadsheet_id, a1_range) + ":clear",
            headers=self._hdr(),
            json={},
        )
        r.raise_for_status()
        return {"cleared_range": r.json().get("clearedRange")}

    def list_sheets(self, spreadsheet_id):
        r = self._http.get(
            f"{self._base}/{spreadsheet_id}",
            headers=self._hdr(),
            params={"fields": "properties.title,sheets.properties"},
        )
        r.raise_for_status()
        d = r.json()
        tabs = []
        for s in d.get("sheets", []):
            p = s.get("properties", {})
            gp = p.get("gridProperties", {})
            tabs.append({
                "title": p.get("title"),
                "sheet_id": p.get("sheetId", 0),
                "index": p.get("index", 0),
                "row_count": gp.get("rowCount", 0),
                "col_count": gp.get("columnCount", 0),
            })
        return {"title": d.get("properties", {}).get("title"), "tabs": tabs}


class NoCredentials(Exception):
    """Raised when a user has no stored Google credentials (never connected, or
    revoked). Tools surface this as an actionable error rather than a 500."""


_clients = {}  # user_id -> SheetsClient, cached per container (KMS/refresh ≈ cold starts)


def _build_credentials(refresh_token):
    """An auto-refreshing user OAuth client. google-auth swaps the refresh token
    for a fresh access token on first use (and when it expires)."""
    return Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=_GOOGLE_TOKEN_URI,
        client_id=get_secret("google_oauth_client_id"),
        client_secret=get_secret("google_oauth_client_secret"),
        scopes=_SCOPES,
    )


def sheets_client_for(user_id):
    """The credential seam — per-user Google client (Phase 3).

    Looks up the user's stored refresh token, decrypts it (KMS), and returns an
    auto-refreshing client. Cached per container so KMS decrypt + token refresh
    happen roughly once per cold start per user."""
    if user_id in _clients:
        return _clients[user_id]
    user = store.get_user(user_id)
    if not user or not user.get("refresh_token_ct"):
        raise NoCredentials(f"no Google credentials for user {user_id!r} — connect your Google account")
    refresh_token = crypto.decrypt_refresh_token(user["refresh_token_ct"])
    client = SheetsClient(creds=_build_credentials(refresh_token))
    _clients[user_id] = client
    return client
