"""Google Sheets and Drive access, authed as a service account.

The Sheets methods are thin wrappers that return the REST API's own response
shapes, because the tools built on them mirror Google's official Sheets MCP
server (https://developers.google.com/workspace/sheets/api/reference/mcp).

One set of credentials for the whole server: users share their spreadsheets with
the service account's e-mail address, and every API call is made as that account.
Nothing per-user is stored — Drive already knows who owns each file, which is what
``list_spreadsheets`` and ``owner_emails`` build on.

Drive is used read-only and only for metadata: listing a caller's spreadsheets and
answering "who owns this file" for the ownership check in tools.py.

REST + httpx + google-auth, mirroring the sibling treant-calories-bot.
"""
import json
import os
import threading
from urllib.parse import quote

import httpx
from google.auth.transport.requests import Request
from google.oauth2 import service_account

_SCOPES = [
    "https://www.googleapis.com/auth/spreadsheets",           # read + write
    "https://www.googleapis.com/auth/drive.metadata.readonly",  # list + owners
]
_SHEETS_BASE = "https://sheets.googleapis.com/v4/spreadsheets"
_DRIVE_BASE = "https://www.googleapis.com/drive/v3/files"
_SPREADSHEET_MIME = "application/vnd.google-apps.spreadsheet"
_TIMEOUT = 15


class SheetsClient:
    """Thin wrapper over the Sheets and Drive REST APIs. ``creds``/``http`` are
    injectable for tests (pass ``creds=None`` to skip token refresh and use a
    fixed token)."""

    def __init__(self, creds=None, http=None, base=_SHEETS_BASE, drive_base=_DRIVE_BASE):
        self._creds = creds
        self._http = http or httpx.Client(timeout=_TIMEOUT)
        self._base = base
        self._drive = drive_base

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

    # Responses are passed through as the API returns them (ValueRange,
    # UpdateValuesResponse, Spreadsheet …). The tools mirror Google's own Sheets
    # MCP server, whose output is the raw REST shape, so re-mapping fields here
    # would only make our answers differ from what a model expects.
    def values_get(self, spreadsheet_id, a1_range):
        r = self._http.get(self._values_url(spreadsheet_id, a1_range), headers=self._hdr())
        r.raise_for_status()
        return r.json()

    def values_update(self, spreadsheet_id, a1_range, values, value_input_option):
        r = self._http.put(
            self._values_url(spreadsheet_id, a1_range),
            headers=self._hdr(),
            params={"valueInputOption": value_input_option},
            json={"values": values},
        )
        r.raise_for_status()
        return r.json()

    def values_append(self, spreadsheet_id, a1_range, values, value_input_option="USER_ENTERED"):
        r = self._http.post(
            self._values_url(spreadsheet_id, a1_range) + ":append",
            headers=self._hdr(),
            params={
                "valueInputOption": value_input_option,
                "insertDataOption": "INSERT_ROWS",
            },
            json={"values": values},
        )
        r.raise_for_status()
        return r.json()

    def values_clear(self, spreadsheet_id, a1_range):
        r = self._http.post(
            self._values_url(spreadsheet_id, a1_range) + ":clear",
            headers=self._hdr(),
            json={},
        )
        r.raise_for_status()
        return r.json()

    def spreadsheets_get(self, spreadsheet_id, include_grid_data=False):
        """Spreadsheet metadata; with ``include_grid_data`` also every cell's value
        and formatting, which on a real sheet is a lot of JSON."""
        params = {"includeGridData": "true"} if include_grid_data else {
            "fields": "spreadsheetId,properties.title,sheets.properties"}
        r = self._http.get(f"{self._base}/{spreadsheet_id}", headers=self._hdr(), params=params)
        r.raise_for_status()
        return r.json()

    def batch_update(self, spreadsheet_id, requests):
        """Apply a list of Sheets API ``Request`` objects — everything structural or
        visual (sheets, formatting, merges, filters, charts) goes through here."""
        r = self._http.post(
            f"{self._base}/{spreadsheet_id}:batchUpdate",
            headers=self._hdr(),
            json={"requests": requests},
        )
        r.raise_for_status()
        return r.json()

    # ── Drive: who owns what ────────────────────────────────────────
    def list_spreadsheets(self, owner_email, page_size=100):
        """Spreadsheets owned by ``owner_email`` that are shared with the service
        account. The owner filter is applied by Drive, so a caller never sees
        another user's files."""
        escaped = owner_email.replace("\\", "\\\\").replace("'", "\\'")
        r = self._http.get(self._drive, headers=self._hdr(), params={
            "q": (f"mimeType='{_SPREADSHEET_MIME}' and trashed=false "
                  f"and '{escaped}' in owners"),
            "fields": "files(id,name,modifiedTime)",
            "orderBy": "modifiedTime desc",
            "pageSize": page_size,
        })
        r.raise_for_status()
        return {"spreadsheets": [
            {"spreadsheet_id": f.get("id"), "title": f.get("name"),
             "modified_time": f.get("modifiedTime")}
            for f in r.json().get("files", [])
        ]}

    def owner_emails(self, spreadsheet_id):
        """E-mail addresses of the file's owners — the basis of the access check."""
        r = self._http.get(f"{self._drive}/{spreadsheet_id}", headers=self._hdr(),
                           params={"fields": "owners(emailAddress)"})
        r.raise_for_status()
        return [o.get("emailAddress", "") for o in r.json().get("owners", [])]


class NoCredentials(Exception):
    """Raised when the service account is not configured. Tools surface this as an
    actionable error rather than a 500."""


_client = None
_client_lock = threading.Lock()


def _service_account_credentials():
    """Service-account credentials from the environment.

    ``GOOGLE_SERVICE_ACCOUNT_JSON`` holds the key JSON inline; otherwise
    ``GOOGLE_APPLICATION_CREDENTIALS`` points at a mounted key file.
    """
    raw = os.environ.get("GOOGLE_SERVICE_ACCOUNT_JSON")
    if raw:
        try:
            info = json.loads(raw)
        except ValueError as exc:
            raise NoCredentials(f"GOOGLE_SERVICE_ACCOUNT_JSON is not valid JSON: {exc}") from exc
        return service_account.Credentials.from_service_account_info(info, scopes=_SCOPES)
    path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
    if path:
        if not os.path.exists(path):
            raise NoCredentials(f"GOOGLE_APPLICATION_CREDENTIALS points at a missing file: {path}")
        return service_account.Credentials.from_service_account_file(path, scopes=_SCOPES)
    raise NoCredentials(
        "no service-account credentials — set GOOGLE_SERVICE_ACCOUNT_JSON or "
        "GOOGLE_APPLICATION_CREDENTIALS"
    )


def client():
    """The one client for the whole process. Tools run in a thread pool, hence the
    lock around lazy construction; ``httpx.Client`` itself is thread-safe."""
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = SheetsClient(creds=_service_account_credentials())
    return _client


def reset_client():
    """Drop the cached client — used by tests."""
    global _client
    _client = None
