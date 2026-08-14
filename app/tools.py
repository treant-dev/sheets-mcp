"""The Sheets MCP tools.

Six of them — ``get_values``, ``get_spreadsheet``, ``update_values``,
``update_formulas``, ``update_spreadsheet`` and ``insert_dimension`` — copy the
names, argument names and response shapes of Google's own Sheets MCP server
(https://developers.google.com/workspace/sheets/api/reference/mcp), so a call a
model composes for that server works here unchanged. That is also why the
arguments are camelCase: argument names are part of a tool's schema.

Three more exist because Google's server has no equivalent: ``list_spreadsheets``
(there is no other way to discover a spreadsheetId), ``append_values`` and
``clear_values``.

Type hints and docstrings here become the tool schemas, so keep them accurate.

Every call is made with the server's service-account credentials, so before
touching a spreadsheet we check that the *caller* owns it. Without that check any
authenticated user could reach someone else's sheet just by knowing its id, since
the service account can see every file shared with it.

The caller's identity comes from the verified access token (its ``email`` claim),
put in place by the SDK's auth middleware. Under the stdio transport there is no
token, so ``LOCAL_USER_EMAIL`` stands in.
"""
import threading
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token

import config
import sheets


class NotAuthorized(Exception):
    """The caller doesn't own this spreadsheet (or isn't identified at all)."""


def caller_email():
    """E-mail of the user this request is being made for."""
    token = get_access_token()
    if token is not None:
        email = (token.claims or {}).get("email")
        if email:
            return email
    local = config.local_user_email()
    if local:
        return local
    raise NotAuthorized("cannot determine the calling user — no access token and no LOCAL_USER_EMAIL")


# spreadsheet id -> owner e-mails. Ownership effectively never changes, and a
# wrong guess only ever denies access, so a plain process cache is enough.
_owners = {}
_owners_lock = threading.Lock()


def _require_owner(spreadsheet_id):
    email = caller_email()
    with _owners_lock:
        owners = _owners.get(spreadsheet_id)
    if owners is None:
        owners = sheets.client().owner_emails(spreadsheet_id)
        with _owners_lock:
            _owners[spreadsheet_id] = owners
    if email.lower() not in {o.lower() for o in owners}:
        raise NotAuthorized(
            f"{email} does not own spreadsheet {spreadsheet_id} — only its owner can use it here"
        )


# ── discovery (not part of Google's set) ────────────────────────────
def list_spreadsheets() -> dict:
    """List the spreadsheets you own that are shared with this server.

    Share a sheet with the server's service-account e-mail to make it appear here.
    Returns each spreadsheet's id, title and last-modified time; use the id as
    spreadsheetId with the other tools.
    """
    return sheets.client().list_spreadsheets(caller_email())


# ── Google's six ────────────────────────────────────────────────────
def get_values(spreadsheetId: str, range: str) -> dict:
    """Returns a range of values from a spreadsheet.

    spreadsheetId: the ID of the spreadsheet to retrieve data from.
    range: the A1 notation of the range to retrieve values from, e.g.
      'Sheet1!A1:D10' or 'A1:D10'.
    Returns a ValueRange: {"range": ..., "values": [[cell, ...], ...]}.
    """
    _require_owner(spreadsheetId)
    return sheets.client().values_get(spreadsheetId, range)


def get_spreadsheet(spreadsheetId: str, includeGridData: bool = False) -> dict:
    """Returns the spreadsheet's title, sheet names, grid properties and other
    metadata.

    spreadsheetId: the ID of the spreadsheet to request.
    includeGridData: also return every cell's value and formatting. This can be a
      very large response on a real spreadsheet — prefer get_values for cell data.
    """
    _require_owner(spreadsheetId)
    return sheets.client().spreadsheets_get(spreadsheetId, includeGridData)


def update_values(spreadsheetId: str, range: str, values: list[list[Any]]) -> dict:
    """Sets values in a range of a spreadsheet, writing them literally.

    Input is not parsed: a string like '=A1+B1' is stored as that text, and
    '01/02/2026' stays text rather than becoming a date. Use update_formulas when
    the cells should be evaluated.

    spreadsheetId: the ID of the spreadsheet to update.
    range: the A1 notation of the values to update.
    values: an array of rows, each row an array of cell values (bool, string or
      number). Set a cell to an empty string to clear it.
    """
    _require_owner(spreadsheetId)
    return sheets.client().values_update(spreadsheetId, range, values, "RAW")


def update_formulas(spreadsheetId: str, range: str, formulas: list[list[Any]]) -> dict:
    """Sets formulas in a range of a spreadsheet.

    Input is parsed the way typing into the Sheets UI is, so '=SUM(A1:A10)'
    becomes a formula and '01/02/2026' becomes a date.

    spreadsheetId: the ID of the spreadsheet to update.
    range: the A1 notation of the values to update.
    formulas: an array of rows, each row an array of cells.
    """
    _require_owner(spreadsheetId)
    return sheets.client().values_update(spreadsheetId, range, formulas, "USER_ENTERED")


def update_spreadsheet(spreadsheetId: str, requests: list[dict]) -> dict:
    """Applies one or more updates to the spreadsheet — anything beyond cell
    values: sheets, formatting, merges, filters, charts, data validation.

    spreadsheetId: the ID of the spreadsheet to update.
    requests: a list of Sheets API Request objects, applied atomically in order.
      Common kinds are addSheet, deleteSheet, updateSheetProperties,
      updateSpreadsheetProperties, updateCells, repeatCell, mergeCells,
      updateBorders, setBasicFilter, addConditionalFormatRule, addChart.
      For example, to rename the first sheet:
        [{"updateSheetProperties": {
            "properties": {"sheetId": 0, "title": "Q3"}, "fields": "title"}}]
      Field names follow the REST reference at
      https://developers.google.com/workspace/sheets/api/reference/rest/v4/spreadsheets/request
    """
    _require_owner(spreadsheetId)
    return sheets.client().batch_update(spreadsheetId, requests)


def insert_dimension(
    spreadsheetId: str, sheetId: int, dimension: str,
    startIndex: int, endIndex: int, inheritFromBefore: bool = False,
) -> dict:
    """Inserts rows or columns in a sheet at a particular index.

    spreadsheetId: the ID of the spreadsheet to update.
    sheetId: the ID of the sheet to insert into (0 for the first sheet; see
      get_spreadsheet for the rest).
    dimension: 'ROWS' or 'COLUMNS'.
    startIndex: 0-based index to insert at, inclusive.
    endIndex: 0-based end index, exclusive — three rows at the top are 0 and 3.
    inheritFromBefore: take formatting from the preceding row/column instead of
      the following one. Must be false when inserting at index 0.
    """
    _require_owner(spreadsheetId)
    return sheets.client().batch_update(spreadsheetId, [{"insertDimension": {
        "range": {
            "sheetId": sheetId,
            "dimension": dimension,
            "startIndex": startIndex,
            "endIndex": endIndex,
        },
        "inheritFromBefore": inheritFromBefore,
    }}])


# ── ours, on top of Google's set ────────────────────────────────────
def append_values(spreadsheetId: str, range: str, values: list[list[Any]]) -> dict:
    """Appends rows after the last row of data in a sheet or table.

    Input is parsed as if typed, so formulas and dates work.

    spreadsheetId: the ID of the spreadsheet to update.
    range: the sheet or table to append to, e.g. 'Sheet1' or 'Sheet1!A1'.
    values: an array of rows, each row an array of cell values.
    """
    _require_owner(spreadsheetId)
    return sheets.client().values_append(spreadsheetId, range, values)


def clear_values(spreadsheetId: str, range: str) -> dict:
    """Clears values from a range. Formatting and other properties are kept.

    spreadsheetId: the ID of the spreadsheet to update.
    range: the A1 notation of the range to clear.
    """
    _require_owner(spreadsheetId)
    return sheets.client().values_clear(spreadsheetId, range)


ALL = [
    list_spreadsheets,
    get_values, get_spreadsheet, update_values, update_formulas,
    update_spreadsheet, insert_dimension,
    append_values, clear_values,
]
