"""The Sheets MCP tools — framework-agnostic functions.

Type hints and docstrings here become the MCP tool schemas, so keep them accurate.

Every call is made with the server's service-account credentials, so before
touching a spreadsheet we check that the *caller* owns it. Without that check any
authenticated user could read someone else's sheet just by knowing its id, since
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


# spreadsheet_id -> owner e-mails. Ownership effectively never changes, and a
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


def list_spreadsheets() -> dict:
    """List the spreadsheets you own that are shared with this server.

    Share a sheet with the server's service-account e-mail to make it appear here.
    Returns each spreadsheet's id, title and last-modified time; use the id with
    the other tools.
    """
    return sheets.client().list_spreadsheets(caller_email())


def read_range(spreadsheet_id: str, range: str) -> dict:
    """Read cell values from a Google Sheets range.

    spreadsheet_id: the long token in the sheet's URL between /d/ and /edit.
    range: A1 notation, e.g. 'Sheet1!A1:D10' or 'A1:D10'.
    """
    _require_owner(spreadsheet_id)
    return sheets.client().read_range(spreadsheet_id, range)


def write_range(
    spreadsheet_id: str, range: str, values: list[list[Any]],
    value_input_option: str = "USER_ENTERED",
) -> dict:
    """Overwrite cell values in a range (A1 notation).

    values: rows of cell values, row-major.
    value_input_option: 'USER_ENTERED' (default, evaluates formulas/dates) or 'RAW'.
    """
    _require_owner(spreadsheet_id)
    return sheets.client().write_range(spreadsheet_id, range, values, value_input_option)


def append_rows(
    spreadsheet_id: str, range: str, values: list[list[Any]],
    value_input_option: str = "USER_ENTERED",
) -> dict:
    """Append rows after the last data row of a sheet or table.

    range: a sheet or table, e.g. 'Sheet1' or 'Sheet1!A1'.
    value_input_option: 'USER_ENTERED' (default) or 'RAW'.
    """
    _require_owner(spreadsheet_id)
    return sheets.client().append_rows(spreadsheet_id, range, values, value_input_option)


def clear_range(spreadsheet_id: str, range: str) -> dict:
    """Clear values from a range (A1 notation). Formatting is preserved."""
    _require_owner(spreadsheet_id)
    return sheets.client().clear_range(spreadsheet_id, range)


def list_sheets(spreadsheet_id: str) -> dict:
    """Spreadsheet metadata: title and tabs with their sheetIds and dimensions."""
    _require_owner(spreadsheet_id)
    return sheets.client().list_sheets(spreadsheet_id)


ALL = [list_spreadsheets, read_range, write_range, append_rows, clear_range, list_sheets]
