"""The Sheets MCP tools — framework-agnostic functions.

Registered with the official MCP SDK in stdio.py (Phase 1), and reused with
mcp-lambda-handler in Phase 2. Type hints + docstrings here become the MCP tool
schemas, so keep them accurate.
"""
from typing import Any

import sheets

# The caller's identity for the current request. Phase 1/stdio leaves it
# "default"; on Lambda, handler.py sets it from the authorizer's verified
# user_id before dispatching. A module global is safe — a Lambda invocation
# handles one request at a time. Phase 3 makes this pick a per-user Google client.
_current_user = "default"


def set_current_user(user_id):
    """Set the identity for tool calls in this invocation (called by handler.py)."""
    global _current_user
    _current_user = user_id or "default"


def _user():
    return _current_user


def read_range(spreadsheet_id: str, range: str) -> dict:
    """Read cell values from a Google Sheets range.

    spreadsheet_id: the long token in the sheet's URL between /d/ and /edit.
    range: A1 notation, e.g. 'Sheet1!A1:D10' or 'A1:D10'.
    """
    return sheets.sheets_client_for(_user()).read_range(spreadsheet_id, range)


def write_range(
    spreadsheet_id: str, range: str, values: list[list[Any]],
    value_input_option: str = "USER_ENTERED",
) -> dict:
    """Overwrite cell values in a range (A1 notation).

    values: rows of cell values, row-major.
    value_input_option: 'USER_ENTERED' (default, evaluates formulas/dates) or 'RAW'.
    """
    return sheets.sheets_client_for(_user()).write_range(
        spreadsheet_id, range, values, value_input_option)


def append_rows(
    spreadsheet_id: str, range: str, values: list[list[Any]],
    value_input_option: str = "USER_ENTERED",
) -> dict:
    """Append rows after the last data row of a sheet or table.

    range: a sheet or table, e.g. 'Sheet1' or 'Sheet1!A1'.
    value_input_option: 'USER_ENTERED' (default) or 'RAW'.
    """
    return sheets.sheets_client_for(_user()).append_rows(
        spreadsheet_id, range, values, value_input_option)


def clear_range(spreadsheet_id: str, range: str) -> dict:
    """Clear values from a range (A1 notation). Formatting is preserved."""
    return sheets.sheets_client_for(_user()).clear_range(spreadsheet_id, range)


def list_sheets(spreadsheet_id: str) -> dict:
    """Spreadsheet metadata: title and tabs with their sheetIds and dimensions."""
    return sheets.sheets_client_for(_user()).list_sheets(spreadsheet_id)


ALL = [read_range, write_range, append_rows, clear_range, list_sheets]
