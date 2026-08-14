# sheets-mcp

An MCP server that reads and writes Google Sheets, packaged as a Docker image.

## Tools

Six of them copy Google's own [Sheets MCP
server](https://developers.google.com/workspace/sheets/api/reference/mcp) — same
names, same argument names, same response shapes — so a call composed for that
server works here unchanged:

| Tool | |
|---|---|
| `get_values(spreadsheetId, range)` | read a range |
| `get_spreadsheet(spreadsheetId, includeGridData=false)` | title, sheets, grid properties; optionally every cell |
| `update_values(spreadsheetId, range, values)` | write values literally (`=A1+1` stays text) |
| `update_formulas(spreadsheetId, range, formulas)` | write parsed input — formulas and dates |
| `update_spreadsheet(spreadsheetId, requests)` | `batchUpdate`: sheets, formatting, merges, filters, charts |
| `insert_dimension(spreadsheetId, sheetId, dimension, startIndex, endIndex, inheritFromBefore=false)` | insert rows or columns |

Three more have no counterpart there:

| Tool | |
|---|---|
| `list_spreadsheets()` | your spreadsheets shared with this server — the only way to find a `spreadsheetId` |
| `append_values(spreadsheetId, range, values)` | append rows after the last row of data |
| `clear_values(spreadsheetId, range)` | clear values, keep formatting |

## How access works

Spreadsheets are reached with **one service account**, not with each user's Google
credentials. You share a sheet with the service account's e-mail address and it
becomes usable here.

Users still sign in with Google, but only so the server knows *who is asking*. That
identity is then checked against Drive: `list_spreadsheets` asks Drive for
spreadsheets you own, and every other tool refuses a spreadsheet you don't own.
Without that check, anyone signed in could read any sheet shared with the service
account just by knowing its id.

Nothing is stored. Client registrations, authorization codes, refresh tokens and
access tokens are all signed JWTs that carry their own contents, so there is no
database, no volume and nothing to lose on restart. The trade-off: individual
tokens can't be revoked — rotating `JWT_SIGNING_KEY` revokes all of them at once.

## Google setup

In a Google Cloud project:

1. Enable **Google Sheets API** and **Google Drive API**.
2. Create a **service account** and download its JSON key → `service-account.json`.
   Note its e-mail (`…@….iam.gserviceaccount.com`) — that's what you share sheets with.
3. Create an **OAuth client ID** of type *Web application* for the sign-in step, with
   authorised redirect URI `https://sheets-mcp.treant.dev/google/callback`.

Then share each spreadsheet you want to use with the service-account e-mail
(Editor, or Viewer if you only need reads).

## Deploy

Every push to `main` builds the image and publishes it to
`ghcr.io/treant-dev/sheets-mcp:latest` (see `.github/workflows/build.yml`; tests run
first and a failure blocks the publish). The server never checks out the source — it
pulls that image.

The VPS needs four files in one directory, two of them secret:

| | |
|---|---|
| `docker-compose.yml` | from this repo, unchanged |
| `Caddyfile` | from this repo, unchanged |
| `.env` | filled in from `.env.example` — **secret** |
| `service-account.json` | the downloaded key — **secret** |

With `sheets-mcp.treant.dev` pointing at the host (A record, Cloudflare set to DNS
only) and ports 80 and 443 open:

```bash
mkdir -p /opt/sheets-mcp && cd /opt/sheets-mcp
# copy the four files here, then:
docker compose up -d
curl https://sheets-mcp.treant.dev/health
```

If the package is private, log in once first:
`echo $GITHUB_TOKEN | docker login ghcr.io -u <user> --password-stdin`.

To ship a new version, push to `main`, then on the server:

```bash
docker compose pull && docker compose up -d
```

Caddy obtains the TLS certificate on first start; `docker compose logs caddy` shows
it happening. HTTPS is not optional — claude.ai rejects plain-http connectors.

## Connect

Add a custom connector in claude.ai with the URL `https://sheets-mcp.treant.dev/`.
Claude registers itself, sends you through Google sign-in, and comes back connected;
the same connector then works in the mobile app.

From the CLI:

```bash
claude mcp add --transport http sheets https://sheets-mcp.treant.dev/
```

## Local use

The same image speaks stdio, with no OAuth — the caller is whoever
`LOCAL_USER_EMAIL` says:

```bash
MCP_TRANSPORT=stdio LOCAL_USER_EMAIL=you@example.com \
GOOGLE_APPLICATION_CREDENTIALS=$PWD/service-account.json \
python app/server.py
```

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

No network and no credentials required: the Sheets and Drive APIs are mocked, and
the OAuth tests drive the real ASGI app with Google's token endpoint stubbed out.

## Layout

| File | |
|---|---|
| `app/server.py` | entry point; builds the ASGI app or runs stdio |
| `app/tools.py` | the six tools, caller identity, ownership check |
| `app/sheets.py` | Sheets + Drive REST client, service-account credentials |
| `app/oauth.py` | stateless OAuth provider + Google callback |
| `app/config.py` | environment variables |

The previous AWS Lambda / API Gateway / DynamoDB implementation is preserved on the
`cloud-archive` branch.
