# sheets-mcp

An MCP server that reads and writes Google Sheets, packaged as a Docker image.

Six tools: `list_spreadsheets`, `read_range`, `write_range`, `append_rows`,
`clear_range`, `list_sheets`.

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

On the VPS, with `sheets-mcp.treant.dev` pointing at it (A record, Cloudflare set to
DNS only) and ports 80 and 443 open:

```bash
git clone git@github.com:treant-dev/sheets-mcp.git && cd sheets-mcp
cp .env.example .env          # fill it in
cp /path/to/key.json service-account.json
docker compose up -d --build
curl https://sheets-mcp.treant.dev/health
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
