# VulnScanner backend

The API supports organization roles (`admin`, `analyst`, and `viewer`), HTTP-only
cookie sessions, explicit scan authorization, Nmap/Nuclei/testssl adapters,
process cancellation, normalized findings, structured remediation guidance,
and HTML/PDF reports. The frontend lives in the sibling `frontend`
directory and is served locally by FastAPI.

## Run locally with PowerShell

From `backend`, with Python 3.11 or newer installed:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,llm]"
Copy-Item .env.example .env
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))"
```

Put the generated value in `SESSION_SECRET` in `.env`, then start the API:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open `http://localhost:8000/` for the console and `http://localhost:8000/docs` for
API documentation. Register an account and create an organization. Its creator
becomes an administrator. Add written scope authorization before starting a scan.

`ENVIRONMENT` defaults to `production` when unset, which requires HTTPS for
session cookies, requires Redis and a worker, and disables `/docs`, `/redoc` and
`/openapi.json` unless `ENABLE_API_DOCS=true`. The example `.env` sets
`ENVIRONMENT=development` for local runs. Empty values in `.env` count as unset.

The `llm` extra installs the AI provider clients; without them, remediation falls
back to generic guidance. Add `reporting` for PDF export. Set `SQL_ECHO=true` only
when debugging: it logs statement parameters, including credential rows.

SQLite and `./uploads` are local defaults. Missing scanner binaries fail clearly;
install the tools required by your chosen profile. testssl.sh and standard RQ
workers are best run on Linux. Without Redis, development mode uses temporary
background threads; these do not survive a server restart, and scans left
running by them are marked failed when the API starts again. Production requires
Redis and workers (`rq worker scans` and `rq worker reports`) and disables that
fallback.

## Docker

See the [deployment guide](../README.md) for secrets setup, stack startup,
localhost console access, scan and report workers (`SCAN_WORKERS`), health checks
and HTTPS production configuration. Compose has no default administrator
credentials or default signing/database secrets.

## Operations

- **Health.** `/health` answers while the process runs; `/health/ready` also checks
  the database and Redis (Redis is optional in development and tests) and returns
  503 when not ready, without error details.
- **Stale scans.** A scan still active `SCAN_TIMEOUT` + `SCAN_STALE_GRACE_SECONDS`
  after it started belongs to a worker that died; it is marked failed (or
  cancelled, if cancellation was requested) at API startup and whenever a worker
  picks up a scan. Each closure adds a scan event and an audit entry.
- **Startup.** Missing tables and indexes are created, built-in scan profiles are
  synchronized with `app/scanning/profiles.py` (an operator's choice to disable
  one is kept), and the optional bootstrap superuser is created. Its email is
  stored in lowercase, and its password must satisfy the password policy.
- **Proxies.** `TRUSTED_PROXY_HOPS` sets how many reverse proxies' `X-Forwarded-For`
  entries are trusted for the client IP used in rate limits and audit entries:
  0 when clients connect directly, 1 behind the Compose nginx, 2 behind an
  additional HTTPS proxy.
- **Blocked networks.** `SCAN_BLOCKED_NETWORKS` (default
  `127.0.0.0/8 ::1/128 0.0.0.0/8 ::/128`) are never scanned, even when authorized.
  Add internal ranges such as the Docker network the API runs in. Host names are
  resolved at scan start (`SCAN_DNS_TIMEOUT_SECONDS`) and the scan fails when they
  cannot be resolved.
- **Nmap privileges.** OS detection runs when the worker is root, or with
  `NMAP_PRIVILEGED=true` for a non-root worker that has `CAP_NET_RAW`; otherwise
  it is skipped with a scan warning.
- **Logging.** `LOG_LEVEL` and `LOG_FORMAT` (`console` or `json`) apply to the API
  and workers.
- **Platform audit log.** Superusers read entries without an organization (sign-ins,
  registrations) at `GET /api/v1/audit-log`.

## Accounts and access

Passwords need at least 12 characters, must not be a common password, and must
not contain the part of the email before the `@`. Tokens carry a password
version (`pwv`), so changing a password signs out the account's other sessions;
tokens issued before this was introduced are refused, and every user signs in
once after upgrading. Five wrong passwords lock an account for 15 minutes without
ending its existing sessions. Refresh tokens are single use; the refresh cookie
is scoped to `/api/v1/auth` with `SameSite=Strict`, and without Redis single use
and revocation hold per API process only. See the
[deployment guide](../README.md#accounts-sessions-and-rate-limits) for details. `ALLOW_SELF_REGISTRATION=false` disables public
registration and `ORG_CREATION=superuser` restricts organization creation to
platform administrators; consider both before exposing the API remotely.

Rate limits apply to login, registration, session refresh, password changes, AI
remediation and report downloads, keyed by client IP or by signed-in user
(settings ending in `_RATE_LIMIT`, written as `<count>/<second|minute|hour|day>`;
`RATE_LIMIT_ENABLED=false` turns them off). They are shared through Redis;
without Redis, each API process counts separately. Blocked requests receive
HTTP 429 with `Retry-After`.

## API workflow

Organization routes use `/api/v1/organizations/{organization_id}`. Create an
`/authorizations` record with a title, signer, authorization date, and a list of
`targets` objects (`{"value": "approved-host"}`). Create `/scans` with the
profile and authorization IDs plus target strings. Intrusive profiles require an
administrator and explicit acknowledgement. Monitor a scan at
`/scans/{scan_id}/events` (server-sent events; the stream replays earlier events,
then follows new ones, and sends a `: ping` comment every 15 seconds while idle),
then review `/findings` and `/assets`. Revoking an authorization
(`DELETE /authorizations/{id}`) requests cancellation of its queued and running
scans.

Finding lists (`/findings` and `/assets/{asset_id}/findings`) return summaries
without `evidence` or `remediation_notes`; `GET /findings/{finding_id}` returns
them, newest first, with at most 50 evidence rows. `/assets/{asset_id}/findings`
(default 50, at most 100), `/reports` and `/authorizations` (default 100, at most
100) take `limit` and `offset`. When a scan sees a finding again, its last-seen
time, CVEs, highest CVSS score, confidence and priority score are updated; a
finding marked fixed that is detected again is reopened (`finding.reopened` in
the audit log).

Request remediation with `POST /findings/{finding_id}/remediation`. Guidance
includes structured steps and a source label; fallback advice is generic and
requires review. Save finding status with `PATCH /findings/{finding_id}`.
Accepted risk requires a reason. Signed-in members download reports at
`/reports/{report_id}/html` or `/reports/{report_id}/pdf` under the
organization prefix. Expiring token links,
`/api/v1/reports/download/{token}/html`, remain available for sharing.

## Checks

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

From the project root, with Node installed:

```powershell
node --test frontend/tests/app.test.cjs
```

Backend tests use temporary databases and upload directories, and disable rate
limiting except in the tests that cover it. Browser logic tests exercise
API-shaped fixtures without running scanners or AI providers. The fixture
contracts are checked against the actual API schemas.

## Limits

Rate limiting, atomic per-organization concurrency limits and per-scan finding
history (`scan_findings`, recorded for scans run after it was introduced) are in
place. Known gaps:

- The concurrency limit is atomic on PostgreSQL (row lock); on SQLite, used for
  development, it is best-effort.
- No versioned database migrations: new tables and indexes are created at
  startup, but changes to existing columns or constraints need manual SQL.
- Host names are checked against blocked networks when a scan starts, but the
  scanners resolve them again, so DNS rebinding between the two is not caught.
- The event stream assumes events are written in timestamp order; an event
  written with an earlier timestamp (clock skew between hosts) reaches an open
  stream only after it reconnects.
- Scan reports use snapshots of finding state and complete observed evidence
  captured during normalization. Later observations and workflow changes do not
  rewrite them. Remediation guidance is separate and labelled current. Older
  scans have no snapshots: reports warn that finding values are current, and
  evidence uses the older per-type reconstruction, which may omit repeated
  items when the scan also stored new evidence of the same type. Existing HTML
  and PDF files remain unchanged until explicitly rebuilt.
- Scan comparisons require completed, warning-free execution with matching
  targets and captured runtime tool/configuration coverage. Legacy scans without
  that coverage, and incomplete or incompatible scans, return 409. A finding
  absent from the compared scan is an observation difference, not verified
  remediation; the response's `comparison_note` explains the legacy
  `resolved_findings` field names.
- Not validated: real scans against an authorized lab, PDF generation, real AI
  providers and a complete Docker image build/startup. Native `nginx -t` passed
  with cached nginx 1.29.7; this does not validate proxy behavior in the full stack.

Empty findings alone do not establish that a target has been assessed or is free
of vulnerabilities.
