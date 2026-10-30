# VulnScanner

VulnScanner brings authorized vulnerability scans, findings, risk scoring, and remediation reports into one organization-based web console. The backend runs Nmap, Nuclei, and testssl.sh through a queued worker; the console follows scan progress and helps review results.

## Run locally with Docker Desktop

Start Docker Desktop with Linux containers enabled. From the project root:

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32)); print(secrets.token_hex(32))"
```

Put the first generated value in `SESSION_SECRET` and the second in `POSTGRES_PASSWORD` in the root `.env`. Use separate values. Keep that file private. The database password must be URL-safe because Compose places it in a connection URL; the generated hexadecimal value is suitable. There are no built-in passwords or administrator accounts.

```powershell
docker compose config --quiet
docker compose up --build -d
docker compose ps
```

Open [the console](http://localhost:8080) and register an account, then create an organization. [API documentation](http://localhost:8080/docs), [health](http://localhost:8080/health), and [scanner availability](http://localhost:8080/system/scanner-status) are available through the same address. If port 8080 is occupied, change `WEB_PORT` and the corresponding `CORS_ORIGINS` entries in `.env`.

The first build downloads Python dependencies and scanner tools. PostgreSQL, Redis, the API, and the workers stay inside the Docker network; the console port is bound to `127.0.0.1` so other computers cannot access it. The application defaults to `ENVIRONMENT=production` when the variable is unset; the local HTTP setup sets `ENVIRONMENT=development` (as `.env.example` does) so session cookies work over HTTP and the API documentation is available. In production the documentation is disabled unless `ENABLE_API_DOCS=true`. Workers start after the API has initialized the database.

For a platform administrator, set both `FIRST_SUPERUSER_EMAIL` and `FIRST_SUPERUSER_PASSWORD` to your own credentials before the first startup; setting only one of them stops the API with a configuration error. The password must follow the password policy: at least 12 characters, not a common password, and not containing the part of the email before the `@`. Otherwise the API logs an error and does not create the account. The account is created only when that email does not exist; changing the environment does not reset its password. Remove those two values after creation and recreate the API container with `docker compose up -d --force-recreate api`. Later password changes use the authenticated `/api/v1/auth/change-password` endpoint, which applies the same policy and signs out the account's other sessions.

## Services, workers and health checks

| Service | Role | Health check |
| --- | --- | --- |
| `api` | REST API and startup tasks | `/health/ready`: database reachable and Redis reachable (Redis is optional only in development) |
| `worker` | Scans from the `scans` queue, one scan per container | registered with Redis under its own hostname |
| `report-worker` | HTML/PDF reports from the `reports` queue | registered with Redis under its own hostname |
| `frontend` | nginx: console files and API proxy | none |

`SCAN_WORKERS` (default 2) sets how many scan worker containers run, which is the platform-wide number of scans that execute at the same time. Each organization's own limit (`max_concurrent_scans`) still applies. Reports have their own worker so they never wait behind a long scan. `/health` only shows that the API process answers; `/health/ready` is used by the container health check and is not proxied by nginx.

A worker that is stopped or killed mid-scan cannot record the outcome. A stale-scan reaper closes such scans: a scan still active after `SCAN_TIMEOUT` plus `SCAN_STALE_GRACE_SECONDS` (15 minutes by default) is marked failed (or cancelled, if cancellation was requested), keeping the partial results already stored. It runs at API startup and whenever a worker starts a scan, and each closure is recorded in the organization's audit log. Queued scans are never reaped.

## Check and stop the stack

```powershell
docker compose logs --tail=100 api worker report-worker frontend
docker compose down
```

Stopping the stack keeps database, queue, authorization, and report volumes. Avoid `docker compose down -v` unless you intend to permanently remove those volumes. Keep backups before upgrades: the app creates missing tables and indexes at startup but does not provide a versioned database migration workflow. Built-in scan profiles are updated to the current definitions at each API start; a profile you disabled stays disabled.

Set `LOG_FORMAT=json` for one JSON object per log line, for log collectors. Audit log lines identify actors by id; email addresses stay in the database.

The containers need network access to explicitly authorized scan targets. Inside a container, `localhost` refers to that container; `host.docker.internal` can reach the Docker Desktop host, but it still needs to be covered by a valid scope authorization. Scan only targets you are authorized to assess.

## Scan safety limits

`SCAN_BLOCKED_NETWORKS` lists networks that are never scanned, even when an authorization covers them. Target names are resolved when the scan runs, so a hostname that points into a blocked network is refused too; a name that cannot be resolved within `SCAN_DNS_TIMEOUT_SECONDS` fails the scan rather than skipping the check. The scanners resolve names again themselves, so a DNS answer that changes between the check and the scan (DNS rebinding) is not caught; authorize IP addresses when that matters. The default blocks loopback and unspecified addresses (`127.0.0.0/8 ::1/128 0.0.0.0/8 ::/128`); link-local and cloud metadata addresses, and IPv6 forms that embed them (IPv4-mapped, 6to4, NAT64), are always blocked. Add the Compose network's subnet (`docker network inspect vulnscanner_default`) and any other internal ranges the scanners must never reach, separated by spaces or commas.

Before each tool runs, the worker checks the scan's authorization again: revoking an authorization (or its expiry) stops further tools, and revoking also requests cancellation of the scans that use it.

Nmap scripts come from fixed script sets, never from raw names. Denial-of-service, brute-force, fuzzing, broadcast and third-party (`external`) scripts never run; non-intrusive profiles also exclude `intrusive` scripts. As a result the `vulners` script (it sends product versions to vulners.com) never runs, and TLS cipher grading comes from testssl.sh rather than Nmap. OS detection needs raw sockets: the Docker image runs the worker as root, so it is enabled there; a non-root worker skips it with a scan warning unless `NMAP_PRIVILEGED=true` and the worker has `CAP_NET_RAW`. testssl.sh scans one host per run and skips address ranges with a warning; Nmap runs IPv4 and IPv6 targets separately. Warnings appear in the scan's events and its final message ("Scan completed with warnings: ..."); a range scan usually reports how many addresses did not respond.

## Accounts, sessions and rate limits

Passwords must be at least 12 characters, must not be a common password, and must not contain the part of the email before the `@`. Sessions are bound to the password: changing it ends the account's other sessions (the console that made the change gets new cookies). An upgrade of the stored hash to new Argon2 parameters ends other sessions once, at the next sign-in. API clients that send a bearer token rather than cookies receive no new token from `/auth/change-password` and must sign in again.

Five wrong passwords lock an account for 15 minutes. A locked account answers every sign-in with the same generic error; sessions that already exist are not ended by a lockout.

Refresh tokens are single use and rotate on every refresh. The refresh cookie is sent only to `/api/v1/auth` (`SameSite=Strict`). When two console tabs refresh at the same moment, one wins; the other retries its request with the rotated cookies, and the refused refresh is recorded as `auth.refresh_reuse` in the audit log, which then does not by itself mean a token was stolen. Without Redis, single use and revocation are enforced per API process only.

Password hashing is limited to `PASSWORD_HASH_CONCURRENCY` (4) operations per API process, since each uses 64 MiB; a sign-in that cannot get a slot within 5 seconds receives HTTP 429. Validation errors (HTTP 422) name the field and the problem but never echo submitted values.

Sensitive endpoints are rate limited per client IP or per user: login (`LOGIN_RATE_LIMIT`, 10/minute), registration (`REGISTER_RATE_LIMIT`, 10/hour), session refresh (`REFRESH_RATE_LIMIT`, 30/minute), password change (`PASSWORD_CHANGE_RATE_LIMIT`, 5/minute), AI remediation (`LLM_RATE_LIMIT`, 30/hour) and report downloads (`REPORT_DOWNLOAD_RATE_LIMIT`, 60/minute). Clients over the limit receive HTTP 429 with a `Retry-After` header. Counters are shared through Redis; when Redis is unavailable each API process counts on its own. `RATE_LIMIT_ENABLED=false` turns this off.

Signed-in users download reports at `/api/v1/organizations/{organization_id}/reports/{report_id}/html` (or `/pdf`) with their own session and role. Expiring token links (`/api/v1/reports/download/{token}/html`) remain for sharing a report with someone outside the console. Every download is recorded in the audit log. PDF downloads return 404 when the server has no PDF support installed (the `reporting` extra; the Docker image includes it).

## Upgrading from an earlier version

- Every user signs in once after the upgrade: earlier tokens carry no password binding and are refused.
- The refresh cookie moved from `/` to `/api/v1/auth`; the old cookie is removed at the next sign-in or refresh.
- Finding lists (`/findings`, `/assets/{id}/findings`) return summaries without evidence or notes; fetch `/findings/{id}` for those. Asset findings, reports and authorizations are paginated with `limit` and `offset`.
- Built-in scan profiles are rewritten to the current definitions at startup (a profile you disabled stays disabled).
- Scan reports count the assets that have findings in that scan ("Assets With Findings"); organization reports count all of the organization's assets.
- Findings recorded before per-scan history existed start with a lower recurrence count in their priority score until new scans see them again.
- New scan observations store historical finding snapshots in an additive table created at startup. Scan reports retain the captured severity, priority, confidence, workflow status, identifiers, asset association and complete observed evidence even when later scans or review decisions change the live finding. Remediation guidance is shown separately as current guidance. Existing scan reports without snapshots explicitly identify their finding values as current state; historical values cannot be recovered retroactively. Previously generated report files remain unchanged until rebuilt.
- Scan comparisons require two successful, warning-free scans with matching verified target sets and recorded runtime scanner configurations. Scans recorded before execution coverage was captured must be rerun before comparison; incompatible or incomplete coverage returns HTTP 409. The existing `resolved_findings` fields mean findings were not observed in the comparable scan, not that remediation was verified; the response includes `comparison_note` explaining this.

## Configure AI remediation

Choose `LLM_PROVIDER` and `LLM_MODEL`, and supply `LLM_API_KEY` for the selected hosted provider. For Ollama on the Docker Desktop host, use `LLM_PROVIDER=ollama` and the example `OLLAMA_BASE_URL`. Without a usable provider, remediation falls back to clearly labelled generic guidance. Restart the API and worker after changing these settings.

Only selected finding fields are sent to the provider: title, severity, CVE/CWE ids, port, protocol, detected product, source tool, and a redacted, length-limited description. Before sending, the affected asset's address and names become `[asset]`, and other IP and MAC addresses, host names, URLs, e-mail addresses, credential headers, `key=value` secrets and long tokens are replaced with placeholders. Evidence rows and remediation notes are never sent. Each provider call waits up to `LLM_TIMEOUT_SECONDS` (60) and the hosted clients retry once; keep it at or below 70 seconds so guidance arrives before the console stops waiting (150 seconds). Each new generation counts against `LLM_RATE_LIMIT` per user; reading guidance already generated does not.

## Prepare remote HTTPS access

The supplied Compose stack is for local use. Before exposing it remotely, put an HTTPS reverse proxy on the Docker host in front of `127.0.0.1:8080`, with a valid certificate for your hostname. Set `ENVIRONMENT=production` and set `CORS_ORIGINS` to your HTTPS origin, then recreate the API and workers. Production session cookies require HTTPS; opening the console directly over HTTP in that mode will not maintain a cookie session. The API logs a warning at startup for risky production settings, such as plain-HTTP origins or open registration.

Decide who may use the instance. By default anyone who can reach the console can register (`ALLOW_SELF_REGISTRATION=true`), create an organization (`ORG_CREATION=any_user`) and launch scans against targets they authorize themselves. For a remote deployment, set `ALLOW_SELF_REGISTRATION=false` (accounts are then created by the bootstrap superuser and added to organizations) or `ORG_CREATION=superuser` so that only platform administrators create organizations.

Client addresses for rate limits and the audit log come from `X-Forwarded-For` only for trusted proxy hops. `TRUSTED_PROXY_HOPS=1` (the Compose default) trusts the bundled nginx. Behind an external HTTPS proxy that also appends `X-Forwarded-For`, set `TRUSTED_PROXY_HOPS=2`. Entries further left are supplied by clients and are ignored.

Configure the external proxy to preserve the host, disable buffering for `/api/v1/` event streams, and permit long-running SSE connections. Keep the database, Redis, API, and worker ports private. Manage credentials and backups outside source control. The internal Nginx connection remains HTTP behind the HTTPS proxy.

## Develop without Docker

See [the backend setup guide](backend/README.md) for the Python environment and tests. For a PostgreSQL installation outside Docker, add the optional driver with `pip install -e ".[dev,postgres]"` from `backend`. The Docker image includes PostgreSQL, PDF reporting, and AI client dependencies, without development tools or tests.

Docker image builds and live scanner/PDF execution need separate validation on a host with a running Docker engine. The project is a working prototype; passing automated tests does not establish production readiness.
