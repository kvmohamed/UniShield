# UniShield — Deployment and Operations

How to place UniShield, run it as a service and operate it: network
placement, install, accounts, HTTPS, analyst-side outputs and threat
intelligence, health, the audit log, the database (migrations, retention,
backups) and upgrades. The threat model behind these choices is in
[threat_model.md](threat_model.md).

UniShield runs on the **receiving side** of a data diode. It reads copies of
monitored traffic (capture files, Zeek logs, flow exports) that the diode
delivers, and reports to analysts who work on a **separate analyst network**.
It never sends anything into the monitored network: there is no path back
through the diode, and the software has no probing, blocking, decryption or
response capability.

```
  monitored network ──► data diode ──► UniShield host ──► analyst network
  (home_networks)       (one way)      reads files/logs     SIEM (syslog), mail relay,
                                       detects, stores      webhook receiver, analysts'
                                       │                    browsers (dashboard/API),
                                       └─ export files ───► file collectors
```

Outbound traffic from UniShield is optional and goes only to analyst-side
systems the operator lists. Nothing is fetched from the internet: threat
intelligence is imported from files you bring across yourself.

## 1. Network placement and firewalling

- Put the UniShield host on the analyst side. Feed it from the diode through
  a directory it can read (`paths.data_dir`, `ingest.allowed_dirs`).
- Inbound to UniShield: the API/dashboard port (default `127.0.0.1:8000`,
  or 443 on a reverse proxy) from analysts' machines only, over HTTPS
  (section 6), with accounts enabled (section 5).
- Outbound from UniShield: allow, at the host or network firewall, only the
  destinations you also put in `outbound.allowed_destinations` (SIEM syslog
  port, SMTP relay, webhook receiver). Deny everything else, and in
  particular every address of the monitored network. The firewall and
  UniShield's own policy are independent layers.

## 2. Describe the monitored network

`network.home_networks` must list the monitored network's address ranges.
It drives flow direction and is the deny-list for outbound delivery: any
destination inside it is refused, and an allow-list entry overlapping it
stops the configuration from loading.

The default is every private range (RFC 1918 + IPv6 ULA). With that
default, private analyst-side addresses are refused too, so outbound
delivery stays off until you narrow `home_networks` to the real monitored
ranges, for example:

```yaml
network:
  home_networks: ["10.20.0.0/16", "fd20::/48"]     # the monitored plant / OT network
outbound:
  allowed_destinations: ["192.168.50.10", "siem.analyst.example"]
```

## 3. Install

Python 3.12 on Linux or Windows.

```bash
sudo useradd --system --home-dir /opt/unishield --shell /usr/sbin/nologin unishield
sudo git clone https://github.com/kvmohamed/UniShield.git /opt/unishield   # or unpack a release
cd /opt/unishield
sudo python3.12 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo .venv/bin/pip install --no-deps .
sudo .venv/bin/pip install "psycopg[binary]==3.3.6"     # only for PostgreSQL
```

`requirements.txt` pins every runtime dependency; CI audits the pins with
pip-audit and publishes a CycloneDX SBOM for each commit (see
[releasing.md](releasing.md)).

## 4. Configure

Settings come from `configs/config.yaml`, overridden by `UNISHIELD_*`
environment variables (all of them are listed in `.env.example`). For a
service, put the environment in one file readable only by the service:
[`deploy/systemd/unishield.env`](../deploy/systemd/unishield.env) is a
production starting point (accounts mode, API docs off, retention, SQLite
under `/var/lib/unishield`).

| Setting | Production value | Why |
|---|---|---|
| `UNISHIELD_ENV` | `production` | refuses `auth.mode: open` |
| `UNISHIELD_AUTH_MODE` | `accounts` (default) | every data endpoint needs a login or token |
| `UNISHIELD_API_DOCS` | `false` | `/docs` needs no login and loads Swagger UI from a CDN |
| `UNISHIELD_API_HOST` | `127.0.0.1` behind a proxy; the serving interface with direct TLS | |
| `UNISHIELD_FORWARDED_ALLOW_IPS` | the proxy's address (default `127.0.0.1`) | real client addresses in the audit log and rate limiter |
| `UNISHIELD_ALERT_RETENTION_DAYS` | e.g. `90` | bounded storage |
| `api.workers` | `1` | replay state and the login rate limiter live in the process |

## 5. Accounts and roles

There are **no default accounts**. Create the first administrator on the
server (it prompts for the password twice; `--password-stdin` reads it from
standard input for automation):

```bash
sudo -u unishield .venv/bin/unishield-admin user create alice --role admin
```

| Role | Can |
|---|---|
| viewer | read every data endpoint and the dashboard |
| analyst | everything a viewer can; reserved for alert feedback and annotations (no analyst-only endpoint exists yet) |
| admin | start/stop replays and demos, delete alerts, manage users, read the audit log |

Administrators manage further users in the dashboard (Admin tab) or with
`unishield-admin user list | set-role | set-password | disable | enable |
unlock | delete`. Role, password and disabled-state changes end that user's
sessions. The last active administrator cannot be demoted, disabled or
deleted. Passwords: at least 12 characters (`auth.min_password_length`),
not containing the username; stored as Argon2id hashes.

**Sessions.** Logging in sets an HttpOnly, SameSite=Strict cookie (Secure
over HTTPS; `auth.cookie_secure`) and returns a CSRF token the dashboard
sends with every state-changing request. Sessions end after
`auth.session_idle_minutes` (30) without activity or
`auth.session_ttl_minutes` (480) in total.

**Brute force.** After `auth.max_failed_logins` (5) consecutive wrong
passwords an account is locked for `auth.lockout_minutes` (15); an
administrator can unlock it early. Independently, a client address with
`auth.login_rate_limit` (10) failed logins or API keys within
`auth.login_rate_window_sec` (300 s) gets HTTP 429 until the window
passes. The answer to a failed login never says whether the user exists,
the password was wrong or the account is locked; the audit log does.

**Automation: service tokens.** Scripts and SIEM collectors use the
`X-API-Key` header with a token that has a fixed role:

```bash
unishield-admin token create --name siem --role viewer --expires-days 90   # prints the token once
unishield-admin token list
unishield-admin token revoke siem
```

Tokens need no CSRF token, cannot manage users or change passwords, and are
stored only as SHA-256 digests. `UNISHIELD_ADMIN_API_KEY` remains as one
static token acting with `api.api_key_role` (default `admin`); prefer named
tokens, which can expire and be revoked individually.

**Lab-only open mode.** `auth.mode: open` lets anonymous callers read (the
pre-accounts behaviour, for classroom demos on an isolated machine);
replays, deletion, users and the audit log still need an administrator.
UniShield refuses to start in open mode with `UNISHIELD_ENV=production`.

> Loopback is not trusted. Earlier versions let any client on 127.0.0.1
> use the administrative endpoints; behind a reverse proxy on the same host
> that would have been every client.

## 6. HTTPS

Never expose UniShield over plain HTTP beyond the local machine: logins and
session cookies would cross the network in clear text. Choose one of:

**a) A reverse proxy terminates TLS (recommended).** UniShield listens on
`127.0.0.1:8000`; the proxy listens on 443. Examples:
[`deploy/nginx/unishield.conf`](../deploy/nginx/unishield.conf) and
[`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile). The proxy must send
`X-Forwarded-Proto` and `X-Forwarded-For` (replacing any client-supplied
value), and its address must be in `api.forwarded_allow_ips` (default
`127.0.0.1`). UniShield then sees the request as HTTPS, sets the Secure
cookie flag and HSTS, and records the real client address. Do not set
`forwarded_allow_ips` to `*` if clients can reach UniShield directly: they
could forge their address and scheme.

**b) UniShield serves HTTPS itself.**

```bash
UNISHIELD_TLS_CERTFILE=/etc/unishield/tls/fullchain.pem
UNISHIELD_TLS_KEYFILE=/etc/unishield/tls/privkey.pem
UNISHIELD_TLS_KEYFILE_PASSWORD=...        # only if the key is encrypted
UNISHIELD_API_HOST=0.0.0.0                # or the serving interface
```

`python -m unishield.main` passes these to uvicorn and stops with an error
if a file is missing. Keep the key readable only by the service user
(`chmod 0640`, group `unishield`).

Either way, HTTPS responses carry `Strict-Transport-Security:
max-age=31536000` (`tls.hsts_max_age`; `tls.hsts_include_subdomains`
optional). `/health` and the `system.start` audit entry report whether TLS
is on. When starting on a non-loopback address without TLS, UniShield logs
a warning.

This is the TLS of UniShield's own API. Syslog over TLS to an analyst-side
SIEM is configured per destination (`outbound.syslog.destinations[].tls`,
section 8).

## 7. Run as a service

### Linux (systemd)

```bash
sudo install -d -o root -g unishield -m 0750 /etc/unishield
sudo install -m 0640 -o root -g unishield deploy/systemd/unishield.env /etc/unishield/unishield.env
sudo install -m 0644 deploy/systemd/unishield.service /etc/systemd/system/unishield.service
sudo systemctl daemon-reload
sudo systemctl enable --now unishield
journalctl -u unishield -f
```

The unit ([`deploy/systemd/unishield.service`](../deploy/systemd/unishield.service))
runs `unishield-admin db upgrade` and then `python -m unishield.main` as
the `unishield` user with no capabilities, a read-only system
(`ProtectSystem=strict`; only `/var/lib/unishield` and `/var/log/unishield`
are writable), private `/tmp`, restricted address families and a
system-service syscall filter. Capture directories stay read-only. CI runs
`systemd-analyze verify` on it.

### Windows (NSSM, documented only)

UniShield has no Windows service wrapper of its own; [NSSM](https://nssm.cc)
runs it as a service. From an elevated prompt, with UniShield in
`C:\UniShield` and its virtualenv in `C:\UniShield\.venv`:

```bat
nssm install UniShield C:\UniShield\.venv\Scripts\python.exe -m unishield.main
nssm set UniShield AppDirectory C:\UniShield
nssm set UniShield AppEnvironmentExtra UNISHIELD_ENV=production UNISHIELD_API_DOCS=false UNISHIELD_DB_URL=sqlite:///C:/ProgramData/UniShield/unishield.db UNISHIELD_LOGS_DIR=C:\ProgramData\UniShield\logs
nssm set UniShield AppStopMethodConsole 45000
nssm set UniShield AppStopMethodWindow 0
nssm set UniShield AppStopMethodThreads 0
nssm set UniShield AppStdout C:\ProgramData\UniShield\logs\service.log
nssm set UniShield AppStderr C:\ProgramData\UniShield\logs\service.log
nssm set UniShield AppRotateFiles 1
nssm set UniShield ObjectName "NT SERVICE\UniShield"
nssm start UniShield
```

`AppStopMethodConsole` sends Ctrl+C, which uvicorn handles like SIGTERM
(graceful shutdown below); 45 s leaves time for it. Run the service as its
virtual account (`NT SERVICE\UniShield`), give that account modify rights on
`C:\ProgramData\UniShield` only, and read rights on the capture directories.
Create the first administrator before starting:
`C:\UniShield\.venv\Scripts\unishield-admin.exe user create alice --role admin`
(with the same `UNISHIELD_DB_URL`). Put IIS, nginx for Windows or Caddy in
front for HTTPS, or use `UNISHIELD_TLS_CERTFILE`/`_KEYFILE`. WinSW or the
Task Scheduler work similarly; whichever you use, it must stop the process
with Ctrl+C or Ctrl+Break, not by killing it.

### Container

```bash
docker compose up -d --build
docker compose run --rm api unishield-admin user create alice --role admin
```

The image runs `python -m unishield.main` as an unprivileged user with a
read-only root filesystem and no capabilities; the database lives in the
`unishield-state` volume. The port is published on the host's loopback
only: put a TLS proxy in front for remote access. (The Docker files were not
built on the development machine; Docker was not installed there.)

Export files live in the `unishield-exports` volume (`/app/exports`). Mount
CA bundles or client certificates for syslog over TLS read-only and point
the destination's `tls.ca_file` / `tls.cert_file` at them.

### Graceful shutdown

On SIGTERM, SIGINT or Ctrl+Break, uvicorn stops accepting connections and
waits up to `api.shutdown_timeout_sec` (15 s) for open requests. UniShield
then stops housekeeping, stops a running replay and waits up to the same
time for it to record its final state (a run that does not stop in time is
recorded as `interrupted`), writes `system.stop` to the audit log and
closes the database. Service managers should allow at least twice
`shutdown_timeout_sec` (the unit uses 45 s, compose `stop_grace_period:
45s`).

## 8. Analyst-side outputs

All outputs are off by default (`configs/config.yaml`, `export:` and
`outbound:` sections).

| Output | Enable | Notes |
|---|---|---|
| On-demand files | always available | `python scripts/export_alerts.py` or `POST /export` (admin) → `<export.directory>/on-demand/` |
| Continuous files | `export.continuous: true` (`UNISHIELD_EXPORT_CONTINUOUS=true`) | `alerts.jsonl`, `incidents.jsonl`, `unishield.cef`, `unishield.stix.json` in `export.directory`; rotated by size, `backup_count` kept |
| Syslog | `outbound.syslog.enabled` + destinations | RFC 5424 over UDP, TCP or TLS (port 6514, verify against `tls.ca_file`, optional client certificate); CEF or JSON payload |
| Email | `outbound.email.enabled` | relay must be allow-listed; password from `UNISHIELD_SMTP_PASSWORD` (name configurable); STARTTLS by default |
| Webhook | `outbound.webhook.enabled` + destinations | JSON POST; auth headers from environment variables (`headers_from_env`); no redirects or proxies |

Notifications go out for alerts at or above `min_severity`, at most one
message per `min_interval_sec` and `max_per_hour` per channel; alerts in
between are sent as one digest. Only the listed `fields` leave the host
(never raw evidence); `redact_ips: true` replaces addresses with
"redacted". Syslog destinations have their own `redact_ips`.

Delivery runs in a background worker with a bounded queue
(`outbound.queue_size`); if a destination is slow or down, detection is not
delayed and overflowing alerts are counted as dropped. Check
`GET /outputs/status` or the dashboard's architecture tab.

Validation happens twice: when the configuration loads (allow-list against
`home_networks`, each enabled destination against the allow-list) and before
every connection (host names are resolved, every address is checked, and the
connection goes to the checked address).

## 9. Threat intelligence

```bash
python scripts/import_intel.py --source feodo feodo_ipblocklist.csv
python scripts/import_intel.py --source sslbl-ja3 --type ja3 --expires 2026-12-31 ja3_fingerprints.csv
python scripts/import_intel.py --status
curl -X POST -H "X-API-Key: $TOKEN" --data-binary @bundle.json \
     "https://unishield.example.internal/intel/import?source=partner&filename=bundle.json"
```

Plain text, CSV (common feed columns are recognised) and STIX 2.1 indicator
bundles are accepted. Each import names a source; re-importing replaces it.
Indicators take effect at the next replay. Purge expired entries with
`--purge-expired` or `POST /intel/purge-expired`.

`$TOKEN` is an admin service token (`unishield-admin token create --name
intel-import --role admin --expires-days 1`); in the dashboard an
administrator can do the same after signing in. Status (`GET /intel/status`)
needs a viewer; imports, source removal and purges need an administrator
and are audited.

## 10. Secrets

The static API key, the TLS key password, the SMTP password and webhook tokens are read from environment
variables only (`.env` next to the working directory, or the container
environment). They never appear in the configuration file, logs or status
endpoints. Webhook URLs are shown as scheme, host and port only, because
some receivers embed tokens in the path.

Login passwords are stored only as Argon2id hashes, and session ids and
service tokens only as SHA-256 digests (section 5); `unishield-admin token
create` shows a token once.

## 11. Health monitoring

`GET /health` needs no login and returns `status`:

| Status | HTTP | Meaning |
|---|---|---|
| `healthy` | 200 | all components fine |
| `degraded` | 200 | working, but `degraded_components` need attention |
| `unhealthy` | 503 | the database is unreachable |

`components` reports `storage`, `schema` (outdated → run `unishield-admin db
upgrade`), `accounts` (no active administrator), `housekeeping` (retention
job stopped or failing), `replay` (last run failed or was interrupted) and
`models` (in `hybrid`/`ml` mode: window model missing or its SHA-256 does
not match). Container and service health checks fail only on 503; alert on
`degraded` from your monitoring.

## 12. Audit log

Administrators read it in the dashboard (Admin tab) or at `GET /audit`
(filters: `action` — exact or a prefix such as `auth.` —, `actor`,
`outcome`, `since`, `until`; paging with `limit`/`offset` and
`X-Total-Count`). Entries record time, actor (`alice`, `token:siem`,
`cli:root`, `system`, `anonymous`), role, action, outcome
(`success`/`failure`/`denied`), target, client address and details:

| Action | When |
|---|---|
| `auth.login`, `auth.logout`, `auth.lockout`, `auth.password_change` | logins (failures with the real reason), logouts, lockouts, password changes |
| `auth.token`, `auth.csrf_rejected`, `access.denied` | invalid API keys, missing/wrong CSRF token, insufficient role |
| `user.create`, `user.update`, `user.password_reset`, `user.unlock`, `user.delete` | account changes (API and CLI) |
| `token.create`, `token.revoke` | service tokens (CLI) |
| `replay.start`, `replay.demo`, `replay.stop` | analyses started and stopped |
| `intel.import`, `intel.remove`, `intel.purge_expired` | threat-intel imports (source, format, accepted/rejected, SHA-256), removals, purges via the API |
| `export.files` | on-demand exports (formats, range, number of alerts and files) |
| `alerts.delete`, `retention.purge` | data deletion (manual, by a replay with `clear`, or by retention) |
| `system.start`, `system.stop` | service start with the security-relevant configuration and the keys changed since the previous start; clean or interrupted stop |

The API has no route that changes or deletes entries, and on SQLite and
PostgreSQL the database itself refuses UPDATE, DELETE and (PostgreSQL)
TRUNCATE on `audit_log`. Anyone who can write the SQLite file, or act as
the table owner or a database administrator on PostgreSQL, can still drop
those triggers (section 13 shows how to keep the service itself from owning
them): forward entries to a SIEM (a viewer token
cannot read `/audit`; use an admin token for the collector) or back the
database up regularly if you need evidence that survives a compromised
host. The audit log is never purged by retention.

## 13. Database

### Migrations

The schema is managed by Alembic revisions shipped in the package
(`src/unishield/storage/migrations/versions`):

```bash
unishield-admin db current     # current and latest revision (exit 1 if behind)
unishield-admin db upgrade     # apply pending revisions
```

With `database.auto_migrate: true` (default) the API applies pending
revisions at start; with `false` it refuses to start on an outdated schema
and you run `db upgrade` yourself (the systemd unit does so before every
start). Databases created by versions before migrations existed are
recognised and stamped at `0001_initial` without changes, so their alerts
are kept. **Back up before upgrading UniShield** (below). Developers create
new revisions with `alembic -c alembic.ini revision -m "..."` in a source
checkout; CI checks that the migrated schema matches the code's table
definitions on SQLite and PostgreSQL.

### Retention

`retention.alert_days` (`UNISHIELD_ALERT_RETENTION_DAYS`, off by default)
deletes alerts stored more than that many days ago and finished runs that
ended before then. The API runs this housekeeping (which also removes
expired login sessions) every `retention.interval_minutes`; you can also
run it from cron or the Task Scheduler:

```bash
unishield-admin retention run              # uses retention.alert_days
unishield-admin retention run --days 30
```

Purges are audited as `retention.purge`. The audit log is not purged.

### Backup and restore — SQLite

The database is one file (default `./data/unishield.db`; the unit file uses
`/var/lib/unishield/unishield.db`) in WAL mode, so copying the file while
UniShield runs can produce an inconsistent copy. Use SQLite's online backup,
which is consistent while the service is running:

```bash
sqlite3 /var/lib/unishield/unishield.db ".backup '/backup/unishield-$(date +%F).db'"
# without the sqlite3 tool:
python -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()" \
    /var/lib/unishield/unishield.db /backup/unishield-$(date +%F).db
```

Or stop the service and copy `unishield.db` together with any
`unishield.db-wal` / `unishield.db-shm` files. Check a backup with
`sqlite3 backup.db "PRAGMA integrity_check"`.

Restore: stop the service, move the current `unishield.db*` files aside,
copy the backup to `unishield.db` (owned by the service user, mode 0600),
run `unishield-admin db upgrade` (a backup from an older version is
migrated forward), start the service. Accounts, sessions, tokens and the
audit log are in the same file, so a restore also rolls those back: review
users and tokens afterwards.

### Backup and restore — PostgreSQL

```bash
pg_dump --format=custom --file=/backup/unishield-$(date +%F).dump \
        "postgresql://unishield@db.internal/unishield"
```

Restore into an empty database, then bring the schema up to date:

```bash
createdb -O unishield unishield
pg_restore --no-owner --role=unishield --dbname=unishield /backup/unishield-2026-10-22.dump
unishield-admin --db-url postgresql+psycopg://unishield@db.internal/unishield db upgrade
```

The dump contains the audit triggers and their function. Note that the
owner of a table can disable or drop its triggers: if UniShield connects as
the owner (simplest setup), the triggers stop mistakes and injected
statements, not a compromised service. For stronger separation, run
`unishield-admin db upgrade` as an owner role, set `database.auto_migrate:
false`, and connect the service as a role that is not the owner and holds
only `SELECT, INSERT, UPDATE, DELETE` on its tables and `SELECT, INSERT` on
`audit_log` (plus `USAGE` on the sequences).

## 14. Upgrading UniShield

1. Read the release notes for configuration changes.
2. Back up the database (section 13).
3. Install the new version's pinned requirements and package.
4. `unishield-admin db upgrade`, then restart the service (the systemd unit
   upgrades automatically before starting).
5. Check `/health` and the `system.start` entry in the audit log
   (`changed_since_last_start`).

## 15. Verify a deployment

```bash
python scripts/verify_passive_mode.py      # static scan + runtime tripwire, writes reports/
curl -H "X-API-Key: $VIEWER_TOKEN" https://unishield.example.internal/outputs/status   # outputs configured / delivered
curl -H "X-API-Key: $VIEWER_TOKEN" https://unishield.example.internal/intel/status     # indicators per source
curl https://unishield.example.internal/health                                          # no login needed
```

The verification confirms that only `unishield/export/transport.py` has
network capability, that readers, pipeline and detectors make no socket
calls, that the transport reaches only allow-listed destinations, and that
a monitored-network destination is refused at load time, at send time and
at socket level.

## 16. Checklist

- [ ] `UNISHIELD_ENV=production`, `auth.mode: accounts`, API docs off
- [ ] first administrator created; no shared accounts; automation on named, expiring tokens
- [ ] HTTPS via a proxy (with `forwarded_allow_ips` set to it) or `tls.certfile`
- [ ] service runs unprivileged; capture directories read-only to it
- [ ] retention set; backups scheduled and a restore tested
- [ ] `/health` monitored (503 and `degraded`); audit log reviewed or forwarded
- [ ] `network.home_networks` lists the monitored ranges; outbound destinations allow-listed and firewalled
- [ ] `scripts/verify_passive_mode.py` passes on the installed version
