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
- Live flow exports (optional): allow UDP to `live.netflow_port` (default
  2055) only from the exporters, typically the receiving side of the diode,
  and list them in `live.allowed_exporters`. The collector only receives;
  nothing is sent back, so no return path is needed.
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

## Site tuning

This guide takes UniShield from the lab defaults to a site: describe the
hosts whose normal behaviour looks like an attack, learn the site's own
thresholds, and keep detector state across restarts. UniShield stays
passive throughout: it reads files, never sends packets into the monitored
network and never writes its own configuration.

Order of work for a new site:

1. Install and check passive operation (`python scripts/verify_passive_mode.py`).
2. Write `configs/assets.yaml` for the site.
3. Collect a few days of the site's traffic and run learning mode.
4. Review the suggested `thresholds.site.yaml` and the learning report; select it.
5. Enable restart-safe state and run the service.
6. Review INFO and suppressed alerts regularly (`/system/assets`).

## 16. Site files and settings

| What | Where | Override |
|---|---|---|
| General settings | `configs/config.yaml` | environment variables in `.env.example` |
| Default thresholds | `configs/thresholds.yaml` | never edited by UniShield |
| Asset inventory | `configs/assets.yaml` (`site.assets_file`) | `UNISHIELD_ASSETS_FILE` |
| Site thresholds overlay | none by default (`site.thresholds_file`) | `UNISHIELD_THRESHOLDS_FILE` |
| Detector state snapshot | `./data/state/pipeline_state.json` (`state.path`), off by default | `UNISHIELD_STATE_ENABLED`, `UNISHIELD_STATE_FILE` |

Relative site file names are resolved against the configs directory
(`UNISHIELD_CONFIG_DIR`). Every site file is validated at start-up and an
invalid or missing *named* file is an error, so a typo never silently
falls back to defaults. `GET /system/architecture` lists the files the
running thresholds and inventory came from.

## 17. Asset inventory (`configs/assets.yaml`)

Some hosts are supposed to scan, upload a lot, query odd names or poll on a
timer. Listing them with a role keeps their expected behaviour from being
reported as an attack. Detection still runs on their traffic; after
detection and deduplication the role's policy decides what happens to
each alert:

| Action | Effect |
|---|---|
| `alert` | reported unchanged |
| `info` | reported with severity INFO; `evidence.asset_policy` keeps the original severity and the matching asset |
| `suppress` | not reported; counted per action, class and role, and the latest 200 suppressed alerts are kept for review |

Built-in policies:

| Role | Side | Effect |
|---|---|---|
| `vulnerability_scanner` | source | PORT_SCAN, HOST_SCAN, RECONNAISSANCE → info |
| `backup_server` | destination | DATA_EXFILTRATION → suppress; C2_BEACONING → info. Uploads to it are also kept out of the uploader's baseline |
| `dns_resolver` | source | DGA_DETECTED, DNS_TUNNELLING → info (clients' own queries are still analysed) |
| `update_server` | destination | C2_BEACONING → info |
| `cdn_or_proxy` | destination | C2_BEACONING → info |
| `monitoring` | source | scans and C2_BEACONING → info |
| `monitoring` | destination | C2_BEACONING → info |
| `server` | – | no policy; the role appears in alert evidence |

Example:

```yaml
version: 1
assets:
  - name: vuln-scanner
    addresses: ["10.20.0.15"]
    roles: [vulnerability_scanner]
    description: weekly authenticated scan, Sunday 02:00
  - name: offsite-backup
    addresses: ["198.51.100.0/28"]
    roles: [backup_server]
  - name: resolvers
    addresses: ["10.20.0.53", "10.20.0.54"]
    roles: [dns_resolver]
policies:                         # optional overrides, per role, side and class
  vulnerability_scanner:
    source: {PORT_SCAN: suppress}
```

Matching rules:

- A source-side policy applies when every source of the alert holds the
  role. A DNS tunnelling alert without a single source uses its client
  list, and only when that list is complete.
- When several roles match, the most lenient action wins (suppress > info > alert).
- Threat intelligence wins over roles: an INTEL_MATCH alert, or an alert an
  imported indicator matched, is reported unchanged; the overridden policy is
  in its evidence and counted as `kept_for_intel_match`.
- With `security.anonymize_ips` on, alerts carry salted hashes. Single
  addresses still match through their hash; networks (CIDR) cannot.
- Classes a policy handled still count as explained for that window, so
  the statistical and Isolation Forest stages do not re-report an expected
  scan as a STATISTICAL_ANOMALY.

Each entry is a trust decision. If a listed scanner is compromised, its
scans are reported as INFO. Prefer `info` to `suppress`, keep the list
short, and check `GET /system/assets` (the inventory, the effective
policies, counts of what they changed and the latest suppressed alerts)
and the `alerts_downgraded_by_policy` / `alerts_suppressed_by_policy`
counters in `/metrics`.

## 18. Learning mode

`thresholds.yaml` holds starting values tuned on synthetic traffic.
Learning mode measures how close the site's benign traffic comes to each
threshold and suggests site values.

```bash
python scripts/learn_baseline.py data/zeek/2026-10-01 data/zeek/2026-10-02 data/zeek/2026-10-03
```

Inputs are any format UniShield reads, oldest first. They run through one
pipeline, so cross-window history carries over between files. Nothing is
stored or sent. The script writes:

- `configs/thresholds.site.yaml`, the suggested overlay. Changed values are
  active; unchanged ones are comments; every value records its percentile,
  observed value, margin, default, sample count and how many samples would
  still reach it (`_learned` block, ignored at load). It refuses to write
  `thresholds.yaml` and refuses to overwrite an existing overlay without
  `--force`.
- `reports/learning_report.md`: a table of all learned thresholds, the hosts
  behind every raised value, beacon-like pairs, alerts the current
  thresholds would have raised over the period, and the thresholds not
  learned.

Options: `--percentile` (default 99.9), `--margin` (default 1.5 for
volume thresholds), `--allow-tighten` (also suggest stricter values where
the site stayed far below a threshold; off by default), `--state-out`
(save the learned detector state for a warm start, see section 5) and
`--synthetic-hours N` (learn from generated site traffic, for trying the
tool).

What is learned:

| Threshold | Recorded per window |
|---|---|
| `ddos.packets_per_second`, `ddos.bytes_per_second` | peak 1 s rate to the busiest destination |
| `ddos.syn_rate_threshold`, `ddos.udp_flood_pps` | peak half-open / UDP rate to the busiest target, while its half-open / UDP share meets the rule |
| `scanning.unique_dest_ports`, `horizontal_scan_hosts`, `horizontal_scan_hosts_any`, `burst_connections` | the largest per-source value meeting the rule's failure condition |
| `exfiltration.min_upload_mb`, `baseline_deviation_sigma` | the largest upload-dominated upload, the largest robust z of an eligible upload |
| `dns.dga_min_domains`, `dns.tunnel_min_queries` | the most generated-looking domains of one client, the most queries to one encoded-looking base domain |
| `beaconing.regularity_cv_threshold` | per pair: the lowest interval CV of pairs meeting every other beacon condition |
| `statistical.mad_threshold`, `anomaly.min_score` | the score of every window those stages computed |

Ratios, time constants and severity bands are not learned (the report
lists them); they describe the shape of an attack rather than the volume
of a site.

Reading the report:

- Hosts listed under "Who drove the raised values" that are scanners,
  backup targets, resolvers, update servers or monitoring hosts belong in
  `assets.yaml`. Add them and run learning again, rather than raising a
  threshold for the whole network. On UniShield's synthetic site, learning
  without an inventory raises `scanning.unique_dest_ports` from 25 to 225
  because of one scanner; with the inventory it changes nothing.
- A host listed there that should not behave like that is a finding:
  investigate it before using the suggestions.
- `beaconing.regularity_cv_threshold` never goes below 0.05. Pairs more
  regular than that are listed, and they too belong in the inventory.

**Learning assumes the period contained no attack.** An attack inside it
raises exactly the thresholds that would have caught it. Use a period that
was reviewed, and repeat learning after major changes (new services,
monitoring, backup schedules).

The same run is available through the API: `POST
/replay/start?file_path=...&learning=true` (admin) stores no alerts, and
`GET /learning/latest` returns the suggested overlay text and the report.
The API never writes configuration; save the YAML yourself after review.

## 19. Site thresholds

Select the reviewed overlay:

```yaml
# configs/config.yaml
site:
  thresholds_file: "thresholds.site.yaml"
```

or `UNISHIELD_THRESHOLDS_FILE=thresholds.site.yaml`. Its values replace
those of `thresholds.yaml` key by key. A key that does not exist in
`thresholds.yaml`, or a value of the wrong type, is an error at start-up.
Hand edits are fine, and learning carries values of an active overlay over
into its next suggestion.

## 20. Restart-safe state

Beacons are slower than a window: a beacon detection needs 10 check-ins,
and exfiltration baselines need 10 windows of history. Without persistence a
restart forgets that history. With `state.enabled` (or
`UNISHIELD_STATE_ENABLED=true`) the following are snapshotted to
`state.path`: beacon pair histories, per-source upload baselines and
destination rarity, the statistical baseline, the Isolation Forest's
warm-up windows, the detectors' re-alert memory and the correlator's
dedup cache.

- Format: one JSON file with a format name, a version and the SHA-256 of
  its canonical payload. Nothing is pickled. The online Isolation Forest
  is rebuilt by refitting on its stored warm-up windows with the same seed.
- Written atomically every `state.snapshot_interval_sec` (default 300 s)
  of wall time, and whenever a run ends or is stopped. API shutdown waits
  for that final write.
- Restored when a file replay starts. A snapshot that is corrupt, edited,
  of another format or version is refused and the run starts cold.
  Components restore independently. The outcome (restored components,
  skipped ones and why) is in the run summary, `/replay/status` and
  `/system/architecture`.
- File replays use it when enabled; `state=true|false` on `POST
  /replay/start` overrides per run. Synthetic demos never do.
- Consecutive files of one site's feed (for example hourly Zeek log
  rotations) continue from each other's snapshot, with or without a
  restart in between.
- `scripts/learn_baseline.py --state-out <state.path>` gives the service a
  warm start with the learning period's baselines.

Restore a snapshot only to continue the same site's traffic. Replaying
older traffic on top of restored state counts it twice; delete the file
to start cold. Records of the window still open at shutdown are not saved
(up to one window, 10 s by default, is not analysed across a restart).

In Docker, `docker-compose.yml` points `UNISHIELD_STATE_FILE` at the
`unishield-state` volume; set `UNISHIELD_STATE_ENABLED=true` in `.env`.

Snapshot cost grows with the number of active beacon pairs. On the
development machine a 5.7 MB snapshot (about 36,000 pairs) took about
0.4 s to write, during which the pipeline pauses. See `reports/soak_test.md` for
the measured cost over a long run and choose the interval accordingly.

## 21. Long runs

`scripts/soak_test.py` streams generated site traffic through one pipeline
for a chosen wall-clock duration and rate, sampling memory, CPU, lag,
window latency, alert rate and state size; it writes
`reports/soak_test.md`. Run it on the target hardware at the site's
record rate before relying on the service:

```bash
python scripts/soak_test.py --duration 24h --rate 1000          # traffic time = wall time
python scripts/soak_test.py --duration 30m --rate 1000 --speedup 8
python scripts/soak_test.py --quick                             # 2 minutes
```

Memory bounds that matter on long runs: each run result keeps the newest
`processing.max_alerts_in_memory` alerts (counts cover all of them, and
stored alerts are in the database); beacon pairs and destinations idle for
longer than `beaconing.history_sec` are dropped; re-alert memories prune
expired entries.

## Live input

Two receive-only live inputs replace file replay when the site has them
(`live:` in `configs/config.yaml`; started from the dashboard or the API by
an administrator, stopped with `POST /replay/stop`; counters at
`GET /live/status`):

- **NetFlow v5/v9 and IPFIX**: point the exporter (router, switch, a probe
  such as softflowd or nProbe, or the diode's flow output) at
  `live.netflow_bind:live.netflow_port`. Bind the interface facing the
  exporters (`UNISHIELD_NETFLOW_BIND`) rather than `0.0.0.0`, and set
  `live.allowed_exporters`. Biflow IPFIX (RFC 5103) keeps request and
  response bytes apart, which the exfiltration and beaconing rules use;
  unidirectional exports leave them unknown. Sampled exports are not scaled.
- **Zeek follow**: give the directory Zeek writes (the current log
  directory, under `paths.data_dir` / `ingest.allowed_dirs`).
  `live.zeek_from_start: false` starts at the end of the existing logs, like
  `tail -F`. Rotation is followed; lines written between the last poll and
  a rotation are read from the renamed file while it stays in the directory.

UDP has no retransmission. The collector asks for a 4 MB receive buffer
(exporters send in bursts) and counts gaps in the exporters' sequence
numbers as `lost_records` (v5, IPFIX) or `lost_datagrams` (v9) in
`/live/status`; a growing count means the host or the path drops exports.
On Linux the buffer is capped by `net.core.rmem_max`.

Flow exports arrive after the flows end, so windows wait
`live.allowed_lateness_sec` before closing (120 s). Lower it for exporters
with short active/inactive timeouts; records older than that are dropped
and counted.

`scripts/demo_live_feed.py` plays synthetic scenarios to either input on
the same machine (loopback only) to check a deployment end to end.

## 22. Checklist

- [ ] `UNISHIELD_ENV=production`, `auth.mode: accounts`, API docs off
- [ ] first administrator created; no shared accounts; automation on named, expiring tokens
- [ ] HTTPS via a proxy (with `forwarded_allow_ips` set to it) or `tls.certfile`
- [ ] service runs unprivileged; capture directories read-only to it
- [ ] retention set; backups scheduled and a restore tested
- [ ] `/health` monitored (503 and `degraded`); audit log reviewed or forwarded
- [ ] `network.home_networks` lists the monitored ranges; outbound destinations allow-listed and firewalled
- [ ] `scripts/verify_passive_mode.py` passes on the installed version
- [ ] live input (if used): collector bound to the exporter-facing interface, `live.allowed_exporters` set, UDP port firewalled to the exporters
- [ ] `configs/assets.yaml` reviewed with the owners of the listed hosts.
- [ ] Learning run over a reviewed period; report read; overlay selected.
- [ ] State persistence enabled, on a writable volume.
- [ ] Soak test run on the target hardware at the site's rate.
- [ ] INFO and suppressed alerts (`/system/assets`) reviewed on a schedule.
