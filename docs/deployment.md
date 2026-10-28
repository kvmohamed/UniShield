# UniShield — Deployment on the analyst side of a one-way network

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
- Inbound to UniShield: the API/dashboard port (default `127.0.0.1:8000`)
  from analysts' machines only. Set `UNISHIELD_ADMIN_API_KEY` before
  exposing the API beyond loopback.
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

## 3. Outputs

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

## 4. Threat intelligence

```bash
python scripts/import_intel.py --source feodo feodo_ipblocklist.csv
python scripts/import_intel.py --source sslbl-ja3 --type ja3 --expires 2026-12-31 ja3_fingerprints.csv
python scripts/import_intel.py --status
curl -X POST -H "X-API-Key: $KEY" --data-binary @bundle.json \
     "http://127.0.0.1:8000/intel/import?source=partner&filename=bundle.json"
```

Plain text, CSV (common feed columns are recognised) and STIX 2.1 indicator
bundles are accepted. Each import names a source; re-importing replaces it.
Indicators take effect at the next replay. Purge expired entries with
`--purge-expired` or `POST /intel/purge-expired`.

## 5. Secrets

The admin key, SMTP password and webhook tokens are read from environment
variables only (`.env` next to the working directory, or the container
environment). They never appear in the configuration file, logs or status
endpoints. Webhook URLs are shown as scheme, host and port only, because
some receivers embed tokens in the path.

## 6. Docker

`docker-compose.yml` runs the API with a read-only root filesystem, no
capabilities and read-only mounts for configs, data, reports and models.
Alerts live in the `unishield-state` volume and export files in the
`unishield-exports` volume (`/app/exports`). Mount CA bundles or client
certificates read-only and point `tls.ca_file` / `tls.cert_file` at them.
The Docker files were not built on the development machine.

## 7. Verify a deployment

```bash
python scripts/verify_passive_mode.py      # static scan + runtime tripwire, writes reports/
curl http://127.0.0.1:8000/outputs/status  # what is configured and delivered
curl http://127.0.0.1:8000/intel/status    # imported indicators per source
```

The verification confirms that only `unishield/export/transport.py` has
network capability, that readers, pipeline and detectors make no socket
calls, that the transport reaches only allow-listed destinations, and that
a monitored-network destination is refused at load time, at send time and
at socket level.
