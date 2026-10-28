# UniShield — Limitations

## What UniShield is not

1. **Not a live sensor.** It analyses files and replayed streams in event
   time. It does not capture from network interfaces; "real time" in the
   reports means near-real-time processing of a replayed stream.
2. **Not a SOC or IPS.** It cannot block, rate-limit or remediate; that is
   intentional for a one-way network. Its only outbound traffic is the
   optional delivery of alerts to the analyst network (files, syslog, email,
   webhooks); it never sends anything into the monitored network.
3. **Not a payload inspector.** Only metadata is used. Threats visible only
   in payloads are invisible to it. TLS, QUIC and VPN traffic is never
   decrypted; encrypted-session findings describe how a session looks, not
   what it carries.

## Detection limits

4. **Thresholds need tuning.** `configs/thresholds.yaml` holds starting
   values tuned on synthetic scenarios, not on any production network.
   Learning mode suggests site values, but it assumes the learning period
   was free of attacks: an attack inside it raises the thresholds that would
   have caught it. It has only been exercised on UniShield's synthetic site
   traffic, not on a real network's logs. Ratios, time constants and
   severity bands are not learned.
4a. **Asset roles are trust decisions.** A listed vulnerability scanner's
   scans become INFO, uploads to a listed backup server are suppressed
   (counted, not shown as alerts). A compromised listed host hides behind
   its role. Window-level STATISTICAL_ANOMALY alerts are not attributed to
   hosts, so roles cannot exempt them; for example, a large *internal*
   backup can still raise one.
4b. **Statistical stages are starved by regular pollers.** The statistical
   and Isolation Forest detectors only score windows no rule explained.
   A regular pair (a beacon, or a monitoring poller even when its alerts
   are INFO) keeps the beaconing class "explained" in almost every window
   while it lasts, so at sites with many pollers these stages score few
   windows. The learning report shows how many they scored.
5. **Evidence takes time.** Beaconing needs at least 10 connections and
   exfiltration baselines need 10 windows of history. Window-level recall
   for these classes is therefore lower than episode-level recall.
6. **Evasion.** Jittered or slow beacons, uploads below baseline noise,
   dictionary DGAs and low-rate tunnels can stay below the rules. A beacon
   that pauses and resumes on the same (source, destination, port) within
   `beaconing.history_sec` (2 h) is not re-detected until the earlier
   episode leaves the history, because the pause makes the intervals
   irregular (found by the soak test; reproduced with a 93-minute pause).
7. **Statistical and anomaly alerts are leads.** STATISTICAL_ANOMALY says a
   window is unusual, not why. The robust-z baseline drifts with the traffic
   it accepts as normal.
8. **Isolation Forest cannot extrapolate.** A point beyond the training range
   scores no higher than the training edge, so extreme values are left to the
   robust-z detector.
9. **DNS heuristics** misfire on CDNs and services that use generated-looking
   names; they need response codes for the strongest DGA evidence.

10. **Threat intelligence is only as good as the lists.** UniShield never
    fetches feeds; operators import files and keep them current. Matches
    are exact (addresses, networks, a domain and its subdomains, JA3
    hashes): URLs, file hashes and fuzzy patterns are not supported, and
    STIX patterns are imported only when they are plain address/domain
    comparisons joined by OR. With IP anonymisation on, network (CIDR)
    indicators cannot match the hashed addresses. Intel severities and
    confidences are list-match scores, not measured accuracy, and no list
    was evaluated here.

## Model and data limits

11. **Synthetic training data.** The window models are trained and evaluated
    on UniShield's own generator. Train and test share a distribution, so the
    supervised scores in `reports/model_evaluation.md` are optimistic; the
    leave-one-attack-out results show that unseen attack types are mostly
    missed by the supervised model.
12. **No public-dataset results are included.** The pipeline reads CICIDS2017
    CSVs and CTU-13 labels (`scripts/prepare_dataset.py --input ...`), but
    those datasets were not downloaded or evaluated here.
13. **Calibration is distribution-specific.** Probabilities are calibrated on
    held-out runs of the same generator and may be miscalibrated elsewhere.
14. **Window labels.** A window counts as an attack window if it contains any
    attack-labelled flow; mixed windows are labelled by the majority attack
    label.

## Engineering limits

15. **Single process.** One pipeline thread, SQLite by default. PostgreSQL
    works by URL, but there is no horizontal scaling. Run one uvicorn worker:
    the replay state and the login rate limiter live in the process (the
    rate limiter also resets on restart; account lockouts are stored in the
    database and survive it).
15a. **Restart safety covers detector history, not in-flight data.** The
    state snapshot holds beacon histories, baselines, the Isolation Forest
    warm-up and re-alert memory. The window still open at shutdown is not
    saved (up to one window of traffic is not analysed across a restart), a
    crash loses what happened since the last snapshot, and restoring a
    snapshot before replaying *older* traffic counts it twice. The pipeline
    pauses while a snapshot is written; the cost grows with the number of
    active beacon pairs (measured in `reports/soak_test.md`).
15b. **Soak testing is synthetic and short.** The soak test streams
    UniShield's own generated site traffic; the measured run lasted 30
    minutes of wall time. No 24-hour run and no run on real traffic has
    been done.
16. **PCAP parsing is the slow path** (scapy in Python, a few thousand
    packets per second on the benchmark machine); convert large captures to
    Zeek logs first.
17. **Docker** files are provided but were not built on the development
    machine (Docker was not installed there). The systemd unit and the nginx
    example are checked only in CI (`systemd-analyze verify`, `nginx -t`); the
    Caddy example and the NSSM instructions for Windows are documented but
    were not run.
18. **IP anonymisation** reduces correlation accuracy and must be noted in
    experiment reports when enabled.

## Output limits

19. **Delivery is best effort.** UDP syslog can lose messages silently;
    TCP/TLS syslog retries a bounded backlog (1,000 messages) and then
    drops; the delivery queue drops alerts beyond `outbound.queue_size`.
    Drops are counted in `/outputs/status`, not recovered. Notifications
    are rate-limited by design, so a burst arrives as one digest that
    lists at most `digest_max_alerts` alerts.
20. **Not tested against a real SIEM, mail server or SOAR.** Delivery was
    exercised against UniShield's own loopback receivers (syslog UDP/TCP/TLS,
    SMTP, SMTPS, HTTP); interoperability with specific products was not
    verified.
21. **STIX output** follows the 2.1 specification's structure (checked by a
    test-side validator, not the OASIS validator). Object identifiers are
    deterministic UUIDv5 values so repeated exports de-duplicate, whereas the
    specification recommends UUIDv4 for domain objects. Incidents in rotated
    continuous bundles link only to indicators in the same bundle.
22. **Export files are not encrypted or signed** at rest; protect the export
    directory on the host.

## Access control and operations limits

23. **Local accounts only.** No single sign-on (OIDC, SAML, LDAP/AD) and no
    multi-factor authentication. Passwords are the only interactive factor;
    use a password manager, the minimum length and the lockout.
24. **The analyst role has no analyst-only actions yet.** It reads like a
    viewer; it exists so alert feedback and annotations can be added without
    changing who holds which role.
25. **The audit log is append-only against the application, not against
    the host.** Triggers refuse changes on SQLite and PostgreSQL, but anyone
    who can write the database file, or own the tables on PostgreSQL, can
    drop them. Forward entries to a SIEM for evidence that must survive a
    host compromise. Entries are never purged by UniShield, so the table
    grows without bound (a few hundred bytes per login or action).
26. **Throttling is per client address.** Behind a proxy that is not listed
    in `api.forwarded_allow_ips`, every client shares the proxy's address and
    one attacker can throttle everyone's logins for the window. Lockout is
    per account: an attacker who knows a username can keep that account
    locked by guessing wrong (an administrator can unlock it; consider the
    lockout length against this).
27. **Sessions are server-side rows in the alert database.** If the database
    is unavailable nobody can log in; restoring a backup also restores the
    sessions, tokens and accounts it contained.
28. **Service tokens have no IP binding or per-endpoint scopes** beyond their
    role. The static `UNISHIELD_ADMIN_API_KEY` cannot expire; prefer named
    tokens with `--expires-days`.
29. **Retention deletes by storage time.** Replayed historical traffic is
    kept for `alert_days` after it was analysed, whatever its traffic time.
30. **The API docs (`/docs`) need no login** when enabled and load Swagger UI
    from a CDN; turn them off in production (`UNISHIELD_API_DOCS=false`).

## Ethics

Use only authorised datasets or isolated lab traffic. The generator produces
flow records only — no packets are sent, and no exploit, malware, credential
harvesting, persistence, evasion or scanning functionality is included.
