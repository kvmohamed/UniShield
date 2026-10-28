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
5. **Evidence takes time.** Beaconing needs at least 10 connections and
   exfiltration baselines need 10 windows of history. Window-level recall
   for these classes is therefore lower than episode-level recall.
6. **Evasion.** Jittered or slow beacons, uploads below baseline noise,
   dictionary DGAs and low-rate tunnels can stay below the rules.
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
    works by URL, but there is no horizontal scaling.
16. **PCAP parsing is the slow path** (scapy in Python, a few thousand
    packets per second on the benchmark machine); convert large captures to
    Zeek logs first.
17. **Docker** files are provided but were not built on the development
    machine (Docker was not installed there).
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

## Ethics

Use only authorised datasets or isolated lab traffic. The generator produces
flow records only — no packets are sent, and no exploit, malware, credential
harvesting, persistence, evasion or scanning functionality is included.
