# UniShield — Limitations

## What UniShield is not

1. **Not a live sensor.** It analyses files and replayed streams in event
   time. It does not capture from network interfaces; "real time" in the
   reports means near-real-time processing of a replayed stream.
2. **Not a SOC or IPS.** It cannot block, rate-limit or remediate; that is
   intentional for a one-way network.
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

## Model and data limits

10. **Synthetic training data.** The window models are trained and evaluated
    on UniShield's own generator. Train and test share a distribution, so the
    supervised scores in `reports/model_evaluation.md` are optimistic; the
    leave-one-attack-out results show that unseen attack types are mostly
    missed by the supervised model.
11. **No public-dataset results are included.** The pipeline reads CICIDS2017
    CSVs and CTU-13 labels (`scripts/prepare_dataset.py --input ...`), but
    those datasets were not downloaded or evaluated here.
12. **Calibration is distribution-specific.** Probabilities are calibrated on
    held-out runs of the same generator and may be miscalibrated elsewhere.
13. **Window labels.** A window counts as an attack window if it contains any
    attack-labelled flow; mixed windows are labelled by the majority attack
    label.

## Engineering limits

14. **Single process.** One pipeline thread, SQLite by default. PostgreSQL
    works by URL, but there is no horizontal scaling.
15. **PCAP parsing is the slow path** (scapy in Python, a few thousand
    packets per second on the benchmark machine); convert large captures to
    Zeek logs first.
16. **Docker** files are provided but were not built on the development
    machine (Docker was not installed there).
17. **IP anonymisation** reduces correlation accuracy and must be noted in
    experiment reports when enabled.

## Ethics

Use only authorised datasets or isolated lab traffic. The generator produces
flow records only — no packets are sent, and no exploit, malware, credential
harvesting, persistence, evasion or scanning functionality is included.
