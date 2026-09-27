# UniShield — Limitations

## System Limitations

1. **Not a complete SOC**: UniShield is a research prototype, not a production
   Security Operations Centre. It does not replace commercial SIEM/IDS products.

2. **No detection guarantees**: The system does not guarantee detection of all
   attacks. False negatives are expected, especially for novel threats.

3. **Metadata-only analysis**: Because payload content is never inspected,
   the system has blind spots for attacks that are only visible in payload data.

4. **Encrypted traffic classification is probabilistic**: Analysis of encrypted
   sessions uses metadata patterns (timing, sizes, TLS fingerprints). These
   patterns are indicative, not definitive. The system uses terms like
   "suspicious encrypted-session behaviour" rather than claiming proof of malware.

5. **Public datasets may not represent real infrastructure**: Models trained on
   public datasets (CICIDS, CTU-13, UNSW-NB15) may not generalise to specific
   production environments without fine-tuning.

6. **No mitigation capability**: The system operates in a unidirectional
   monitoring environment. It cannot block, rate-limit, or remediate detected
   threats. Alert escalation must be handled by external processes.

7. **Threshold sensitivity**: Rule-based detection thresholds require tuning
   for each deployment environment. Default thresholds are starting points only.

8. **Baseline drift**: Statistical anomaly detection relies on baseline profiles
   that may drift over time. Periodic re-baselining is required.

9. **IP anonymisation trade-offs**: When IP anonymisation is enabled, correlation
   accuracy between alerts is reduced. This affects evaluation metrics and should
   be documented in experiment reports.

10. **Single-machine processing**: The current architecture runs on a single
    machine. High-volume production traffic may require architectural changes
    not included in this prototype.

## Ethical Considerations

- This system is intended **only** for defensive research.
- It must be used **only** with authorised datasets or isolated lab traffic.
- It does **not** include offensive capabilities.
- Attack simulations are limited to controlled local generation.
