"""
UniShield — Alert Explanations ("why did this fire?")

Turns an alert's evidence into plain sentences for the analyst: what the
rule looks for, what was observed against which threshold, the context
added after detection (threat intel, asset inventory), common benign
causes worth ruling out, and caveats on what metadata cannot show.

Everything is derived from the stored alert alone; nothing is looked up,
recomputed or sent anywhere. Missing evidence fields are skipped, never
guessed, so an explanation can be shorter than usual but not wrong. The
benign causes are general experience with these patterns, not findings
about the alert.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from unishield.correlation.mitre_mapping import TECHNIQUE_NAMES, technique_url
from unishield.schemas.alert import Alert, ThreatClass

_ENCRYPTED_CAVEAT = ("Only handshake metadata and the shape of the session (timing, sizes, ports) were used; "
                     "the content was not decrypted and is unknown.")
_SPOOF_CAVEAT = "Source addresses of flood traffic can be spoofed; the listed sources may not be the real senders."
_ASSET_HINT = "If the host is known to do this, give it a role in configs/assets.yaml instead of ignoring the alert."

RULES: dict[ThreatClass, str] = {
    ThreatClass.PORT_SCAN: "One source tried many different destination ports within one analysis window "
                           "(on one host, or across hosts with most attempts failing).",
    ThreatClass.HOST_SCAN: "One source contacted many different hosts on the same port within one window.",
    ThreatClass.RECONNAISSANCE: "One source made a burst of connection attempts, most of which failed, without "
                                "reaching the port- or host-scan thresholds.",
    ThreatClass.SYN_FLOOD: "A host received connection requests (SYN) far faster than usual, and most were never "
                           "completed.",
    ThreatClass.UDP_FLOOD: "A host received UDP packets at a very high rate, making up most of its traffic.",
    ThreatClass.DDOS_VOLUMETRIC: "A host received more packets or bytes per second than the volumetric thresholds.",
    ThreatClass.DDOS_PROTOCOL: "A host received traffic whose protocol mix matches a protocol-level flood.",
    ThreatClass.C2_BEACONING: "A host connected to the same destination at regular intervals over a long period, "
                              "as malware checking in with its controller does.",
    ThreatClass.DATA_EXFILTRATION: "A host sent much more data to an outside destination than it received, or "
                                   "much more than its usual upload volume.",
    ThreatClass.DNS_TUNNELLING: "Queries under one domain carried long, random-looking, mostly unique subdomains, "
                                "as when data is encoded into DNS names.",
    ThreatClass.DGA_DETECTED: "A host looked up many random-looking domain names, most of which did not exist, as "
                              "malware using a domain-generation algorithm does.",
    ThreatClass.ENCRYPTED_SESSION_ANOMALY: "An encrypted session had suspicious handshake properties or shape "
                                           "(outdated protocol, listed client fingerprint, unusual port or "
                                           "duration).",
    ThreatClass.STATISTICAL_ANOMALY: "The traffic in this window deviated strongly from this network's own "
                                     "recent baseline.",
    ThreatClass.INTEL_MATCH: "Traffic involved an address or domain on an imported threat-intelligence list.",
    ThreatClass.BRUTE_FORCE: "One source opened many short, small connections to one login service on one host, "
                             "as password guessing does.",
    ThreatClass.SPAM_ACTIVITY: "One internal host delivered mail directly to many external mail servers, which "
                               "workstations do not normally do.",
}

BENIGN_CAUSES: dict[ThreatClass, list[str]] = {
    ThreatClass.PORT_SCAN: ["an authorised vulnerability scanner or asset-discovery tool",
                            "a monitoring system checking many services"],
    ThreatClass.HOST_SCAN: ["an authorised scanner or inventory tool", "a monitoring system polling many hosts",
                            "a client retrying a list of servers it cannot reach"],
    ThreatClass.RECONNAISSANCE: ["a misconfigured client retrying a service that is down",
                                 "a monitoring or inventory tool"],
    ThreatClass.SYN_FLOOD: ["clients retrying a service that is down or not listening (requests go unanswered)",
                            "a load test"],
    ThreatClass.UDP_FLOOD: ["a busy DNS, NTP, syslog or streaming server under legitimate load", "a load test"],
    ThreatClass.DDOS_VOLUMETRIC: ["a large legitimate transfer or backup to one host",
                                  "a sudden legitimate surge of users", "a load test"],
    ThreatClass.DDOS_PROTOCOL: ["a load test", "a legitimate surge of users"],
    ThreatClass.C2_BEACONING: ["software update checks, telemetry or licence agents",
                               "monitoring agents and keep-alive connections", "time synchronisation (NTP)"],
    ThreatClass.DATA_EXFILTRATION: ["backups or file synchronisation to a cloud service",
                                    "large legitimate uploads (video calls, screen sharing, data deliveries)"],
    ThreatClass.DNS_TUNNELLING: ["security products and CDNs that encode lookups into DNS names "
                                 "(reputation and telemetry services)", "a resolver forwarding for many clients"],
    ThreatClass.DGA_DETECTED: ["browsers probing random names to detect DNS hijacking",
                               "CDN or cloud hostnames that contain hashes",
                               "a resolver forwarding queries for many clients"],
    ThreatClass.ENCRYPTED_SESSION_ANOMALY: ["legacy or embedded devices that only support old TLS versions",
                                            "internal services on non-standard ports", "VPN clients"],
    ThreatClass.STATISTICAL_ANOMALY: ["a planned change, maintenance window or new service",
                                      "a short baseline (few windows learned)"],
    ThreatClass.INTEL_MATCH: ["shared hosting or CDN addresses that also serve legitimate sites",
                              "addresses reassigned since they were listed", "an outdated list entry"],
    ThreatClass.BRUTE_FORCE: ["health checks or monitoring logging in repeatedly",
                              "automation tools (configuration management) opening many sessions",
                              "a service account with a wrong stored password"],
    ThreatClass.SPAM_ACTIVITY: ["a mail server or relay not registered as one in the asset inventory",
                                "a newsletter or ticketing system sending mail directly"],
}

CLASS_NAMES: dict[ThreatClass, str] = {
    ThreatClass.DDOS_VOLUMETRIC: "volumetric flood", ThreatClass.DDOS_PROTOCOL: "protocol flood",
    ThreatClass.SYN_FLOOD: "SYN flood", ThreatClass.UDP_FLOOD: "UDP flood", ThreatClass.PORT_SCAN: "port scan",
    ThreatClass.HOST_SCAN: "host scan", ThreatClass.RECONNAISSANCE: "reconnaissance burst",
    ThreatClass.C2_BEACONING: "command-and-control beaconing", ThreatClass.DATA_EXFILTRATION: "data exfiltration",
    ThreatClass.DNS_TUNNELLING: "DNS tunnel", ThreatClass.DGA_DETECTED: "DGA domain lookups",
    ThreatClass.ENCRYPTED_SESSION_ANOMALY: "suspicious encrypted session",
    ThreatClass.STATISTICAL_ANOMALY: "statistical anomaly", ThreatClass.INTEL_MATCH: "threat-intel match",
    ThreatClass.BRUTE_FORCE: "brute-force attempt", ThreatClass.SPAM_ACTIVITY: "spam sending",
}

_ASSET_ROLE_HINT = {ThreatClass.PORT_SCAN, ThreatClass.HOST_SCAN, ThreatClass.RECONNAISSANCE,
                    ThreatClass.DATA_EXFILTRATION, ThreatClass.DNS_TUNNELLING, ThreatClass.DGA_DETECTED,
                    ThreatClass.BRUTE_FORCE, ThreatClass.SPAM_ACTIVITY, ThreatClass.C2_BEACONING}


def _n(value: Any) -> str:
    """Readable number: thousands separators, at most three decimals."""
    if isinstance(value, bool) or value is None:
        return str(value)
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e15:
            return f"{int(value):,}"
        return f"{value:,.3f}".rstrip("0").rstrip(".") if abs(value) < 1000 else f"{value:,.0f}"
    return str(value)


def _count(value: Any, noun: str) -> str:
    return f"{_n(value)} {noun}" + ("" if value == 1 else "s")


def _pct(value: Any) -> str:
    return f"{float(value):.0%}" if isinstance(value, (int, float)) else str(value)


def _bytes(value: Any) -> str:
    if not isinstance(value, (int, float)):
        return str(value)
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("kB", 1e3)):
        if abs(value) >= size:
            return f"{value / size:.1f} {unit}"
    return f"{int(value)} bytes"


def _list(values: Any, limit: int = 5) -> str:
    items = [str(v) for v in (values or [])]
    more = f" (+{len(items) - limit} more)" if len(items) > limit else ""
    return ", ".join(items[:limit]) + more


class _Builder:
    def __init__(self, alert: Alert):
        self.alert = alert
        self.ev: dict[str, Any] = alert.evidence or {}
        self.observed: list[str] = []
        self.thresholds: list[str] = []
        self.caveats: list[str] = []

    def has(self, *keys: str) -> bool:
        return all(self.ev.get(k) is not None for k in keys)

    def threshold(self, label: str, observed_key: Optional[str], threshold_key: str,
                  fmt: Callable[[Any], str] = _n) -> None:
        if self.ev.get(threshold_key) is None:
            return
        limit = fmt(self.ev[threshold_key])
        if observed_key and self.ev.get(observed_key) is not None:
            self.thresholds.append(f"{label}: {fmt(self.ev[observed_key])} observed, threshold {limit}.")
        else:
            self.thresholds.append(f"{label}: threshold {limit}.")


def _scan(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    who = ev.get("scanner_source_ip") or a.source_ip or "The source"
    if b.has("attempts"):
        rate = f" ({_n(ev['attempts_per_second'])} per second)" if b.has("attempts_per_second") else ""
        failed = (f"; {_pct(ev['failed_connection_ratio'])} of them failed to connect"
                  if b.has("failed_connection_ratio") else "")
        b.observed.append(f"{who} made {_n(ev['attempts'])} connection attempts in the window{rate}{failed}.")
    if a.threat_class == ThreatClass.PORT_SCAN:
        if b.has("unique_dest_ports", "unique_dest_hosts"):
            b.observed.append(f"It tried {_n(ev['unique_dest_ports'])} distinct destination ports across "
                              f"{_n(ev['unique_dest_hosts'])} hosts.")
        if b.has("max_ports_on_one_host", "most_probed_host"):
            b.observed.append(f"Most probed host: {ev['most_probed_host']} ({_n(ev['max_ports_on_one_host'])} "
                              "ports).")
        b.threshold("Distinct ports", "unique_dest_ports", "port_threshold")
    elif a.threat_class == ThreatClass.HOST_SCAN:
        if b.has("hosts_on_one_port", "swept_port"):
            b.observed.append(f"It contacted {_n(ev['hosts_on_one_port'])} hosts on port {ev['swept_port']}.")
        b.threshold("Hosts on one port", "hosts_on_one_port", "horizontal_threshold")
    else:
        b.threshold("Attempts in a burst", "burst_attempts", "burst_threshold")


def _flood(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    target = ev.get("target_ip") or a.destination_ip or "the target"
    if b.has("unique_sources"):
        spread = " (distributed)" if ev.get("distributed") else ""
        window = f" within {_n(ev['window_observed_sec'])} s" if b.has("window_observed_sec") else ""
        b.observed.append(f"{target} received traffic from {_n(ev['unique_sources'])} sources{spread}{window}.")
    if a.threat_class == ThreatClass.SYN_FLOOD:
        if b.has("half_open_attempts"):
            b.observed.append(f"{_n(ev['half_open_attempts'])} connection requests were never completed.")
        b.threshold("Peak incomplete connections per second", "peak_half_open_per_second", "syn_rate_threshold")
        b.threshold("Share of requests left incomplete", "half_open_ratio", "syn_only_ratio_threshold", _pct)
    elif a.threat_class == ThreatClass.UDP_FLOOD:
        b.threshold("Peak UDP packets per second", "peak_udp_packets_per_second", "udp_flood_pps_threshold")
        b.threshold("UDP share of the target's packets", "udp_share_of_target_packets", "udp_ratio_threshold",
                    _pct)
    else:
        if b.has("target_packets"):
            b.observed.append(f"{_n(ev['target_packets'])} packets reached {target} in the window.")
        b.threshold("Peak packets per second", "peak_packets_per_second", "pps_threshold")
        b.threshold("Peak bytes per second", "peak_bytes_per_second", "bps_threshold", _bytes)
    b.caveats.append(_SPOOF_CAVEAT)


def _beacon(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    if b.has("connection_count", "interval_mean_sec"):
        port = f":{ev['destination_port']}" if b.has("destination_port") else ""
        jitter = f" (standard deviation {_n(ev['interval_std_sec'])} s)" if b.has("interval_std_sec") else ""
        span = f" over {_n(ev['observed_span_sec'])} s" if b.has("observed_span_sec") else ""
        b.observed.append(f"{a.source_ip} connected to {a.destination_ip}{port} {_n(ev['connection_count'])} times"
                          f"{span}, on average every {_n(ev['interval_mean_sec'])} s{jitter}.")
    if b.has("destination_sources"):
        n = ev["destination_sources"]
        b.observed.append("No other monitored host talks to this destination." if n == 1 else
                          f"{_n(n)} monitored hosts talk to this destination.")
    b.threshold("Interval variation (coefficient of variation; lower is more regular)", "interval_cv",
                "cv_threshold")
    b.threshold("Periodicity", "periodicity", "periodicity_threshold")
    if ev.get("uses_tls"):
        b.caveats.append(_ENCRYPTED_CAVEAT)


def _exfil(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    if b.has("upload_bytes"):
        down = f" and received {_bytes(ev['download_bytes'])}" if b.has("download_bytes") else ""
        b.observed.append(f"{a.source_ip} sent {_bytes(ev['upload_bytes'])} to {a.destination_ip}{down}.")
    if ev.get("destination_ports"):
        unusual = " (an unusual port for bulk transfers)" if ev.get("unusual_port") else ""
        b.observed.append(f"Destination ports: {_list(ev['destination_ports'])}{unusual}.")
    if ev.get("rare_destination"):
        b.observed.append("The destination is rarely contacted by monitored hosts.")
    if ev.get("rules"):
        b.observed.append(f"Rules that matched: {_list([r.replace('_', ' ') for r in ev['rules']])}.")
    if ev.get("min_upload_mb") is not None and b.has("upload_bytes"):
        b.thresholds.append(f"Upload volume: {_bytes(ev['upload_bytes'])} observed, threshold "
                            f"{_n(ev['min_upload_mb'])} MB.")
    b.threshold("Upload/download ratio", "upload_download_ratio", "ratio_threshold")
    if ev.get("baseline_windows") and b.has("baseline_median_bytes", "robust_z"):
        b.thresholds.append(f"Compared with this host's usual upload ({_bytes(ev['baseline_median_bytes'])} "
                            f"median over {_n(ev['baseline_windows'])} windows): {_n(ev['robust_z'])} robust "
                            "deviations above it.")


def _dns_tunnel(b: _Builder) -> None:
    ev = b.ev
    if b.has("base_domain", "queries"):
        clients = f" from {_list(ev['clients'], 3)}" if ev.get("clients") else ""
        b.observed.append(f"{_n(ev['queries'])} queries under {ev['base_domain']}{clients}.")
    if b.has("avg_subdomain_length", "avg_subdomain_entropy"):
        b.observed.append(f"Subdomains averaged {_n(ev['avg_subdomain_length'])} characters with entropy "
                          f"{_n(ev['avg_subdomain_entropy'])} bits per character (random-looking).")
    if b.has("unique_subdomain_ratio"):
        b.observed.append(f"{_pct(ev['unique_subdomain_ratio'])} of the subdomains were unique.")
    if b.has("txt_or_null_ratio"):
        b.observed.append(f"{_pct(ev['txt_or_null_ratio'])} asked for TXT or NULL records, which can carry data "
                          "back.")
    if b.has("encoded_bytes"):
        b.observed.append(f"About {_bytes(ev['encoded_bytes'])} could have been carried in the names.")


def _dga(b: _Builder) -> None:
    ev = b.ev
    if b.has("generated_looking_domains", "distinct_domains"):
        b.observed.append(f"{_n(ev['generated_looking_domains'])} of {_n(ev['distinct_domains'])} distinct "
                          "domains looked generated.")
    if b.has("nxdomain_ratio"):
        b.observed.append(f"{_pct(ev['nxdomain_ratio'])} of the lookups returned 'no such domain'.")
    if ev.get("examples"):
        b.observed.append(f"Examples: {_list(ev['examples'], 4)}.")
    b.threshold("Generated-looking domains", "generated_looking_domains", "min_domains")


def _encrypted(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    port = f":{ev['destination_port']}" if b.has("destination_port") else ""
    flows = f" ({_count(ev['flows'], 'session')})" if b.has("flows") else ""
    b.observed.append(f"Encrypted traffic from {a.source_ip} to {a.destination_ip}{port}{flows}.")
    if ev.get("rules"):
        b.observed.append(f"Properties that matched: {_list([r.replace('_', ' ') for r in ev['rules']])}.")
    if ev.get("outdated_versions"):
        b.observed.append(f"Outdated protocol versions offered: {_list(ev['outdated_versions'])}.")
    if ev.get("blocklisted_ja3"):
        b.observed.append(f"Client fingerprints on the blocklist: {_list(list(ev['blocklisted_ja3']))}.")
    if ev.get("unusual_port") and b.has("destination_port"):
        b.observed.append(f"TLS on unusual port {ev['destination_port']}.")
    if b.has("max_session_sec"):
        b.observed.append(f"Longest session {_n(ev['max_session_sec'])} s"
                          + (f" at up to {_bytes(ev['max_session_bytes_per_sec'])}/s."
                             if b.has("max_session_bytes_per_sec") else "."))
    b.caveats.append(_ENCRYPTED_CAVEAT)


def _statistical(b: _Builder) -> None:
    ev = b.ev
    for metric, d in (ev.get("deviating_metrics") or {}).items():
        if isinstance(d, dict) and d.get("value") is not None:
            base = f" (usual {_n(d['baseline_median'])})" if d.get("baseline_median") is not None else ""
            z = f", {_n(d['robust_z'])} robust deviations above normal" if d.get("robust_z") is not None else ""
            b.observed.append(f"{metric.replace('_', ' ')}: {_n(d['value'])}{base}{z}.")
    b.threshold("Deviation needed per metric", None, "mad_threshold")
    if b.has("baseline_windows"):
        b.thresholds.append(f"Baseline: the previous {_n(ev['baseline_windows'])} windows.")
    for feature, d in (ev.get("most_unusual_features") or {}).items():
        if isinstance(d, dict):
            b.observed.append(f"{feature.replace('_', ' ')}: {_n(d.get('value'))} "
                              f"({_n(d.get('deviation'))} deviations from training).")
    if b.has("training_percentile"):
        b.observed.append(f"Anomaly score {_n(ev.get('anomaly_score'))}, more unusual than "
                          f"{_pct(ev['training_percentile'])} of the training windows.")
    b.caveats.append("A deviation means the window is unusual for this network, not that it is malicious; no "
                     "attack technique is implied.")


def _intel(b: _Builder) -> None:
    ev = b.ev
    if b.has("matched_field", "observed"):
        b.observed.append(f"{ev['observed']} ({ev['matched_field'].replace('_', ' ')}) is on an imported list.")
    if b.has("flows"):
        peers = f" with {_list(ev['peers'], 3)}" if ev.get("peers") else ""
        size = f", {_bytes(ev['bytes'])}" if b.has("bytes") else ""
        direction = f" ({ev['direction']})" if b.has("direction") else ""
        b.observed.append(f"{_count(ev['flows'], 'flow')}{peers}{size}{direction}.")
    b.caveats.append("A list match is only as reliable as the list it came from.")


def _brute(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    if b.has("attempts", "destination_port"):
        span = f" within {_n(ev['span_sec'])} s" if b.has("span_sec") else ""
        rate = f" ({_n(ev['attempts_per_min'])} per minute)" if b.has("attempts_per_min") else ""
        b.observed.append(f"{a.source_ip} opened {_n(ev['attempts'])} short connections to port "
                          f"{ev['destination_port']} on {a.destination_ip}{span}{rate}.")
    if b.has("failed_to_connect"):
        b.observed.append(f"{_n(ev['failed_to_connect'])} of them failed to connect.")
    if b.has("min_attempts", "horizon_sec"):
        b.thresholds.append(f"Attempts: {_n(ev.get('attempts'))} observed, threshold {_n(ev['min_attempts'])} "
                            f"within {_n(ev['horizon_sec'])} s.")
    b.caveats.append("Whether a login succeeded is not visible in traffic metadata; the rule counts short, small "
                     "connections.")


def _spam(b: _Builder) -> None:
    a, ev = b.alert, b.ev
    if b.has("smtp_destinations", "smtp_connections"):
        b.observed.append(f"{a.source_ip} made {_n(ev['smtp_connections'])} SMTP connections to "
                          f"{_n(ev['smtp_destinations'])} external mail servers.")
    if b.has("failed_to_connect"):
        b.observed.append(f"{_n(ev['failed_to_connect'])} connections failed.")
    if ev.get("examples"):
        b.observed.append(f"Examples: {_list(ev['examples'], 4)}.")
    if b.has("min_destinations", "horizon_sec"):
        b.thresholds.append(f"Mail servers: {_n(ev.get('smtp_destinations'))} observed, threshold "
                            f"{_n(ev['min_destinations'])} within {_n(ev['horizon_sec'])} s.")


def _model(b: _Builder) -> None:
    ev = b.ev
    if b.has("calibrated_probability", "threshold"):
        b.observed.append(f"The window model scored this window {_n(ev['calibrated_probability'])} "
                          f"(threshold {_n(ev['threshold'])}) and named {ev.get('predicted_class', 'this class')} "
                          "as the most likely attack.")
    if b.has("flows_in_window"):
        b.observed.append(f"{_n(ev['flows_in_window'])} flows were in the window.")
    b.caveats.append("The shipped models were trained on synthetic traffic and scored close to chance on public "
                     "datasets (ROC-AUC 0.53-0.56); treat model-only alerts as leads.")


_BY_CLASS: dict[ThreatClass, Callable[[_Builder], None]] = {
    ThreatClass.PORT_SCAN: _scan, ThreatClass.HOST_SCAN: _scan, ThreatClass.RECONNAISSANCE: _scan,
    ThreatClass.SYN_FLOOD: _flood, ThreatClass.UDP_FLOOD: _flood, ThreatClass.DDOS_VOLUMETRIC: _flood,
    ThreatClass.DDOS_PROTOCOL: _flood, ThreatClass.C2_BEACONING: _beacon, ThreatClass.DATA_EXFILTRATION: _exfil,
    ThreatClass.DNS_TUNNELLING: _dns_tunnel, ThreatClass.DGA_DETECTED: _dga,
    ThreatClass.ENCRYPTED_SESSION_ANOMALY: _encrypted, ThreatClass.STATISTICAL_ANOMALY: _statistical,
    ThreatClass.INTEL_MATCH: _intel, ThreatClass.BRUTE_FORCE: _brute, ThreatClass.SPAM_ACTIVITY: _spam,
}


def _generic(b: _Builder) -> None:
    """Unknown evidence layout: list the plain values."""
    for key, value in b.ev.items():
        if isinstance(value, (int, float, str, bool)) and key not in ("summary",):
            b.observed.append(f"{key.replace('_', ' ')}: {_n(value)}")


def _context(alert: Alert) -> list[str]:
    ev = alert.evidence or {}
    out = [f"Detector {alert.detector_name}, confidence {_n(alert.confidence)}, severity {alert.severity.value}; "
           f"traffic window {alert.window_start.isoformat()} to {alert.window_end.isoformat()}."]
    matches = ev.get("intel_matches") or []
    if matches and alert.threat_class != ThreatClass.INTEL_MATCH:
        names = _list([f"{m.get('label') or m.get('indicator')} ({m.get('source')})" for m in matches], 3)
        raised = (f"; severity raised from {ev['intel_escalated_from']}" if ev.get("intel_escalated_from") else "")
        out.append(f"Also matched imported threat intelligence: {names}{raised}.")
    elif matches:
        out.append("Listed by: " + _list([f"{m.get('source')}: {m.get('label') or m.get('indicator')}"
                                          for m in matches], 3) + ".")
    policy = ev.get("asset_policy")
    if isinstance(policy, dict):
        roles = _list([m.get("role") for m in policy.get("matches", []) if isinstance(m, dict)], 3)
        if policy.get("overridden"):
            out.append(f"The asset inventory would have applied '{policy['overridden']}' ({roles}), but kept the "
                       "alert because threat intelligence matched.")
        elif policy.get("action"):
            original = policy.get("original_severity")
            out.append(f"Asset inventory ({roles}): severity lowered to {alert.severity.value}"
                       + (f" from {original}." if original else "."))
    assets = ev.get("assets")
    if isinstance(assets, dict):
        for side, entries in assets.items():
            for e in entries if isinstance(entries, list) else []:
                out.append(f"Known asset ({side}): {e.get('address')} is {e.get('asset')} "
                           f"({_list(e.get('roles'), 3)}).")
    return out


def explain(alert: Alert) -> dict[str, Any]:
    """Plain-language explanation of one stored alert."""
    builder = _Builder(alert)
    model_alert = alert.detector_name == "ml_detector" or "calibrated_probability" in builder.ev
    (_model if model_alert else _BY_CLASS.get(alert.threat_class, _generic))(builder)
    if not builder.observed:
        _generic(builder)
    rule = RULES.get(alert.threat_class, "")
    if model_alert:
        rule = (f"A trained window model scored the window's traffic features as a likely "
                f"{CLASS_NAMES.get(alert.threat_class, alert.threat_class.value)}.")
    benign = list(BENIGN_CAUSES.get(alert.threat_class, []))
    if alert.threat_class in _ASSET_ROLE_HINT:
        benign.append(_ASSET_HINT)
    return {
        "alert_id": alert.alert_id,
        "threat_class": alert.threat_class.value,
        "headline": builder.observed[0] if builder.observed else rule,
        "rule": rule,
        "observed": builder.observed,
        "thresholds": builder.thresholds,
        "context": _context(alert),
        "benign_causes": benign,
        "caveats": builder.caveats,
        "techniques": [{"id": t, "name": TECHNIQUE_NAMES.get(t, ""), "url": technique_url(t)}
                       for t in alert.mitre_techniques],
    }
