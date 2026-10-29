"""
UniShield — Learning Mode

Runs the pipeline over a site's own traffic (days of Zeek logs, flow files
or a replay) without reporting anything, records the distribution of the
value each rule compares with its threshold, and suggests site thresholds.

What is recorded, per window, for each learned threshold: the largest value
any host (or pair, or domain) reached on the rule's metric while meeting
the rule's other conditions — 0 when none did — so the percentile of these
values says how close benign traffic came to raising that alert. Beacon
regularity is recorded per pair (its lowest interval CV), the statistical
and Isolation Forest scores per window they were computed.

Hosts whose alerts an asset role already handles (``configs/assets.yaml``,
e.g. a listed vulnerability scanner or backup server) are left out: the
inventory, not a threshold, should explain them.

Suggestion, per threshold:
    upper thresholds (alert when the value reaches it):
        observed = percentile (default p99.9) of the recorded values
        candidate = observed x margin (default 1.5)
        suggested = candidate if it exceeds the current value, else the
        current value. Thresholds are only loosened unless
        ``allow_tighten`` is set (then never below the metric's floor).
    beacon regularity (alert when the CV is at or below it):
        observed = the lowest CV of any beacon-like pair (p0.1 of pairs)
        suggested = observed x 0.8 when that pair would have alerted, never
        below a floor of 0.05; pairs still below the floor are listed so
        they can go into the asset inventory instead.

Every suggestion keeps the percentile, the observed value, the margin, the
current/default value, the number of samples and how many of them would
still reach the suggested value. Nothing is written to thresholds.yaml: the
output is an overlay (``thresholds.site.yaml``) the operator reviews and
selects with ``site.thresholds_file``.

Learning assumes the period contained no attack. An attack in the learning
data raises the thresholds that would have caught it; the report lists the
hosts behind every raised value so this can be checked.

SECURITY CONSTRAINTS:
    - Read-only analysis of local records. No network communication.
"""

from __future__ import annotations

import math
import random
from array import array
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Iterable, Optional

import numpy as np
import yaml

from unishield.assets import AssetInventory
from unishield.config import merge_thresholds
from unishield.schemas.alert import Alert, ThreatClass

_C = ThreatClass
_MAX_SAMPLES = 2_000_000          # per threshold; reservoir sampling beyond this
_MAX_ENTITIES = 2_000             # contributors tracked per threshold
_MAX_PAIRS = 50_000               # beacon-like pairs tracked


@dataclass(frozen=True)
class LearnedThreshold:
    key: str                       # "section.name" in thresholds.yaml
    measures: str                  # what one sample is
    direction: str = "upper"       # upper: alert at or above; lower: alert at or below
    margin: float = 1.5
    floor: Optional[float] = None  # never suggest less than this
    cap: Optional[float] = None    # never suggest more than this
    integer: bool = False
    scale: float = 1.0             # sample / scale = threshold unit (bytes -> MB)
    unit: str = ""


LEARNED: tuple[LearnedThreshold, ...] = (
    LearnedThreshold("ddos.packets_per_second", "peak packets/s to the busiest destination", integer=True),
    LearnedThreshold("ddos.bytes_per_second", "peak bytes/s to the busiest destination", integer=True),
    LearnedThreshold("ddos.syn_rate_threshold", "peak half-open attempts/s to the busiest half-open target "
                     "(windows where its half-open share reached syn_only_ratio)", integer=True),
    LearnedThreshold("ddos.udp_flood_pps", "peak UDP packets/s to the busiest UDP target "
                     "(windows where UDP reached udp_ratio of its packets)", integer=True),
    LearnedThreshold("scanning.unique_dest_ports", "most ports one source tried on one host, or on any hosts "
                     "while mostly failing", integer=True, floor=10),
    LearnedThreshold("scanning.horizontal_scan_hosts", "most hosts one source tried on one port while mostly "
                     "failing", integer=True, floor=10),
    LearnedThreshold("scanning.horizontal_scan_hosts_any", "most hosts one source contacted on one port",
                     integer=True, floor=20),
    LearnedThreshold("scanning.burst_connections", "largest burst of mostly failing attempts by one source",
                     integer=True, floor=10),
    LearnedThreshold("exfiltration.min_upload_mb", "largest upload-dominated upload from one internal host to "
                     "one external destination", scale=1e6, floor=1.0, unit="MB"),
    LearnedThreshold("exfiltration.baseline_deviation_sigma", "largest robust z of a source's window upload "
                     "against its own baseline (eligible uploads)", floor=2.5),
    LearnedThreshold("dns.dga_min_domains", "most generated-looking domains from one client meeting the "
                     "NXDOMAIN / share condition", integer=True, floor=5),
    LearnedThreshold("dns.tunnel_min_queries", "most queries to one base domain with mostly unique long or "
                     "high-entropy subdomains", integer=True, floor=10),
    LearnedThreshold("beaconing.regularity_cv_threshold", "lowest interval CV of a pair meeting every other "
                     "beacon condition (one sample per pair)", direction="lower", margin=0.8, floor=0.05),
    LearnedThreshold("statistical.mad_threshold", "robust z a window needed on min_deviating_metrics "
                     "metrics at once (windows the detector scored)", margin=1.25, floor=2.5),
    LearnedThreshold("anomaly.min_score", "Isolation Forest anomaly score (windows the model scored)",
                     margin=1.05, cap=0.95),
)

NOT_LEARNED_REASON = {
    "ratio": "a share or ratio describing the attack's shape, not traffic volume",
    "time": "a time constant (history, re-alert, burst or session length)",
    "severity": "severity bands; they follow the alert thresholds",
    "other": "set by judgement (see docs/deployment.md)",
}


def _leaves(d: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in d.items():
        key = f"{prefix}.{k}" if prefix else str(k)
        if isinstance(v, dict) and v:
            out.update(_leaves(v, key))
        else:
            out[key] = v
    return out


def _get(d: dict[str, Any], key: str) -> Any:
    node: Any = d
    for part in key.split("."):
        node = node[part]
    return node


def _not_learned_reason(key: str) -> str:
    name = key.rsplit(".", 1)[-1]
    if ".severity_levels." in key:
        return NOT_LEARNED_REASON["severity"]
    if "ratio" in name or "share" in name or "uniqueness" in name or "frequency" in name \
            or name in ("periodicity_score", "min_deviating_metrics", "quantile"):
        return NOT_LEARNED_REASON["ratio"]
    if name.endswith("_sec") or name in ("burst_window_sec", "history_sec"):
        return NOT_LEARNED_REASON["time"]
    return NOT_LEARNED_REASON["other"]


@dataclass
class _Series:
    values: array = field(default_factory=lambda: array("d"))
    seen: int = 0
    contributors: dict[str, float] = field(default_factory=dict)

    def add(self, value: float, entity: Optional[str], rng: random.Random) -> None:
        self.seen += 1
        if len(self.values) < _MAX_SAMPLES:
            self.values.append(value)
        else:
            j = rng.randrange(self.seen)
            if j < _MAX_SAMPLES:
                self.values[j] = value
        if entity and value > 0:
            if value > self.contributors.get(entity, -math.inf):
                self.contributors[entity] = value
            if len(self.contributors) > 2 * _MAX_ENTITIES:
                top = sorted(self.contributors.items(), key=lambda kv: kv[1], reverse=True)[:_MAX_ENTITIES]
                self.contributors = dict(top)


@dataclass
class Suggestion:
    key: str
    measures: str
    direction: str
    percentile: float
    margin: float
    default: Any
    current: Any
    observed: Optional[float]
    suggested: Any
    samples: int
    still_reaching: int
    changed: bool
    reason: str
    unit: str = ""
    top: list[tuple[str, float]] = field(default_factory=list)

    def provenance(self) -> dict[str, Any]:
        return {"percentile": self.percentile, "observed": _plain(self.observed), "margin": self.margin,
                "default": self.default, "current": self.current, "suggested": self.suggested,
                "samples": self.samples, "samples_reaching_suggestion": self.still_reaching,
                "changed": self.changed}


def _plain(x: Any) -> Any:
    if isinstance(x, float):
        return float(f"{x:.6g}")
    return x


class BaselineLearner:
    """
    Pipeline hooks that record the metrics behind each threshold.

    Use ``observe`` as the pipeline's ``window_observer`` and ``count_alert``
    as its ``alert_callback`` (alerts are counted, never stored), and call
    ``attach(pipeline)`` so the statistical and anomaly scores can be read.
    """

    def __init__(self, thresholds: dict[str, Any], assets: Optional[AssetInventory] = None, seed: int = 1):
        self.thresholds = thresholds
        self.assets = assets if assets is not None else AssetInventory()
        self.series: dict[str, _Series] = {spec.key: _Series() for spec in LEARNED}
        self.beacon_pairs: dict[tuple, dict[str, Any]] = {}
        self.windows = 0
        self.first_event: Optional[datetime] = None
        self.last_event: Optional[datetime] = None
        self.would_alert: Counter[str] = Counter()
        self.info_alerts: Counter[str] = Counter()
        self.excluded: Counter[str] = Counter()
        self._rng = random.Random(seed)
        self._statistical = None
        self._anomaly = None

    # ------------------------------------------------------------ hooks

    def attach(self, pipeline) -> None:
        for d in pipeline.detectors:
            if d.name == "statistical_detector":
                self._statistical = d
            elif d.name == "anomaly_detector":
                self._anomaly = d

    def count_alert(self, alert: Alert) -> None:
        target = self.info_alerts if alert.severity.value == "INFO" else self.would_alert
        target[alert.threat_class.value] += 1

    def _record(self, key: str, value: float, entity: Optional[str] = None) -> None:
        self.series[key].add(float(value), entity, self._rng)

    def _expected_source(self, ip: Optional[str], *classes: ThreatClass) -> bool:
        return any(self.assets.expected_source(ip, c) for c in classes)

    def observe(self, window, features: dict[str, Any], alerts: list[Alert], rule_classes: set[str]) -> None:
        t = self.thresholds
        self.windows += 1
        self.first_event = self.first_event or window.start
        self.last_event = window.end
        f = features

        # --- DDoS: busiest targets
        ddos = t["ddos"]
        target = f.get("vol_target_ip")
        expected = target and self.assets.expected_destination(target, _C.DDOS_VOLUMETRIC)
        self._record("ddos.packets_per_second", 0 if expected else f.get("vol_target_pps_peak") or 0, target)
        self._record("ddos.bytes_per_second", 0 if expected else f.get("vol_target_bps_peak") or 0, target)
        syn_target = f.get("syn_target_ip")
        syn_ok = syn_target and (f.get("syn_target_syn_only_ratio") or 0) >= ddos["syn_only_ratio"] \
            and not self.assets.expected_destination(syn_target, _C.SYN_FLOOD)
        self._record("ddos.syn_rate_threshold", f.get("syn_target_rate_peak") or 0 if syn_ok else 0, syn_target)
        udp_target = f.get("udp_target_ip")
        udp_ok = udp_target and (f.get("udp_target_udp_ratio") or 0) >= ddos["udp_ratio"] \
            and not self.assets.expected_destination(udp_target, _C.UDP_FLOOD)
        self._record("ddos.udp_flood_pps", f.get("udp_target_pps_peak") or 0 if udp_ok else 0, udp_target)

        # --- Scanning: per source
        scan = t["scanning"]
        best = {"scanning.unique_dest_ports": (0, None), "scanning.horizontal_scan_hosts": (0, None),
                "scanning.horizontal_scan_hosts_any": (0, None), "scanning.burst_connections": (0, None)}
        for c in f.get("scan_candidates") or []:
            src = c["source_ip"]
            if self._expected_source(src, _C.PORT_SCAN, _C.HOST_SCAN, _C.RECONNAISSANCE):
                self.excluded["scanning (asset role)"] += 1
                continue
            failing = c["failed_ratio"] >= scan["failed_connection_ratio"]
            values = {
                "scanning.unique_dest_ports": max(c["vertical_ports"], c["unique_ports"] if failing else 0),
                "scanning.horizontal_scan_hosts": c["horizontal_hosts"] if failing else 0,
                "scanning.horizontal_scan_hosts_any": c["horizontal_hosts"],
                "scanning.burst_connections": c["burst"] if failing else 0,
            }
            for key, v in values.items():
                if v > best[key][0]:
                    best[key] = (v, src)
        for key, (v, src) in best.items():
            self._record(key, v, src)

        # --- Exfiltration: per internal source -> external destination
        ex = t["exfiltration"]
        upload, z = (0.0, None), (0.0, None)
        for c in f.get("exfil_candidates") or []:
            if c["upload_download_ratio"] < ex["upload_download_ratio"]:
                continue
            if c.get("expected_destination") or self.assets.decide(
                    _C.DATA_EXFILTRATION, [c["source_ip"]], c["destination_ip"])[0] != "alert":
                self.excluded["exfiltration (asset role)"] += 1
                continue
            pair = f"{c['source_ip']} -> {c['destination_ip']}"
            if c["upload_bytes"] > upload[0]:
                upload = (c["upload_bytes"], pair)
            if (c["robust_z"] is not None and c["baseline_windows"] >= ex["min_baseline_windows"]
                    and c["source_window_upload"] >= ex["baseline_min_upload_mb"] * 1e6 and c["robust_z"] > z[0]):
                z = (c["robust_z"], c["source_ip"])
        self._record("exfiltration.min_upload_mb", *upload)
        self._record("exfiltration.baseline_deviation_sigma", *z)

        # --- DNS: DGA per client, tunnelling per base domain
        dns = t["dns"]
        dga = (0, None)
        for c in f.get("dga_candidates") or []:
            if self._expected_source(c["source_ip"], _C.DGA_DETECTED):
                self.excluded["DGA (asset role)"] += 1
                continue
            nx = c["nxdomain_ratio"]
            meets = nx >= dns["nxdomain_ratio"] if nx is not None else c["generated_share"] >= dns["dga_generated_share"]
            if meets and c["generated_looking_domains"] > dga[0]:
                dga = (c["generated_looking_domains"], c["source_ip"])
        self._record("dns.dga_min_domains", *dga)
        tunnel = (0, None)
        for c in f.get("tunnel_candidates") or []:
            encoded = (c["avg_subdomain_length"] >= dns["query_length_threshold"]
                       or c["avg_subdomain_entropy"] >= dns["domain_entropy_threshold"])
            if not (encoded and c["unique_subdomain_ratio"] >= dns["subdomain_uniqueness"]):
                continue
            clients = c["clients"]
            if clients and c.get("client_count", len(clients)) == len(clients) \
                    and all(self._expected_source(ip, _C.DNS_TUNNELLING) for ip in clients):
                self.excluded["DNS tunnelling (asset role)"] += 1
                continue
            if c["queries"] > tunnel[0]:
                tunnel = (c["queries"], c["base_domain"])
        self._record("dns.tunnel_min_queries", *tunnel)

        # --- Beaconing: pairs meeting every condition except regularity
        b = t["beaconing"]
        for c in f.get("beacon_candidates") or []:
            if not (c["connection_count"] >= b["min_connections"]
                    and b["min_interval_sec"] <= c["interval_mean_sec"] <= b["max_interval_sec"]
                    and c["periodicity"] >= b["periodicity_score"]
                    and c["destination_sources"] <= b["max_destination_sources"]):
                continue
            key = (c["source_ip"], c["destination_ip"], c["destination_port"])
            if self.assets.decide(_C.C2_BEACONING, [c["source_ip"]], c["destination_ip"])[0] != "alert":
                self.excluded["beaconing (asset role)"] += 1
                continue
            known = self.beacon_pairs.get(key)
            if known is None and len(self.beacon_pairs) >= _MAX_PAIRS:
                continue
            if known is None or c["interval_cv"] < known["cv"]:
                self.beacon_pairs[key] = {"cv": c["interval_cv"], "interval_sec": round(c["interval_mean_sec"], 1),
                                          "connections": c["connection_count"]}

        # --- Statistical and Isolation Forest scores
        stat = self._statistical
        if stat is not None and stat.last_scores:
            k = int(t["statistical"]["min_deviating_metrics"])
            ranked = sorted(stat.last_scores.values(), reverse=True)
            if len(ranked) >= k:
                self._record("statistical.mad_threshold", max(ranked[k - 1], 0.0))
        if self._anomaly is not None and self._anomaly.last_score is not None:
            self._record("anomaly.min_score", self._anomaly.last_score)

    # ------------------------------------------------------------ results

    def suggest(self, defaults: dict[str, Any], *, percentile: float = 99.9, margin: Optional[float] = None,
                allow_tighten: bool = False) -> list[Suggestion]:
        out = []
        for spec in LEARNED:
            m = spec.margin if margin is None or spec.direction == "lower" or spec.key.startswith(
                ("statistical.", "anomaly.")) else margin
            default, current = _get(defaults, spec.key), _get(self.thresholds, spec.key)
            if spec.direction == "lower":
                samples = [p["cv"] for p in self.beacon_pairs.values()]
                pct = round(100.0 - percentile, 6)
                top = sorted(((f"{s} -> {d}:{port}", p["cv"]) for (s, d, port), p in self.beacon_pairs.items()),
                             key=lambda kv: kv[1])[:10]
            else:
                series = self.series[spec.key]
                samples = list(series.values)
                pct = percentile
                top = sorted(series.contributors.items(), key=lambda kv: kv[1], reverse=True)[:5]
                top = [(e, v / spec.scale) for e, v in top]
            suggestion = self._suggest_one(spec, samples, pct, m, default, current, allow_tighten, top)
            if spec.key.startswith(("statistical.", "anomaly.")) and self.windows                     and len(samples) < 0.05 * self.windows:
                suggestion.reason += (f"; scored in only {len(samples):,} of {self.windows:,} windows (windows a "
                                      "rule explained, including regular pollers, are not scored)")
            out.append(suggestion)
        return out

    @staticmethod
    def _suggest_one(spec: LearnedThreshold, samples: list[float], pct: float, margin: float, default: Any,
                     current: Any, allow_tighten: bool, top: list) -> Suggestion:
        if not samples:
            return Suggestion(spec.key, spec.measures, spec.direction, pct, margin, default, current, None, current,
                              0, 0, current != default, "no samples: nothing in the learning data exercised this rule",
                              spec.unit, top)
        values = np.asarray(samples, dtype=float) / spec.scale
        method = "higher" if spec.direction == "upper" else "lower"
        observed = float(np.percentile(values, pct, method=method))
        candidate = observed * margin
        if spec.direction == "upper":
            if candidate > current:
                suggested, reason = candidate, "benign traffic came within the margin of the current value"
            elif allow_tighten:
                suggested, reason = candidate, "tightened to the observed value x margin (--allow-tighten)"
            else:
                suggested, reason = current, "headroom: benign traffic stayed below it"
            if spec.floor is not None:
                suggested = max(suggested, spec.floor)
            if spec.cap is not None:
                suggested = min(suggested, spec.cap)
            suggested = math.ceil(suggested) if spec.integer else _round_up(suggested)
            still = int(np.count_nonzero(values >= suggested))
        else:
            if observed <= current:
                suggested, reason = candidate, "a benign pair would have alerted: lowered below it"
            elif allow_tighten:
                suggested, reason = candidate, "tightened towards the most regular benign pair (--allow-tighten)"
            else:
                suggested, reason = current, "headroom: no benign pair was this regular"
            if spec.floor is not None and suggested < spec.floor:
                suggested, reason = spec.floor, reason + f"; held at the floor {spec.floor}"
            suggested = round(suggested, 3)
            still = int(np.count_nonzero(values <= suggested))
        if isinstance(current, int) and not isinstance(current, bool) and float(suggested).is_integer():
            suggested = int(suggested)
        return Suggestion(spec.key, spec.measures, spec.direction, pct, margin, default, current, observed,
                          suggested, len(samples), still, suggested != default, reason, spec.unit, top)


def _round_up(x: float) -> float:
    """Round up to three significant figures."""
    if x <= 0:
        return 0.0
    digits = 3 - int(math.floor(math.log10(x))) - 1
    factor = 10 ** digits
    return math.ceil(x * factor) / factor if digits > 0 else float(math.ceil(x / 10 ** -digits) * 10 ** -digits)


# ---------------------------------------------------------------- output

def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.6f}".rstrip("0")
        return text + "0" if text.endswith(".") else text
    return yaml.safe_dump(value, default_flow_style=True, width=1_000).strip().removesuffix("\n...").strip()


def render_site_thresholds(suggestions: list[Suggestion], defaults: dict[str, Any], current: dict[str, Any],
                           meta: dict[str, Any]) -> str:
    """
    The suggested overlay as commented YAML. Changed values are active;
    unchanged ones appear as comments; values the current thresholds already
    override (another site file) and learning did not cover are carried over.
    """
    by_key = {s.key: s for s in suggestions}
    learned = set(by_key)
    default_leaves, current_leaves = _leaves(defaults), _leaves(current)
    carried = {k: v for k, v in current_leaves.items() if k not in learned and default_leaves.get(k) != v}

    lines = [
        "# ============================================================",
        "# UniShield — Site thresholds suggested by learning mode",
        "# ============================================================",
        f"# Generated {meta['generated_at']} by scripts/learn_baseline.py from {meta['records']:,} records",
        f"# ({meta['windows']:,} windows, traffic {meta['first_event']} to {meta['last_event']}).",
        f"# Inputs: {', '.join(meta['inputs'])}",
        "#",
        "# REVIEW BEFORE USE. This file overlays configs/thresholds.yaml key by key;",
        "# select it with site.thresholds_file in config.yaml or UNISHIELD_THRESHOLDS_FILE.",
        "# Learning assumes the learning period contained no attack: any attack in it",
        "# raises the thresholds that would have caught it. See the learning report.",
        f"# Method: p{meta['percentile']:g} of the recorded values x margin; thresholds are only",
        "# loosened unless --allow-tighten. Unchanged values are commented out.",
        "",
    ]
    for section in defaults:
        rows: list[str] = []
        active = False
        for key in [k for k in default_leaves if k.split(".", 1)[0] == section]:
            name = key.split(".", 1)[1]
            if key in by_key:
                s = by_key[key]
                obs = "n/a" if s.observed is None else f"{s.observed:.6g}{(' ' + s.unit) if s.unit else ''}"
                note = (f"p{s.percentile:g} of {s.samples:,} = {obs}, x{s.margin:g}; default "
                        f"{_yaml_scalar(s.default)}")
                if s.changed:
                    rows.append(f"  {name}: {_yaml_scalar(s.suggested)}    # {note}")
                    active = True
                else:
                    rows.append(f"  # {name}: {_yaml_scalar(s.suggested)}    # unchanged: {note}")
            elif key in carried:
                if "." in name:
                    continue                                    # nested keys are emitted below
                rows.append(f"  {name}: {_yaml_scalar(carried[key])}    # carried over from the active site file")
                active = True
        nested = {k.split(".", 1)[1]: v for k, v in carried.items() if k.split(".", 1)[0] == section
                  and "." in k.split(".", 1)[1]}
        if nested:
            tree: dict[str, Any] = {}
            for path, v in nested.items():
                node = tree
                parts = path.split(".")
                for part in parts[:-1]:
                    node = node.setdefault(part, {})
                node[parts[-1]] = v
            dumped = yaml.safe_dump(tree, default_flow_style=False, sort_keys=False).rstrip().splitlines()
            rows += [f"  {line}" for line in dumped]
            rows[-len(dumped)] += "    # carried over from the active site file"
            active = True
        if not rows:
            continue
        lines.append(f"{section}:" if active else f"# {section}:    (no changes)")
        lines += rows
        lines.append("")

    provenance = {"_learned": {
        "generated_at": meta["generated_at"], "inputs": meta["inputs"], "records": meta["records"],
        "windows": meta["windows"], "first_event": meta["first_event"], "last_event": meta["last_event"],
        "percentile": meta["percentile"], "allow_tighten": meta["allow_tighten"],
        "values": {s.key: s.provenance() for s in suggestions},
    }}
    lines.append("# Provenance of every learned value (ignored when the file is loaded).")
    lines.append(yaml.safe_dump(provenance, default_flow_style=False, sort_keys=False).rstrip())
    text = "\n".join(lines) + "\n"
    merge_thresholds(defaults, yaml.safe_load(text) or {}, source="generated site thresholds")   # must load
    return text


def _fmt(value: Any, unit: str = "") -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        value = f"{value:,.6g}" if abs(value) < 1e6 else f"{value:,.0f}"
    elif isinstance(value, int):
        value = f"{value:,}"
    return f"{value} {unit}".strip()


def render_report(learner: BaselineLearner, suggestions: list[Suggestion], meta: dict[str, Any]) -> str:
    changed = [s for s in suggestions if s.changed]
    lines = [
        "# UniShield — Learning Report", "",
        f"Generated {meta['generated_at']} by `scripts/learn_baseline.py`.", "",
        "## Learning data", "",
        "| | |", "|---|---|",
        f"| Inputs | {', '.join(f'`{i}`' for i in meta['inputs'])} |",
        f"| Records / windows | {meta['records']:,} / {meta['windows']:,} |",
        f"| Traffic period | {meta['first_event']} to {meta['last_event']} |",
        f"| Asset inventory | {meta['assets']} entries |",
        f"| Thresholds in use | {', '.join(f'`{p}`' for p in meta['threshold_sources']) or 'built-in defaults'} |",
        "",
        "## How the suggestions were made", "",
        f"For every window the learner recorded, per threshold, the largest value any host reached on the "
        f"rule's metric while meeting the rule's other conditions (0 when none did). The suggestion is the "
        f"p{meta['percentile']:g} of those values times a margin "
        f"({'only loosening' if not meta['allow_tighten'] else 'loosening or tightening'} the current value). "
        "Beacon regularity uses the most regular beacon-like pair instead. Hosts whose alerts an asset role "
        "handles were left out. **Learning assumes the period contained no attack.**", "",
        f"{len(changed)} of {len(suggestions)} learned thresholds differ from `thresholds.yaml`.", "",
        "| Threshold | Measures | Default | Observed (percentile, samples) | Suggested | Samples reaching it | Note |",
        "|---|---|---|---|---|---|---|",
    ]
    for s in suggestions:
        observed = "-" if s.observed is None else f"{_fmt(s.observed, s.unit)} (p{s.percentile:g}, {s.samples:,})"
        mark = "**" if s.changed else ""
        lines.append(f"| `{s.key}` | {s.measures} | {_fmt(s.default)} | {observed} | {mark}{_fmt(s.suggested)}{mark} "
                     f"| {s.still_reaching:,} | {s.reason} |")

    raised = [s for s in suggestions if s.changed and s.top and s.direction == "upper"]
    if raised:
        lines += ["", "## Who drove the raised values", "",
                  "If one of these is a scanner, backup target, resolver, update server or monitoring host, "
                  "list it in `configs/assets.yaml` and learn again instead of raising the threshold; "
                  "if it should not do this at all, investigate it.", ""]
        for s in raised:
            lines.append(f"- `{s.key}`: " + ", ".join(f"{e} ({_fmt(v, s.unit)})" for e, v in s.top))
    pairs = sorted(learner.beacon_pairs.items(), key=lambda kv: kv[1]["cv"])[:10]
    if pairs:
        lines += ["", "## Beacon-like pairs", "",
                  "Pairs that met every beacon condition except, possibly, regularity (lowest CV first). Regular "
                  "pollers (update checks, monitoring, backups) belong in the asset inventory.", "",
                  "| Source | Destination:port | Mean interval s | Connections | Lowest CV |", "|---|---|---|---|---|"]
        for (src, dst, port), p in pairs:
            lines.append(f"| {src} | {dst}:{port} | {p['interval_sec']} | {p['connections']} | {p['cv']:.4f} |")
    lines += ["", "## Alerts during learning", "",
              "Alerts the current thresholds would have raised over the learning data (nothing was stored or "
              "sent):", ""]
    if learner.would_alert:
        lines += [f"- {k}: {v:,}" for k, v in sorted(learner.would_alert.items())]
    else:
        lines.append("- none above INFO")
    if learner.info_alerts:
        lines.append("- reported as INFO by asset policies: "
                     + ", ".join(f"{k} {v:,}" for k, v in sorted(learner.info_alerts.items())))
    if learner.excluded:
        lines.append("- candidates left out of learning because an asset role handles them: "
                     + ", ".join(f"{k} {v:,}" for k, v in sorted(learner.excluded.items())))
    lines += ["", "## Not learned", "",
              "These thresholds keep their configured values; review them by hand (docs/deployment.md):", ""]
    learned = {s.key for s in suggestions}
    for key, reason in sorted((k, _not_learned_reason(k)) for k in _leaves(learner.thresholds)
                              if k not in learned and ".severity_levels." not in k):
        lines.append(f"- `{key}`: {reason}")
    lines += ["", "## Caveats", "",
              "- An attack inside the learning period raises the thresholds that would have caught it. Check the "
              "hosts listed above.",
              "- Percentiles come from this period only; seasonal peaks (month-end jobs, patch days) that did not "
              "occur in it are not covered.",
              "- Suggestions never touch `configs/thresholds.yaml`; the overlay takes effect only when selected.",
              ]
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- runner

@dataclass
class LearningRun:
    learner: BaselineLearner
    records: int
    inputs: list[str]
    threshold_sources: list[str]
    assets: int

    def meta(self, generated_at: str, percentile: float, allow_tighten: bool) -> dict[str, Any]:
        lr = self.learner
        return {
            "generated_at": generated_at, "inputs": self.inputs, "records": self.records, "windows": lr.windows,
            "first_event": lr.first_event.isoformat() if lr.first_event else None,
            "last_event": lr.last_event.isoformat() if lr.last_event else None,
            "percentile": percentile, "allow_tighten": allow_tighten, "assets": self.assets,
            "threshold_sources": self.threshold_sources,
        }


def learn(inputs: Iterable[tuple[str, Any]], *, thresholds: dict[str, Any], threshold_sources: list[str],
          assets: Optional[AssetInventory] = None, state_store=None,
          progress: Optional[Callable[[str, Any], None]] = None, normalizer=None) -> LearningRun:
    """
    Run one pipeline over ``inputs`` ((name, reader) pairs, in order, so state
    carries over between files) with learning hooks and no alert storage.
    ``normalizer`` overrides the configured one (e.g. other home networks).
    """
    from unishield.processing.pipeline import Pipeline

    assets = assets if assets is not None else AssetInventory.from_config()
    learner = BaselineLearner(thresholds, assets)
    pipeline = Pipeline(window_observer=learner.observe, alert_callback=learner.count_alert, assets=assets,
                        state_store=state_store, normalizer=normalizer)
    learner.attach(pipeline)
    records, names = 0, []
    for name, reader in inputs:
        result = pipeline.run(reader)
        records += result.total_records
        names.append(name)
        if progress:
            progress(name, result)
    return LearningRun(learner, records, names, threshold_sources, len(assets))
