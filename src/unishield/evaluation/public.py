"""
UniShield — Evaluation on Public Labelled Datasets

Runs the default (``rules``) pipeline over labelled public captures (CTU-13
binetflow files, CIC-IDS2017 TrafficLabelling CSVs) and measures:

    window level   attack windows (any attack-labelled flow) vs windows the
                   rule stage, or rules + statistics, flagged
    host level     which attack hosts were named in at least one alert, how
                   many alerts involve an attack host, how many other hosts
                   were named, and the traffic time from a host's first
                   attack flow to its first alert
    models         the window model trained on synthetic data, scored on the
                   real windows (cross-domain), and a random forest trained on
                   the other files and tested on each held-out file
                   (leave-one-file-out: unseen botnet / attack day)

Attack hosts: for CTU-13, the infected host (source of ``From-Botnet`` flows,
destination of ``To-Botnet`` flows); for other datasets, both ends of every
attack-labelled flow. An alert is attack-related when it names an attack
host, or has no source and names a target of attack traffic as destination
(a flood's victim).

Caveats recorded with the results: CTU-13 "Background" flows are unverified
(treated as benign here), so host-level false positives are an upper bound;
public-dataset labels contain known errors.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional, Sequence

import numpy as np

from unishield.evaluation.metrics import binary_metrics, episode_metrics, per_class_recall, ranking_metrics
from unishield.ingest.base import BaseReader
from unishield.models.dataset import BENIGN, WindowRecord, WindowRecorder, normalise_label
from unishield.models.features import MODEL_FEATURE_KEYS


class _TallyingReader(BaseReader):
    """Wraps a reader, counting labels and collecting attack hosts as records pass."""

    def __init__(self, inner: BaseReader):
        super().__init__(getattr(inner, "source_path", None))
        self.inner = inner
        self.packet_level = getattr(inner, "packet_level", False)
        self.labels: Counter = Counter()
        self.attack_hosts: set[str] = set()
        self.attack_targets: set[str] = set()
        self.first_attack: dict[str, datetime] = {}
        self.first_ts: Optional[datetime] = None
        self.last_ts: Optional[datetime] = None

    def validate_source(self) -> bool:
        return self.inner.validate_source()

    def _host(self, ip: str, ts: datetime) -> None:
        self.attack_hosts.add(ip)
        if ip not in self.first_attack or ts < self.first_attack[ip]:
            self.first_attack[ip] = ts

    def read(self) -> Iterator:
        for flow in self.inner.read():
            raw = (flow.label or "").upper()
            label = normalise_label(flow.label) or BENIGN
            self.labels[label] += 1
            ts = flow.timestamp
            self.first_ts = ts if self.first_ts is None or ts < self.first_ts else self.first_ts
            self.last_ts = ts if self.last_ts is None or ts > self.last_ts else self.last_ts
            if label != BENIGN:
                if raw.startswith("FLOW=FROM-BOTNET"):
                    self._host(flow.source_ip, ts)
                    self.attack_targets.add(flow.destination_ip)
                elif raw.startswith("FLOW=TO-BOTNET"):
                    self._host(flow.destination_ip, ts)
                    self.attack_targets.add(flow.source_ip)
                else:
                    self._host(flow.source_ip, ts)
                    self._host(flow.destination_ip, ts)
                    self.attack_targets.add(flow.destination_ip)
            yield flow

    @property
    def records_read(self) -> int:
        return self.inner.records_read

    @property
    def errors(self) -> int:
        return self.inner.errors


@dataclass
class FileRun:
    name: str
    path: str
    fmt: str
    records: int
    reader_errors: int
    labels: dict[str, int]
    traffic_hours: float
    windows: list[WindowRecord] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    attack_hosts: list[str] = field(default_factory=list)
    attack_targets: list[str] = field(default_factory=list)
    first_attack: dict[str, datetime] = field(default_factory=dict)


def run_file(path: Path | str, home_networks: Sequence[str] | None = None) -> FileRun:
    """Run the default rules pipeline over one labelled file, keeping windows and alerts."""
    from unishield.ingest.detect import open_reader
    from unishield.processing.normalization import Normalizer
    from unishield.processing.pipeline import Pipeline

    path = Path(path)
    inner, fmt = open_reader(path)
    reader = _TallyingReader(inner)
    recorder = WindowRecorder(path.name, MODEL_FEATURE_KEYS)
    alerts: list[dict[str, Any]] = []

    def keep(alert) -> None:
        alerts.append({
            "threat_class": alert.threat_class.value, "severity": alert.severity.value,
            "source_ip": alert.source_ip, "destination_ip": alert.destination_ip,
            "window_end": alert.window_end, "detector": alert.detector_name,
        })

    kwargs: dict[str, Any] = {"detection_mode": "rules", "window_observer": recorder, "alert_callback": keep}
    if home_networks:
        kwargs["normalizer"] = Normalizer(home_networks=list(home_networks))
    Pipeline(**kwargs).run(reader)
    hours = ((reader.last_ts - reader.first_ts).total_seconds() / 3600) if reader.first_ts else 0.0
    return FileRun(
        name=path.name, path=str(path), fmt=fmt, records=reader.records_read, reader_errors=reader.errors,
        labels=dict(reader.labels.most_common()), traffic_hours=round(hours, 2), windows=recorder.records,
        alerts=alerts, attack_hosts=sorted(reader.attack_hosts), attack_targets=sorted(reader.attack_targets),
        first_attack=reader.first_attack,
    )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def window_metrics(windows: Sequence[WindowRecord]) -> dict[str, Any]:
    y = np.array([int(w.is_attack) for w in windows])
    out = {"windows": len(windows), "attack_windows": int(y.sum())}
    for name, pred in (("rules", [int(bool(w.rule_classes)) for w in windows]),
                       ("rules_statistical", [int(bool(w.rule_classes or w.post_rule_classes)) for w in windows])):
        m = binary_metrics(y, pred)
        m["recall_by_class"] = per_class_recall(windows, pred)
        m.update({k: v for k, v in episode_metrics(windows, pred).items()
                  if k in ("episodes", "episodes_detected", "episode_recall", "delay_median_sec")})
        out[name] = m
    return out


def host_metrics(run: FileRun) -> dict[str, Any]:
    attack, targets = set(run.attack_hosts), set(run.attack_targets)

    def related(a) -> bool:
        return (a["source_ip"] in attack or a["destination_ip"] in attack
                or (a["source_ip"] is None and a["destination_ip"] in targets))

    involves = [a for a in run.alerts if related(a)]
    first_alert: dict[str, datetime] = {}
    named: set[str] = set()
    for a in run.alerts:
        for ip in (a["source_ip"], a["destination_ip"]):
            if ip:
                named.add(ip)
                if ip in attack and (ip not in first_alert or a["window_end"] < first_alert[ip]):
                    first_alert[ip] = a["window_end"]
    delays = [(first_alert[h] - run.first_attack[h]).total_seconds() for h in first_alert if h in run.first_attack]
    by_class: dict[str, dict[str, int]] = defaultdict(lambda: {"alerts": 0, "involving_attack_hosts": 0})
    for a in run.alerts:
        row = by_class[a["threat_class"]]
        row["alerts"] += 1
        row["involving_attack_hosts"] += int(related(a))
    return {
        "attack_hosts": len(attack),
        "attack_hosts_detected": len(attack & named),
        "alerts": len(run.alerts),
        "alerts_involving_attack_hosts": len(involves),
        "alert_precision_host_level": round(len(involves) / len(run.alerts), 4) if run.alerts else None,
        "other_hosts_named": len(named - attack - {a["destination_ip"] for a in involves}),
        "first_alert_delay_sec": sorted(round(d, 1) for d in delays),
        "alerts_by_class": dict(sorted(by_class.items())),
    }


def _scores(bundle: dict[str, Any], windows: Sequence[WindowRecord]) -> np.ndarray:
    from unishield.models.predict import WindowModel
    from unishield.models.train import matrix

    raw, prob = WindowModel(bundle).scores(matrix(windows))
    return prob if prob is not None else raw


def model_metrics(y: np.ndarray, score: np.ndarray, thresholds: Sequence[float] = (0.5, 0.9)) -> dict[str, Any]:
    out: dict[str, Any] = dict(ranking_metrics(y, score))
    for t in thresholds:
        m = binary_metrics(y, (score >= t).astype(int))
        out[f"at_{t}"] = {k: m[k] for k in ("precision", "recall", "f1", "false_positive_rate")}
    return out


def cross_domain(synthetic_csv: Path, windows: Sequence[WindowRecord], seed: int = 7) -> dict[str, Any] | None:
    """Random forest trained and calibrated on synthetic windows, scored on the real windows."""
    from unishield.models.dataset import load_windows
    from unishield.models.train import split_by_run, train_bundle

    if not synthetic_csv.is_file():
        return None
    records, keys = load_windows(synthetic_csv)
    if keys != MODEL_FEATURE_KEYS:
        return None
    train, cal = split_by_run(records, (0.75, 0.25), seed=seed)
    bundle = train_bundle("random_forest", train, cal, keys, seed=seed)
    y = np.array([int(w.is_attack) for w in windows])
    return {"trained_on": synthetic_csv.name, "train_windows": len(train), **model_metrics(y, _scores(bundle, windows))}


def leave_one_file_out(runs: Sequence[FileRun], seed: int = 7) -> dict[str, Any]:
    """For each file: random forest trained/calibrated on the other files' windows, tested on it."""
    from unishield.models.train import split_by_run, train_bundle

    out: dict[str, Any] = {}
    for held in runs:
        others = [w for r in runs if r is not held for w in r.windows]
        y_others = {int(w.is_attack) for w in others}
        if len(runs) < 3 or y_others != {0, 1}:
            continue
        train, cal = split_by_run(others, (0.67, 0.33), seed=seed)
        if not train or not cal or len({int(w.is_attack) for w in cal}) < 2:
            train, cal = others, []
        bundle = train_bundle("random_forest", train, cal, MODEL_FEATURE_KEYS, seed=seed)
        y = np.array([int(w.is_attack) for w in held.windows])
        out[held.name] = {"calibrated": bundle["calibrator"] is not None,
                          **model_metrics(y, _scores(bundle, held.windows))}
    return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _f(v: Any) -> str:
    if v is None:
        return "–"
    return f"{v:.3f}" if isinstance(v, float) else str(v)


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# UniShield — Evaluation on Public Datasets", "",
             f"Generated {report['generated_at']} by `scripts/evaluate_public_datasets.py` "
             "with the default `rules` detection mode and default thresholds (no tuning to these datasets).", ""]
    for ds in report["datasets"]:
        lines += [f"## {ds['dataset']}", "", ds.get("description", ""), "",
                  f"Home networks used for direction: {', '.join(ds['home_networks']) or 'config default'}.", "",
                  "| File | Records | Hours | Attack flows | Windows (attack) | Attack hosts detected | "
                  "Alerts (involving attack hosts) | Other hosts named | First-alert delay (s) |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for f in ds["files"]:
            h, w = f["host"], f["window"]
            attack_flows = sum(v for k, v in f["labels"].items() if k != BENIGN)
            delays = h["first_alert_delay_sec"]
            lines.append(
                f"| {f['name']} | {f['records']:,} | {f['traffic_hours']} | {attack_flows:,} | "
                f"{w['windows']:,} ({w['attack_windows']:,}) | {h['attack_hosts_detected']}/{h['attack_hosts']} | "
                f"{h['alerts']} ({h['alerts_involving_attack_hosts']}) | {h['other_hosts_named']} | "
                f"{', '.join(str(d) for d in delays[:5]) or '–'} |")
        lines += ["", "### Window level (default rules)", "",
                  "| File | Approach | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|---|"]
        for f in ds["files"]:
            for name in ("rules", "rules_statistical"):
                m = f["window"][name]
                lines.append(f"| {f['name']} | {name} | {_f(m['precision'])} | {_f(m['recall'])} | {_f(m['f1'])} | "
                             f"{_f(m['false_positive_rate'])} |")
        lines += ["", "### Alerts by class", ""]
        for f in ds["files"]:
            parts = [f"{c} {v['alerts']} ({v['involving_attack_hosts']} on attack hosts)"
                     for c, v in f["host"]["alerts_by_class"].items()]
            lines.append(f"- {f['name']}: {'; '.join(parts) or 'no alerts'}")
        if ds.get("cross_domain"):
            c = ds["cross_domain"]
            lines += ["", "### Synthetic-trained random forest on these windows (cross-domain)", "",
                      f"PR-AUC {_f(c['pr_auc'])}, ROC-AUC {_f(c['roc_auc'])}; at P ≥ 0.5: precision "
                      f"{_f(c['at_0.5']['precision'])}, recall {_f(c['at_0.5']['recall'])}; at P ≥ 0.9: precision "
                      f"{_f(c['at_0.9']['precision'])}, recall {_f(c['at_0.9']['recall'])}."]
        if ds.get("leave_one_file_out"):
            lines += ["", "### Random forest trained on the other files, tested on each (unseen attack)", "",
                      "| Held-out file | PR-AUC | ROC-AUC | Precision@0.5 | Recall@0.5 | FPR@0.5 | Recall@0.9 |",
                      "|---|---|---|---|---|---|---|"]
            for name, m in ds["leave_one_file_out"].items():
                lines.append(f"| {name} | {_f(m['pr_auc'])} | {_f(m['roc_auc'])} | {_f(m['at_0.5']['precision'])} | "
                             f"{_f(m['at_0.5']['recall'])} | {_f(m['at_0.5']['false_positive_rate'])} | "
                             f"{_f(m['at_0.9']['recall'])} |")
        lines += ["", "### Caveats", ""] + [f"- {c}" for c in ds.get("caveats", [])] + [""]
    return "\n".join(lines) + "\n"
