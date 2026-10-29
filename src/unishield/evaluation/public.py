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


def time_sorted_copy(path: Path, directory: Path) -> Path:
    """
    Copy of a flow CSV with its rows in timestamp order (stable, so rows of one
    minute keep their file order). Some CIC-IDS2017 files are not written in
    time order; event-time windows would drop the out-of-order rows as late.
    Timestamps are parsed the way the flow reader parses them (dataset profile
    and its fix-ups); unparseable rows go last, where the reader counts them.
    """
    import csv

    from unishield.ingest.detect import open_reader
    from unishield.ingest.flow_reader import _clean_key, _parse_flow_timestamp

    reader, _ = open_reader(path)
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        rows = csv.reader(f)
        header = next(rows)
        cleaned = [_clean_key(h) for h in header]
        reader._select_profile(set(cleaned))
        mapping = reader.field_map
        ts_col = next((i for i, k in enumerate(cleaned) if mapping.get(k) == "timestamp"), None)
        profile = reader.profile
        keyed = []
        for idx, row in enumerate(rows):
            key = None
            if ts_col is not None and ts_col < len(row):
                data = {"timestamp": row[ts_col]}
                try:
                    if profile and profile.row_hook:
                        data = profile.row_hook(data)
                    if profile:
                        key = _parse_flow_timestamp(data["timestamp"], profile.timestamp_formats)
                    else:
                        key = _parse_flow_timestamp(data["timestamp"])
                except (ValueError, KeyError, TypeError):
                    key = None
            keyed.append((key is None, key.timestamp() if key else 0.0, idx, row))
    keyed.sort(key=lambda k: (k[0], k[1], k[2]))
    out = directory / path.name
    with open(out, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(k[3] for k in keyed)
    return out


class _MinuteSpreader(BaseReader):
    """
    For files whose timestamps have minute resolution (seven of the eight
    CIC-IDS2017 TrafficLabelling files): spreads each minute's flows evenly
    over that minute in file order, so a minute's ~1,000 flows are not
    analysed as one burst at :00. Files with second resolution pass through
    unchanged. Two passes over the file; nothing else is altered.
    """

    def __init__(self, path: Path):
        from unishield.ingest.detect import open_reader

        self._open = lambda: open_reader(path)[0]
        first = self._open()
        super().__init__(path)
        self.packet_level = False
        self._last = first
        self.spread = False

    def validate_source(self) -> bool:
        return True

    def read(self) -> Iterator:
        from datetime import timedelta
        from itertools import islice

        sample = list(islice(self._open().read(), 2000))
        self.spread = bool(sample) and all(f.timestamp.second == 0 and f.timestamp.microsecond == 0 for f in sample)
        if not self.spread:
            self._last = self._open()
            yield from self._last.read()
            return
        counts: Counter = Counter(f.timestamp for f in self._open().read())
        seen: Counter = Counter()
        self._last = self._open()
        for flow in self._last.read():
            k = flow.timestamp
            offset = 60.0 * seen[k] / counts[k] if counts[k] else 0.0
            seen[k] += 1
            yield flow.model_copy(update={"timestamp": k + timedelta(seconds=offset)})

    @property
    def records_read(self) -> int:
        return self._last.records_read

    @property
    def errors(self) -> int:
        return self._last.errors


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
    late_dropped: int = 0


def run_file(path: Path | str, home_networks: Sequence[str] | None = None, spread_minutes: bool = False,
             sort_by_time: bool = False) -> FileRun:
    """
    Run the default rules pipeline over one labelled file, keeping windows and
    alerts. ``sort_by_time`` analyses a time-sorted copy (``time_sorted_copy``);
    ``spread_minutes`` spreads minute-resolution timestamps (``_MinuteSpreader``).
    """
    import tempfile

    if sort_by_time:
        with tempfile.TemporaryDirectory() as tmp:
            run = run_file(time_sorted_copy(Path(path), Path(tmp)), home_networks, spread_minutes)
        run.path = str(path)
        return run
    from unishield.ingest.detect import open_reader
    from unishield.processing.normalization import Normalizer
    from unishield.processing.pipeline import Pipeline

    path = Path(path)
    inner, fmt = open_reader(path)
    if spread_minutes:
        inner = _MinuteSpreader(path)
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
    result = Pipeline(**kwargs).run(reader)
    late = (result.ingest.get("windowing") or {}).get("late_dropped", 0)
    hours = ((reader.last_ts - reader.first_ts).total_seconds() / 3600) if reader.first_ts else 0.0
    return FileRun(
        name=path.name, path=str(path), fmt=fmt, records=reader.records_read, reader_errors=reader.errors,
        labels=dict(reader.labels.most_common()), traffic_hours=round(hours, 2), windows=recorder.records,
        alerts=alerts, attack_hosts=sorted(reader.attack_hosts), attack_targets=sorted(reader.attack_targets),
        first_attack=reader.first_attack, late_dropped=late,
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
                started = run.first_attack.get(ip)
                # an alert counts for an attack host only once its attack traffic has begun
                if ip in attack and started is not None and a["window_end"] >= started \
                        and (ip not in first_alert or a["window_end"] < first_alert[ip]):
                    first_alert[ip] = a["window_end"]
    delays = [(first_alert[h] - run.first_attack[h]).total_seconds() for h in first_alert if h in run.first_attack]
    by_class: dict[str, dict[str, int]] = defaultdict(lambda: {"alerts": 0, "involving_attack_hosts": 0})
    for a in run.alerts:
        row = by_class[a["threat_class"]]
        row["alerts"] += 1
        row["involving_attack_hosts"] += int(related(a))
    return {
        "attack_hosts": len(attack),
        "attack_hosts_detected": len(first_alert),
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
                  "| File | Records (late-dropped) | Hours | Attack flows | Windows (attack) | Attack hosts detected | "
                  "Alerts (involving attack hosts) | Other hosts named | First-alert delay (s) |",
                  "|---|---|---|---|---|---|---|---|---|"]
        for f in ds["files"]:
            h, w = f["host"], f["window"]
            attack_flows = sum(v for k, v in f["labels"].items() if k != BENIGN)
            delays = h["first_alert_delay_sec"]
            lines.append(
                f"| {f['name']} | {f['records']:,} ({f.get('late_dropped', 0):,}) | {f['traffic_hours']} | {attack_flows:,} | "
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
        if ds.get("site_tuned"):
            st = ds["site_tuned"]
            defaults = {f["name"]: f["host"] for f in ds["files"]}
            lines += ["", f"### Site tuning ({st.get('design', 'leave one file out')}, percentile {st['percentile']})", "",
                      "Learning mode, without an asset inventory, with attack-labelled flows removed from the "
                      "learning traffic (standing in for an attack-free learning period); an evaluated file never "
                      "influences its own thresholds.", "",
                      "| File | Hosts detected (default → tuned) | Alerts | Alerts on attack hosts | "
                      "Host-level precision | Other hosts named |", "|---|---|---|---|---|---|"]
            for name, t in st["files"].items():
                d, h = defaults.get(name, {}), t["host"]
                lines.append(
                    f"| {name} | {d.get('attack_hosts_detected')}/{d.get('attack_hosts')} → "
                    f"{h['attack_hosts_detected']}/{h['attack_hosts']} | {d.get('alerts')} → {h['alerts']} | "
                    f"{d.get('alerts_involving_attack_hosts')} → {h['alerts_involving_attack_hosts']} | "
                    f"{_f(d.get('alert_precision_host_level'))} → {_f(h['alert_precision_host_level'])} | "
                    f"{d.get('other_hosts_named')} → {h['other_hosts_named']} |")
            lines += ["", "Thresholds changed by learning (held-out file: key default → learned):", ""]
            for name, t in st["files"].items():
                parts = [f"{k} {v['default']} → {v['learned']}" for k, v in t["changed"].items()]
                lines.append(f"- {name}: {'; '.join(parts) or 'none'}")
        lines += ["", "### Caveats", ""] + [f"- {c}" for c in ds.get("caveats", [])] + [""]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Site tuning (learning mode), leave one file out
# ---------------------------------------------------------------------------

class _CleanReader(BaseReader):
    """Drops attack-labelled records: stands in for an attack-free learning period."""

    def __init__(self, inner: BaseReader):
        super().__init__(getattr(inner, "source_path", None))
        self.inner = inner
        self.packet_level = getattr(inner, "packet_level", False)
        self.dropped = 0

    def validate_source(self) -> bool:
        return self.inner.validate_source()

    def read(self) -> Iterator:
        for flow in self.inner.read():
            if (normalise_label(flow.label) or BENIGN) != BENIGN:
                self.dropped += 1
                continue
            yield flow


def site_tuned(paths: Sequence[Path], home_networks: Sequence[str] | None, percentile: float = 99.9,
               scratch: Optional[Path] = None, spread_minutes: bool = False,
               learn_from: Optional[Sequence[Path]] = None, sort_by_time: bool = False) -> dict[str, Any]:
    """
    Learn site thresholds (learning mode, no asset inventory) and rerun files
    with the learned overlay, scored like the default run.

    Without ``learn_from``: for each file, learn from the other files with
    attack-labelled flows removed (leave one file out). With ``learn_from``
    (e.g. an attack-free day): learn once from those files and evaluate every
    other file. A file never influences its own thresholds.
    """
    import tempfile

    import yaml

    from unishield.assets import AssetInventory
    from unishield.config import config_dir, load_thresholds, reset_thresholds
    from unishield.evaluation.learning import learn, render_site_thresholds
    from unishield.ingest.detect import open_reader
    from unishield.processing.normalization import Normalizer

    base = config_dir() / "thresholds.yaml"
    defaults = yaml.safe_load(base.read_text(encoding="utf-8"))
    out: dict[str, Any] = {"percentile": percentile, "files": {},
                           "design": "learned once from " + ", ".join(p.name for p in learn_from) if learn_from
                           else "leave one file out"}
    learned_cache: dict[tuple, Any] = {}
    targets = [p for p in paths if not learn_from or p not in set(learn_from)]
    with tempfile.TemporaryDirectory(dir=scratch) as tmp:
        for held in targets:
            others = list(learn_from) if learn_from else [p for p in paths if p != held]
            reset_thresholds()
            current = load_thresholds(use_site=False)
            cleaners = []

            def inputs():
                for p in others:
                    if sort_by_time:
                        p = time_sorted_copy(p, Path(tmp))
                    reader = _CleanReader(_MinuteSpreader(p) if spread_minutes else open_reader(p)[0])
                    cleaners.append(reader)
                    yield p.name, reader

            normalizer = Normalizer(home_networks=list(home_networks)) if home_networks else None
            key = tuple(sorted(str(p) for p in others))
            if key not in learned_cache:
                run = learn(inputs(), thresholds=current, threshold_sources=[str(base)], assets=AssetInventory(),
                            normalizer=normalizer)
                learned_cache[key] = (run, run.learner.suggest(defaults, percentile=percentile),
                                      sum(c.dropped for c in cleaners))
            run, suggestions, dropped = learned_cache[key]
            overlay = Path(tmp) / f"site_{held.stem}.yaml"
            meta = run.meta("learned for evaluation", percentile, False)
            overlay.write_text(render_site_thresholds(suggestions, defaults, current, meta), encoding="utf-8")
            try:
                reset_thresholds()
                load_thresholds(site_path=overlay)
                tuned = run_file(held, home_networks, spread_minutes, sort_by_time)
            finally:
                reset_thresholds()
            out["files"][held.name] = {
                "learned_from": [p.name for p in others],
                "learning_records": run.records,
                "attack_flows_removed": dropped,
                "changed": {s.key: {"default": s.default, "learned": s.suggested} for s in suggestions if s.changed},
                "window": window_metrics(tuned.windows),
                "host": host_metrics(tuned),
            }
    return out
